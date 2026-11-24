# ruff: noqa: E501 — messages and SQL are kept one per line
"""APPL-X4a — saved synthetic scenarios, regression suites and immutable recorded evaluation runs.

* A SCENARIO is one saved synthetic application: profiles, typed facts (a value, ``null`` for "not known", or absent
  for "not provided"), and the exact library definitions that give those facts their meaning — pinned, never "the
  latest". A variant is a genuine saved scenario that names its baseline.
* A SUITE is an ordered regression dataset for ONE policy. Every member carries the outcome a person EXPECTS. An
  expectation is never derived silently from a result, and is never rewritten when the policy changes.
* A RUN is immutable evidence: the exact policy revision and manifest, the definitions the evaluator read, every
  scenario exactly as it was, what was expected, what the evaluator returned and the verdict. It can be re-evaluated
  from the record alone (``verify``), without reading the library.

Everything is evaluated by the one Python evaluator through ``policies.resolve``. No selection logic is copied here.
No policy candidate or published policy exists here (APPL-X4b). Nothing refers to a customer, an operational policy,
a case or a session, and no assignment rule, survey binding or requirement group is read or written.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta
from app.domain.survey.applicability import evaluator as ev_
from app.domain.survey.applicability import library as lib
from app.domain.survey.applicability import policies as pol
from app.domain.survey.applicability.logic import CONTRACT, ApplicabilityError, Workspace, _check_value
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.store import SurveyError, _all, _audit, _one, _ref

SCENARIO, SUITE, RUN = "applicability_scenario", "applicability_suite", "applicability_evaluation_run"
SNAPSHOT_CONTRACT = "call360.applicability-scenario-snapshot/1"
RUN_CONTRACT = "call360.applicability-evaluation-run/1"
MAX_FACTS, MAX_PROFILES, MAX_MEMBERS, MAX_EVALUATE = 400, 20, 200, 60
MAX_RECORD = 48_000_000
PURPOSES, SUITE_PURPOSES = ("REGRESSION", "EXPLORATORY"), ("PUBLICATION_GATING", "EXPLORATORY")
PLAN_STATUSES = ("RESOLVED", "UNRESOLVED", "OUT_OF_SCOPE", "SCOPE_UNRESOLVED")
_BAD = (ApplicabilityError, AttributeError, KeyError, TypeError, ValueError)
#: things that look like a real person or contract and never belong in synthetic data
_IDENTIFIERS = (
    (re.compile(r"\b[STFGM]\d{7}[A-Z]\b"), "a national identity number"),
    (re.compile(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}"), "an e-mail address"),
    (re.compile(r"\b[A-Z]{1,3}\d{7,}\b"), "a policy or account number"),
    (re.compile(r"\d{8,}"), "a long number such as a phone or account number"),
)
S_SQL = (
    "SELECT s.id, s.market_code, s.code, s.purpose, s.policy_id, s.baseline_id, s.document, s.snapshot, s.document_sha256, "
    "s.snapshot_sha256, s.draft_revision, s.draft_updated_at, s.draft_updated_by, s.archived_at, s.created_at, s.created_by "
    "FROM applicability_scenario s "
)
U_SQL = (
    "SELECT u.id, u.market_code, u.code, u.policy_id, u.purpose, u.document, u.document_sha256, u.draft_revision, "
    "u.draft_updated_at, u.draft_updated_by, u.archived_at, u.created_at, u.created_by FROM applicability_suite u "
)


def _bad(code: str, message: str, status: int = 422, details: list[dict[str, Any]] | None = None) -> SurveyError:
    return SurveyError(status, code, message, details)


def _d(severity: str, code: str, message: str, /, **at: Any) -> dict[str, Any]:
    return {"severity": severity, "code": code, "message": message, "at": at}


def _synthetic_only(what: str, value: str) -> None:
    for pattern, kind in _IDENTIFIERS:
        if pattern.search(value):
            raise _bad(
                "LOOKS_LIKE_REAL_DATA",
                f"The {what} contains what looks like {kind}. Scenarios are synthetic: never enter a real customer, policy, case or contact detail",
            )


# ------------------------------------------------------------------------------------------------------ scenarios
def normalise(raw: Any) -> dict[str, Any]:
    """The stored scenario: its own fields only. There is no field for a customer, a policy number, a case or a session."""
    if not isinstance(raw, Mapping):
        raise _bad("INVALID_DOCUMENT", "The scenario must be an object")
    name = raw.get("name")
    if not isinstance(name, str) or len(name.strip()) < 2 or len(name) > 160:
        raise _bad("NAME_REQUIRED", "Give the scenario a name of 2 to 160 characters")
    description = str(raw.get("description") or "").strip()
    if len(description) > 2000:
        raise _bad("INVALID_DOCUMENT", "The description is too long")
    _synthetic_only("name", name)
    _synthetic_only("description", description)
    profiles = raw.get("profiles") or []
    if not isinstance(profiles, list) or len(profiles) > MAX_PROFILES:
        raise _bad("INVALID_DOCUMENT", f"'profiles' must be a list of at most {MAX_PROFILES} codes")
    facts = raw.get("facts") or {}
    if not isinstance(facts, Mapping) or len(facts) > MAX_FACTS:
        raise _bad("INVALID_DOCUMENT", f"'facts' must be an object of at most {MAX_FACTS} facts")
    for code, value in facts.items():
        if isinstance(value, str):
            _synthetic_only(f"fact '{code}'", value)
    pins = raw.get("pins") or []
    if not isinstance(pins, list) or not all(isinstance(x, Mapping) for x in pins):
        raise _bad("INVALID_DOCUMENT", "'pins' must be a list of objects")
    return {
        "name": name.strip(), "description": description, "profiles": list(dict.fromkeys(str(p) for p in profiles)),
        "facts": {str(k): facts[k] for k in sorted(facts, key=str)},
        "pins": [
            {"kind": str(p.get("kind")), "code": str(p.get("code")), **({"version": int(p["version"])} if p.get("version") is not None else {"draft_revision": int(p["draft_revision"])} if p.get("draft_revision") is not None else {})}
            for p in pins
        ],
    }  # fmt: skip


class Resolved:
    """A scenario resolved against EXACTLY what it pins: its dependency entries and the definitions themselves."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []
        self.variables: dict[str, dict[str, Any]] = {}
        self.profiles: dict[str, dict[str, Any]] = {}
        self.diagnostics: list[dict[str, Any]] = []
        self.invalid: list[dict[str, Any]] = []
        self.pins: list[dict[str, Any]] = []

    @property
    def stale(self) -> list[dict[str, Any]]:
        return [e for e in self.entries if e.get("stale")]

    def snapshot(self) -> dict[str, Any]:
        keep = ("kind", "code", "state", "asset_id", "version_id", "version_no", "draft_revision", "content_sha256", "manifest_sha256")  # fmt: skip
        rows = sorted(
            ({k: e[k] for k in keep if e.get(k) is not None} for e in self.entries),
            key=lambda e: (e["kind"], e["code"].lower()),
        )
        return {"contract": SNAPSHOT_CONTRACT, "dependencies": rows}


def resolve(market: lib.Market, doc: Mapping[str, Any], previous: Mapping[str, Any] | None = None) -> Resolved:
    """Every variable a fact is given for, and every profile (with what it extends), at the exact version pinned.
    Nothing pinned yet: the published version current NOW becomes the stated intent. A pinned draft that has moved is
    reported as stale — its earlier content is not kept, so it is never silently replaced by the newer draft."""
    out = Resolved()
    pinned = {(p["kind"], p["code"].lower()): p for p in doc.get("pins") or []}
    before = {(e["kind"], e["code"].lower(), e.get("draft_revision")): e for e in (previous or {}).get("dependencies") or [] if e.get("state") == "DRAFT"}  # fmt: skip
    seen: set[tuple[str, str]] = set()

    def invalid(kind: str, code: str, message: str, error: str = "INVALID_DEPENDENCY_PIN") -> None:
        d = _d("BLOCKER", error, message, kind=kind.lower(), code=code)
        out.invalid.append(d)
        out.diagnostics.append(d)

    def take(kind: str, code: str) -> None:
        if (kind, code.lower()) in seen:
            return
        seen.add((kind, code.lower()))
        asset = market.find(kind, code)
        if asset is None:
            invalid(kind, code, f"The {kind.lower()} '{code}' does not exist in market {market.market}", "UNKNOWN_REFERENCE")  # fmt: skip
            return
        done = market.published(asset)
        pin = pinned.get((kind, code.lower())) or {}
        entry: dict[str, Any]
        definition: dict[str, Any]
        if pin.get("draft_revision") is None and (pin.get("version") is not None or done):
            want = pin.get("version") if pin.get("version") is not None else done[-1]["version_no"]
            target = next((v for v in done if v["version_no"] == want), None)
            if target is None:
                invalid(kind, code, f"The {kind.lower()} '{code}' has no published version {want}")
                return
            entry = {
                "kind": kind, "code": asset["code"], "state": "PUBLISHED", "asset_id": str(asset["id"]), "version_id": str(target["id"]),
                "version_no": target["version_no"], "content_sha256": target["content_sha256"], "manifest_sha256": target["manifest_sha256"],
                "name": target["document"].get("name") or asset["code"], "version_status": target["status"],
            }  # fmt: skip
            if done[-1]["version_no"] > target["version_no"]:
                entry["newer_version_no"] = done[-1]["version_no"]
            definition = {**target["document"], "version": target["version_no"], "status": "PUBLISHED"}
        else:
            revision = pin.get("draft_revision") if pin.get("draft_revision") is not None else asset["draft_revision"]
            current = asset["draft"]
            if current is None and pin.get("draft_revision") is None:
                invalid(kind, code, f"The {kind.lower()} '{code}' has neither a published version nor a draft")
                return
            stale = current is None or asset["draft_revision"] != revision
            kept = before.get((kind, code.lower(), revision))
            if stale and kept is None:
                invalid(kind, code, f"The {kind.lower()} '{code}' has no draft revision {revision}")
                return
            entry = {
                "kind": kind, "code": asset["code"], "state": "DRAFT", "asset_id": str(asset["id"]), "draft_revision": revision,
                "content_sha256": kept["content_sha256"] if stale and kept else sha256_hex(current), "name": (current or {}).get("name") or asset["code"],
            }  # fmt: skip
            if stale:
                entry["stale"] = True
                entry["current_draft_revision"] = asset["draft_revision"] if current is not None else None
            if done:
                entry["published_version_no"] = done[-1]["version_no"]
            definition = {**(current or {}), "version": (done[-1]["version_no"] if done else 0) + 1, "status": "DRAFT"}
        definition["code"] = asset["code"]
        out.entries.append(entry)
        if kind == "VARIABLE":
            definition["markets"] = [market.market]
            out.variables[asset["code"]] = definition
        else:
            out.profiles[asset["code"]] = definition
            for parent in definition.get("extends") or []:
                take("PROFILE", str(parent))

    for code in doc.get("profiles") or []:
        take("PROFILE", str(code))
    for code in doc.get("facts") or {}:
        take("VARIABLE", str(code))

    for e in out.entries:
        word = e["kind"].lower()
        if e.get("stale"):
            now = f"it is now at draft revision {e['current_draft_revision']}" if e.get("current_draft_revision") else "that draft no longer exists"  # fmt: skip
            out.diagnostics.append(_d("BLOCKER", "STALE_DEPENDENCY", f"The {word} '{e['name']}' was changed after this scenario was saved against its draft revision {e['draft_revision']}: {now}. The earlier draft is not kept, so this scenario cannot be reproduced until you reconcile it", kind=word, code=e["code"]))  # fmt: skip
        elif e["state"] == "DRAFT":
            out.diagnostics.append(_d("WARNING", "UNPUBLISHED_DEPENDENCY", f"The {word} '{e['name']}' is a draft (revision {e['draft_revision']}), not a published version: this scenario is not reproducible evidence", kind=word, code=e["code"]))  # fmt: skip
        if e.get("newer_version_no"):
            out.diagnostics.append(_d("INFO", "NEWER_VERSION", f"The {word} '{e['name']}' is pinned at version {e['version_no']}; version {e['newer_version_no']} is now published. Nothing changes until you adopt it", kind=word, code=e["code"]))  # fmt: skip
        out.pins.append({"kind": e["kind"], "code": e["code"], **({"version": e["version_no"]} if e["state"] == "PUBLISHED" else {"draft_revision": e["draft_revision"]})})  # fmt: skip
    out.pins.sort(key=lambda p: (p["kind"], p["code"].lower()))
    for code, value in (doc.get("facts") or {}).items():
        var = out.variables.get(code)
        if var is None or value is None:
            continue
        if var.get("derived"):
            out.diagnostics.append(_d("WARNING", "DERIVED_FACT", f"'{var.get('name') or code}' is worked out from other facts; a value given for it is not read", kind="variable", code=code))  # fmt: skip
            continue
        why = _check_value(var, value)
        if why:
            out.diagnostics.append(_d("WARNING", "FACT_INVALID", f"{var.get('name') or code}: {why}. The evaluator treats an invalid value as not known", kind="variable", code=code))  # fmt: skip
    return out


def _fingerprint(doc: Mapping[str, Any], snapshot: Mapping[str, Any]) -> str:
    return sha256_hex({"document": doc, "snapshot": snapshot})


def inspect(db: Session, market: str, doc: Mapping[str, Any], previous: Mapping[str, Any] | None = None, m: lib.Market | None = None) -> dict[str, Any]:  # fmt: skip
    res = resolve(m or lib.Market(db, market), doc, previous)
    snapshot = res.snapshot()
    return {
        "pins": res.pins, "dependencies": res.entries, "diagnostics": res.diagnostics, "snapshot_sha256": sha256_hex(snapshot),
        "scenario_fingerprint": _fingerprint({**doc, "pins": res.pins}, snapshot), "stale": len(res.stale),
        "unpublished": sum(1 for e in res.entries if e["state"] == "DRAFT"), "invalid": len(res.invalid),
        "reproducible": not res.invalid and not res.stale and all(e["state"] == "PUBLISHED" for e in res.entries),
        "definitions": {"variables": list(res.variables.values()), "profiles": list(res.profiles.values())},
    }  # fmt: skip


def scenario_row(db: Session, sid: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    s = _one(db, S_SQL + "WHERE s.id = :i" + (" FOR UPDATE" if lock else ""), i=sid)
    if s is None or s["market_code"] not in markets:  # another market's scenario does not exist for this person
        raise SurveyError(404, "NOT_FOUND", "No such scenario")
    return s


def suite_row(db: Session, uid: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    u = _one(db, U_SQL + "WHERE u.id = :i" + (" FOR UPDATE" if lock else ""), i=uid)
    if u is None or u["market_code"] not in markets:
        raise SurveyError(404, "NOT_FOUND", "No such suite")
    return u


def _event(db: Session, kind: str, sid: Any, event: str, actor: Actor, revision: int, comment: str = "", detail: Mapping[str, Any] | None = None) -> None:  # fmt: skip
    column = "scenario_id" if kind == SCENARIO else "suite_id"
    db.execute(
        text(f"INSERT INTO applicability_scenario_event ({column}, event, actor_ref, draft_revision, comment, detail) VALUES (:s, :e, :a, :r, :c, CAST(:d AS jsonb))"),
        {"s": sid, "e": event, "a": _ref(actor), "r": revision, "c": comment.strip(), "d": json.dumps(dict(detail or {}))},
    )  # fmt: skip


def _freeze(db: Session, market: str, raw: Any, previous: Mapping[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any], Resolved]:  # fmt: skip
    doc = normalise(raw)
    res = resolve(lib.Market(db, market), doc, previous)
    if res.invalid:
        code = (
            "UNKNOWN_REFERENCE"
            if all(d["code"] == "UNKNOWN_REFERENCE" for d in res.invalid)
            else "INVALID_DEPENDENCY_PIN"
        )
        raise _bad(code, "This scenario cannot be saved: it names a fact or profile that does not exist exactly as stated", details=res.invalid)  # fmt: skip
    doc["pins"] = res.pins
    return doc, res.snapshot(), res


def _write_dependencies(db: Session, sid: Any, snapshot: Mapping[str, Any]) -> None:
    db.execute(text("DELETE FROM applicability_scenario_dependency WHERE scenario_id = :s"), {"s": sid})
    for e in snapshot["dependencies"]:
        done = e["state"] == "PUBLISHED"
        db.execute(
            text("INSERT INTO applicability_scenario_dependency (scenario_id, kind, code, asset_id, asset_version_id, draft_revision, version_no, content_sha256, manifest_sha256) VALUES (:s, :k, :c, :a, :av, :dr, :n, :h, :m)"),
            {"s": sid, "k": e["kind"], "c": e["code"], "a": uuid.UUID(e["asset_id"]), "av": uuid.UUID(e["version_id"]) if done else None,
             "dr": e.get("draft_revision"), "n": e.get("version_no") if done else None, "h": e["content_sha256"], "m": e.get("manifest_sha256") if done else None},
        )  # fmt: skip


def _policy_of(db: Session, markets: Sequence[str], market: str, policy_id: uuid.UUID | None) -> uuid.UUID | None:
    if policy_id is None:
        return None
    p = pol.policy_row(db, policy_id, markets)
    if p["market_code"] != market:
        raise _bad("OTHER_MARKET", "That policy belongs to another market", 409)
    return policy_id


def _code(db: Session, table: str, market: str, code: str) -> None:
    if not lib.CODE_RE.match(code or ""):
        raise _bad("INVALID_CODE", "A code starts with a letter and uses 2 to 60 letters, digits, '_', '-' or '.'")
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"{table}:{market}:{code.lower()}"})
    if _one(db, f"SELECT id FROM {table} WHERE market_code = :m AND lower(code) = lower(:c)", m=market, c=code):
        raise SurveyError(409, "CODE_TAKEN", f"The code '{code}' is already used in this market")


def create(db: Session, markets: Sequence[str], market: str, code: str, raw: Any, actor: Actor, meta: RequestMeta | None = None, *,
           purpose: str = "REGRESSION", policy_id: uuid.UUID | None = None, baseline_id: uuid.UUID | None = None, origin: str = "") -> uuid.UUID:  # fmt: skip
    if market not in markets:
        raise SurveyError(403, "MARKET_NOT_IN_SCOPE", "You cannot work with scenarios of this market")
    if purpose not in PURPOSES:
        raise _bad("INVALID_PURPOSE", "A scenario is a regression scenario or an exploratory one")
    _code(db, SCENARIO, market, code)
    _policy_of(db, markets, market, policy_id)
    if baseline_id is not None and scenario_row(db, baseline_id, markets)["market_code"] != market:
        raise _bad("OTHER_MARKET", "A variant belongs to the market of its baseline", 409)
    doc, snapshot, res = _freeze(db, market, raw, None)
    sid = uuid.uuid4()
    db.execute(
        text("INSERT INTO applicability_scenario (id, market_code, code, purpose, policy_id, baseline_id, document, snapshot, document_sha256, snapshot_sha256, draft_updated_by, created_by) "
             "VALUES (:i, :m, :c, :pu, :p, :b, CAST(:d AS jsonb), CAST(:s AS jsonb), :dh, :sh, :by, :by)"),
        {"i": sid, "m": market, "c": code, "pu": purpose, "p": policy_id, "b": baseline_id, "d": json.dumps(doc), "s": json.dumps(snapshot),
         "dh": sha256_hex(doc), "sh": sha256_hex(snapshot), "by": _ref(actor)},
    )  # fmt: skip
    _write_dependencies(db, sid, snapshot)
    _event(db, SCENARIO, sid, "CREATED", actor, 1, detail={"origin": origin, "facts": len(doc["facts"]), "profiles": doc["profiles"], "baseline": str(baseline_id) if baseline_id else None})  # fmt: skip
    _audit(db, actor, meta, "APPLICABILITY.SCENARIO_CREATED", SCENARIO, sid, {"market": market, "code": code, "origin": origin, "purpose": purpose})  # fmt: skip
    return sid


def _stale(row: Mapping[str, Any], expected: int, what: str, db: Session) -> None:
    if expected != row["draft_revision"]:
        who = lib._names(db, [row["draft_updated_by"]]).get(str(row["draft_updated_by"]), "someone else")  # noqa: SLF001
        raise SurveyError(409, "STALE_REVISION", f"Someone saved this {what} after you opened it. Nothing of yours was saved and nothing of theirs was overwritten",
                          details=[{"current_revision": row["draft_revision"], "updated_by": who}])  # fmt: skip


def save(db: Session, markets: Sequence[str], sid: uuid.UUID, expected: int, raw: Any, actor: Actor, meta: RequestMeta | None = None, *, purpose: str | None = None, note: str = "") -> None:  # fmt: skip
    s = scenario_row(db, sid, markets, lock=True)
    if s["archived_at"] is not None:
        raise SurveyError(409, "ARCHIVED", "This scenario was archived; restore it before changing it")
    _stale(s, expected, "scenario", db)
    purpose = purpose or s["purpose"]
    if purpose not in PURPOSES:
        raise _bad("INVALID_PURPOSE", "A scenario is a regression scenario or an exploratory one")
    if purpose == "EXPLORATORY" and s["purpose"] != "EXPLORATORY":
        gating = _all(db, "SELECT u.code FROM applicability_suite_member m JOIN applicability_suite u ON u.id = m.suite_id WHERE m.scenario_id = :s AND u.purpose = 'PUBLICATION_GATING' AND u.archived_at IS NULL", s=sid)  # fmt: skip
        if gating:
            raise SurveyError(409, "IN_GATING_SUITE", f"This scenario is part of the publication-gating suite '{gating[0]['code']}'. Remove it from that suite before making it exploratory")  # fmt: skip
    doc, snapshot, res = _freeze(db, s["market_code"], raw, s["snapshot"])
    if (
        sha256_hex(doc) == s["document_sha256"]
        and sha256_hex(snapshot) == s["snapshot_sha256"]
        and purpose == s["purpose"]
    ):
        raise SurveyError(409, "NOTHING_CHANGED", "Nothing changed since the last save")
    changed = sorted(k for k in set(doc["facts"]) | set(s["document"].get("facts") or {}) if doc["facts"].get(k, "∅") != (s["document"].get("facts") or {}).get(k, "∅"))  # fmt: skip
    db.execute(
        text("UPDATE applicability_scenario SET document = CAST(:d AS jsonb), snapshot = CAST(:s AS jsonb), document_sha256 = :dh, snapshot_sha256 = :sh, purpose = :pu, "
             "draft_revision = draft_revision + 1, draft_updated_at = now(), draft_updated_by = :by WHERE id = :i"),
        {"d": json.dumps(doc), "s": json.dumps(snapshot), "dh": sha256_hex(doc), "sh": sha256_hex(snapshot), "pu": purpose, "by": _ref(actor), "i": sid},
    )  # fmt: skip
    _write_dependencies(db, sid, snapshot)
    _event(db, SCENARIO, sid, "DRAFT_SAVED", actor, s["draft_revision"] + 1, note, {"facts_changed": changed, "purpose": purpose, "document_sha256": sha256_hex(doc), "snapshot_sha256": sha256_hex(snapshot)})  # fmt: skip
    _audit(db, actor, meta, "APPLICABILITY.SCENARIO_SAVED", SCENARIO, sid, {"revision": s["draft_revision"] + 1, "snapshot_sha256": sha256_hex(snapshot)})  # fmt: skip


def archive(db: Session, markets: Sequence[str], kind: str, rid: uuid.UUID, expected: int, reason: str, actor: Actor, meta: RequestMeta | None = None, *, restore: bool = False) -> None:  # fmt: skip
    """Scenarios and suites are never deleted. Archiving takes one out of the listings; everything is kept."""
    row = scenario_row(db, rid, markets, lock=True) if kind == SCENARIO else suite_row(db, rid, markets, lock=True)
    word = "scenario" if kind == SCENARIO else "suite"
    _stale(row, expected, word, db)
    if restore == (row["archived_at"] is None):
        raise SurveyError(409, "NOT_ARCHIVED" if restore else "ARCHIVED", f"This {word} is not archived" if restore else f"This {word} is already archived")  # fmt: skip
    if not restore and len(reason.strip()) < 10:
        raise _bad("COMMENT_REQUIRED", "Say why, in at least 10 characters")
    if not restore and kind == SCENARIO:
        used = _all(db, "SELECT u.code FROM applicability_suite_member m JOIN applicability_suite u ON u.id = m.suite_id WHERE m.scenario_id = :s AND u.archived_at IS NULL", s=rid)  # fmt: skip
        if used:
            raise SurveyError(409, "IN_SUITE", f"This scenario is part of the suite '{used[0]['code']}'. Remove it from every suite before archiving it")  # fmt: skip
    db.execute(text(f"UPDATE {kind} SET archived_at = " + ("NULL" if restore else "now()") + " WHERE id = :i"), {"i": rid})  # fmt: skip
    _event(db, kind, rid, "RESTORED" if restore else "ARCHIVED", actor, row["draft_revision"], reason)
    _audit(db, actor, meta, f"APPLICABILITY.{word.upper()}_{'RESTORED' if restore else 'ARCHIVED'}", kind, rid, {"revision": row["draft_revision"]})  # fmt: skip


def _summary(s: Mapping[str, Any], names: Mapping[str, str]) -> dict[str, Any]:
    deps = s["snapshot"].get("dependencies") or []
    facts = s["document"].get("facts") or {}
    return {
        "id": str(s["id"]), "market_code": s["market_code"], "code": s["code"], "name": s["document"].get("name") or s["code"],
        "description": s["document"].get("description") or "", "record_class": "SYNTHETIC", "purpose": s["purpose"],
        "state": "ARCHIVED" if s["archived_at"] else "DRAFT", "policy_id": str(s["policy_id"]) if s["policy_id"] else None,
        "baseline_id": str(s["baseline_id"]) if s["baseline_id"] else None, "draft_revision": s["draft_revision"],
        "updated_at": s["draft_updated_at"], "updated_by": names.get(str(s["draft_updated_by"])), "created_at": s["created_at"],
        "profiles": s["document"].get("profiles") or [], "facts": len(facts), "unknown_facts": sum(1 for v in facts.values() if v is None),
        "unpublished": sum(1 for e in deps if e.get("state") == "DRAFT"), "document_sha256": s["document_sha256"],
        "snapshot_sha256": s["snapshot_sha256"], "scenario_fingerprint": _fingerprint(s["document"], s["snapshot"]),
    }  # fmt: skip


def listing(db: Session, markets: Sequence[str], *, policy_id: uuid.UUID | None = None, q: str = "", purpose: str | None = None, baseline_id: uuid.UUID | None = None,
            suite_id: uuid.UUID | None = None, archived: bool = False, limit: int = 50, offset: int = 0) -> dict[str, Any]:  # fmt: skip
    """A page of scenarios. Nothing is evaluated or inspected to list them."""
    where = (
        "WHERE s.market_code = ANY(:m) AND (CAST(:p AS uuid) IS NULL OR s.policy_id = :p) AND (CAST(:b AS uuid) IS NULL OR s.baseline_id = :b) "
        "AND (CAST(:pu AS text) IS NULL OR s.purpose = :pu) AND (:q = '' OR s.code ILIKE :like OR s.document->>'name' ILIKE :like OR s.document->>'description' ILIKE :like) "
        "AND (CAST(:u AS uuid) IS NULL OR EXISTS (SELECT 1 FROM applicability_suite_member x WHERE x.scenario_id = s.id AND x.suite_id = :u)) "
        + ("AND s.archived_at IS NOT NULL " if archived else "AND s.archived_at IS NULL ")
    )
    args = {
        "m": list(markets),
        "p": policy_id,
        "b": baseline_id,
        "pu": purpose,
        "q": q.strip(),
        "like": f"%{q.strip()}%",
        "u": suite_id,
    }
    total = (_one(db, "SELECT count(*) AS n FROM applicability_scenario s " + where, **args) or {"n": 0})["n"]
    rows = _all(
        db,
        S_SQL.replace("FROM applicability_scenario s", ", (SELECT count(*) FROM applicability_suite_member x JOIN applicability_suite u ON u.id = x.suite_id WHERE x.scenario_id = s.id AND u.archived_at IS NULL) AS suites, "
                      "(SELECT count(*) FROM applicability_scenario v WHERE v.baseline_id = s.id AND v.archived_at IS NULL) AS variants FROM applicability_scenario s")
        + where + "ORDER BY s.draft_updated_at DESC, s.code LIMIT :l OFFSET :o",
        **args, l=max(1, min(limit, 100)), o=max(0, offset),
    )  # fmt: skip
    names = lib._names(db, [r["draft_updated_by"] for r in rows])  # noqa: SLF001
    return {"items": [{**_summary(r, names), "suites": r["suites"], "variants": r["variants"]} for r in rows], "total": total, "limit": max(1, min(limit, 100)), "offset": max(0, offset)}  # fmt: skip


def _events(db: Session, column: str, rid: uuid.UUID) -> list[dict[str, Any]]:
    rows = _all(db, f"SELECT e.seq, e.event, e.actor_ref, e.draft_revision, e.comment, e.detail, e.occurred_at, pr.display_name FROM applicability_scenario_event e LEFT JOIN principal pr ON CAST(pr.id AS text) = e.actor_ref WHERE e.{column} = :i ORDER BY e.seq", i=rid)  # fmt: skip
    return [{"seq": e["seq"], "event": e["event"], "actor": e["display_name"] or e["actor_ref"], "draft_revision": e["draft_revision"], "comment": e["comment"], "detail": e["detail"], "occurred_at": e["occurred_at"]} for e in rows]  # fmt: skip


def detail(db: Session, markets: Sequence[str], sid: uuid.UUID) -> dict[str, Any]:
    s = scenario_row(db, sid, markets)
    out = _summary(s, lib._names(db, [s["draft_updated_by"]]))  # noqa: SLF001
    out["document"], out["snapshot"] = s["document"], s["snapshot"]
    out["inspection"] = inspect(db, s["market_code"], s["document"], s["snapshot"])
    base = _one(db, "SELECT id, code, document->>'name' AS name, document->'facts' AS facts, document->'profiles' AS profiles FROM applicability_scenario WHERE id = :i", i=s["baseline_id"]) if s["baseline_id"] else None  # fmt: skip
    out["baseline"] = {"id": str(base["id"]), "code": base["code"], "name": base["name"], "facts": base["facts"] or {}, "profiles": base["profiles"] or []} if base else None  # fmt: skip
    out["variant_list"] = [{"id": str(v["id"]), "code": v["code"], "name": v["name"]} for v in _all(db, "SELECT id, code, document->>'name' AS name FROM applicability_scenario WHERE baseline_id = :i AND archived_at IS NULL ORDER BY created_at", i=sid)]  # fmt: skip
    out["suite_list"] = [{"id": str(u["id"]), "code": u["code"], "name": u["name"], "purpose": u["purpose"]} for u in _all(db, "SELECT u.id, u.code, u.purpose, u.document->>'name' AS name FROM applicability_suite_member m JOIN applicability_suite u ON u.id = m.suite_id WHERE m.scenario_id = :i AND u.archived_at IS NULL ORDER BY u.code", i=sid)]  # fmt: skip
    out["suites"], out["variants"] = len(out["suite_list"]), len(out["variant_list"])
    out["events"] = _events(db, "scenario_id", sid)
    return out


# ---------------------------------------------------------------------------------------------------- evaluation
def _workspace(base: Mapping[str, list[Any]], res: Resolved) -> dict[str, list[Any]]:
    """The policy's own pinned definitions, with the PROFILES of this scenario exactly as the scenario pins them.
    Profiles describe an application; they never decide applicability, so the scenario's version is the one read."""
    mine = {c.lower() for c in res.profiles}
    profiles = [p for p in base["profiles"] if not p.get("scenario_context") and p["code"].lower() not in mine]
    return {"variables": base["variables"], "conditions": base["conditions"], "profiles": profiles + list(res.profiles.values())}  # fmt: skip


def _mismatches(pres: pol.Resolution, res: Resolved) -> list[dict[str, Any]]:
    out = []
    mine = {(e["kind"], e["code"].lower()): e for e in pres.entries if e["kind"] in ("VARIABLE", "PROFILE")}
    for e in res.entries:
        other = mine.get((e["kind"], e["code"].lower()))
        if other is None or other["content_sha256"] == e["content_sha256"]:
            continue

        def at(x: Mapping[str, Any]) -> str:
            return (
                f"version {x['version_no']}" if x["state"] == "PUBLISHED" else f"draft revision {x['draft_revision']}"
            )

        if e["kind"] == "PROFILE":
            out.append(_d("WARNING", "PROFILE_VERSION_DIFFERS", f"The scenario pins the profile '{e['name']}' at {at(e)}; the policy pins it at {at(other)}. The scenario's is read for this evaluation. Reconcile them before this scenario can count towards publication", kind="profile", code=e["code"]))  # fmt: skip
        else:
            out.append(_d("INFO", "VARIABLE_VERSION_DIFFERS", f"The scenario was saved against '{e['name']}' at {at(e)}; the policy evaluates it at {at(other)}. The policy's definition decides the result", kind="variable", code=e["code"]))  # fmt: skip
    return out


@dataclass
class Subject:
    """Exactly what a run evaluates: the saved working draft at one revision, a frozen candidate, or a published version."""

    evaluator: Evaluator
    revision: int
    document: Mapping[str, Any]
    document_sha256: str
    target: dict[str, Any]


class Evaluator:
    """One policy document resolved once; any number of scenarios evaluated against it by the Python evaluator."""

    def __init__(self, db: Session, policy: Mapping[str, Any], doc: Mapping[str, Any], previous: Mapping[str, Any] | None, *, source: str) -> None:  # fmt: skip
        self.market = lib.Market(db, policy["market_code"])
        self.policy, self.doc, self.source = policy, doc, source
        self.res = pol.resolve(db, self.market, doc, previous)
        self.snapshot = self.res.snapshot()
        self.edoc = pol.evaluator_document(policy, doc)
        self.blocked: str | None = "INVALID_DEPENDENCY" if self.res.invalid else "DEPENDENCY_STALE" if self.res.stale else None  # fmt: skip
        self.reasons = self.res.invalid or [d for d in self.res.diagnostics if d["code"] == "STALE_DEPENDENCY"]
        self.fingerprint: str | None = None
        if not self.blocked:
            try:
                self.fingerprint = ev_.fingerprint(Workspace(self.res.workspace), self.edoc)
            except _BAD:
                self.fingerprint = None

    @classmethod
    def frozen(cls, db: Session, policy: Mapping[str, Any], doc: Mapping[str, Any], manifest: Mapping[str, Any], *, source: str) -> Evaluator:  # fmt: skip
        """A FROZEN policy — a candidate or a published version: its own stored document and the definitions stored with
        it. The library is not asked what those definitions are; it is only read for the scenarios' own pins."""
        self = cls.__new__(cls)
        self.market = lib.Market(db, policy["market_code"])
        self.policy, self.doc, self.source = policy, doc, source
        self.res = pol.Resolution()
        self.res.workspace = {k: list(v) for k, v in manifest["workspace"].items()}
        self.res.entries = [dict(e) for e in manifest["snapshot"].get("dependencies") or []]
        self.snapshot = dict(manifest["snapshot"])
        self.edoc = pol.evaluator_document(policy, doc)
        self.blocked, self.reasons = None, []
        try:
            self.fingerprint = ev_.fingerprint(Workspace(self.res.workspace), self.edoc)
        except _BAD:
            self.fingerprint = None
        return self

    def head(self) -> dict[str, Any]:
        return {"policy_source": self.source, "status": self.blocked or "OK", "contract": CONTRACT, "policy_fingerprint": self.fingerprint,
                "policy_snapshot_sha256": sha256_hex(self.snapshot), "reasons": self.reasons if self.blocked else []}  # fmt: skip

    def one(
        self, doc: Mapping[str, Any], previous: Mapping[str, Any] | None, *, gating: bool = False
    ) -> dict[str, Any]:
        """``state``: EVALUATED, COULD_NOT_EVALUATE or INVALID_DEFINITION — never a pass by default."""
        res = resolve(self.market, doc, previous)
        snapshot = res.snapshot()
        row: dict[str, Any] = {
            "state": "EVALUATED", "plan": None, "diagnostics": list(res.diagnostics), "resolved": res.entries, "snapshot": snapshot,
            "scenario_fingerprint": _fingerprint({**doc, "pins": res.pins}, snapshot), "profiles": list(res.profiles.values()),
            "reproducible": not res.invalid and not res.stale and all(e["state"] == "PUBLISHED" for e in res.entries),
        }  # fmt: skip
        if res.invalid:
            return {**row, "state": "INVALID_DEFINITION", "reason": res.invalid[0]["message"]}
        if res.stale:
            return {**row, "state": "COULD_NOT_EVALUATE", "reason": next(d["message"] for d in res.diagnostics if d["code"] == "STALE_DEPENDENCY")}  # fmt: skip
        if self.blocked:
            return {**row, "state": "COULD_NOT_EVALUATE", "reason": (self.reasons[0]["message"] if self.reasons else "The policy cannot be evaluated until its dependencies are reconciled")}  # fmt: skip
        differ = _mismatches(self.res, res)
        row["diagnostics"] += differ
        # A variable at another version than the policy's is information ONLY while the given value is still valid under
        # the POLICY's definition. Another type, another currency, or a value the policy's definition does not allow is
        # a material incompatibility: reported everywhere, and never a passing publication-gating result.
        mine = {str(v.get("code")).lower(): v for v in self.res.workspace["variables"]}
        clash: list[dict[str, Any]] = []
        for d in differ:
            if d["code"] != "VARIABLE_VERSION_DIFFERS":
                continue
            code = str(d["at"]["code"])
            theirs, ours, value = (
                res.variables.get(code) or {},
                mine.get(code.lower()) or {},
                (doc.get("facts") or {}).get(code),
            )
            if value is None or ours.get("derived"):
                continue
            why = (
                f"its type is {ours.get('type')} for the policy and {theirs.get('type')} for the scenario" if ours.get("type") != theirs.get("type")
                else f"its currency is {ours.get('currency')} for the policy and {theirs.get('currency')} for the scenario" if ours.get("currency") != theirs.get("currency")
                else _check_value(ours, value)
            )  # fmt: skip
            if why:
                clash.append(_d("WARNING", "VARIABLE_VERSION_INCOMPATIBLE", f"The value given for '{ours.get('name') or code}' is not valid under the version of that fact the policy evaluates: {why}. Reconcile the scenario with the policy's version before it can count towards publication", kind="variable", code=code))  # fmt: skip
        row["diagnostics"] += clash
        if gating and clash:
            return {**row, "state": "INVALID_DEFINITION", "reason": clash[0]["message"]}
        if gating and any(d["code"] == "PROFILE_VERSION_DIFFERS" for d in differ):
            return {**row, "state": "INVALID_DEFINITION", "reason": next(d["message"] for d in differ if d["code"] == "PROFILE_VERSION_DIFFERS")}  # fmt: skip
        return self.plan(row, _workspace(self.res.workspace, res), doc)

    def plan(self, row: dict[str, Any], workspace: Mapping[str, Any], doc: Mapping[str, Any]) -> dict[str, Any]:
        try:
            row["plan"] = ev_.evaluate(Workspace(dict(workspace)), self.edoc, dict(doc.get("facts") or {}), list(doc.get("profiles") or []) or None)  # fmt: skip
        except _BAD as exc:
            return {**row, "state": "COULD_NOT_EVALUATE", "reason": getattr(exc, "message", "The evaluator could not work this out"), "error": getattr(exc, "code", "INVALID_DOCUMENT")}  # fmt: skip
        return row


def evaluate(db: Session, markets: Sequence[str], policy_id: uuid.UUID, items: Sequence[Mapping[str, Any]], policy_document: Any = None) -> dict[str, Any]:  # fmt: skip
    """Scenarios — saved (by id) or unsaved (a document) — against a saved policy or an unsaved edit of it. Records
    nothing. Each row says exactly what it is: a saved scenario at its revision, or an exploratory one, with the
    identities and fingerprints of everything that was resolved for it."""
    if len(items) > MAX_EVALUATE:
        raise _bad("TOO_MANY", f"At most {MAX_EVALUATE} scenarios are evaluated at once; run a suite for more")
    p = pol.policy_row(db, policy_id, markets)
    doc = p["document"] if policy_document is None else pol.normalise(policy_document)
    ev = Evaluator(db, p, doc, p["snapshot"], source="SAVED" if policy_document is None else "PREVIEW")
    rows = []
    for item in items:
        if item.get("scenario_id"):
            s = scenario_row(db, uuid.UUID(str(item["scenario_id"])), markets)
            if s["market_code"] != p["market_code"]:
                raise _bad("OTHER_MARKET", "A scenario is evaluated against a policy of its own market only", 409)
            sdoc, previous, mode = s["document"], s["snapshot"], "SAVED_SCENARIO"
            ident = {"scenario_id": str(s["id"]), "scenario_code": s["code"], "scenario_revision": s["draft_revision"]}
        else:
            sdoc, previous, mode = normalise(item.get("document")), item.get("snapshot"), "EXPLORATORY"
            ident = {"scenario_id": None, "scenario_code": None, "scenario_revision": None}
        row = ev.one(sdoc, previous)
        rows.append({"ref": str(item.get("ref") or ident["scenario_id"] or ""), **ident, "mode": mode, "state": row["state"], "reason": row.get("reason"),
                     "plan": row["plan"], "diagnostics": row["diagnostics"], "resolved": row["resolved"], "scenario_fingerprint": row["scenario_fingerprint"],
                     "scenario_snapshot_sha256": sha256_hex(row["snapshot"]), "reproducible": row["reproducible"] and mode == "SAVED_SCENARIO" and ev.source == "SAVED"})  # fmt: skip
    return {**ev.head(), "policy_id": str(p["id"]), "policy_revision": p["draft_revision"], "policy_document_sha256": p["document_sha256"] if policy_document is None else None, "results": rows}  # fmt: skip


def _facts_changed(a: Mapping[str, Any], b: Mapping[str, Any]) -> list[dict[str, Any]]:
    fa, fb = a.get("facts") or {}, b.get("facts") or {}
    absent = "NOT_PROVIDED"
    out = [{"variable": k, "before": fa.get(k, absent) if k in fa else absent, "after": fb.get(k, absent) if k in fb else absent, "before_given": k in fa, "after_given": k in fb}
           for k in sorted(set(fa) | set(fb)) if (k in fa) != (k in fb) or fa.get(k) != fb.get(k)]  # fmt: skip
    if (a.get("profiles") or []) != (b.get("profiles") or []):
        out.append({"variable": "(profiles)", "before": a.get("profiles") or [], "after": b.get("profiles") or [], "before_given": True, "after_given": True})  # fmt: skip
    return out


def _plan_change(before: Mapping[str, Any] | None, after: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not before or not after or before.get("status") == "ERROR" or after.get("status") == "ERROR":
        return None
    try:
        out = ev_.compare(dict(before), dict(after))
    except _BAD:
        return None
    a, b = {e["survey"]["code"] for e in before["pending"]}, {e["survey"]["code"] for e in after["pending"]}
    out["pending_added"], out["pending_removed"] = sorted(b - a), sorted(a - b)
    out["now_resolved"] = before["status"] != "RESOLVED" and after["status"] == "RESOLVED"
    out["changed"] = out["changed"] or bool(out["pending_added"] or out["pending_removed"])
    return out


def compare_scenarios(db: Session, markets: Sequence[str], policy_id: uuid.UUID, before: uuid.UUID, after: uuid.UUID) -> dict[str, Any]:  # fmt: skip
    """Two saved scenarios (a baseline and a variant, say) against one saved policy: which facts differ, and what that changes."""
    run = evaluate(db, markets, policy_id, [{"scenario_id": str(before)}, {"scenario_id": str(after)}])
    a, b = scenario_row(db, before, markets), scenario_row(db, after, markets)
    ra, rb = run["results"]
    return {"policy_id": run["policy_id"], "policy_revision": run["policy_revision"], "status": run["status"], "before": ra, "after": rb,
            "facts_changed": _facts_changed(a["document"], b["document"]), "comparison": _plan_change(ra["plan"], rb["plan"])}  # fmt: skip


# ---------------------------------------------------------------------------------------------------------- suites
#: what the server adds to a stated expectation; never part of what the person stated
EXPECTATION_META = ("reviewed_at_revision", "stated_by", "stated_at")


def _stated(e: Mapping[str, Any] | None) -> dict[str, Any]:
    return {k: v for k, v in (e or {}).items() if k not in EXPECTATION_META}


def expectation(raw: Any) -> dict[str, Any] | None:
    """What a person says the result must be. It is stored as stated — never filled in from an actual result here."""
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise _bad("INVALID_EXPECTATION", "An expected outcome must be an object")
    if raw.get("status") not in PLAN_STATUSES:
        raise _bad("INVALID_EXPECTATION", "State the expected plan status: resolved, unresolved, out of scope or scope unresolved")  # fmt: skip
    if raw.get("confirmed") is not True:
        raise _bad("EXPECTATION_NOT_CONFIRMED", "An expected outcome must be reviewed and confirmed by the person who states it")  # fmt: skip
    selected = []
    for x in raw.get("selected") or []:
        if not isinstance(x, Mapping) or not x.get("code"):
            raise _bad("INVALID_EXPECTATION", "Each expected survey needs its code")
        selected.append({"code": str(x["code"]), "version": int(x["version"]) if x.get("version") is not None else None, "name": str(x.get("name") or x["code"])[:200]})  # fmt: skip
    out: dict[str, Any] = {
        "status": raw["status"], "selected": selected, "pending": sorted({str(x) for x in raw.get("pending") or []}),
        "source": "PROPOSED_FROM_RESULT" if raw.get("source") == "PROPOSED_FROM_RESULT" else "AUTHORED", "confirmed": True,
        "note": str(raw.get("note") or "").strip()[:500],
    }  # fmt: skip
    if len({x["code"] for x in selected}) != len(selected):
        raise _bad("INVALID_EXPECTATION", "A survey is expected once")
    for key in ("replaced", "needs"):
        if raw.get(key) is not None:
            out[key] = sorted({str(x) for x in raw[key]})
    _synthetic_only("note", out["note"])
    return out


def check(expected: Mapping[str, Any], plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every way the actual plan differs from what was expected. Empty: the test passed."""
    out: list[dict[str, Any]] = []
    reqs = {r["id"]: r for r in plan.get("requirements") or []}

    def involved(code: str) -> list[str]:
        return [r["id"] for r in reqs.values() if any(s.get("code") == code for s in r.get("surveys") or [])]

    def add(kind: str, textual: str, want: Any, got: Any, **at: Any) -> None:
        out.append({"kind": kind, "text": textual, "expected": want, "actual": got, **at})

    if plan.get("status") != expected["status"]:
        add("STATUS", f"Expected the plan to be {expected['status'].replace('_', ' ').lower()}; it is {str(plan.get('status')).replace('_', ' ').lower()}", expected["status"], plan.get("status"))  # fmt: skip
    actual = {e["survey"]["code"]: e["survey"] for e in plan.get("selected") or []}
    for x in expected["selected"]:
        got = actual.get(x["code"])
        if got is None:
            where = (
                "pending"
                if any(e["survey"]["code"] == x["code"] for e in plan.get("pending") or [])
                else "not selected"
            )
            add("SURVEY_MISSING", f"Expected '{x['name']}' to be selected; it is {where}", x["code"], None, survey=x["code"], requirements=involved(x["code"]))  # fmt: skip
        elif x["version"] is not None and got.get("version") != x["version"]:
            add("SURVEY_VERSION", f"Expected '{x['name']}' at version {x['version']}; version {got.get('version')} is selected", x["version"], got.get("version"), survey=x["code"], requirements=involved(x["code"]))  # fmt: skip
    wanted = {x["code"] for x in expected["selected"]}
    for code, got in actual.items():
        if code not in wanted:
            add("SURVEY_UNEXPECTED", f"'{got.get('name') or code}' is selected and was not expected", None, code, survey=code, requirements=involved(code))  # fmt: skip
    pending = {e["survey"]["code"]: e["survey"] for e in plan.get("pending") or []}
    for code in expected["pending"]:
        if code not in pending:
            add("PENDING_MISSING", f"Expected '{code}' to be pending; it is {'selected' if code in actual else 'not pending'}", code, None, survey=code, requirements=involved(code))  # fmt: skip
    for code, got in pending.items():
        if code not in expected["pending"]:
            add("PENDING_UNEXPECTED", f"'{got.get('name') or code}' is pending and was not expected to be", None, code, survey=code, requirements=involved(code))  # fmt: skip
    for rid in expected.get("replaced") or []:
        r = reqs.get(rid)
        if r is None or r["outcome"] != "REPLACED":
            add("NOT_REPLACED", f"Expected the requirement '{(r or {}).get('name') or rid}' to be replaced; it is {str((r or {}).get('outcome') or 'absent').replace('_', ' ').lower()}", "REPLACED", (r or {}).get("outcome"), requirements=[rid])  # fmt: skip
    if expected.get("needs") is not None:
        got_needs = sorted({n["variable"] for n in plan.get("needs") or []})
        if got_needs != expected["needs"]:
            add("REASONS", f"Expected the unresolved result to be waiting for {', '.join(expected['needs']) or 'nothing'}; it is waiting for {', '.join(got_needs) or 'nothing'}", expected["needs"], got_needs)  # fmt: skip
    return out


def _members(db: Session, uid: Any) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT m.position, m.expectation, s.id, s.code, s.purpose, s.draft_revision, s.archived_at, s.document, s.snapshot, s.document_sha256, s.snapshot_sha256, s.baseline_id "
        "FROM applicability_suite_member m JOIN applicability_scenario s ON s.id = m.scenario_id WHERE m.suite_id = :u ORDER BY m.position",
        u=uid,
    )


def _suite_fingerprint(doc: Mapping[str, Any], purpose: str, members: Sequence[Mapping[str, Any]]) -> str:
    return sha256_hex({"document": doc, "purpose": purpose, "members": [{"scenario_id": str(m["scenario_id"]), "expectation": m["expectation"]} for m in members]})  # fmt: skip


def _suite_input(db: Session, markets: Sequence[str], market: str, raw: Any, purpose: str, members: Sequence[Mapping[str, Any]], old: Mapping[str, Any] | None = None, actor: Actor | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:  # fmt: skip
    if not isinstance(raw, Mapping) or not isinstance(raw.get("name"), str) or not 2 <= len(raw["name"].strip()) <= 160:
        raise _bad("NAME_REQUIRED", "Give the suite a name of 2 to 160 characters")
    doc = {"name": raw["name"].strip(), "description": str(raw.get("description") or "").strip()[:2000]}
    _synthetic_only("name", doc["name"])
    _synthetic_only("description", doc["description"])
    if purpose not in SUITE_PURPOSES:
        raise _bad("INVALID_PURPOSE", "A suite is publication-gating or exploratory")
    if len(members) > MAX_MEMBERS:
        raise _bad("SUITE_TOO_LARGE", f"A suite holds at most {MAX_MEMBERS} scenarios; split it into several suites")
    out, seen = [], set()
    for m in members:
        try:
            sid = uuid.UUID(str(m.get("scenario_id")))
        except ValueError as exc:
            raise _bad("INVALID_MEMBER", "A suite member names a saved scenario") from exc
        if sid in seen:
            raise _bad("INVALID_MEMBER", "A scenario is in a suite once")
        seen.add(sid)
        s = scenario_row(db, sid, markets)
        if s["market_code"] != market:
            raise _bad("OTHER_MARKET", "A suite holds scenarios of its own market only", 409)
        if s["archived_at"] is not None:
            raise _bad("INVALID_MEMBER", f"The scenario '{s['code']}' is archived", 409)
        if purpose == "PUBLICATION_GATING" and s["purpose"] != "REGRESSION":
            raise _bad("EXPLORATORY_IN_GATING_SUITE", f"'{s['document'].get('name')}' is an exploratory scenario. A publication-gating suite holds regression scenarios only", 409)  # fmt: skip
        exp = expectation(m.get("expectation"))
        if exp is not None:
            # when the expectation was last stated is kept with it, so a later change of the scenario can be noticed
            prior = (old or {}).get(str(sid))
            same = prior is not None and _stated(prior) == exp
            exp["reviewed_at_revision"] = prior["reviewed_at_revision"] if same and prior else s["draft_revision"]
            # APPL-X4b: WHO stated this outcome and WHEN is stamped by the server whenever its stated content changes — and
            # only then. An expectation saved before this existed keeps no stamp: its author is read from the suite's
            # append-only history, and is labelled as such; nobody is invented.
            if same and prior:
                for key in ("stated_by", "stated_at"):
                    if prior.get(key):
                        exp[key] = prior[key]
            elif actor is not None:
                exp["stated_by"], exp["stated_at"] = _ref(actor), datetime.now(UTC).isoformat(timespec="seconds")
        out.append({"scenario_id": sid, "expectation": exp})
    return doc, out


def _write_members(db: Session, uid: Any, members: Sequence[Mapping[str, Any]]) -> None:
    db.execute(text("DELETE FROM applicability_suite_member WHERE suite_id = :u"), {"u": uid})
    for i, m in enumerate(members, 1):
        db.execute(
            text("INSERT INTO applicability_suite_member (suite_id, scenario_id, position, expectation) VALUES (:u, :s, :p, CAST(:e AS jsonb))"),
            {"u": uid, "s": m["scenario_id"], "p": i, "e": json.dumps(m["expectation"]) if m["expectation"] is not None else None},
        )  # fmt: skip


def create_suite(db: Session, markets: Sequence[str], market: str, code: str, policy_id: uuid.UUID, raw: Any, purpose: str, members: Sequence[Mapping[str, Any]],
                 actor: Actor, meta: RequestMeta | None = None, origin: str = "") -> uuid.UUID:  # fmt: skip
    if market not in markets:
        raise SurveyError(403, "MARKET_NOT_IN_SCOPE", "You cannot work with suites of this market")
    _code(db, SUITE, market, code)
    _policy_of(db, markets, market, policy_id)
    doc, rows = _suite_input(db, markets, market, raw, purpose, members, None, actor)
    uid = uuid.uuid4()
    db.execute(
        text("INSERT INTO applicability_suite (id, market_code, code, policy_id, purpose, document, document_sha256, draft_updated_by, created_by) VALUES (:i, :m, :c, :p, :pu, CAST(:d AS jsonb), :h, :by, :by)"),
        {"i": uid, "m": market, "c": code, "p": policy_id, "pu": purpose, "d": json.dumps(doc), "h": _suite_fingerprint(doc, purpose, rows), "by": _ref(actor)},
    )  # fmt: skip
    _write_members(db, uid, rows)
    _event(db, SUITE, uid, "CREATED", actor, 1, detail={"origin": origin, "members": len(rows), "purpose": purpose})
    _audit(db, actor, meta, "APPLICABILITY.SUITE_CREATED", SUITE, uid, {"market": market, "code": code, "policy": str(policy_id), "purpose": purpose})  # fmt: skip
    return uid


def save_suite(db: Session, markets: Sequence[str], uid: uuid.UUID, expected: int, raw: Any, purpose: str, members: Sequence[Mapping[str, Any]],
               actor: Actor, meta: RequestMeta | None = None, note: str = "") -> None:  # fmt: skip
    u = suite_row(db, uid, markets, lock=True)
    if u["archived_at"] is not None:
        raise SurveyError(409, "ARCHIVED", "This suite was archived; restore it before changing it")
    _stale(u, expected, "suite", db)
    had = _members(db, uid)
    old = {str(m["id"]): m["expectation"] for m in had if m["expectation"]}
    doc, rows = _suite_input(db, markets, u["market_code"], raw, purpose, members, old, actor)
    fingerprint = _suite_fingerprint(doc, purpose, rows)
    if fingerprint == u["document_sha256"]:
        raise SurveyError(409, "NOTHING_CHANGED", "Nothing changed since the last save")
    before, after = {str(m["id"]) for m in had}, {str(m["scenario_id"]) for m in rows}
    changed = sorted(str(m["scenario_id"]) for m in rows if str(m["scenario_id"]) in before and _stated(old.get(str(m["scenario_id"]))) != _stated(m["expectation"]))  # fmt: skip
    db.execute(
        text("UPDATE applicability_suite SET document = CAST(:d AS jsonb), document_sha256 = :h, purpose = :pu, draft_revision = draft_revision + 1, draft_updated_at = now(), draft_updated_by = :by WHERE id = :i"),
        {"d": json.dumps(doc), "h": fingerprint, "pu": purpose, "by": _ref(actor), "i": uid},
    )  # fmt: skip
    _write_members(db, uid, rows)
    _event(db, SUITE, uid, "DRAFT_SAVED", actor, u["draft_revision"] + 1, note,
           {"members": len(rows), "added": sorted(after - before), "removed": sorted(before - after), "expectations_changed": changed, "purpose": purpose,
            "proposed_from_result": sorted(str(m["scenario_id"]) for m in rows if (m["expectation"] or {}).get("source") == "PROPOSED_FROM_RESULT" and str(m["scenario_id"]) in changed + sorted(after - before))})  # fmt: skip
    _audit(db, actor, meta, "APPLICABILITY.SUITE_SAVED", SUITE, uid, {"revision": u["draft_revision"] + 1, "members": len(rows), "suite_sha256": fingerprint})  # fmt: skip


def _suite_summary(db: Session, u: Mapping[str, Any], names: Mapping[str, str], members: int | None = None, expected: int | None = None) -> dict[str, Any]:  # fmt: skip
    last = _one(db, "SELECT id, status, passed, failed, scenarios, created_at, policy_revision, suite_revision FROM applicability_evaluation_run WHERE suite_id = :u ORDER BY created_at DESC, id LIMIT 1", u=u["id"])  # fmt: skip
    return {
        "id": str(u["id"]), "market_code": u["market_code"], "code": u["code"], "name": u["document"].get("name") or u["code"],
        "description": u["document"].get("description") or "", "purpose": u["purpose"], "policy_id": str(u["policy_id"]),
        "state": "ARCHIVED" if u["archived_at"] else "DRAFT", "draft_revision": u["draft_revision"], "updated_at": u["draft_updated_at"],
        "updated_by": names.get(str(u["draft_updated_by"])), "created_at": u["created_at"], "suite_sha256": u["document_sha256"],
        "members": members if members is not None else 0, "with_expectation": expected if expected is not None else 0,
        "last_run": {"id": str(last["id"]), "status": last["status"], "passed": last["passed"], "failed": last["failed"], "scenarios": last["scenarios"], "created_at": last["created_at"],
                     "policy_revision": last["policy_revision"], "suite_revision": last["suite_revision"]} if last else None,
    }  # fmt: skip


def suites(db: Session, markets: Sequence[str], *, policy_id: uuid.UUID | None = None, archived: bool = False, limit: int = 50, offset: int = 0) -> dict[str, Any]:  # fmt: skip
    where = "WHERE u.market_code = ANY(:m) AND (CAST(:p AS uuid) IS NULL OR u.policy_id = :p) " + ("AND u.archived_at IS NOT NULL " if archived else "AND u.archived_at IS NULL ")  # fmt: skip
    args = {"m": list(markets), "p": policy_id}
    total = (_one(db, "SELECT count(*) AS n FROM applicability_suite u " + where, **args) or {"n": 0})["n"]
    rows = _all(db, U_SQL.replace("FROM applicability_suite u", ", (SELECT count(*) FROM applicability_suite_member x WHERE x.suite_id = u.id) AS n_members, (SELECT count(*) FROM applicability_suite_member x WHERE x.suite_id = u.id AND x.expectation IS NOT NULL) AS n_expected FROM applicability_suite u")
                + where + "ORDER BY u.draft_updated_at DESC, u.code LIMIT :l OFFSET :o", **args, l=max(1, min(limit, 100)), o=max(0, offset))  # fmt: skip
    names = lib._names(db, [r["draft_updated_by"] for r in rows])  # noqa: SLF001
    return {"items": [_suite_summary(db, r, names, r["n_members"], r["n_expected"]) for r in rows], "total": total, "limit": max(1, min(limit, 100)), "offset": max(0, offset)}  # fmt: skip


def suite_detail(db: Session, markets: Sequence[str], uid: uuid.UUID) -> dict[str, Any]:
    u = suite_row(db, uid, markets)
    members = _members(db, uid)
    out = _suite_summary(
        db, u, lib._names(db, [u["draft_updated_by"]]), len(members), sum(1 for m in members if m["expectation"])
    )  # noqa: SLF001
    p = _one(db, "SELECT id, code, document->>'name' AS name, draft_revision, archived_at FROM applicability_policy WHERE id = :i", i=u["policy_id"])  # fmt: skip
    assert p is not None
    out["policy"] = {"id": str(p["id"]), "code": p["code"], "name": p["name"] or p["code"], "draft_revision": p["draft_revision"], "archived": p["archived_at"] is not None}  # fmt: skip
    diagnostics = []
    out["member_list"] = []
    for m in members:
        exp = m["expectation"]
        moved = bool(exp) and exp.get("reviewed_at_revision") not in (None, m["draft_revision"])
        if exp is None:
            diagnostics.append(_d("BLOCKER", "NO_EXPECTATION", f"'{m['document'].get('name')}' has no expected outcome yet: it cannot pass or fail", scenario=str(m["id"])))  # fmt: skip
        elif moved:
            diagnostics.append(_d("WARNING", "SCENARIO_CHANGED", f"'{m['document'].get('name')}' was changed (now revision {m['draft_revision']}) after its expected outcome was reviewed at revision {exp.get('reviewed_at_revision')}. Review the expectation", scenario=str(m["id"])))  # fmt: skip
        if m["archived_at"] is not None:
            diagnostics.append(
                _d("BLOCKER", "MEMBER_ARCHIVED", f"'{m['document'].get('name')}' is archived", scenario=str(m["id"]))
            )
        out["member_list"].append({
            "position": m["position"], "scenario_id": str(m["id"]), "code": m["code"], "name": m["document"].get("name") or m["code"], "purpose": m["purpose"],
            "draft_revision": m["draft_revision"], "facts": m["document"].get("facts") or {}, "profiles": m["document"].get("profiles") or [],
            "baseline_id": str(m["baseline_id"]) if m["baseline_id"] else None, "expectation": exp, "scenario_changed": moved,
        })  # fmt: skip
    stated_names = lib._names(
        db,
        [
            (m["expectation"] or {}).get("stated_by")
            for m in out["member_list"]
            if (m["expectation"] or {}).get("stated_by")
        ],
    )  # noqa: SLF001
    for m in out["member_list"]:
        exp = m["expectation"] or {}
        m["expectation_stated_by"] = stated_names.get(str(exp.get("stated_by"))) if exp.get("stated_by") else None
        m["expectation_stated_at"] = exp.get("stated_at")
    if not members:
        diagnostics.append(_d("BLOCKER", "EMPTY_SUITE", "This suite holds no scenario yet"))
    out["diagnostics"] = diagnostics
    out["events"] = _events(db, "suite_id", uid)
    return out


# ------------------------------------------------------------------------------------------------------- coverage
def coverage(
    doc: Mapping[str, Any], rows: Sequence[Mapping[str, Any]], purpose: str, run_passed: bool = True
) -> dict[str, Any]:
    """Which requirements and which parts of their conditions the evaluated scenarios exercised — read from the plans
    the evaluator returned. It is requirement- and condition-level coverage of THESE scenarios. It never claims that
    every possible application was tested."""
    reqs: dict[str, dict[str, Any]] = {}
    for r in doc.get("requirements") or []:
        action = r.get("action") or {}
        reqs[str(r["id"])] = {
            "id": str(r["id"]), "name": r.get("name") or str(r["id"]), "applies": 0, "does_not_apply": 0, "unknown": 0, "replaced": 0, "selected": 0,
            "replaces": [str(x) for x in r.get("replaces") or []], "replaced_them": 0, "alternatives": len(action.get("alternatives") or []),
            "alternatives_chosen": [], "conditions": {},
        }  # fmt: skip
    scope = {"TRUE": 0, "FALSE": 0, "UNKNOWN": 0} if doc.get("scope") else None
    evaluated = positive = negative = unresolved = overlaps = 0

    def leaves(trace: Mapping[str, Any] | None, into: dict[str, Any]) -> None:
        if not isinstance(trace, Mapping):
            return
        if trace.get("op") in ("test", "ref"):
            cell = into.setdefault(str(trace.get("path")), {"text": trace.get("text") or "", "TRUE": 0, "FALSE": 0, "UNKNOWN": 0})  # fmt: skip
            if trace.get("result") in ("TRUE", "FALSE", "UNKNOWN"):
                cell[trace["result"]] += 1
        for c in trace.get("children") or []:
            leaves(c, into)

    for row in rows:
        plan = row.get("plan")
        if not plan or plan.get("status") == "ERROR":
            continue
        evaluated += 1
        if scope is not None and (plan.get("scope") or {}).get("result") in scope:
            scope[plan["scope"]["result"]] += 1
        passed = row.get("outcome") == "PASSED"
        if plan["status"] == "RESOLVED" and plan.get("selected") and passed:
            positive += 1
        if (
            plan["status"] == "RESOLVED"
            and passed
            and any(r["state"] == "DOES_NOT_APPLY" for r in plan.get("requirements") or [])
        ):
            negative += 1
        if plan["status"] != "RESOLVED":
            unresolved += 1
        if any(len(e.get("required_by") or []) > 1 for e in plan.get("selected") or []):
            overlaps += 1
        by = {str(x["id"]): x for x in plan.get("requirements") or []}
        for r in plan.get("requirements") or []:
            c = reqs.get(str(r["id"]))
            if c is None:
                continue
            c[
                "applies"
                if r["state"] == "APPLIES"
                else "does_not_apply"
                if r["state"] == "DOES_NOT_APPLY"
                else "unknown"
            ] += 1
            if r["outcome"] == "REPLACED":
                c["replaced"] += 1
            if r["outcome"] == "ACTIVE":
                c["selected"] += 1
                if c["replaces"] and any(by.get(t, {}).get("outcome") == "REPLACED" for t in c["replaces"]):
                    c["replaced_them"] += 1
                chosen = (r.get("choice") or {}).get("alternatives") or []
                for a in chosen:
                    if a.get("chosen") and a["index"] not in c["alternatives_chosen"]:
                        c["alternatives_chosen"].append(a["index"])
            leaves(r.get("trace"), c["conditions"])

    gaps: list[dict[str, Any]] = []

    def gap(code: str, textual: str, rid: str | None = None) -> None:
        gaps.append({"code": code, "text": textual, "requirement": rid})

    for c in reqs.values():
        if not c["applies"]:
            gap("NEVER_APPLIES", f"No scenario makes '{c['name']}' apply", c["id"])
        if not c["does_not_apply"]:
            gap("NEVER_DOES_NOT_APPLY", f"No scenario makes '{c['name']}' not apply", c["id"])
        if c["replaces"] and not c["replaced_them"]:
            gap("REPLACEMENT_NOT_EXERCISED", f"No scenario shows '{c['name']}' replacing what it replaces", c["id"])
        if c["alternatives"] > 1:
            for i in range(c["alternatives"]):
                if i not in c["alternatives_chosen"]:
                    gap(
                        "ALTERNATIVE_NOT_CHOSEN",
                        f"No scenario makes '{c['name']}' choose its alternative {i + 1}",
                        c["id"],
                    )
        for cell in c["conditions"].values():
            for value, word in (("TRUE", "true"), ("FALSE", "false"), ("UNKNOWN", "not known")):
                if not cell[value]:
                    gap(f"CONDITION_NOT_{value}", f"In '{c['name']}', “{cell['text']}” is never {word}", c["id"])
        c["conditions"] = [{"path": p, **cell} for p, cell in sorted(c["conditions"].items())]
    if scope is not None:
        for value, word in (("TRUE", "covered by"), ("FALSE", "outside")):
            if not scope[value]:
                gap(f"SCOPE_NOT_{value}", f"No scenario is {word} the policy's scope")
    shared = sum(1 for d in doc.get("shared_deliveries") or [] if len(d.get("requirements") or []) > 1)
    if shared and not overlaps:
        gap("OVERLAP_NOT_EXERCISED", "No scenario has one survey required by several requirements at once")
    essential = [g for g in gaps if g["code"] in ("NEVER_APPLIES", "NEVER_DOES_NOT_APPLY", "REPLACEMENT_NOT_EXERCISED", "ALTERNATIVE_NOT_CHOSEN", "SCOPE_NOT_TRUE", "SCOPE_NOT_FALSE", "OVERLAP_NOT_EXERCISED")]  # fmt: skip
    only_unresolved = evaluated > 0 and unresolved == evaluated
    meaningful = (
        run_passed
        and purpose == "PUBLICATION_GATING"
        and positive > 0
        and negative > 0
        and not only_unresolved
        and not essential
    )
    return {
        "method": "REQUIREMENT_AND_CONDITION_LEVEL", "exhaustive": False,
        "label": ("Every requirement was exercised as applying and as not applying by passing scenarios. " if not essential and evaluated else "Partial coverage. ")
        + "This describes the scenarios that were run; it does not prove every possible application.",
        "scenarios_evaluated": evaluated, "resolved_positive_passing": positive, "negative_passing": negative, "unresolved": unresolved, "only_unresolved": only_unresolved,
        "requirements": list(reqs.values()), "scope": scope, "gaps": gaps, "essential_gaps": len(essential), "condition_gaps": len(gaps) - len(essential),
        "meaningful_for_publication": meaningful,
        "why_not_meaningful": None if meaningful else (
            "the suite is exploratory" if purpose != "PUBLICATION_GATING" else "nothing was evaluated" if not evaluated else "the run did not pass" if not run_passed else "every result is unresolved" if only_unresolved
            else "no passing scenario has a resolved result that selects a survey" if not positive else "no passing scenario shows a requirement that does not apply" if not negative
            else f"{len(essential)} requirement-level gap{'' if len(essential) == 1 else 's'} remain"),
    }  # fmt: skip


# ----------------------------------------------------------------------------------------------------------- runs
def _digest(results: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [{"position": r["position"], "scenario": r["scenario_document_sha256"], "snapshot": r["scenario_snapshot_sha256"], "expectation": r["expectation"],
             "outcome": r["outcome"], "plan": r["plan_fingerprint"], "differences": r["differences"]} for r in results]  # fmt: skip


def run_suite(db: Session, markets: Sequence[str], uid: uuid.UUID, idempotency_key: str, actor: Actor, meta: RequestMeta | None = None, subject: Subject | None = None) -> tuple[uuid.UUID, bool]:  # fmt: skip
    """Evaluate every member against the policy's SAVED revision and record the whole thing, once. The same key for the
    same suite returns the run that was already recorded. Nothing recorded is ever changed."""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,80}", idempotency_key or ""):
        raise _bad("INVALID_KEY", "A run needs an idempotency key of 8 to 80 letters, digits, '-', '_', '.' or ':'")
    u = suite_row(db, uid, markets, lock=True)
    done = _one(db, "SELECT id FROM applicability_evaluation_run WHERE suite_id = :u AND idempotency_key = :k", u=uid, k=idempotency_key)  # fmt: skip
    if done:
        return done["id"], False
    if u["archived_at"] is not None:
        raise SurveyError(409, "ARCHIVED", "This suite is archived")
    members = _members(db, uid)
    if not members:
        raise _bad("EMPTY_SUITE", "This suite holds no scenario to run", 409)
    p = pol.policy_row(db, u["policy_id"], markets)
    started = time.monotonic()
    if subject is None:
        ev = Evaluator(db, p, p["document"], p["snapshot"], source="SAVED")
        target = {"kind": "DRAFT", "revision": p["draft_revision"], "document_sha256": p["document_sha256"], "manifest_sha256": sha256_hex(ev.snapshot)}  # fmt: skip
    else:  # a frozen candidate or published version: its own document and revision are what is recorded
        ev, target = subject.evaluator, subject.target
        p = {**p, "document": subject.document, "draft_revision": subject.revision, "document_sha256": subject.document_sha256}  # fmt: skip
    gating = u["purpose"] == "PUBLICATION_GATING"
    results: list[dict[str, Any]] = []
    for m in members:
        row = ev.one(m["document"], m["snapshot"], gating=gating)
        plan, exp = row["plan"], m["expectation"]
        differences: list[dict[str, Any]] = []
        if row["state"] != "EVALUATED" or plan is None or plan.get("status") == "ERROR":
            outcome = "INVALID_DEFINITION" if row["state"] == "INVALID_DEFINITION" else "COULD_NOT_EVALUATE"
        elif exp is None:
            outcome = "NO_EXPECTATION"
        else:
            differences = check(exp, plan)
            outcome = "FAILED" if differences else "PASSED"
        results.append({
            "position": m["position"], "scenario_id": m["id"], "scenario_code": m["code"], "scenario_name": m["document"].get("name") or m["code"],
            "scenario_revision": m["draft_revision"], "scenario_document": m["document"], "scenario_snapshot": row["snapshot"],
            "scenario_document_sha256": sha256_hex(m["document"]), "scenario_snapshot_sha256": sha256_hex(row["snapshot"]), "expectation": exp, "outcome": outcome,
            "plan": plan, "plan_fingerprint": (plan or {}).get("fingerprint"), "differences": differences, "diagnostics": row["diagnostics"],
            "actual": {"profiles": row["profiles"], "reason": row.get("reason"), "reproducible": row["reproducible"], "scenario_fingerprint": row["scenario_fingerprint"], "resolved": row["resolved"]},
        })  # fmt: skip
    count = {k: sum(1 for r in results if r["outcome"] == k) for k in ("PASSED", "FAILED", "COULD_NOT_EVALUATE", "INVALID_DEFINITION", "NO_EXPECTATION")}  # fmt: skip
    status = ("INVALID_DEFINITION" if count["INVALID_DEFINITION"] or count["NO_EXPECTATION"] else "COULD_NOT_EVALUATE" if count["COULD_NOT_EVALUATE"]
              else "FAILED" if count["FAILED"] else "PASSED")  # fmt: skip
    cover = coverage(p["document"], results, u["purpose"], status == "PASSED")
    record = {
        "contract": RUN_CONTRACT, "evaluator": CONTRACT, "record_class": "SYNTHETIC", "target": target,
        "policy": {"id": str(p["id"]), "code": p["code"], "market": p["market_code"], "revision": p["draft_revision"], "document": p["document"], "snapshot": ev.snapshot,
                   "document_sha256": p["document_sha256"], "snapshot_sha256": sha256_hex(ev.snapshot), "status": ev.blocked or "OK", "reasons": ev.reasons if ev.blocked else [],
                   "workspace": {k: [x for x in v if not x.get("scenario_context")] for k, v in ev.res.workspace.items()} if not ev.blocked else None},
        "suite": {"id": str(u["id"]), "code": u["code"], "revision": u["draft_revision"], "purpose": u["purpose"], "name": u["document"].get("name"), "description": u["document"].get("description"),
                  "suite_sha256": u["document_sha256"], "members": [{"position": m["position"], "scenario_id": str(m["id"]), "code": m["code"], "revision": m["draft_revision"], "expectation": m["expectation"]} for m in members]},
    }  # fmt: skip
    size = len(json.dumps(record)) + sum(len(json.dumps(r["plan"])) for r in results if r["plan"])
    if size > MAX_RECORD:
        raise _bad(
            "RUN_TOO_LARGE", "This run would be too large to record as one piece of evidence; split the suite", 413
        )
    record_sha = sha256_hex(record)
    run_sha = sha256_hex({"record": record_sha, "status": status, "results": _digest(results), "coverage": cover})
    rid = uuid.uuid4()
    db.execute(
        text("INSERT INTO applicability_evaluation_run (id, market_code, suite_id, suite_revision, suite_purpose, policy_id, policy_revision, policy_document_sha256, policy_snapshot_sha256, policy_fingerprint, "
             "evaluator_contract, idempotency_key, status, scenarios, passed, failed, not_evaluated, invalid, no_expectation, coverage, record, record_sha256, run_sha256, duration_ms, created_by) "
             "VALUES (:i, :m, :u, :ur, :up, :p, :pr, :pd, :ps, :pf, :ec, :k, :st, :n, :a, :b, :c, :d, :e, CAST(:cov AS jsonb), CAST(:rec AS jsonb), :rh, :runh, :ms, :by)"),
        {"i": rid, "m": u["market_code"], "u": uid, "ur": u["draft_revision"], "up": u["purpose"], "p": p["id"], "pr": p["draft_revision"], "pd": p["document_sha256"],
         "ps": sha256_hex(ev.snapshot), "pf": ev.fingerprint, "ec": CONTRACT, "k": idempotency_key, "st": status, "n": len(results), "a": count["PASSED"], "b": count["FAILED"],
         "c": count["COULD_NOT_EVALUATE"], "d": count["INVALID_DEFINITION"], "e": count["NO_EXPECTATION"], "cov": json.dumps(cover), "rec": json.dumps(record), "rh": record_sha,
         "runh": run_sha, "ms": int((time.monotonic() - started) * 1000), "by": _ref(actor)},
    )  # fmt: skip
    for r in results:
        db.execute(
            text("INSERT INTO applicability_evaluation_result (run_id, position, scenario_id, scenario_code, scenario_name, scenario_revision, scenario_document, scenario_snapshot, scenario_document_sha256, "
                 "scenario_snapshot_sha256, expectation, outcome, plan, plan_fingerprint, actual, differences, diagnostics) VALUES (:r, :p, :s, :c, :n, :rev, CAST(:d AS jsonb), CAST(:sn AS jsonb), :dh, :sh, "
                 "CAST(:e AS jsonb), :o, CAST(:pl AS jsonb), :pf, CAST(:a AS jsonb), CAST(:df AS jsonb), CAST(:dg AS jsonb))"),
            {"r": rid, "p": r["position"], "s": r["scenario_id"], "c": r["scenario_code"], "n": r["scenario_name"], "rev": r["scenario_revision"], "d": json.dumps(r["scenario_document"]),
             "sn": json.dumps(r["scenario_snapshot"]), "dh": r["scenario_document_sha256"], "sh": r["scenario_snapshot_sha256"], "e": json.dumps(r["expectation"]) if r["expectation"] is not None else None,
             "o": r["outcome"], "pl": json.dumps(r["plan"]) if r["plan"] is not None else None, "pf": r["plan_fingerprint"], "a": json.dumps(r["actual"]), "df": json.dumps(r["differences"]),
             "dg": json.dumps(r["diagnostics"])},
        )  # fmt: skip
    _audit(db, actor, meta, "APPLICABILITY.SUITE_RUN_RECORDED", RUN, rid, {"suite": str(uid), "policy": str(p["id"]), "policy_revision": p["draft_revision"], "status": status, "scenarios": len(results), "run_sha256": run_sha})  # fmt: skip
    return rid, True


RUN_SQL = (
    "SELECT r.id, r.market_code, r.suite_id, r.suite_revision, r.suite_purpose, r.policy_id, r.policy_revision, r.policy_document_sha256, r.policy_snapshot_sha256, r.policy_fingerprint, "
    "r.evaluator_contract, r.status, r.scenarios, r.passed, r.failed, r.not_evaluated, r.invalid, r.no_expectation, r.record_sha256, r.run_sha256, r.duration_ms, r.created_at, r.created_by, "
    "r.record->'target' AS target, u.code AS suite_code, u.document->>'name' AS suite_name, p.code AS policy_code, p.document->>'name' AS policy_name, pr.display_name "
    "FROM applicability_evaluation_run r JOIN applicability_suite u ON u.id = r.suite_id JOIN applicability_policy p ON p.id = r.policy_id LEFT JOIN principal pr ON CAST(pr.id AS text) = r.created_by "
)


def _run_summary(r: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": str(r["id"]), "market_code": r["market_code"], "record_class": "SYNTHETIC", "suite_id": str(r["suite_id"]),
        # exactly what was evaluated; a run recorded before targets existed was of the saved draft at that revision
        "target": r["target"] or {"kind": "DRAFT", "revision": r["policy_revision"], "document_sha256": r["policy_document_sha256"], "manifest_sha256": r["policy_snapshot_sha256"]}, "suite_code": r["suite_code"], "suite_name": r["suite_name"] or r["suite_code"],
        "suite_revision": r["suite_revision"], "suite_purpose": r["suite_purpose"], "policy_id": str(r["policy_id"]), "policy_code": r["policy_code"], "policy_name": r["policy_name"] or r["policy_code"],
        "policy_revision": r["policy_revision"], "policy_document_sha256": r["policy_document_sha256"], "policy_snapshot_sha256": r["policy_snapshot_sha256"], "policy_fingerprint": r["policy_fingerprint"],
        "evaluator_contract": r["evaluator_contract"], "status": r["status"], "scenarios": r["scenarios"], "passed": r["passed"], "failed": r["failed"], "not_evaluated": r["not_evaluated"],
        "invalid": r["invalid"], "no_expectation": r["no_expectation"], "record_sha256": r["record_sha256"], "run_sha256": r["run_sha256"], "duration_ms": r["duration_ms"],
        "created_at": r["created_at"], "created_by": r["display_name"] or r["created_by"],
    }  # fmt: skip


def run_row(db: Session, rid: uuid.UUID, markets: Sequence[str], extra: str = "") -> dict[str, Any]:
    r = _one(db, RUN_SQL.replace("SELECT r.id,", f"SELECT {extra}r.id,") + "WHERE r.id = :i", i=rid)
    if r is None or r["market_code"] not in markets:
        raise SurveyError(404, "NOT_FOUND", "No such recorded run")
    return r


def runs(db: Session, markets: Sequence[str], *, suite_id: uuid.UUID | None = None, policy_id: uuid.UUID | None = None, limit: int = 25, offset: int = 0) -> dict[str, Any]:  # fmt: skip
    where = "WHERE r.market_code = ANY(:m) AND (CAST(:u AS uuid) IS NULL OR r.suite_id = :u) AND (CAST(:p AS uuid) IS NULL OR r.policy_id = :p) "
    args = {"m": list(markets), "u": suite_id, "p": policy_id}
    total = (_one(db, "SELECT count(*) AS n FROM applicability_evaluation_run r " + where, **args) or {"n": 0})["n"]
    rows = _all(db, RUN_SQL + where + "ORDER BY r.created_at DESC, r.id LIMIT :l OFFSET :o", **args, l=max(1, min(limit, 100)), o=max(0, offset))  # fmt: skip
    return {
        "items": [_run_summary(r) for r in rows],
        "total": total,
        "limit": max(1, min(limit, 100)),
        "offset": max(0, offset),
    }


def _result_summary(r: Mapping[str, Any]) -> dict[str, Any]:
    return {"position": r["position"], "scenario_id": str(r["scenario_id"]), "scenario_code": r["scenario_code"], "scenario_name": r["scenario_name"], "scenario_revision": r["scenario_revision"],
            "scenario_document_sha256": r["scenario_document_sha256"], "scenario_snapshot_sha256": r["scenario_snapshot_sha256"], "expectation": r["expectation"], "outcome": r["outcome"],
            "plan_fingerprint": r["plan_fingerprint"], "differences": r["differences"], "reason": (r["actual"] or {}).get("reason"),
            "actual": {"status": r["plan_status"], "selected": r["sel"] or [], "pending": r["pen"] or []}}  # fmt: skip


RESULT_SQL = (
    "SELECT x.position, x.scenario_id, x.scenario_code, x.scenario_name, x.scenario_revision, x.scenario_document_sha256, x.scenario_snapshot_sha256, x.expectation, x.outcome, x.plan_fingerprint, "
    "x.differences, x.actual, x.plan->>'status' AS plan_status, "
    "(SELECT jsonb_agg(jsonb_build_object('code', e->'survey'->>'code', 'version', (e->'survey'->>'version')::int, 'name', e->'survey'->>'name')) FROM jsonb_array_elements(coalesce(x.plan->'selected', '[]'::jsonb)) e) AS sel, "
    "(SELECT jsonb_agg(e->'survey'->>'code') FROM jsonb_array_elements(coalesce(x.plan->'pending', '[]'::jsonb)) e) AS pen "
    "FROM applicability_evaluation_result x "
)


def run_detail(db: Session, markets: Sequence[str], rid: uuid.UUID, *, outcome: str | None = None, limit: int = 50, offset: int = 0) -> dict[str, Any]:  # fmt: skip
    """The run and a page of its results — what was expected, what happened, the verdict. The full plan of one result
    is read on its own (``run_result``), so a large run never arrives in one answer."""
    r = run_row(db, rid, markets, "r.coverage, r.record->'suite' AS suite_record, r.record->'policy'->'reasons' AS policy_reasons, r.record->'policy'->>'status' AS policy_status, ")  # fmt: skip
    out = _run_summary(r)
    out["coverage"], out["suite"] = r["coverage"], r["suite_record"]
    out["policy_status"], out["policy_reasons"] = r["policy_status"], r["policy_reasons"] or []
    where = "WHERE x.run_id = :r AND (CAST(:o AS text) IS NULL OR x.outcome = :o) "
    out["results_total"] = (_one(db, "SELECT count(*) AS n FROM applicability_evaluation_result x " + where, r=rid, o=outcome) or {"n": 0})["n"]  # fmt: skip
    out["results"] = [_result_summary(x) for x in _all(db, RESULT_SQL + where + "ORDER BY x.position LIMIT :l OFFSET :f", r=rid, o=outcome, l=max(1, min(limit, 100)), f=max(0, offset))]  # fmt: skip
    out["limit"], out["offset"] = max(1, min(limit, 100)), max(0, offset)
    return out


def run_result(db: Session, markets: Sequence[str], rid: uuid.UUID, position: int) -> dict[str, Any]:
    run_row(db, rid, markets)
    x = _one(db, RESULT_SQL.replace("FROM applicability_evaluation_result x", ", x.plan, x.scenario_document, x.scenario_snapshot, x.diagnostics FROM applicability_evaluation_result x") + "WHERE x.run_id = :r AND x.position = :p", r=rid, p=position)  # fmt: skip
    if x is None:
        raise SurveyError(404, "NOT_FOUND", "No such result in this run")
    return {**_result_summary(x), "plan": x["plan"], "scenario_document": x["scenario_document"], "scenario_snapshot": x["scenario_snapshot"], "diagnostics": x["diagnostics"],
            "resolved": (x["actual"] or {}).get("resolved") or [], "reproducible": bool((x["actual"] or {}).get("reproducible")), "scenario_fingerprint": (x["actual"] or {}).get("scenario_fingerprint")}  # fmt: skip


def _stored(db: Session, rid: uuid.UUID) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    run = _one(db, "SELECT record, record_sha256, run_sha256, status, coverage, suite_purpose FROM applicability_evaluation_run WHERE id = :i", i=rid)  # fmt: skip
    assert run is not None
    rows = _all(db, "SELECT position, scenario_id, scenario_code, scenario_name, scenario_document, scenario_snapshot, scenario_document_sha256, scenario_snapshot_sha256, expectation, outcome, plan, plan_fingerprint, actual, differences FROM applicability_evaluation_result WHERE run_id = :i ORDER BY position", i=rid)  # fmt: skip
    return run, rows


def verify(db: Session, markets: Sequence[str], rid: uuid.UUID) -> dict[str, Any]:
    """Re-evaluate a recorded run FROM THE RECORD ALONE — the stored policy document, the stored definitions, the stored
    scenarios — without reading the library, and compare every fingerprint with what was recorded."""
    run_row(db, rid, markets)
    run, rows = _stored(db, rid)
    record = run["record"]
    ok_record = sha256_hex(record) == run["record_sha256"]
    ok_run = sha256_hex({"record": run["record_sha256"], "status": run["status"], "results": _digest(rows), "coverage": run["coverage"]}) == run["run_sha256"]  # fmt: skip
    policy = record["policy"]
    checked = same = 0
    mismatched: list[int] = []
    if policy.get("workspace"):
        edoc = pol.evaluator_document({"code": policy["code"], "market_code": policy["market"]}, policy["document"])
        for x in rows:
            if x["plan"] is None or x["plan"].get("status") == "ERROR":
                continue
            checked += 1
            mine = {c.lower() for c in (p["code"] for p in (x["actual"] or {}).get("profiles") or [])}
            ws = {"variables": policy["workspace"]["variables"], "conditions": policy["workspace"]["conditions"],
                  "profiles": [p for p in policy["workspace"]["profiles"] if p["code"].lower() not in mine] + list((x["actual"] or {}).get("profiles") or [])}  # fmt: skip
            try:
                again = ev_.evaluate(Workspace(ws), edoc, dict(x["scenario_document"].get("facts") or {}), list(x["scenario_document"].get("profiles") or []) or None)  # fmt: skip
            except _BAD:
                again = {}
            if again.get("fingerprint") == x["plan_fingerprint"] and (
                not x["expectation"] or (not check(x["expectation"], again)) == (x["outcome"] == "PASSED")
            ):
                same += 1
            else:
                mismatched.append(x["position"])
    return {"run_id": str(rid), "record_intact": ok_record, "run_fingerprint_intact": ok_run, "results_checked": checked, "results_reproduced": same, "mismatched_positions": mismatched,
            "reproduced": ok_record and ok_run and checked == same, "note": "Re-evaluated from the stored record only; the library was not read."}  # fmt: skip


def _dependency_changes(a: Mapping[str, Any], b: Mapping[str, Any]) -> list[dict[str, Any]]:
    def key(e: Mapping[str, Any]) -> tuple[str, str]:
        return (e["kind"], e["code"])

    def at(e: Mapping[str, Any] | None) -> str | None:
        return (
            None
            if e is None
            else f"v{e['version_no']}"
            if e.get("state") == "PUBLISHED"
            else f"draft r{e.get('draft_revision')}"
        )

    da, db_ = {key(e): e for e in a.get("dependencies") or []}, {key(e): e for e in b.get("dependencies") or []}
    out = []
    for k in sorted(set(da) | set(db_)):
        x, y = da.get(k), db_.get(k)
        if x is None or y is None or x["content_sha256"] != y["content_sha256"]:
            out.append({"kind": k[0], "code": k[1], "before": at(x), "after": at(y), "change": "ADDED" if x is None else "REMOVED" if y is None else "VERSION"})  # fmt: skip
    return out


def _pairs(before: Sequence[Mapping[str, Any]], after: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    a, b = {str(x["scenario_id"]): x for x in before}, {str(x["scenario_id"]): x for x in after}
    rows = []
    for sid in [*a, *(k for k in b if k not in a)]:
        x, y = a.get(sid), b.get(sid)
        if x is None or y is None:
            rows.append({"scenario_id": sid, "scenario_name": (x or y or {})["scenario_name"], "in": "AFTER_ONLY" if x is None else "BEFORE_ONLY", "outcome_before": (x or {}).get("outcome"), "outcome_after": (y or {}).get("outcome"),
                         "facts_changed": [], "expectation_changed": False, "comparison": None, "changed": True})  # fmt: skip
            continue
        cmp_ = _plan_change(x["plan"], y["plan"])
        facts = _facts_changed(x["scenario_document"], y["scenario_document"])
        exp = _stated(x["expectation"]) != _stated(y["expectation"])
        rows.append({"scenario_id": sid, "scenario_name": y["scenario_name"], "in": "BOTH", "outcome_before": x["outcome"], "outcome_after": y["outcome"], "facts_changed": facts, "expectation_changed": exp,
                     "comparison": cmp_, "changed": bool(facts or exp or x["outcome"] != y["outcome"] or (cmp_ or {}).get("changed") or x["plan_fingerprint"] != y["plan_fingerprint"] and cmp_ is None)})  # fmt: skip
    return {
        "scenarios": rows,
        "changed": sum(1 for r in rows if r["changed"]),
        "unchanged": sum(1 for r in rows if not r["changed"]),
    }


def compare_runs(db: Session, markets: Sequence[str], before: uuid.UUID, after: uuid.UUID) -> dict[str, Any]:
    """What differs between two recorded runs: the policy revision and its dependencies, and for each scenario its facts,
    its expectation, its verdict and its selection — surveys added, removed, at another version, newly pending or resolved."""
    ra, rb = run_row(db, before, markets), run_row(db, after, markets)
    if ra["market_code"] != rb["market_code"]:
        raise _bad("OTHER_MARKET", "Two runs are compared inside one market", 409)
    (sa_, xa), (sb, xb) = _stored(db, before), _stored(db, after)
    return {"kind": "RUN_TO_RUN", "before": _run_summary(ra), "after": _run_summary(rb), "same_policy": ra["policy_id"] == rb["policy_id"],
            "policy_changed": ra["policy_document_sha256"] != rb["policy_document_sha256"] or ra["policy_snapshot_sha256"] != rb["policy_snapshot_sha256"],
            "dependency_changes": _dependency_changes(sa_["record"]["policy"]["snapshot"], sb["record"]["policy"]["snapshot"]), **_pairs(xa, xb),
            "note": "Both sides are recorded evidence. Draft-versus-published impact needs published policy versions, which do not exist yet."}  # fmt: skip


def against_current(db: Session, markets: Sequence[str], rid: uuid.UUID) -> dict[str, Any]:
    """A recorded run's own scenarios and expectations, exactly as recorded, against the policy's CURRENT saved revision.
    Nothing is recorded: the 'after' side is a what-if, and it says so."""
    r = run_row(db, rid, markets)
    run, rows = _stored(db, rid)
    p = pol.policy_row(db, r["policy_id"], markets)
    ev = Evaluator(db, p, p["document"], p["snapshot"], source="SAVED")
    now = []
    for x in rows:
        row: dict[str, Any] = {"state": "EVALUATED", "plan": None}
        if ev.blocked or not run["record"]["policy"].get("workspace"):
            row["state"] = "COULD_NOT_EVALUATE"
        else:
            frozen = Resolved()
            frozen.profiles = {p_["code"]: p_ for p_ in (x["actual"] or {}).get("profiles") or []}
            row = ev.plan(row, _workspace(ev.res.workspace, frozen), x["scenario_document"])
        plan = row["plan"]
        outcome = "COULD_NOT_EVALUATE" if row["state"] != "EVALUATED" or plan is None else "NO_EXPECTATION" if x["expectation"] is None else "FAILED" if check(x["expectation"], plan) else "PASSED"  # fmt: skip
        now.append({**x, "plan": plan, "plan_fingerprint": (plan or {}).get("fingerprint"), "outcome": outcome})
    return {"kind": "RUN_TO_CURRENT_DRAFT", "before": _run_summary(r), "after": {"policy_id": str(p["id"]), "policy_revision": p["draft_revision"], "policy_document_sha256": p["document_sha256"],
            "policy_snapshot_sha256": sha256_hex(ev.snapshot), "policy_fingerprint": ev.fingerprint, "status": ev.blocked or "OK", "recorded": False},
            "same_policy": True, "policy_changed": r["policy_document_sha256"] != p["document_sha256"] or r["policy_snapshot_sha256"] != sha256_hex(ev.snapshot),
            "dependency_changes": _dependency_changes(run["record"]["policy"]["snapshot"], ev.snapshot), **_pairs(rows, now),
            "note": "The 'after' side is the policy's current saved draft, evaluated now and NOT recorded. Run the suite to record it."}  # fmt: skip
