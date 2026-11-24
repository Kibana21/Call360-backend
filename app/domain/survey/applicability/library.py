# ruff: noqa: E501 — messages and SQL are kept one per line
"""APPL-X2 — the governed Applicability library: variables, application profiles and reusable conditions, persisted.

One asset has a stable identity (market, kind, code), ONE working draft saved with an expected revision, immutable
candidates frozen at submission, and published versions. Publication needs three different people: the one who
submitted, the one who approved and the one who published — refused here and again by the table (migration 0038).

A candidate pins the exact published versions it reads (its ``manifest`` and ``applicability_asset_dependency``): a
later version of a variable never changes a condition or a profile that was already published.

Validation and evaluation are the existing pure evaluator and analysis (``logic``, ``analysis``): nothing here decides
applicability, and nothing reads or writes assignment rules, survey bindings or requirement groups.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta
from app.domain.survey.applicability import analysis
from app.domain.survey.applicability.logic import CONTRACT, Evaluation, Workspace
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.store import SurveyError, _all, _audit, _one, _ref

KINDS = ("VARIABLE", "PROFILE", "CONDITION")
MANIFEST_CONTRACT = "call360.applicability-asset/1"
ENTITY = "applicability_asset"
CODE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{1,59}$")
OPEN = ("SUBMITTED", "APPROVED")
WAS_PUBLISHED = ("PUBLISHED", "SUPERSEDED")
MAX_DOCUMENT = 64_000
SOURCE_STATUSES = ("MAPPED", "PROPOSED", "UNMAPPED", "DERIVED")
#: the fields of each kind's document; anything else in a request is dropped, never stored
FIELDS: dict[str, tuple[str, ...]] = {
    "VARIABLE": ("name", "description", "category", "type", "values", "currency", "min", "max", "source", "owner",
                 "samples", "derived"),
    "PROFILE": ("name", "description", "extends", "sections", "required", "constraints"),
    "CONDITION": ("name", "description", "expr"),
}  # fmt: skip


def _bad(code: str, message: str, status: int = 422) -> SurveyError:
    return SurveyError(status, code, message)


def _diag(severity: str, code: str, message: str, /, **at: Any) -> dict[str, Any]:
    return {"severity": severity, "code": code, "message": message, "at": at}


# ------------------------------------------------------------------------------------------------------ documents
def normalise(kind: str, raw: Any) -> dict[str, Any]:
    """The stored document of one kind: its own fields only, in a canonical shape. Refuses what cannot be a draft."""
    if not isinstance(raw, Mapping):
        raise _bad("INVALID_DOCUMENT", "The definition must be an object")
    doc: dict[str, Any] = {k: raw[k] for k in FIELDS[kind] if k in raw and raw[k] is not None}
    name = doc.get("name")
    if not isinstance(name, str) or len(name.strip()) < 2 or len(name) > 160:
        raise _bad("NAME_REQUIRED", "Give it a name of 2 to 160 characters")
    doc["name"] = name.strip()
    doc["description"] = str(doc.get("description") or "").strip()
    if kind == "VARIABLE":
        doc["category"] = str(doc.get("category") or "").strip()
        doc["type"] = str(doc.get("type") or "")
        if "values" in doc:
            if not isinstance(doc["values"], list) or not all(isinstance(o, Mapping) for o in doc["values"]):
                raise _bad("INVALID_DOCUMENT", "Allowed values must be a list of value and label")
            doc["values"] = [
                {"value": str(o.get("value") or ""), "label": str(o.get("label") or o.get("value") or "")}
                for o in doc["values"]
            ]
        src = doc.get("source")
        src = dict(src) if isinstance(src, Mapping) else {}
        derived = doc.get("derived")
        if derived is not None and not (isinstance(derived, Mapping) and isinstance(derived.get("expr"), Mapping)):
            raise _bad("INVALID_DOCUMENT", "A derived variable needs an expression")
        if derived is not None:
            doc["derived"] = {"expr": dict(derived["expr"])}
        status = "DERIVED" if derived is not None else str(src.get("status") or "UNMAPPED")
        doc["source"] = {
            "status": status,
            **{k: str(src[k]) for k in ("system", "field", "note") if src.get(k)},
        }
    elif kind == "PROFILE":
        for key in ("extends", "required"):
            value = doc.get(key) or []
            if not isinstance(value, list):
                raise _bad("INVALID_DOCUMENT", f"'{key}' must be a list")
            doc[key] = [str(x) for x in value]
        sections = doc.get("sections") or []
        if not isinstance(sections, list) or not all(isinstance(x, Mapping) for x in sections):
            raise _bad("INVALID_DOCUMENT", "Sections must be a list")
        doc["sections"] = [
            {"name": str(x.get("name") or ""), "variables": [str(v) for v in (x.get("variables") or [])]}
            for x in sections
        ]
        constraints = doc.get("constraints") or {}
        if not isinstance(constraints, Mapping):
            raise _bad("INVALID_DOCUMENT", "Constraints must be an object")
        doc["constraints"] = {
            str(k): {"allowed": [str(a) for a in (dict(v).get("allowed") or [])]}
            for k, v in constraints.items()
            if isinstance(v, Mapping)
        }
    else:
        if not isinstance(doc.get("expr"), Mapping):
            raise _bad("INVALID_DOCUMENT", "A condition needs an expression")
        doc["expr"] = dict(doc["expr"])
    if len(json.dumps(doc)) > MAX_DOCUMENT:
        raise _bad("DOCUMENT_TOO_LARGE", "This definition is too large")
    return doc


def references(kind: str, doc: Mapping[str, Any]) -> list[tuple[str, str, Any]]:
    """Everything a document reads, as (kind, code, version): ``version`` is set only for a saved-condition reference."""
    out: list[tuple[str, str, Any]] = []

    def add(k: str, code: Any, version: Any = None) -> None:
        item = (k, str(code), version)
        if item not in out:
            out.append(item)

    def walk(node: Any, depth: int = 0) -> None:
        if not isinstance(node, Mapping) or depth > 60:
            return
        op = node.get("op")
        if op in ("all", "any"):
            for a in node.get("args") or []:
                walk(a, depth + 1)
        elif op == "not":
            walk(node.get("arg"), depth + 1)
        elif op == "test" and node.get("variable"):
            add("VARIABLE", node["variable"])
        elif op == "ref" and node.get("condition"):
            add("CONDITION", node["condition"], node.get("version"))

    if kind == "CONDITION":
        walk(doc.get("expr"))
    elif kind == "VARIABLE":
        walk((doc.get("derived") or {}).get("expr"))
    else:
        for parent in doc.get("extends") or []:
            add("PROFILE", parent)
        for s in doc.get("sections") or []:
            for v in s.get("variables") or []:
                add("VARIABLE", v)
        for v in (*(doc.get("required") or []), *(doc.get("constraints") or {})):
            add("VARIABLE", v)
    return out


# --------------------------------------------------------------------------------------------------------- reading
ASSET_SQL = (
    "SELECT a.id, a.market_code, a.kind, a.code, a.draft, a.draft_revision, a.draft_base_version_no, "
    "a.draft_updated_at, a.draft_updated_by, a.created_at, a.created_by FROM applicability_asset a "
)
VERSION_SQL = (
    "SELECT v.id, v.asset_id, v.candidate_no, v.version_no, v.status, v.document, v.manifest, v.content_sha256, "
    "v.manifest_sha256, v.draft_revision, v.note, v.submitted_by, v.submitted_at, v.decided_by, v.decided_at, "
    "v.decision_comment, v.published_by, v.published_at FROM applicability_asset_version v "
)


def _names(db: Session, refs: Sequence[Any]) -> dict[str, str]:
    wanted = sorted({str(r) for r in refs if r})
    if not wanted:
        return {}
    rows = _all(
        db, "SELECT CAST(id AS text) AS id, display_name FROM principal WHERE CAST(id AS text) = ANY(:r)", r=wanted
    )
    return {r["id"]: r["display_name"] for r in rows}


class Market:
    """Every asset of one market with its versions, read once: what lists, workspaces and validation work from."""

    def __init__(self, db: Session, market: str) -> None:
        self.market = market
        self.assets = _all(
            db, ASSET_SQL + "WHERE a.market_code = :m ORDER BY a.kind, a.created_at, lower(a.code)", m=market
        )
        versions = _all(
            db,
            VERSION_SQL + "JOIN applicability_asset a ON a.id = v.asset_id WHERE a.market_code = :m "
            "ORDER BY v.asset_id, v.candidate_no",
            m=market,
        )
        self.versions: dict[Any, list[dict[str, Any]]] = {}
        for v in versions:
            self.versions.setdefault(v["asset_id"], []).append(v)
        self.by_key = {(a["kind"], a["code"].lower()): a for a in self.assets}

    def find(self, kind: str, code: str) -> dict[str, Any] | None:
        return self.by_key.get((kind, code.lower()))

    def published(self, asset: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Every version that was published, oldest first."""
        out = [v for v in self.versions.get(asset["id"], []) if v["status"] in WAS_PUBLISHED]
        return sorted(out, key=lambda v: v["version_no"])

    def latest(self, asset: Mapping[str, Any]) -> dict[str, Any] | None:
        done = self.published(asset)
        return done[-1] if done else None

    def open(self, asset: Mapping[str, Any]) -> dict[str, Any] | None:
        return next((v for v in self.versions.get(asset["id"], []) if v["status"] in OPEN), None)

    def entry(self, asset: Mapping[str, Any], *, drafts: bool, replace: Mapping[str, Any] | None = None) -> Any:
        """One asset as the evaluator reads it: the draft (when asked and present) or the latest published version."""
        latest = self.latest(asset)
        history = self.published(asset)
        if replace is not None or (drafts and asset["draft"] is not None):
            doc = dict(replace if replace is not None else asset["draft"])
            out = {**doc, "version": (latest["version_no"] if latest else 0) + 1, "status": "DRAFT"}
            if latest:
                out["previous"] = {**latest["document"], "code": asset["code"], "version": latest["version_no"], "status": "PUBLISHED"}  # fmt: skip
        elif latest:
            out = {**latest["document"], "version": latest["version_no"], "status": "PUBLISHED"}
            out["version_id"], out["fingerprint"] = str(latest["id"]), latest["content_sha256"]
            history = history[:-1]
        else:
            return None
        out["code"], out["asset_id"] = asset["code"], str(asset["id"])
        if asset["kind"] == "VARIABLE":
            out["markets"] = [self.market]
        if asset["kind"] == "CONDITION":
            out["history"] = [{"version": v["version_no"], "expr": v["document"].get("expr")} for v in history]
        return out

    def workspace(self, *, drafts: bool, replace: tuple[Any, Mapping[str, Any]] | None = None) -> dict[str, Any]:
        """``drafts`` false: published versions only. True: a draft stands in for its asset where one exists."""
        out: dict[str, list[Any]] = {"variables": [], "profiles": [], "conditions": []}
        for a in self.assets:
            mine = replace[1] if replace is not None and replace[0] == a["id"] else None
            e = self.entry(a, drafts=drafts, replace=mine)
            if e is not None:
                out[{"VARIABLE": "variables", "PROFILE": "profiles", "CONDITION": "conditions"}[a["kind"]]].append(e)
        return out


def asset_row(db: Session, asset_id: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    a = _one(db, ASSET_SQL + "WHERE a.id = :i" + (" FOR UPDATE" if lock else ""), i=asset_id)
    if a is None or a["market_code"] not in markets:  # another market's item does not exist for this person
        raise SurveyError(404, "NOT_FOUND", "No such applicability library item")
    return a


def version_row(db: Session, version_id: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    v = _one(db, VERSION_SQL + "WHERE v.id = :i" + (" FOR UPDATE" if lock else ""), i=version_id)
    if v is None:
        raise SurveyError(404, "NOT_FOUND", "No such applicability candidate or version")
    asset_row(db, v["asset_id"], markets)
    return v


# ------------------------------------------------------------------------------------------------------ validation
def pins(market: Market, asset: Mapping[str, Any], doc: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:  # fmt: skip
    """The exact published versions a document would pin, and every reference that cannot be pinned."""
    found: list[dict[str, Any]] = []
    problems: list[dict[str, Any]] = []
    where = {"kind": asset["kind"].lower(), "code": asset["code"]}
    for kind, code, version in references(asset["kind"], doc):
        label = f"{kind.lower()} '{code}'"
        other = market.find(kind, code)
        if other is None:
            problems.append(
                _diag(
                    "BLOCKER",
                    "UNKNOWN_REFERENCE",
                    f"The {label} does not exist in market {market.market}",
                    **where,
                    reference=code,
                )  # fmt: skip
            )
            continue
        if other["id"] == asset["id"]:
            problems.append(_diag("BLOCKER", "DEPENDENCY_CYCLE", f"The {label} cannot depend on itself", **where, reference=code))  # fmt: skip
            continue
        done = market.published(other)
        if not done:
            problems.append(
                _diag(
                    "BLOCKER",
                    "UNPUBLISHED_DEPENDENCY",
                    f"The {label} is not published yet. Publish it first: a published item reads published items only",
                    **where,
                    reference=code,
                )  # fmt: skip
            )
            continue
        if kind == "CONDITION":
            target = next((v for v in done if v["version_no"] == version), None)
            if target is None:
                text_ = "names no version" if version is None else f"has no published version {version}"
                problems.append(_diag("BLOCKER", "UNKNOWN_CONDITION_VERSION", f"The {label} {text_}", **where, reference=code))  # fmt: skip
                continue
        else:
            target = done[-1]
        found.append(
            {
                "kind": kind, "code": other["code"], "version_no": target["version_no"], "version_id": str(target["id"]),
                "content_sha256": target["content_sha256"],
            }
        )  # fmt: skip
    found.sort(key=lambda p: (p["kind"], p["code"].lower(), p["version_no"]))
    return found, problems


def validate(market: Market, asset: Mapping[str, Any], doc: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every diagnostic of one document: what it refers to, then what the evaluator's own analysis says about it."""
    kind = asset["kind"]
    _, out = pins(market, asset, doc)
    if kind == "VARIABLE":
        if (doc.get("source") or {}).get("status") not in SOURCE_STATUSES:
            out.append(_diag("BLOCKER", "UNKNOWN_SOURCE_STATUS", "Say whether the source is mapped, proposed or not mapped", kind="variable", code=asset["code"]))  # fmt: skip
        values = [o["value"] for o in doc.get("values") or []]
        if any(not v for v in values) or len(set(values)) != len(values):
            out.append(_diag("BLOCKER", "INVALID_VALUES", "Every allowed value needs a code of its own", kind="variable", code=asset["code"]))  # fmt: skip
    ws = Workspace(market.workspace(drafts=True, replace=(asset["id"], doc)))
    referenced = {d["at"].get("reference") for d in out}
    for d in analysis.analyse(ws):
        at = d.get("at") or {}
        if at.get("kind") != kind.lower() or at.get("code") != asset["code"]:
            continue
        if d["code"] in ("UNKNOWN_VARIABLE", "UNKNOWN_CONDITION", "UNKNOWN_PROFILE") and referenced:
            continue  # already said, more precisely, above
        out.append(d)
    return out


def blockers(diagnostics: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [dict(d) for d in diagnostics if d["severity"] == "BLOCKER"]


# --------------------------------------------------------------------------------------------------------- writing
def _event(
    db: Session, asset_id: Any, event: str, actor: Actor, *, version_id: Any = None, comment: str = "",
    detail: Mapping[str, Any] | None = None,
) -> None:  # fmt: skip
    db.execute(
        text(
            "INSERT INTO applicability_event (asset_id, version_id, event, actor_ref, comment, detail) "
            "VALUES (:a, :v, :e, :r, :c, CAST(:d AS jsonb))"
        ),
        {"a": asset_id, "v": version_id, "e": event, "r": _ref(actor), "c": comment.strip(), "d": json.dumps(dict(detail or {}))},
    )  # fmt: skip


def _deny(db: Session, actor: Actor, meta: RequestMeta | None, asset_id: Any, version_id: Any, rule: str, message: str) -> SurveyError:  # fmt: skip
    """An identity rule refused someone: the refusal is itself recorded (the caller commits it)."""
    _event(db, asset_id, "DENIED", actor, version_id=version_id, detail={"rule": rule})
    _audit(db, actor, meta, "APPLICABILITY.DENIED", ENTITY, asset_id, {"rule": rule}, outcome="DENIED")
    return SurveyError(403, rule, message)


def create(
    db: Session, markets: Sequence[str], market: str, kind: str, code: str, raw: Any, actor: Actor,
    meta: RequestMeta | None = None,
) -> uuid.UUID:  # fmt: skip
    if market not in markets:
        raise SurveyError(403, "MARKET_NOT_IN_SCOPE", "You cannot work with the applicability library of this market")
    if kind not in KINDS:
        raise _bad("UNKNOWN_KIND", "Choose a variable, a profile or a condition")
    if not CODE_RE.match(code or ""):
        raise _bad("INVALID_CODE", "A code starts with a letter and uses 2 to 60 letters, digits, '_', '-' or '.'")
    doc = normalise(kind, raw)
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"applicability:{market}:{kind}:{code.lower()}"}
    )
    if _one(
        db, "SELECT id FROM applicability_asset WHERE market_code = :m AND kind = :k AND lower(code) = lower(:c)",
        m=market, k=kind, c=code,
    ):  # fmt: skip
        raise SurveyError(409, "CODE_TAKEN", f"A {kind.lower()} with the code '{code}' already exists in this market")
    aid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO applicability_asset (id, market_code, kind, code, draft, draft_revision, draft_updated_at, "
            "draft_updated_by, created_by) VALUES (:i, :m, :k, :c, CAST(:d AS jsonb), 1, now(), :by, :by)"
        ),
        {"i": aid, "m": market, "k": kind, "c": code, "d": json.dumps(doc), "by": _ref(actor)},
    )
    _event(db, aid, "CREATED", actor, detail={"revision": 1})
    _audit(db, actor, meta, "APPLICABILITY.ASSET_CREATED", ENTITY, aid, {"market": market, "kind": kind, "code": code})
    return aid


def _stale(a: Mapping[str, Any], names: Mapping[str, str]) -> SurveyError:
    return SurveyError(
        409, "STALE_REVISION",
        "Someone saved this draft after you opened it. Nothing of yours was saved and nothing of theirs was overwritten",
        details=[{"current_revision": a["draft_revision"], "updated_by": names.get(str(a["draft_updated_by"]), "someone else")}],
    )  # fmt: skip


def _editable(db: Session, a: Mapping[str, Any]) -> None:
    if _one(db, "SELECT id FROM applicability_asset_version WHERE asset_id = :a AND status = ANY(:s)", a=a["id"], s=list(OPEN)):  # fmt: skip
        raise SurveyError(409, "CANDIDATE_OPEN", "This item is in review; its draft cannot change until it is returned, withdrawn or published")  # fmt: skip


def save(
    db: Session, markets: Sequence[str], asset_id: uuid.UUID, expected: int, raw: Any, actor: Actor,
    meta: RequestMeta | None = None,
) -> None:  # fmt: skip
    a = asset_row(db, asset_id, markets, lock=True)
    if a["draft"] is None:
        raise SurveyError(409, "NO_DRAFT", "There is no draft to save; start one from the published version")
    if expected != a["draft_revision"]:
        raise _stale(a, _names(db, [a["draft_updated_by"]]))
    _editable(db, a)
    doc = normalise(a["kind"], raw)
    db.execute(
        text(
            "UPDATE applicability_asset SET draft = CAST(:d AS jsonb), draft_revision = draft_revision + 1, "
            "draft_updated_at = now(), draft_updated_by = :by WHERE id = :i"
        ),
        {"d": json.dumps(doc), "by": _ref(actor), "i": asset_id},
    )
    _event(db, asset_id, "DRAFT_SAVED", actor, detail={"revision": a["draft_revision"] + 1})
    _audit(db, actor, meta, "APPLICABILITY.DRAFT_SAVED", ENTITY, asset_id, {"revision": a["draft_revision"] + 1})


def start_draft(
    db: Session, markets: Sequence[str], asset_id: uuid.UUID, version_no: int | None, actor: Actor,
    meta: RequestMeta | None = None,
) -> None:  # fmt: skip
    """A new draft from a published version (the latest unless one is named). Published versions are untouched."""
    a = asset_row(db, asset_id, markets, lock=True)
    if a["draft"] is not None:
        raise SurveyError(409, "DRAFT_EXISTS", "This item already has a draft")
    _editable(db, a)
    sql = VERSION_SQL + "WHERE v.asset_id = :a AND v.status = ANY(:s) "
    sql += "AND v.version_no = :n" if version_no is not None else "ORDER BY v.version_no DESC LIMIT 1"
    v = _one(db, sql, a=asset_id, s=list(WAS_PUBLISHED), n=version_no)
    if v is None:
        raise SurveyError(404, "NOT_FOUND", "There is no such published version to start from")
    db.execute(
        text(
            "UPDATE applicability_asset SET draft = CAST(:d AS jsonb), draft_revision = draft_revision + 1, "
            "draft_base_version_no = :n, draft_updated_at = now(), draft_updated_by = :by WHERE id = :i"
        ),
        {"d": json.dumps(v["document"]), "n": v["version_no"], "by": _ref(actor), "i": asset_id},
    )
    _event(db, asset_id, "DRAFT_STARTED", actor, detail={"from_version": v["version_no"], "revision": a["draft_revision"] + 1})  # fmt: skip
    _audit(db, actor, meta, "APPLICABILITY.DRAFT_STARTED", ENTITY, asset_id, {"from_version": v["version_no"]})


def discard_draft(
    db: Session, markets: Sequence[str], asset_id: uuid.UUID, expected: int, actor: Actor,
    meta: RequestMeta | None = None,
) -> None:  # fmt: skip
    a = asset_row(db, asset_id, markets, lock=True)
    if a["draft"] is None:
        raise SurveyError(409, "NO_DRAFT", "There is no draft to discard")
    if expected != a["draft_revision"]:
        raise _stale(a, _names(db, [a["draft_updated_by"]]))
    _editable(db, a)
    db.execute(
        text(
            "UPDATE applicability_asset SET draft = NULL, draft_revision = draft_revision + 1, "
            "draft_base_version_no = NULL, draft_updated_at = now(), draft_updated_by = :by WHERE id = :i"
        ),
        {"by": _ref(actor), "i": asset_id},
    )
    _event(db, asset_id, "DRAFT_DISCARDED", actor, detail={"revision": a["draft_revision"]})
    _audit(db, actor, meta, "APPLICABILITY.DRAFT_DISCARDED", ENTITY, asset_id, {"revision": a["draft_revision"]})


def submit(
    db: Session, markets: Sequence[str], asset_id: uuid.UUID, expected: int, note: str, actor: Actor,
    meta: RequestMeta | None = None, acknowledged: Sequence[Mapping[str, Any]] | None = None,
) -> uuid.UUID:  # fmt: skip
    """Freeze the saved draft as an immutable candidate, with the exact published versions it pins."""
    a = asset_row(db, asset_id, markets, lock=True)
    if a["draft"] is None:
        raise SurveyError(409, "NO_DRAFT", "There is no draft to submit")
    if expected != a["draft_revision"]:
        raise _stale(a, _names(db, [a["draft_updated_by"]]))
    _editable(db, a)
    market = Market(db, a["market_code"])
    doc = dict(a["draft"])
    found = blockers(validate(market, a, doc))
    if found:
        raise SurveyError(
            422, "NOT_VALID", "This draft cannot be submitted until its blockers are resolved", details=found
        )
    latest = market.latest(a)
    if latest is not None and latest["content_sha256"] == sha256_hex(doc):
        raise SurveyError(409, "NOTHING_CHANGED", "This draft is identical to the published version")
    pinned, _ = pins(market, a, doc)
    # Owner ruling A4: no surprising dependency upgrade. When the submitter says which exact versions they reviewed,
    # the candidate is frozen only if those are the versions it would pin now; otherwise nothing is submitted and the
    # difference is returned for them to look at again.
    if acknowledged is not None:
        seen = {(str(p.get("kind")), str(p.get("code")).lower(), p.get("version_no")) for p in acknowledged}
        now = {(p["kind"], p["code"].lower(), p["version_no"]) for p in pinned}
        if seen != now:
            raise SurveyError(
                409, "PINS_CHANGED",
                "What this draft would pin is not what you reviewed: a newer version of something it reads was published. Review the exact versions again before submitting",
                details=[{"would_pin": pinned, "reviewed": sorted(f"{k.lower()} {c} v{v}" for k, c, v in seen)}],
            )  # fmt: skip
    manifest = {
        "contract": MANIFEST_CONTRACT, "evaluator": CONTRACT, "market": a["market_code"], "kind": a["kind"],
        "code": a["code"], "content_sha256": sha256_hex(doc), "pins": pinned,
    }  # fmt: skip
    vid = uuid.uuid4()
    number = db.execute(
        text("SELECT coalesce(max(candidate_no), 0) + 1 FROM applicability_asset_version WHERE asset_id = :a"),
        {"a": asset_id},
    ).scalar_one()
    db.execute(
        text(
            "INSERT INTO applicability_asset_version (id, asset_id, candidate_no, status, document, manifest, "
            "content_sha256, manifest_sha256, draft_revision, note, submitted_by) VALUES (:i, :a, :n, 'SUBMITTED', "
            "CAST(:d AS jsonb), CAST(:m AS jsonb), :c, :ms, :r, :note, :by)"
        ),
        {
            "i": vid, "a": asset_id, "n": number, "d": json.dumps(doc), "m": json.dumps(manifest),
            "c": manifest["content_sha256"], "ms": sha256_hex(manifest), "r": a["draft_revision"],
            "note": note.strip(), "by": _ref(actor),
        },
    )  # fmt: skip
    for p in pinned:
        db.execute(
            text("INSERT INTO applicability_asset_dependency (version_id, depends_on_version_id) VALUES (:v, :d)"),
            {"v": vid, "d": uuid.UUID(p["version_id"])},
        )
    _event(db, asset_id, "SUBMITTED", actor, version_id=vid, comment=note, detail={"candidate": number, "revision": a["draft_revision"]})  # fmt: skip
    _audit(db, actor, meta, "APPLICABILITY.SUBMITTED", ENTITY, asset_id, {"candidate": str(vid), "sha256": manifest["content_sha256"], "pins": len(pinned)})  # fmt: skip
    return vid


def decide(
    db: Session, markets: Sequence[str], version_id: uuid.UUID, verdict: str, comment: str, actor: Actor,
    meta: RequestMeta | None = None,
) -> None:  # fmt: skip
    v = version_row(db, version_id, markets, lock=True)
    if v["status"] != "SUBMITTED":
        raise SurveyError(409, "NOT_SUBMITTED", "This candidate is not waiting for a decision")
    if _ref(actor) == v["submitted_by"]:
        raise _deny(db, actor, meta, v["asset_id"], version_id, "SELF_REVIEW_DENIED", "The person who submitted a candidate cannot approve or return it")  # fmt: skip
    if verdict == "RETURN" and len(comment.strip()) < 10:
        raise _bad("COMMENT_REQUIRED", "Returning a candidate needs a comment of at least 10 characters")
    status = "APPROVED" if verdict == "APPROVE" else "RETURNED"
    db.execute(
        text(
            "UPDATE applicability_asset_version SET status = :s, decided_by = :by, decided_at = now(), "
            "decision_comment = :c WHERE id = :i"
        ),
        {"s": status, "by": _ref(actor), "c": comment.strip(), "i": version_id},
    )
    _event(db, v["asset_id"], status, actor, version_id=version_id, comment=comment)
    _audit(db, actor, meta, f"APPLICABILITY.{status}", ENTITY, v["asset_id"], {"candidate": str(version_id)})


def withdraw(
    db: Session, markets: Sequence[str], version_id: uuid.UUID, reason: str, actor: Actor,
    meta: RequestMeta | None = None,
) -> None:  # fmt: skip
    """The submitter takes an open candidate back; the draft becomes editable again."""
    v = version_row(db, version_id, markets, lock=True)
    if v["status"] not in OPEN:
        raise SurveyError(409, "NOT_OPEN", "This candidate is closed")
    if _ref(actor) != v["submitted_by"]:
        raise SurveyError(403, "NOT_SUBMITTER", "Only the person who submitted a candidate can withdraw it")
    db.execute(text("UPDATE applicability_asset_version SET status = 'WITHDRAWN' WHERE id = :i"), {"i": version_id})
    _event(db, v["asset_id"], "WITHDRAWN", actor, version_id=version_id, comment=reason)
    _audit(db, actor, meta, "APPLICABILITY.WITHDRAWN", ENTITY, v["asset_id"], {"candidate": str(version_id), "was": v["status"]})  # fmt: skip


def publish(
    db: Session, markets: Sequence[str], version_id: uuid.UUID, actor: Actor, meta: RequestMeta | None = None
) -> None:
    v = version_row(db, version_id, markets, lock=True)
    a = asset_row(db, v["asset_id"], markets, lock=True)
    if v["status"] != "APPROVED":
        raise SurveyError(409, "NOT_APPROVED", "Only an approved candidate can be published")
    me = _ref(actor)
    if me in (v["submitted_by"], v["decided_by"]):
        rule = "SELF_PUBLISH_DENIED" if me == v["submitted_by"] else "APPROVER_PUBLISH_DENIED"
        raise _deny(db, actor, meta, a["id"], version_id, rule, "The submitter and the approver of a candidate cannot publish it: a third person must")  # fmt: skip
    # everything it pins is checked again at the moment it takes effect: still published, still exactly what was pinned
    for p in v["manifest"].get("pins") or []:
        row = _one(db, "SELECT status, content_sha256 FROM applicability_asset_version WHERE id = :i", i=uuid.UUID(p["version_id"]))  # fmt: skip
        if row is None or row["status"] not in WAS_PUBLISHED or row["content_sha256"] != p["content_sha256"]:
            raise SurveyError(409, "DEPENDENCY_CHANGED", f"The {p['kind'].lower()} '{p['code']}' it pins is no longer a published version")  # fmt: skip
    previous = _one(db, "SELECT id, version_no FROM applicability_asset_version WHERE asset_id = :a AND status = 'PUBLISHED'", a=a["id"])  # fmt: skip
    number = db.execute(
        text("SELECT coalesce(max(version_no), 0) + 1 FROM applicability_asset_version WHERE asset_id = :a"),
        {"a": a["id"]},
    ).scalar_one()
    if previous:
        db.execute(text("UPDATE applicability_asset_version SET status = 'SUPERSEDED' WHERE id = :i"), {"i": previous["id"]})  # fmt: skip
        _event(db, a["id"], "SUPERSEDED", actor, version_id=previous["id"], comment=f"superseded by version {number}")
    db.execute(
        text(
            "UPDATE applicability_asset_version SET status = 'PUBLISHED', version_no = :n, published_by = :by, "
            "published_at = now() WHERE id = :i"
        ),
        {"n": number, "by": me, "i": version_id},
    )
    # the draft it was frozen from is now the published version; a draft saved since (none can be: it was locked) stays
    db.execute(
        text(
            "UPDATE applicability_asset SET draft = NULL, draft_revision = draft_revision + 1, "
            "draft_base_version_no = NULL WHERE id = :i AND draft_revision = :r"
        ),
        {"i": a["id"], "r": v["draft_revision"]},
    )
    _event(db, a["id"], "PUBLISHED", actor, version_id=version_id, detail={"version": number})
    _audit(db, actor, meta, "APPLICABILITY.PUBLISHED", ENTITY, a["id"], {"version": number, "candidate": str(version_id), "sha256": v["content_sha256"], "manifest_sha256": v["manifest_sha256"]})  # fmt: skip


# ----------------------------------------------------------------------------------------------------- presenting
def _version_out(v: Mapping[str, Any], names: Mapping[str, str], me: str) -> dict[str, Any]:
    return {
        "id": str(v["id"]), "candidate_no": v["candidate_no"], "version_no": v["version_no"], "status": v["status"],
        "document": v["document"], "pins": v["manifest"].get("pins") or [], "content_sha256": v["content_sha256"],
        "manifest_sha256": v["manifest_sha256"], "note": v["note"], "draft_revision": v["draft_revision"],
        "submitted_by": names.get(v["submitted_by"], v["submitted_by"]), "submitted_at": v["submitted_at"],
        "decided_by": names.get(v["decided_by"] or "", v["decided_by"]), "decided_at": v["decided_at"],
        "decision_comment": v["decision_comment"],
        "published_by": names.get(v["published_by"] or "", v["published_by"]), "published_at": v["published_at"],
        "is_submitter": v["submitted_by"] == me, "is_approver": v["decided_by"] == me,
    }  # fmt: skip


def _who(versions: Sequence[Mapping[str, Any]], assets: Sequence[Mapping[str, Any]]) -> list[Any]:
    out: list[Any] = [a["draft_updated_by"] for a in assets] + [a["created_by"] for a in assets]
    for v in versions:
        out += [v["submitted_by"], v["decided_by"], v["published_by"]]
    return out


def summary(market: Market, a: Mapping[str, Any], names: Mapping[str, str], me: str) -> dict[str, Any]:
    latest, opened = market.latest(a), market.open(a)
    returned = [v for v in market.versions.get(a["id"], []) if v["status"] == "RETURNED"]
    every = market.versions.get(a["id"], [])
    last_status = every[-1]["status"] if every else None
    state = (
        "IN_REVIEW" if opened and opened["status"] == "SUBMITTED"
        else "APPROVED" if opened
        else "RETURNED" if a["draft"] is not None and last_status == "RETURNED"
        else "DRAFT" if a["draft"] is not None
        else "PUBLISHED" if latest
        else "EMPTY"
    )  # fmt: skip
    doc = a["draft"] or (latest["document"] if latest else {})
    return {
        "id": str(a["id"]), "market_code": a["market_code"], "kind": a["kind"], "code": a["code"],
        "name": doc.get("name") or a["code"], "state": state,
        "draft": None if a["draft"] is None else {
            "document": a["draft"], "revision": a["draft_revision"], "base_version_no": a["draft_base_version_no"],
            "updated_at": a["draft_updated_at"], "updated_by": names.get(str(a["draft_updated_by"]), None),
            "locked": opened is not None,
        },
        "draft_revision": a["draft_revision"],
        "candidate": _version_out(opened, names, me) if opened else None,
        "published": _version_out(latest, names, me) if latest else None,
        "returned": _version_out(returned[-1], names, me) if state == "RETURNED" and returned else None,
        "published_versions": len(market.published(a)),
    }  # fmt: skip


def listing(db: Session, markets: Sequence[str], me: str, kind: str | None = None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for code in markets:
        market = Market(db, code)
        names = _names(db, _who([v for vs in market.versions.values() for v in vs], market.assets))
        for a in market.assets:
            if kind and a["kind"] != kind:
                continue
            item = summary(market, a, names, me)
            if item["state"] != "EMPTY":  # a discarded first draft that was never submitted leaves nothing to show
                out.append(item)
    return out


def used_by(db: Session, market: Market, a: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Where this item is used: published versions that pin it (exactly), and drafts that refer to it (by code)."""
    out: list[dict[str, Any]] = []
    rows = _all(
        db,
        "SELECT DISTINCT ua.kind, ua.code, uv.version_no, uv.status, uv.candidate_no, uv.document->>'name' AS name, "
        "dv.version_no AS pinned FROM applicability_asset_dependency d "
        "JOIN applicability_asset_version dv ON dv.id = d.depends_on_version_id "
        "JOIN applicability_asset_version uv ON uv.id = d.version_id "
        "JOIN applicability_asset ua ON ua.id = uv.asset_id WHERE dv.asset_id = :a AND uv.status = ANY(:s) "
        "ORDER BY ua.kind, ua.code, uv.version_no",
        a=a["id"], s=[*WAS_PUBLISHED, *OPEN],
    )  # fmt: skip
    for r in rows:
        out.append(
            {
                "kind": r["kind"], "code": r["code"], "name": r["name"] or r["code"], "pinned_version": r["pinned"],
                "state": "PUBLISHED" if r["status"] == "PUBLISHED" else "EARLIER_VERSION" if r["status"] == "SUPERSEDED" else "IN_REVIEW",
                "version_no": r["version_no"],
            }
        )  # fmt: skip
    for other in market.assets:
        if other["id"] == a["id"] or other["draft"] is None:
            continue
        if any(
            k == a["kind"] and c.lower() == a["code"].lower() for k, c, _ in references(other["kind"], other["draft"])
        ):
            out.append(
                {
                    "kind": other["kind"], "code": other["code"], "name": other["draft"].get("name") or other["code"],
                    "pinned_version": None, "state": "DRAFT", "version_no": None,
                }
            )  # fmt: skip
    return out


def detail(db: Session, markets: Sequence[str], asset_id: uuid.UUID, me: str) -> dict[str, Any]:
    a = asset_row(db, asset_id, markets)
    market = Market(db, a["market_code"])
    a = next(x for x in market.assets if x["id"] == a["id"])
    versions = market.versions.get(a["id"], [])
    events = _all(
        db,
        "SELECT e.seq, e.event, e.actor_ref, e.comment, e.detail, e.occurred_at, e.version_id, p.display_name "
        "FROM applicability_event e LEFT JOIN principal p ON CAST(p.id AS text) = e.actor_ref "
        "WHERE e.asset_id = :a ORDER BY e.seq",
        a=a["id"],
    )
    names = _names(db, _who(versions, [a]))
    out = summary(market, a, names, me)
    out["versions"] = [_version_out(v, names, me) for v in versions]
    out["events"] = [
        {
            "seq": e["seq"], "event": e["event"], "actor": e["display_name"] or e["actor_ref"], "comment": e["comment"],
            "detail": e["detail"], "occurred_at": e["occurred_at"],
            "version_id": str(e["version_id"]) if e["version_id"] else None,
        }
        for e in events
    ]  # fmt: skip
    out["used_by"] = used_by(db, market, a)
    doc = a["draft"] if a["draft"] is not None else (market.latest(a) or {}).get("document")
    out["diagnostics"] = validate(market, a, doc) if doc else []
    # a published version keeps what it pinned; say so when something it pins has moved on
    out["newer_pins"] = []
    latest = market.latest(a)
    for p in (latest or {}).get("manifest", {}).get("pins") or []:
        other = market.find(p["kind"], p["code"])
        current = market.latest(other) if other else None
        if current and current["version_no"] != p["version_no"]:
            out["newer_pins"].append({**p, "current_version_no": current["version_no"]})
    return out


def test_expression(
    db: Session, market_code: str, expr: Mapping[str, Any], facts: Mapping[str, Any], profiles: Sequence[str] | None,
    *, drafts: bool,
) -> dict[str, Any]:  # fmt: skip
    """TRUE / FALSE / UNKNOWN for one expression against the PERSISTED library, by the one Python evaluator."""
    market = Market(db, market_code)
    ws = Workspace(market.workspace(drafts=drafts))
    out: list[dict[str, Any]] = []
    analysis.check_expr(ws, dict(expr), {"kind": "expression"}, out)
    ev = Evaluation(ws, dict(facts), list(profiles or []) or None)
    trace = ev.expr(dict(expr), "")
    return {"result": trace["result"], "trace": trace, "facts": dict(ev._states), "diagnostics": out}  # noqa: SLF001
