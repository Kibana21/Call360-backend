# ruff: noqa: E501 — messages and SQL are kept one per line
"""APPL-X3 — persistent Applicability Policies: one saved working draft per policy, and the exact dependencies it means.

A policy is ONE document (scope, requirements, conditions, survey-selection actions, delivery order). What it is saved
against is recorded with it and never moves by itself:

* a reusable condition is named in the document at an exact version (as before);
* every variable and profile the policy reads — directly, through a condition, or through a derived variable — is
  PINNED in the document (``pins``) at an exact published version, or at an exact draft revision when it is not
  published yet;
* every survey is an exact published Survey Studio version (id and both fingerprints).

``resolve`` turns a document into the workspace the evaluator reads, built from EXACTLY those pins — never from
"the latest" — and into the snapshot (dependency manifest) that is stored with the draft and mirrored as rows.
Saving, inspecting, previewing and evaluating all go through it, and all use the one Python evaluator.

Publication of policies is not here (APPL-X4). No assignment rule, survey binding or requirement group is read or
written, and nothing selects a survey for a real case.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta
from app.domain.survey.applicability import analysis
from app.domain.survey.applicability import evaluator as ev_
from app.domain.survey.applicability import library as lib
from app.domain.survey.applicability.logic import CONTRACT, ApplicabilityError, Workspace
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.store import STATUS_OF_EVENT, SurveyError, _all, _audit, _one, _ref

ENTITY = "applicability_policy"
SNAPSHOT_CONTRACT = "call360.applicability-policy-snapshot/1"
MAX_DOCUMENT = 600_000
FIELDS = ("name", "description", "profiles", "scope", "shared_deliveries", "requirements", "order", "pins")
_BAD = (ApplicabilityError, AttributeError, KeyError, TypeError, ValueError)
POLICY_SQL = (
    "SELECT p.id, p.market_code, p.code, p.document, p.snapshot, p.document_sha256, p.snapshot_sha256, p.draft_revision, "
    "p.draft_updated_at, p.draft_updated_by, p.archived_at, p.created_at, p.created_by FROM applicability_policy p "
)


def _bad(code: str, message: str, status: int = 422, details: list[dict[str, Any]] | None = None) -> SurveyError:
    return SurveyError(status, code, message, details)


def _d(severity: str, code: str, message: str, /, **at: Any) -> dict[str, Any]:
    return {"severity": severity, "code": code, "message": message, "at": at}


# ------------------------------------------------------------------------------------------------------ documents
def normalise(raw: Any) -> dict[str, Any]:
    """The stored document: the policy's own fields only. Identity (market, code) and the revision are the row's."""
    if not isinstance(raw, Mapping):
        raise _bad("INVALID_DOCUMENT", "The policy must be an object")
    name = raw.get("name")
    if not isinstance(name, str) or len(name.strip()) < 2 or len(name) > 200:
        raise _bad("NAME_REQUIRED", "Give the policy a name of 2 to 200 characters")
    doc: dict[str, Any] = {"name": name.strip(), "description": str(raw.get("description") or "").strip()}
    for key in ("profiles", "order"):
        value = raw.get(key) or []
        if not isinstance(value, list):
            raise _bad("INVALID_DOCUMENT", f"'{key}' must be a list")
        doc[key] = [str(x) for x in value]
    scope = raw.get("scope")
    if scope is not None and not isinstance(scope, Mapping):
        raise _bad("INVALID_DOCUMENT", "The scope must be a condition or nothing")
    doc["scope"] = dict(scope) if scope else None
    for key in ("shared_deliveries", "requirements"):
        value = raw.get(key) or []
        if not isinstance(value, list) or not all(isinstance(x, Mapping) for x in value):
            raise _bad("INVALID_DOCUMENT", f"'{key}' must be a list of objects")
        doc[key] = [dict(x) for x in value]
    ids = [str(r.get("id") or "") for r in doc["requirements"]]
    if any(not i for i in ids) or len(set(ids)) != len(ids):
        raise _bad("INVALID_DOCUMENT", "Every requirement needs an identifier of its own")
    pins = raw.get("pins") or []
    if not isinstance(pins, list) or not all(isinstance(x, Mapping) for x in pins):
        raise _bad("INVALID_DOCUMENT", "'pins' must be a list of objects")
    doc["pins"] = [
        {"kind": str(p.get("kind")), "code": str(p.get("code")), **({"version": int(p["version"])} if p.get("version") is not None else {"draft_revision": int(p["draft_revision"])} if p.get("draft_revision") is not None else {})}
        for p in pins
    ]  # fmt: skip
    if len(json.dumps(doc)) > MAX_DOCUMENT:
        raise _bad("DOCUMENT_TOO_LARGE", "This policy is too large to save as one document")
    return doc


def evaluator_document(policy: Mapping[str, Any], doc: Mapping[str, Any]) -> dict[str, Any]:
    """The document as the evaluator reads it. The pins are not part of it: they decide the workspace instead."""
    out = {k: v for k, v in doc.items() if k != "pins"}
    return {**out, "code": policy["code"], "market": policy["market_code"], "version": 1, "status": "DRAFT"}


def _surveys_of(doc: Mapping[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for r in doc.get("requirements") or []:
        action = r.get("action") or {}
        refs = action.get("surveys") or [a.get("survey") for a in action.get("alternatives") or []]
        out.extend((str(r.get("id")), dict(s)) for s in refs if isinstance(s, Mapping))
    return out


# ------------------------------------------------------------------------------------------------------ resolution
class Resolution:
    """One document resolved against EXACTLY what it pins: the evaluator's workspace, the dependency entries, what
    each requirement depends on, and everything that is wrong or worth knowing about those dependencies."""

    def __init__(self) -> None:
        self.workspace: dict[str, list[Any]] = {"variables": [], "profiles": [], "conditions": []}
        self.entries: list[dict[str, Any]] = []
        self.diagnostics: list[dict[str, Any]] = []
        self.pins: list[dict[str, Any]] = []
        self.requirements: dict[str, dict[str, list[str]]] = {}
        self.invalid: list[dict[str, Any]] = []

    @property
    def stale(self) -> list[dict[str, Any]]:
        return [e for e in self.entries if e.get("stale")]

    @property
    def unpublished(self) -> list[dict[str, Any]]:
        return [e for e in self.entries if e["state"] == "DRAFT"]

    def snapshot(self) -> dict[str, Any]:
        """The dependency manifest that is stored: identities and fingerprints only, nothing that changes by itself."""
        keep = ("kind", "code", "state", "asset_id", "version_id", "version_no", "draft_revision", "content_sha256",
                "manifest_sha256", "definition_id", "label", "market")  # fmt: skip
        rows = [{k: e[k] for k in keep if e.get(k) is not None} for e in self.entries]
        rows.sort(key=lambda e: (e["kind"], e["code"].lower(), e.get("version_no") or 0, e.get("draft_revision") or 0))
        return {"contract": SNAPSHOT_CONTRACT, "evaluator": CONTRACT, "dependencies": rows}


def resolve(db: Session, market: lib.Market, doc: Mapping[str, Any], previous: Mapping[str, Any] | None = None) -> Resolution:  # fmt: skip
    """``previous``: the stored snapshot, from which a draft pin that has since moved keeps the fingerprint it had."""
    out = Resolution()
    pinned = {(p["kind"], p["code"].lower()): p for p in doc.get("pins") or []}
    before = {(e["kind"], e["code"].lower(), e.get("draft_revision")): e for e in (previous or {}).get("dependencies") or [] if e.get("state") == "DRAFT"}  # fmt: skip
    taken: dict[tuple[str, str, Any], dict[str, Any] | None] = {}
    docs: dict[tuple[str, str, Any], dict[str, Any]] = {}

    def invalid(kind: str, code: str, message: str, where: str) -> None:
        d = _d("BLOCKER", "INVALID_DEPENDENCY_PIN", message, kind=kind.lower(), code=code, requirement=where)
        out.invalid.append(d)
        out.diagnostics.append(d)

    def take(kind: str, code: str, version: Any, where: str) -> dict[str, Any] | None:
        """The exact definition of one dependency, as pinned. Never the latest unless nothing was pinned yet."""
        asset = market.find(kind, code)
        if asset is None:
            if (kind, code.lower(), "missing") not in taken:
                taken[(kind, code.lower(), "missing")] = None
                out.diagnostics.append(
                    _d(
                        "BLOCKER",
                        "UNKNOWN_REFERENCE",
                        f"The {kind.lower()} '{code}' does not exist in market {market.market}",
                        kind=kind.lower(),
                        code=code,
                        requirement=where,
                    )
                )
            return None
        done = market.published(asset)
        latest = done[-1]["version_no"] if done else 0
        pin = pinned.get((kind, code.lower())) or {}
        want_version = version if kind == "CONDITION" else pin.get("version")
        want_draft = pin.get("draft_revision")
        if kind == "CONDITION" and want_version is None:
            invalid(kind, code, f"The reference to the condition '{code}' names no version", where)
            return None
        target = next((v for v in done if v["version_no"] == want_version), None) if want_version is not None else None
        # a condition that was pinned as a DRAFT and has since been published under the same number is not silently
        # read as that published version: what was pinned was a draft revision, and it is reported as changed
        since_published = kind == "CONDITION" and want_draft is not None and target is not None
        if since_published:
            target = None
        entry: dict[str, Any]
        if target is not None:
            key = (kind, code.lower(), ("v", target["version_no"]))
            if key in taken:
                return docs.get(key)
            entry = {
                "kind": kind, "code": asset["code"], "state": "PUBLISHED", "asset_id": str(asset["id"]),
                "version_id": str(target["id"]), "version_no": target["version_no"], "content_sha256": target["content_sha256"],
                "manifest_sha256": target["manifest_sha256"], "name": target["document"].get("name") or asset["code"],
            }  # fmt: skip
            if latest > target["version_no"]:
                entry["newer_version_no"] = latest
            definition = dict(target["document"])
            entry["pins"] = target["manifest"].get("pins") or []
        else:
            draft_version = latest + 1
            is_draft_ref = kind == "CONDITION" and (want_version == draft_version or since_published)
            if kind != "CONDITION" and want_version is not None:
                invalid(kind, code, f"The {kind.lower()} '{code}' has no published version {want_version}", where)
                return None
            if kind == "CONDITION" and not is_draft_ref:
                invalid(kind, code, f"The condition '{code}' has no published version {want_version}", where)
                return None
            if want_draft is None and kind != "CONDITION" and done:
                # nothing was pinned yet for this item: the published version current NOW becomes the stated intent
                return take_published(kind, asset, done[-1], where)
            revision = want_draft if want_draft is not None else asset["draft_revision"]
            key = (kind, code.lower(), ("d", revision))
            if key in taken:
                return docs.get(key)
            current = asset["draft"]
            if current is None and want_draft is None:
                invalid(kind, code, f"The {kind.lower()} '{code}' has neither a published version nor a draft", where)
                return None
            stale = since_published or current is None or asset["draft_revision"] != revision
            kept = before.get((kind, code.lower(), revision))
            if stale and kept is None:
                invalid(kind, code, f"The {kind.lower()} '{code}' has no draft revision {revision}", where)
                return None
            entry = {
                "kind": kind, "code": asset["code"], "state": "DRAFT", "asset_id": str(asset["id"]), "draft_revision": revision,
                "content_sha256": kept["content_sha256"] if stale and kept else sha256_hex(current),
                "name": (current or {}).get("name") or asset["code"],
            }  # fmt: skip
            if stale:
                entry["stale"] = True
                entry["current_draft_revision"] = asset["draft_revision"] if current is not None else None
            if done:
                entry["published_version_no"] = latest
            definition = dict(current or {})
            if kind == "CONDITION":
                entry["version_no"] = want_version  # the number the document's reference uses for the draft
        taken[key] = entry
        out.entries.append(entry)
        definition = {
            **definition,
            "code": asset["code"],
            "status": entry["state"],
            "version": entry.get("version_no") or (latest + 1),
        }
        docs[key] = definition
        if kind == "VARIABLE":
            definition["markets"] = [market.market]
            walk((definition.get("derived") or {}).get("expr"), where)
        elif kind == "CONDITION":
            walk(definition.get("expr"), where)
        elif kind == "PROFILE":
            for parent in definition.get("extends") or []:
                take("PROFILE", str(parent), None, where)
        return definition

    def take_published(
        kind: str, asset: Mapping[str, Any], target: Mapping[str, Any], where: str
    ) -> dict[str, Any] | None:
        pinned[(kind, asset["code"].lower())] = {"kind": kind, "code": asset["code"], "version": target["version_no"]}
        return take(kind, asset["code"], None, where)

    def note(where: str, kind: str, code: str) -> None:
        bucket = out.requirements.setdefault(where, {"conditions": [], "variables": [], "profiles": []})
        key = {"CONDITION": "conditions", "VARIABLE": "variables", "PROFILE": "profiles"}[kind]
        if code not in bucket[key]:
            bucket[key].append(code)

    def walk(node: Any, where: str, depth: int = 0) -> None:
        if not isinstance(node, Mapping) or depth > 80:
            return
        op = node.get("op")
        if op in ("all", "any"):
            for a in node.get("args") or []:
                walk(a, where, depth + 1)
        elif op == "not":
            walk(node.get("arg"), where, depth + 1)
        elif op == "test" and node.get("variable"):
            note(where, "VARIABLE", str(node["variable"]))
            take("VARIABLE", str(node["variable"]), None, where)
        elif op == "ref" and node.get("condition"):
            note(where, "CONDITION", f"{node['condition']}@{node.get('version')}")
            take("CONDITION", str(node["condition"]), node.get("version"), where)

    walk(doc.get("scope"), "scope")
    for r in doc.get("requirements") or []:
        rid = str(r.get("id"))
        out.requirements.setdefault(rid, {"conditions": [], "variables": [], "profiles": []})
        walk(r.get("when"), rid)
        for a in (r.get("action") or {}).get("alternatives") or []:
            walk(a.get("when"), rid)
    for code in doc.get("profiles") or []:
        note("policy", "PROFILE", str(code))
        take("PROFILE", str(code), None, "policy")

    # ---- the workspace: exactly the pinned definitions
    by_condition: dict[str, list[dict[str, Any]]] = {}
    for key, definition in docs.items():
        if key[0] == "VARIABLE":
            out.workspace["variables"].append(definition)
        elif key[0] == "PROFILE":
            out.workspace["profiles"].append(definition)
        else:
            by_condition.setdefault(definition["code"], []).append(definition)
    for versions in by_condition.values():
        versions.sort(key=lambda c: c["version"])
        out.workspace["conditions"].append(
            {**versions[-1], "history": [{"version": c["version"], "expr": c.get("expr")} for c in versions[:-1]]}
        )
    # A scenario may name a profile the policy does not: those are scenario input, read at their published version.
    have = {p["code"] for p in out.workspace["profiles"]}
    for a in market.assets:
        if a["kind"] == "PROFILE" and a["code"] not in have and (v := market.latest(a)):
            out.workspace["profiles"].append(
                {
                    **v["document"],
                    "code": a["code"],
                    "version": v["version_no"],
                    "status": "PUBLISHED",
                    "scenario_context": True,
                }
            )

    # ---- the pins as the document should carry them: every variable and profile it reads, and every draft condition
    for e in out.entries:
        if e["state"] == "DRAFT":
            out.pins.append({"kind": e["kind"], "code": e["code"], "draft_revision": e["draft_revision"]})
        elif e["kind"] != "CONDITION":
            out.pins.append({"kind": e["kind"], "code": e["code"], "version": e["version_no"]})
    out.pins.sort(key=lambda p: (p["kind"], p["code"].lower()))

    _surveys(db, market.market, doc, out)
    _dependency_diagnostics(doc, out)
    return out


def _surveys(db: Session, market: str, doc: Mapping[str, Any], out: Resolution) -> None:
    """Every survey reference must be an exact PUBLISHED Survey Studio version of this market, with its fingerprints."""
    refs = _surveys_of(doc)
    ids: list[uuid.UUID] = []
    for _, s in refs:
        if s.get("version_id"):
            try:
                ids.append(uuid.UUID(str(s["version_id"])))
            except ValueError:
                pass
    rows = {
        str(r["id"]): r
        for r in _all(
            db,
            "SELECT v.id, v.version_no, v.label, v.survey_definition_id, d.code, d.market_code, "
            f"{'d.artifact_kind'} AS kind, c.content_sha256, c.manifest_sha256, "
            "(SELECT e.event FROM survey_lifecycle_event e WHERE e.subject_id = v.id ORDER BY e.seq DESC LIMIT 1) AS event, "
            "(SELECT max(v2.version_no) FROM survey_version v2 WHERE v2.survey_definition_id = v.survey_definition_id) AS latest_no "
            "FROM survey_version v JOIN survey_definition d ON d.id = v.survey_definition_id "
            "JOIN survey_candidate c ON c.id = v.candidate_id WHERE v.id = ANY(:ids)",
            ids=ids,
        )
    } if ids else {}  # fmt: skip
    seen: set[str] = set()
    for rid, s in refs:
        code = str(s.get("code") or "")
        if not s.get("version_id"):
            continue  # not pinned yet: the evaluator's own analysis reports it (SURVEY_NOT_PINNED)
        row = rows.get(str(s["version_id"]))
        status = STATUS_OF_EVENT.get(str(row["event"])) if row else None
        why = (
            "Survey Studio has no such published version" if row is None or row["market_code"] != market  # another market's survey does not exist here
            else "that is a module, not a survey" if row["kind"] != "SURVEY"
            else "it is not a published version" if status not in ("PUBLISHED", "SUPERSEDED")
            else "its code is not the survey's" if row["code"] != code
            else "its version number is not that version's" if row["version_no"] != s.get("version")
            else "its content fingerprint is not that version's" if row["content_sha256"] != s.get("fingerprint")
            else "its manifest fingerprint is not that version's" if s.get("manifest") and row["manifest_sha256"] != s.get("manifest")
            else None
        )  # fmt: skip
        if why:
            d = _d(
                "BLOCKER",
                "INVALID_SURVEY_REFERENCE",
                f"The reference to the survey '{code}' cannot be used: {why}",
                kind="survey",
                code=code,
                requirement=rid,
            )
            out.invalid.append(d)
            out.diagnostics.append(d)
            continue
        assert row is not None
        out.requirements.setdefault(rid, {"conditions": [], "variables": [], "profiles": []}).setdefault(
            "surveys", []
        ).append(code)
        if str(row["id"]) in seen:
            continue
        seen.add(str(row["id"]))
        entry = {
            "kind": "SURVEY", "code": row["code"], "state": "PUBLISHED", "definition_id": str(row["survey_definition_id"]),
            "version_id": str(row["id"]), "version_no": row["version_no"], "label": row["label"], "market": row["market_code"],
            "content_sha256": row["content_sha256"], "manifest_sha256": row["manifest_sha256"], "name": str(s.get("name") or row["code"]),
            "survey_status": status,
        }  # fmt: skip
        if row["latest_no"] and row["latest_no"] > row["version_no"]:
            entry["newer_version_no"] = row["latest_no"]
        out.entries.append(entry)


def _dependency_diagnostics(doc: Mapping[str, Any], out: Resolution) -> None:
    """What a person must know about the dependencies, each tied to the requirements it concerns."""

    def where(e: Mapping[str, Any]) -> list[str]:
        key = {"CONDITION": "conditions", "VARIABLE": "variables", "PROFILE": "profiles", "SURVEY": "surveys"}[
            e["kind"]
        ]
        return sorted(
            r
            for r, deps in out.requirements.items()
            if any(str(x).split("@")[0] == e["code"] for x in deps.get(key, []))
        )

    for e in out.entries:
        word, at = e["kind"].lower(), {"kind": e["kind"].lower(), "code": e["code"], "requirements": where(e)}
        if e.get("stale"):
            now = (
                f"it is now at draft revision {e['current_draft_revision']}"
                if e.get("current_draft_revision")
                else "that draft no longer exists"
            )
            also = f"; version {e['published_version_no']} is published" if e.get("published_version_no") else ""
            out.diagnostics.append(
                _d(
                    "BLOCKER",
                    "STALE_DEPENDENCY",
                    f"The {word} '{e['name']}' was changed after this policy was saved against its draft revision {e['draft_revision']}: {now}{also}. Review it and accept the change before relying on a new result",
                    **at,
                )
            )
        elif e["state"] == "DRAFT":
            out.diagnostics.append(
                _d(
                    "WARNING",
                    "UNPUBLISHED_DEPENDENCY",
                    f"The {word} '{e['name']}' is a draft (revision {e['draft_revision']}), not a published version",
                    **at,
                )
            )
        if e.get("newer_version_no"):
            code = "SURVEY_NEWER_VERSION" if e["kind"] == "SURVEY" else "NEWER_VERSION"
            out.diagnostics.append(
                _d(
                    "INFO",
                    code,
                    f"The {word} '{e['name']}' is pinned at version {e.get('label') or e['version_no']}; version {e['newer_version_no']} is now published. Nothing changes until you adopt it",
                    **at,
                )
            )
    # a published condition says which variable versions it was published against; the policy evaluates one version of each
    chosen = {e["code"].lower(): e for e in out.entries if e["kind"] == "VARIABLE"}
    for e in out.entries:
        if e["kind"] == "PROFILE":
            continue  # a profile only lists variables; which version it listed changes no result
        for p in e.get("pins") or []:
            mine = chosen.get(str(p["code"]).lower()) if p["kind"] == "VARIABLE" else None
            if mine and (mine["state"] != "PUBLISHED" or mine["version_no"] != p["version_no"]):
                now = (
                    f"version {mine['version_no']}"
                    if mine["state"] == "PUBLISHED"
                    else f"draft revision {mine['draft_revision']}"
                )
                out.diagnostics.append(
                    _d(
                        "INFO",
                        "PIN_DIFFERS",
                        f"The {e['kind'].lower()} '{e['name']}' version {e['version_no']} was published reading '{p['code']}' version {p['version_no']}; this policy evaluates '{p['code']}' at {now}",
                        kind=e["kind"].lower(),
                        code=e["code"],
                        variable=p["code"],
                        requirements=where(e),
                    )
                )
    # profiles organise facts; they never decide applicability — but a fact the policy reads from outside them is worth seeing
    if doc.get("profiles"):
        try:
            members, _ = Workspace(out.workspace).profile_variables([str(p) for p in doc["profiles"]])
        except ApplicabilityError:
            members = None
        if members is not None:
            for e in out.entries:
                if (
                    e["kind"] == "VARIABLE"
                    and e["code"] not in members
                    and not any(e["code"] == v.get("code") and v.get("derived") for v in out.workspace["variables"])
                ):
                    out.diagnostics.append(
                        _d(
                            "INFO",
                            "OUTSIDE_PROFILES",
                            f"'{e['name']}' is read by this policy and is not in its profiles. It is still read when given, and marked as coming from outside them",
                            kind="variable",
                            code=e["code"],
                            requirements=where(e),
                        )
                    )


def inspect(db: Session, policy: Mapping[str, Any], doc: Mapping[str, Any], previous: Mapping[str, Any] | None = None) -> dict[str, Any]:  # fmt: skip
    """Everything the server can say about one document, saved or not: pins, dependencies, diagnostics, readiness."""
    market = lib.Market(db, policy["market_code"])
    res = resolve(db, market, doc, previous)
    edoc = evaluator_document(policy, doc)
    diagnostics = list(res.diagnostics)
    fingerprint = None
    if not res.invalid:
        try:
            ws = Workspace(res.workspace)
            diagnostics += analysis.analyse(ws, edoc)
            diagnostics = [
                d
                for d in diagnostics
                if (d.get("at") or {}).get("kind") not in ("variable", "profile", "condition")
                or d["code"] in DEPENDENCY_CODES
            ]
            fingerprint = ev_.fingerprint(ws, edoc)
        except _BAD as exc:
            diagnostics.append(
                _d(
                    "BLOCKER",
                    getattr(exc, "code", "INVALID_DOCUMENT"),
                    getattr(exc, "message", "The policy is not well formed"),
                )
            )
    blockers = [d for d in diagnostics if d["severity"] == "BLOCKER"]
    reasons = []
    if res.unpublished:
        reasons.append(
            f"it reads {len(res.unpublished)} unpublished library item{'' if len(res.unpublished) == 1 else 's'}"
        )
    if res.stale:
        reasons.append(
            f"{len(res.stale)} dependenc{'y has' if len(res.stale) == 1 else 'ies have'} changed since it was saved"
        )
    if blockers:
        reasons.append(f"{len(blockers)} blocking problem{'' if len(blockers) == 1 else 's'}")
    return {
        "pins": res.pins, "dependencies": res.entries, "requirements": res.requirements, "diagnostics": diagnostics,
        "workspace": res.workspace, "policy_fingerprint": fingerprint, "snapshot_sha256": sha256_hex(res.snapshot()),
        "unpublished": len(res.unpublished), "stale": len(res.stale), "blockers": len(blockers),
        "ready_for_publication": not reasons,
        "readiness": "Not ready for publication: " + "; ".join(reasons) + "." if reasons else "No blocker was found. Publication of policies is not available yet (APPL-X4).",
        "can_evaluate": not res.stale and not res.invalid,
    }  # fmt: skip


DEPENDENCY_CODES = ("UNKNOWN_REFERENCE", "INVALID_DEPENDENCY_PIN", "STALE_DEPENDENCY", "UNPUBLISHED_DEPENDENCY", "NEWER_VERSION", "PIN_DIFFERS", "OUTSIDE_PROFILES")  # fmt: skip


def run(db: Session, policy: Mapping[str, Any], doc: Mapping[str, Any], scenarios: Sequence[Mapping[str, Any]], *, source: str, previous: Mapping[str, Any] | None = None, compare: Mapping[str, Any] | None = None) -> dict[str, Any]:  # fmt: skip
    """The selection plan of one document for each scenario, by the one Python evaluator, from exactly what it pins.
    Refused while a pinned draft has moved or a pin is invalid: a result computed on something else would not be the
    result of this document."""
    market = lib.Market(db, policy["market_code"])
    res = resolve(db, market, doc, previous)
    head: dict[str, Any] = {
        "source": source,
        "contract": CONTRACT,
        "snapshot_sha256": sha256_hex(res.snapshot()),
        "policy_fingerprint": None,
        "results": [],
    }
    if res.invalid:
        return {**head, "status": "INVALID_DEPENDENCY", "reasons": res.invalid}
    if res.stale:
        return {
            **head,
            "status": "DEPENDENCY_STALE",
            "reasons": [d for d in res.diagnostics if d["code"] == "STALE_DEPENDENCY"],
        }
    ws, edoc = Workspace(res.workspace), evaluator_document(policy, doc)
    other = None
    if compare is not None:
        before = resolve(db, market, compare, previous)
        other = (
            None
            if before.invalid or before.stale
            else (Workspace(before.workspace), evaluator_document(policy, compare))
        )
    results = []
    for s in scenarios:
        row: dict[str, Any] = {"scenario": s["id"]}
        try:
            row["plan"] = ev_.evaluate(ws, edoc, dict(s.get("facts") or {}), list(s.get("profiles") or []) or None)
        except _BAD as exc:
            row["plan"] = {
                "status": "ERROR",
                "error": {
                    "code": getattr(exc, "code", "INVALID_DOCUMENT"),
                    "message": getattr(exc, "message", "The document is not well formed"),
                },
            }
        if other is not None and row["plan"].get("status") != "ERROR":
            try:
                row["before"] = ev_.evaluate(
                    other[0], other[1], dict(s.get("facts") or {}), list(s.get("profiles") or []) or None
                )
                row["comparison"] = ev_.compare(row["before"], row["plan"])
            except _BAD:
                pass
        results.append(row)
    try:
        fingerprint = ev_.fingerprint(ws, edoc)
    except _BAD:
        fingerprint = None
    return {**head, "status": "OK", "policy_fingerprint": fingerprint, "results": results}


# --------------------------------------------------------------------------------------------------------- storing
def policy_row(db: Session, policy_id: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    p = _one(db, POLICY_SQL + "WHERE p.id = :i" + (" FOR UPDATE" if lock else ""), i=policy_id)
    if p is None or p["market_code"] not in markets:  # another market's policy does not exist for this person
        raise SurveyError(404, "NOT_FOUND", "No such applicability policy")
    return p


def _event(
    db: Session,
    pid: Any,
    event: str,
    actor: Actor,
    revision: int,
    comment: str = "",
    detail: Mapping[str, Any] | None = None,
) -> None:
    db.execute(
        text(
            "INSERT INTO applicability_policy_event (policy_id, event, actor_ref, draft_revision, comment, detail) VALUES (:p, :e, :a, :r, :c, CAST(:d AS jsonb))"
        ),
        {
            "p": pid,
            "e": event,
            "a": _ref(actor),
            "r": revision,
            "c": comment.strip(),
            "d": json.dumps(dict(detail or {})),
        },
    )


def _write_dependencies(db: Session, pid: Any, snapshot: Mapping[str, Any]) -> None:
    """The rows ARE the snapshot: both are written here, in the caller's transaction, from the same list."""
    db.execute(text("DELETE FROM applicability_policy_dependency WHERE policy_id = :p"), {"p": pid})
    for e in snapshot["dependencies"]:
        survey = e["kind"] == "SURVEY"
        db.execute(
            text(
                "INSERT INTO applicability_policy_dependency (policy_id, kind, code, asset_id, asset_version_id, draft_revision, "
                "survey_definition_id, survey_version_id, version_no, content_sha256, manifest_sha256) "
                "VALUES (:p, :k, :c, :a, :av, :dr, :sd, :sv, :n, :h, :m)"
            ),
            {
                "p": pid, "k": e["kind"], "c": e["code"],
                "a": None if survey else uuid.UUID(e["asset_id"]),
                "av": uuid.UUID(e["version_id"]) if not survey and e["state"] == "PUBLISHED" else None,
                "dr": e.get("draft_revision"),
                "sd": uuid.UUID(e["definition_id"]) if survey else None, "sv": uuid.UUID(e["version_id"]) if survey else None,
                "n": e.get("version_no") if e["state"] == "PUBLISHED" else None, "h": e["content_sha256"], "m": e.get("manifest_sha256"),
            },
        )  # fmt: skip


def _freeze(
    db: Session, policy: Mapping[str, Any], raw: Any, previous: Mapping[str, Any] | None
) -> tuple[dict[str, Any], dict[str, Any], Resolution]:
    """A document ready to store: normalised, every dependency pinned and valid, its snapshot beside it."""
    doc = normalise(raw)
    res = resolve(db, lib.Market(db, policy["market_code"]), doc, previous)
    if res.invalid:
        code = (
            "INVALID_SURVEY_REFERENCE"
            if all(d["code"] == "INVALID_SURVEY_REFERENCE" for d in res.invalid)
            else "INVALID_DEPENDENCY_PIN"
        )
        raise _bad(
            code,
            "This policy cannot be saved: a reference in it does not name something that exists exactly as stated",
            details=res.invalid,
        )
    doc["pins"] = res.pins  # what was resolved is what is stored: nothing is left to be decided at the next reload
    return doc, res.snapshot(), res


def create(db: Session, markets: Sequence[str], market: str, code: str, raw: Any, actor: Actor, meta: RequestMeta | None = None, origin: str = "") -> uuid.UUID:  # fmt: skip
    if market not in markets:
        raise SurveyError(403, "MARKET_NOT_IN_SCOPE", "You cannot work with applicability policies of this market")
    if not lib.CODE_RE.match(code or ""):
        raise _bad("INVALID_CODE", "A code starts with a letter and uses 2 to 60 letters, digits, '_', '-' or '.'")
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"applicability-policy:{market}:{code.lower()}"}
    )
    if _one(
        db, "SELECT id FROM applicability_policy WHERE market_code = :m AND lower(code) = lower(:c)", m=market, c=code
    ):
        raise SurveyError(409, "CODE_TAKEN", f"A policy with the code '{code}' already exists in this market")
    pid = uuid.uuid4()
    policy = {"id": pid, "market_code": market, "code": code}
    doc, snapshot, _ = _freeze(db, policy, raw, None)
    db.execute(
        text(
            "INSERT INTO applicability_policy (id, market_code, code, document, snapshot, document_sha256, snapshot_sha256, "
            "draft_revision, draft_updated_by, created_by) VALUES (:i, :m, :c, CAST(:d AS jsonb), CAST(:s AS jsonb), :dh, :sh, 1, :by, :by)"
        ),
        {
            "i": pid,
            "m": market,
            "c": code,
            "d": json.dumps(doc),
            "s": json.dumps(snapshot),
            "dh": sha256_hex(doc),
            "sh": sha256_hex(snapshot),
            "by": _ref(actor),
        },
    )
    _write_dependencies(db, pid, snapshot)
    _event(
        db,
        pid,
        "CREATED",
        actor,
        1,
        detail={
            "origin": origin,
            "requirements": len(doc["requirements"]),
            "dependencies": len(snapshot["dependencies"]),
        },
    )
    _audit(
        db, actor, meta, "APPLICABILITY.POLICY_CREATED", ENTITY, pid, {"market": market, "code": code, "origin": origin}
    )
    return pid


def _names(db: Session, refs: Sequence[Any]) -> dict[str, str]:
    return lib._names(db, refs)  # noqa: SLF001


def save(db: Session, markets: Sequence[str], policy_id: uuid.UUID, expected: int, raw: Any, actor: Actor, meta: RequestMeta | None = None, note: str = "") -> None:  # fmt: skip
    """Document, snapshot, dependency rows, history and audit record — one transaction, or nothing."""
    p = policy_row(db, policy_id, markets, lock=True)
    if p["archived_at"] is not None:
        raise SurveyError(409, "ARCHIVED", "This policy was archived; restore it before changing it")
    if expected != p["draft_revision"]:
        who = _names(db, [p["draft_updated_by"]]).get(str(p["draft_updated_by"]), "someone else")
        raise SurveyError(
            409, "STALE_REVISION",
            "Someone saved this policy after you opened it. Nothing of yours was saved and nothing of theirs was overwritten",
            details=[{"current_revision": p["draft_revision"], "updated_by": who}],
        )  # fmt: skip
    doc, snapshot, res = _freeze(db, p, raw, p["snapshot"])
    if sha256_hex(doc) == p["document_sha256"] and sha256_hex(snapshot) == p["snapshot_sha256"]:
        raise SurveyError(409, "NOTHING_CHANGED", "Nothing changed since the last save")
    before = {
        (e["kind"], e["code"], e.get("version_no"), e.get("draft_revision"))
        for e in p["snapshot"].get("dependencies") or []
    }
    after = {(e["kind"], e["code"], e.get("version_no"), e.get("draft_revision")) for e in snapshot["dependencies"]}
    db.execute(
        text(
            "UPDATE applicability_policy SET document = CAST(:d AS jsonb), snapshot = CAST(:s AS jsonb), document_sha256 = :dh, "
            "snapshot_sha256 = :sh, draft_revision = draft_revision + 1, draft_updated_at = now(), draft_updated_by = :by WHERE id = :i"
        ),
        {
            "d": json.dumps(doc),
            "s": json.dumps(snapshot),
            "dh": sha256_hex(doc),
            "sh": sha256_hex(snapshot),
            "by": _ref(actor),
            "i": policy_id,
        },
    )
    _write_dependencies(db, policy_id, snapshot)

    def word(e: tuple[Any, ...]) -> str:
        return f"{e[0].lower()} {e[1]} " + (f"v{e[2]}" if e[2] is not None else f"draft r{e[3]}")

    detail = {
        "requirements": len(doc["requirements"]), "dependencies": len(snapshot["dependencies"]),
        "pinned": sorted(word(e) for e in after - before), "released": sorted(word(e) for e in before - after),
        "unpublished": len(res.unpublished), "document_sha256": sha256_hex(doc), "snapshot_sha256": sha256_hex(snapshot),
    }  # fmt: skip
    _event(db, policy_id, "DRAFT_SAVED", actor, p["draft_revision"] + 1, note, detail)
    _audit(
        db,
        actor,
        meta,
        "APPLICABILITY.POLICY_SAVED",
        ENTITY,
        policy_id,
        {"revision": p["draft_revision"] + 1, "snapshot_sha256": sha256_hex(snapshot)},
    )


def archive(db: Session, markets: Sequence[str], policy_id: uuid.UUID, expected: int, reason: str, actor: Actor, meta: RequestMeta | None = None, *, restore: bool = False) -> None:  # fmt: skip
    """A policy is never deleted. Archiving takes it out of the gallery; its document and history are kept."""
    p = policy_row(db, policy_id, markets, lock=True)
    if expected != p["draft_revision"]:
        raise SurveyError(
            409,
            "STALE_REVISION",
            "This policy was saved after you opened it; look at it again first",
            details=[{"current_revision": p["draft_revision"]}],
        )
    if restore == (p["archived_at"] is None):
        raise SurveyError(
            409,
            "NOT_ARCHIVED" if restore else "ARCHIVED",
            "This policy is not archived" if restore else "This policy is already archived",
        )
    if not restore and len(reason.strip()) < 10:
        raise _bad("COMMENT_REQUIRED", "Say why, in at least 10 characters")
    db.execute(
        text("UPDATE applicability_policy SET archived_at = " + ("NULL" if restore else "now()") + " WHERE id = :i"),
        {"i": policy_id},
    )
    _event(db, policy_id, "RESTORED" if restore else "ARCHIVED", actor, p["draft_revision"], reason)
    _audit(
        db,
        actor,
        meta,
        "APPLICABILITY.POLICY_RESTORED" if restore else "APPLICABILITY.POLICY_ARCHIVED",
        ENTITY,
        policy_id,
        {"revision": p["draft_revision"]},
    )


# ----------------------------------------------------------------------------------------------------- presenting
def summary(p: Mapping[str, Any], names: Mapping[str, str]) -> dict[str, Any]:
    deps = p["snapshot"].get("dependencies") or []
    return {
        "id": str(p["id"]), "market_code": p["market_code"], "code": p["code"], "name": p["document"].get("name") or p["code"],
        "description": p["document"].get("description") or "", "state": "ARCHIVED" if p["archived_at"] else "DRAFT",
        "draft_revision": p["draft_revision"], "updated_at": p["draft_updated_at"], "updated_by": names.get(str(p["draft_updated_by"]), None),
        "created_at": p["created_at"], "requirements": len(p["document"].get("requirements") or []),
        "surveys": sorted({e["code"] for e in deps if e["kind"] == "SURVEY"}),
        "conditions": sorted({e["code"] for e in deps if e["kind"] == "CONDITION"}),
        "unpublished": sum(1 for e in deps if e.get("state") == "DRAFT"),
        "document_sha256": p["document_sha256"], "snapshot_sha256": p["snapshot_sha256"],
    }  # fmt: skip


def listing(db: Session, markets: Sequence[str], *, archived: bool = False) -> list[dict[str, Any]]:
    rows = _all(
        db,
        POLICY_SQL
        + "WHERE p.market_code = ANY(:m) "
        + ("" if archived else "AND p.archived_at IS NULL ")
        + "ORDER BY p.draft_updated_at DESC",
        m=list(markets),
    )
    names = _names(db, [r["draft_updated_by"] for r in rows])
    return [summary(r, names) for r in rows]


def detail(db: Session, markets: Sequence[str], policy_id: uuid.UUID, *, inspection: bool = True) -> dict[str, Any]:
    p = policy_row(db, policy_id, markets)
    events = _all(
        db,
        "SELECT e.seq, e.event, e.actor_ref, e.draft_revision, e.comment, e.detail, e.occurred_at, pr.display_name FROM applicability_policy_event e "
        "LEFT JOIN principal pr ON CAST(pr.id AS text) = e.actor_ref WHERE e.policy_id = :p ORDER BY e.seq",
        p=policy_id,
    )
    out = summary(p, _names(db, [p["draft_updated_by"]]))
    out["document"] = p["document"]
    out["snapshot"] = p["snapshot"]
    # the inspection runs the evaluator's whole analysis: it is worked out when asked for, not for every listing
    out["inspection"] = inspect(db, p, p["document"], p["snapshot"]) if inspection else None
    out["events"] = [
        {
            "seq": e["seq"],
            "event": e["event"],
            "actor": e["display_name"] or e["actor_ref"],
            "draft_revision": e["draft_revision"],
            "comment": e["comment"],
            "detail": e["detail"],
            "occurred_at": e["occurred_at"],
        }
        for e in events
    ]
    return out


def usage(
    db: Session, markets: Sequence[str], *, kind: str | None = None, code: str | None = None
) -> list[dict[str, Any]]:
    """Which saved policies depend on a library item or a survey: from the dependency rows, exact and indexed."""
    rows = _all(
        db,
        "SELECT p.id, p.code, p.market_code, p.document->>'name' AS name, p.draft_revision, d.kind, d.code AS dependency, d.version_no, d.draft_revision AS pinned_draft, "
        "d.content_sha256 FROM applicability_policy_dependency d JOIN applicability_policy p ON p.id = d.policy_id "
        "WHERE p.market_code = ANY(:m) AND p.archived_at IS NULL AND (CAST(:k AS text) IS NULL OR d.kind = :k) AND (CAST(:c AS text) IS NULL OR lower(d.code) = lower(:c)) "
        "ORDER BY p.code, d.kind, d.code",
        m=list(markets), k=kind, c=code,
    )  # fmt: skip
    return [
        {"policy_id": str(r["id"]), "policy_code": r["code"], "policy_name": r["name"] or r["code"], "market_code": r["market_code"], "draft_revision": r["draft_revision"],
         "kind": r["kind"], "code": r["dependency"], "version_no": r["version_no"], "pinned_draft_revision": r["pinned_draft"], "content_sha256": r["content_sha256"]}
        for r in rows
    ]  # fmt: skip


def consistent(db: Session, policy_id: uuid.UUID) -> bool:
    """Whether the dependency rows of a policy are exactly its stored snapshot (they are written together; this proves it)."""
    p = _one(db, "SELECT snapshot FROM applicability_policy WHERE id = :i", i=policy_id)
    rows = _all(
        db,
        "SELECT kind, code, version_no, draft_revision, content_sha256, manifest_sha256, CAST(coalesce(asset_version_id, survey_version_id) AS text) AS version_id FROM applicability_policy_dependency WHERE policy_id = :i",
        i=policy_id,
    )
    have = sorted(
        (
            r["kind"],
            r["code"],
            r["version_no"],
            r["draft_revision"],
            r["content_sha256"],
            r["manifest_sha256"],
            r["version_id"],
        )
        for r in rows
    )
    want = sorted(
        (
            e["kind"],
            e["code"],
            e.get("version_no") if e["state"] == "PUBLISHED" else None,
            e.get("draft_revision"),
            e["content_sha256"],
            e.get("manifest_sha256"),
            e.get("version_id") if e["state"] == "PUBLISHED" else None,
        )
        for e in (p or {"snapshot": {}})["snapshot"].get("dependencies") or []
    )
    return have == want
