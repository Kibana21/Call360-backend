"""Persistence and governance of survey definitions (SS-03A.2).

Draft -> immutable Candidate -> immutable Version (owner decisions D-143, TS-12 as amended). A candidate's content
record is written once. Its lifecycle is an APPEND-ONLY history of decisions and its status is DERIVED from that
history: no row is ever updated to say it was approved. Approval of wording is append-only evidence that names the
exact wording version and candidate (D-178); the frozen wording row is never touched.

Identity rules are enforced here AND by the database (trigger ``survey_lifecycle_event_guard``), independently of
permissions (D-163, D-182): the approver is not a maker of the candidate; the publisher is not its submitter, not a
maker and, until governance rules otherwise, not its approver.

Nothing here executes a survey, assembles a call plan, or implements any non-answer, refusal, repeat, consent or
timeout behaviour. Every catalog entry and every wording is synthetic and unapproved for operational use (D-183).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta, write_audit
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.conditions import fields_of
from app.domain.survey.documents import SCHEMA_OF, Bundle, check_document, manifest_of, manifest_sha256
from app.domain.survey.validator import validate

ASSET_KINDS = ("OPTION_SET", "ITEM", "WORDING", "CONDITION", "MODULE")
STATUS_OF_EVENT = {
    "SUBMITTED": "IN_REVIEW",
    "APPROVED": "APPROVED",
    "REJECTED": "REJECTED",
    "WITHDRAWN": "WITHDRAWN",
    "SUPERSEDED": "SUPERSEDED",
    "PUBLISHED": "PUBLISHED",
    "SCHEDULED": "SCHEDULED",
}
OPEN_CANDIDATE = ("IN_REVIEW", "APPROVED")


class SurveyError(Exception):
    def __init__(self, status: int, code: str, message: str, details: list[dict[str, Any]] | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details


def _one(db: Session, sql: str, **p: Any) -> dict[str, Any] | None:
    r = db.execute(text(sql), p).mappings().first()
    return dict(r) if r else None


def _all(db: Session, sql: str, **p: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in db.execute(text(sql), p).mappings()]


def _ref(actor: Actor) -> str:
    return str(actor.principal_id) if actor.principal_id else f"SERVICE:{actor.service}"


def _audit(
    db: Session, actor: Actor, meta: RequestMeta | None, action: str, entity: str, entity_id: Any,
    after: dict[str, Any],
    *, outcome: str = "SUCCEEDED", reason: str | None = None,
) -> None:  # fmt: skip
    write_audit(
        db, action=action, outcome=outcome, actor=actor, meta=meta, entity_type=entity, entity_id=str(entity_id),
        reason=reason, after=after,
    )  # fmt: skip


def asset_key(kind: str, doc: Mapping[str, Any]) -> tuple[str, int]:
    """(code, version) of an asset document: a wording is keyed by its item, a module by its revision."""
    if kind == "WORDING":
        return str(doc["item"]), int(doc["wording_version"])
    if kind == "MODULE":
        return str(doc["code"]), int(doc["revision"])
    return str(doc["code"]), int(doc["version"])


# ---------------------------------------------------------------------------------------------------------- surveys
def create_survey(
    db: Session, *, code: str, name: str, purpose: str, market: str, actor: Actor, meta: RequestMeta | None = None
) -> uuid.UUID:
    if _one(db, "SELECT 1 AS x FROM survey_definition WHERE code = :c", c=code):
        raise SurveyError(409, "SURVEY_CODE_TAKEN", "A survey with this code already exists")
    sid, who = uuid.uuid4(), _ref(actor)
    db.execute(
        text(
            "INSERT INTO survey_definition (id, code, name, purpose, market_code, created_by) "
            "VALUES (:i, :c, :n, :p, :m, :by)"
        ),
        {"i": sid, "c": code, "n": name, "p": purpose, "m": market, "by": who},
    )
    content = {"schema": SCHEMA_OF["SURVEY"], "code": code, "sequence": []}
    db.execute(
        text(
            "INSERT INTO survey_draft (id, survey_definition_id, revision, content, makers, updated_by) "
            "VALUES (:i, :s, 0, CAST(:c AS jsonb), CAST(:m AS jsonb), :by)"
        ),
        {"i": uuid.uuid4(), "s": sid, "c": json.dumps(content), "m": json.dumps([who]), "by": who},
    )
    _audit(db, actor, meta, "SURVEY.CREATED", "survey_definition", sid, {"code": code, "market": market})
    return sid


def survey(db: Session, sid: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    """Object-level scope: a survey outside the caller's markets does not exist for them."""
    row = _one(
        db,
        "SELECT * FROM survey_definition WHERE id = :i AND market_code = ANY(:m)" + (" FOR UPDATE" if lock else ""),
        i=sid,
        m=list(markets),
    )
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Survey not found or not available to you")
    return row


def surveys(db: Session, markets: Sequence[str]) -> list[dict[str, Any]]:
    return _all(db, "SELECT * FROM survey_definition WHERE market_code = ANY(:m) ORDER BY code", m=list(markets))


def draft(db: Session, sid: uuid.UUID, *, lock: bool = False) -> dict[str, Any]:
    row = _one(
        db, "SELECT * FROM survey_draft WHERE survey_definition_id = :s" + (" FOR UPDATE" if lock else ""), s=sid
    )
    assert row is not None, "every survey has exactly one draft"
    return row


def status_of(db: Session, subject_id: uuid.UUID) -> str | None:
    """The status of a candidate or version: derived from its newest lifecycle event, never stored."""
    row = _one(
        db, "SELECT event FROM survey_lifecycle_event WHERE subject_id = :s ORDER BY seq DESC LIMIT 1", s=subject_id
    )
    return STATUS_OF_EVENT[row["event"]] if row else None


def history(db: Session, subject_id: uuid.UUID) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT e.seq, e.subject_type, e.event, e.actor_ref, e.reason, e.details, e.occurred_at, p.display_name "
        "FROM survey_lifecycle_event e LEFT JOIN principal p ON CAST(p.id AS text) = e.actor_ref "
        "WHERE e.subject_id = :s ORDER BY e.seq",
        s=subject_id,
    )


def _event(
    db: Session, subject_type: str, subject_id: uuid.UUID, sid: uuid.UUID, event: str, actor: Actor,
    reason: str | None = None, **details: Any,
) -> None:  # fmt: skip
    db.execute(
        text(
            "INSERT INTO survey_lifecycle_event (id, subject_type, subject_id, survey_definition_id, event, actor_ref, "
            "reason, details) VALUES (:i, :t, :s, :d, :e, :by, :r, CAST(:j AS jsonb))"
        ),
        {
            "i": uuid.uuid4(), "t": subject_type, "s": subject_id, "d": sid, "e": event, "by": _ref(actor), "r": reason,
            "j": json.dumps(details, default=str),
        },
    )  # fmt: skip


# ----------------------------------------------------------------------------------------------- the draft: operations
MAX_BATCH = 500


def _apply_one(
    db: Session, sid: uuid.UUID, content: Mapping[str, Any], operation: Mapping[str, Any], who: str,
    require_issued: bool = False,
) -> tuple[Mapping[str, Any], dict[str, Any]]:  # fmt: skip
    """One operation against the locked draft: writes the asset (if any) and returns the content and a summary. It does
    NOT touch the draft row; the caller advances the revision once, for one operation or for a whole batch."""
    op = operation.get("op")
    summary: dict[str, Any] = {"op": op}
    if op == "SET_CONTENT":
        new = operation.get("content")
        problems = check_document("SURVEY", new)
        if problems:
            raise SurveyError(
                422, "DOCUMENT_INVALID", "The survey content is not well formed", [p.__dict__ for p in problems]
            )
        assert isinstance(new, dict)
        if new["code"] != content["code"]:
            raise SurveyError(422, "DOCUMENT_INVALID", "The content names a different survey")
        return new, summary
    if op == "SET_DETAILS":
        # the survey's name and purpose: descriptive, not part of any hashed document
        name, purpose = operation.get("name"), operation.get("purpose", "")
        if not isinstance(name, str) or not 3 <= len(name.strip()) <= 160:
            raise SurveyError(422, "OPERATION_INVALID", "A survey name has 3 to 160 characters")
        if not isinstance(purpose, str) or len(purpose) > 2000:
            raise SurveyError(422, "OPERATION_INVALID", "A purpose has at most 2000 characters")
        db.execute(
            text("UPDATE survey_definition SET name = :n, purpose = :p WHERE id = :i"),
            {"n": name.strip(), "p": purpose, "i": sid},
        )
        return content, {**summary, "name": name.strip()}
    if op not in ("PUT_ASSET", "REMOVE_ASSET"):
        raise SurveyError(422, "OPERATION_INVALID", "Unknown operation")
    kind = str(operation.get("kind"))
    if kind not in ASSET_KINDS:
        raise SurveyError(422, "OPERATION_INVALID", "Unknown kind of asset")
    if op == "PUT_ASSET":
        doc = operation.get("document")
        problems = check_document(kind, doc)
        if problems:
            raise SurveyError(
                422, "DOCUMENT_INVALID", "The document is not well formed", [p.__dict__ for p in problems]
            )
        assert isinstance(doc, dict)
        code, version = asset_key(kind, doc)
    else:
        v = operation.get("version")
        code, version = str(operation.get("code")), int(v) if isinstance(v, int) else 0
    existing = _one(
        db,
        "SELECT id, state, owner_definition_id FROM survey_asset_version WHERE kind = :k AND code = :c AND "
        "version = :v FOR UPDATE",
        k=kind, c=code, v=version,
    )  # fmt: skip
    if existing and existing["state"] == "FROZEN":
        # a frozen version is never changed: a change is a new version
        raise SurveyError(409, "ASSET_FROZEN", f"{kind} {code} version {version} is frozen; create a new version")
    if existing and existing["owner_definition_id"] != sid:
        raise SurveyError(409, "ASSET_OWNED_ELSEWHERE", f"{kind} {code} version {version} is a draft of another survey")
    if op == "PUT_ASSET":
        if not existing:
            _check_identity(db, sid, kind, code, require_issued)
        params = {"k": kind, "c": code, "v": version, "j": json.dumps(doc), "h": sha256_hex(doc), "by": who}
        if existing:
            db.execute(
                text("UPDATE survey_asset_version SET content = CAST(:j AS jsonb), sha256 = :h WHERE id = :i"),
                {"j": params["j"], "h": params["h"], "i": existing["id"]},
            )
        else:
            db.execute(
                text(
                    "INSERT INTO survey_asset_version (id, kind, code, version, state, content, sha256, "
                    "owner_definition_id, created_by) VALUES (:i, :k, :c, :v, "
                    "'DRAFT', CAST(:j AS jsonb), :h, :o, :by)"
                ),
                {**params, "i": uuid.uuid4(), "o": sid},
            )
    else:
        if not existing:
            raise SurveyError(404, "NOT_FOUND", "No such draft asset")
        db.execute(text("DELETE FROM survey_asset_version WHERE id = :i"), {"i": existing["id"]})
    return content, {**summary, "kind": kind, "code": code, "version": version}


def _check_identity(db: Session, sid: uuid.UUID, kind: str, code: str, require_issued: bool) -> None:
    """LIB-1 — who may start a NEW version of an asset code.

    * A code that already has versions belongs to the survey that owns them. Another survey can PIN a published
      version of it, and can derive its own copy under a code of its own; it can never add a version to someone else's
      code (``CODE_OWNED_ELSEWHERE``). A wording follows its item.
    * With the library on, a code nobody has used yet must have been ISSUED by the server to this survey for this kind
      (``CODE_NOT_ISSUED``): the backend, not an editor, is the authority for a permanent identity. Historical codes
      are never touched by this — it only concerns codes that do not exist yet.
    """
    lineage_kind = "ITEM" if kind == "WORDING" else kind
    owners = _all(
        db,
        "SELECT DISTINCT owner_definition_id FROM survey_asset_version WHERE kind = :k AND code = :c",
        k=lineage_kind, c=code,
    )  # fmt: skip
    if owners:
        if all(o["owner_definition_id"] != sid for o in owners):
            raise SurveyError(
                409,
                "CODE_OWNED_ELSEWHERE",
                f"{lineage_kind} {code} belongs to another survey: pin a published version of it, or make a copy "
                "under a code of your own",
            )
        return
    if kind == "WORDING" or not require_issued:
        return
    issued = _one(db, "SELECT kind, survey_definition_id FROM survey_issued_code WHERE code = :c", c=code)
    if not issued or issued["survey_definition_id"] != sid or issued["kind"] != kind:
        raise SurveyError(
            422, "CODE_NOT_ISSUED", f"{kind} {code} is not a code the server issued to this survey for a {kind}"
        )


def _locked_draft(db: Session, sid: uuid.UUID, markets: Sequence[str], expected_revision: int) -> dict[str, Any]:
    survey(db, sid, markets)
    d = draft(db, sid, lock=True)
    if d["revision"] != expected_revision:
        raise SurveyError(
            409,
            "STALE_DRAFT",
            f"The draft is at revision {d['revision']}; this change was made against {expected_revision}",
            [{"current_revision": d["revision"], "expected_revision": expected_revision}],
        )
    return d


def _advance(db: Session, d: Mapping[str, Any], content: Mapping[str, Any], who: str) -> None:
    makers = sorted(set(d["makers"]) | {who})
    db.execute(
        text(
            "UPDATE survey_draft SET revision = revision + 1, content = CAST(:c AS jsonb), makers = CAST(:m AS jsonb), "
            "updated_at = now(), updated_by = :by WHERE id = :i"
        ),
        {"c": json.dumps(content), "m": json.dumps(makers), "by": who, "i": d["id"]},
    )


def apply_operation(
    db: Session, sid: uuid.UUID, markets: Sequence[str], expected_revision: int, operation: Mapping[str, Any],
    actor: Actor, meta: RequestMeta | None = None, *, require_issued: bool = False,
) -> dict[str, Any]:  # fmt: skip
    """Applies ONE operation to the draft. A stale ``expected_revision`` is refused before anything is written."""
    d = _locked_draft(db, sid, markets, expected_revision)
    who = _ref(actor)
    content, summary = _apply_one(db, sid, d["content"], operation, who, require_issued)
    _check_references(db, sid, content)
    _advance(db, d, content, who)
    _audit(
        db, actor, meta, "SURVEY.DRAFT_CHANGED", "survey_definition", sid, {**summary, "revision": d["revision"] + 1}
    )
    return draft(db, sid)


def apply_batch(
    db: Session, sid: uuid.UUID, markets: Sequence[str], expected_revision: int,
    operations: Sequence[Mapping[str, Any]], actor: Actor, meta: RequestMeta | None = None,
    *, require_issued: bool = False,
) -> dict[str, Any]:  # fmt: skip
    """FI-1 — one SAVE: every operation, in order, as ONE revision. All or nothing: the first operation that is refused
    raises, and the caller's rollback leaves the draft, every asset and the audit trail exactly as they were. A stale
    ``expected_revision`` is refused before anything is written. The error names the operation that failed."""
    if not 1 <= len(operations) <= MAX_BATCH:
        raise SurveyError(422, "OPERATION_INVALID", f"A save holds 1 to {MAX_BATCH} operations")
    d = _locked_draft(db, sid, markets, expected_revision)
    who = _ref(actor)
    content: Mapping[str, Any] = d["content"]
    summaries: list[dict[str, Any]] = []
    for index, operation in enumerate(operations):
        if not isinstance(operation, Mapping):
            raise SurveyError(422, "OPERATION_INVALID", "An operation is an object", [{"operation_index": index}])
        try:
            content, summary = _apply_one(db, sid, content, operation, who, require_issued)
        except SurveyError as exc:
            exc.details = [{"operation_index": index, "op": operation.get("op"), "kind": operation.get("kind")}] + list(
                exc.details or []
            )
            raise
        summaries.append(summary)
    _check_references(db, sid, content)
    _advance(db, d, content, who)
    counts: dict[str, int] = {}
    for s in summaries:
        counts[str(s["op"])] = counts.get(str(s["op"]), 0) + 1
    _audit(
        db, actor, meta, "SURVEY.DRAFT_SAVED", "survey_definition", sid,
        {"revision": d["revision"] + 1, "operations": len(summaries), "by_operation": counts,
         "assets": [f"{s['op']}:{s['kind']}:{s['code']}@{s['version']}" for s in summaries if "kind" in s][:200]},
    )  # fmt: skip
    return draft(db, sid)


def draft_documents(db: Session, sid: uuid.UUID) -> dict[str, Any]:
    """FI-1 — everything an editor needs to open the draft: the content, and the full document of every asset version
    this survey owns (draft or frozen) or its content pins, with the server's hash and state for each."""
    d = draft(db, sid)
    rows = {
        (r["kind"], r["code"], r["version"]): r
        for r in _all(
            db,
            "SELECT kind, code, version, state, sha256, content, owner_definition_id FROM survey_asset_version "
            "WHERE owner_definition_id = :s",
            s=sid,
        )
    }
    for e in manifest_of(load_bundle(db, d["content"])):
        key = (e["kind"], e["code"], e["version"])
        if key not in rows:
            row = _one(
                db,
                "SELECT kind, code, version, state, sha256, content, owner_definition_id FROM survey_asset_version "
                "WHERE kind = :k AND code = :c AND version = :v",
                k=e["kind"], c=e["code"], v=e["version"],
            )  # fmt: skip
            if row:
                rows[key] = row
    who = _one(db, "SELECT display_name FROM principal WHERE CAST(id AS text) = :r", r=d["updated_by"])
    fields, outcomes, obligations = catalogs(db)
    return {
        "revision": d["revision"],
        "content": d["content"],
        "content_sha256": sha256_hex(d["content"]),
        "updated_at": d["updated_at"],
        "updated_by": who["display_name"] if who else None,
        "assets": [
            {
                "kind": r["kind"],
                "code": r["code"],
                "version": r["version"],
                "state": r["state"],
                "sha256": r["sha256"],
                "owned": r["owner_definition_id"] == sid,
                "document": r["content"],
            }
            for _, r in sorted(rows.items())
        ],  # fmt: skip
        "catalogs": {"fields": fields, "outcomes": outcomes, "response_obligations": sorted(obligations)},
    }


# ------------------------------------------------------------------------------------------ resolving and validating
def catalogs(db: Session) -> tuple[dict[str, dict[str, Any]], dict[str, str], frozenset[str]]:
    """The governed catalogs: fields, outcomes (code → class) and response obligations. All entries are synthetic."""
    rows = _all(db, "SELECT catalog, code, attributes FROM survey_catalog_entry ORDER BY catalog, code")
    fields = {r["code"]: dict(r["attributes"]) for r in rows if r["catalog"] == "FIELD"}
    outcomes = {r["code"]: str(r["attributes"]["class"]) for r in rows if r["catalog"] == "OUTCOME"}
    obligations = frozenset(r["code"] for r in rows if r["catalog"] == "RESPONSE_OBLIGATION")
    return fields, outcomes, obligations


def _fetch(db: Session, kind: str, keys: Iterable[tuple[Any, Any]]) -> list[dict[str, Any]]:
    out = []
    for code, version in sorted({(str(c), int(v)) for c, v in keys if c is not None and isinstance(v, int)}):
        row = _one(
            db, "SELECT content FROM survey_asset_version WHERE kind = :k AND code = :c AND version = :v",
            k=kind, c=code, v=version,
        )  # fmt: skip
        if row:
            out.append(dict(row["content"]))
    return out


def load_bundle(db: Session, content: Mapping[str, Any]) -> Bundle:
    """Resolves everything a survey content pins from the stored asset versions and the governed catalogs."""
    seq = [i for i in content.get("sequence", []) if isinstance(i, dict)]
    modules = _fetch(
        db, "MODULE", [((i.get("module") or {}).get("code"), (i.get("module") or {}).get("revision")) for i in seq]
    )
    conds = [((i.get("eligibility") or {}).get("condition") or {}) for i in seq]
    item_keys: list[tuple[Any, Any]] = []
    wording_keys: list[tuple[Any, Any]] = []
    for m in modules:
        for n in m.get("nodes", []):
            if n.get("type") == "DECISION":
                conds.append((n.get("binding") or {}).get("condition") or {})
            else:
                ref = n.get("item") or {}
                item_keys.append((ref.get("code"), ref.get("version")))
                wording_keys.append((ref.get("code"), ref.get("wording_version")))
    items = _fetch(db, "ITEM", item_keys)
    option_keys = [((i.get("option_set") or {}).get("code"), (i.get("option_set") or {}).get("version")) for i in items]
    fields, outcomes, obligations = catalogs(db)
    return Bundle.build(
        fields=fields,
        outcomes=outcomes,
        obligations=obligations,
        option_sets=_fetch(db, "OPTION_SET", option_keys),
        items=items,
        wordings=_fetch(db, "WORDING", wording_keys),
        conditions=_fetch(db, "CONDITION", [(c.get("code"), c.get("version")) for c in conds]),
        modules=modules,
        survey=content,
    )


def findings_of(db: Session, content: Mapping[str, Any], sid: uuid.UUID | None = None) -> list[dict[str, Any]]:
    """Server validation of a content document: structural problems first, then every rule of the validator, then the
    server-governed warnings. With ``sid`` (the survey the content belongs to) also the library rules of LIB-1: a
    reference to another survey's unpublished asset is a blocker, and a newer published revision of something pinned
    is an INFORMATION item — never a warning, never a blocker, never an upgrade."""
    problems = check_document("SURVEY", content)
    if problems:
        return [{"code": p.code, "at": p.path, "severity": "BLOCKER", "message": p.detail or p.code} for p in problems]
    bundle = load_bundle(db, content)
    out = [f.__dict__ | {"code": f.code} for f in validate(bundle)]
    if sid is not None:
        out += [
            {
                "code": "REFERENCE_NOT_PUBLISHED",
                "at": f"{e['kind']}:{e['code']}@{e['version']}",
                "severity": "BLOCKER",
                "message": f"{e['kind']} {e['code']} version {e['version']} belongs to another survey and is not in a "
                "published version: it cannot be used here",
            }
            for e in foreign_unpublished(db, sid, bundle)
        ]  # fmt: skip
    out += governed_warnings(bundle)
    if sid is not None:
        out += newer_revisions(db, sid, bundle)
    return out


# ------------------------------------------------------------------------------ LIB-1: what may be reused, and by whom
PUBLISHED_VERSION_EVENTS = ("PUBLISHED", "SUPERSEDED")  # a version that was published; a withdrawn one is not a source


def published_versions(db: Session, markets: Sequence[str]) -> list[dict[str, Any]]:
    """Every survey version that was published, in the given markets, with its manifest. AUTHORITATIVE: read from the
    immutable versions and candidates themselves, never from the derived usage index."""
    rows = _all(
        db,
        "SELECT v.id AS version_id, v.label, v.version_no, v.created_at, v.created_by, d.id AS survey_id, "
        "d.code AS survey_code, d.name AS survey_name, d.market_code, c.manifest, "
        "(SELECT e.event FROM survey_lifecycle_event e WHERE e.subject_id = v.id ORDER BY e.seq DESC LIMIT 1) AS event "
        "FROM survey_version v JOIN survey_candidate c ON c.id = v.candidate_id "
        "JOIN survey_definition d ON d.id = v.survey_definition_id WHERE d.market_code = ANY(:m) "
        "ORDER BY d.code, v.version_no",
        m=list(markets),
    )
    return [r for r in rows if r["event"] in PUBLISHED_VERSION_EVENTS]


def published_index(db: Session, markets: Sequence[str]) -> dict[tuple[str, str, int], list[dict[str, Any]]]:
    """(kind, code, version) → the published versions that pin it. An asset is REUSABLE across surveys if and only if
    it is a key of this index (owner decision LIB-D-1): drafts, rejected and never-published candidates are not."""
    index: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    for v in published_versions(db, markets):
        for e in v["manifest"]:
            index.setdefault((e["kind"], e["code"], int(e["version"])), []).append(v)
    return index


def foreign_unpublished(db: Session, sid: uuid.UUID, bundle: Bundle) -> list[dict[str, Any]]:
    """The asset versions a content pins that this survey neither owns nor may reuse."""
    market = _one(db, "SELECT market_code FROM survey_definition WHERE id = :i", i=sid)
    index: dict[tuple[str, str, int], list[dict[str, Any]]] | None = None
    bad = []
    for e in manifest_of(bundle):
        owner = _one(
            db,
            "SELECT owner_definition_id FROM survey_asset_version WHERE kind = :k AND code = :c AND version = :v",
            k=e["kind"], c=e["code"], v=e["version"],
        )  # fmt: skip
        if owner and owner["owner_definition_id"] == sid:
            continue
        if index is None:
            index = published_index(db, [market["market_code"]] if market else [])
        if (e["kind"], e["code"], int(e["version"])) not in index:
            bad.append(e)
    return bad


def _check_references(db: Session, sid: uuid.UUID, content: Mapping[str, Any]) -> None:
    """A draft must never ACQUIRE a reference to another survey's unpublished asset: refused when it is saved, whatever
    client sent it."""
    if check_document("SURVEY", content):
        return
    bad = foreign_unpublished(db, sid, load_bundle(db, content))
    if bad:
        raise SurveyError(
            422,
            "REFERENCE_NOT_PUBLISHED",
            f"{len(bad)} referenced version(s) belong to another survey and are not in a published version",
            [{"kind": e["kind"], "code": e["code"], "version": e["version"]} for e in bad],
        )


def newer_revisions(db: Session, sid: uuid.UUID, bundle: Bundle) -> list[dict[str, Any]]:
    """INFORMATION only (owner decision LIB-D-5): something this content pins has a newer PUBLISHED revision. The pin
    is never changed for the author, and this never blocks or invalidates anything."""
    market = _one(db, "SELECT market_code FROM survey_definition WHERE id = :i", i=sid)
    index = published_index(db, [market["market_code"]] if market else [])
    latest: dict[tuple[str, str], int] = {}
    for kind, code, version in index:
        latest[(kind, code)] = max(latest.get((kind, code), 0), version)
    out = []
    for e in manifest_of(bundle):
        if e["kind"] == "WORDING":
            continue
        newest = latest.get((e["kind"], e["code"]), 0)
        if newest > int(e["version"]):
            out.append(
                {
                    "code": "NEWER_REVISION_PUBLISHED", "at": f"{e['kind']}:{e['code']}@{e['version']}",
                    "severity": "INFO",
                    "message": f"{e['kind']} {e['code']} is pinned at version {e['version']}; version {newest} has "
                    "been published. Nothing is upgraded for you, and nothing is blocked.",
                }
            )  # fmt: skip
    return out


CODE_PREFIX = {"MODULE": "M", "ITEM": "Q", "STATEMENT": "S", "CONDITION": "C", "OPTION_SET": "OS"}
MAX_CODES = 60


def issue_codes(
    db: Session, sid: uuid.UUID, markets: Sequence[str], requests: Sequence[Mapping[str, Any]], actor: Actor,
    meta: RequestMeta | None = None,
) -> list[dict[str, Any]]:  # fmt: skip
    """New, permanent, globally unique asset codes for one survey. The number comes from a database sequence, which
    never returns a value twice — not to two concurrent requests, and not after a request that was rolled back — and
    every issued code is recorded under a primary key. A code that any asset already carries is skipped, so a
    historical code is never issued. ``kind`` STATEMENT is an ITEM whose code starts with S, by convention."""
    survey(db, sid, markets)
    wanted: list[tuple[str, str]] = []
    for r in requests:
        kind, count = str(r.get("kind")), r.get("count", 1)
        if kind not in CODE_PREFIX or not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise SurveyError(
                422, "OPERATION_INVALID", "Ask for a count of MODULE, ITEM, STATEMENT, CONDITION or OPTION_SET"
            )
        wanted += [(kind, "ITEM" if kind == "STATEMENT" else kind)] * count
    if not 1 <= len(wanted) <= MAX_CODES:
        raise SurveyError(422, "OPERATION_INVALID", f"Ask for 1 to {MAX_CODES} codes at a time")
    who, out = _ref(actor), []
    for asked, stored in wanted:
        while True:
            n = db.execute(text("SELECT nextval('survey_code_seq')")).scalar_one()
            code = f"{CODE_PREFIX[asked]}-{n}"
            if not _one(db, "SELECT 1 AS x FROM survey_asset_version WHERE code = :c LIMIT 1", c=code):
                break
        db.execute(
            text(
                "INSERT INTO survey_issued_code (code, kind, survey_definition_id, issued_by) VALUES (:c, :k, :s, :by)"
            ),
            {"c": code, "k": stored, "s": sid, "by": who},
        )
        out.append({"kind": asked, "code": code})
    _audit(
        db, actor, meta, "SURVEY.CODES_ISSUED", "survey_definition", sid,
        {"count": len(out), "codes": [o["code"] for o in out]},
    )  # fmt: skip
    return out


#: FI-2 (owner decision FI2-D-1) — warnings the SERVER governs. Each has a stable code; each must be acknowledged,
#: with a recorded reason, before a draft can be submitted; the acknowledgement is stored in the immutable candidate
#: beside the content fingerprint it was given for. A warning never blocks on its own and never makes anything eligible
#: for a call. Warnings that only the editor raises are advisory and are never recorded here.
WARNING_CODES = ("SYNTHETIC_WORDING_UNAPPROVED",)
ACK_REASON_MIN, ACK_REASON_MAX = 10, 500


def governed_warnings(bundle: Bundle) -> list[dict[str, Any]]:
    wordings = [e for e in manifest_of(bundle) if e["kind"] == "WORDING"]
    if not wordings:
        return []
    # Every wording in Call360 today is synthetic and unapproved for operational use (owner decision D-183). Review and
    # development publication of a candidate are not Compliance approval of insurance wording.
    return [
        {
            "code": "SYNTHETIC_WORDING_UNAPPROVED",
            "at": str(bundle.survey.get("code")),
            "severity": "WARNING",
            "message": (
                f"The wording in this survey ({len(wordings)} version{'' if len(wordings) == 1 else 's'}) is "
                "synthetic and not approved for operational use. Reviewing or publishing this survey is not "
                "Compliance approval of its wording."
            ),
        }
    ]


def check_acknowledgements(
    findings: Sequence[Mapping[str, Any]], given: Sequence[Any], content_sha256: str, actor: Actor
) -> list[dict[str, Any]]:
    """The acknowledgements to store with a candidate: exactly one, with a reason, for every server-governed warning of
    the content being submitted. Anything missing, empty or not asked for refuses the submission."""
    warnings = {(str(f["code"]), str(f["at"])): f for f in findings if f["severity"] == "WARNING"}
    seen: dict[tuple[str, str], str] = {}
    for a in given:
        if not isinstance(a, Mapping) or not isinstance(a.get("reason"), str):
            raise SurveyError(422, "ACKNOWLEDGEMENT_INVALID", "An acknowledgement names a warning and gives a reason")
        key = (str(a.get("code")), str(a.get("at")))
        if key not in warnings:
            raise SurveyError(
                422, "ACKNOWLEDGEMENT_UNKNOWN", "An acknowledgement was given for a warning the server did not raise",
                [{"code": key[0], "at": key[1]}],
            )  # fmt: skip
        seen[key] = a["reason"].strip()
    missing = [
        {"code": k[0], "at": k[1], "message": w["message"]}
        for k, w in warnings.items()
        if not ACK_REASON_MIN <= len(seen.get(k, "")) <= ACK_REASON_MAX
    ]
    if missing:
        raise SurveyError(
            422,
            "ACKNOWLEDGEMENT_REQUIRED",
            f"{len(missing)} warning(s) need an acknowledgement with a reason of {ACK_REASON_MIN} to {ACK_REASON_MAX} "
            "characters before submitting",
            missing,
        )
    return [
        {
            "code": k[0], "at": k[1], "message": w["message"], "reason": seen[k], "content_sha256": content_sha256,
            "acknowledged_by": _ref(actor), "acknowledged_by_name": actor.display_name,
        }
        for k, w in sorted(warnings.items())
    ]  # fmt: skip


# ---------------- candidates
def submit(
    db: Session, sid: uuid.UUID, markets: Sequence[str], note: str, acknowledgements: list[dict[str, Any]],
    actor: Actor, meta: RequestMeta | None = None,
) -> uuid.UUID:  # fmt: skip
    """Freezes what the draft pins and inserts an immutable candidate. The draft stays editable."""
    survey(db, sid, markets)
    d = draft(db, sid, lock=True)
    content = d["content"]
    findings = findings_of(db, content, sid)
    blockers = [f for f in findings if f["severity"] == "BLOCKER"]
    if blockers:
        raise SurveyError(
            422, "VALIDATION_BLOCKED", f"{len(blockers)} blocker(s) must be fixed before submitting", blockers
        )
    # server-governed warnings: each acknowledged with a reason, recorded against THIS content's fingerprint (FI2-D-1)
    acknowledgements = check_acknowledgements(findings, acknowledgements, sha256_hex(content), actor)
    bundle = load_bundle(db, content)
    manifest = manifest_of(bundle)
    who = _ref(actor)
    for e in manifest:  # freeze: from here on these exact versions can never change
        db.execute(
            text(
                "UPDATE survey_asset_version SET state = 'FROZEN', frozen_at = now() WHERE kind = :k AND code = :c AND "
                "version = :v AND state = 'DRAFT'"
            ),
            {"k": e["kind"], "c": e["code"], "v": e["version"]},
        )
    n = int(
        db.execute(
            text("SELECT coalesce(max(n), 0) + 1 FROM survey_candidate WHERE survey_definition_id = :s"), {"s": sid}
        ).scalar_one()
    )
    earlier = _all(db, "SELECT id FROM survey_candidate WHERE survey_definition_id = :s ORDER BY n", s=sid)
    cid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO survey_candidate (id, survey_definition_id, n, "
            "draft_revision, content, content_sha256, manifest, "
            "manifest_sha256, makers, note, acknowledgements, submitted_by) "
            "VALUES (:i, :s, :n, :r, CAST(:c AS jsonb), :ch, "
            "CAST(:m AS jsonb), :mh, CAST(:mk AS jsonb), :note, CAST(:a AS jsonb), :by)"
        ),
        {
            "i": cid, "s": sid, "n": n, "r": d["revision"], "c": json.dumps(content), "ch": sha256_hex(content),
            "m": json.dumps(manifest), "mh": manifest_sha256(manifest),
            "mk": json.dumps(sorted(set(d["makers"]) | {who})),
            "note": note, "a": json.dumps(acknowledgements), "by": who,
        },
    )  # fmt: skip
    for c in earlier:  # an open candidate is superseded; its approval, if any, is not carried over
        if status_of(db, c["id"]) in OPEN_CANDIDATE:
            _event(db, "CANDIDATE", c["id"], sid, "SUPERSEDED", actor, by_candidate=str(cid))
    _event(db, "CANDIDATE", cid, sid, "SUBMITTED", actor, n=n)
    rebuild_usage(db, "CANDIDATE", cid, manifest)
    _audit(
        db, actor, meta, "SURVEY.SUBMITTED", "survey_candidate", cid,
        {"n": n, "content_sha256": sha256_hex(content), "manifest_sha256": manifest_sha256(manifest),
         "acknowledged": [a["code"] for a in acknowledgements]},
    )  # fmt: skip
    return cid


def candidate(db: Session, cid: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    row = _one(
        db,
        "SELECT c.*, d.market_code, d.code AS survey_code FROM survey_candidate c JOIN survey_definition d "
        "ON d.id = c.survey_definition_id WHERE c.id = :i AND d.market_code = ANY(:m)"
        + (" FOR UPDATE OF c" if lock else ""),
        i=cid, m=list(markets),
    )  # fmt: skip
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Candidate not found or not available to you")
    return row


def manifest_problems(db: Session, cand: Mapping[str, Any]) -> list[str]:
    """Recomputes every hash of a candidate from the stored rows and compares. Empty = intact."""
    out: list[str] = []
    if sha256_hex(cand["content"]) != cand["content_sha256"]:
        out.append("the content does not match its recorded hash")
    if manifest_sha256(list(cand["manifest"])) != cand["manifest_sha256"]:
        out.append("the manifest does not match its recorded hash")
    for e in cand["manifest"]:
        row = _one(
            db,
            "SELECT state, content, sha256 FROM survey_asset_version WHERE kind = :k AND code = :c AND version = :v",
            k=e["kind"], c=e["code"], v=e["version"],
        )  # fmt: skip
        where = f"{e['kind']} {e['code']} version {e['version']}"
        if row is None:
            out.append(f"{where} no longer exists")
        elif row["state"] != "FROZEN":
            out.append(f"{where} is not frozen")
        elif not (sha256_hex(row["content"]) == row["sha256"] == e["sha256"]):
            out.append(f"{where} does not match the hash the manifest pinned")
    if not out and manifest_of(load_bundle(db, cand["content"])) != list(cand["manifest"]):
        out.append("the manifest does not pin exactly what the content refers to")  # missing or surplus entries
    return out


def _verify(db: Session, cand: Mapping[str, Any], actor: Actor, meta: RequestMeta | None) -> None:
    problems = manifest_problems(db, cand)
    if problems:
        _audit(
            db, actor, meta, "SURVEY.MANIFEST_MISMATCH", "survey_candidate", cand["id"], {"problems": problems},
            outcome="DENIED",
        )  # fmt: skip
        db.commit()  # the refusal itself is evidence and must survive the caller's rollback
        raise SurveyError(
            409,
            "MANIFEST_MISMATCH",
            "The candidate no longer matches what was submitted",
            [{"message": p} for p in problems],
        )


def _deny(
    db: Session, actor: Actor, meta: RequestMeta | None, action: str, cid: Any, code: str, message: str
) -> SurveyError:
    _audit(db, actor, meta, action, "survey_candidate", cid, {"code": code}, outcome="DENIED", reason=message)
    db.commit()
    return SurveyError(403, code, message)


def approver_of(db: Session, cid: uuid.UUID) -> str | None:
    row = _one(
        db,
        "SELECT actor_ref FROM survey_lifecycle_event WHERE subject_id = :s AND event = 'APPROVED' "
        "ORDER BY seq DESC LIMIT 1",
        s=cid,
    )  # fmt: skip
    return str(row["actor_ref"]) if row else None


def decide(
    db: Session, cid: uuid.UUID, markets: Sequence[str], verdict: str, comment: str, actor: Actor,
    meta: RequestMeta | None = None,
) -> None:  # fmt: skip
    cand = candidate(db, cid, markets, lock=True)
    who = _ref(actor)
    if status_of(db, cid) != "IN_REVIEW":
        raise SurveyError(409, "ALREADY_DECIDED", "This candidate is not waiting for a decision")
    if who == cand["submitted_by"] or who in cand["makers"]:
        # a permission is never enough: the identities must differ
        raise _deny(
            db,
            actor,
            meta,
            "SURVEY.REVIEW_DENIED",
            cid,
            "SELF_REVIEW_DENIED",
            "A maker of a candidate cannot decide it",
        )
    if verdict not in ("APPROVE", "REJECT"):
        raise SurveyError(422, "OPERATION_INVALID", "The verdict must be APPROVE or REJECT")
    if verdict == "REJECT" and not comment.strip():
        raise SurveyError(422, "COMMENT_REQUIRED", "Say why the candidate is sent back")
    _verify(db, cand, actor, meta)
    sid = cand["survey_definition_id"]
    if verdict == "APPROVE":
        _event(db, "CANDIDATE", cid, sid, "APPROVED", actor, comment.strip() or None)
        for e in cand["manifest"]:
            if e["kind"] == "WORDING":
                # append-only approval evidence naming the exact wording version and this candidate (D-178).
                # It records that the wording was reviewed in this candidate; it does NOT make synthetic wording
                # approved for operational use (D-183).
                db.execute(
                    text(
                        "INSERT INTO survey_wording_approval (id, item_code, "
                        "language, wording_version, wording_sha256, "
                        "candidate_id, actor_ref) VALUES (:i, :c, 'en', :v, :h, :cand, :by)"
                    ),
                    {"i": uuid.uuid4(), "c": e["code"], "v": e["version"], "h": e["sha256"], "cand": cid, "by": who},
                )
        _audit(
            db,
            actor,
            meta,
            "SURVEY.APPROVED",
            "survey_candidate",
            cid,
            {"n": cand["n"]},
            reason=comment.strip() or None,
        )
    else:
        _event(db, "CANDIDATE", cid, sid, "REJECTED", actor, comment.strip())
        _audit(db, actor, meta, "SURVEY.REJECTED", "survey_candidate", cid, {"n": cand["n"]}, reason=comment.strip())


def withdraw(
    db: Session, cid: uuid.UUID, markets: Sequence[str], reason: str, actor: Actor, meta: RequestMeta | None = None
) -> None:
    cand = candidate(db, cid, markets, lock=True)
    if _ref(actor) != cand["submitted_by"]:
        raise SurveyError(403, "NOT_SUBMITTER", "Only the person who submitted a candidate can withdraw it")
    if status_of(db, cid) not in OPEN_CANDIDATE:
        raise SurveyError(409, "ALREADY_DECIDED", "This candidate is no longer open")
    _event(db, "CANDIDATE", cid, cand["survey_definition_id"], "WITHDRAWN", actor, reason.strip() or None)
    _audit(
        db, actor, meta, "SURVEY.WITHDRAWN", "survey_candidate", cid, {"n": cand["n"]}, reason=reason.strip() or None
    )


def publish(
    db: Session, cid: uuid.UUID, markets: Sequence[str], effective_from: datetime | None, actor: Actor,
    meta: RequestMeta | None = None,
) -> uuid.UUID:  # fmt: skip
    cand = candidate(db, cid, markets, lock=True)
    who, sid = _ref(actor), cand["survey_definition_id"]
    if status_of(db, cid) != "APPROVED":
        raise SurveyError(409, "NOT_APPROVED", "Only an approved candidate can be published")
    if who == cand["submitted_by"] or who in cand["makers"]:
        raise _deny(
            db,
            actor,
            meta,
            "SURVEY.PUBLISH_DENIED",
            cid,
            "SELF_PUBLISH_DENIED",
            "A maker of a candidate cannot publish it",
        )
    if who == approver_of(db, cid):
        # most restrictive rule until governance decides whether an approver may also publish (D-182)
        raise _deny(
            db,
            actor,
            meta,
            "SURVEY.PUBLISH_DENIED",
            cid,
            "APPROVER_PUBLISH_DENIED",
            "The approver of a candidate cannot publish it",
        )
    _verify(db, cand, actor, meta)
    previous = _all(db, "SELECT id FROM survey_version WHERE survey_definition_id = :s ORDER BY version_no", s=sid)
    version_no = len(previous) + 1
    vid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO survey_version (id, survey_definition_id, version_no, label, candidate_id, effective_from, "
            "created_by) VALUES (:i, :s, :n, :l, :c, :e, :by)"
        ),
        {"i": vid, "s": sid, "n": version_no, "l": f"{version_no}.0", "c": cid, "e": effective_from, "by": who},
    )
    _event(db, "CANDIDATE", cid, sid, "PUBLISHED", actor, version=str(vid))
    # `effective_from` is recorded only: nothing takes effect on a date in SS-03A (owner decision D-165)
    _event(db, "VERSION", vid, sid, "PUBLISHED", actor, effective_from=effective_from)
    for v in previous:
        if status_of(db, v["id"]) == "PUBLISHED":
            _event(db, "VERSION", v["id"], sid, "SUPERSEDED", actor, by_version=str(vid))
    rebuild_usage(db, "VERSION", vid, list(cand["manifest"]))
    _audit(
        db, actor, meta, "SURVEY.PUBLISHED", "survey_version", vid,
        {"version_no": version_no, "candidate": str(cid), "manifest_sha256": cand["manifest_sha256"]},
    )  # fmt: skip
    return vid


def version(db: Session, vid: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    row = _one(
        db,
        "SELECT v.*, c.content, c.content_sha256, c.manifest, "
        "c.manifest_sha256, c.n AS candidate_n, d.code AS survey_code "
        "FROM survey_version v JOIN survey_candidate c ON c.id = v.candidate_id JOIN survey_definition d "
        "ON d.id = v.survey_definition_id WHERE v.id = :i AND d.market_code = ANY(:m)",
        i=vid, m=list(markets),
    )  # fmt: skip
    if row is None:
        raise SurveyError(404, "NOT_FOUND", "Version not found or not available to you")
    return row


def candidates_of(db: Session, sid: uuid.UUID) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT id, n, submitted_by, submitted_at FROM survey_candidate WHERE survey_definition_id = :s ORDER BY n",
        s=sid,
    )


def versions_of(db: Session, sid: uuid.UUID) -> list[dict[str, Any]]:
    return _all(
        db,
        "SELECT id, version_no, label, created_at FROM survey_version "
        "WHERE survey_definition_id = :s ORDER BY version_no",
        s=sid,
    )


# ------------------------------------------------------------------------------------ FI-2: what a reviewer is shown
def _names(db: Session, refs: Iterable[str]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for r in sorted(set(refs)):
        row = _one(db, "SELECT display_name FROM principal WHERE CAST(id AS text) = :r", r=r)
        out[r] = row["display_name"] if row else None
    return out


def restrictions(db: Session, cand: Mapping[str, Any], actor: Actor) -> dict[str, Any]:
    """What the identity rules allow THIS person to do with this candidate, and why not. Shown to a reviewer so the rule
    is visible before they try; ``decide``, ``withdraw`` and ``publish`` enforce the same rules whatever is shown, and a
    permission is needed as well."""
    who, status = _ref(actor), status_of(db, cand["id"])
    maker = who == cand["submitted_by"] or who in cand["makers"]
    approver = approver_of(db, cand["id"])
    decide_reason = "NOT_IN_REVIEW" if status != "IN_REVIEW" else "SELF_REVIEW_DENIED" if maker else None
    publish_reason = (
        "NOT_APPROVED" if status != "APPROVED"
        else "SELF_PUBLISH_DENIED" if maker
        else "APPROVER_PUBLISH_DENIED" if who == approver
        else None
    )  # fmt: skip
    withdraw_reason = (
        "NOT_OPEN" if status not in OPEN_CANDIDATE else None if who == cand["submitted_by"] else "NOT_SUBMITTER"
    )
    return {
        "is_maker": maker, "is_approver": approver is not None and who == approver,
        "can_decide": decide_reason is None, "decide_reason": decide_reason,
        "can_publish": publish_reason is None, "publish_reason": publish_reason,
        "can_withdraw": withdraw_reason is None, "withdraw_reason": withdraw_reason,
    }  # fmt: skip


def candidate_documents(db: Session, cand: Mapping[str, Any], actor: Actor) -> dict[str, Any]:
    """Everything a reviewer inspects: the frozen content, the full document of every pinned version with the hash the
    manifest pins and whether the stored document still has it, who made the candidate, what was acknowledged, the
    server's validation of this exact content, and what the identity rules allow the reader. Read-only."""
    assets = []
    for e in cand["manifest"]:
        row = _one(
            db,
            "SELECT state, sha256, content FROM survey_asset_version WHERE kind = :k AND code = :c AND version = :v",
            k=e["kind"], c=e["code"], v=e["version"],
        )  # fmt: skip
        intact = bool(row) and row is not None and row["state"] == "FROZEN" and row["sha256"] == e["sha256"]
        intact = intact and row is not None and sha256_hex(row["content"]) == e["sha256"]
        assets.append(
            {
                "kind": e["kind"], "code": e["code"], "version": e["version"], "sha256": e["sha256"],
                "intact": intact, "document": row["content"] if row else None,
            }
        )  # fmt: skip
    approver = approver_of(db, cand["id"])
    names = _names(db, [*cand["makers"], cand["submitted_by"], *([approver] if approver else [])])
    problems = manifest_problems(db, cand)
    findings = findings_of(db, cand["content"], cand["survey_definition_id"])
    v = _one(db, "SELECT id, label FROM survey_version WHERE candidate_id = :c", c=cand["id"])
    return {
        "id": cand["id"], "survey_id": cand["survey_definition_id"], "survey_code": cand["survey_code"],
        "n": cand["n"], "status": status_of(db, cand["id"]) or "UNKNOWN", "draft_revision": cand["draft_revision"],
        "note": cand["note"], "submitted_at": cand["submitted_at"],
        "submitted_by": {"ref": cand["submitted_by"], "name": names.get(cand["submitted_by"])},
        "makers": [{"ref": m, "name": names.get(m)} for m in sorted(set(cand["makers"]) | {cand["submitted_by"]})],
        "approver": {"ref": approver, "name": names.get(approver)} if approver else None,
        "content": cand["content"], "content_sha256": cand["content_sha256"],
        "manifest_sha256": cand["manifest_sha256"], "manifest_intact": not problems, "manifest_problems": problems,
        "assets": assets, "acknowledgements": list(cand["acknowledgements"] or []),
        "validation": {
            "blockers": sum(f["severity"] == "BLOCKER" for f in findings),
            "warnings": sum(f["severity"] == "WARNING" for f in findings),
            "findings": [{k: f[k] for k in ("code", "at", "severity", "message")} for f in findings],
        },
        "restrictions": restrictions(db, cand, actor),
        "version_id": v["id"] if v else None, "version_label": v["label"] if v else None,
    }  # fmt: skip


def survey_history(db: Session, sid: uuid.UUID) -> dict[str, Any]:
    """Every candidate and every version of a survey, oldest first, with the status derived from its events."""
    cands = _all(
        db,
        "SELECT id, n, draft_revision, content_sha256, manifest_sha256, note, makers, submitted_by, submitted_at "
        "FROM survey_candidate WHERE survey_definition_id = :s ORDER BY n",
        s=sid,
    )
    vers = _all(
        db,
        "SELECT v.id, v.version_no, v.label, v.candidate_id, v.created_at, v.created_by, c.n AS candidate_n, "
        "c.content_sha256 FROM survey_version v JOIN survey_candidate c ON c.id = v.candidate_id "
        "WHERE v.survey_definition_id = :s ORDER BY v.version_no",
        s=sid,
    )
    names = _names(db, [c["submitted_by"] for c in cands] + [v["created_by"] for v in vers])
    last = {
        c["id"]: _one(
            db,
            "SELECT e.event, e.reason, e.occurred_at, p.display_name FROM survey_lifecycle_event e "
            "LEFT JOIN principal p ON CAST(p.id AS text) = e.actor_ref "
            "WHERE e.subject_id = :s ORDER BY e.seq DESC LIMIT 1",
            s=c["id"],
        )
        or {}
        for c in cands
    }
    return {
        "candidates": [
            {
                "id": c["id"], "n": c["n"], "status": status_of(db, c["id"]) or "UNKNOWN",
                "draft_revision": c["draft_revision"], "content_sha256": c["content_sha256"],
                "manifest_sha256": c["manifest_sha256"], "note": c["note"],
                "submitted_by": names.get(c["submitted_by"]), "submitted_at": c["submitted_at"],
                "makers": len(set(c["makers"]) | {c["submitted_by"]}),
                "last_event": last[c["id"]].get("event"), "last_event_by": last[c["id"]].get("display_name"),
                "last_event_at": last[c["id"]].get("occurred_at"), "last_event_reason": last[c["id"]].get("reason"),
            }
            for c in cands
        ],
        "versions": [
            {
                "id": v["id"], "version_no": v["version_no"], "label": v["label"],
                "status": status_of(db, v["id"]) or "UNKNOWN", "candidate_id": v["candidate_id"],
                "candidate_n": v["candidate_n"], "content_sha256": v["content_sha256"],
                "published_by": names.get(v["created_by"]), "published_at": v["created_at"],
            }
            for v in vers
        ],
    }  # fmt: skip


# ------------------------------------------------------------------------------- LIB-1: the component library, read
COMPONENT_KINDS = ("MODULE", "ITEM", "CONDITION", "OPTION_SET")


def _doc(db: Session, kind: str, code: str, version: int) -> dict[str, Any] | None:
    return _one(
        db,
        "SELECT kind, code, version, state, sha256, content, owner_definition_id FROM survey_asset_version "
        "WHERE kind = :k AND code = :c AND version = :v",
        k=kind, c=code, v=version,
    )  # fmt: skip


def _usage(db: Session, markets: Sequence[str], kind: str, code: str, version: int) -> dict[str, int]:
    """How widely a version is used — from the DERIVED usage index (never the source of truth for anything else)."""
    row = _one(
        db,
        "SELECT count(*) AS versions, count(DISTINCT v.survey_definition_id) AS surveys "
        "FROM survey_asset_usage u JOIN survey_version v ON v.id = u.subject_id "
        "JOIN survey_definition d ON d.id = v.survey_definition_id "
        "WHERE u.subject_type = 'VERSION' AND u.kind = :k AND u.code = :c AND u.version = :v "
        "AND d.market_code = ANY(:m)",
        k=kind, c=code, v=version, m=list(markets),
    )  # fmt: skip
    return {"versions": int(row["versions"]) if row else 0, "surveys": int(row["surveys"]) if row else 0}


def _sources(pins: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "survey_id": v["survey_id"], "survey_code": v["survey_code"], "survey_name": v["survey_name"],
            "version_id": v["version_id"], "version_label": v["label"], "version_status": v["event"],
        }
        for v in pins
    ]  # fmt: skip


def _module_pairs(db: Session, index: Mapping[tuple[str, str, int], Any]) -> dict[tuple[str, int], set[int]]:
    """(item code, item version) → the wording versions it is published with, from the published modules."""
    pairs: dict[tuple[str, int], set[int]] = {}
    for kind, code, version in index:
        if kind != "MODULE":
            continue
        row = _doc(db, "MODULE", code, version)
        for n in row["content"].get("nodes", []) if row else []:
            ref = n.get("item")
            if isinstance(ref, dict):
                pairs.setdefault((str(ref.get("code")), int(ref.get("version") or 0)), set()).add(
                    int(ref.get("wording_version") or 0)
                )
    return pairs


def _summary(
    db: Session, kind: str, doc: Mapping[str, Any], wording: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """What a person recognises a component by. Only what the documents themselves say: nothing is invented."""
    if kind == "MODULE":
        nodes = doc.get("nodes", [])
        return {
            "title": str(doc.get("name") or doc.get("code")),
            "description": str((doc.get("authoring") or {}).get("intent") or ""),
            "category": str(doc.get("kind") or "COMMON"),
            "facts": {
                "questions": sum(n.get("type") == "QUESTION" for n in nodes),
                "statements": sum(n.get("type") == "STATEMENT" for n in nodes),
                "decisions": sum(n.get("type") == "DECISION" for n in nodes),
                "outcomes": list(doc.get("outcomes", [])),
            },
        }
    if kind == "ITEM":
        return {
            "title": str((wording or {}).get("text") or doc.get("intent") or doc.get("code")),
            "description": str(doc.get("intent") or ""),
            "category": str(doc.get("answer_type")),
            "facts": {
                "answer_type": doc.get("answer_type"), "option_set": doc.get("option_set"),
                "statement_role": doc.get("statement_role"), "lifecycle_role": doc.get("lifecycle_role"),
                "response_obligation": doc.get("response_obligation"),
                "delivery_mode": (wording or {}).get("delivery_mode"),
            },
        }  # fmt: skip
    if kind == "CONDITION":
        return {
            "title": str(doc.get("name") or doc.get("code")),
            "description": "",
            "category": "CONDITION",
            "facts": {
                "fields": sorted(fields_of(doc.get("ast") or {})),
                "params": doc.get("params") or {},
                "inputs": doc.get("inputs") or {},
            },
        }
    options = doc.get("options", [])
    return {
        "title": " / ".join(str(o.get("label") or o.get("code")) for o in options),
        "description": "",
        "category": "OPTION_SET",
        "facts": {
            "options": len(options),
            "exclusive": [o["code"] for o in options if o.get("exclusive")],
            "other": [o["code"] for o in options if o.get("is_other")],
        },
    }


def components(db: Session, markets: Sequence[str], kind: str, query: str = "") -> list[dict[str, Any]]:
    """The reusable library: PUBLISHED versions of one kind in the reader's markets (LIB-D-1), newest first per code."""
    if kind not in COMPONENT_KINDS:
        raise SurveyError(404, "NOT_FOUND", "Unknown kind of component")
    index = published_index(db, markets)
    latest: dict[str, int] = {}
    for k, code, version in index:
        if k == kind:
            latest[code] = max(latest.get(code, 0), version)
    pairs = _module_pairs(db, index) if kind == "ITEM" else {}
    out = []
    for (k, code, version), pins in sorted(index.items()):
        if k != kind:
            continue
        row = _doc(db, kind, code, version)
        if not row:
            continue
        wording_versions: list[int | None] = [None]
        if kind == "ITEM" and pairs.get((code, version)):
            wording_versions = [*sorted(pairs[(code, version)])]
        for wv in wording_versions:
            wrow = _doc(db, "WORDING", code, wv) if wv else None
            entry = {
                "kind": kind, "code": code, "version": version, "sha256": row["sha256"], "wording_version": wv,
                **_summary(db, kind, row["content"], wrow["content"] if wrow else None),
                "published_in": _sources(pins), "used_by": _usage(db, markets, kind, code, version),
                "latest_published_version": latest[code], "is_latest": latest[code] == version,
            }  # fmt: skip
            out.append(entry)
    q = query.strip().lower()
    if q:
        out = [
            e for e in out
            if q in e["title"].lower() or q in e["description"].lower() or q in e["code"].lower()
            or any(q in s["survey_name"].lower() for s in e["published_in"])
        ]  # fmt: skip
    return sorted(out, key=lambda e: (e["title"].lower(), e["code"], -e["version"]))


def component(
    db: Session, markets: Sequence[str], kind: str, code: str, version: int, wording_version: int | None = None
) -> dict[str, Any]:
    """One published component, complete: its document, every document it depends on (so it can be previewed and
    placed exactly as published), its published revisions, where it is used and where it came from."""
    if kind not in COMPONENT_KINDS:
        raise SurveyError(404, "NOT_FOUND", "Unknown kind of component")
    index = published_index(db, markets)
    pins = index.get((kind, code, version))
    row = _doc(db, kind, code, version)
    if not pins or not row:
        # not published in the reader's markets: it does not exist for them, whatever its real state
        raise SurveyError(404, "NOT_FOUND", "No such published component")
    doc = row["content"]
    wanted: list[tuple[str, str, int]] = []

    def want_item(item_code: str, item_version: int, wv: int | None) -> None:
        wanted.append(("ITEM", item_code, item_version))
        if wv:
            wanted.append(("WORDING", item_code, wv))
        irow = _doc(db, "ITEM", item_code, item_version)
        ref = (irow["content"].get("option_set") or {}) if irow else {}
        if ref.get("code"):
            wanted.append(("OPTION_SET", str(ref["code"]), int(ref.get("version") or 0)))

    if kind == "MODULE":
        for n in doc.get("nodes", []):
            if n.get("type") == "DECISION":
                c = (n.get("binding") or {}).get("condition") or {}
                if c.get("code"):
                    wanted.append(("CONDITION", str(c["code"]), int(c.get("version") or 0)))
            elif isinstance(n.get("item"), dict):
                want_item(
                    str(n["item"].get("code")), int(n["item"].get("version") or 0), n["item"].get("wording_version")
                )
    elif kind == "ITEM":
        pairs = _module_pairs(db, index).get((code, version), set())
        if wording_version is None and len(pairs) == 1:
            wording_version = next(iter(pairs))
        if wording_version not in pairs:
            raise SurveyError(404, "NOT_FOUND", "This question is not published with that wording version")
        wanted.append(("WORDING", code, wording_version))
        ref = doc.get("option_set") or {}
        if ref.get("code"):
            wanted.append(("OPTION_SET", str(ref["code"]), int(ref.get("version") or 0)))
    dependencies, missing = [], []
    for k, c, v in dict.fromkeys(wanted):
        drow = _doc(db, k, c, v)
        if not drow or (k, c, v) not in index:
            missing.append({"kind": k, "code": c, "version": v})
            continue
        dependencies.append(
            {"kind": k, "code": c, "version": v, "sha256": drow["sha256"], "document": drow["content"]}
        )  # fmt: skip
    wdoc = next((d["document"] for d in dependencies if d["kind"] == "WORDING" and d["code"] == code), None)
    revisions = [
        {"version": v, "sha256": (_doc(db, kind, code, v) or {}).get("sha256", ""), "published_in": _sources(p)}
        for (k, c, v), p in sorted(index.items())
        if k == kind and c == code
    ]
    fields: set[str] = set()
    for d in [{"kind": kind, "document": doc}, *dependencies]:
        if d["kind"] == "CONDITION":
            fields |= set(fields_of(d["document"].get("ast") or {}))
    return {
        "kind": kind, "code": code, "version": version, "sha256": row["sha256"], "wording_version": wording_version,
        **_summary(db, kind, doc, wdoc if kind == "ITEM" else None),
        "document": doc, "dependencies": dependencies, "missing_dependencies": missing,
        "revisions": revisions, "published_in": _sources(pins), "used_by": _usage(db, markets, kind, code, version),
        "latest_published_version": max(r["version"] for r in revisions),
        "is_latest": max(r["version"] for r in revisions) == version,
        "requires": {"fields": sorted(fields)},
        "derived_from": (doc.get("authoring") or {}).get("derived_from"),
    }  # fmt: skip


# ------------------------------------------------------------------------------------------------- derived usage index
def rebuild_usage(db: Session, subject_type: str, subject_id: uuid.UUID, manifest: list[dict[str, Any]]) -> None:
    """Which candidate or version pins which asset version. DERIVED from the manifest: it can be rebuilt at any time and
    is never the source of truth."""
    db.execute(text("DELETE FROM survey_asset_usage WHERE subject_id = :s"), {"s": subject_id})
    for e in manifest:
        db.execute(
            text(
                "INSERT INTO survey_asset_usage (subject_type, subject_id, kind, code, version) "
                "VALUES (:t, :s, :k, :c, :v)"
            ),
            {"t": subject_type, "s": subject_id, "k": e["kind"], "c": e["code"], "v": e["version"]},
        )


def library(db: Session, kind: str, markets: Sequence[str]) -> list[dict[str, Any]]:
    """The legacy list of the survey library (SS-03A): asset versions of one kind with their fingerprint and how widely
    they are pinned. Since the LIB-1 security correction it lists ONLY what is reusable — versions pinned by a published
    survey version in the reader's markets (the rule of ``published_index``, owner decision LIB-D-1) — whether or not
    the library setting is on. A draft, a version frozen only in an unpublished, rejected or withdrawn candidate, and
    anything of another market are not listed and not counted. ``candidates`` counts the published candidates only."""
    if kind not in ASSET_KINDS:
        raise SurveyError(404, "NOT_FOUND", "Unknown kind of asset")
    out = []
    for (k, code, version), pins in sorted(published_index(db, markets).items()):
        if k != kind:
            continue
        row = _one(
            db,
            "SELECT sha256, frozen_at FROM survey_asset_version WHERE kind = :k AND code = :c AND version = :v "
            "AND state = 'FROZEN'",
            k=kind, c=code, v=version,
        )  # fmt: skip
        if row:
            out.append(
                {
                    "kind": kind, "code": code, "version": version, "sha256": row["sha256"],
                    "frozen_at": row["frozen_at"], "candidates": len(pins), "versions": len(pins),
                }
            )  # fmt: skip
    return out
