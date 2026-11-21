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
def apply_operation(
    db: Session, sid: uuid.UUID, markets: Sequence[str], expected_revision: int, operation: Mapping[str, Any],
    actor: Actor, meta: RequestMeta | None = None,
) -> dict[str, Any]:  # fmt: skip
    """Applies ONE operation to the draft. A stale ``expected_revision`` is refused before anything is written."""
    survey(db, sid, markets)
    d = draft(db, sid, lock=True)
    if d["revision"] != expected_revision:
        raise SurveyError(
            409,
            "STALE_DRAFT",
            f"The draft is at revision {d['revision']}; this change was made against {expected_revision}",
        )
    who, op = _ref(actor), operation.get("op")
    summary: dict[str, Any] = {"op": op}
    content = d["content"]
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
        content = new
    elif op in ("PUT_ASSET", "REMOVE_ASSET"):
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
            code, version = str(operation.get("code")), int(operation.get("version") or 0)
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
            raise SurveyError(
                409, "ASSET_OWNED_ELSEWHERE", f"{kind} {code} version {version} is a draft of another survey"
            )
        if op == "PUT_ASSET":
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
        summary.update(kind=kind, code=code, version=version)
    else:
        raise SurveyError(422, "OPERATION_INVALID", "Unknown operation")
    makers = sorted(set(d["makers"]) | {who})
    db.execute(
        text(
            "UPDATE survey_draft SET revision = revision + 1, content = CAST(:c AS jsonb), makers = CAST(:m AS jsonb), "
            "updated_at = now(), updated_by = :by WHERE id = :i"
        ),
        {"c": json.dumps(content), "m": json.dumps(makers), "by": who, "i": d["id"]},
    )
    _audit(
        db, actor, meta, "SURVEY.DRAFT_CHANGED", "survey_definition", sid, {**summary, "revision": d["revision"] + 1}
    )
    return draft(db, sid)


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


def findings_of(db: Session, content: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Server validation of a content document: structural problems first, then every rule of the validator."""
    problems = check_document("SURVEY", content)
    if problems:
        return [{"code": p.code, "at": p.path, "severity": "BLOCKER", "message": p.detail or p.code} for p in problems]
    return [f.__dict__ | {"code": f.code} for f in validate(load_bundle(db, content))]


# ---------------- candidates
def submit(
    db: Session, sid: uuid.UUID, markets: Sequence[str], note: str, acknowledgements: list[dict[str, Any]],
    actor: Actor, meta: RequestMeta | None = None,
) -> uuid.UUID:  # fmt: skip
    """Freezes what the draft pins and inserts an immutable candidate. The draft stays editable."""
    survey(db, sid, markets)
    d = draft(db, sid, lock=True)
    content = d["content"]
    blockers = [f for f in findings_of(db, content) if f["severity"] == "BLOCKER"]
    if blockers:
        raise SurveyError(
            422, "VALIDATION_BLOCKED", f"{len(blockers)} blocker(s) must be fixed before submitting", blockers
        )
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
        {"n": n, "content_sha256": sha256_hex(content), "manifest_sha256": manifest_sha256(manifest)},
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


def library(db: Session, kind: str) -> list[dict[str, Any]]:
    """Frozen asset versions of one kind, with how many candidates and versions pin each."""
    if kind not in ASSET_KINDS:
        raise SurveyError(404, "NOT_FOUND", "Unknown kind of asset")
    return _all(
        db,
        "SELECT a.kind, a.code, a.version, a.sha256, a.frozen_at, "
        "(SELECT count(*) FROM survey_asset_usage u WHERE u.kind = a.kind "
        "AND u.code = a.code AND u.version = a.version "
        " AND u.subject_type = 'CANDIDATE') AS candidates, "
        "(SELECT count(*) FROM survey_asset_usage u WHERE u.kind = a.kind "
        "AND u.code = a.code AND u.version = a.version "
        " AND u.subject_type = 'VERSION') AS versions "
        "FROM survey_asset_version a WHERE a.kind = :k AND a.state = 'FROZEN' ORDER BY a.code, a.version",
        k=kind,
    )
