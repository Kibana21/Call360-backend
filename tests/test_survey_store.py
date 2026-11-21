"""SS-03A.2 — persistence and governance of survey definitions, on the isolated test database only.

Immutability, identity rules, optimistic concurrency, manifest verification, append-only history and audit, the derived
usage index and the governed catalogs. Every assertion that a row cannot be changed is made against the DATABASE itself,
not only the service."""

# ruff: noqa: E501 — the SQL statements in these tests are kept on one line each, as in the migrations
from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.audit.chain import verify_chain
from app.core.settings import Settings
from app.domain.survey import store
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.store import SurveyError
from tests.support import Account, make_account, migrate
from tests.survey_support import MARKETS, acks_for, actor_of, build_draft, fixture_bundle

HEAD, BEFORE = "0027_survey_definitions", "0026_gpt_live_provider"
SURVEY_TABLES = {
    "survey_definition", "survey_draft", "survey_asset_version", "survey_candidate", "survey_version",
    "survey_lifecycle_event", "survey_wording_approval", "survey_asset_usage", "survey_catalog_entry",
}  # fmt: skip


@pytest.fixture()
def people(db: Session) -> tuple[Account, Account, Account]:
    """Three different people. None holds any survey permission: the service is called directly, and what is under test
    here is the IDENTITY rules, which no permission can satisfy."""
    return make_account(db, prefix="author"), make_account(db, prefix="checker"), make_account(db, prefix="publisher")


def _refused(db: Session, sql: str, **p: Any) -> str:
    with pytest.raises(DBAPIError) as e:
        db.execute(text(sql), p)
    db.rollback()
    return str(e.value.orig)


def _events(db: Session, subject: uuid.UUID) -> list[str]:
    return [h["event"] for h in store.history(db, subject)]


def _published(
    db: Session, people: tuple[Account, Account, Account], prefix: str = "K1"
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    author, checker, publisher = people
    sid, _ = build_draft(db, author, prefix)
    cid = store.submit(db, sid, MARKETS, "first", acks_for(db, sid), actor_of(author))
    store.decide(db, cid, MARKETS, "APPROVE", "ok", actor_of(checker))
    vid = store.publish(db, cid, MARKETS, None, actor_of(publisher))
    db.commit()
    return sid, cid, vid


# ---------------------------------------------------------------- schema: additive, and nothing of Script Studio touched
def test_the_migration_is_additive_and_points_at_no_script_table(db: Session) -> None:
    tables = set(db.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'call360_test'")).scalars())
    assert SURVEY_TABLES <= tables
    fks = db.execute(
        text(
            "SELECT cl.relname, ref.relname FROM pg_constraint c JOIN pg_class cl ON cl.oid = c.conrelid "
            "JOIN pg_class ref ON ref.oid = c.confrelid JOIN pg_namespace n ON n.oid = cl.relnamespace "
            "WHERE c.contype = 'f' AND n.nspname = 'call360_test'"
        )
    ).all()
    out_of_survey = {(a, b) for a, b in fks if a in SURVEY_TABLES and b not in SURVEY_TABLES}
    into_survey = {(a, b) for a, b in fks if b in SURVEY_TABLES and a not in SURVEY_TABLES}
    assert out_of_survey == set() and into_survey == set()  # no link in either direction, to scripts or anything else


def test_status_is_derived_no_candidate_or_version_row_carries_one(db: Session) -> None:
    cols = db.execute(
        text(
            "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'call360_test' "
            "AND table_name IN ('survey_candidate', 'survey_version', 'survey_asset_version')"
        )
    ).all()
    by: dict[str, set[str]] = {}
    for t, c in cols:
        by.setdefault(t, set()).add(c)
    assert "status" not in by["survey_candidate"] and "status" not in by["survey_version"]
    assert not any(
        "approv" in c for c in by["survey_asset_version"]
    )  # approval is evidence elsewhere, never a flag here


def test_survey_permissions_exist_and_are_granted_to_no_role(db: Session) -> None:
    held = db.execute(
        text(
            "SELECT p.code, count(rp.role_id) FROM permission p LEFT JOIN role_permission rp ON rp.permission_id = p.id "
            "WHERE p.code LIKE 'survey.%' GROUP BY p.code ORDER BY p.code"
        )
    ).all()
    assert [tuple(r) for r in held] == [
        ("survey.approve", 0),
        ("survey.edit", 0),
        ("survey.publish", 0),
        ("survey.read", 0),
    ]


def test_catalogs_are_synthetic_unapproved_and_no_field_is_speakable(db: Session) -> None:
    rows = db.execute(text("SELECT catalog, code, attributes, approval, is_synthetic FROM survey_catalog_entry")).all()
    assert {r[0] for r in rows} == {"FIELD", "OUTCOME", "RESPONSE_OBLIGATION"}
    assert all(r[3] == "SYNTHETIC_UNAPPROVED" and r[4] is True for r in rows)
    fields = [r for r in rows if r[0] == "FIELD"]
    assert len(fields) == 8 and all(r[2]["speakable"] is False for r in fields)  # default-deny (D-181)
    classes = {r[2]["class"] for r in rows if r[0] == "OUTCOME"}
    assert "NON_ANSWER_EXCEPTION" not in classes  # the category exists in the schema; no outcome of it does (D-180)
    new = "INSERT INTO survey_catalog_entry (id, catalog, code, attributes, approval, created_by) VALUES (:i, :c, :k, CAST(:a AS jsonb), :ap, 'test')"
    # the database stores no approval state other than "synthetic, unapproved"
    assert "ck_survey_catalog_entry_unapproved" in _refused(
        db, new, i=uuid.uuid4(), c="OUTCOME", k="X", a='{"class": "EXCEPTION"}', ap="APPROVED_BY_SC"
    )
    # a field cannot be stored without an explicit speakable flag; an outcome class outside the schema is refused
    assert "ck_survey_catalog_entry_speakable" in _refused(
        db, new, i=uuid.uuid4(), c="FIELD", k="x.y", a='{"type": "TEXT"}', ap="SYNTHETIC_UNAPPROVED"
    )
    assert "ck_survey_catalog_entry_outcome_class" in _refused(
        db, new, i=uuid.uuid4(), c="OUTCOME", k="X", a='{"class": "WHATEVER"}', ap="SYNTHETIC_UNAPPROVED"
    )
    # the non-answer category is admitted by the schema — and still nothing is seeded in it
    db.execute(
        text(new),
        {
            "i": uuid.uuid4(),
            "c": "OUTCOME",
            "k": "T-NA",
            "a": '{"class": "NON_ANSWER_EXCEPTION"}',
            "ap": "SYNTHETIC_UNAPPROVED",
        },
    )
    db.rollback()


# ---------------------------------------------------------------------------------- drafts and optimistic concurrency
def test_a_draft_is_revisioned_and_a_stale_revision_changes_nothing(
    db: Session, people: tuple[Account, Account, Account]
) -> None:
    author = people[0]
    sid, _ = build_draft(db, author, "K1")
    before = store.draft(db, sid)
    code = before["content"]["code"]
    assert before["revision"] > 0
    assets_before = db.execute(text("SELECT count(*), max(sha256) FROM survey_asset_version")).one()
    stale = {"op": "SET_CONTENT", "content": {**before["content"], "sequence": []}}
    with pytest.raises(SurveyError) as e:
        store.apply_operation(db, sid, MARKETS, before["revision"] - 1, stale, actor_of(author))
    assert (e.value.status, e.value.code) == (409, "STALE_DRAFT")
    db.rollback()
    after = store.draft(db, sid)
    assert (after["revision"], after["content"], after["updated_at"]) == (
        before["revision"],
        before["content"],
        before["updated_at"],
    )
    assert db.execute(text("SELECT count(*), max(sha256) FROM survey_asset_version")).one() == assets_before
    # with the right revision the same change is accepted, and the revision advances by exactly one
    done = store.apply_operation(db, sid, MARKETS, before["revision"], stale, actor_of(author))
    assert done["revision"] == before["revision"] + 1 and done["content"]["code"] == code
    db.commit()
    # the database itself refuses a revision that does not advance by one, and refuses to delete a draft
    assert "advances by exactly one" in _refused(
        db, "UPDATE survey_draft SET revision = revision + 2 WHERE survey_definition_id = :s", s=sid
    )
    assert "advances by exactly one" in _refused(
        db, "UPDATE survey_draft SET content = '{}'::jsonb WHERE survey_definition_id = :s", s=sid
    )
    assert "never deleted" in _refused(db, "DELETE FROM survey_draft WHERE survey_definition_id = :s", s=sid)


def test_a_malformed_document_or_operation_is_refused_and_the_revision_does_not_move(
    db: Session, people: tuple[Account, Account, Account]
) -> None:
    author = people[0]
    sid, _ = build_draft(db, author, "K1")
    rev = store.draft(db, sid)["revision"]
    for op, code in (
        (
            {
                "op": "PUT_ASSET",
                "kind": "ITEM",
                "document": {"schema": "call360.survey.item/9", "code": "Q", "version": 1},
            },
            "DOCUMENT_INVALID",
        ),
        ({"op": "PUT_ASSET", "kind": "PROMPT", "document": {}}, "OPERATION_INVALID"),
        (
            {"op": "SET_CONTENT", "content": {"schema": "call360.survey.content/1", "code": "ANOTHER", "sequence": []}},
            "DOCUMENT_INVALID",
        ),
        ({"op": "DO_SOMETHING"}, "OPERATION_INVALID"),
    ):
        with pytest.raises(SurveyError) as e:
            store.apply_operation(db, sid, MARKETS, rev, op, actor_of(author))
        assert e.value.code == code
        db.rollback()
    assert store.draft(db, sid)["revision"] == rev


# ------------------------------------------------------------------------------------- submission and immutability
def test_blockers_prevent_submission_and_freeze_nothing(db: Session, people: tuple[Account, Account, Account]) -> None:
    author = people[0]
    sid, _ = build_draft(db, author, "K5")  # wording with variables: no field is allowlisted for speech
    with pytest.raises(SurveyError) as e:
        store.submit(db, sid, MARKETS, "", acks_for(db, sid), actor_of(author))
    assert (e.value.status, e.value.code) == (422, "VALIDATION_BLOCKED")
    assert {d["code"] for d in e.value.details or []} == {"VARIABLE_NOT_PERMITTED"}
    db.rollback()
    assert store.candidates_of(db, sid) == []
    owned = (
        db.execute(text("SELECT DISTINCT state FROM survey_asset_version WHERE owner_definition_id = :s"), {"s": sid})
        .scalars()
        .all()
    )
    assert owned == ["DRAFT"]


def test_submission_freezes_the_assets_and_inserts_an_immutable_candidate(
    db: Session, people: tuple[Account, Account, Account]
) -> None:
    author = people[0]
    sid, sfx = build_draft(db, author, "K7")
    d = store.draft(db, sid)
    cid = store.submit(db, sid, MARKETS, "please review", acks_for(db, sid), actor_of(author))
    db.commit()
    cand = store.candidate(db, cid, MARKETS)
    assert (cand["n"], cand["draft_revision"], cand["submitted_by"]) == (1, d["revision"], str(author.principal_id))
    assert cand["content_sha256"] == sha256_hex(cand["content"]) == sha256_hex(d["content"])
    assert (
        cand["manifest_sha256"] == sha256_hex(cand["manifest"]) and len(cand["manifest"]) == 9
    )  # 3 items, 3 wordings, 1 option set, 2 modules
    assert store.status_of(db, cid) == "IN_REVIEW" and _events(db, cid) == ["SUBMITTED"]
    assert store.manifest_problems(db, cand) == []
    states = (
        db.execute(text("SELECT DISTINCT state FROM survey_asset_version WHERE owner_definition_id = :s"), {"s": sid})
        .scalars()
        .all()
    )
    assert states == ["FROZEN"]
    # the draft stays editable; a frozen version does not — a change is a new version
    item = {**fixture_bundle("K7").items[("Q-CLEAR", 1)], "code": "Q-CLEAR" + sfx}
    with pytest.raises(SurveyError) as e:
        store.apply_operation(
            db,
            sid,
            MARKETS,
            d["revision"],
            {"op": "PUT_ASSET", "kind": "ITEM", "document": {**item, "intent": "changed"}},
            actor_of(author),
        )
    assert e.value.code == "ASSET_FROZEN"
    db.rollback()
    store.apply_operation(
        db,
        sid,
        MARKETS,
        d["revision"],
        {"op": "PUT_ASSET", "kind": "ITEM", "document": {**item, "version": 2}},
        actor_of(author),
    )
    db.commit()
    # the DATABASE refuses every change to what is frozen or submitted
    k = {"s": sid, "c": cid}
    assert "immutable" in _refused(
        db,
        "UPDATE survey_asset_version SET content = '{}'::jsonb WHERE owner_definition_id = :s AND state = 'FROZEN'",
        **k,
    )
    assert "immutable" in _refused(
        db,
        "UPDATE survey_asset_version SET state = 'DRAFT', frozen_at = NULL WHERE owner_definition_id = :s AND state = 'FROZEN'",
        **k,
    )
    assert "immutable" in _refused(
        db, "DELETE FROM survey_asset_version WHERE owner_definition_id = :s AND state = 'FROZEN'", **k
    )
    for sql in (
        "UPDATE survey_candidate SET note = 'x' WHERE id = :c",
        "UPDATE survey_candidate SET content = '{}'::jsonb WHERE id = :c",
        "UPDATE survey_candidate SET manifest_sha256 = repeat('0', 64) WHERE id = :c",
        "DELETE FROM survey_candidate WHERE id = :c",
        "UPDATE survey_lifecycle_event SET event = 'APPROVED' WHERE subject_id = :c",
        "DELETE FROM survey_lifecycle_event WHERE subject_id = :c",
    ):
        _refused(db, sql, **k)
    assert (
        store.status_of(db, cid) == "IN_REVIEW" and store.manifest_problems(db, store.candidate(db, cid, MARKETS)) == []
    )


# ------------------------------------------------------------------------------- identity rules, service and database
def test_approval_and_publication_need_different_people_whatever_they_are_permitted(
    db: Session, people: tuple[Account, Account, Account]
) -> None:
    author, checker, publisher = people
    sid, _ = build_draft(db, author, "K1")
    cid = store.submit(db, sid, MARKETS, "", acks_for(db, sid), actor_of(author))
    db.commit()
    with pytest.raises(SurveyError) as e:  # a maker cannot decide the candidate
        store.decide(db, cid, MARKETS, "APPROVE", "", actor_of(author))
    assert (e.value.status, e.value.code) == (403, "SELF_REVIEW_DENIED")
    with pytest.raises(SurveyError) as e:  # nor publish it before or after approval
        store.publish(db, cid, MARKETS, None, actor_of(publisher))
    assert e.value.code == "NOT_APPROVED"
    db.rollback()
    with pytest.raises(SurveyError) as e:
        store.decide(db, cid, MARKETS, "REJECT", "  ", actor_of(checker))
    assert e.value.code == "COMMENT_REQUIRED"
    db.rollback()
    store.decide(db, cid, MARKETS, "APPROVE", "looks right", actor_of(checker))
    db.commit()
    assert store.status_of(db, cid) == "APPROVED"
    for who, code in ((author, "SELF_PUBLISH_DENIED"), (checker, "APPROVER_PUBLISH_DENIED")):
        with pytest.raises(SurveyError) as e:
            store.publish(db, cid, MARKETS, None, actor_of(who))
        assert (e.value.status, e.value.code) == (403, code)
    with pytest.raises(SurveyError) as e:  # a decision is made once
        store.decide(db, cid, MARKETS, "REJECT", "changed my mind", actor_of(checker))
    assert e.value.code == "ALREADY_DECIDED"
    db.rollback()
    vid = store.publish(db, cid, MARKETS, None, actor_of(publisher))
    db.commit()
    assert store.status_of(db, cid) == "PUBLISHED" and store.status_of(db, vid) == "PUBLISHED"
    assert _events(db, cid) == ["SUBMITTED", "APPROVED", "PUBLISHED"] and _events(db, vid) == ["PUBLISHED"]
    # each refusal is itself in the audit trail
    denied = (
        db.execute(
            text("SELECT action FROM audit_event WHERE entity_id = :c AND outcome = 'DENIED' ORDER BY seq"),
            {"c": str(cid)},
        )
        .scalars()
        .all()
    )
    assert denied == ["SURVEY.REVIEW_DENIED", "SURVEY.PUBLISH_DENIED", "SURVEY.PUBLISH_DENIED"]


def test_the_database_enforces_the_identity_rules_and_transitions_without_the_service(
    db: Session, people: tuple[Account, Account, Account]
) -> None:
    author, checker, publisher = people
    sid, _ = build_draft(db, author, "K1")
    cid = store.submit(db, sid, MARKETS, "", acks_for(db, sid), actor_of(author))
    db.commit()
    ins = (
        "INSERT INTO survey_lifecycle_event (id, subject_type, subject_id, survey_definition_id, event, actor_ref) "
        "VALUES (:i, :t, :s, :d, :e, :by)"
    )

    def event(e: str, by: Account | str, subject: uuid.UUID = cid, t: str = "CANDIDATE") -> dict[str, Any]:
        return {
            "i": uuid.uuid4(),
            "t": t,
            "s": subject,
            "d": sid,
            "e": e,
            "by": by if isinstance(by, str) else str(by.principal_id),
        }

    assert "maker of a candidate" in _refused(db, ins, **event("APPROVED", author))  # the submitter approving
    assert "illegal candidate transition" in _refused(db, ins, **event("PUBLISHED", publisher))  # never approved
    assert "illegal candidate transition" in _refused(db, ins, **event("SUBMITTED", author))  # submitted twice
    assert "unknown candidate" in _refused(db, ins, **event("APPROVED", checker, uuid.uuid4()))
    new_version = (
        "INSERT INTO survey_version (id, survey_definition_id, version_no, label, candidate_id, created_by) "
        "VALUES (:i, :d, 1, '1.0', :c, 'x')"
    )
    assert "approved candidate" in _refused(
        db, new_version, i=uuid.uuid4(), d=sid, c=cid
    )  # no version without approval
    db.execute(text(ins), event("APPROVED", checker))
    db.commit()
    assert "approver of a candidate" in _refused(db, ins, **event("PUBLISHED", checker))
    assert "maker of a candidate" in _refused(db, ins, **event("PUBLISHED", author))
    assert "illegal candidate transition" in _refused(db, ins, **event("REJECTED", publisher))  # already approved
    vid = uuid.uuid4()
    db.execute(text(new_version), {"i": vid, "d": sid, "c": cid})
    db.execute(text(ins), event("PUBLISHED", publisher))
    db.execute(text(ins), event("PUBLISHED", publisher, vid, "VERSION"))
    db.commit()
    assert "illegal version transition" in _refused(db, ins, **event("PUBLISHED", publisher, vid, "VERSION"))
    for sql in ("UPDATE survey_version SET label = '9.9' WHERE id = :v", "DELETE FROM survey_version WHERE id = :v"):
        _refused(db, sql, v=vid)


# ------------------------------------------------------------------------------------------------------ supersession
def test_a_changed_draft_supersedes_and_an_old_approval_cannot_be_used(
    db: Session, people: tuple[Account, Account, Account]
) -> None:
    author, checker, publisher = people
    sid, _ = build_draft(db, author, "K1")
    c1 = store.submit(db, sid, MARKETS, "", acks_for(db, sid), actor_of(author))
    store.decide(db, c1, MARKETS, "APPROVE", "", actor_of(checker))
    db.commit()
    d = store.draft(db, sid)
    store.apply_operation(
        db, sid, MARKETS, d["revision"], {"op": "SET_CONTENT", "content": d["content"]}, actor_of(author)
    )
    c2 = store.submit(db, sid, MARKETS, "again", acks_for(db, sid), actor_of(author))
    db.commit()
    assert store.status_of(db, c1) == "SUPERSEDED" and _events(db, c1) == ["SUBMITTED", "APPROVED", "SUPERSEDED"]
    assert store.status_of(db, c2) == "IN_REVIEW" and store.candidate(db, c2, MARKETS)["n"] == 2
    # identical content to the candidate that WAS approved — and still not approved: approval belongs to a candidate id
    assert store.candidate(db, c1, MARKETS)["content_sha256"] == store.candidate(db, c2, MARKETS)["content_sha256"]
    for cid in (c1, c2):
        with pytest.raises(SurveyError) as e:
            store.publish(db, cid, MARKETS, None, actor_of(publisher))
        assert e.value.code == "NOT_APPROVED"
        db.rollback()
    with pytest.raises(SurveyError) as e:  # only its submitter withdraws a candidate
        store.withdraw(db, c2, MARKETS, "", actor_of(checker))
    assert e.value.code == "NOT_SUBMITTER"
    db.rollback()
    store.withdraw(db, c2, MARKETS, "not ready", actor_of(author))
    db.commit()
    assert store.status_of(db, c2) == "WITHDRAWN"


def test_a_new_version_supersedes_the_previous_one_in_the_history_only(
    db: Session, people: tuple[Account, Account, Account]
) -> None:
    author, checker, publisher = people
    sid, c1, v1 = _published(db, people)
    d = store.draft(db, sid)
    store.apply_operation(
        db, sid, MARKETS, d["revision"], {"op": "SET_CONTENT", "content": d["content"]}, actor_of(author)
    )
    c2 = store.submit(db, sid, MARKETS, "", acks_for(db, sid), actor_of(author))
    store.decide(db, c2, MARKETS, "APPROVE", "", actor_of(checker))
    v2 = store.publish(db, c2, MARKETS, None, actor_of(publisher))
    db.commit()
    assert [store.status_of(db, v) for v in (v1, v2)] == ["SUPERSEDED", "PUBLISHED"]
    assert [v["version_no"] for v in store.versions_of(db, sid)] == [1, 2]
    assert (
        store.version(db, v1, MARKETS)["content_sha256"] == store.candidate(db, c1, MARKETS)["content_sha256"]
    )  # v1 is untouched


# ------------------------------------------------------------------------------------------------ manifest verification
def test_tampering_with_a_manifest_is_detected_and_refused(
    db: Session, people: tuple[Account, Account, Account]
) -> None:
    author, checker, publisher = people
    sid, _ = build_draft(db, author, "K1")
    good = store.submit(db, sid, MARKETS, "", acks_for(db, sid), actor_of(author))
    db.commit()
    real = store.candidate(db, good, MARKETS)

    def forge(n: int, **changed: Any) -> uuid.UUID:
        """A candidate row written around the service, as someone with database access might."""
        row = {
            "content": real["content"],
            "content_sha256": real["content_sha256"],
            "manifest": real["manifest"],
            "manifest_sha256": real["manifest_sha256"],
            **changed,
        }
        fid = uuid.uuid4()
        db.execute(
            text(
                "INSERT INTO survey_candidate (id, survey_definition_id, n, draft_revision, content, content_sha256, manifest, "
                "manifest_sha256, makers, submitted_by) VALUES (:i, :s, :n, 0, CAST(:c AS jsonb), :ch, CAST(:m AS jsonb), :mh, "
                "CAST(:mk AS jsonb), :by)"
            ),
            {"i": fid, "s": sid, "n": n, "c": json.dumps(row["content"]), "ch": row["content_sha256"], "m": json.dumps(row["manifest"]),
             "mh": row["manifest_sha256"], "mk": json.dumps([str(author.principal_id)]), "by": str(author.principal_id)},
        )  # fmt: skip
        db.execute(
            text(
                "INSERT INTO survey_lifecycle_event (id, subject_type, subject_id, survey_definition_id, event, actor_ref) VALUES (:i, 'CANDIDATE', :s, :d, 'SUBMITTED', :by)"
            ),
            {"i": uuid.uuid4(), "s": fid, "d": sid, "by": str(author.principal_id)},
        )
        db.commit()
        return fid

    wrong_entry = [{**e, "sha256": "0" * 64} if i == 0 else e for i, e in enumerate(real["manifest"])]
    cases = {
        "a pinned hash was changed": forge(2, manifest=wrong_entry, manifest_sha256=sha256_hex(wrong_entry)),
        "the manifest hash was changed": forge(3, manifest_sha256="1" * 64),
        "the content was changed": forge(4, content={**real["content"], "sequence": []}),
        "an entry was removed": forge(
            5, manifest=real["manifest"][1:], manifest_sha256=sha256_hex(real["manifest"][1:])
        ),
    }
    for why, fid in cases.items():
        assert store.manifest_problems(db, store.candidate(db, fid, MARKETS)), why
        with pytest.raises(SurveyError) as e:
            store.decide(db, fid, MARKETS, "APPROVE", "", actor_of(checker))
        assert (e.value.status, e.value.code) == (409, "MANIFEST_MISMATCH"), why
        db.rollback()
        assert store.status_of(db, fid) == "IN_REVIEW", why  # nothing was approved
    refusals = db.execute(
        text(
            "SELECT count(*) FROM audit_event WHERE action = 'SURVEY.MANIFEST_MISMATCH' AND outcome = 'DENIED' AND entity_id = ANY(:ids)"
        ),
        {"ids": [str(f) for f in cases.values()]},
    ).scalar_one()
    assert refusals == 4
    # the untouched candidate still verifies, is approved and is published
    store.decide(db, good, MARKETS, "APPROVE", "", actor_of(checker))
    store.publish(db, good, MARKETS, None, actor_of(publisher))
    db.commit()


# ---------------------------------------------------------------------------- approval evidence, usage index, catalogs
def test_wording_approval_is_append_only_evidence_and_the_wording_row_is_never_touched(
    db: Session, people: tuple[Account, Account, Account]
) -> None:
    sid, cid, _ = _published(db, people, "K7")
    cand = store.candidate(db, cid, MARKETS)
    wordings = [e for e in cand["manifest"] if e["kind"] == "WORDING"]
    rows = db.execute(
        text(
            "SELECT item_code, language, wording_version, wording_sha256, candidate_id, actor_ref FROM survey_wording_approval WHERE candidate_id = :c ORDER BY item_code"
        ),
        {"c": cid},
    ).all()
    assert [(r[0], r[1], r[2], r[3]) for r in rows] == [(e["code"], "en", e["version"], e["sha256"]) for e in wordings]
    assert {r[4] for r in rows} == {cid} and {r[5] for r in rows} == {
        str(people[1].principal_id)
    }  # this candidate, this checker
    frozen = db.execute(
        text("SELECT sha256, state FROM survey_asset_version WHERE kind = 'WORDING' AND code = :c AND version = :v"),
        {"c": wordings[0]["code"], "v": wordings[0]["version"]},
    ).one()
    assert tuple(frozen) == (wordings[0]["sha256"], "FROZEN")
    for sql in (
        "UPDATE survey_wording_approval SET actor_ref = 'x' WHERE candidate_id = :c",
        "DELETE FROM survey_wording_approval WHERE candidate_id = :c",
    ):
        _refused(db, sql, c=cid)


def test_the_usage_index_is_derived_and_can_be_rebuilt(db: Session, people: tuple[Account, Account, Account]) -> None:
    sid, cid, vid = _published(db, people, "K7")
    cand = store.candidate(db, cid, MARKETS)
    q_clear = next(e["code"] for e in cand["manifest"] if e["kind"] == "ITEM" and e["code"].startswith("Q-CLEAR"))
    count = "SELECT count(*) FROM survey_asset_usage WHERE subject_id = :s"
    assert (
        db.execute(text(count), {"s": cid}).scalar_one()
        == db.execute(text(count), {"s": vid}).scalar_one()
        == len(cand["manifest"])
    )
    db.execute(
        text("DELETE FROM survey_asset_usage WHERE subject_id = :s"), {"s": vid}
    )  # derived: losing it loses nothing
    store.rebuild_usage(db, "VERSION", vid, list(cand["manifest"]))
    db.commit()
    assert db.execute(text(count), {"s": vid}).scalar_one() == len(cand["manifest"])
    lib = {(r["code"], r["version"]): r for r in store.library(db, "ITEM")}
    assert lib[(q_clear, 1)]["versions"] == 1 and lib[(q_clear, 1)]["candidates"] == 1
    with pytest.raises(SurveyError):
        store.library(db, "PROMPT")


def test_a_survey_outside_the_callers_markets_does_not_exist_for_them(
    db: Session, people: tuple[Account, Account, Account]
) -> None:
    sid, cid, vid = _published(db, people)
    for call in (
        lambda: store.survey(db, sid, ["MY"]),
        lambda: store.candidate(db, cid, []),
        lambda: store.version(db, vid, ["MY"]),
    ):
        with pytest.raises(SurveyError) as e:
            call()
        assert (e.value.status, e.value.code) == (404, "NOT_FOUND")


# -------------------------------------------------------------------------------------------------------- audit trail
def test_every_transition_is_audited_and_the_chain_verifies(
    db: Session, people: tuple[Account, Account, Account]
) -> None:
    sid, cid, vid = _published(db, people)
    actions = (
        db.execute(
            text("SELECT action FROM audit_event WHERE entity_id = ANY(:ids) AND outcome = 'SUCCEEDED' ORDER BY seq"),
            {"ids": [str(sid), str(cid), str(vid)]},
        )
        .scalars()
        .all()
    )
    assert actions[0] == "SURVEY.CREATED" and set(actions[1:-3]) == {"SURVEY.DRAFT_CHANGED"}
    assert actions[-3:] == ["SURVEY.SUBMITTED", "SURVEY.APPROVED", "SURVEY.PUBLISHED"]
    report = verify_chain(db)
    assert report.ok and report.events > 0


# ---------------------------------------------------------------------------- migration: upgrade and downgrade, last
def test_zz_migration_downgrades_to_the_previous_head_and_upgrades_again(
    fresh_schema: None, engine: Engine, settings: Settings
) -> None:
    def state() -> tuple[set[str], int, str]:
        with engine.connect() as c:
            tables = set(c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'call360_test'")).scalars())
            perms = c.execute(
                text("SELECT count(*) FROM call360_test.permission WHERE code LIKE 'survey.%'")
            ).scalar_one()
            head = c.execute(text("SELECT version_num FROM call360_test.alembic_version")).scalar_one()
        return tables & SURVEY_TABLES, perms, head

    assert state() == (SURVEY_TABLES, 4, HEAD)
    with engine.connect() as c:
        others = (
            set(c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'call360_test'")).scalars())
            - SURVEY_TABLES
        )
        functions = c.execute(
            text(
                "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'call360_test' AND p.proname IN ('survey_asset_version_guard', 'survey_draft_guard', 'survey_lifecycle_event_guard', 'survey_version_guard')"
            )
        ).scalar_one()
    assert functions == 4
    migrate(settings, BEFORE, down=True)
    assert state() == (set(), 0, BEFORE)
    with engine.connect() as c:  # every other table is still there, untouched by the round trip
        assert (
            set(c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'call360_test'")).scalars())
            == others
        )
        assert (
            c.execute(
                text(
                    "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'call360_test' AND p.proname IN ('survey_asset_version_guard', 'survey_draft_guard', 'survey_lifecycle_event_guard', 'survey_version_guard')"
                )
            ).scalar_one()
            == 0
        )
    migrate(settings, HEAD)
    assert state() == (SURVEY_TABLES, 4, HEAD)


def test_zz_downgrade_refuses_while_survey_definitions_exist(
    fresh_schema: None, db: Session, settings: Settings
) -> None:
    author = make_account(db, prefix="author")
    build_draft(db, author, "K1")
    with pytest.raises(RuntimeError, match="survey definitions exist"):
        migrate(settings, BEFORE, down=True)
