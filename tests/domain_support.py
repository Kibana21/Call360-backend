"""Helpers for CP0.2 domain tests: revision discovery, reflected inserts and governed-code lookups.
Everything here runs against call360_test only (the engine fixture is guarded)."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Table, bindparam, insert, select, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import DBAPIError

from app.core.settings import BACKEND_ROOT
from app.domain.catalog import LATER_MIGRATION_TABLES, MIGRATION_TABLES
from app.domain.tables import reflect

SCHEMA = "call360_test"
NOW = datetime(2026, 11, 15, 1, 0, tzinfo=UTC)
CP01_TABLES = {
    "identity_provider",
    "principal",
    "identity_binding",
    "local_credential",
    "app_group",
    "group_membership",
    "role",
    "permission",
    "role_permission",
    "group_role_mapping",
    "auth_session",
    "refresh_token_family",
    "refresh_token",
    "login_attempt",
    "audit_event",
    "code_list",
    "code_list_version",
    "code_value",
    "feature_flag",
    "feature_flag_change",
}


def revisions() -> list[str]:
    """Alembic revisions from base to head, in order."""
    cfg = Config(str(BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_ROOT / "migrations"))
    return [r.revision for r in reversed(list(ScriptDirectory.from_config(cfg).walk_revisions()))]


def tables_at(revision: str) -> set[str]:
    revs = revisions()
    built = set(CP01_TABLES)
    for rev in revs[: revs.index(revision) + 1]:
        built |= set(MIGRATION_TABLES.get(rev, ())) | set(LATER_MIGRATION_TABLES.get(rev, ()))
    return built


_TABLES: dict[str, Table] = {}


def t(conn: Connection, name: str) -> Table:
    if not _TABLES:
        _TABLES.update(reflect(conn, SCHEMA))
    return _TABLES[name]


def prov(ref: str | None = None) -> dict[str, Any]:
    return {
        "source_type": "SEED",
        "source_system": "PYTEST",
        "source_reference": ref or f"pytest-{uuid.uuid4().hex[:12]}",
        "recorded_at": NOW,
        "is_synthetic": True,
        "created_by": "SYSTEM:pytest",
    }


def ins(conn: Connection, table: str, *, p: bool = True, **cols: Any) -> uuid.UUID:
    row_id = cols.pop("id", None) or uuid.uuid4()
    values = {"id": row_id, **(prov() if p else {"created_by": "SYSTEM:pytest"}), **cols}
    conn.execute(insert(t(conn, table)).values(**values))
    return row_id


def rejected(conn: Connection, sql: str, params: dict[str, Any] | None = None) -> str:
    """Run a statement inside a savepoint and return the PostgreSQL SQLSTATE it fails with."""
    sp = conn.begin_nested()
    try:
        conn.execute(text(sql), params or {})
    except DBAPIError as exc:
        sp.rollback()
        return str(getattr(exc.orig, "sqlstate", ""))
    sp.rollback()
    raise AssertionError(f"statement unexpectedly succeeded: {sql}")


def active_version(conn: Connection, list_code: str) -> uuid.UUID:
    return conn.execute(
        text(
            f"SELECT clv.id FROM {SCHEMA}.code_list_version clv JOIN {SCHEMA}.code_list cl ON cl.id = clv.code_list_id "  # noqa: S608
            "WHERE cl.code = :c AND clv.status = 'ACTIVE'"
        ),
        {"c": list_code},
    ).scalar_one()


def days(n: float) -> timedelta:
    return timedelta(days=n)


def count(conn: Connection, table: str) -> int:
    return int(conn.execute(select(text("count(*)")).select_from(t(conn, table))).scalar_one())


# ---- builders: minimal valid rows, reused by later migrations' tests -------------------------------------
def make_party(conn: Connection) -> uuid.UUID:
    n = uuid.uuid4().hex[:6]
    return ins(
        conn,
        "party",
        party_ref=f"PT-{n}",
        kind="PERSON",
        display_alias=f"Party {n}",
        name_ciphertext=b"\x01test",
        masked_name="Example P. 000",
        personal_data_class="SYNTHETIC_PERSONAL",
    )


def make_contact(conn: Connection, party_id: uuid.UUID, **over: Any) -> uuid.UUID:
    cols: dict[str, Any] = {
        "party_id": party_id,
        "channel": "PHONE",
        "value_ciphertext": b"\x01test",
        "value_hmac": uuid.uuid4().hex * 2,
        "masked_value": "SYN-TEL-SG-••••01",
        "is_verified": False,
        "preference_rank": 1,
        "language": "en",
        "timezone": "Asia/Singapore",
        "consent_status": "GRANTED",
        "suppressed": False,
        "valid_from": NOW - days(100),
    }
    return ins(conn, "contact_method", **{**cols, **over})


def make_policy(conn: Connection, market: str = "SG", **over: Any) -> uuid.UUID:
    cols: dict[str, Any] = {
        "policy_ref": f"POL-{uuid.uuid4().hex[:8]}",
        "market_code": market,
        "product_code": "SYN-ILP",
        "product_family": "ILP",
        "product_subtype": "ILP_REGULAR",
        "is_ilp": True,
        "status": "IN_FORCE",
        "premium_amount": 100,
        "currency": "SGD",
        "premium_frequency": "MONTHLY",
        "premium_term_years": 10,
        "effective_from": NOW - days(200),
    }
    return ins(conn, "policy", **{**cols, **over})


def make_fsc(conn: Connection) -> uuid.UUID:
    return ins(
        conn,
        "fsc_representative",
        fsc_ref=f"FSC-{uuid.uuid4().hex[:6]}",
        display_name="Example Representative",
        channel="AGENCY",
        status="ACTIVE",
    )


def make_sale(conn: Connection, policy_id: uuid.UUID, **over: Any) -> uuid.UUID:
    cols: dict[str, Any] = {
        "sale_ref": f"SALE-{uuid.uuid4().hex[:8]}",
        "policy_id": policy_id,
        "sale_event_type": "NEW_BUSINESS",
        "sold_at": NOW - days(150),
        "fsc_id": make_fsc(conn),
        "selling_channel": "AGENCY",
        "selling_location": "SYN-BRANCH-01",
        "proposal_ref": f"PR-{uuid.uuid4().hex[:6]}",
        "product_snapshot": {"product_code": "SYN-ILP"},
        "premium_amount": 100,
        "currency": "SGD",
    }
    return ins(conn, "sale_event", **{**cols, **over})


def make_snapshot(conn: Connection, policy_id: uuid.UUID, sale_id: uuid.UUID) -> uuid.UUID:
    return ins(
        conn,
        "policy_fact_snapshot",
        policy_id=policy_id,
        sale_event_id=sale_id,
        captured_at=NOW - days(149),
        schema_version="1",
        facts={"premium_term_years": 10},
        field_provenance={"premium_term_years": {"source": "PYTEST"}},
        sha256=uuid.uuid4().hex * 2,
    )


def _list_id(conn: Connection, list_code: str) -> uuid.UUID:
    return conn.execute(text(f"SELECT id FROM {SCHEMA}.code_list WHERE code = :c"), {"c": list_code}).scalar_one()  # noqa: S608


def draft_version(conn: Connection, list_code: str, values: dict[str, dict[str, Any]]) -> uuid.UUID:
    """A new DRAFT version of ``list_code`` holding ``values`` (inside the caller's transaction)."""
    list_id = _list_id(conn, list_code)
    nxt = conn.execute(
        text(f"SELECT coalesce(max(version), 0) + 1 FROM {SCHEMA}.code_list_version WHERE code_list_id = :l"),  # noqa: S608
        {"l": list_id},
    ).scalar_one()
    vid = ins(
        conn,
        "code_list_version",
        p=False,
        code_list_id=list_id,
        version=nxt,
        status="DRAFT",
        effective_from=NOW,
        change_reason="pytest",
        created_by="SYSTEM:pytest",
    )
    for i, (code, attrs) in enumerate(values.items()):
        conn.execute(
            insert(t(conn, "code_value")).values(
                id=uuid.uuid4(), code_list_version_id=vid, code=code, label=code, attributes=attrs, sort_order=i
            )
        )
    return vid


def ensure_active(conn: Connection, list_code: str, values: dict[str, dict[str, Any]]) -> uuid.UUID:
    """The ACTIVE version of ``list_code`` if it already holds ``values``' codes; otherwise activate a new one
    (before migration 0007 exists, governed lists have no versions)."""
    current = conn.execute(
        text(
            f"SELECT clv.id FROM {SCHEMA}.code_list_version clv WHERE clv.code_list_id = :l AND clv.status = 'ACTIVE'"  # noqa: S608
        ),
        {"l": _list_id(conn, list_code)},
    ).scalar()
    if current is not None:
        have = set(
            conn.execute(
                text(f"SELECT code FROM {SCHEMA}.code_value WHERE code_list_version_id = :v"),
                {"v": current},  # noqa: S608
            ).scalars()
        )
        if set(values) <= have:
            return uuid.UUID(str(current))
    vid = draft_version(conn, list_code, values)
    if current is not None:
        conn.execute(text(f"UPDATE {SCHEMA}.code_list_version SET status = 'SUPERSEDED' WHERE id = :v"), {"v": current})  # noqa: S608
    conn.execute(text(f"UPDATE {SCHEMA}.code_list_version SET status = 'ACTIVE' WHERE id = :v"), {"v": vid})  # noqa: S608
    return vid


BANDS = {"LOW": {}, "MEDIUM": {}, "HIGH": {}, "UNKNOWN": {}}
FACTORS = {"ILP_INDICATOR": {"value_type": "BOOLEAN"}, "SELLING_CHANNEL": {"value_type": "ENUM"}}


def make_assessment(conn: Connection, sale_id: uuid.UUID, **over: Any) -> uuid.UUID:
    cols: dict[str, Any] = {
        "sale_event_id": sale_id,
        "kind": "CALLBACK_SELECTION",
        "origin": "SOURCE_ASSIGNED",
        "status": "PROVISIONAL",
        "band_code": "HIGH",
        "explanation": "pytest",
        "source_original_value": "H",
        "assessed_at": NOW - days(140),
        "valid_at": NOW - days(140),
        "input_snapshot_sha256": uuid.uuid4().hex * 2,
    }
    if "band_list_version_id" not in over:
        cols["band_list_version_id"] = ensure_active(conn, "sbq_risk_band", BANDS)
    return ins(conn, "risk_assessment", **{**cols, **over})


def make_question(conn: Connection, **over: Any) -> uuid.UUID:
    item = ins(conn, "question_bank_item", question_code=f"Q-{uuid.uuid4().hex[:8]}", intent="pytest", category="T")
    cols: dict[str, Any] = {
        "question_bank_item_id": item,
        "revision": 1,
        "language": "en",
        "customer_wording": "[SYNTHETIC] pytest question",
        "delivery_mode": "CONVERSATIONAL",
        "answer_type": "YES_NO",
        "answer_schema": {"type": "boolean"},
        "mandatory": True,
        "expected_answer_policy": "EXACT_BOOLEAN",
        "expected_value": {"value": True},
        "evidence_required": True,
        "max_reprompts": 1,
        "content_approval_status": "SYNTHETIC_UNAPPROVED",
    }
    return ins(conn, "question_revision", **{**cols, **over})


def make_module(conn: Connection, questions: list[uuid.UUID], *, publish: bool = True) -> uuid.UUID:
    mid = ins(
        conn,
        "script_module",
        code=f"M-{uuid.uuid4().hex[:6]}",
        revision=1,
        kind="COMMON",
        status="DRAFT",
        name="pytest module",
    )
    for i, q in enumerate(questions):
        ins(conn, "module_question", script_module_id=mid, question_revision_id=q, position=i + 1)
    if publish:
        conn.execute(text(f"UPDATE {SCHEMA}.script_module SET status='PUBLISHED' WHERE id=:i"), {"i": mid})  # noqa: S608
    return mid


def make_version(
    conn: Connection,
    modules: list[uuid.UUID],
    *,
    published_at: datetime | None = None,
    effective_to: datetime | None = None,
    final: str = "PUBLISHED",
    market: str = "SG",
    questions: list[uuid.UUID] | None = None,
) -> uuid.UUID:
    """Create a script version and walk it through the ADR-0007 lifecycle to ``final``."""
    published_at = published_at or NOW - days(300)
    fam = ins(
        conn,
        "script_family",
        code=f"F-{uuid.uuid4().hex[:6]}",
        name="pytest",
        market_code=market,
        purpose="SALE_VERIFICATION",
        description="pytest",
    )
    vid = ins(
        conn,
        "script_version",
        script_family_id=fam,
        version_label="1.0",
        status="DRAFT",
        validation_status="NOT_VALIDATED",
        language="en",
        author_ref="pytest-author",
        content_approval_status="SYNTHETIC_UNAPPROVED",
    )
    for i, m in enumerate(modules):
        ins(conn, "script_section", script_version_id=vid, script_module_id=m, position=i + 1)
    if final == "DRAFT":
        return vid
    upd = f"UPDATE {SCHEMA}.script_version SET "  # noqa: S608
    manifest = {"question_revision_ids": [str(q) for q in (questions or [])]}
    conn.execute(
        text(
            upd + "manifest = :m, manifest_sha256 = :h, validation_status = 'VALID', "
            "status = 'SUBMITTED_FOR_REVIEW' WHERE id = :i"
        ).bindparams(bindparam("m", type_=JSONB)),
        {"m": manifest, "h": uuid.uuid4().hex * 2, "i": vid},
    )
    conn.execute(text(upd + "status = 'APPROVED', reviewer_ref = 'pytest-reviewer' WHERE id = :i"), {"i": vid})
    conn.execute(
        text(upd + "status = 'PUBLISHED', published_at = :p, effective_from = :p WHERE id = :i"),
        {"p": published_at, "i": vid},
    )
    if final in {"SUPERSEDED", "WITHDRAWN"}:
        conn.execute(
            text(upd + "status = :s, effective_to = :e WHERE id = :i"), {"s": final, "e": effective_to, "i": vid}
        )
    return vid


HOLDS = {
    "AWAITING_SCRIPT_ASSIGNMENT": {"blocking": True},
    "AWAITING_SCRIPT_REVIEW": {"blocking": True},
    "RISK_TRIAGE": {"blocking": True},
    "NO_ELIGIBLE_CONTACT": {"blocking": True},
    "DATA_CONFLICT": {"blocking": True},
    "OPERATOR_HOLD": {"blocking": False},
}
ROLES = {
    "OWNER": {"callable": True, "requires_authorization_evidence": False},
    "AUTHORIZED_CONTACT": {"callable": True, "requires_authorization_evidence": True},
    "INSURED": {"callable": False},
    "PAYER": {"callable": False},
    "PROPOSER": {"callable": False},
    "BENEFICIARY": {"callable": False},
}
CANCELLATIONS = {
    "POLICY_NOT_TAKEN_UP": {"sla_exempt_eligible": True},
    "POLICY_FREE_LOOK_CANCELLED": {"sla_exempt_eligible": True},
    "DUPLICATE_OBLIGATION": {"sla_exempt_eligible": True},
    "SOURCE_WITHDRAWN": {"sla_exempt_eligible": False},
    "OTHER": {"sla_exempt_eligible": False},
}


def scalar(conn: Connection, sql: str, **params: Any) -> Any:
    return conn.execute(text(sql), params).scalar_one()


class Chain:
    """A minimal valid case chain: policy -> sale -> party/role/contact -> snapshot -> FINAL risk ->
    published script version -> case (state VALIDATED by default)."""

    def __init__(self, conn: Connection, *, market: str = "SG", state: str = "VALIDATED") -> None:
        self.conn = conn
        self.policy = make_policy(conn, market)
        self.sale = make_sale(conn, self.policy)
        self.party = make_party(conn)
        self.role = ins(
            conn,
            "policy_party_role",
            policy_id=self.policy,
            party_id=self.party,
            role="OWNER",
            valid_from=NOW - days(200),
        )
        self.contact = make_contact(conn, self.party)
        self.snapshot = make_snapshot(conn, self.policy, self.sale)
        self.snapshot_sha = scalar(
            conn, f"SELECT sha256 FROM {SCHEMA}.policy_fact_snapshot WHERE id = :i", i=self.snapshot
        )
        self.risk = make_assessment(conn, self.sale)
        conn.execute(text(f"UPDATE {SCHEMA}.risk_assessment SET status='FINAL' WHERE id=:i"), {"i": self.risk})
        self.risk_sha = scalar(
            conn, f"SELECT input_snapshot_sha256 FROM {SCHEMA}.risk_assessment WHERE id=:i", i=self.risk
        )
        self.question = make_question(conn)
        self.module = make_module(conn, [self.question])
        self.version = make_version(conn, [self.module], questions=[self.question], market=market)
        self.version_sha = scalar(
            conn, f"SELECT manifest_sha256 FROM {SCHEMA}.script_version WHERE id=:i", i=self.version
        )
        self.case = ins(
            conn,
            "callback_case",
            case_ref=f"CB-T-{uuid.uuid4().hex[:8]}",
            sale_event_id=self.sale,
            obligation_type="SALE_VERIFICATION",
            source_request_ref="PYTEST",
            market_code=market,
            state=state,
            priority=3,
            due_at=NOW + days(10),
        )

    def attempt(self, status: str = "CONNECTED", seq: int = 1, **over: Any) -> uuid.UUID:
        cols: dict[str, Any] = {
            "attempt_ref": f"AT-{uuid.uuid4().hex[:10]}",
            "callback_case_id": self.case,
            "sequence": seq,
            "transport": "SYNTHETIC",
            "direction": "OUTBOUND",
            "status": status,
            "contacted_party_id": self.party,
            "contact_method_id": self.contact,
            "contact_snapshot": {"masked_value": "SYN-TEL-SG-••••01", "contact_method_id": str(self.contact)},
            "scheduled_at": NOW - days(20),
            "record_origin": "SYNTHETIC_SEED",
        }
        return ins(self.conn, "contact_attempt", **{**cols, **over})

    def session(self, attempt: uuid.UUID, **over: Any) -> uuid.UUID:
        cols: dict[str, Any] = {
            "session_ref": f"SS-{uuid.uuid4().hex[:10]}",
            "contact_attempt_id": attempt,
            "state": "COMPLETED",
            "transport": "SYNTHETIC",
            "started_at": NOW - days(19),
            "script_version_id": self.version,
            "script_manifest_sha256": self.version_sha,
            "risk_assessment_id": self.risk,
            "risk_snapshot_sha256": self.risk_sha,
            "policy_fact_snapshot_id": self.snapshot,
            "policy_fact_snapshot_sha256": self.snapshot_sha,
            "contacted_party_id": self.party,
            "contact_method_snapshot": {"masked_value": "SYN-TEL-SG-••••01"},
            "media_status": "NOT_REQUIRED",
            "transcript_status": "UNAVAILABLE",
            "record_origin": "SYNTHETIC_SEED",
        }
        return ins(self.conn, "conversation_session", **{**cols, **over})

    def run(self, session: uuid.UUID, status: str = "IN_PROGRESS") -> uuid.UUID:
        return ins(
            self.conn,
            "survey_run",
            session_id=session,
            script_version_id=self.version,
            script_manifest_sha256=self.version_sha,
            policy_fact_snapshot_id=self.snapshot,
            status=status,
            started_at=NOW - days(19),
            record_origin="SYNTHETIC_SEED",
        )

    def hold(self, reason: str, **over: Any) -> uuid.UUID:
        cols: dict[str, Any] = {
            "callback_case_id": self.case,
            "hold_reason": reason,
            "hold_reason_list_version_id": ensure_active(self.conn, "case_hold_reason", HOLDS),
            "is_blocking": False,
            "placed_at": NOW - days(5),
            "placed_by": "SYSTEM:pytest",
            "placed_reason": "pytest",
            "source": "SEED",
        }
        return ins(self.conn, "case_hold", p=False, **{**cols, **over})


GOVERNED_LIFECYCLE = {
    "CONFIG.CODE_LIST_VERSION_ACTIVATED",
    "CONFIG.CODE_LIST_VERSION_REMOVED",
    "ADMIN.GROUP_MAPPING_CHANGED",  # seeded scope mappings (0008, D-39)
}


def audit_rows(engine: Any) -> list[tuple[int, str, str, str | None]]:
    with engine.connect() as c:
        return [
            (r.seq, r.row_hash, r.action, r.entity_id)
            for r in c.execute(text(f"SELECT seq, row_hash, action, entity_id FROM {SCHEMA}.audit_event ORDER BY seq"))
        ]


def assert_audit_append_only(before: list[tuple[Any, ...]], after: list[tuple[Any, ...]]) -> Counter[str]:
    """Every earlier event survives unchanged (seq, hash) and only governed lifecycle events were appended."""
    assert after[: len(before)] == before
    appended = Counter(a[2] for a in after[len(before) :])
    assert set(appended) <= GOVERNED_LIFECYCLE, appended
    return appended
