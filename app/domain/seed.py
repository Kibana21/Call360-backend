"""Deterministic synthetic seed S0-SEED-1 (S0_DATA_MODEL §6; D-33, D-36…D-38).

- Deterministic: RNG seed 360, anchor 2026-11-15 Asia/Singapore (``SEED_ANCHOR`` overrides), UUIDv5 ids,
  business timestamps derived from the anchor. Ciphertext nonces are random and excluded from the digest.
- Idempotent: a second run finds the ``SEED.MANIFEST`` audit event, re-checks the digest and inserts nothing.
- Honest: every row is synthetic (``is_synthetic``, ``SYNTHETIC_SEED``, ``SYNTHETIC_UNAPPROVED``). No risk
  band is computed and no script is resolved by an engine: the seed writes recorded decisions with their
  traces (ADR-0008 §1). Contact values are non-dialable identifiers and ``example.invalid`` addresses.
- Every write goes through the database guards; nothing is relaxed for the seed.
"""

from __future__ import annotations

import os
import random
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import Connection, Table, insert, select, text, update
from sqlalchemy.orm import Session

from app.audit.chain import Actor, write_audit
from app.domain import seed_content as C
from app.domain.digest import content_digest, sha256_of
from app.domain.governed import version_id as governed_version
from app.domain.outcomes import EVIDENCE_INCOMPLETE, derive_outcomes
from app.domain.protection import DataProtection, aad, mask_contact, mask_name, matches_any
from app.domain.tables import reflect

SEED_VERSION = "S0-SEED-1"
RNG_SEED = 360
NS = uuid.UUID("5d6c0a2e-3b1f-4c9e-9a51-360000000360")
SGT = ZoneInfo("Asia/Singapore")
BY = "SYSTEM:seed"
SRC = "SYN-SEED"
TARGETS = {
    "policy": 230,
    "sale_event": 250,
    "callback_case": 250,
    "party": 320,
    "fsc_representative": 24,
    "contact_attempt": 400,
    "conversation_session": 80,
    "survey_run": 80,
    "finding": 24,
    "risk_assessment": 290,
    "script_version": 5,
}
GOLDEN = (
    "CB-2026-10482",
    "CB-2026-10483",
    "CB-2026-20001",
    "CB-2026-10490",
    "CB-2026-10491",
    "CB-2026-10492",
    "CB-2026-10493",
    "CB-2026-10494",
    "CB-2026-10495",
    "CB-2026-10496",
    "CB-2026-10497",
    "CB-2026-10498",
)


class SeedError(RuntimeError):
    pass


def default_anchor() -> datetime:
    raw = os.environ.get("SEED_ANCHOR", "2026-11-15")
    y, m, d = (int(x) for x in raw.split("-"))
    return datetime(y, m, d, tzinfo=SGT)


def uid(kind: str, key: object) -> uuid.UUID:
    return uuid.uuid5(NS, f"{kind}:{key}")


@dataclass(eq=False)  # identity semantics: many planned cases are alike
class Profile:
    """One planned callback case. Attempt statuses are in sequence order; a session (if any) is on the last."""

    state: str
    attempts: list[str] = field(default_factory=list)
    session: str | None = None  # COMPLETED | INTERRUPTED | ABORTED
    ref: str | None = None
    market: str | None = None
    product: str | None = None  # PROTECTION | ILP | ENDOWMENT
    band: str | None = None
    closure: str | None = None
    cancel: tuple[str, bool, str] | None = None  # reason, authorised, BEFORE|AFTER due
    holds: list[tuple[str, bool]] = field(default_factory=list)  # (reason, released)
    findings: list[tuple[str, str]] = field(default_factory=list)  # (severity, category)
    risk: str = "SINGLE"  # SINGLE | PAIR | CONFLICT | SUPERSEDED | NONE
    assign: bool = True
    contact: str = "OWNER"  # OWNER | SUPPRESSED_ONLY
    sold_days: float | None = None
    term_years: int | None = None
    wrong_term: int | None = None
    # filled by the planner
    era: str = ""
    topup: bool = False
    origin: str = ""
    constrained: bool = False


def _n(count: int, **kw: Any) -> list[Profile]:
    out = []
    for _ in range(count):
        args: dict[str, Any] = {k: (list(v) if isinstance(v, list) else v) for k, v in kw.items()}
        out.append(Profile(**args))
    return out


def plan() -> list[Profile]:
    """The S0_DATA_MODEL §6.2 composition, profile by profile; totals are asserted below."""
    na, bz, fl, ok, wp = "NO_ANSWER", "BUSY", "FAILED", "CONNECTED", "WRONG_PARTY"
    g = [
        Profile(
            "AWAITING_REVIEW",
            [na, bz, ok],
            "COMPLETED",
            "CB-2026-10482",
            "SG",
            "ILP",
            "HIGH",
            findings=[("HIGH", "FACT_MISMATCH")],
            risk="PAIR",
            term_years=10,
            wrong_term=5,
            sold_days=30,
        ),
        Profile("AWAITING_CALLBACK", [na, na], ref="CB-2026-10483", market="SG", sold_days=20),
        Profile("VERIFIED", [ok], "COMPLETED", "CB-2026-20001", "MY", "PROTECTION", "LOW", sold_days=90),
        Profile(
            "VALIDATED",
            ref="CB-2026-10490",
            market="SG",
            holds=[("AWAITING_SCRIPT_ASSIGNMENT", False)],
            assign=False,
            sold_days=6,
        ),
        Profile(
            "VALIDATED",
            ref="CB-2026-10491",
            market="SG",
            holds=[("NO_ELIGIBLE_CONTACT", False)],
            contact="SUPPRESSED_ONLY",
            sold_days=7,
        ),
        Profile(
            "VALIDATED",
            ref="CB-2026-10492",
            market="SG",
            product="ILP",
            holds=[("RISK_TRIAGE", False)],
            risk="NONE",
            assign=False,
            sold_days=10,
        ),
        Profile(
            "CLOSED_UNVERIFIED",
            [na, bz, na, fl],
            ref="CB-2026-10493",
            market="SG",
            closure="ATTEMPTS_EXHAUSTED",
            sold_days=70,
        ),
        Profile(
            "CANCELLED", ref="CB-2026-10494", market="SG", cancel=("POLICY_NOT_TAKEN_UP", True, "BEFORE"), sold_days=50
        ),
        Profile(
            "CANCELLED",
            ref="CB-2026-10495",
            market="SG",
            cancel=("POLICY_FREE_LOOK_CANCELLED", False, "BEFORE"),
            sold_days=55,
        ),
        Profile(
            "CANCELLED",
            [na],
            ref="CB-2026-10496",
            market="SG",
            cancel=("DUPLICATE_OBLIGATION", True, "AFTER"),
            sold_days=80,
        ),
        Profile("VERIFIED", [ok], "COMPLETED", "CB-2026-10497", "SG", "PROTECTION", "LOW", sold_days=60),
        Profile(
            "VALIDATED",
            ref="CB-2026-10498",
            market="SG",
            product="ILP",
            holds=[("RISK_TRIAGE", False)],
            risk="NONE",
            assign=False,
            sold_days=45,
        ),
    ]
    p: list[Profile] = list(g)
    # Zero attempts: 6 golden above + 4.
    p += _n(2, state="CREATED", assign=False)
    p += _n(1, state="VALIDATED")
    p += _n(1, state="VALIDATED", holds=[("AWAITING_SCRIPT_REVIEW", False)])
    # Sessions (80 = 62 COMPLETED + 10 INTERRUPTED + 8 ABORTED); golden 10482, 20001, 10497 included.
    p += _n(28, state="VERIFIED", session="COMPLETED", product="NON_ILP", band="NOT_HIGH")
    p += _n(
        4,
        state="VERIFIED",
        session="COMPLETED",
        product="NON_ILP",
        band="NOT_HIGH",
        findings=[("LOW", "UNCLEAR_UNDERSTANDING")],
    )
    p += _n(
        4,
        state="VERIFIED",
        session="COMPLETED",
        product="NON_ILP",
        band="NOT_HIGH",
        findings=[("MEDIUM", "FACT_MISMATCH")],
    )
    p += _n(5, state="AWAITING_REVIEW", session="COMPLETED", product="ILP", band="HIGH", risk="PAIR")
    p += _n(3, state="AWAITING_REVIEW", session="COMPLETED", product="ILP")
    p += _n(3, state="AWAITING_REVIEW", session="COMPLETED", product="ILP", findings=[("HIGH", "CONTRADICTORY_ANSWER")])
    p += _n(2, state="AWAITING_REVIEW", session="COMPLETED", product="ILP", findings=[("HIGH", "FACT_MISMATCH")])
    p += _n(
        4, state="AWAITING_REVIEW", session="COMPLETED", product="ILP", findings=[("MEDIUM", "UNCLEAR_UNDERSTANDING")]
    )
    p += _n(2, state="AWAITING_REVIEW", session="COMPLETED", product="ILP", findings=[("LOW", "UNCLEAR_UNDERSTANDING")])
    p += _n(3, state="ESCALATED", session="COMPLETED", product="ILP", findings=[("CRITICAL", "DISCLOSURE_CONCERN")])
    p += _n(1, state="ESCALATED", session="COMPLETED", product="ILP", findings=[("HIGH", "CONTRADICTORY_ANSWER")])
    p += _n(6, state="AWAITING_CALLBACK", session="INTERRUPTED")
    p += _n(2, state="IN_PROGRESS", session="INTERRUPTED")
    p += _n(2, state="CLOSED_UNVERIFIED", session="INTERRUPTED", closure="UNABLE_TO_VERIFY")
    p += _n(4, state="CLOSED_UNVERIFIED", session="ABORTED", closure="CUSTOMER_REFUSED")
    p += _n(4, state="AWAITING_CALLBACK", session="ABORTED")
    # Non-session cases with attempts (counts per attempt group fixed in _attempts()).
    p += _n(20, state="READY", attempts=["SCHEDULED"])
    p += _n(53, state="AWAITING_CALLBACK", attempts=["ONE"])
    p += _n(3, state="AWAITING_CALLBACK", attempts=["ONE"], holds=[("DATA_CONFLICT", False)], risk="CONFLICT")
    p += _n(2, state="AWAITING_CALLBACK", attempts=["ONE"], holds=[("OPERATOR_HOLD", False)])
    p += _n(1, state="CANCELLED", attempts=["ONE"], cancel=("SOURCE_WITHDRAWN", True, "BEFORE"))
    p += _n(1, state="CANCELLED", attempts=["ONE"], cancel=("OTHER", False, "BEFORE"))
    p += _n(4, state="IN_PROGRESS", attempts=["INITIATED"])
    p += _n(2, state="CLOSED_UNVERIFIED", attempts=[wp], closure="INELIGIBLE")
    p += _n(2, state="CLOSED_UNVERIFIED", attempts=["ONE"], closure="POLICY_CANCELLED")
    p += _n(1, state="CLOSED_UNVERIFIED", attempts=["ONE"], closure="DUPLICATE_OBLIGATION")
    p += _n(27, state="AWAITING_CALLBACK", attempts=["ONE", "ONE"])
    p += _n(2, state="AWAITING_CALLBACK", attempts=["ONE", "ONE"], holds=[("AWAITING_SCRIPT_REVIEW", True)])
    p += _n(3, state="IN_PROGRESS", attempts=["ONE", "CONNECTING"])
    p += _n(4, state="CLOSED_UNVERIFIED", attempts=["ONE", "ONE"], closure="UNABLE_TO_VERIFY")
    p += _n(2, state="CLOSED_UNVERIFIED", attempts=["ONE", wp], closure="INELIGIBLE")
    p += _n(1, state="CANCELLED", attempts=["ONE", "ONE"], cancel=("DUPLICATE_OBLIGATION", True, "BEFORE"))
    p += _n(13, state="CLOSED_UNVERIFIED", attempts=["ONE"] * 3, closure="ATTEMPTS_EXHAUSTED")
    p += _n(10, state="AWAITING_CALLBACK", attempts=["ONE"] * 3)
    p += _n(6, state="CLOSED_UNVERIFIED", attempts=["ONE"] * 4, closure="ATTEMPTS_EXHAUSTED")
    return p


def _attempt_counts_for_sessions(profiles: list[Profile]) -> None:
    """Session cases: 45 with one attempt, 20 with two, 12 with three, 3 with four (golden fixed)."""
    sessions = [x for x in profiles if x.session and not x.attempts]
    sizes = [1] * 45 + [2] * 20 + [3] * 12 + [4] * 3
    fixed = [x for x in profiles if x.session and x.attempts]  # golden: 10482 has 3, 20001 and 10497 have 1
    for x in fixed:
        sizes.remove(len(x.attempts))
    assert len(sizes) == len(sessions), (len(sizes), len(sessions))
    for x, n in zip(sessions, sizes, strict=True):
        x.attempts = ["ONE"] * (n - 1) + ["CONNECTED"]


def _check_plan(profiles: list[Profile]) -> None:
    assert len(profiles) == 250
    sizes = Counter(len(x.attempts) for x in profiles)
    assert sizes == {0: 10, 1: 135, 2: 60, 3: 35, 4: 10}, sizes
    assert sum(len(x.attempts) for x in profiles) == 400
    assert Counter(x.session for x in profiles if x.session) == {"COMPLETED": 62, "INTERRUPTED": 10, "ABORTED": 8}
    sev = Counter(s for x in profiles for s, _ in x.findings)
    assert sev == {"LOW": 6, "MEDIUM": 8, "HIGH": 7, "CRITICAL": 3}, sev
    assert {x.state for x in profiles} == {
        "CREATED",
        "VALIDATED",
        "READY",
        "IN_PROGRESS",
        "AWAITING_CALLBACK",
        "AWAITING_REVIEW",
        "ESCALATED",
        "VERIFIED",
        "CLOSED_UNVERIFIED",
        "CANCELLED",
    }
    assert {r for x in profiles for r, _ in x.holds} == set(_HOLD_REASONS)


_HOLD_REASONS = (
    "AWAITING_SCRIPT_ASSIGNMENT",
    "AWAITING_SCRIPT_REVIEW",
    "RISK_TRIAGE",
    "NO_ELIGIBLE_CONTACT",
    "DATA_CONFLICT",
    "OPERATOR_HOLD",
)
TERMINAL = {"VERIFIED", "CLOSED_UNVERIFIED", "CANCELLED"}


@dataclass
class SeedReport:
    version: str
    digest: str
    counts: dict[str, int]
    key_ids: dict[str, str]
    created: bool


class _Seeder:
    def __init__(self, conn: Connection, schema: str, protection: DataProtection, anchor: datetime) -> None:
        self.conn, self.schema, self.dp, self.anchor = conn, schema, protection, anchor
        self.t: dict[str, Table] = reflect(conn, schema)
        self.rnd = random.Random(RNG_SEED)  # noqa: S311 — deterministic synthetic data, not security
        self.events: list[dict[str, Any]] = []
        self.session = Session(bind=conn)
        self.patterns = self._contact_patterns()
        self.changes_left = 15  # T-38 contact changes still to place

    # ---- helpers -------------------------------------------------------------------------------------------
    def at(self, days_ago: float) -> datetime:
        return self.anchor - timedelta(days=days_ago)

    def ins(
        self, table: str, key: object, recorded_at: datetime | None = None, *, p: bool = True, **cols: Any
    ) -> uuid.UUID:
        row_id = cols.pop("id", None) or uid(table, key)
        values: dict[str, Any] = {"id": row_id, "created_by": BY, **cols}
        if p:
            when = recorded_at or self.anchor
            values = {
                "source_type": "SEED",
                "source_system": SRC,
                "source_reference": f"{SEED_VERSION}:{table}:{key}",
                "source_observed_at": when,
                "recorded_at": when,
                "is_synthetic": True,
                **values,
            }
        self.conn.execute(insert(self.t[table]).values(**values))
        return row_id

    def upd(self, table: str, row_id: uuid.UUID, **cols: Any) -> None:
        tbl = self.t[table]
        self.conn.execute(update(tbl).where(tbl.c.id == row_id).values(**cols))

    def event(
        self, case_id: uuid.UUID, kind: str, when: datetime, summary: str, entity: tuple[str, uuid.UUID] | None = None
    ) -> None:
        self.events.append(
            {
                "id": uid("case_event", f"{case_id}:{len(self.events)}"),
                "callback_case_id": case_id,
                "event_type": kind,
                "occurred_at": when,
                "actor_ref": BY,
                "related_entity_type": entity[0] if entity else None,
                "related_entity_id": entity[1] if entity else None,
                "summary": f"{summary} (seeded synthetic)",
                "created_by": BY,
            }
        )

    def _contact_patterns(self) -> dict[str, list[str]]:
        rows = self.conn.execute(
            select(self.t["code_value"].c.attributes).where(
                self.t["code_value"].c.code_list_version_id == governed_version("synthetic_contact_ranges")
            )
        ).scalars()
        out: dict[str, list[str]] = {}
        for attrs in rows:
            out.setdefault(attrs["channel"], []).append(attrs["pattern"])
        if not out:
            raise SeedError("synthetic_contact_ranges version 1 is missing (migration 0007)")
        return out

    # ---- reference content ---------------------------------------------------------------------------------
    def reference_content(self) -> None:
        a = self.at
        self.fscs: list[tuple[uuid.UUID, str]] = []
        channels = ["AGENCY", "BANCASSURANCE", "BROKER", "DIRECT"]
        for i in range(1, 25):
            ch = channels[(i - 1) % 4]
            fid = self.ins(
                "fsc_representative",
                i,
                a(500),
                fsc_ref=f"FSC-{i:04d}",
                display_name=f"Example Representative {i:02d}",
                channel=ch,
                status="INACTIVE" if i in (23, 24) else "ACTIVE",
            )
            self.ins(
                "external_reference",
                f"fsc:{i}",
                p=False,
                source_system="SYN-DISTRIBUTION",
                object_type="FSC_REPRESENTATIVE",
                external_id=f"AGT{i:05d}",
                entity_id=fid,
            )
            self.fscs.append((fid, ch))

        for version, eff, end, status in C.RULE_SETS:
            body = {"code": "SYN-SBQ-RULES", "version": version, "rules": C.RISK_RULES}
            self.ins(
                "risk_rule_set_version",
                version,
                a(eff),
                code="SYN-SBQ-RULES",
                version=version,
                effective_from=a(eff),
                effective_to=a(end) if end else None,
                rules=C.RISK_RULES,
                checksum=sha256_of(body),
                status=status,
                content_approval_status="SYNTHETIC_UNAPPROVED",
                author_ref="SYNTHETIC-AUTHOR-01",
                checker_ref="SYNTHETIC-CHECKER-01",
            )
        self.rule_sets = {v: uid("risk_rule_set_version", v) for v, *_ in C.RULE_SETS}

        self.questions: dict[str, uuid.UUID] = {}
        for code, q in C.QUESTIONS.items():
            item = self.ins(
                "question_bank_item", code, a(420), question_code=code, intent=q["intent"], category=q["category"]
            )
            self.questions[code] = self.ins(
                "question_revision",
                code,
                a(420),
                question_bank_item_id=item,
                revision=1,
                language="en",
                customer_wording=C.WORDING_PREFIX + q["wording"],
                delivery_mode=q.get("mode", "CONVERSATIONAL"),
                answer_type=q["answer_type"],
                answer_schema=q.get("schema", {"type": q["answer_type"].lower()}),
                mandatory=q["mandatory"],
                expected_answer_policy=q["policy"],
                expected_value=q.get("expected"),
                acceptable_variants=[],
                policy_fact_key=q.get("fact_key"),
                unacceptable_outcomes=[],
                not_applicable_predicate=q.get("not_applicable"),
                evidence_required=q["mandatory"],
                max_reprompts=1,
                content_approval_status="SYNTHETIC_UNAPPROVED",
            )

        self.modules: dict[tuple[str, int], uuid.UUID] = {}

        def publish_module(key: tuple[str, int]) -> None:
            kind, name, codes = C.MODULES[key]
            mid = self.ins(
                "script_module",
                f"{key[0]}:{key[1]}",
                a(410),
                code=key[0],
                revision=key[1],
                kind=kind,
                status="DRAFT",
                name=name,
            )
            for pos, code in enumerate(codes, start=1):
                self.ins(
                    "module_question",
                    f"{key[0]}:{key[1]}:{pos}",
                    a(410),
                    script_module_id=mid,
                    question_revision_id=self.questions[code],
                    position=pos,
                )
            self.upd("script_module", mid, status="PUBLISHED")
            self.modules[key] = mid

        for key in (("COMMON_SALES_CONDUCT", 1), ("PROTECTION", 1), ("ILP", 1), ("ELEVATED_RISK", 1)):
            publish_module(key)

        self.families = {}
        for market in ("SG", "MY"):
            self.families[market] = self.ins(
                "script_family",
                market,
                a(420),
                code=f"SALES_VERIFICATION_{market}",
                name=f"Sales verification ({market}, synthetic)",
                market_code=market,
                purpose="SALE_VERIFICATION",
                description=C.LABEL,
            )

        self.versions: dict[tuple[str, str], uuid.UUID] = {}
        self.manifests: dict[uuid.UUID, dict[str, Any]] = {}
        self.version_window: dict[uuid.UUID, tuple[datetime, datetime | None]] = {}
        previous: dict[str, uuid.UUID] = {}
        for market, label, common_rev, pub, end, final in C.VERSIONS:
            if common_rev == 2 and ("COMMON_SALES_CONDUCT", 2) not in self.modules:
                publish_module(("COMMON_SALES_CONDUCT", 2))
                self.upd("script_module", self.modules[("COMMON_SALES_CONDUCT", 1)], status="SUPERSEDED")
            vid = self._script_version(market, label, common_rev, pub, end, final, previous.get(market))
            self.versions[(market, label)] = vid
            if final != "DRAFT" and final != "WITHDRAWN":
                previous[market] = vid

        rules = [
            ("SG-PILOT", 1, "SG", "0.9", 400, 300, "WITHDRAWN"),
            ("SG-SALES-VERIFY", 1, "SG", "1.0", 300, 120, "SUPERSEDED"),
            ("SG-SALES-VERIFY", 2, "SG", "1.1", 120, None, "PUBLISHED"),
            ("MY-SALES-VERIFY", 1, "MY", "1.0", 300, None, "PUBLISHED"),
        ]
        self.rules: list[tuple[str, int, str, uuid.UUID, datetime, datetime | None, uuid.UUID]] = []
        for code, ver, market, label, eff, end, status in rules:
            predicate = {
                "all": [{"fact": "market", "equals": market}, {"fact": "case_purpose", "equals": "SALE_VERIFICATION"}]
            }
            target = self.versions[(market, label)]
            body = {"rule_code": code, "version": ver, "predicate": predicate, "target": str(target)}
            rid = self.ins(
                "script_assignment_rule_version",
                f"{code}:{ver}",
                a(eff),
                rule_code=code,
                version=ver,
                predicate=predicate,
                priority=10,
                specificity=2 if code != "SG-PILOT" else 3,
                target_script_version_id=target,
                effective_from=a(eff),
                effective_to=a(end) if end else None,
                status=status,
                checksum=sha256_of(body),
                author_ref="SYNTHETIC-AUTHOR-01",
                checker_ref="SYNTHETIC-CHECKER-01",
            )
            self.rules.append((code, ver, market, target, a(eff), a(end) if end else None, rid))

        refs = {}
        for i, (market, title) in enumerate(C.REG_REFS, start=1):
            refs[market] = self.ins(
                "regulatory_reference",
                i,
                a(420),
                issuer="SYNTHETIC REGULATOR (placeholder)",
                jurisdiction=market,
                market_code=market,
                title=title,
                document_version="placeholder-1",
                url=None,
                published_on=None,
                interpretation_status="NOT_REVIEWED",
            )
        for code, name, qcodes in C.CONTROLS:
            cid = self.ins(
                "control",
                code,
                a(420),
                control_code=code,
                name=name,
                owner_role="S&C (proposed)",
                content_approval_status="SYNTHETIC_UNAPPROVED",
            )
            for qcode in qcodes:
                item = uid("question_bank_item", qcode)
                self.ins(
                    "control_mapping",
                    f"{code}:{qcode}",
                    a(420),
                    question_bank_item_id=item,
                    control_id=cid,
                    regulatory_reference_id=refs["SG"] if code in C.REG_MAPPED_CONTROLS else None,
                    rationale="Synthetic mapping for S0 display; not an approved control interpretation",
                    status="PROPOSED",
                )

    def _script_version(
        self,
        market: str,
        label: str,
        common_rev: int,
        pub: int | None,
        end: int | None,
        final: str,
        supersedes: uuid.UUID | None,
    ) -> uuid.UUID:
        key = f"{market}:{label}"
        vid = self.ins(
            "script_version",
            key,
            self.at(pub or 30),
            script_family_id=self.families[market],
            version_label=label,
            status="DRAFT",
            validation_status="NOT_VALIDATED",
            language="en",
            author_ref="SYNTHETIC-AUTHOR-01",
            content_approval_status="SYNTHETIC_UNAPPROVED",
            supersedes_id=supersedes,
        )
        sections = []
        all_ids: list[str] = []
        for pos, mod in enumerate(("COMMON_SALES_CONDUCT", "PROTECTION", "ILP", "ELEVATED_RISK"), start=1):
            rev = common_rev if mod == "COMMON_SALES_CONDUCT" else 1
            mid = self.modules[(mod, rev)]
            self.ins(
                "script_section",
                f"{key}:{pos}",
                self.at(pub or 30),
                script_version_id=vid,
                script_module_id=mid,
                position=pos,
                inclusion_condition=C.CONDITIONS[mod],
            )
            questions = []
            for qpos, code in enumerate(C.MODULES[(mod, rev)][2], start=1):
                q = C.QUESTIONS[code]
                questions.append(
                    {
                        "question_code": code,
                        "question_revision_id": str(self.questions[code]),
                        "position": qpos,
                        "mandatory": q["mandatory"],
                        "expected_answer_policy": q["policy"],
                        "policy_fact_key": q.get("fact_key"),
                        "not_applicable_predicate": q.get("not_applicable"),
                    }
                )
                all_ids.append(str(self.questions[code]))
            sections.append(
                {
                    "module_code": mod,
                    "module_revision": rev,
                    "module_id": str(mid),
                    "position": pos,
                    "inclusion_condition": C.CONDITIONS[mod],
                    "questions": questions,
                }
            )
        manifest = {
            "family": f"SALES_VERIFICATION_{market}",
            "version_label": label,
            "language": "en",
            "content_approval_status": "SYNTHETIC_UNAPPROVED",
            "sections": sections,
            "question_revision_ids": all_ids,
        }
        if final == "DRAFT":
            return vid
        self.manifests[vid] = manifest
        self.upd(
            "script_version",
            vid,
            manifest=manifest,
            manifest_sha256=sha256_of(manifest),
            validation_status="VALID",
            status="SUBMITTED_FOR_REVIEW",
        )
        self.upd("script_version", vid, status="APPROVED", reviewer_ref="SYNTHETIC-REVIEWER-01")
        assert pub is not None
        self.upd("script_version", vid, status="PUBLISHED", published_at=self.at(pub), effective_from=self.at(pub))
        if final in {"SUPERSEDED", "WITHDRAWN"}:
            assert end is not None
            self.upd("script_version", vid, status=final, effective_to=self.at(end))
        self.version_window[vid] = (self.at(pub), self.at(end) if end else None)
        return vid

    # ---- planning ------------------------------------------------------------------------------------------
    def assign_profiles(self, profiles: list[Profile]) -> None:
        rnd = self.rnd
        _attempt_counts_for_sessions(profiles)
        _check_plan(profiles)
        for x in profiles:
            x.constrained = x.product is not None or x.band is not None or bool(x.findings)
        free = [x for x in profiles if x.ref is None]
        # Markets: exactly 55 MY cases (20001 + 54); MY policies have one sale each.
        my = rnd.sample([x for x in free if x.risk != "CONFLICT"], 54)
        for x in profiles:
            x.market = x.market or ("MY" if x in my else "SG")
        # Products and bands.
        for x in profiles:
            if x.product == "NON_ILP" or x.product is None:
                options = ["PROTECTION", "ENDOWMENT"] if x.product == "NON_ILP" else ["PROTECTION", "ILP", "ENDOWMENT"]
                x.product = rnd.choice(options)
            if x.band == "NOT_HIGH":
                x.band = rnd.choice(["LOW", "LOW", "MEDIUM"])
            elif x.band is None and x.risk != "NONE":
                weights = ["HIGH", "HIGH", "MEDIUM", "LOW"] if x.product == "ILP" else ["LOW", "LOW", "MEDIUM", "HIGH"]
                x.band = rnd.choice(weights)
        # Origins: RULE_ASSESSED only where the synthetic rules support the recorded band (HIGH needs ILP;
        # ILP always indicates HIGH). Pairs and conflicts have a rule-assessed effective assessment.
        for x in profiles:
            if x.risk == "NONE":
                x.origin = ""
            elif x.risk in {"PAIR", "CONFLICT"}:
                if x.product == "ILP":
                    x.band = "HIGH"
                elif x.band == "HIGH":
                    x.band = "MEDIUM"
                x.origin = "RULE_ASSESSED"
            elif x.product == "ILP":
                x.origin = "RULE_ASSESSED" if x.band == "HIGH" and rnd.random() < 0.6 else "SOURCE_ASSIGNED"
            elif x.band == "HIGH":
                x.origin = "SOURCE_ASSIGNED"
            else:
                x.origin = "RULE_ASSESSED" if rnd.random() < 0.5 else "SOURCE_ASSIGNED"
        # 25 pairs (10482 + 5 planned + 3 conflicts + 16 more) and 17 superseded predecessors.
        rule_singles = [x for x in free if x.risk == "SINGLE" and x.origin == "RULE_ASSESSED"]
        for x in rnd.sample(rule_singles, 25 - sum(1 for y in profiles if y.risk in {"PAIR", "CONFLICT"})):
            x.risk = "PAIR"
        source_singles = [x for x in free if x.risk == "SINGLE" and x.origin == "SOURCE_ASSIGNED"]
        for x in rnd.sample(source_singles, 17):
            x.risk = "SUPERSEDED"
        # Timeline: open cases are recent; terminal SG cases avoid the 1.0 -> 1.1 boundary window.
        for x in profiles:
            if x.sold_days is None:
                if x.state in TERMINAL:
                    early = x.market == "SG" and rnd.random() < 0.35
                    x.sold_days = rnd.randint(160, 250) if early else rnd.randint(40, 118)
                elif x.state == "READY":
                    x.sold_days = rnd.randint(5, 20)
                elif not x.attempts:
                    x.sold_days = rnd.randint(1, 10)
                else:
                    x.sold_days = rnd.randint(12, 60)
            x.era = "1.0" if x.market == "SG" and x.sold_days >= 160 else ("1.1" if x.market == "SG" else "MY")
        # 20 top-up / replacement sales on existing SG policies (non-golden, risk-free of special handling).
        # Their product comes from the host policy, so they are unconstrained and source-assigned (the
        # synthetic rules would otherwise have to support a band chosen for another product).
        candidates = [
            x
            for x in free
            if x.market == "SG"
            and x.risk in {"SINGLE", "SUPERSEDED"}
            and x.state not in TERMINAL
            and not x.holds
            and not x.constrained
        ]
        for x in rnd.sample(candidates, 20):
            x.topup = True
            x.origin = "SOURCE_ASSIGNED"

    # ---- parties, policies and sales -----------------------------------------------------------------------
    def build_sales(self, profiles: list[Profile]) -> None:
        rnd = self.rnd
        primaries = [x for x in profiles if not x.topup]
        assert len(primaries) == 230
        self.case_ids: dict[str, uuid.UUID] = {}
        party_no = 0

        def new_party(market: str, when: datetime) -> tuple[uuid.UUID, int]:
            nonlocal party_no
            party_no += 1
            pid = uid("party", party_no)
            name = f"Example Policyholder {party_no:03d}"
            self.ins(
                "party",
                party_no,
                when,
                id=pid,
                party_ref=f"PTY-{party_no:06d}",
                kind="PERSON",
                display_alias=f"Synthetic party {party_no:06d}",
                name_ciphertext=self.dp.encrypt(name, aad=aad("party", "name", pid)),
                masked_name=mask_name(name),
                date_of_birth_year=rnd.randint(1950, 2000),
                personal_data_class="SYNTHETIC_PERSONAL",
            )
            self.ins(
                "external_reference",
                f"party:{party_no}",
                p=False,
                source_system="SYN-CRM",
                object_type="PARTY",
                external_id=f"C{party_no:07d}",
                entity_id=pid,
            )
            self.party_market[pid] = market
            return pid, party_no

        self.party_market: dict[uuid.UUID, str] = {}
        self.contacts: dict[uuid.UUID, list[dict[str, Any]]] = {}
        self.policy_of: dict[int, dict[str, Any]] = {}
        policy_no = 0
        joint_pool = [i for i, x in enumerate(primaries) if x.ref is None and x.market == "SG" and x.attempts]
        joint = set(rnd.sample(joint_pool, 25))
        auth_pool = [i for i, x in enumerate(primaries) if x.ref is None and i not in joint]
        auth = rnd.sample(auth_pool, 20)
        auth_ok = set(auth[:12])
        auth_set = set(auth)
        insured_pool = [i for i, x in enumerate(primaries) if x.ref is None and x.contact == "OWNER"]
        insured = set(rnd.sample(insured_pool, 45))

        for i, x in enumerate(primaries):
            policy_no += 1
            sold = self.at(x.sold_days or 30)
            market = x.market or "SG"
            fam = x.product or "PROTECTION"
            mismatch = any(cat == "FACT_MISMATCH" for _, cat in x.findings)
            single = fam == "ILP" and not mismatch and x.term_years is None and rnd.random() < 0.2
            freq = "SINGLE" if single else ("ANNUAL" if fam == "ENDOWMENT" else "MONTHLY")
            term = x.term_years or (None if single else rnd.choice([5, 10, 15, 20, 25]))
            premium = Decimal(rnd.randrange(80, 2000, 10)) if not single else Decimal(rnd.randrange(10000, 90000, 500))
            prod = {
                "PROTECTION": ("SYN-PROT-TERM", "TERM_LIFE"),
                "ILP": ("SYN-ILP-GROWTH", "ILP_SINGLE" if single else "ILP_REGULAR"),
                "ENDOWMENT": ("SYN-END-SAVER", "ENDOWMENT"),
            }[fam]
            currency = "SGD" if market == "SG" else "MYR"
            pol_id = self.ins(
                "policy",
                policy_no,
                sold,
                policy_ref=f"POL-{market}-{policy_no:06d}",
                market_code=market,
                product_code=prod[0],
                product_family=fam,
                product_subtype=prod[1],
                is_ilp=fam == "ILP",
                status="IN_FORCE",
                premium_amount=premium,
                currency=currency,
                premium_frequency=freq,
                premium_term_years=term,
                sum_assured=Decimal(rnd.randrange(50000, 800000, 5000)),
                sum_assured_currency=currency,
                effective_from=sold + timedelta(days=1),
            )
            self.ins(
                "external_reference",
                f"policy:{policy_no}",
                p=False,
                source_system="SYN-POLICY-ADMIN",
                object_type="POLICY",
                external_id=f"POL-{market}-{policy_no:06d}",
                entity_id=pol_id,
            )
            info: dict[str, Any] = {
                "id": pol_id,
                "no": policy_no,
                "market": market,
                "family": fam,
                "product": prod,
                "premium": premium,
                "currency": currency,
                "freq": freq,
                "term": term,
                "roles": [],
                "sales": 0,
            }
            self.policy_of[i] = info
            start = sold - timedelta(days=2)
            owner, owner_no = new_party(market, start)
            self._contact(owner, owner_no, "PHONE", start, suppressed=x.contact == "SUPPRESSED_ONLY")
            if x.contact != "SUPPRESSED_ONLY":
                self._contact(owner, owner_no, "EMAIL", start, rank=2)
            for role in ("OWNER", "PROPOSER", "PAYER"):
                self._role(info, owner, role, start)
            info["owners"] = [owner]
            if i in joint:
                second, second_no = new_party(market, start)
                self._contact(second, second_no, "PHONE", start)
                self._contact(second, second_no, "EMAIL", start, rank=2)
                self._role(info, second, "OWNER", start)
                info["owners"].append(second)
                self._role(info, second, "BENEFICIARY", start)
            if i in insured:
                ins_party, ins_no = new_party(market, start)
                self._contact(ins_party, ins_no, "PHONE", start, consent="UNKNOWN")
                self._role(info, ins_party, "INSURED", start)
                if i not in joint:
                    self._role(info, ins_party, "BENEFICIARY", start)
            else:
                self._role(info, owner, "INSURED", start)
            if i in auth_set:
                ac, ac_no = new_party(market, start)
                self._contact(ac, ac_no, "PHONE", start)
                evidenced = i in auth_ok
                self._role(
                    info,
                    ac,
                    "AUTHORIZED_CONTACT",
                    start,
                    authorization_ref=f"SYN-AUTH-{ac_no:06d}" if evidenced else None,
                    authorization_valid_from=start if evidenced else None,
                )
                info["auth_contact"] = (ac, evidenced)
        assert party_no == 320, party_no
        # Assign every case its sale: primaries own a new-business sale; top-ups attach to an SG policy
        # with the same product family that has no top-up yet.
        self.sale_of: dict[int, dict[str, Any]] = {}
        sale_no = 0
        topup_hosts = [i for i, x in enumerate(primaries) if x.market == "SG" and x.ref is None]
        index_of = {id(x): i for i, x in enumerate(primaries)}
        used: set[int] = set()
        order = []
        for x in profiles:
            if x.topup:
                # A top-up follows its host's new-business sale by at least 5 days.
                later = [
                    h for h in topup_hosts if h not in used and (primaries[h].sold_days or 0) >= (x.sold_days or 0) + 5
                ]
                cands = [h for h in later if self.policy_of[h]["family"] == x.product] or later
                if not cands:
                    raise SeedError("no top-up host sold early enough")
                host = rnd.choice(cands)
                used.add(host)
                x.product = self.policy_of[host]["family"]
                order.append((x, self.policy_of[host], "TOP_UP" if len(used) % 4 else "REPLACEMENT"))
            else:
                order.append((x, self.policy_of[index_of[id(x)]], "NEW_BUSINESS"))
        self.case_plan: list[tuple[Profile, dict[str, Any], dict[str, Any]]] = []
        for x, pol, kind in order:
            sale_no += 1
            sale = self._sale(x, pol, kind, sale_no)
            self.case_plan.append((x, pol, sale))

    def _contact(
        self,
        party: uuid.UUID,
        party_no: int,
        channel: str,
        start: datetime,
        *,
        rank: int = 1,
        suppressed: bool = False,
        consent: str = "GRANTED",
        variant: int = 0,
        valid_to: datetime | None = None,
    ) -> dict[str, Any]:
        market = self.party_market[party]
        if channel == "PHONE":
            value = f"SYN-TEL-{market}-{(500000 if variant else 100000) + party_no:06d}"
        else:
            value = f"example.policyholder.{party_no:03d}@example.invalid"
        if not matches_any(value, self.patterns[channel]):
            raise SeedError("INGEST_CONTACT_NOT_SYNTHETIC")  # never reached: values are generated in range
        cid = uid("contact_method", f"{party_no}:{channel}:{variant}")
        self.ins(
            "contact_method",
            f"{party_no}:{channel}:{variant}",
            start,
            id=cid,
            party_id=party,
            channel=channel,
            value_ciphertext=self.dp.encrypt(value, aad=aad("contact_method", "value", cid)),
            value_hmac=self.dp.token(channel, value),
            masked_value=mask_contact(channel, value),
            is_verified=False,
            preference_rank=rank,
            language="en",
            timezone="Asia/Singapore" if market == "SG" else "Asia/Kuala_Lumpur",
            consent_status=consent,
            suppressed=suppressed,
            valid_from=start,
            valid_to=valid_to,
        )
        row = {
            "id": cid,
            "channel": channel,
            "masked": mask_contact(channel, value),
            "from": start,
            "to": valid_to,
            "suppressed": suppressed,
            "consent": consent,
            "rank": rank,
        }
        self.contacts.setdefault(party, []).append(row)
        return row

    def _role(self, pol: dict[str, Any], party: uuid.UUID, role: str, start: datetime, **extra: Any) -> None:
        key = f"{pol['no']}:{party}:{role}"
        rid = self.ins(
            "policy_party_role", key, start, policy_id=pol["id"], party_id=party, role=role, valid_from=start, **extra
        )
        pol["roles"].append({"id": rid, "party": party, "role": role, **extra})

    def _sale(self, x: Profile, pol: dict[str, Any], kind: str, n: int) -> dict[str, Any]:
        rnd = self.rnd
        sold = self.at(x.sold_days or 30)
        is_ilp = pol["family"] == "ILP"
        # Choose sale attributes so a rule-assessed band is supported by the synthetic rules.
        if x.origin == "RULE_ASSESSED" and not is_ilp and x.band == "MEDIUM":
            channel, band_label = rnd.choice(
                [("BANCASSURANCE", rnd.choice(["BAND_A", "BAND_B"])), (rnd.choice(["AGENCY", "DIRECT"]), "BAND_C")]
            )
        elif x.origin == "RULE_ASSESSED" and not is_ilp:
            channel, band_label = rnd.choice(["AGENCY", "BROKER", "DIRECT"]), rnd.choice(["BAND_A", "BAND_B"])
        else:
            channel, band_label = (
                rnd.choice(["AGENCY", "BANCASSURANCE", "BROKER", "DIRECT"]),
                rnd.choice(["BAND_A", "BAND_B", "BAND_C"]),
            )
        fsc_id = rnd.choice([f for f, ch in self.fscs if ch == channel])
        location = f"SYN-{'BANK' if channel == 'BANCASSURANCE' else 'BRANCH'}-{rnd.randint(1, 8):02d}"
        premium = pol["premium"] if kind == "NEW_BUSINESS" else Decimal(rnd.randrange(1000, 20000, 500))
        snapshot = {
            "product_code": pol["product"][0],
            "product_family": pol["family"],
            "product_subtype": pol["product"][1],
            "is_ilp": is_ilp,
            "premium_amount_band": band_label,
        }
        sref = f"SALE-{pol['market']}-{n:06d}"
        sid = self.ins(
            "sale_event",
            n,
            sold,
            sale_ref=sref,
            policy_id=pol["id"],
            sale_event_type=kind,
            sold_at=sold,
            fsc_id=fsc_id,
            selling_channel=channel,
            selling_location=location,
            campaign_code=f"SYN-CMP-{rnd.randint(1, 5):02d}" if rnd.random() < 0.3 else None,
            proposal_ref=f"PRP-{n:06d}",
            product_snapshot=snapshot,
            premium_amount=premium,
            currency=pol["currency"],
            source_reference=f"SYN-POLICY-ADMIN:{sref}",
        )
        self.ins(
            "external_reference",
            f"sale:{n}",
            p=False,
            source_system="SYN-POLICY-ADMIN",
            object_type="SALE_EVENT",
            external_id=sref,
            entity_id=sid,
        )
        pol["sales"] += 1
        return {
            "id": sid,
            "ref": sref,
            "n": n,
            "sold": sold,
            "channel": channel,
            "location": location,
            "band_label": band_label,
            "premium": premium,
            "kind": kind,
        }

    # ---- per case ------------------------------------------------------------------------------------------
    def build_cases(self) -> None:
        golden_iter = iter(f"CB-2026-{n:05d}" for n in range(10001, 19999) if f"CB-2026-{n:05d}" not in GOLDEN)
        my_iter = iter(f"CB-2026-{n:05d}" for n in range(20002, 29999))
        self.finding_no = 0
        for idx, (x, pol, sale) in enumerate(self.case_plan, start=1):
            ref = x.ref or (next(my_iter) if x.market == "MY" else next(golden_iter))
            self._case(idx, ref, x, pol, sale)

    def _case(self, idx: int, ref: str, x: Profile, pol: dict[str, Any], sale: dict[str, Any]) -> None:
        sold: datetime = sale["sold"]
        risk = self._risk(x, pol, sale)
        facts = {
            "policy_ref": f"POL-{pol['market']}-{pol['no']:06d}",
            "market": pol["market"],
            "product_code": pol["product"][0],
            "product_family": pol["family"],
            "product_subtype": pol["product"][1],
            "is_ilp": pol["family"] == "ILP",
            "premium_amount": str(sale["premium"]),
            "currency": pol["currency"],
            "premium_frequency": pol["freq"],
            "premium_term_years": pol["term"],
            "sale_ref": sale["ref"],
            "sale_event_type": sale["kind"],
            "selling_channel": sale["channel"],
            "suitability": {
                "risk_tolerance": self.rnd.choice(["CONSERVATIVE", "MODERATE", "GROWTH"]),
                "source": "SYN-FNA",
                "as_of": (sold - timedelta(days=3)).date().isoformat(),
                "note": "Customer investment suitability fact (sourced). Not SBQ callback-selection risk.",
            },
        }
        captured = sold + timedelta(hours=19)
        snap_id = self.ins(
            "policy_fact_snapshot",
            sale["n"],
            captured,
            policy_id=pol["id"],
            sale_event_id=sale["id"],
            captured_at=captured,
            schema_version="1",
            facts=facts,
            field_provenance={
                k: {"source_system": "SYN-POLICY-ADMIN", "as_of": sold.date().isoformat()}
                for k in facts
                if k != "suitability"
            }
            | {"suitability": {"source_system": "SYN-FNA"}},
            sha256=sha256_of(facts),
        )
        due = sold + timedelta(days=30)
        closure: dict[str, Any] = (
            {"closure_reason": x.closure, "closure_reason_list_version_id": governed_version("case_closure_reason")}
            if x.closure
            else {}
        )
        cancel: dict[str, Any] = {}
        if x.cancel:
            reason, authorised, when = x.cancel
            recorded = sold + timedelta(days=3) if when == "BEFORE" else due + timedelta(days=2)
            cancel = {
                "cancellation_reason": reason,
                "cancellation_reason_list_version_id": governed_version("case_cancellation_reason"),
                "cancelled_recorded_at": recorded,
            }
            if authorised:
                cancel |= {
                    "cancellation_authorized_by": "SYNTHETIC-SUPERVISOR-01",
                    "cancellation_authorization_ref": f"SYN-CANCEL-AUTH-{idx:04d}",
                }
        created = sold + timedelta(hours=12)
        times = self._attempt_times(sold, len(x.attempts))
        last_end = times[-1][1] if times else created
        terminal_at = last_end + timedelta(days=1)
        # Session timing mirrors _session(): start = last attempt + 40 s, 14 minutes long; verified 2 h later.
        verified_at = times[-1][0] + timedelta(seconds=40, minutes=14, hours=2) if x.state == "VERIFIED" else None
        case_id = self.ins(
            "callback_case",
            ref,
            created,
            case_ref=ref,
            sale_event_id=sale["id"],
            obligation_type="SALE_VERIFICATION",
            source_request_ref=f"SYN-REQ-{sale['ref']}",
            market_code=pol["market"],
            state=x.state,
            priority={"HIGH": 1, "MEDIUM": 2}.get(x.band or "", 3),
            due_at=due,
            verified_at=verified_at,
            closed_at=terminal_at if x.state == "CLOSED_UNVERIFIED" else None,
            created_at=created,
            **closure,
            **cancel,
        )
        self.event(case_id, "CASE_CREATED", created, f"Callback obligation created for {sale['ref']}")
        if risk:
            self.event(
                case_id,
                "RISK_RECORDED",
                risk["assessed_at"],
                f"SBQ selection risk {risk['band']} recorded ({risk['origin']})",
                ("risk_assessment", risk["id"]),
            )
        selections = self._selections(case_id, x, pol, created)
        assignment = None
        if x.assign and risk is not None:
            assignment = self._assignment(case_id, x, pol, sale, risk, snap_id, facts, sold + timedelta(days=1))
        for reason, released in x.holds:
            self._hold(case_id, ref, reason, created + timedelta(hours=2), released)
        contacted = self._attempts(case_id, ref, x, pol, sold, selections)
        if x.session:
            assert assignment is not None and risk is not None
            self._session(case_id, ref, x, pol, contacted, assignment, risk, snap_id, facts)
        if verified_at is not None:
            self.event(case_id, "CASE_VERIFIED", verified_at, "Verification recorded")
        elif x.state == "CLOSED_UNVERIFIED":
            self.event(case_id, "CASE_CLOSED", terminal_at, f"Closed unverified: {x.closure}")
        elif x.state == "CANCELLED":
            self.event(
                case_id,
                "CASE_CANCELLED",
                cancel["cancelled_recorded_at"],
                f"Cancelled: {x.cancel[0]}" if x.cancel else "Cancelled",
            )
        self.case_ids[ref] = case_id

    @staticmethod
    def _attempt_times(sold: datetime, n: int) -> list[tuple[datetime, datetime]]:
        out = []
        for i in range(n):
            start = sold + timedelta(days=2 + 2 * i, hours=2)
            out.append((start, start + timedelta(minutes=3)))
        return out

    def _risk(self, x: Profile, pol: dict[str, Any], sale: dict[str, Any]) -> dict[str, Any] | None:
        if x.risk == "NONE":
            return None
        sold: datetime = sale["sold"]
        band_list = governed_version("sbq_risk_band")
        is_ilp = pol["family"] == "ILP"

        def write(
            key: str, origin: str, band: str, when: datetime, supersedes: uuid.UUID | None = None
        ) -> dict[str, Any]:
            rule_set = None
            factors: list[dict[str, Any]] = []
            if origin == "RULE_ASSESSED":
                version = 1 if when < self.at(200) else 2
                rule_set = self.rule_sets[version]
                values = {
                    "SELLING_CHANNEL": ("ENUM", sale["channel"]),
                    "SELLING_LOCATION": ("ENUM", sale["location"]),
                    "PREMIUM_AMOUNT_BAND": ("ENUM", sale["band_label"]),
                    "PRODUCT_CLASS": ("ENUM", pol["family"]),
                    "ILP_INDICATOR": ("BOOLEAN", is_ilp),
                }
                matched = []
                for code, (vtype, value) in values.items():
                    rule = next((r for r in C.RISK_RULES if r["factor"] == code), None)
                    hit = rule is not None and rule["equals"] == value
                    if hit and rule is not None:
                        matched.append(rule)
                    factors.append(
                        {
                            "factor_code": code,
                            "value_type": vtype,
                            "value": value,
                            "source": "SYN-POLICY-ADMIN",
                            "matched_rule_id": rule["id"] if hit and rule else None,
                            "result": "MATCHED" if hit else ("NOT_MATCHED" if rule else "NOT_EVALUATED"),
                        }
                    )
                order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
                indicated = max((r["indicates"] for r in matched), key=order.__getitem__, default="LOW")
                if indicated != band:
                    raise SeedError(f"seeded rule trace does not support band {band} for {sale['ref']}")
                digest = sha256_of(
                    sorted(
                        ({k: f[k] for k in ("factor_code", "value_type", "value", "source")} for f in factors),
                        key=lambda f: f["factor_code"],
                    )
                )
                reasons = [r["id"] for r in matched] or ["NO_RULE_MATCHED"]
                explanation = (
                    f"Seeded synthetic trace against SYN-SBQ-RULES v{version} (not AIA-approved); "
                    "no rule engine runs in Stage 0"
                )
                original = None
            else:
                original = {"LOW": "SBQ-L", "MEDIUM": "SBQ-M", "HIGH": "SBQ-H", "UNKNOWN": "SBQ-U"}[band]
                reasons = [f"SRC-{band}"]
                digest = sha256_of(
                    {
                        "origin": origin,
                        "source_original_value": original,
                        "reason_codes": reasons,
                        "source_reference": f"SYN-SBQ:{sale['ref']}:{key}",
                    }
                )
                explanation = f"Band supplied by synthetic source system SYN-SBQ (original value {original})"
            aid = self.ins(
                "risk_assessment",
                f"{sale['n']}:{key}",
                when,
                sale_event_id=sale["id"],
                kind="CALLBACK_SELECTION",
                origin=origin,
                status="PROVISIONAL",
                band_code=band,
                band_list_version_id=band_list,
                score=None,
                reason_codes=reasons,
                explanation=explanation,
                source_original_value=original,
                rule_set_version_id=rule_set,
                assessed_at=when,
                valid_at=when,
                input_snapshot_sha256=digest,
                supersedes_id=supersedes,
            )
            for f in factors:
                self.ins(
                    "risk_factor_result",
                    f"{sale['n']}:{key}:{f['factor_code']}",
                    when,
                    assessment_id=aid,
                    factor_list_version_id=governed_version("risk_factor"),
                    weight=None,
                    **f,
                )
            return {"id": aid, "band": band, "origin": origin, "sha": digest, "assessed_at": when}

        band = x.band or "LOW"
        effective_at = sold + timedelta(hours=12)
        if x.risk in {"PAIR", "CONFLICT"}:
            other = band if x.risk == "PAIR" else ("LOW" if band != "LOW" else "HIGH")
            counterpart = write("source", "SOURCE_ASSIGNED", other, sold + timedelta(hours=6))
            self.upd("risk_assessment", counterpart["id"], status="FINAL")
            eff = write("rule", x.origin, band, effective_at)
            self.upd("risk_assessment", eff["id"], status="FINAL")
            return eff
        if x.risk == "SUPERSEDED":
            first = write("initial", x.origin, "UNKNOWN", sold + timedelta(hours=4))
            self.upd("risk_assessment", first["id"], status="FINAL")
            eff = write("current", x.origin, band, effective_at, supersedes=first["id"])
            self.upd("risk_assessment", first["id"], status="SUPERSEDED")
            self.upd("risk_assessment", eff["id"], status="FINAL")
            return eff
        eff = write("current", x.origin, band, effective_at)
        self.upd("risk_assessment", eff["id"], status="FINAL")
        return eff

    def _method_at(self, party: uuid.UUID, when: datetime, channel: str = "PHONE") -> dict[str, Any] | None:
        for m in self.contacts.get(party, []):
            if m["channel"] == channel and m["from"] <= when and (m["to"] is None or when < m["to"]):
                return m
        return None

    def _selections(
        self, case_id: uuid.UUID, x: Profile, pol: dict[str, Any], created: datetime
    ) -> list[dict[str, Any]]:
        decided = created + timedelta(hours=1)
        roles_version = governed_version("callable_party_roles")
        out = []
        for r in pol["roles"]:
            if r["role"] not in {"OWNER", "AUTHORIZED_CONTACT", "INSURED"}:
                continue
            if r["role"] == "INSURED" and r["party"] in pol["owners"]:
                continue
            method = self._method_at(r["party"], decided)
            reason = None
            if r["role"] == "INSURED":
                reason = "ROLE_NOT_CALLABLE"
            elif r["role"] == "AUTHORIZED_CONTACT" and not r.get("authorization_ref"):
                reason = "AUTHORIZATION_NOT_EVIDENCED"
            elif method is None:
                reason = "NO_CONTACT_METHOD"
            elif method["suppressed"]:
                reason = "CONTACT_SUPPRESSED"
            elif method["consent"] != "GRANTED":
                reason = "CONSENT_NOT_GRANTED"
            sid = self.ins(
                "case_contact_selection",
                f"{case_id}:{r['id']}",
                decided,
                callback_case_id=case_id,
                party_id=r["party"],
                policy_party_role_id=r["id"],
                contact_method_id=method["id"] if method else None,
                eligible=reason is None,
                ineligibility_reason=reason,
                rule_basis=r["role"],
                rule_basis_list_version_id=roles_version,
                decided_at=decided,
                decided_by=BY,
            )
            out.append(
                {
                    "id": sid,
                    "party": r["party"],
                    "role": r["role"],
                    "eligible": reason is None,
                    "role_id": r["id"],
                    "method": method,
                }
            )
        self.event(
            case_id,
            "CONTACTS_SELECTED",
            decided,
            f"{sum(s['eligible'] for s in out)} eligible contact(s) of {len(out)} considered",
        )
        return out

    def _assignment(
        self,
        case_id: uuid.UUID,
        x: Profile,
        pol: dict[str, Any],
        sale: dict[str, Any],
        risk: dict[str, Any],
        snap: uuid.UUID,
        facts: dict[str, Any],
        when: datetime,
    ) -> dict[str, Any]:
        market = pol["market"]
        chosen = None
        excluded = []
        for code, ver, rmarket, target, eff, end, rid in self.rules:
            active = eff <= when and (end is None or when < end)
            if rmarket == market and active:
                chosen = (code, ver, target, rid)
            else:
                excluded.append(
                    {
                        "rule": f"{code} v{ver}",
                        "reason": "market" if rmarket != market else "not effective at assignment time",
                    }
                )
        if chosen is None:
            raise SeedError(f"no seeded rule for {sale['ref']} at {when.isoformat()}")
        code, ver, target, rid = chosen
        manifest = self.manifests[target]
        sections = [
            s["module_code"] for s in manifest["sections"] if _holds(s["inclusion_condition"], facts, risk["band"])
        ]
        inputs = {
            "market": market,
            "product_family": pol["family"],
            "is_ilp": pol["family"] == "ILP",
            "risk_band": risk["band"],
            "risk_assessment_id": str(risk["id"]),
            "selling_channel": sale["channel"],
            "language": "en",
            "case_purpose": "SALE_VERIFICATION",
            "event_time": when.isoformat(),
        }
        trace = {
            "engine": "NONE: seeded decision record (ADR-0008 §1); no resolver runs in Stage 0",
            "matched": f"{code} v{ver}",
            "excluded": excluded,
            "precedence": "priority, then specificity",
            "resolved_sections": sections,
            "label": C.LABEL,
        }
        aid = self.ins(
            "script_assignment",
            case_id,
            when,
            callback_case_id=case_id,
            script_version_id=target,
            script_manifest_sha256=sha256_of(manifest),
            risk_assessment_id=risk["id"],
            policy_fact_snapshot_id=snap,
            matched_rule_version_id=rid,
            rule_trace=trace,
            input_snapshot=inputs,
            input_sha256=sha256_of(inputs),
            origin="SEED",
            assigned_at=when,
            assigned_by=BY,
        )
        self.event(
            case_id,
            "SCRIPT_ASSIGNED",
            when,
            f"Script {manifest['family']} {manifest['version_label']} assigned ({' + '.join(sections)})",
            ("script_assignment", aid),
        )
        return {"id": aid, "version": target, "manifest": manifest, "sections": sections}

    def _hold(self, case_id: uuid.UUID, ref: str, reason: str, when: datetime, released: bool) -> None:
        hid = self.ins(
            "case_hold",
            f"{case_id}:{reason}",
            p=False,
            callback_case_id=case_id,
            hold_reason=reason,
            hold_reason_list_version_id=governed_version("case_hold_reason"),
            is_blocking=False,
            placed_at=when,
            placed_by=BY,
            placed_reason=f"Seeded synthetic {reason} hold",
            source="SEED",
        )
        write_audit(
            self.session,
            action="CASE.HOLD_PLACED",
            outcome="SUCCEEDED",
            actor=Actor(service="seed"),
            entity_type="callback_case",
            entity_id=ref,
            reason=f"Seeded synthetic hold ({SEED_VERSION})",
            after={"hold_reason": reason},
        )
        self.event(case_id, "HOLD_PLACED", when, f"Hold placed: {reason}", ("case_hold", hid))
        if released:
            rel = when + timedelta(hours=20)
            self.upd("case_hold", hid, released_at=rel, released_by=BY, release_reason="Seeded synthetic release")
            write_audit(
                self.session,
                action="CASE.HOLD_RELEASED",
                outcome="SUCCEEDED",
                actor=Actor(service="seed"),
                entity_type="callback_case",
                entity_id=ref,
                reason=f"Seeded synthetic release ({SEED_VERSION})",
                before={"hold_reason": reason},
            )
            self.event(case_id, "HOLD_RELEASED", rel, f"Hold released: {reason}", ("case_hold", hid))

    def _attempts(
        self,
        case_id: uuid.UUID,
        ref: str,
        x: Profile,
        pol: dict[str, Any],
        sold: datetime,
        selections: list[dict[str, Any]],
    ) -> dict[str, Any]:
        eligible = [s for s in selections if s["eligible"]]
        if not x.attempts:
            return {}
        if not eligible:
            raise SeedError(f"{ref} has attempts but no eligible contact")
        pick = eligible[0]
        if len(eligible) > 1 and self.rnd.random() < 0.4:
            pick = eligible[1]  # joint owners or an evidenced authorised contact (T-32)
        times = self._attempt_times(sold, len(x.attempts))
        change = (
            len(x.attempts) >= 2
            and self.changes_left > 0
            and pick["role"] == "OWNER"
            and not x.ref
            and pol["sales"] == 1
        )
        result: dict[str, Any] = {}
        for seq, (status, (start, end)) in enumerate(zip(x.attempts, times, strict=True), start=1):
            if change and seq == 2:
                self._change_contact(case_id, pick, times[0][1] + timedelta(hours=1))
            method = self._method_at(pick["party"], start)
            assert method is not None
            st = {"ONE": self.rnd.choice(["NO_ANSWER", "NO_ANSWER", "BUSY", "FAILED"])}.get(status, status)
            scheduled = start
            started: datetime | None = start
            ended: datetime | None = end
            if st == "SCHEDULED":
                scheduled, started, ended = self.anchor + timedelta(days=1), None, None
            elif st in {"INITIATED", "CONNECTING"}:
                scheduled = started = self.anchor - timedelta(hours=1)
                ended = None
            snapshot = {
                "contact_method_id": str(method["id"]),
                "channel": method["channel"],
                "masked_value": method["masked"],
                "method_valid_from": method["from"].isoformat(),
            }
            aid = self.ins(
                "contact_attempt",
                f"{ref}:{seq}",
                started or scheduled,
                attempt_ref=f"AT-{ref[3:]}-{seq}",
                callback_case_id=case_id,
                sequence=seq,
                transport="SYNTHETIC",
                direction="OUTBOUND",
                status=st,
                contacted_party_id=pick["party"],
                contact_method_id=method["id"],
                contact_snapshot=snapshot,
                scheduled_at=scheduled,
                started_at=started,
                ended_at=ended,
                failure_reason="SYNTHETIC_NETWORK_FAILURE" if st == "FAILED" else None,
                record_origin="SYNTHETIC_SEED",
            )
            self.event(
                case_id, "ATTEMPT_RECORDED", started or scheduled, f"Attempt {seq}: {st}", ("contact_attempt", aid)
            )
            result = {"id": aid, "party": pick["party"], "snapshot": snapshot, "start": start, "end": end}
        return result

    def _change_contact(self, case_id: uuid.UUID, pick: dict[str, Any], when: datetime) -> None:
        """T-38: a new phone version; the old one is closed; earlier attempt snapshots are untouched."""
        self.changes_left -= 1
        old = pick["method"]
        self.upd("contact_method", old["id"], valid_to=when)
        old["to"] = when
        party_no = int(
            self.conn.execute(
                select(self.t["party"].c.party_ref).where(self.t["party"].c.id == pick["party"])
            ).scalar_one()[4:]
        )
        new = self._contact(pick["party"], party_no, "PHONE", when, variant=1)
        roles_version = governed_version("callable_party_roles")
        self.ins(
            "case_contact_selection",
            f"{case_id}:{pick['role_id']}:changed",
            when,
            callback_case_id=case_id,
            party_id=pick["party"],
            policy_party_role_id=pick["role_id"],
            contact_method_id=new["id"],
            eligible=True,
            rule_basis=pick["role"],
            rule_basis_list_version_id=roles_version,
            decided_at=when,
            decided_by=BY,
            supersedes_id=pick["id"],
        )
        self.event(case_id, "CONTACT_CHANGED", when, "Contact method updated; earlier attempt evidence unchanged")

    def _session(
        self,
        case_id: uuid.UUID,
        ref: str,
        x: Profile,
        pol: dict[str, Any],
        att: dict[str, Any],
        assignment: dict[str, Any],
        risk: dict[str, Any],
        snap: uuid.UUID,
        facts: dict[str, Any],
    ) -> None:
        start: datetime = att["start"] + timedelta(seconds=40)
        end = start + timedelta(minutes=14)
        manifest = assignment["manifest"]
        snap_sha = sha256_of(facts)
        sid = self.ins(
            "conversation_session",
            ref,
            start,
            session_ref=f"SS-{ref[3:]}",
            contact_attempt_id=att["id"],
            state=x.session,
            transport="SYNTHETIC",
            started_at=start,
            ended_at=end,
            script_version_id=assignment["version"],
            script_manifest_sha256=sha256_of(manifest),
            risk_assessment_id=risk["id"],
            risk_snapshot_sha256=risk["sha"],
            policy_fact_snapshot_id=snap,
            policy_fact_snapshot_sha256=snap_sha,
            contacted_party_id=att["party"],
            contact_method_snapshot=att["snapshot"],
            media_status="NOT_REQUIRED",
            transcript_status="UNAVAILABLE",
            record_origin="SYNTHETIC_SEED",
        )
        self.event(
            case_id,
            "SESSION_RECORDED",
            start,
            f"Seeded session {x.session}; no media or transcript (S1)",
            ("conversation_session", sid),
        )
        run = self.ins(
            "survey_run",
            ref,
            start,
            session_id=sid,
            script_version_id=assignment["version"],
            script_manifest_sha256=sha256_of(manifest),
            policy_fact_snapshot_id=snap,
            status="IN_PROGRESS",
            started_at=start + timedelta(seconds=30),
            record_origin="SYNTHETIC_SEED",
        )
        questions = [
            q
            for s in manifest["sections"]
            if s["module_code"] in assignment["sections"]
            for q in s["questions"]
            if not _holds_na(q["not_applicable_predicate"], facts, risk["band"])
        ]
        if x.session == "INTERRUPTED":
            questions = questions[: (len(questions) + 1) // 2]
        elif x.session == "ABORTED":
            questions = questions[:2]
        targets = self._finding_targets(x, [q["question_code"] for q in questions], ref)
        executions: dict[str, tuple[uuid.UUID, uuid.UUID | None, uuid.UUID]] = {}
        for pos, q in enumerate(questions, start=1):
            code = q["question_code"]
            t0 = start + timedelta(minutes=1 + pos)
            qe = self.ins(
                "question_execution",
                f"{ref}:{pos}",
                t0,
                survey_run_id=run,
                question_revision_id=uuid.UUID(q["question_revision_id"]),
                position=pos,
                delivery_status="DELIVERED",
                retries=0,
                event_range={"offset_s": [60 * (1 + pos), 60 * (1 + pos) + 50], "transcript": "NOT_AVAILABLE"},
                record_origin="SYNTHETIC_SEED",
            )
            state, value, verbatim, expected, observed, result = self._answer(code, facts, targets.get(code), x)
            obs = self.ins(
                "answer_observation",
                f"{ref}:{pos}",
                t0,
                question_execution_id=qe,
                answer_state=state,
                typed_value=value,
                verbatim_text_redacted=verbatim,
                transcript_segment_ids=[],
                extraction_engine="SYNTHETIC_SEED",
                extraction_version=SEED_VERSION,
                record_origin="SYNTHETIC_SEED",
            )
            ev = None
            if result is not None:
                ev = self.ins(
                    "rule_evaluation",
                    f"{ref}:{pos}",
                    t0,
                    question_execution_id=qe,
                    rule_ref=f"SYN-RULE-{code}",
                    rule_version=SEED_VERSION,
                    expected=expected,
                    observed=observed,
                    result=result,
                    evaluated_at=t0 + timedelta(seconds=5),
                    record_origin="SYNTHETIC_SEED",
                )
            executions[code] = (qe, ev, obs)
        final = {"COMPLETED": "COMPLETED", "INTERRUPTED": "INCOMPLETE", "ABORTED": "ABORTED"}[x.session or ""]
        self.upd("survey_run", run, status=final, completed_at=end if final == "COMPLETED" else None)
        for severity, category in x.findings:
            code = next(c for c, (sev, cat) in targets.items() if (sev, cat) == (severity, category))
            qe, ev, obs = executions[code]
            self.finding_no += 1
            fid = self.ins(
                "finding",
                self.finding_no,
                end,
                finding_ref=f"FND-2026-{self.finding_no:05d}",
                callback_case_id=case_id,
                question_execution_id=qe,
                category=category,
                severity=severity,
                status="UNDER_REVIEW" if x.state == "ESCALATED" else "OPEN",
                evidence_refs={
                    "question_execution_id": str(qe),
                    "answer_observation_id": str(obs),
                    "rule_evaluation_id": str(ev) if ev else None,
                    "transcript": "NOT_AVAILABLE",
                    "label": C.LABEL,
                },
                origin="NARRATIVE_FLAG" if category == "CONTRADICTORY_ANSWER" else "RULE_EVALUATION",
                raised_at=end + timedelta(minutes=5),
                review_assigned_at=end + timedelta(hours=2) if x.state == "ESCALATED" else None,
                record_origin="SYNTHETIC_SEED",
            )
            self.event(
                case_id,
                "FINDING_RAISED",
                end + timedelta(minutes=5),
                f"{severity} {category} finding",
                ("finding", fid),
            )

    @staticmethod
    def _finding_targets(x: Profile, codes: list[str], ref: str) -> dict[str, tuple[str, str]]:
        """Which executed question carries each planned finding."""
        by_category = {
            "FACT_MISMATCH": "Q-PREMIUM-TERM-YEARS",
            "DISCLOSURE_CONCERN": "Q-REP-DISCLOSED",
            "UNCLEAR_UNDERSTANDING": "Q-REASON-UNDERSTOOD",
            "CONTRADICTORY_ANSWER": "Q-ILP-OWN-WORDS",
        }
        out = {}
        for severity, category in x.findings:
            code = by_category[category]
            if code not in codes:
                raise SeedError(f"{ref}: finding {category} needs {code}, which was not asked")
            out[code] = (severity, category)
        return out

    def _answer(
        self, code: str, facts: dict[str, Any], finding: tuple[str, str] | None, x: Profile
    ) -> tuple[str, Any, str, Any, Any, str | None]:
        """(answer_state, typed_value, verbatim, expected, observed, rule result or None)."""
        q = C.QUESTIONS[code]
        policy = q["policy"]
        if policy == "NUMERIC_MATCH_POLICY_FACT":
            expected = facts.get(q["fact_key"])
            if expected is None:  # single-premium plans have no premium term: indeterminate, never a match
                return "UNCLEAR", None, "[synthetic] not sure", {"value": None}, {"value": None}, "INDETERMINATE"
            value = (x.wrong_term or max(expected - 5, 1)) if finding else expected
            return (
                "YES",
                {"value": value},
                f"[synthetic] {value} years",
                {"value": expected},
                {"value": value},
                "MATCH" if value == expected else "MISMATCH",
            )
        if policy == "EXACT_BOOLEAN":
            want = q["expected"]["value"]
            got = (not want) if finding else want
            return (
                "YES" if got else "NO",
                {"value": got},
                f"[synthetic] {'yes' if got else 'no'}",
                {"value": want},
                {"value": got},
                "MATCH" if got == want else "MISMATCH",
            )
        if policy == "ACKNOWLEDGEMENT":
            if finding:
                return (
                    "UNCLEAR",
                    None,
                    "[synthetic] I am not sure I follow",
                    {"acknowledged": True},
                    {"acknowledged": None},
                    "INDETERMINATE",
                )
            return (
                "YES",
                {"acknowledged": True},
                "[synthetic] yes, understood",
                {"acknowledged": True},
                {"acknowledged": True},
                "MATCH",
            )
        if policy == "NARRATIVE_REVIEW":
            text_ = (
                "[synthetic] I was told there are no charges at all"
                if finding
                else "[synthetic] narrative answer pending human review"
            )
            return "YES", {"text_captured": True}, text_, None, None, None
        if code == "Q-PREMIUM-FREQUENCY":
            return "YES", {"value": facts["premium_frequency"]}, "[synthetic] as agreed", None, None, None
        return "YES", {"text_captured": True}, "[synthetic] no further concerns", None, None, None


def _holds(cond: dict[str, Any] | None, facts: dict[str, Any], band: str | None) -> bool:
    from app.domain.outcomes import condition_holds

    return condition_holds(cond, facts, band)


def _holds_na(pred: dict[str, Any] | None, facts: dict[str, Any], band: str | None) -> bool:
    return pred is not None and _holds(pred, facts, band)


def counts(conn: Connection, schema: str) -> dict[str, int]:
    from app.domain.catalog import CP02_TABLES

    return {
        t: int(conn.execute(text(f"SELECT count(*) FROM {schema}.{t}")).scalar_one())  # noqa: S608
        for t in CP02_TABLES
    }


def _manifest_event(conn: Connection, schema: str) -> dict[str, Any] | None:
    row = conn.execute(
        text(
            f"SELECT after FROM {schema}.audit_event WHERE action = 'SEED.MANIFEST' AND entity_id = :v "  # noqa: S608
            "ORDER BY seq DESC LIMIT 1"
        ),
        {"v": SEED_VERSION},
    ).scalar()
    return dict(row) if row else None


def seed(conn: Connection, schema: str, protection: DataProtection, *, anchor: datetime | None = None) -> SeedReport:
    """Seed ``schema`` in the caller's transaction. Idempotent; refuses foreign or partial business data."""
    assert schema in {"call360", "call360_test"}, schema
    anchor = anchor or default_anchor()
    existing = _manifest_event(conn, schema)
    current = counts(conn, schema)
    if existing is not None:
        digest = content_digest(conn, schema)
        if digest != existing["digest"]:
            raise SeedError("business data differs from the recorded seed manifest")
        return SeedReport(SEED_VERSION, digest, current, protection.key_ids, created=False)
    if any(current.values()):
        raise SeedError("refusing to seed: CP0.2 tables already hold data without a seed manifest")

    s = _Seeder(conn, schema, protection, anchor)
    profiles = plan()
    s.reference_content()
    s.assign_profiles(profiles)
    s.build_sales(profiles)
    s.build_cases()
    if s.changes_left:
        raise SeedError(f"{s.changes_left} planned contact changes were not placed")
    conn.execute(insert(s.t["case_event"]), s.events)
    final = counts(conn, schema)
    for table, n in TARGETS.items():
        if final[table] != n:
            raise SeedError(f"{table}: {final[table]} rows, expected {n}")
    outcomes = derive_outcomes(conn, schema)
    if any(o.category == EVIDENCE_INCOMPLETE for o in outcomes.values()):
        raise SeedError("a VERIFIED case lacks satisfied mandatory controls (VERIFIED_CONTROL_EVIDENCE_INCOMPLETE)")
    digest = content_digest(conn, schema)
    write_audit(
        s.session,
        action="SEED.MANIFEST",
        outcome="SUCCEEDED",
        actor=Actor(service="seed"),
        entity_type="seed",
        entity_id=SEED_VERSION,
        reason="Deterministic synthetic seed (S0_DATA_MODEL §6)",
        after={
            "digest": digest,
            "rng_seed": RNG_SEED,
            "anchor": anchor.date().isoformat(),
            "counts": final,
            "key_ids": protection.key_ids,
            "outcomes": dict(Counter(o.category for o in outcomes.values())),
        },
    )
    s.session.flush()
    return SeedReport(SEED_VERSION, digest, final, protection.key_ids, created=True)
