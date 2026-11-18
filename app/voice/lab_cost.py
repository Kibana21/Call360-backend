"""Voice Lab cost control (S1-E.1): provider catalogue, rate cards, estimates and backend-enforced budgets.

Rules (all enforced here, on the server, inside one transaction holding a per-spend-class advisory lock):

- **Fail closed.** A provider without a known rate card cannot run (``COST_UNKNOWN``); only a provider declared
  cost-free (the keyless mock) runs without a reservation.
- **Paid access is off by default.** ``PAID`` providers are refused (``PAID_DISABLED``) unless a manager has switched
  ``lab_control.paid_enabled`` on (S1-E.2) — and even then a session needs the server's GPT-Live configuration (mode
  LIVE + backend-only key), a single-use smoke-test authorisation by another user (``app.voice.lab``) and the PAID
  budget below. Paid experiments are impossible (database CHECK).
- **Reserve before start.** A metered session or experiment reserves its *estimated maximum* cost before anything is
  created: per-experiment, daily (Asia/Singapore day) and overall limits, maximum concurrent sessions and the kill
  switch are checked first. The reservation is reconciled with the measured cost at the end, or released.
- **No retries, no schedules.** Both are disabled by database CHECK constraints.

The ``MOCK_METERED`` provider is the keyless mock with a *synthetic* rate card, so budget enforcement can be exercised
without any money; its rates are not provider pricing. Real provider rates must be taken from the provider's current
official price list (and recorded with their source and date) before such a provider is ever configured.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime
from decimal import ROUND_UP, Decimal
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import text
from sqlalchemy.orm import Session

SGT = ZoneInfo("Asia/Singapore")
GPT_VOICES = (
    "marin",
    "quartz",
    "ripple",
    "vesper",
    "willow",
    "stone",
    "gleam",
    "meridian",
    "bossa",
    "tempo",
    "beacon",
    "delta",
    "cinder",
    "nuri",
    "juni",
    "flitz",
    "brise",
    "sillage",
    "nira",
    "harema",
    "shida",
    "noeul",
)
CENT = Decimal("0.0001")


class BudgetError(Exception):
    def __init__(self, status: int, code: str, message: str, details: list[str] | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details or []


@dataclass(frozen=True)
class RateCard:
    """USD per minute of audio into and out of the provider, plus (S1-E.2) a per-session-minute voice rate billed on
    the provider-reported session duration. ``None`` rates mean the cost cannot be estimated."""

    input_per_min: Decimal | None
    output_per_min: Decimal | None
    basis: str
    source: str
    session_per_min: Decimal = Decimal(0)
    verified_on: str | None = None

    @property
    def known(self) -> bool:
        return self.input_per_min is not None and self.output_per_min is not None

    def as_json(self) -> dict[str, Any]:
        return {
            "input_usd_per_audio_min": str(self.input_per_min) if self.input_per_min is not None else None,
            "output_usd_per_audio_min": str(self.output_per_min) if self.output_per_min is not None else None,
            "session_usd_per_min": str(self.session_per_min),
            "billing": "per second of provider-reported session duration" if self.session_per_min else "audio minutes",
            "verified_on": self.verified_on,
            "basis": self.basis,
            "source": self.source,
        }


@dataclass(frozen=True)
class Provider:
    code: str
    label: str
    spend_class: str  # NONE | SIMULATED | PAID
    available: bool
    reason: str
    models: tuple[str, ...]
    voices: tuple[str, ...]
    rates: RateCard
    network: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)


ZERO = RateCard(Decimal(0), Decimal(0), "Keyless local mock: no external service, no charge", "Call360 code")
SYNTHETIC = RateCard(
    Decimal("0.04"),
    Decimal("0.12"),
    "SYNTHETIC test rates to exercise budget controls — not provider pricing; no money is spent",
    "Call360 S1-E.1 test configuration",
)
UNKNOWN = RateCard(None, None, "Not configured: current official provider pricing has not been verified", "—")
GPT_LIVE_RATE = RateCard(
    Decimal(0),
    Decimal(0),
    "gpt-live-1 voice sessions: USD 0.05 per minute, billed per second, not rounded up to a whole minute; backend "
    "model and tool usage billed separately (Call360 uses none). Not stated: whether instruction tokens, live "
    "transcription or regional uplift apply — the budget covers the voice rate only",
    "developers.openai.com/api/docs/pricing and /api/docs/models/gpt-live-1 (read 2026-11-18)",
    session_per_min=Decimal("0.05"),
    verified_on="2026-11-18",
)
GPT_LIVE_MOCK_RATE = RateCard(
    Decimal(0),
    Decimal(0),
    "The verified GPT-Live rate applied as SYNTHETIC metering to the mocked protocol server's reported usage — no "
    "money is spent",
    "Call360 S1-E.2 test configuration",
    session_per_min=Decimal("0.05"),
    verified_on="2026-11-18",
)

PROVIDERS: dict[str, Provider] = {
    "MOCK": Provider(
        "MOCK",
        "Mock voice provider (keyless)",
        "NONE",
        True,
        "Local mock: speaks the fixed synthetic test message; does not interpret prompts",
        ("mock-fixed-message-1",),
        ("synthetic-fixed",),
        ZERO,
    ),
    "MOCK_METERED": Provider(
        "MOCK_METERED",
        "Mock voice provider with synthetic metering",
        "SIMULATED",
        True,
        "The same local mock, metered with synthetic rates so reservations, limits and reconciliation are exercised",
        ("mock-fixed-message-1",),
        ("synthetic-fixed",),
        SYNTHETIC,
    ),
    "GPT_LIVE": Provider(
        "GPT_LIVE",
        "GPT-Live (real provider, paid)",
        "PAID",
        False,
        "Disabled: paid access needs VOICE_LAB_GPT_LIVE_MODE=LIVE, a backend-only API key, the Voice Lab paid switch "
        "and a single-use smoke-test authorisation (S1-E.2 is offline-verified only)",
        ("gpt-live-1",),
        GPT_VOICES,
        GPT_LIVE_RATE,
        network=True,
    ),
    "GPT_LIVE_MOCK": Provider(
        "GPT_LIVE_MOCK",
        "GPT-Live adapter on a mocked protocol server",
        "SIMULATED",
        False,
        "The real GPT-Live adapter against a local mocked protocol server (loopback): no model, no key, no money",
        ("gpt-live-1",),
        GPT_VOICES,
        GPT_LIVE_MOCK_RATE,
    ),
}


def resolve(code: str, settings: Any) -> Provider:
    """The provider with its availability on this server (configuration, never the browser, decides)."""
    p = provider(code)
    if code == "GPT_LIVE":
        missing = []
        if settings.voice_lab_gpt_live_mode != "LIVE":
            missing.append("VOICE_LAB_GPT_LIVE_MODE is not LIVE")
        if settings.voice_lab_openai_api_key is None:
            missing.append("no backend API key is configured")
        if missing:
            return replace(
                p,
                available=False,
                reason=f"Not configured on this server: {'; '.join(missing)}. "
                "A paid session also needs the Voice Lab paid switch and a single-use smoke-test "
                "authorisation (S1-E.2 is verified offline only)",
            )
        return replace(
            p,
            available=True,
            reason="Configured on this server; every session still needs the paid "
            "switch, a single-use smoke-test authorisation and the PAID budget",
        )
    if code == "GPT_LIVE_MOCK":
        if not settings.voice_lab_gpt_live_mock_url:
            return replace(p, reason="Not configured: VOICE_LAB_GPT_LIVE_MOCK_URL (loopback) is not set")
        return replace(p, available=True)
    return p


def provider(code: str) -> Provider:
    p = PROVIDERS.get(code)
    if p is None:
        raise BudgetError(422, "PROVIDER_UNKNOWN", f"Unknown voice provider {code}")
    return p


def _usd(x: Decimal) -> Decimal:
    return x.quantize(CENT, rounding=ROUND_UP)


def estimate_session(p: Provider, max_duration_s: int) -> Decimal:
    """Upper bound: audio flowing both ways for the whole maximum duration."""
    if not p.rates.known:
        raise BudgetError(422, "COST_UNKNOWN", "The cost of this provider cannot be estimated; refused (fail closed)")
    assert p.rates.input_per_min is not None and p.rates.output_per_min is not None
    per_min = p.rates.input_per_min + p.rates.output_per_min + p.rates.session_per_min
    return _usd(per_min * Decimal(max_duration_s) / 60)


def measured_cost(rates: dict[str, Any], input_s: float, output_s: float, session_s: float = 0.0) -> Decimal:
    i, o = rates.get("input_usd_per_audio_min"), rates.get("output_usd_per_audio_min")
    if i is None or o is None:
        raise BudgetError(422, "COST_UNKNOWN", "No rate card recorded")
    sess = Decimal(str(rates.get("session_usd_per_min") or 0))
    return _usd(
        Decimal(i) * Decimal(str(input_s)) / 60
        + Decimal(o) * Decimal(str(output_s)) / 60
        + sess * Decimal(str(session_s)) / 60
    )


# ---- controls and budgets ----------------------------------------------------------------------------------------
def control(db: Session, *, lock: bool = False) -> dict[str, Any]:
    sql = "SELECT * FROM lab_control WHERE id = 1" + (" FOR UPDATE" if lock else "")  # noqa: S608 — identifiers are constants; values are bound
    return dict(db.execute(text(sql)).mappings().one())


def budget(db: Session, spend_class: str, *, lock: bool = False) -> dict[str, Any]:
    sql = "SELECT * FROM lab_budget WHERE spend_class = :c" + (" FOR UPDATE" if lock else "")  # noqa: S608 — identifiers are constants; values are bound
    return dict(db.execute(text(sql), {"c": spend_class}).mappings().one())


def usage(db: Session, spend_class: str, now: datetime) -> dict[str, Any]:
    day = now.astimezone(SGT).date()
    r = (
        db.execute(
            text(
                "SELECT coalesce(sum(CASE status WHEN 'HELD' THEN reserved_usd WHEN 'RECONCILED' THEN actual_usd "
                "ELSE 0 END), 0) AS overall, "
                "coalesce(sum(CASE WHEN (created_at AT TIME ZONE 'Asia/Singapore')::date = :d THEN CASE status "
                "WHEN 'HELD' THEN reserved_usd WHEN 'RECONCILED' THEN actual_usd ELSE 0 END ELSE 0 END), 0) AS daily, "
                "coalesce(sum(reserved_usd) FILTER (WHERE status = 'HELD'), 0) AS held, "
                "coalesce(sum(actual_usd) FILTER (WHERE status = 'RECONCILED'), 0) AS reconciled, "
                "count(*) FILTER (WHERE status = 'HELD') AS active, count(*) AS reservations "
                "FROM lab_reservation WHERE spend_class = :c"
            ),
            {"c": spend_class, "d": day},
        )
        .mappings()
        .one()
    )
    return dict(r)


def refusal_reasons(db: Session, p: Provider, amount: Decimal, now: datetime, *, ctl: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if ctl["kill_switch"]:
        reasons.append("KILL_SWITCH: the Voice Lab emergency stop is engaged")
    if p.spend_class == "PAID" and not ctl["paid_enabled"]:
        reasons.append("PAID_DISABLED: paid providers are disabled (no paid access without separate authorisation)")
    if not p.available:
        reasons.append(f"PROVIDER_NOT_AVAILABLE: {p.reason}")
    if p.spend_class == "NONE":
        return reasons
    b = budget(db, p.spend_class, lock=True)
    u = usage(db, p.spend_class, now)
    if amount > b["per_experiment_usd"]:
        reasons.append(f"PER_EXPERIMENT_LIMIT: estimated maximum USD {amount} exceeds USD {b['per_experiment_usd']}")
    if u["daily"] + amount > b["daily_usd"]:
        reasons.append(
            f"DAILY_LIMIT: USD {u['daily']} already used or reserved today; USD {amount} more exceeds "
            f"USD {b['daily_usd']}"
        )
    if u["overall"] + amount > b["overall_usd"]:
        reasons.append(
            f"OVERALL_LIMIT: USD {u['overall']} used or reserved; USD {amount} more exceeds USD {b['overall_usd']}"
        )
    if u["active"] >= b["max_concurrent_sessions"]:
        reasons.append(
            f"CONCURRENCY_LIMIT: {u['active']} metered session(s) or experiment(s) already active "
            f"(maximum {b['max_concurrent_sessions']})"
        )
    return reasons


def lock_class(db: Session, spend_class: str) -> None:
    """Serialise reservations per spend class (two concurrent requests can never both pass the limits)."""
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('call360-voicelab-budget:' || :c))"), {"c": spend_class})


def reserve(
    db: Session,
    p: Provider,
    amount: Decimal,
    *,
    actor: str,
    now: datetime,
    session_id: uuid.UUID | None = None,
    experiment_id: uuid.UUID | None = None,
    basis: dict[str, Any],
) -> uuid.UUID | None:
    """Check every limit and hold the estimated maximum. Raises ``BudgetError`` (409) with all reasons."""
    if p.spend_class in ("SIMULATED", "PAID"):
        lock_class(db, p.spend_class)
    ctl = control(db)
    reasons = refusal_reasons(db, p, amount, now, ctl=ctl)
    if reasons:
        code = reasons[0].split(":", 1)[0]
        raise BudgetError(409, code, "Refused by Voice Lab cost controls", reasons)
    if p.spend_class == "NONE":
        return None
    rid = uuid.uuid4()
    db.execute(
        text(
            "INSERT INTO lab_reservation (id, spend_class, scope, session_id, experiment_id, reserved_usd, basis, "
            "created_by, created_at) VALUES (:id, :c, :scope, :s, :e, :amt, CAST(:b AS jsonb), :by, :at)"
        ),
        {
            "id": rid,
            "c": p.spend_class,
            "scope": "SESSION" if session_id else "EXPERIMENT",
            "s": session_id,
            "e": experiment_id,
            "amt": amount,
            "b": _json(basis),
            "by": actor,
            "at": now,
        },
    )
    return rid


def close(
    db: Session,
    *,
    session_id: uuid.UUID | None = None,
    experiment_id: uuid.UUID | None = None,
    actual: Decimal | None,
    now: datetime,
) -> dict[str, Any] | None:
    """Reconcile (measured cost) or release (nothing consumed) the held reservation, once."""
    col, val = ("session_id", session_id) if session_id else ("experiment_id", experiment_id)
    r = (
        db.execute(text(f"SELECT * FROM lab_reservation WHERE {col} = :v AND status = 'HELD' FOR UPDATE"), {"v": val})  # noqa: S608 — identifiers are constants; values are bound
        .mappings()
        .first()
    )
    if r is None:
        return None
    status = "RELEASED" if actual is None else "RECONCILED"
    db.execute(
        text("UPDATE lab_reservation SET status = :st, actual_usd = :a, closed_at = :t WHERE id = :id"),
        {"st": status, "a": actual, "t": now, "id": r["id"]},
    )
    return {
        **dict(r),
        "status": status,
        "actual_usd": actual,
        "overrun": actual is not None and actual > r["reserved_usd"],
    }


def _json(v: Any) -> str:
    import json

    return json.dumps(v, default=str, sort_keys=True)


def paid_spend(db: Session) -> dict[str, Any]:
    """Application evidence that no money was spent: PAID reservations and paid sessions / experiments (all must be
    zero; the database refuses PAID rows in this build)."""
    r = (
        db.execute(
            text(
                "SELECT (SELECT count(*) FROM lab_reservation WHERE spend_class = 'PAID') AS paid_reservations, "
                "(SELECT coalesce(sum(coalesce(actual_usd, reserved_usd)), 0) FROM lab_reservation "
                "WHERE spend_class = 'PAID') AS paid_usd, "
                "(SELECT count(*) FROM lab_session WHERE spend_class = 'PAID') AS paid_sessions, "
                "(SELECT count(*) FROM lab_experiment WHERE spend_class = 'PAID') AS paid_experiments"
            )
        )
        .mappings()
        .one()
    )
    return dict(r)
