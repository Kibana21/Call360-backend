"""Operational audit visibility (CP0.6-F1, owner decision 2026-11-17).

The audit ledger stays complete, immutable and hash-chained. The *operational* view (API-021 and the Administration
counts) follows the business visibility policy (D-39): an event about a business record outside the caller's markets
is not listed; an access-denied event on such a record is listed with the record ID redacted (the security signal
stays visible without exposing the record); the seed manifest is listed without its dataset-wide totals; market-neutral
events (sign-in, users, groups, configuration, search) are listed unchanged. Chain verification still covers every
event (API-026). The predicates are SQL fragments bound to ``:scope_markets`` (the caller's effective markets).
"""

from __future__ import annotations

import uuid

from sqlalchemy import bindparam, text
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import TextClause

# The event's business record lies outside the caller's markets (resolved by ID or reference).
_OUT_OF_SCOPE_ENTITY = """(
  (audit_event.entity_type = 'callback_case' AND EXISTS (SELECT 1 FROM callback_case c
     WHERE (CAST(c.id AS text) = audit_event.entity_id OR c.case_ref = audit_event.entity_id)
       AND c.market_code <> ALL(:scope_markets)))
  OR (audit_event.entity_type = 'policy' AND EXISTS (SELECT 1 FROM policy p
     WHERE (CAST(p.id AS text) = audit_event.entity_id OR p.policy_ref = audit_event.entity_id)
       AND p.market_code <> ALL(:scope_markets)))
  OR (audit_event.entity_type = 'sale_event' AND EXISTS (SELECT 1 FROM sale_event s JOIN policy p ON p.id = s.policy_id
     WHERE (CAST(s.id AS text) = audit_event.entity_id OR s.sale_ref = audit_event.entity_id)
       AND p.market_code <> ALL(:scope_markets)))
  OR (audit_event.entity_type = 'risk_assessment' AND EXISTS (SELECT 1 FROM risk_assessment ra
     JOIN sale_event s ON s.id = ra.sale_event_id JOIN policy p ON p.id = s.policy_id
     WHERE CAST(ra.id AS text) = audit_event.entity_id AND p.market_code <> ALL(:scope_markets)))
  OR (audit_event.entity_type IN ('script_family', 'script_version') AND EXISTS (SELECT 1 FROM script_version v
     JOIN script_family f ON f.id = v.script_family_id
     WHERE (CAST(v.id AS text) = audit_event.entity_id OR CAST(f.id AS text) = audit_event.entity_id)
       AND f.market_code <> ALL(:scope_markets)))
  OR (audit_event.entity_type = 'assignment_rule_draft' AND EXISTS (SELECT 1 FROM assignment_rule_draft d
     WHERE CAST(d.id AS text) = audit_event.entity_id AND d.market_code <> ALL(:scope_markets)))
  OR (audit_event.entity_type = 'simulation_scenario' AND EXISTS (SELECT 1 FROM simulation_scenario x
     WHERE (CAST(x.id AS text) = audit_event.entity_id OR x.scenario_ref = audit_event.entity_id)
       AND x.market_code <> ALL(:scope_markets)))
  OR (audit_event.entity_type = 'simulation_batch' AND EXISTS (SELECT 1 FROM simulation_batch b
     WHERE (CAST(b.id AS text) = audit_event.entity_id OR b.batch_ref = audit_event.entity_id)
       AND b.market_code <> ALL(:scope_markets)))
)"""

# The payload names an out-of-scope policy, sale or case reference.
_TEXT = (
    "(coalesce(audit_event.before::text, '') || coalesce(audit_event.after::text, '') "
    "|| coalesce(audit_event.reason, '') || coalesce(audit_event.entity_id, ''))"
)
_OUT_OF_SCOPE_PAYLOAD = f"""(
  {_TEXT} ~ '(POL|SALE|CB)-'
  AND (
    EXISTS (SELECT 1 FROM policy p
      WHERE p.market_code <> ALL(:scope_markets) AND strpos({_TEXT}, p.policy_ref) > 0)
    OR EXISTS (SELECT 1 FROM sale_event s JOIN policy p ON p.id = s.policy_id
      WHERE p.market_code <> ALL(:scope_markets) AND strpos({_TEXT}, s.sale_ref) > 0)
    OR EXISTS (SELECT 1 FROM callback_case c
      WHERE c.market_code <> ALL(:scope_markets) AND strpos({_TEXT}, c.case_ref) > 0)
  )
)"""  # noqa: S608 — constant SQL; values are bound parameters

DENIED_OBJECT = "ACCESS.DENIED_OBJECT"
SEED_TOTALS = ("counts", "outcomes", "key_ids")  # dataset-wide, all markets


def _bind(sql: str, markets: list[str]) -> TextClause:
    return text(sql).bindparams(bindparam("scope_markets", value=markets))


def visible(markets: list[str]) -> TextClause:
    """WHERE fragment: the event belongs in the caller's operational audit view."""
    return _bind(
        f"NOT ((audit_event.action <> '{DENIED_OBJECT}' AND {_OUT_OF_SCOPE_ENTITY}) OR {_OUT_OF_SCOPE_PAYLOAD})",
        markets,
    )


def redacted_ids(db: Session, event_ids: list[uuid.UUID], markets: list[str]) -> set[uuid.UUID]:
    """Of these events, the access-denied ones on an out-of-scope record (listed with the record ID withheld)."""
    if not event_ids:
        return set()
    sql = (
        f"SELECT audit_event.id FROM audit_event WHERE audit_event.id = ANY(:ids) "  # noqa: S608 — constants only
        f"AND audit_event.action = '{DENIED_OBJECT}' AND {_OUT_OF_SCOPE_ENTITY}"
    )
    return set(db.execute(text(sql), {"ids": event_ids, "scope_markets": markets}).scalars())
