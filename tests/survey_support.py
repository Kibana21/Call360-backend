"""Helpers for the SS-03A persistence and API tests: put a golden fixture into a survey draft through the service's own
operations. Synthetic content only; isolated test database only."""

from __future__ import annotations

import copy
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.audit.chain import Actor
from app.domain.survey import store
from app.domain.survey.documents import Bundle
from tests.support import Account
from tests.survey_fixtures import load_all, to_bundle

MARKETS = ["SG"]


def actor_of(account: Account) -> Actor:
    return Actor(principal_id=account.principal_id, display_name="Test", username=account.username)


def fixture_bundle(prefix: str) -> Bundle:
    return to_bundle(next(f for f in load_all() if f["fixture"].startswith(prefix)))


def new_code(prefix: str = "S") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10].upper()}"


def namespaced(bundle: Bundle, sfx: str) -> Bundle:
    """The same bundle with every asset code given a suffix, consistently. A draft asset belongs to ONE survey until
    it is frozen, so each test survey gets its own codes."""

    def ref(r: Any) -> Any:
        return {**r, "code": r["code"] + sfx} if isinstance(r, dict) and "code" in r else r

    def binding(b: Any) -> Any:
        return {**b, "condition": ref(b["condition"])} if isinstance(b, dict) and b.get("condition") else b

    option_sets = [{**d, "code": d["code"] + sfx} for d in bundle.option_sets.values()]
    items = [
        {**d, "code": d["code"] + sfx, **({"option_set": ref(d["option_set"])} if "option_set" in d else {})}
        for d in bundle.items.values()
    ]
    wordings = [{**d, "item": d["item"] + sfx} for d in bundle.wordings.values()]
    conditions = [
        {
            **d,
            "code": d["code"] + sfx,
            "inputs": {
                k: {**v, **({"item": ref(v["item"])} if "item" in v else {})}
                for k, v in (d.get("inputs") or {}).items()
            },
        }
        for d in bundle.conditions.values()
    ]
    modules = []
    for m in bundle.modules.values():
        nodes = [
            {**n, "binding": binding(n.get("binding"))} if n["type"] == "DECISION" else {**n, "item": ref(n["item"])}
            for n in m["nodes"]
        ]
        modules.append({**m, "code": m["code"] + sfx, "nodes": nodes})
    sequence = [
        {**i, "module": ref(i["module"]), **({"eligibility": binding(i["eligibility"])} if "eligibility" in i else {})}
        for i in bundle.survey["sequence"]
    ]
    return Bundle.build(
        fields=bundle.fields, outcomes=bundle.outcomes, option_sets=option_sets, items=items, wordings=wordings,
        conditions=conditions, modules=modules, survey={**bundle.survey, "sequence": sequence},
    )  # fmt: skip


def operations_for(bundle: Bundle, survey_code: str) -> list[dict[str, Any]]:
    """The operations that put a bundle into a draft: every asset, then the content naming THIS survey."""
    ops: list[dict[str, Any]] = []
    for kind, docs in (
        ("OPTION_SET", bundle.option_sets),
        ("ITEM", bundle.items),
        ("WORDING", bundle.wordings),
        ("CONDITION", bundle.conditions),
        ("MODULE", bundle.modules),
    ):
        ops.extend({"op": "PUT_ASSET", "kind": kind, "document": copy.deepcopy(dict(d))} for d in docs.values())
    ops.append({"op": "SET_CONTENT", "content": {**copy.deepcopy(dict(bundle.survey)), "code": survey_code}})
    return ops


def build_draft(db: Session, author: Account, prefix: str = "K1") -> tuple[uuid.UUID, str]:
    """A survey whose draft holds the given golden fixture, built with the service's operations. Committed. Returns the
    survey id and the suffix its asset codes carry."""
    code = new_code()
    sfx = "-" + code[2:]
    actor = actor_of(author)
    sid = store.create_survey(db, code=code, name=f"Test {code}", purpose="synthetic test", market="SG", actor=actor)
    for op in operations_for(namespaced(fixture_bundle(prefix), sfx), code):
        store.apply_operation(db, sid, MARKETS, store.draft(db, sid)["revision"], op, actor)
    db.commit()
    return sid, sfx


ACK_REASON = "Synthetic test content; acknowledged for this test."


def acks_for(db: Session, sid: uuid.UUID) -> list[dict[str, Any]]:
    """An acknowledgement, with a reason, for every server-governed warning of the survey's current draft (FI-2)."""
    content = store.draft(db, sid)["content"]
    return [
        {"code": f["code"], "at": f["at"], "reason": ACK_REASON}
        for f in store.findings_of(db, content)
        if f["severity"] == "WARNING"
    ]
