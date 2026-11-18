"""S2-D deterministic question controller (pure): progression, approved conditions, mandatory handling, answer types,
unclear / refused / unknown answers, clarification and retry limits, bypass attempts, duplicates, invalid transitions,
completion and deterministic replay."""

from __future__ import annotations

from typing import Any

import pytest

from app.domain import question_controller as qc


def q(code: str, atype: str, mandatory: bool, pos: int, **kw: Any) -> dict[str, Any]:
    return {
        "question_code": code,
        "question_revision_id": f"rev-{code}",
        "revision": 1,
        "position": pos,
        "customer_wording": f"Wording of {code}?",
        "answer_type": atype,
        "mandatory": mandatory,
        "delivery_mode": kw.pop("delivery_mode", "CONVERSATIONAL"),
        "max_reprompts": kw.pop("max_reprompts", 1),
        "answer_schema": {"enum": kw.pop("options")} if "options" in kw else {"type": atype.lower()},
        **kw,
    }


CONTENT = {
    "sections": [
        {
            "module_code": "CORE",
            "module_name": "Core",
            "module_kind": "COMMON",
            "position": 1,
            "inclusion_condition": None,
            "questions": [
                q("Q-A", "YES_NO", True, 1),
                q("Q-B", "NUMERIC", True, 2, max_reprompts=0),
                q("Q-C", "ENUM", False, 3, options=["MONTHLY", "ANNUAL"]),
                q("Q-D", "ACKNOWLEDGEMENT", True, 4, delivery_mode="CONTROLLED_TTS"),
                q("Q-E", "FREE_TEXT", False, 5, branch_condition={"fact": "is_ilp", "equals": True}),
            ],
        },
        {
            "module_code": "ILP",
            "module_name": "ILP",
            "module_kind": "PRODUCT",
            "position": 2,
            "inclusion_condition": {"fact": "is_ilp", "equals": True},
            "questions": [q("Q-F", "YES_NO", True, 1)],
        },
        {
            "module_code": "HIGH",
            "module_name": "Elevated",
            "module_kind": "RISK",
            "position": 3,
            "inclusion_condition": {"risk_band_in": ["HIGH"]},
            "questions": [
                q("Q-G", "YES_NO", True, 1, not_applicable_predicate={"fact": "selling_channel", "equals": "BROKER"})
            ],
        },
    ]
}


def plan(is_ilp: bool = False, band: str | None = "LOW", channel: str = "AGENCY") -> qc.Plan:
    return qc.build_plan(
        CONTENT,
        script_label="TEST v1",
        manifest_sha256="a" * 64,
        facts={"is_ilp": is_ilp, "selling_channel": channel},
        band=band,
    )


def ask(c: qc.Controller) -> qc.Action:
    a = c.next_action()
    assert a.kind in ("ASK", "REPROMPT") and a.action_id
    if not a.presented:
        c.record_delivery(a.action_id, True)
    return c.next_action()


def answer(c: qc.Controller, value: Any, kind: str = "ANSWER") -> list[qc.Event]:
    a = ask(c)
    assert a.action_id is not None
    return c.submit_answer(a.action_id, kind, value)


def test_applicability_comes_only_from_approved_conditions() -> None:
    p = plan()
    by = {x.code: x for x in p.questions}
    assert [x.code for x in p.questions] == ["Q-A", "Q-B", "Q-C", "Q-D", "Q-E", "Q-F", "Q-G"]  # fixed order
    assert by["Q-E"].applicable is False and "Asked only when is ilp is yes" in (by["Q-E"].skip_reason or "")
    assert by["Q-F"].applicable is False and "Section ILP not included" in (by["Q-F"].skip_reason or "")
    assert by["Q-G"].applicable is False  # LOW band: elevated-risk section excluded
    ilp_high = {x.code: x for x in plan(is_ilp=True, band="HIGH").questions}
    assert ilp_high["Q-E"].applicable and ilp_high["Q-F"].applicable and ilp_high["Q-G"].applicable
    broker = {x.code: x for x in plan(is_ilp=True, band="HIGH", channel="BROKER").questions}
    assert broker["Q-G"].applicable is False and "Not applicable when" in (broker["Q-G"].skip_reason or "")
    assert not plan(band=None).questions[-1].applicable  # unassessed band does not include a HIGH-only section


def test_normal_progression_types_and_completion() -> None:
    c = qc.Controller(plan())
    c.start()
    st = c.state()
    skipped = {x["code"]: x["reason"] for x in st["questions"] if x["status"] == "SKIPPED_BY_CONDITION"}
    assert set(skipped) == {"Q-E", "Q-F", "Q-G"} and all(skipped.values())  # skipped explicitly, with reasons
    first = c.next_action()
    assert (first.kind, first.question_code, first.action_id, first.presented) == ("ASK", "Q-A", "Q-A#1", False)
    with pytest.raises(qc.ControllerError, match="not presented") as e:
        c.submit_answer("Q-A#1", "ANSWER", True)  # a request is not delivery
    assert e.value.code == "NOT_PRESENTED"
    c.record_delivery("Q-A#1", False)  # not delivered: still requested
    assert c.next_action().presented is False and c.q["Q-A"].not_delivered == 1
    answer(c, True)
    for bad in ("twelve", True, float("nan")):
        a = ask(c)
        with pytest.raises(qc.ControllerError) as e:
            c.submit_answer(a.action_id or "", "ANSWER", bad)
        assert e.value.code == "INVALID_ANSWER" and e.value.status == 422
    c.submit_answer("Q-B#1", "ANSWER", "12")  # numeric text is accepted as a number
    assert c.q["Q-B"].answer and c.q["Q-B"].answer["value"] == 12.0
    a = ask(c)
    with pytest.raises(qc.ControllerError):
        c.submit_answer(a.action_id or "", "ANSWER", "WEEKLY")  # not an approved option
    c.submit_answer(a.action_id or "", "ANSWER", "ANNUAL")
    d = ask(c)
    assert d.statement and d.verbatim_required and d.question_code == "Q-D"
    c.submit_answer(d.action_id or "", "ANSWER", True)
    assert c.next_action().kind == "SEQUENCE_FINISHED" and c.finished
    out = c.end(abandon=False)
    assert out[-1].data["outcome"] == "COMPLETED" and c.state()["status"] == "COMPLETED"
    assert c.summary()["mandatory_completed"] == ["Q-A", "Q-B", "Q-D"]
    assert c.summary()["mandatory_skipped_by_condition"] == ["Q-F", "Q-G"]


def test_unclear_clarification_retry_limits_refusal_and_unknown() -> None:
    c = qc.Controller(plan(is_ilp=True, band="HIGH"))
    c.start()
    answer(c, None, "UNCLEAR")  # Q-A allows one re-prompt
    a = c.next_action()
    assert (a.kind, a.action_id, a.reprompts_used, a.reprompts_allowed) == ("REPROMPT", "Q-A#2", 1, 1)
    c.record_delivery("Q-A#2", True)
    c.request_clarification("Q-A#2", "Customer asked what the question means")
    assert c.q["Q-A"].status == "UNRESOLVED" and c.q["Q-A"].reason == "RETRY_LIMIT"
    answer(c, None, "UNCLEAR")  # Q-B allows no re-prompt
    assert c.q["Q-B"].status == "UNRESOLVED"
    answer(c, None, "REFUSED")  # optional Q-C refused
    assert (c.q["Q-C"].status, c.q["Q-C"].reason) == ("UNRESOLVED", "REFUSED")
    answer(c, None, "UNKNOWN")  # mandatory Q-D: customer does not know
    assert c.q["Q-D"].reason == "UNKNOWN"
    answer(c, "Explained the fund risks (synthetic)")
    answer(c, True)
    answer(c, False)
    c.end(abandon=False)
    s = c.summary()
    assert c.ended == "INCOMPLETE" and s["mandatory_unresolved"] == ["Q-A", "Q-B", "Q-D"]


def test_bypass_duplicates_stale_actions_and_invalid_transitions() -> None:
    c = qc.Controller(plan())
    with pytest.raises(qc.ControllerError, match="has not started"):
        c.record_delivery("Q-A#1", True)
    c.start()
    with pytest.raises(qc.ControllerError) as e:
        c.start()
    assert e.value.code == "ALREADY_STARTED"
    with pytest.raises(qc.ControllerError) as e:
        c.skip("Q-A#1")
    assert e.value.code == "MANDATORY_NOT_SKIPPABLE"
    with pytest.raises(qc.ControllerError) as e:
        c.record_delivery("Q-B#1", True)  # answering out of order
    assert e.value.code == "STALE_ACTION"
    c.record_delivery("Q-A#1", True)
    with pytest.raises(qc.ControllerError) as e:
        c.record_delivery("Q-A#1", True)
    assert e.value.code == "ALREADY_PRESENTED"
    first = c.submit_answer("Q-A#1", "ANSWER", True)
    assert first and c.submit_answer("Q-A#1", "ANSWER", True) == []  # duplicate submission: nothing new
    with pytest.raises(qc.ControllerError) as e:
        c.submit_answer("Q-A#1", "ANSWER", False)  # a different answer to a resolved action
    assert e.value.code == "ACTION_ALREADY_RESOLVED"
    c.record_delivery("Q-B#1", True)
    c.submit_answer("Q-B#1", "ANSWER", 10)
    a = ask(c)
    with pytest.raises(qc.ControllerError) as e:
        c.skip(a.action_id or "")
    assert e.value.code == "SKIP_NOT_APPROVED"  # optional questions are not skippable either
    early = c.end(abandon=False)  # ending early is never "completed"
    assert early[-1].data["outcome"] == "INCOMPLETE" and "Q-D" in early[-1].data["summary"]["mandatory_open"]
    with pytest.raises(qc.ControllerError) as e:
        c.submit_answer(a.action_id or "", "ANSWER", "ANNUAL")
    assert e.value.code in ("ALREADY_ENDED", "STALE_ACTION")
    abandoned = qc.Controller(plan())
    abandoned.start()
    assert abandoned.end(abandon=True, reason="test")[-1].data["outcome"] == "ABANDONED"


def test_state_is_the_deterministic_replay_of_events() -> None:
    c = qc.Controller(plan(is_ilp=True, band="HIGH"))
    c.start()
    answer(c, True)
    answer(c, None, "UNCLEAR")
    answer(c, "MONTHLY")
    replayed = qc.Controller(c.plan, [qc.Event.from_dict(e.as_dict()) for e in c.events])
    assert replayed.state() == c.state() and replayed.next_action() == c.next_action()
    again = qc.Controller(plan(is_ilp=True, band="HIGH"))
    again.start()
    answer(again, True)
    answer(again, None, "UNCLEAR")
    answer(again, "MONTHLY")
    assert [e.as_dict() for e in again.events] == [e.as_dict() for e in c.events]  # same inputs, same events
