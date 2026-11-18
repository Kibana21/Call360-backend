"""S2-D.1 conversation lifecycle and control gates (pure controller, SUR-009): opening → identity → disclosure →
consent → verification → closing; identity success / failure / inconclusive / wrong person; declining to proceed;
recording consent and cloud-processing authorisation handled independently; callback requested; undelivered mandatory
disclosure; refused mandatory question; interruption; normal closing; identity-gate bypass attempts; deterministic
replay. All identity and consent outcomes are simulated; nothing is evaluated for compliance."""

from __future__ import annotations

from typing import Any

import pytest

from app.domain import question_controller as qc


def item(
    code: str, atype: str, pos: int, role: str = "VERIFICATION", mandatory: bool = True, **kw: Any
) -> dict[str, Any]:
    return {
        "question_code": code,
        "revision": 1,
        "position": pos,
        "customer_wording": f"[Synthetic] {code}",
        "answer_type": atype,
        "mandatory": mandatory,
        "delivery_mode": kw.pop("delivery_mode", "CONVERSATIONAL"),
        "max_reprompts": kw.pop("max_reprompts", 1),
        "lifecycle_role": role,
        **kw,
    }


def sec(code: str, kind: str, pos: int, *items: dict[str, Any]) -> dict[str, Any]:
    return {
        "module_code": code,
        "module_name": code,
        "module_kind": kind,
        "position": pos,
        "inclusion_condition": None,
        "questions": list(items),
    }


CONTENT = {
    "sections": [
        # Placed first on purpose: the system stage order still asks it after identity (it discloses policy data).
        sec(
            "CORE",
            "COMMON",
            1,
            item("Q-POLICY-SUMMARY", "ACKNOWLEDGEMENT", 1, discloses_policy_information=True),
            item("Q-TERM", "NUMERIC", 2),
        ),
        sec("OPEN", "OPENING", 2, item("Q-OPEN", "ACKNOWLEDGEMENT", 1, "OPENING_STATEMENT")),
        sec(
            "ID",
            "IDENTITY",
            3,
            item("Q-ID-NAME", "YES_NO", 1, "IDENTITY_CHECK"),
            item("Q-ID-DOB", "YES_NO", 2, "IDENTITY_CHECK"),
        ),
        sec(
            "DISC",
            "DISCLOSURE",
            4,
            item("Q-DISC", "ACKNOWLEDGEMENT", 1, "DISCLOSURE", delivery_mode="CONTROLLED_TTS", on_failure="TERMINATE"),
        ),
        sec(
            "CONSENT",
            "CONSENT",
            5,
            item("Q-PROCEED", "YES_NO", 1, "CONSENT_TO_PROCEED"),
            item("Q-REC", "YES_NO", 2, "RECORDING_CONSENT", on_failure="CONTINUE_WITHOUT_RECORDING"),
            item(
                "Q-CLOUD",
                "YES_NO",
                3,
                "CLOUD_PROCESSING_CONSENT",
                mandatory=False,
                on_failure="CONTINUE_WITHOUT_CLOUD_PROCESSING",
            ),
        ),
        sec(
            "CLOSE",
            "CLOSING",
            6,
            item("Q-CLOSE", "ACKNOWLEDGEMENT", 1, "CLOSING_STATEMENT", deliver_on_termination=True),
        ),
    ]
}


def plan(content: dict[str, Any] = CONTENT) -> qc.Plan:
    return qc.build_plan(content, script_label="LIFECYCLE v1", manifest_sha256="b" * 64, facts={}, band="LOW")


def started() -> qc.Controller:
    c = qc.Controller(plan())
    c.start()
    return c


def cur(c: qc.Controller) -> qc.Action:
    return c.next_action()


def deliver(c: qc.Controller, delivered: bool = True) -> None:
    c.record_delivery(cur(c).action_id or "", delivered)


def say(c: qc.Controller, value: Any = None, kind: str = "ANSWER") -> None:
    a = cur(c)
    if not a.presented:
        c.record_delivery(a.action_id or "", True)
    if not a.completes_on_delivery:  # a statement completes when delivered
        c.submit_answer(a.action_id or "", kind, value)


def through_identity(c: qc.Controller) -> None:
    deliver(c)  # opening statement completes on delivery
    say(c, True)
    say(c, True)


def requested(c: qc.Controller) -> set[str]:
    return {e.question_code for e in c.events if e.type == "QUESTION_REQUESTED" and e.question_code}


def test_full_conversation_from_opening_to_normal_closing() -> None:
    c = started()
    assert [x.code for x in c.plan.questions] == [
        "Q-OPEN",
        "Q-ID-NAME",
        "Q-ID-DOB",
        "Q-DISC",
        "Q-PROCEED",
        "Q-REC",
        "Q-CLOUD",
        "Q-POLICY-SUMMARY",
        "Q-TERM",
        "Q-CLOSE",
    ]
    a = cur(c)
    assert (a.stage, a.role, a.completes_on_delivery) == ("OPENING", "OPENING_STATEMENT", True)
    c.record_delivery(a.action_id or "", True)  # a statement completes when delivered
    assert c.q["Q-OPEN"].status == "COMPLETED"
    with pytest.raises(qc.ControllerError) as e:
        c.submit_answer(a.action_id or "", "ANSWER", True)
    assert e.value.code == "ACTION_ALREADY_RESOLVED"  # no answer to a statement
    say(c, True)
    assert c.gates["identity"] == "PENDING"  # one identity check is not enough
    say(c, True)
    assert c.gates["identity"] == "CONFIRMED" and cur(c).stage == "DISCLOSURE"
    deliver(c)
    say(c, True)  # proceed
    say(c, True)  # recording
    say(c, True)  # cloud processing
    assert c.gates == {
        "identity": "CONFIRMED",
        "willingness": "AGREED",
        "recording_consent": "GRANTED",
        "cloud_processing": "GRANTED",
    }
    say(c, True)  # policy summary (acknowledged)
    say(c, 12)
    assert cur(c).stage == "CLOSING"
    deliver(c)
    assert c.finished and c.end(abandon=False)[-1].data["outcome"] == "COMPLETED"
    life = c.lifecycle()
    assert life["disclosures_delivered"] == ["Q-DISC"] and life["termination"] is None
    assert life["simulated"] and life["compliance_outcome"] == "NOT_EVALUATED"


@pytest.mark.parametrize(("answers", "status"), [([False], "FAILED"), ([None, None], "INCONCLUSIVE")])
def test_identity_failure_or_inconclusive_terminates_without_policy_disclosure(answers: list[Any], status: str) -> None:
    c = started()
    deliver(c)
    for v in answers:
        say(c, v, "ANSWER" if v is not None else "UNCLEAR")
    assert c.gates["identity"] == status and c.terminated and c.terminated["reason"] == f"IDENTITY_{status}"
    assert "Q-POLICY-SUMMARY" not in requested(c) and "Q-DISC" not in requested(c)
    a = cur(c)
    assert a.question_code == "Q-CLOSE" and a.stage == "CLOSING"  # closing statement marked for termination
    deliver(c)
    assert c.end(abandon=False)[-1].data["outcome"] == "TERMINATED"


def test_wrong_person_callback_and_interruption_events() -> None:
    c = started()
    deliver(c)
    c.report("WRONG_PERSON")
    assert c.gates["identity"] == "WRONG_PERSON" and c.terminated and c.terminated["reason"] == "WRONG_PERSON"
    assert "Q-POLICY-SUMMARY" not in requested(c) and cur(c).question_code == "Q-CLOSE"
    with pytest.raises(qc.ControllerError) as e:
        c.report("CALLBACK_REQUESTED")
    assert e.value.code == "ALREADY_TERMINATED"
    later = started()
    through_identity(later)
    later.report("CALLBACK_REQUESTED")
    assert later.gates["willingness"] == "CALLBACK_REQUESTED" and later.terminated
    assert later.terminated["reason"] == "CALLBACK_REQUESTED"
    cut = started()
    through_identity(cut)
    cut.report("INTERRUPTED")
    assert cut.next_action().kind == "SEQUENCE_FINISHED"  # no closing statement after an interruption
    assert cut.end(abandon=False)[-1].data["outcome"] == "TERMINATED"


def test_declining_to_proceed_and_recording_and_cloud_consent_are_independent() -> None:
    c = started()
    through_identity(c)
    deliver(c)
    say(c, False)  # does not want to proceed
    assert c.gates["willingness"] == "DECLINED" and c.terminated and c.terminated["reason"] == "DECLINED_TO_PROCEED"
    assert c.gates["recording_consent"] == "NOT_ASKED" and "Q-TERM" not in requested(c)
    r = started()
    through_identity(r)
    deliver(r)
    say(r, True)  # proceed
    say(r, False)  # declines recording: continues without recording
    say(r, False)  # declines cloud processing: continues without it
    assert r.terminated is None and r.gates["willingness"] == "AGREED"
    assert (r.gates["recording_consent"], r.gates["cloud_processing"]) == ("DECLINED", "DECLINED")
    assert r.flags == ["CONTINUE_WITHOUT_RECORDING", "CONTINUE_WITHOUT_CLOUD_PROCESSING"]
    say(r, True)
    say(r, 10)
    deliver(r)
    assert r.end(abandon=False)[-1].data["outcome"] == "COMPLETED"


def test_undelivered_mandatory_disclosure_and_refused_mandatory_question() -> None:
    c = started()
    through_identity(c)
    deliver(c, False)
    assert c.terminated is None and cur(c).kind == "REPROMPT"  # one approved re-attempt
    deliver(c, False)
    assert c.terminated and c.terminated["reason"] == "MANDATORY_DISCLOSURE_NOT_DELIVERED"
    assert c.lifecycle()["disclosures_undelivered"] == ["Q-DISC"]
    r = started()
    through_identity(r)
    deliver(r)
    for v in (True, True, True, True):
        say(r, v)
    say(r, None, "REFUSED")  # mandatory verification question refused: recorded, conversation continues
    assert r.terminated is None and cur(r).stage == "CLOSING"
    deliver(r)
    out = r.end(abandon=False)[-1].data
    assert out["outcome"] == "INCOMPLETE" and out["summary"]["mandatory_unresolved"] == ["Q-TERM"]
    assert out["lifecycle"]["gates"]["identity"] == "CONFIRMED"  # identity is reported separately from completion


def test_identity_gate_cannot_be_bypassed() -> None:
    c = started()
    with pytest.raises(qc.ControllerError) as e:
        c.record_delivery("Q-POLICY-SUMMARY#1", True)  # jumping ahead to a policy-disclosing item
    assert e.value.code == "STALE_ACTION"
    with pytest.raises(qc.ControllerError) as e:
        c.skip(cur(c).action_id or "")
    assert e.value.code == "MANDATORY_NOT_SKIPPABLE"
    no_identity = {"sections": [s for s in CONTENT["sections"] if s["module_kind"] != "IDENTITY"]}
    n = qc.Controller(plan(no_identity))
    n.start()
    assert n.gates["identity"] == "NOT_CONFIGURED"
    while n.next_action().kind in ("ASK", "REPROMPT"):
        say(n, 5 if n.next_action().answer_type == "NUMERIC" else True)
    assert n.q["Q-POLICY-SUMMARY"].reason == "BLOCKED_BY_IDENTITY_GATE"
    assert "Q-POLICY-SUMMARY" not in requested(n)
    assert n.end(abandon=False)[-1].data["outcome"] == "INCOMPLETE"


def test_terminated_runs_replay_deterministically() -> None:
    c = started()
    deliver(c)
    say(c, True)
    say(c, None, "UNCLEAR")
    c.report("DECLINED_TO_CONTINUE")
    deliver(c)
    c.end(abandon=False)
    replay = qc.Controller(c.plan, [qc.Event.from_dict(e.as_dict()) for e in c.events])
    assert replay.state() == c.state() and replay.lifecycle() == c.lifecycle() and replay.ended == "TERMINATED"
