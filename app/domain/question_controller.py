"""S2-D / S2-D.1 deterministic question controller (SUR-008, SUR-009, VOICE-011; provider-independent).

Pure and event-sourced: no database, clock, randomness or LLM. A ``Plan`` is built from a pinned, published script
version's frozen content plus the pinned policy fact snapshot and SBQ band; the controller then only appends events, and
the state is always the replay of those events. The same interface serves the text simulator now and a real-time voice
provider later — the provider reports delivery, answers and conversation events; it never chooses the next item.

Only approved configuration and the documented S2-D.1 synthetic assumptions (``app.domain.lifecycle``) are used:

- **Lifecycle** (S2-D.1): every item has a stage and a role. Stages always run OPENING → IDENTITY → DISCLOSURE →
  CONSENT → VERIFICATION → CLOSING, whatever the section positions. Statement roles (opening, disclosure, closing)
  complete when delivered. Identity and consent roles are yes/no gates: identity is confirmed only when every identity
  check is answered yes (simulated — no real identity verification); a failure terminates. Willingness to proceed,
  recording consent and cloud-processing authorisation are separate gates. Items that disclose policy information are
  never requested before the identity gate is confirmed. Failure behaviour follows the item's configured ``on_failure``
  within the system-enforced policies. Conversation events (wrong person, callback requested, declined to continue,
  interrupted) terminate the conversation. After termination only closing statements marked for termination are
  offered (none after an interruption).
- **Applicability**: a section's inclusion condition, a question's asked-when and not-applicable conditions, in the
  approved S0 predicate language over the policy facts and SBQ band, evaluated once at start. Excluded items are
  ``SKIPPED_BY_CONDITION`` with the reason; nothing else can skip an item (``SKIP_NOT_APPROVED``).
- **Retries**: the item's approved ``max_reprompts`` (unclear answers, clarification requests and undelivered items).
- **Answer types**: YES_NO and ACKNOWLEDGEMENT (yes / no), NUMERIC, ENUM (approved options), FREE_TEXT; non-answers
  UNCLEAR (re-prompt), REFUSED and UNKNOWN (unresolved).

Item states: PENDING → REQUESTED → PRESENTED → (ANSWER_RECEIVED) → COMPLETED | CLARIFICATION_REQUIRED → REQUESTED …
| UNRESOLVED | SKIPPED_BY_CONDITION. A request is not delivery. The controller records completeness and gate states
only: it never evaluates expected answers, compliance or real identity, and mandatory completion is reported separately
from the identity and consent gates.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from app.domain import lifecycle as lc
from app.domain.outcomes import condition_holds

ANSWER_TYPES = ("YES_NO", "NUMERIC", "ENUM", "FREE_TEXT", "ACKNOWLEDGEMENT")
NON_ANSWERS = ("UNCLEAR", "REFUSED", "UNKNOWN")
TERMINAL = ("COMPLETED", "UNRESOLVED", "SKIPPED_BY_CONDITION")
ENGINE = "call360.question-controller/2 (S2-D.1 lifecycle)"


class ControllerError(Exception):
    def __init__(self, code: str, message: str, status: int = 409) -> None:
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


# ---- plan -------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class PlannedQuestion:
    code: str
    revision_id: str
    revision: int
    section: str
    section_name: str
    position: int  # global delivery order (stage order, then section and question position)
    wording: str
    answer_type: str
    options: tuple[str, ...]
    mandatory: bool
    delivery_mode: str
    max_reprompts: int
    applicable: bool
    skip_reason: str | None
    role: str = "VERIFICATION"
    stage: str = "VERIFICATION"
    on_failure: str = "CONTINUE"
    discloses_policy_information: bool = False
    deliver_on_termination: bool = False

    @property
    def verbatim_required(self) -> bool:
        return self.delivery_mode in ("EXACT_AUDIO", "CONTROLLED_TTS")

    @property
    def completes_on_delivery(self) -> bool:
        return self.role in lc.STATEMENT_ROLES


@dataclass(frozen=True)
class PlannedSection:
    module_code: str
    name: str
    kind: str
    position: int
    included: bool
    condition: str
    stage: str = "VERIFICATION"


@dataclass(frozen=True)
class Plan:
    script_label: str
    manifest_sha256: str
    sections: tuple[PlannedSection, ...]
    questions: tuple[PlannedQuestion, ...]

    def question(self, code: str) -> PlannedQuestion:
        for q in self.questions:
            if q.code == code:
                return q
        raise ControllerError("UNKNOWN_QUESTION", f"{code} is not in this script", 404)

    @property
    def identity_configured(self) -> bool:
        return any(q.role == "IDENTITY_CHECK" and q.applicable for q in self.questions)


def describe(cond: Any) -> str:
    if cond is None:
        return "always"
    if "all" in cond:
        return " and ".join(describe(c) for c in cond["all"])
    if "risk_band_in" in cond:
        return f"SBQ band is {' or '.join(cond['risk_band_in'])}"
    if "fact" in cond:
        v = cond.get("equals")
        return f"{cond['fact'].replace('_', ' ')} is {'yes' if v is True else 'no' if v is False else v}"
    return str(cond)


def build_plan(
    content: Mapping[str, Any], *, script_label: str, manifest_sha256: str, facts: Mapping[str, Any], band: str | None
) -> Plan:
    """Applicability from approved conditions only; order = system stage order, then section and question position."""
    sections: list[PlannedSection] = []
    rows: list[tuple[tuple[int, int, int], dict[str, Any]]] = []
    for sec in sorted(content.get("sections", []), key=lambda s: s["position"]):
        cond = sec.get("inclusion_condition")
        included = condition_holds(cond, dict(facts), band)
        kind = sec.get("module_kind") or ""
        sstage = lc.KIND_STAGE.get(kind, "VERIFICATION")
        sections.append(
            PlannedSection(
                sec["module_code"],
                sec.get("module_name") or sec["module_code"],
                kind,
                sec["position"],
                included,
                describe(cond),
                sstage,
            )
        )
        for q in sorted(sec["questions"], key=lambda x: x["position"]):
            role = q.get("lifecycle_role") or "VERIFICATION"
            stage = lc.ROLE_STAGE.get(role, sstage)
            reason = None
            if not included:
                reason = f"Section {sec['module_code']} not included ({describe(cond)} does not hold)"
            elif q.get("branch_condition") is not None and not condition_holds(
                q["branch_condition"], dict(facts), band
            ):
                reason = f"Asked only when {describe(q['branch_condition'])}; that does not hold"
            elif q.get("not_applicable_predicate") is not None and condition_holds(
                q["not_applicable_predicate"], dict(facts), band
            ):
                reason = f"Not applicable when {describe(q['not_applicable_predicate'])}; that holds"
            rows.append(
                (
                    (lc.STAGE_ORDER[stage], sec["position"], q["position"]),
                    {"q": q, "sec": sec, "role": role, "stage": stage, "reason": reason},
                )
            )
    questions: list[PlannedQuestion] = []
    for pos, (_, r) in enumerate(sorted(rows, key=lambda x: x[0]), start=1):
        q, sec, role = r["q"], r["sec"], r["role"]
        schema = q.get("answer_schema") or {}
        questions.append(
            PlannedQuestion(
                code=q["question_code"],
                revision_id=str(q.get("question_revision_id") or q.get("id") or ""),
                revision=int(q.get("revision") or 1),
                section=sec["module_code"],
                section_name=sec.get("module_name") or sec["module_code"],
                position=pos,
                wording=q.get("customer_wording") or q.get("wording") or "",
                answer_type=q["answer_type"] if q["answer_type"] in ANSWER_TYPES else "FREE_TEXT",
                options=tuple(schema.get("enum") or ()),
                mandatory=bool(q["mandatory"]),
                delivery_mode=q.get("delivery_mode") or "CONVERSATIONAL",
                max_reprompts=int(q.get("max_reprompts") if q.get("max_reprompts") is not None else 1),
                applicable=r["reason"] is None,
                skip_reason=r["reason"],
                role=role,
                stage=r["stage"],
                on_failure=q.get("on_failure") or lc.DEFAULT_ON_FAILURE.get(role, "CONTINUE"),
                discloses_policy_information=bool(q.get("discloses_policy_information")),
                deliver_on_termination=bool(q.get("deliver_on_termination")),
            )
        )
    return Plan(script_label, manifest_sha256, tuple(sections), tuple(questions))


# ---- events and state -------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Event:
    type: str  # STARTED | QUESTION_SKIPPED | QUESTION_REQUESTED | DELIVERY_RECORDED | ANSWER_RECEIVED |
    #            CLARIFICATION_REQUIRED | QUESTION_COMPLETED | QUESTION_UNRESOLVED | GATE_UPDATED |
    #            CONVERSATION_EVENT | TERMINATED | SEQUENCE_FINISHED | ENDED
    question_code: str | None = None
    action_id: str | None = None
    data: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "question_code": self.question_code,
            "action_id": self.action_id,
            "data": dict(self.data),
        }

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> Event:
        return Event(d["type"], d.get("question_code"), d.get("action_id"), d.get("data") or {})


@dataclass
class QuestionState:
    code: str
    status: str = "PENDING"
    requests: int = 0  # times requested (first ask + re-prompts)
    reprompts: int = 0
    presented: int = 0
    not_delivered: int = 0
    answer: dict[str, Any] | None = None
    reason: str | None = None


@dataclass
class Action:
    kind: Literal["ASK", "REPROMPT", "SEQUENCE_FINISHED", "ENDED", "NOT_STARTED"]
    action_id: str | None
    question_code: str | None
    wording: str | None
    answer_type: str | None
    options: list[str]
    mandatory: bool | None
    verbatim_required: bool | None
    presented: bool
    reprompts_used: int
    reprompts_allowed: int
    statement: bool  # an acknowledgement item (a statement the customer acknowledges)
    note: str
    stage: str | None = None
    role: str | None = None
    completes_on_delivery: bool = False


GATE_FOR_ROLE = {
    "IDENTITY_CHECK": "identity",
    "CONSENT_TO_PROCEED": "willingness",
    "RECORDING_CONSENT": "recording_consent",
    "CLOUD_PROCESSING_CONSENT": "cloud_processing",
}


class Controller:
    """Replays ``events`` over ``plan``. Mutating methods validate, append and return the new events."""

    def __init__(self, plan: Plan, events: Sequence[Event] = ()) -> None:
        self.plan = plan
        self.events: list[Event] = []
        self.q: dict[str, QuestionState] = {x.code: QuestionState(x.code) for x in plan.questions}
        self.started = False
        self.finished = False
        self.ended: str | None = None
        self.current: str | None = None  # question code of the open request
        self.action_id: str | None = None
        self.resolved: dict[str, dict[str, Any]] = {}  # action_id -> how it was resolved (duplicate detection)
        self.gates: dict[str, str] = {
            "identity": "PENDING" if plan.identity_configured else "NOT_CONFIGURED",
            "willingness": "NOT_ASKED",
            "recording_consent": "NOT_ASKED",
            "cloud_processing": "NOT_ASKED",
        }
        self.flags: list[str] = []  # continuations recorded under a CONTINUE_* failure policy
        self.terminated: dict[str, Any] | None = None
        for e in events:
            self._apply(e)

    # -- replay --
    def _apply(self, e: Event) -> None:
        self.events.append(e)
        t, code = e.type, e.question_code
        qs = self.q.get(code) if code else None
        if t == "STARTED":
            self.started = True
        elif t == "QUESTION_SKIPPED" and qs:
            qs.status, qs.reason = "SKIPPED_BY_CONDITION", e.data.get("reason")
        elif t == "QUESTION_REQUESTED" and qs:
            qs.status = "REQUESTED"
            qs.requests += 1
            qs.reprompts = qs.requests - 1
            self.current, self.action_id = code, e.action_id
        elif t == "DELIVERY_RECORDED" and qs:
            if e.data.get("status") == "DELIVERED":
                qs.status = "PRESENTED"
                qs.presented += 1
            else:
                qs.not_delivered += 1
        elif t == "ANSWER_RECEIVED" and qs:
            qs.status = "ANSWER_RECEIVED"
            qs.answer = dict(e.data)
            if e.action_id:
                self.resolved[e.action_id] = {"kind": "ANSWER", "code": code, **dict(e.data)}
        elif t == "CLARIFICATION_REQUIRED" and qs:
            qs.status = "CLARIFICATION_REQUIRED"
            if e.action_id and e.action_id not in self.resolved:
                self.resolved[e.action_id] = {"kind": "CLARIFICATION", "reason": e.data.get("reason")}
            self.current = self.action_id = None
        elif t == "QUESTION_COMPLETED" and qs:
            qs.status, qs.reason = "COMPLETED", None
            if e.action_id and e.action_id not in self.resolved:
                self.resolved[e.action_id] = {"kind": "DELIVERED"}
            self.current = self.action_id = None
        elif t == "QUESTION_UNRESOLVED" and qs:
            qs.status, qs.reason = "UNRESOLVED", e.data.get("reason")
            if e.action_id and e.action_id not in self.resolved:
                self.resolved[e.action_id] = {"kind": "UNRESOLVED"}
            if self.current == code:
                self.current = self.action_id = None
        elif t == "GATE_UPDATED":
            self.gates[e.data["gate"]] = e.data["status"]
            if e.data.get("flag"):
                self.flags.append(e.data["flag"])
        elif t == "FLAG_RECORDED":
            self.flags.append(e.data["flag"])
        elif t == "TERMINATED":
            self.terminated = dict(e.data)
            self.current = self.action_id = None
        elif t == "SEQUENCE_FINISHED":
            self.finished = True
        elif t == "ENDED":
            self.ended = e.data.get("outcome")
            self.current = self.action_id = None

    def _emit(self, *events: Event) -> list[Event]:
        for e in events:
            self._apply(e)
        return list(events)

    # -- helpers --
    def _require_open(self) -> None:
        if not self.started:
            raise ControllerError("NOT_STARTED", "The execution has not started")
        if self.ended:
            raise ControllerError("ALREADY_ENDED", f"The execution has ended ({self.ended})")

    def _request(self, pq: PlannedQuestion) -> list[Event]:
        n = self.q[pq.code].requests + 1
        data: dict[str, Any] = {"attempt": n, "stage": pq.stage, "role": pq.role}
        return self._emit(Event("QUESTION_REQUESTED", pq.code, f"{pq.code}#{n}", data))

    def _advance(self) -> list[Event]:
        """Request the next permitted item in order (honouring the identity gate and termination), or finish."""
        out: list[Event] = []
        for pq in self.plan.questions:
            if self.q[pq.code].status != "PENDING":
                continue
            if self.terminated is not None:
                if (
                    pq.role == "CLOSING_STATEMENT"
                    and pq.deliver_on_termination
                    and self.terminated.get("reason") != "INTERRUPTED"
                ):
                    return out + self._request(pq)
                continue
            if pq.discloses_policy_information and self.gates["identity"] != "CONFIRMED":
                out += self._emit(
                    Event(
                        "QUESTION_UNRESOLVED",
                        pq.code,
                        None,
                        {
                            "reason": "BLOCKED_BY_IDENTITY_GATE",
                            "mandatory": pq.mandatory,
                            "detail": "Discloses policy information; the identity gate is "
                            f"{self.gates['identity'].replace('_', ' ').lower()}",
                        },
                    )
                )
                continue
            return out + self._request(pq)
        return out + self._emit(Event("SEQUENCE_FINISHED", data=self.summary()))

    def _current(self, action_id: str) -> PlannedQuestion:
        self._require_open()
        if action_id in self.resolved:
            raise ControllerError("ACTION_ALREADY_RESOLVED", f"{action_id} was already resolved")
        if self.action_id is None or action_id != self.action_id:
            raise ControllerError(
                "STALE_ACTION",
                f"{action_id} is not the current action (current: {self.action_id or 'none'}); questions are "
                "answered only in the controller's order",
            )
        assert self.current is not None
        return self.plan.question(self.current)

    def _gate(self, gate: str, status: str, flag: str | None = None) -> list[Event]:
        return self._emit(Event("GATE_UPDATED", data={"gate": gate, "status": status, "flag": flag}))

    def _terminate(self, reason: str, detail: str, stage: str | None = None) -> list[Event]:
        out: list[Event] = []
        if self.current is not None:
            pq = self.plan.question(self.current)
            out += self._emit(
                Event(
                    "QUESTION_UNRESOLVED",
                    pq.code,
                    self.action_id,
                    {"reason": "CONVERSATION_TERMINATED", "mandatory": pq.mandatory},
                )
            )
        out += self._emit(
            Event("TERMINATED", data={"reason": reason, "detail": detail, "stage": stage or self.stage()})
        )
        return out + self._advance()

    def _after_item(self, pq: PlannedQuestion, ok: bool, why: str) -> list[Event]:
        """Gate effects of a finished item (``ok``: completed with a passing answer / delivered), then advance."""
        role = pq.role
        if role == "IDENTITY_CHECK":
            if ok:
                done = all(
                    self.q[x.code].status == "COMPLETED"
                    for x in self.plan.questions
                    if x.role == "IDENTITY_CHECK" and x.applicable
                )
                return (self._gate("identity", "CONFIRMED") if done else []) + self._advance()
            status = "INCONCLUSIVE" if why in ("UNKNOWN", "RETRY_LIMIT", "NOT_DELIVERED") else "FAILED"
            return self._gate("identity", status) + self._terminate(
                f"IDENTITY_{status}",
                f"Identity {status.lower()} at {pq.code} ({why.replace('_', ' ').lower()})",
                "IDENTITY",
            )
        if role == "CONSENT_TO_PROCEED":
            if ok:
                return self._gate("willingness", "AGREED") + self._advance()
            return self._gate("willingness", "DECLINED") + self._terminate(
                "DECLINED_TO_PROCEED",
                f"The customer did not agree to proceed ({why.replace('_', ' ').lower()})",
                "CONSENT",
            )
        if role in ("RECORDING_CONSENT", "CLOUD_PROCESSING_CONSENT"):
            gate = GATE_FOR_ROLE[role]
            if ok:
                return self._gate(gate, "GRANTED") + self._advance()
            if pq.on_failure == "TERMINATE":
                return self._gate(gate, "DECLINED") + self._terminate(
                    f"{gate.upper()}_DECLINED",
                    f"{gate.replace('_', ' ').capitalize()} declined; configured to terminate",
                    "CONSENT",
                )
            return self._gate(gate, "DECLINED", flag=pq.on_failure) + self._advance()
        if ok:
            return self._advance()
        if pq.on_failure == "TERMINATE":
            reason = {
                "OPENING_STATEMENT": "OPENING_NOT_DELIVERED",
                "DISCLOSURE": "MANDATORY_DISCLOSURE_NOT_DELIVERED" if pq.mandatory else "DISCLOSURE_NOT_DELIVERED",
                "VERIFICATION": "MANDATORY_QUESTION_UNRESOLVED" if pq.mandatory else "QUESTION_UNRESOLVED",
            }.get(role, "ITEM_FAILED")
            return self._terminate(reason, f"{pq.code}: {why.replace('_', ' ').lower()}; configured to terminate")
        if pq.on_failure == "CONTINUE_FLAGGED":
            return self._emit(Event("FLAG_RECORDED", pq.code, None, {"flag": f"{pq.code}:{why}"})) + self._advance()
        return self._advance()

    # -- interface --
    def start(self) -> list[Event]:
        if self.started:
            raise ControllerError("ALREADY_STARTED", "The execution has already started")
        out = self._emit(
            Event(
                "STARTED",
                data={
                    "engine": ENGINE,
                    "script": self.plan.script_label,
                    "manifest_sha256": self.plan.manifest_sha256,
                    "identity_gate": self.gates["identity"],
                },
            )
        )
        for pq in self.plan.questions:
            if not pq.applicable:
                out += self._emit(
                    Event("QUESTION_SKIPPED", pq.code, data={"reason": pq.skip_reason, "mandatory": pq.mandatory})
                )
        return out + self._advance()

    def record_delivery(self, action_id: str, delivered: bool, note: str | None = None) -> list[Event]:
        pq = self._current(action_id)
        qs = self.q[pq.code]
        if qs.status != "REQUESTED":
            raise ControllerError("ALREADY_PRESENTED", f"{pq.code} is already presented for {action_id}")
        out = self._emit(
            Event(
                "DELIVERY_RECORDED",
                pq.code,
                action_id,
                {"status": "DELIVERED" if delivered else "NOT_DELIVERED", "note": note},
            )
        )
        if delivered and pq.completes_on_delivery:
            out += self._emit(Event("QUESTION_COMPLETED", pq.code, action_id, {"completed_by": "DELIVERY"}))
            return out + self._after_item(pq, True, "DELIVERED")
        if not delivered and qs.not_delivered > pq.max_reprompts:
            out += self._emit(
                Event(
                    "QUESTION_UNRESOLVED",
                    pq.code,
                    action_id,
                    {
                        "reason": "NOT_DELIVERED",
                        "mandatory": pq.mandatory,
                        "detail": f"Not delivered after {pq.max_reprompts} approved re-attempt(s)",
                    },
                )
            )
            return out + self._after_item(pq, False, "NOT_DELIVERED")
        return out

    def _reprompt_or_unresolve(self, pq: PlannedQuestion, action_id: str, reason: str) -> list[Event]:
        qs = self.q[pq.code]
        out = self._emit(
            Event(
                "CLARIFICATION_REQUIRED",
                pq.code,
                action_id,
                {"reason": reason, "reprompts_used": qs.reprompts, "reprompts_allowed": pq.max_reprompts},
            )
        )
        if qs.reprompts < pq.max_reprompts:
            n = qs.requests + 1
            return out + self._emit(
                Event(
                    "QUESTION_REQUESTED",
                    pq.code,
                    f"{pq.code}#{n}",
                    {"attempt": n, "reprompt": True, "reason": reason, "stage": pq.stage, "role": pq.role},
                )
            )
        out += self._emit(
            Event(
                "QUESTION_UNRESOLVED",
                pq.code,
                action_id,
                {
                    "reason": "RETRY_LIMIT",
                    "detail": f"No clear answer after {pq.max_reprompts} approved re-prompt(s)",
                    "mandatory": pq.mandatory,
                },
            )
        )
        return out + self._after_item(pq, False, "RETRY_LIMIT")

    def submit_answer(self, action_id: str, kind: str, value: Any = None, verbatim: str | None = None) -> list[Event]:
        """``kind``: ANSWER (with a typed value), UNCLEAR, REFUSED or UNKNOWN. A duplicate of the answer that already
        resolved ``action_id`` returns no new events (idempotent); any other repeat is refused."""
        prior = self.resolved.get(action_id)
        if prior is not None and prior.get("kind") == "ANSWER":
            same = prior.get("answer_kind") == kind
            if same and kind == "ANSWER":
                try:
                    same = _validate(self.plan.question(prior["code"]), value) == prior.get("value")
                except ControllerError:
                    same = False
            if same:
                return []  # a duplicate submission of the same answer: nothing new happens
            raise ControllerError("ACTION_ALREADY_RESOLVED", f"{action_id} already has a different answer")
        pq = self._current(action_id)
        qs = self.q[pq.code]
        if pq.completes_on_delivery:
            raise ControllerError("STATEMENT_NOT_ANSWERED", f"{pq.code} is a statement: record its delivery")
        if qs.status != "PRESENTED":
            raise ControllerError(
                "NOT_PRESENTED",
                f"{pq.code} has been requested but not presented; record its delivery "
                "before an answer (a request is not proof of delivery)",
            )
        if kind not in ("ANSWER", *NON_ANSWERS):
            raise ControllerError("INVALID_ANSWER", f"Unknown answer kind {kind}", 422)
        typed = _validate(pq, value) if kind == "ANSWER" else None
        if verbatim is not None and len(verbatim) > 2000:
            raise ControllerError("INVALID_ANSWER", "Verbatim text is limited to 2000 characters", 422)
        data = {"answer_kind": kind, "value": typed, "answer_state": _state(pq, kind, typed), "verbatim": verbatim}
        out = self._emit(Event("ANSWER_RECEIVED", pq.code, action_id, data))
        if kind == "UNCLEAR":
            return out + self._reprompt_or_unresolve(pq, action_id, "UNCLEAR_ANSWER")
        if kind in ("REFUSED", "UNKNOWN"):
            out += self._emit(
                Event(
                    "QUESTION_UNRESOLVED",
                    pq.code,
                    action_id,
                    {
                        "reason": kind,
                        "detail": "Customer refused to answer" if kind == "REFUSED" else "Customer did not know",
                        "mandatory": pq.mandatory,
                    },
                )
            )
            return out + self._after_item(pq, False, kind)
        out += self._emit(Event("QUESTION_COMPLETED", pq.code, action_id, {"answer_state": data["answer_state"]}))
        gate_ok = typed is True if pq.role in lc.YES_NO_ROLES else True
        return out + self._after_item(pq, gate_ok, "ANSWERED_NO" if not gate_ok else "ANSWERED")

    def request_clarification(self, action_id: str, reason: str) -> list[Event]:
        pq = self._current(action_id)
        if self.q[pq.code].status != "PRESENTED":
            raise ControllerError("NOT_PRESENTED", "Clarification applies to a presented question")
        if not reason or len(reason) > 300:
            raise ControllerError("INVALID_REASON", "Give a clarification reason (1–300 characters)", 422)
        return self._reprompt_or_unresolve(pq, action_id, f"CLARIFICATION: {reason}")

    def report(self, kind: str, note: str | None = None) -> list[Event]:
        """A conversation event (wrong person, callback requested, declined to continue, interrupted): terminates."""
        self._require_open()
        if kind not in lc.EVENTS:
            raise ControllerError("UNKNOWN_EVENT", f"Unknown conversation event {kind}", 422)
        if self.terminated is not None:
            raise ControllerError(
                "ALREADY_TERMINATED", f"The conversation was already terminated ({self.terminated.get('reason')})"
            )
        out = self._emit(Event("CONVERSATION_EVENT", data={"kind": kind, "note": note, "stage": self.stage()}))
        if kind == "WRONG_PERSON":
            out += self._gate("identity", "WRONG_PERSON")
        elif kind == "CALLBACK_REQUESTED":
            out += self._gate("willingness", "CALLBACK_REQUESTED")
        elif kind == "DECLINED_TO_CONTINUE":
            out += self._gate("willingness", "DECLINED")
        return out + self._terminate(kind, lc.EVENTS[kind])

    def skip(self, action_id: str) -> list[Event]:
        """Never permitted: questions are skipped only by approved conditions at start."""
        pq = self._current(action_id)
        code = "MANDATORY_NOT_SKIPPABLE" if pq.mandatory else "SKIP_NOT_APPROVED"
        raise ControllerError(code, f"{pq.code} cannot be skipped: questions are skipped only by approved conditions")

    def end(self, *, abandon: bool, reason: str | None = None) -> list[Event]:
        self._require_open()
        s = self.summary()
        if abandon:
            outcome = "ABANDONED"
        elif self.terminated is not None:
            outcome = "TERMINATED"
        else:
            outcome = (
                "COMPLETED"
                if self.finished and not s["mandatory_open"] and not s["mandatory_unresolved"]
                else "INCOMPLETE"
            )
        return self._emit(
            Event("ENDED", data={"outcome": outcome, "reason": reason, "summary": s, "lifecycle": self.lifecycle()})
        )

    # -- queries --
    def stage(self) -> str:
        if not self.started:
            return "NOT_STARTED"
        if self.ended:
            return "ENDED"
        if self.current is not None:
            st = self.plan.question(self.current).stage
            return f"TERMINATION_{st}" if self.terminated else st
        return "TERMINATED" if self.terminated else ("FINISHED" if self.finished else "STARTING")

    def next_action(self) -> Action:
        def act(kind: Any, note: str, pq: PlannedQuestion | None = None) -> Action:
            qs = self.q[pq.code] if pq else None
            return Action(
                kind,
                self.action_id if pq else None,
                pq.code if pq else None,
                pq.wording if pq else None,
                pq.answer_type if pq else None,
                list(pq.options) if pq else [],
                pq.mandatory if pq else None,
                pq.verbatim_required if pq else None,
                bool(qs and qs.status == "PRESENTED"),
                qs.reprompts if qs else 0,
                pq.max_reprompts if pq else 0,
                bool(pq and pq.answer_type == "ACKNOWLEDGEMENT"),
                note,
                pq.stage if pq else None,
                pq.role if pq else None,
                bool(pq and pq.completes_on_delivery),
            )

        if not self.started:
            return act("NOT_STARTED", "Start the execution")
        if self.ended:
            return act("ENDED", f"Execution ended: {self.ended}")
        if self.current is None:
            if self.terminated:
                return act(
                    "SEQUENCE_FINISHED", f"Conversation terminated ({self.terminated.get('reason')}); end the execution"
                )
            return act("SEQUENCE_FINISHED", "No further question is permitted; end the execution")
        pq = self.plan.question(self.current)
        qs = self.q[pq.code]
        if qs.status == "REQUESTED":
            kind = "REPROMPT" if qs.reprompts or qs.not_delivered else "ASK"
            if pq.completes_on_delivery:
                note = "Deliver this statement, then record its delivery (it completes when delivered)"
            else:
                note = "Present this question, then record its delivery"
            return act(kind, note if not qs.not_delivered else "Delivery was not confirmed; present it again", pq)
        return act(
            "REPROMPT" if qs.reprompts else "ASK",
            "Presented; record the customer's answer, an unclear answer or a clarification",
            pq,
        )

    def lifecycle(self) -> dict[str, Any]:
        disc = [x for x in self.plan.questions if x.role == "DISCLOSURE" and x.applicable]
        return {
            "stage": self.stage(),
            "gates": dict(self.gates),
            "flags": list(self.flags),
            "termination": dict(self.terminated) if self.terminated else None,
            "disclosures_delivered": [x.code for x in disc if self.q[x.code].status == "COMPLETED"],
            "disclosures_undelivered": [x.code for x in disc if self.q[x.code].status == "UNRESOLVED"],
            "blocked_by_identity_gate": [c for c, s in self.q.items() if s.reason == "BLOCKED_BY_IDENTITY_GATE"],
            "simulated": True,
            "compliance_outcome": "NOT_EVALUATED",
        }

    def summary(self) -> dict[str, Any]:
        mand = [x for x in self.plan.questions if x.mandatory]
        st = {x.code: self.q[x.code].status for x in self.plan.questions}
        return {
            "questions": len(self.plan.questions),
            "applicable": sum(1 for x in self.plan.questions if x.applicable),
            "completed": [c for c, s in st.items() if s == "COMPLETED"],
            "unresolved": [c for c, s in st.items() if s == "UNRESOLVED"],
            "skipped_by_condition": [c for c, s in st.items() if s == "SKIPPED_BY_CONDITION"],
            "mandatory_total": len(mand),
            "mandatory_completed": [x.code for x in mand if st[x.code] == "COMPLETED"],
            "mandatory_unresolved": [x.code for x in mand if st[x.code] == "UNRESOLVED"],
            "mandatory_skipped_by_condition": [x.code for x in mand if st[x.code] == "SKIPPED_BY_CONDITION"],
            "mandatory_open": [x.code for x in mand if st[x.code] not in TERMINAL],
        }

    def state(self) -> dict[str, Any]:
        status = (
            "NOT_STARTED"
            if not self.started
            else self.ended
            if self.ended
            else "SEQUENCE_FINISHED"
            if self.finished
            else "IN_PROGRESS"
        )
        return {
            "status": status,
            "sequence_finished": self.finished,
            "summary": self.summary(),
            "lifecycle": self.lifecycle(),
            "questions": [
                {
                    "code": pq.code,
                    "section": pq.section,
                    "position": pq.position,
                    "mandatory": pq.mandatory,
                    "answer_type": pq.answer_type,
                    "status": self.q[pq.code].status,
                    "requests": self.q[pq.code].requests,
                    "reprompts_used": self.q[pq.code].reprompts,
                    "reprompts_allowed": pq.max_reprompts,
                    "answer": self.q[pq.code].answer,
                    "reason": self.q[pq.code].reason or pq.skip_reason,
                    "stage": pq.stage,
                    "role": pq.role,
                }
                for pq in self.plan.questions
            ],
        }


def _validate(pq: PlannedQuestion, value: Any) -> Any:
    t = pq.answer_type
    if t in ("YES_NO", "ACKNOWLEDGEMENT"):
        if not isinstance(value, bool):
            raise ControllerError("INVALID_ANSWER", f"{pq.code} expects yes or no", 422)
        return value
    if t == "NUMERIC":
        if isinstance(value, bool) or not isinstance(value, int | float):
            try:
                value = float(str(value).strip())
            except ValueError as exc:
                raise ControllerError("INVALID_ANSWER", f"{pq.code} expects a number", 422) from exc
        if value != value or abs(value) > 1e12:  # NaN or absurd
            raise ControllerError("INVALID_ANSWER", f"{pq.code} expects a finite number", 422)
        return float(value)
    if t == "ENUM":
        if value not in pq.options:
            raise ControllerError("INVALID_ANSWER", f"{pq.code} expects one of {', '.join(pq.options)}", 422)
        return value
    text = str(value or "").strip()
    if not text or len(text) > 2000:
        raise ControllerError("INVALID_ANSWER", f"{pq.code} expects a non-empty answer (≤ 2000 characters)", 422)
    return text


def _state(pq: PlannedQuestion, kind: str, typed: Any) -> str:
    """The approved answer-state vocabulary (YES, NO, UNCLEAR, REFUSED, UNKNOWN) plus VALUE for typed answers."""
    if kind != "ANSWER":
        return kind
    if pq.answer_type in ("YES_NO", "ACKNOWLEDGEMENT"):
        return "YES" if typed else "NO"
    return "VALUE"
