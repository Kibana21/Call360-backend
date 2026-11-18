"""S2-D.1 conversation lifecycle: stages, item roles and the system-enforced gate policies (SUR-009).

Shared by Script Studio validation (what a script may configure) and the question controller (what is enforced).
**These are synthetic development assumptions** recorded in SCRIPT_GOVERNANCE_AND_ASSIGNMENT.md ("Conversation
lifecycle"); they are not approved AIA/MAS policy or wording.

- Stages run in a fixed system order, whatever the section positions: OPENING → IDENTITY → DISCLOSURE → CONSENT →
  VERIFICATION → CLOSING. A section's module kind sets the stage of its items (COMMON / PRODUCT / RISK / LANGUAGE are
  VERIFICATION).
- Each item has a lifecycle role. Statement roles (opening, disclosure, closing) complete when delivered. Identity and
  consent roles are yes/no items whose answer drives a gate.
- Failure behaviour is configurable only inside ``ALLOWED_ON_FAILURE``; the system-enforced minimums (identity
  failure and declining to proceed always terminate; a mandatory disclosure that cannot be delivered always
  terminates) cannot be relaxed by configuration.
- Items that disclose policy information are never presented before the identity gate passes; a script that contains
  them must have an identity gate.
- Willingness to proceed, recording consent and future cloud-processing authorisation are three separate gates.
"""

from __future__ import annotations

STAGES = ("OPENING", "IDENTITY", "DISCLOSURE", "CONSENT", "VERIFICATION", "CLOSING")
STAGE_ORDER = {s: i for i, s in enumerate(STAGES)}
KIND_STAGE = {
    "OPENING": "OPENING",
    "IDENTITY": "IDENTITY",
    "DISCLOSURE": "DISCLOSURE",
    "CONSENT": "CONSENT",
    "CLOSING": "CLOSING",
    "COMMON": "VERIFICATION",
    "PRODUCT": "VERIFICATION",
    "RISK": "VERIFICATION",
    "LANGUAGE": "VERIFICATION",
}
LIFECYCLE_KINDS = ("OPENING", "IDENTITY", "DISCLOSURE", "CONSENT", "CLOSING")

ROLES = (
    "OPENING_STATEMENT",
    "IDENTITY_CHECK",
    "DISCLOSURE",
    "CONSENT_TO_PROCEED",
    "RECORDING_CONSENT",
    "CLOUD_PROCESSING_CONSENT",
    "VERIFICATION",
    "CLOSING_STATEMENT",
)
ROLE_STAGE = {
    "OPENING_STATEMENT": "OPENING",
    "IDENTITY_CHECK": "IDENTITY",
    "DISCLOSURE": "DISCLOSURE",
    "CONSENT_TO_PROCEED": "CONSENT",
    "RECORDING_CONSENT": "CONSENT",
    "CLOUD_PROCESSING_CONSENT": "CONSENT",
    "VERIFICATION": "VERIFICATION",
    "CLOSING_STATEMENT": "CLOSING",
}
STATEMENT_ROLES = ("OPENING_STATEMENT", "DISCLOSURE", "CLOSING_STATEMENT")  # complete on delivery
YES_NO_ROLES = ("IDENTITY_CHECK", "CONSENT_TO_PROCEED", "RECORDING_CONSENT", "CLOUD_PROCESSING_CONSENT")
ROLE_ANSWER_TYPES = {
    "OPENING_STATEMENT": ("ACKNOWLEDGEMENT",),
    "DISCLOSURE": ("ACKNOWLEDGEMENT",),
    "CLOSING_STATEMENT": ("ACKNOWLEDGEMENT",),
    **{r: ("YES_NO",) for r in YES_NO_ROLES},
}

# On a failed item (answered no where a gate needs yes, refused, unresolved, or a statement not delivered):
ALLOWED_ON_FAILURE: dict[str, tuple[str, ...]] = {
    "OPENING_STATEMENT": ("TERMINATE",),
    "IDENTITY_CHECK": ("TERMINATE",),  # system-enforced
    "DISCLOSURE": ("TERMINATE", "CONTINUE_FLAGGED"),  # mandatory disclosures: TERMINATE only
    "CONSENT_TO_PROCEED": ("TERMINATE",),  # system-enforced
    "RECORDING_CONSENT": ("CONTINUE_WITHOUT_RECORDING", "TERMINATE"),
    "CLOUD_PROCESSING_CONSENT": ("CONTINUE_WITHOUT_CLOUD_PROCESSING", "TERMINATE"),
    "VERIFICATION": ("CONTINUE", "TERMINATE"),
    "CLOSING_STATEMENT": ("CONTINUE",),
}
DEFAULT_ON_FAILURE = {r: v[0] for r, v in ALLOWED_ON_FAILURE.items()}
NO_POLICY_DISCLOSURE_STAGES = ("OPENING", "IDENTITY", "CLOSING")

# D-67 (owner condition on accepting S2-D.1): a script without these MANDATORY gates is never eligible for a future live
# customer conversation. Cloud-processing consent is enforced where audio would leave for a cloud provider (D-68).
LIVE_REQUIRED_GATES = ("IDENTITY_CHECK", "CONSENT_TO_PROCEED", "RECORDING_CONSENT")

# Conversation events an operator / provider can report at any time.
EVENTS = {
    "WRONG_PERSON": "The person answering is not the intended customer",
    "CALLBACK_REQUESTED": "The customer asked to be called back later",
    "DECLINED_TO_CONTINUE": "The customer declined to continue",
    "INTERRUPTED": "The conversation was interrupted (connection lost)",
}

ASSUMPTIONS = (
    "Stage order OPENING → IDENTITY → DISCLOSURE → CONSENT → VERIFICATION → CLOSING is system-enforced.",
    "Identity is confirmed only when every identity check is answered yes; no, wrong person, refusal or an unclear "
    "answer after the approved re-prompts terminates the conversation (identity is simulated in S2-D.1).",
    "Declining to proceed, a callback request or declining to continue terminates the conversation.",
    "Recording consent and cloud-processing authorisation are independent of willingness to proceed; declining them "
    "continues without recording / cloud processing unless the script is configured to terminate.",
    "A mandatory disclosure that cannot be delivered after the approved re-prompts terminates the conversation.",
    "A refused or unresolved verification question is recorded and the conversation continues unless configured to "
    "terminate; the conversation is then incomplete.",
    "Items that disclose policy information are never presented before the identity gate passes.",
    "On termination, only closing statements marked 'deliver on termination' are offered (none after an interruption).",
)
