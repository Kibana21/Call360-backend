"""Survey Applicability (APPL-X1) — typed application facts and one applicability policy give a deterministic
survey-selection plan.

Pure Python: no database, no clock, no randomness, no model. ``logic`` evaluates the restricted typed expression tree
in three-valued logic with a full trace; ``evaluator`` applies a policy's requirements (additive selection, explicit
replacement, explicit alternatives, governed order); ``analysis`` validates documents, finds what can be proven by
enumeration and generates scenarios. Nothing here reads or writes an assignment rule, a survey binding, a requirement
group or any operational record, and a selection plan grants nothing: it is a synthetic result.
"""

from app.domain.survey.applicability.logic import CONTRACT, ApplicabilityError

__all__ = ["CONTRACT", "ApplicabilityError"]
