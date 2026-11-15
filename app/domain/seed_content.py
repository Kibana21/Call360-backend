"""Static synthetic content for S0-SEED-1: scripts, questions, risk rules, controls and references.

Every wording here is a **synthetic, unapproved development example** (content_approval_status =
SYNTHETIC_UNAPPROVED). Nothing is AIA or MAS language, an approved threshold or a regulatory interpretation.
"""

from __future__ import annotations

from typing import Any

WORDING_PREFIX = "[Synthetic example, not approved wording] "
LABEL = "Seeded synthetic example: not produced by a Call360 voice session or compliance evaluation"

# question_code -> definition. Mandatory narrative questions occur only in ILP and ELEVATED_RISK.
QUESTIONS: dict[str, dict[str, Any]] = {
    "Q-REP-DISCLOSED": {
        "category": "SALES_CONDUCT",
        "intent": "Representative disclosed whom they represent",
        "wording": "Did the representative tell you which company they represent?",
        "answer_type": "YES_NO",
        "policy": "EXACT_BOOLEAN",
        "expected": {"value": True},
        "mandatory": True,
    },
    "Q-NEEDS-DISCUSSED": {
        "category": "SALES_CONDUCT",
        "intent": "Needs were discussed before the recommendation",
        "wording": "Did the representative discuss your needs before recommending this plan?",
        "answer_type": "YES_NO",
        "policy": "EXACT_BOOLEAN",
        "expected": {"value": True},
        "mandatory": True,
    },
    "Q-REASON-UNDERSTOOD": {
        "category": "SALES_CONDUCT",
        "intent": "Customer acknowledges the reason for the recommendation",
        "wording": "Please confirm you understood why this plan was recommended to you.",
        "answer_type": "ACKNOWLEDGEMENT",
        "policy": "ACKNOWLEDGEMENT",
        "mandatory": True,
        "mode": "CONTROLLED_TTS",
    },
    "Q-PREMIUM-TERM-YEARS": {
        "category": "POLICY_FACT",
        "intent": "Customer states the premium payment term",
        "wording": "For how many years did you understand you will pay premiums?",
        "answer_type": "NUMERIC",
        "policy": "NUMERIC_MATCH_POLICY_FACT",
        "fact_key": "premium_term_years",
        "mandatory": True,
    },
    "Q-ANY-CONCERNS": {
        "category": "SALES_CONDUCT",
        "intent": "Open question for concerns",
        "wording": "Is there anything about the sale you would like to raise?",
        "answer_type": "FREE_TEXT",
        "policy": "COLLECT_ONLY",
        "mandatory": False,
    },
    "Q-COVERAGE-SCOPE": {
        "category": "PRODUCT_UNDERSTANDING",
        "intent": "Customer acknowledges the coverage scope",
        "wording": "Please confirm you understood what this plan covers and does not cover.",
        "answer_type": "ACKNOWLEDGEMENT",
        "policy": "ACKNOWLEDGEMENT",
        "mandatory": True,
        "mode": "CONTROLLED_TTS",
    },
    "Q-PREMIUM-FREQUENCY": {
        "category": "POLICY_FACT",
        "intent": "Customer states how often premiums are paid",
        "wording": "How often will you pay premiums?",
        "answer_type": "ENUM",
        "policy": "COLLECT_ONLY",
        "mandatory": False,
        "schema": {"type": "string", "enum": ["MONTHLY", "QUARTERLY", "HALF_YEARLY", "ANNUAL"]},
        "not_applicable": {"fact": "premium_frequency", "equals": "SINGLE"},
    },
    "Q-INVESTMENT-RISK": {
        "category": "PRODUCT_UNDERSTANDING",
        "intent": "Customer acknowledges investment value can fall",
        "wording": "Please confirm you understood that the value of the investment can go down as well as up.",
        "answer_type": "ACKNOWLEDGEMENT",
        "policy": "ACKNOWLEDGEMENT",
        "mandatory": True,
        "mode": "CONTROLLED_TTS",
    },
    "Q-CHARGES-EXPLAINED": {
        "category": "PRODUCT_UNDERSTANDING",
        "intent": "Charges were explained",
        "wording": "Were the plan's charges explained to you?",
        "answer_type": "YES_NO",
        "policy": "EXACT_BOOLEAN",
        "expected": {"value": True},
        "mandatory": True,
    },
    "Q-SURRENDER-IMPLICATIONS": {
        "category": "PRODUCT_UNDERSTANDING",
        "intent": "Early surrender implications were explained",
        "wording": "Were the effects of ending the plan early explained to you?",
        "answer_type": "YES_NO",
        "policy": "EXACT_BOOLEAN",
        "expected": {"value": True},
        "mandatory": True,
    },
    "Q-ILP-OWN-WORDS": {
        "category": "PRODUCT_UNDERSTANDING",
        "intent": "Customer describes the plan in their own words",
        "wording": "In your own words, how does this plan work?",
        "answer_type": "FREE_TEXT",
        "policy": "NARRATIVE_REVIEW",
        "mandatory": True,
    },
    "Q-ELEVATED-CIRCUMSTANCES": {
        "category": "ELEVATED_RISK",
        "intent": "Customer describes their circumstances at the time of sale",
        "wording": "Could you describe your financial circumstances when you bought the plan?",
        "answer_type": "FREE_TEXT",
        "policy": "NARRATIVE_REVIEW",
        "mandatory": True,
    },
    "Q-PRESSURE-FELT": {
        "category": "ELEVATED_RISK",
        "intent": "Customer felt pressured to buy",
        "wording": "Did you feel pressured to buy the plan?",
        "answer_type": "YES_NO",
        "policy": "EXACT_BOOLEAN",
        "expected": {"value": False},
        "mandatory": True,
    },
}

# (module code, revision) -> (kind, name, question codes in order)
MODULES: dict[tuple[str, int], tuple[str, str, list[str]]] = {
    ("COMMON_SALES_CONDUCT", 1): (
        "COMMON",
        "Common sales conduct (synthetic)",
        ["Q-REP-DISCLOSED", "Q-NEEDS-DISCUSSED", "Q-REASON-UNDERSTOOD", "Q-PREMIUM-TERM-YEARS"],
    ),
    ("COMMON_SALES_CONDUCT", 2): (
        "COMMON",
        "Common sales conduct (synthetic)",
        ["Q-REP-DISCLOSED", "Q-NEEDS-DISCUSSED", "Q-REASON-UNDERSTOOD", "Q-PREMIUM-TERM-YEARS", "Q-ANY-CONCERNS"],
    ),
    ("PROTECTION", 1): ("PRODUCT", "Protection (synthetic)", ["Q-COVERAGE-SCOPE", "Q-PREMIUM-FREQUENCY"]),
    ("ILP", 1): (
        "PRODUCT",
        "Investment-linked (synthetic)",
        ["Q-INVESTMENT-RISK", "Q-CHARGES-EXPLAINED", "Q-SURRENDER-IMPLICATIONS", "Q-ILP-OWN-WORDS"],
    ),
    ("ELEVATED_RISK", 1): ("RISK", "Elevated risk (synthetic)", ["Q-ELEVATED-CIRCUMSTANCES", "Q-PRESSURE-FELT"]),
}

# Section inclusion conditions, evaluated against the pinned fact snapshot and risk band (app.domain.outcomes).
CONDITIONS: dict[str, dict[str, Any] | None] = {
    "COMMON_SALES_CONDUCT": None,
    "PROTECTION": {"fact": "product_family", "equals": "PROTECTION"},
    "ILP": {"fact": "is_ilp", "equals": True},
    "ELEVATED_RISK": {"risk_band_in": ["HIGH"]},
}

# Script versions: (family market, label) -> (common revision, published day offset, effective_to offset,
# final status). Offsets are days before the anchor; None = open-ended or never published.
VERSIONS: list[tuple[str, str, int, int | None, int | None, str]] = [
    ("SG", "0.9", 1, 400, 300, "WITHDRAWN"),
    ("SG", "1.0", 1, 300, 120, "SUPERSEDED"),
    ("SG", "1.1", 2, 120, None, "PUBLISHED"),
    ("SG", "1.2", 2, None, None, "DRAFT"),
    ("MY", "1.0", 2, 300, None, "PUBLISHED"),
]

# Synthetic SBQ rule set content: rules indicate a band from a factor value. No numeric thresholds: premium
# amount bands are labels supplied by the (synthetic) source. Highest indication wins; no match means LOW.
RISK_RULES: list[dict[str, Any]] = [
    {"id": "R-ILP", "factor": "ILP_INDICATOR", "equals": True, "indicates": "HIGH"},
    {"id": "R-BANCA", "factor": "SELLING_CHANNEL", "equals": "BANCASSURANCE", "indicates": "MEDIUM"},
    {"id": "R-PREM-C", "factor": "PREMIUM_AMOUNT_BAND", "equals": "BAND_C", "indicates": "MEDIUM"},
]
# (version, effective_from offset, effective_to offset, status)
RULE_SETS: list[tuple[int, int, int | None, str]] = [(1, 400, 200, "SUPERSEDED"), (2, 200, None, "PUBLISHED")]

CONTROLS: list[tuple[str, str, list[str]]] = [
    ("SYN-CTRL-01", "Representative disclosure (synthetic control)", ["Q-REP-DISCLOSED"]),
    ("SYN-CTRL-02", "Needs discussed before recommendation (synthetic control)", ["Q-NEEDS-DISCUSSED"]),
    (
        "SYN-CTRL-03",
        "Product understanding (synthetic control)",
        ["Q-REASON-UNDERSTOOD", "Q-COVERAGE-SCOPE", "Q-INVESTMENT-RISK", "Q-CHARGES-EXPLAINED", "Q-ILP-OWN-WORDS"],
    ),
    ("SYN-CTRL-04", "Premium term and affordability (synthetic control)", ["Q-PREMIUM-TERM-YEARS"]),
    (
        "SYN-CTRL-05",
        "Elevated-risk review (synthetic control)",
        ["Q-ELEVATED-CIRCUMSTANCES", "Q-PRESSURE-FELT", "Q-SURRENDER-IMPLICATIONS"],
    ),
]
# Placeholder references only: S&C supplies real public references later (REG-001; interpretation NOT_REVIEWED).
REG_REFS: list[tuple[str, str]] = [
    ("SG", "Synthetic placeholder: public sales-conduct guidance reference to be supplied by S&C"),
    ("MY", "Synthetic placeholder: public sales-conduct guidance reference to be supplied by S&C"),
]
REG_MAPPED_CONTROLS = {"SYN-CTRL-01", "SYN-CTRL-03"}
