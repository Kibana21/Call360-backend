"""Survey definition foundation (SS-03A): canonical documents, hashing, validation and the condition engine.

Pure modules: nothing here reads or writes a database, a clock, a network or a model. The persistence and API layers
(SS-03A.2, SS-03A.3) are built on these. Survey EXECUTION, call-plan assembly, wording rendering and every non-answer
behaviour are deliberately absent (SS-03B and later; several await business and Compliance rulings).

Authority: Call360-specs docs/plans/survey-studio/04_SS-01_CANONICAL_CONTRACTS.md (§1–§8) and
26_SS-03A_FOUNDATION_SPECIFICATION.md, as approved by the owner (decision register D-176…D-187).
"""
