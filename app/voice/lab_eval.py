"""Voice Lab deterministic evaluation (S1-E.1). Pure functions, no I/O and no language model.

- **Wording**: word-level alignment (minimum edit distance with a deterministic back-trace) of the expected spoken
  statement against (a) what the provider reports it said (``said``) and (b) what the local faster-whisper engine
  independently heard in the provider audio (``heard``). Each gives exact match, added, omitted and substituted words
  and word error rate.
- **Attribution**: a deviation found in the independent transcript is a *suspected speech deviation* when the provider's
  own text shows the same deviation, a *suspected transcription error* when the provider text matches the expected
  wording there, and *unattributed* when no provider text exists. Every attribution is a suspicion for a person to
  confirm by listening; nothing here decides what was actually spoken.
- **Structured answer accuracy**: field-by-field exact comparison of the extracted answer with the expected answer.
- **Criteria**: optional thresholds per test case; exact wording is judged only on the independent transcript (the
  provider's own text is a claim, not proof); free-text expected behaviour always needs human assessment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.voice.transcript import normalise

VERSION = "call360.voicelab-eval/1"
CRITERIA = {
    "exact_wording": "Wording must match exactly (normalised words)",
    "max_wer": "Maximum word error rate (0–1) of the independent transcript",
    "max_first_audio_ms": "Maximum first-audio latency (ms)",
    "max_interruption_ms": "Maximum interruption latency (ms)",
    "min_answer_accuracy": "Minimum structured-answer accuracy (0–1)",
}


@dataclass(frozen=True)
class Edit:
    op: str  # MATCH | SUBSTITUTED | OMITTED | ADDED
    expected: str | None
    actual: str | None
    position: int  # index in the expected words (insertion point for ADDED)


def align(expected: str, actual: str) -> list[Edit]:
    ref, hyp = normalise(expected), normalise(actual)
    n, m = len(ref), len(hyp)
    d = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n + 1):
        d[i][0] = i
    for j in range(m + 1):
        d[0][j] = j
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (ref[i - 1] != hyp[j - 1]))
    out: list[Edit] = []
    i, j = n, m
    while i or j:  # deterministic preference: match / substitution, then omission, then addition
        if i and j and d[i][j] == d[i - 1][j - 1] + (ref[i - 1] != hyp[j - 1]):
            same = ref[i - 1] == hyp[j - 1]
            out.append(Edit("MATCH" if same else "SUBSTITUTED", ref[i - 1], hyp[j - 1], i - 1))
            i, j = i - 1, j - 1
        elif i and d[i][j] == d[i - 1][j] + 1:
            out.append(Edit("OMITTED", ref[i - 1], None, i - 1))
            i -= 1
        else:
            out.append(Edit("ADDED", None, hyp[j - 1], i))
            j -= 1
    return list(reversed(out))


def wording(expected: str, actual: str | None) -> dict[str, Any] | None:
    if actual is None:
        return None
    edits = align(expected, actual)
    ref = normalise(expected)
    errors = [e for e in edits if e.op != "MATCH"]
    return {
        "exact_match": not errors,
        "wer": round(len(errors) / len(ref), 4) if ref else (0.0 if not normalise(actual) else 1.0),
        "added": [e.actual for e in edits if e.op == "ADDED"],
        "omitted": [e.expected for e in edits if e.op == "OMITTED"],
        "substituted": [{"expected": e.expected, "actual": e.actual} for e in edits if e.op == "SUBSTITUTED"],
        "expected_words": len(ref),
        "edits": [e.__dict__ for e in errors],
    }


def _key(e: Edit) -> tuple[str, int, str | None, str | None]:
    return (e.op, e.position, e.expected, e.actual)


def attribute(expected: str, said: str | None, heard: str | None) -> list[dict[str, Any]]:
    """Attribute each deviation of the independent transcript (``heard``) — and each deviation the provider itself
    reports (``said``) that the transcript does not show — to its most likely source."""
    if heard is None and said is None:
        return []
    said_edits = {_key(e) for e in align(expected, said) if e.op != "MATCH"} if said is not None else None
    heard_edits = [e for e in align(expected, heard) if e.op != "MATCH"] if heard is not None else []
    out = []
    for e in heard_edits:
        if said_edits is None:
            kind = "UNATTRIBUTED"
        elif _key(e) in said_edits:
            kind = "SUSPECTED_SPEECH_DEVIATION"
        else:
            kind = "SUSPECTED_TRANSCRIPTION_ERROR"
        out.append({**e.__dict__, "attribution": kind})
    if said_edits is not None:
        seen = {_key(e) for e in heard_edits}
        for k in sorted(said_edits - seen, key=lambda k: (k[1], k[0])):
            out.append(
                {
                    "op": k[0],
                    "position": k[1],
                    "expected": k[2],
                    "actual": k[3],
                    "attribution": "PROVIDER_TEXT_ONLY" if heard is not None else "SUSPECTED_SPEECH_DEVIATION",
                }
            )
    return out


def answer_accuracy(expected: dict[str, Any], extracted: dict[str, Any] | None) -> dict[str, Any] | None:
    if not expected:
        return None
    got = extracted or {}
    fields = []
    for k, want in sorted(expected.items()):
        have = got.get(k)
        same = str(have).strip().upper() == str(want).strip().upper() if have is not None else False
        fields.append({"field": k, "expected": want, "extracted": have, "match": same})
    hits = sum(f["match"] for f in fields)
    return {"accuracy": round(hits / len(fields), 4), "fields": fields}


def check(criteria: dict[str, Any], metrics: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """Apply the configured criteria. Missing measurements are NOT_MEASURED (never a pass). Expected behaviour is
    always left for human assessment."""
    checks: list[dict[str, Any]] = []
    heard = metrics.get("heard") or {}
    said = metrics.get("said") or {}

    def add(code: str, value: Any, ok: bool | None, detail: str) -> None:
        checks.append(
            {"code": code, "label": CRITERIA.get(code, code), "value": value, "result": _res(ok), "detail": detail}
        )

    if criteria.get("exact_wording"):
        # Only the independent transcript can show what was spoken; the provider's own text is a claim, not proof
        # (an LLM or provider report is never evidence of verbatim delivery). Without audio: NOT_MEASURED.
        if heard:
            add("exact_wording", heard.get("exact_match"), heard.get("exact_match"), "independent transcript")
        else:
            claim = "matches" if said.get("exact_match") else "differs" if said else "absent"
            add("exact_wording", None, None, f"no independent transcript (provider text {claim}; not proof)")
    if "max_wer" in criteria:
        w = heard.get("wer") if heard else None
        add("max_wer", w, None if w is None else w <= float(criteria["max_wer"]), f"≤ {criteria['max_wer']}")
    for code, metric in (("max_first_audio_ms", "first_audio_ms"), ("max_interruption_ms", "interruption_ms")):
        if code in criteria:
            v = metrics.get(metric)
            add(code, v, None if v is None else v <= float(criteria[code]), f"≤ {criteria[code]} ms")
    if "min_answer_accuracy" in criteria:
        acc = (metrics.get("answer") or {}).get("accuracy")
        add(
            "min_answer_accuracy",
            acc,
            None if acc is None else acc >= float(criteria["min_answer_accuracy"]),
            f"≥ {criteria['min_answer_accuracy']}",
        )
    if any(c["result"] == "FAIL" for c in checks):
        verdict = "FAIL"
    elif any(c["result"] == "NOT_MEASURED" for c in checks) or metrics.get("needs_listening"):
        verdict = "NEEDS_HUMAN_REVIEW"
    elif checks:
        verdict = "PASS"
    else:
        verdict = "NOT_EVALUATED"
    return verdict, checks


def _res(ok: bool | None) -> str:
    return "NOT_MEASURED" if ok is None else ("PASS" if ok else "FAIL")


def validate_criteria(criteria: dict[str, Any]) -> list[str]:
    errors = []
    for k, v in criteria.items():
        if k not in CRITERIA:
            errors.append(f"unknown criterion {k}")
        elif k == "exact_wording":
            if not isinstance(v, bool):
                errors.append("exact_wording must be true or false")
        elif not isinstance(v, int | float) or isinstance(v, bool) or v < 0:
            errors.append(f"{k} must be a non-negative number")
        elif k in ("max_wer", "min_answer_accuracy") and v > 1:
            errors.append(f"{k} must be between 0 and 1")
    return errors


SPEECH_RESULTS = {
    "AUTOMATED_TRANSCRIPT_MATCH": "The independent transcript matches the expected wording (automated; not proof of "
    "verbatim delivery)",
    "SUSPECTED_SPEECH_DEVIATION": "Deviation heard in the independent transcript and also present in the provider's "
    "own text — suspected speech deviation; listen to confirm",
    "SUSPECTED_TRANSCRIPTION_ERROR": "Deviation only in the independent transcript (the provider's text matches) — "
    "suspected transcription error; listen to confirm",
    "INSUFFICIENT_AUDIO_EVIDENCE": "No independent transcript of provider audio — speech cannot be assessed "
    "automatically",
}
HUMAN_RESULTS = {
    "CONFIRMED_AS_EXPECTED": "A person listened and confirmed the expected wording was spoken",
    "CONFIRMED_DEVIATION": "A person listened and confirmed a deviation from the expected wording",
    "INCONCLUSIVE": "A person listened and could not confirm either way",
}


def speech_result(metrics: dict[str, Any]) -> str:
    """The automated speech-evaluation result of one trial, from the independent transcript (the primary automated
    source, never definitive proof). A human assessment, when recorded, is reported separately and takes precedence."""
    heard = metrics.get("heard")
    if not heard:
        return "INSUFFICIENT_AUDIO_EVIDENCE"
    if heard.get("exact_match"):
        return "AUTOMATED_TRANSCRIPT_MATCH"
    kinds = {a.get("attribution") for a in metrics.get("attributions") or []}
    if "SUSPECTED_SPEECH_DEVIATION" in kinds:
        return "SUSPECTED_SPEECH_DEVIATION"
    return "SUSPECTED_TRANSCRIPTION_ERROR"
