# ruff: noqa: E501 — messages and SQL are kept one per line
"""APPL-X4b — governed publication of Applicability Policies.

* ``readiness`` is the ONE authoritative gate. It is computed here, in Python, from the saved policy, its resolved
  dependencies, the evaluator's own analysis and one recorded evaluation run the author explicitly chose. Every blocker
  says what is wrong, what it concerns, the exact versions in conflict, how to clear it, and which steps it prevents.
* ``submit`` freezes an immutable CANDIDATE: the document, the whole dependency manifest with the definitions, the
  qualifying run with its fingerprints, coverage and expectation provenance — and one fingerprint over all of it.
* ``decide`` (approve / return), ``withdraw`` and ``publish`` move only the lifecycle. Three DIFFERENT people: the
  service refuses, and the table's CHECK constraints refuse again.
* ``publish`` revalidates the exact candidate — its own integrity, every pinned version, the evidence suite and
  scenarios, the reproduction of the run — and writes the published version FROM THE CANDIDATE, never from the draft.

A published version is a governed configuration artefact. Nothing here selects a survey for a real case, plans a
callback or starts a session; no assignment rule, survey binding or requirement group is read or written.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta
from app.domain.survey.applicability import library as lib
from app.domain.survey.applicability import policies as pol
from app.domain.survey.applicability import scenarios as sc
from app.domain.survey.applicability.logic import CONTRACT
from app.domain.survey.canonical import sha256_hex
from app.domain.survey.store import STATUS_OF_EVENT, SurveyError, _all, _audit, _one, _ref

CANDIDATE, VERSION = "applicability_policy_candidate", "applicability_policy_version"
CANDIDATE_CONTRACT = "call360.applicability-policy-candidate/1"
SUBMIT, APPROVE, PUBLISH = "SUBMISSION", "APPROVAL", "PUBLICATION"
ALL = [SUBMIT, APPROVE, PUBLISH]
#: the requirement-level behaviours a publication-gating suite must exercise — and exercise INDEPENDENTLY
MATERIAL = ("NEVER_APPLIES", "NEVER_DOES_NOT_APPLY", "REPLACEMENT_NOT_EXERCISED", "ALTERNATIVE_NOT_CHOSEN", "SCOPE_NOT_TRUE", "SCOPE_NOT_FALSE", "OVERLAP_NOT_EXERCISED")  # fmt: skip
C_SQL = (
    "SELECT c.id, c.policy_id, c.market_code, c.candidate_no, c.status, c.draft_revision, c.document, c.document_sha256, c.manifest, c.manifest_sha256, c.evidence, "
    "c.evidence_run_id, c.evidence_run_sha256, c.candidate_sha256, c.submitted_by, c.submitted_at, c.submission_note, c.decided_by, c.decided_at, c.decision_comment, "
    "c.published_by, c.published_at, c.closed_at, p.code AS policy_code FROM applicability_policy_candidate c JOIN applicability_policy p ON p.id = c.policy_id "
)
V_SQL = (
    "SELECT v.id, v.policy_id, v.candidate_id, v.market_code, v.version_no, v.status, v.document, v.document_sha256, v.manifest, v.manifest_sha256, v.evidence, v.evidence_run_id, "
    "v.candidate_sha256, v.version_sha256, v.published_by, v.published_at, v.superseded_at, p.code AS policy_code FROM applicability_policy_version v JOIN applicability_policy p ON p.id = v.policy_id "
)


def _blocker(code: str, message: str, action: str, prevents: Sequence[str] = ALL, /, **at: Any) -> dict[str, Any]:
    return {"code": code, "message": message, "action": action, "prevents": list(prevents), "at": at}


def _refuse(code: str, message: str, status: int = 409, details: list[dict[str, Any]] | None = None) -> SurveyError:
    return SurveyError(status, code, message, details)


# ------------------------------------------------------------------------------------------------- provenance
def _history_authors(db: Session, suite_id: Any) -> dict[str, dict[str, Any]]:
    """For expectations saved before the server stamped their author: who saved the suite at the revision an
    expectation was last changed, read from the suite's APPEND-ONLY history. Never invented."""
    out: dict[str, dict[str, Any]] = {}
    events = _all(db, "SELECT e.event, e.actor_ref, e.detail, e.occurred_at, e.draft_revision FROM applicability_scenario_event e WHERE e.suite_id = :u ORDER BY e.seq", u=suite_id)  # fmt: skip
    for e in events:
        touched = [*((e["detail"] or {}).get("expectations_changed") or []), *((e["detail"] or {}).get("added") or [])]
        for sid in touched:
            out[str(sid)] = {"by": e["actor_ref"], "at": e["occurred_at"].isoformat(timespec="seconds"), "revision": e["draft_revision"]}  # fmt: skip
    created = next((e for e in events if e["event"] == "CREATED"), None)
    if created is not None:
        out["*"] = {
            "by": created["actor_ref"],
            "at": created["occurred_at"].isoformat(timespec="seconds"),
            "revision": 1,
        }
    return out


def provenance(db: Session, run: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Per scenario of a recorded run: what was expected, whether that expectation was AUTHORED or first PROPOSED from
    a result, who stated it and when — and where that authorship was read from."""
    history = _history_authors(db, run["suite_id"])
    refs = [(x["expectation"] or {}).get("stated_by") for x in rows] + [h["by"] for h in history.values()]
    names = lib._names(db, [r for r in refs if r])  # noqa: SLF001
    out = []
    for x in rows:
        exp = x["expectation"] or {}
        stamp = {"by": exp.get("stated_by"), "at": exp.get("stated_at")} if exp.get("stated_by") else None
        legacy = None if stamp else history.get(str(x["scenario_id"])) or history.get("*")
        who = stamp or legacy
        out.append({
            "position": x["position"], "scenario_id": str(x["scenario_id"]), "scenario_code": x["scenario_code"], "scenario_name": x["scenario_name"],
            "outcome": x["outcome"], "source": exp.get("source") if exp else None, "independent": bool(exp) and exp.get("source") == "AUTHORED" and x["outcome"] == "PASSED",
            "stated_by": names.get(str(who["by"]), str(who["by"])) if who else None, "stated_by_ref": str(who["by"]) if who else None, "stated_at": who["at"] if who else None,
            "authorship_from": "SERVER_STAMP" if stamp else "SUITE_HISTORY" if legacy else "UNKNOWN", "reviewed_at_revision": exp.get("reviewed_at_revision"),
            "expected": {"status": exp.get("status"), "selected": [s["code"] for s in exp.get("selected") or []], "pending": exp.get("pending") or []} if exp else None,
        })  # fmt: skip
    return out


def independence(doc: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The deterministic rule of the specification (70 §5.2). Read only from the recorded run:

    * EXPECTATIONS_NOT_INDEPENDENT — every expectation began as a proposal from an evaluator result;
    * INDEPENDENT_COVERAGE_REQUIRED — no independently authored passing scenario with a resolved result that selects a
      survey, or none in which a requirement does not apply;
    * BEHAVIOUR_ONLY_RESULT_DERIVED — a material behaviour is exercised only by result-derived expectations.

    A confirmed proposal is still a proposal: confirming a result is not independent evidence that it is right."""
    stated = [x for x in rows if x["expectation"]]
    authored = [x for x in stated if (x["expectation"] or {}).get("source") == "AUTHORED"]
    independent = [x for x in authored if x["outcome"] == "PASSED"]
    cover = sc.coverage(doc, independent, "PUBLICATION_GATING", True)
    whole = sc.coverage(doc, [x for x in rows if x["outcome"] == "PASSED"], "PUBLICATION_GATING", True)
    exercised = {(g["code"], g["requirement"]) for g in whole["gaps"] if g["code"] in MATERIAL}
    only_derived = [
        g for g in cover["gaps"] if g["code"] in MATERIAL and (g["code"], g["requirement"]) not in exercised
    ]
    blockers: list[dict[str, Any]] = []
    if stated and not authored:
        blockers.append(_blocker(
            "EXPECTATIONS_NOT_INDEPENDENT", f"Every one of the {len(stated)} expected outcomes of this suite began as a proposal taken from the evaluator's own result. Confirming a result is not independent evidence that it is right",
            "State the expected outcome of the scenarios that matter from your own understanding of the policy: clear the proposal and state it anew. A proposal never becomes an authored expectation by being edited", ALL,
            proposed=len(stated), authored=0))  # fmt: skip
    else:
        if not cover["resolved_positive_passing"]:
            blockers.append(_blocker("INDEPENDENT_COVERAGE_REQUIRED", "No independently authored, passing scenario has a resolved result that selects a survey",
                                     "Add or re-state at least one scenario whose expected surveys you state yourself", ALL, missing="RESOLVED_POSITIVE"))  # fmt: skip
        if not cover["negative_passing"]:
            blockers.append(_blocker("INDEPENDENT_COVERAGE_REQUIRED", "No independently authored, passing scenario shows a requirement that does not apply",
                                     "Add or re-state at least one scenario in which a requirement must not apply", ALL, missing="NEGATIVE"))  # fmt: skip
        if only_derived:
            blockers.append(_blocker(
                "BEHAVIOUR_ONLY_RESULT_DERIVED", f"{len(only_derived)} material behaviour{' is' if len(only_derived) == 1 else 's are'} exercised only by scenarios whose expected outcome was taken from a result: " + "; ".join(g["text"] for g in only_derived[:6]) + ("; …" if len(only_derived) > 6 else ""),
                "For each behaviour listed, state the expected outcome of a scenario that exercises it yourself (clear the proposal and state it anew), then run the suite again", ALL,
                behaviours=[{"code": g["code"], "requirement": g["requirement"], "text": g["text"].replace("No scenario", "No independently authored scenario")} for g in only_derived]))  # fmt: skip
    return {
        "expectations": len(stated), "authored": len(authored), "proposed_from_result": len(stated) - len(authored), "independent_passing": len(independent),
        "independent_resolved_positive": cover["resolved_positive_passing"], "independent_negative": cover["negative_passing"],
        "behaviours_only_result_derived": [{"code": g["code"], "requirement": g["requirement"], "text": g["text"]} for g in only_derived],
        "condition_branches_only_result_derived": max(0, cover["condition_gaps"] - whole["condition_gaps"]), "satisfied": not blockers, "blockers": blockers,
    }  # fmt: skip


# -------------------------------------------------------------------------------------------------- evidence
def _recorded_revisions(db: Session, run_id: Any) -> tuple[dict[str, Any] | None, dict[str, int]]:
    """The revision identities the run itself recorded: its suite at a revision, each scenario at a revision."""
    run = _one(db, "SELECT suite_id, suite_revision FROM applicability_evaluation_run WHERE id = :i", i=run_id)
    rows = _all(db, "SELECT scenario_id, scenario_revision FROM applicability_evaluation_result WHERE run_id = :i", i=run_id)  # fmt: skip
    return run, {str(r["scenario_id"]): r["scenario_revision"] for r in rows if r["scenario_id"] is not None}


def _revision_drift(db: Session, run_id: Any, code: str, action: str, prevents: Sequence[str]) -> list[dict[str, Any]]:
    """Evidence is a run of EXACT REVISIONS, not of content that happens to look the same. A suite or scenario that was
    changed after the run and then put back byte for byte has the old fingerprint and a newer revision: it is no longer
    what was run, and restoring it does not restore the evidence. Revisions only ever advance, and only on a real
    change, so a differing revision is proof that the item was edited since."""
    run, recorded = _recorded_revisions(db, run_id)
    if run is None:
        return []
    out: list[dict[str, Any]] = []
    suite = _one(db, "SELECT code, document->>'name' AS name, draft_revision FROM applicability_suite WHERE id = :i", i=run["suite_id"])  # fmt: skip
    if suite is not None and suite["draft_revision"] != run["suite_revision"]:
        out.append(_blocker(code, f"The evidence suite '{suite['name'] or suite['code']}' is now revision {suite['draft_revision']}; the run recorded revision {run['suite_revision']}. "
                                  "It was edited after the run — putting its content back does not make it the revision that was run", action, prevents,
                            suite=suite["code"], revision_run=run["suite_revision"], revision_now=suite["draft_revision"], reason="REVISION_ADVANCED"))  # fmt: skip
    now = {str(r["id"]): r for r in _all(db, "SELECT id, code, document->>'name' AS name, draft_revision FROM applicability_scenario WHERE id = ANY(:i)", i=[uuid.UUID(k) for k in recorded])}  # fmt: skip
    for sid, rev in recorded.items():
        cur = now.get(sid)
        if cur is not None and cur["draft_revision"] != rev:
            out.append(_blocker(code, f"Scenario '{cur['name'] or cur['code']}' is now revision {cur['draft_revision']}; the run recorded revision {rev}. "
                                      "It was edited after the run — putting its content back does not make it the revision that was run", action, prevents,
                                scenario=sid, scenario_code=cur["code"], revision_run=rev, revision_now=cur["draft_revision"], reason="REVISION_ADVANCED"))  # fmt: skip
    return out


def _evidence(db: Session, markets: Sequence[str], policy: Mapping[str, Any], snapshot_sha: str, run_id: uuid.UUID | None) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:  # fmt: skip
    """The one recorded run the author chose, examined against the policy as it is saved NOW. Nothing is chosen for them."""
    if run_id is None:
        return None, [_blocker("SUITE_REQUIRED", "No recorded regression run has been chosen as the evidence for this policy",
                               "Choose a passing run of a publication-gating suite of this policy. If there is none, build the suite in the Scenario studio and run it against this saved revision", [SUBMIT])]  # fmt: skip
    run = sc.run_row(db, run_id, markets, "r.coverage, ")
    if run["policy_id"] != policy["id"]:
        raise _refuse("OTHER_POLICY", "That run belongs to another policy", 422)
    stored, rows = sc._stored(db, run_id)  # noqa: SLF001
    record, blockers = stored["record"], []
    suite = sc.suite_row(db, run["suite_id"], markets)
    target = record.get("target") or {"kind": "DRAFT"}
    if run["suite_purpose"] != "PUBLICATION_GATING":
        blockers.append(_blocker("SUITE_REQUIRED", f"The suite '{run['suite_name'] or run['suite_code']}' is exploratory. An exploratory suite never counts towards publication",
                                 "Choose a run of a publication-gating suite", ALL, suite=run["suite_code"]))  # fmt: skip
    if target.get("kind") != "DRAFT":
        blockers.append(_blocker("EVIDENCE_OUT_OF_DATE", "That run evaluated a candidate or a published version, not this working draft", "Run the suite against this saved draft revision and choose that run", ALL))  # fmt: skip
    if run["status"] != "PASSED":
        blockers.append(_blocker("SUITE_FAILED", f"The chosen run did not pass: {run['passed']} of {run['scenarios']} passed, {run['failed']} failed, {run['invalid'] + run['no_expectation']} not validly defined, {run['not_evaluated']} could not be evaluated",
                                 "Open the run, correct the policy or the expectation that is wrong, and run the suite again", ALL, run=str(run_id), status=run["status"]))  # fmt: skip
    for x in rows:  # the specific reason a gating scenario was not validly defined
        if x["outcome"] != "INVALID_DEFINITION":
            continue
        full = _one(db, "SELECT diagnostics FROM applicability_evaluation_result WHERE run_id = :r AND position = :p", r=run_id, p=x["position"]) or {"diagnostics": []}  # fmt: skip
        for d in full["diagnostics"]:
            if d["code"] in ("PROFILE_VERSION_DIFFERS", "VARIABLE_VERSION_INCOMPATIBLE"):
                blockers.append(_blocker("PROFILE_MISMATCH" if d["code"] == "PROFILE_VERSION_DIFFERS" else "VARIABLE_VERSION_INCOMPATIBLE", f"Scenario '{x['scenario_name']}': {d['message']}",
                                         "Open the scenario and adopt the version the policy pins (or change the policy's pin), save, and run the suite again. There is no acknowledgement for a publication-gating scenario", ALL,
                                         scenario=str(x["scenario_id"]), **{k: v for k, v in (d.get("at") or {}).items() if k in ("kind", "code")}))  # fmt: skip
    cover = stored["coverage"]
    if run["status"] == "PASSED" and not cover.get("meaningful_for_publication"):
        blockers.append(_blocker("COVERAGE_NOT_MEANINGFUL", f"The run passed, but its coverage is not meaningful for publication: {cover.get('why_not_meaningful')}",
                                 "Add scenarios for the gaps listed under coverage, state their expected outcomes, and run the suite again", ALL, gaps=[g for g in cover.get("gaps", []) if g["code"] in MATERIAL][:12]))  # fmt: skip
    # ---- is this still evidence for the policy AS IT IS SAVED NOW, and for the suite and scenarios as they are now?
    if run["policy_document_sha256"] != policy["document_sha256"] or run["policy_snapshot_sha256"] != snapshot_sha:
        blockers.append(_blocker("EVIDENCE_OUT_OF_DATE", f"The run evaluated policy revision {run['policy_revision']}; the saved policy is now revision {policy['draft_revision']} with another document or other dependencies",
                                 "Run the suite again against the saved revision and choose that run", ALL, run_revision=run["policy_revision"], policy_revision=policy["draft_revision"]))  # fmt: skip
    if suite["document_sha256"] != (record.get("suite") or {}).get("suite_sha256"):
        blockers.append(_blocker("EVIDENCE_OUT_OF_DATE", "The suite was changed after this run was recorded: its members or expected outcomes are not what was run",
                                 "Run the suite again and choose that run", ALL, suite=run["suite_code"], suite_revision_run=run["suite_revision"], suite_revision_now=suite["draft_revision"]))  # fmt: skip
    current = {str(r["id"]): r for r in _all(db, "SELECT id, code, draft_revision, document_sha256, snapshot_sha256 FROM applicability_scenario WHERE id = ANY(:i)", i=[x["scenario_id"] for x in rows])}  # fmt: skip
    for x in rows:
        now = current.get(str(x["scenario_id"]))
        if (
            now is None
            or now["document_sha256"] != x["scenario_document_sha256"]
            or now["snapshot_sha256"] != x["scenario_snapshot_sha256"]
        ):
            blockers.append(_blocker("EVIDENCE_OUT_OF_DATE", f"Scenario '{x['scenario_name']}' was changed after this run was recorded",
                                     "Run the suite again and choose that run", ALL, scenario=str(x["scenario_id"])))  # fmt: skip
    # … and at the exact REVISIONS the run recorded: a fingerprint that matches again is not enough
    seen = {(b["at"].get("suite"), b["at"].get("scenario")) for b in blockers if b["code"] == "EVIDENCE_OUT_OF_DATE"}
    blockers += [b for b in _revision_drift(db, run_id, "EVIDENCE_OUT_OF_DATE", "Run the suite again and choose that run", ALL) if (b["at"].get("suite"), b["at"].get("scenario")) not in seen]  # fmt: skip
    proof = sc.verify(db, markets, run_id)
    if not proof["reproduced"]:
        blockers.append(_blocker("EVIDENCE_NOT_REPRODUCIBLE", f"The run could not be reproduced from its own record ({proof['results_reproduced']} of {proof['results_checked']} results)",
                                 "Run the suite again; if it still cannot be reproduced, report it", ALL, mismatched=proof["mismatched_positions"]))  # fmt: skip
    indep = independence(record["policy"]["document"], rows)
    blockers += indep["blockers"]
    revisions = _recorded_revisions(db, run_id)[1]
    evidence = {
        "run_id": str(run_id), "run_sha256": stored["run_sha256"], "record_sha256": stored["record_sha256"], "status": run["status"], "recorded_at": run["created_at"].isoformat(timespec="seconds"),
        "recorded_by": run["display_name"] or run["created_by"], "suite_id": str(run["suite_id"]), "suite_code": run["suite_code"], "suite_name": run["suite_name"] or run["suite_code"],
        "suite_revision": run["suite_revision"], "suite_sha256": (record.get("suite") or {}).get("suite_sha256"), "suite_purpose": run["suite_purpose"],
        "policy_revision": run["policy_revision"], "policy_document_sha256": run["policy_document_sha256"], "policy_snapshot_sha256": run["policy_snapshot_sha256"],
        "scenarios": run["scenarios"], "passed": run["passed"], "failed": run["failed"], "coverage": cover, "reproduced": proof["reproduced"],
        "independence": {k: v for k, v in indep.items() if k != "blockers"}, "provenance": provenance(db, run, rows),
        "scenario_fingerprints": [{"scenario_id": str(x["scenario_id"]), "document": x["scenario_document_sha256"], "snapshot": x["scenario_snapshot_sha256"], "revision": revisions.get(str(x["scenario_id"]))} for x in rows],
    }  # fmt: skip
    return evidence, blockers


def _policy_blockers(insp: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Blockers and notices that come from the policy and its dependencies alone."""
    blockers, notices = [], []
    for e in insp["dependencies"]:
        word, at = e["kind"].lower(), {"kind": e["kind"].lower(), "code": e["code"]}
        if e.get("stale"):
            blockers.append(_blocker("DEPENDENCY_STALE", f"The {word} '{e.get('name') or e['code']}' was changed after this policy was saved against its draft revision {e.get('draft_revision')}",
                                     "Open the policy, review the change and accept it — or pin a published version — then save", ALL, **at, pinned=f"draft r{e.get('draft_revision')}", now=f"draft r{e.get('current_draft_revision')}"))  # fmt: skip
        elif e["state"] == "DRAFT":
            blockers.append(_blocker("UNPUBLISHED_DEPENDENCY", f"The {word} '{e.get('name') or e['code']}' is an unpublished draft (revision {e.get('draft_revision')}). A published policy reads published definitions only",
                                     f"Publish the {word} in the library (three people), then adopt the published version in the policy and save", ALL, **at, pinned=f"draft r{e.get('draft_revision')}"))  # fmt: skip
        if e.get("newer_version_no"):
            notices.append({"code": "SURVEY_NEWER_VERSION" if e["kind"] == "SURVEY" else "NEWER_VERSION", "at": at,
                            "message": f"The {word} '{e.get('name') or e['code']}' is pinned at version {e.get('label') or e['version_no']}; version {e['newer_version_no']} is now published. The pinned version was genuinely published and stays valid. Nothing is upgraded for you"})  # fmt: skip
    for d in insp["diagnostics"]:
        at = dict(d.get("at") or {})
        if d["code"] == "PIN_DIFFERS":
            blockers.append(_blocker("PIN_DIFFERS", d["message"] + ". The condition would mean something its approvers did not see",
                                     f"Either pin '{at.get('variable')}' to the version the condition was published with, or publish a new version of the condition against the version this policy uses and adopt it. There is no override", ALL, **at))  # fmt: skip
        elif d["code"] == "INVALID_SURVEY_REFERENCE":
            blockers.append(
                _blocker(
                    "INVALID_SURVEY_REFERENCE",
                    d["message"],
                    "Choose the survey again from the published surveys of Survey Studio and save",
                    ALL,
                    **at,
                )
            )
        elif d["code"] in ("UNKNOWN_REFERENCE", "INVALID_DEPENDENCY_PIN"):
            blockers.append(
                _blocker(
                    "UNPUBLISHED_DEPENDENCY",
                    d["message"],
                    "Refer to an item and a version that exist in the library, and save",
                    ALL,
                    **at,
                )
            )
        elif d["severity"] == "BLOCKER" and d["code"] not in ("STALE_DEPENDENCY",):
            blockers.append(
                _blocker(d["code"], d["message"], "Open the requirement in the designer and correct it", ALL, **at)
            )
    return blockers, notices


def _published(db: Session, policy_id: Any) -> dict[str, Any] | None:
    return _one(db, V_SQL + "WHERE v.policy_id = :p AND v.status = 'PUBLISHED'", p=policy_id)


def readiness(db: Session, markets: Sequence[str], policy_id: uuid.UUID, run_id: uuid.UUID | None = None, actor: Actor | None = None) -> dict[str, Any]:  # fmt: skip
    """Whether this saved policy revision can be submitted — and every reason why not. Writes nothing."""
    p = pol.policy_row(db, policy_id, markets)
    insp = pol.inspect(db, p, p["document"], p["snapshot"])
    blockers, notices = _policy_blockers(insp)
    if p["archived_at"] is not None:
        blockers.append(_blocker("ARCHIVED", "This policy is archived", "Restore it first", ALL))
    if not p["document"].get("requirements"):
        blockers.append(
            _blocker(
                "NO_REQUIREMENT",
                "This policy has no requirement: there is nothing to publish",
                "Add a requirement in the designer",
                ALL,
            )
        )
    evidence, more = _evidence(db, markets, p, insp["snapshot_sha256"], run_id)
    blockers += more
    opened = _one(db, "SELECT id, status, candidate_no FROM applicability_policy_candidate WHERE policy_id = :p AND status IN ('SUBMITTED', 'APPROVED')", p=policy_id)  # fmt: skip
    if opened:
        blockers.append(_blocker("CANDIDATE_OPEN", f"Candidate {opened['candidate_no']} of this policy is already {'submitted' if opened['status'] == 'SUBMITTED' else 'approved'} and waiting",
                                 "Wait for its decision or publication, or withdraw it", [SUBMIT], candidate=str(opened["id"])))  # fmt: skip
    runs = sc.runs(db, markets, policy_id=policy_id, limit=50)["items"]
    live = _published(db, policy_id)
    names = lib._names(db, [p["draft_updated_by"]])  # noqa: SLF001
    return {
        "policy_id": str(p["id"]), "policy_code": p["code"], "policy_name": p["document"].get("name") or p["code"], "market_code": p["market_code"], "draft_revision": p["draft_revision"],
        "document_sha256": p["document_sha256"], "manifest_sha256": insp["snapshot_sha256"], "policy_fingerprint": insp["policy_fingerprint"], "saved_by": names.get(str(p["draft_updated_by"])),
        "saved_at": p["draft_updated_at"].isoformat(timespec="seconds"),
        "ready": not [b for b in blockers if SUBMIT in b["prevents"]], "blockers": blockers, "notices": notices,
        "dependencies": [{k: e.get(k) for k in ("kind", "code", "name", "state", "version_no", "label", "draft_revision", "content_sha256", "manifest_sha256", "newer_version_no", "survey_status")} for e in insp["dependencies"]],
        "evidence": evidence,
        # the runs the author may choose from; the newest is NOT chosen for them
        "runs": [{k: r[k] for k in ("id", "status", "suite_code", "suite_name", "suite_purpose", "suite_revision", "policy_revision", "passed", "scenarios", "created_at", "created_by", "run_sha256", "target")}
                 | {"of_this_revision": r["policy_document_sha256"] == p["document_sha256"] and r["policy_snapshot_sha256"] == insp["snapshot_sha256"] and r["target"].get("kind") == "DRAFT"} for r in runs],
        "open_candidate": {"id": str(opened["id"]), "status": opened["status"], "candidate_no": opened["candidate_no"]} if opened else None,
        "published": {"id": str(live["id"]), "version_no": live["version_no"], "document_sha256": live["document_sha256"], "published_at": live["published_at"].isoformat(timespec="seconds")} if live else None,
        "you": _ref(actor) if actor else None,
    }  # fmt: skip


# ---------------------------------------------------------------------------------------------- the candidate
def _candidate_fingerprint(document_sha: str, manifest_sha: str, evidence: Mapping[str, Any], policy: Mapping[str, Any], revision: int) -> str:  # fmt: skip
    return sha256_hex({"contract": CANDIDATE_CONTRACT, "policy": str(policy["id"]), "market": policy["market_code"], "code": policy["code"], "draft_revision": revision,
                       "document": document_sha, "manifest": manifest_sha, "evidence": sha256_hex(evidence)})  # fmt: skip


def _event(db: Session, cid: Any, event: str, actor: Actor, comment: str = "", detail: Mapping[str, Any] | None = None) -> None:  # fmt: skip
    db.execute(text("INSERT INTO applicability_policy_candidate_event (candidate_id, event, actor_ref, comment, detail) VALUES (:c, :e, :a, :m, CAST(:d AS jsonb))"),
               {"c": cid, "e": event, "a": _ref(actor), "m": comment.strip(), "d": json.dumps(dict(detail or {}), default=str)})  # fmt: skip


def candidate_row(db: Session, cid: uuid.UUID, markets: Sequence[str], *, lock: bool = False) -> dict[str, Any]:
    c = _one(db, C_SQL + "WHERE c.id = :i" + (" FOR UPDATE OF c" if lock else ""), i=cid)
    if c is None or c["market_code"] not in markets:
        raise SurveyError(404, "NOT_FOUND", "No such policy candidate")
    return c


def version_row(db: Session, vid: uuid.UUID, markets: Sequence[str]) -> dict[str, Any]:
    v = _one(db, V_SQL + "WHERE v.id = :i", i=vid)
    if v is None or v["market_code"] not in markets:
        raise SurveyError(404, "NOT_FOUND", "No such published policy version")
    return v


def submit(db: Session, markets: Sequence[str], policy_id: uuid.UUID, expected_revision: int, run_id: uuid.UUID, acknowledged: Mapping[str, Any], note: str, actor: Actor, meta: RequestMeta | None = None) -> uuid.UUID:  # fmt: skip
    """Freeze an immutable candidate from the SAVED revision and the run the author chose and acknowledged. The working
    draft is not touched: it may move on afterwards without affecting the candidate."""
    p = pol.policy_row(db, policy_id, markets, lock=True)
    if expected_revision != p["draft_revision"]:
        raise _refuse("STALE_REVISION", "This policy was saved after you looked at its readiness; look again before submitting", details=[{"current_revision": p["draft_revision"]}])  # fmt: skip
    state = readiness(db, markets, policy_id, run_id, actor)
    stop = [b for b in state["blockers"] if SUBMIT in b["prevents"]]
    if stop:
        raise _refuse("PUBLICATION_BLOCKED", f"This policy cannot be submitted: {len(stop)} blocker{'' if len(stop) == 1 else 's'} remain", details=stop)  # fmt: skip
    evidence = state["evidence"]
    assert evidence is not None
    # the author confirms EXACTLY what they were shown: the manifest and the evidence run
    if (
        acknowledged.get("manifest_sha256") != state["manifest_sha256"]
        or acknowledged.get("document_sha256") != state["document_sha256"]
    ):
        raise _refuse("MANIFEST_CHANGED", "The policy or its dependencies are not what you acknowledged; review the manifest again", details=[{"manifest_sha256": state["manifest_sha256"], "document_sha256": state["document_sha256"]}])  # fmt: skip
    if acknowledged.get("run_sha256") != evidence["run_sha256"]:
        raise _refuse("EVIDENCE_CHANGED", "The evidence run is not the one you acknowledged", details=[{"run_sha256": evidence["run_sha256"]}])  # fmt: skip
    market = lib.Market(db, p["market_code"])
    res = pol.resolve(db, market, p["document"], p["snapshot"])
    snapshot = res.snapshot()
    live = _published(db, policy_id)
    manifest = {"contract": CANDIDATE_CONTRACT, "evaluator": CONTRACT, "snapshot": snapshot,
                "workspace": {k: [x for x in v if not x.get("scenario_context")] for k, v in res.workspace.items()}}  # fmt: skip
    evidence = {
        **evidence,
        "replaces_version": {
            "id": str(live["id"]),
            "version_no": live["version_no"],
            "document_sha256": live["document_sha256"],
        }
        if live
        else None,
    }
    manifest_sha = sha256_hex(snapshot)
    cid = uuid.uuid4()
    number = (_one(db, "SELECT coalesce(max(candidate_no), 0) + 1 AS n FROM applicability_policy_candidate WHERE policy_id = :p", p=policy_id) or {"n": 1})["n"]  # fmt: skip
    fingerprint = _candidate_fingerprint(p["document_sha256"], manifest_sha, evidence, p, p["draft_revision"])
    db.execute(
        text("INSERT INTO applicability_policy_candidate (id, policy_id, market_code, candidate_no, draft_revision, document, document_sha256, manifest, manifest_sha256, evidence, evidence_run_id, "
             "evidence_run_sha256, candidate_sha256, submitted_by, submission_note) VALUES (:i, :p, :m, :n, :r, CAST(:d AS jsonb), :dh, CAST(:mf AS jsonb), :mh, CAST(:e AS jsonb), :run, :rh, :ch, :by, :note)"),
        {"i": cid, "p": policy_id, "m": p["market_code"], "n": number, "r": p["draft_revision"], "d": json.dumps(p["document"]), "dh": p["document_sha256"], "mf": json.dumps(manifest), "mh": manifest_sha,
         "e": json.dumps(evidence, default=str), "run": run_id, "rh": evidence["run_sha256"], "ch": fingerprint, "by": _ref(actor), "note": note.strip()},
    )  # fmt: skip
    for e in snapshot["dependencies"]:
        survey = e["kind"] == "SURVEY"
        db.execute(
            text("INSERT INTO applicability_policy_candidate_dependency (candidate_id, kind, code, asset_id, asset_version_id, survey_definition_id, survey_version_id, version_no, content_sha256, manifest_sha256) "
                 "VALUES (:c, :k, :code, :a, :av, :sd, :sv, :n, :h, :m)"),
            {"c": cid, "k": e["kind"], "code": e["code"], "a": None if survey else uuid.UUID(e["asset_id"]), "av": None if survey else uuid.UUID(e["version_id"]),
             "sd": uuid.UUID(e["definition_id"]) if survey else None, "sv": uuid.UUID(e["version_id"]) if survey else None, "n": e["version_no"], "h": e["content_sha256"], "m": e["manifest_sha256"]},
        )  # fmt: skip
    _event(db, cid, "SUBMITTED", actor, note, {"candidate_sha256": fingerprint, "draft_revision": p["draft_revision"], "document_sha256": p["document_sha256"], "manifest_sha256": manifest_sha, "run_sha256": evidence["run_sha256"]})  # fmt: skip
    _audit(db, actor, meta, "APPLICABILITY.POLICY_SUBMITTED", CANDIDATE, cid, {"policy": str(policy_id), "candidate_no": number, "candidate_sha256": fingerprint, "run_sha256": evidence["run_sha256"]})  # fmt: skip
    return cid


def revalidate(db: Session, markets: Sequence[str], c: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The exact frozen candidate, checked again against what exists NOW. Nothing is refreshed, substituted or upgraded:
    if the evidence or a pinned version is no longer what was approved, the candidate cannot go further."""
    out: list[dict[str, Any]] = []
    again = "Withdraw or return this candidate; the author submits a new one with evidence that is valid now"
    policy = {"id": c["policy_id"], "market_code": c["market_code"], "code": c["policy_code"]}
    if sha256_hex(c["document"]) != c["document_sha256"] or sha256_hex(c["manifest"]["snapshot"]) != c["manifest_sha256"] or _candidate_fingerprint(c["document_sha256"], c["manifest_sha256"], c["evidence"], policy, c["draft_revision"]) != c["candidate_sha256"]:  # fmt: skip
        out.append(
            _blocker(
                "CANDIDATE_CORRUPTED",
                "The stored candidate does not match its own fingerprint",
                "Do not publish. Report it",
                [APPROVE, PUBLISH],
            )
        )
    for e in c["manifest"]["snapshot"].get("dependencies") or []:
        at = {"kind": e["kind"].lower(), "code": e["code"], "pinned": f"v{e['version_no']}"}
        if e["kind"] == "SURVEY":
            row = _one(db, "SELECT v.version_no, d.code, d.market_code, c.content_sha256, c.manifest_sha256, (SELECT x.event FROM survey_lifecycle_event x WHERE x.subject_id = v.id ORDER BY x.seq DESC LIMIT 1) AS event "
                           "FROM survey_version v JOIN survey_definition d ON d.id = v.survey_definition_id JOIN survey_candidate c ON c.id = v.candidate_id WHERE v.id = :i", i=uuid.UUID(e["version_id"]))  # fmt: skip
            good = row is not None and row["market_code"] == c["market_code"] and row["code"] == e["code"] and STATUS_OF_EVENT.get(str(row["event"])) in ("PUBLISHED", "SUPERSEDED") and row["content_sha256"] == e["content_sha256"] and row["manifest_sha256"] == e["manifest_sha256"]  # fmt: skip
        else:
            row = _one(db, "SELECT v.status, v.content_sha256, v.manifest_sha256, a.market_code FROM applicability_asset_version v JOIN applicability_asset a ON a.id = v.asset_id WHERE v.id = :i", i=uuid.UUID(e["version_id"]))  # fmt: skip
            good = row is not None and row["market_code"] == c["market_code"] and row["status"] in lib.WAS_PUBLISHED and row["content_sha256"] == e["content_sha256"] and row["manifest_sha256"] == e["manifest_sha256"]  # fmt: skip
        if not good:
            out.append(_blocker("DEPENDENCY_CHANGED", f"The pinned {e['kind'].lower()} '{e['code']}' version {e['version_no']} no longer resolves to the content that was approved", again, [APPROVE, PUBLISH], **at))  # fmt: skip
    ev = c["evidence"]
    run = _one(
        db, "SELECT run_sha256, suite_id FROM applicability_evaluation_run WHERE id = :i", i=c["evidence_run_id"]
    )
    if run is None or run["run_sha256"] != c["evidence_run_sha256"]:
        out.append(
            _blocker(
                "EVIDENCE_CHANGED", "The evidence run is not the one that was submitted", again, [APPROVE, PUBLISH]
            )
        )
    else:
        suite = _one(
            db,
            "SELECT document_sha256, draft_revision, archived_at FROM applicability_suite WHERE id = :i",
            i=run["suite_id"],
        )
        if suite is None or suite["document_sha256"] != ev["suite_sha256"]:
            out.append(_blocker("EVIDENCE_CHANGED", f"The evidence suite '{ev['suite_name']}' was changed after this candidate was submitted: its members or expected outcomes are no longer what was reviewed", again, [APPROVE, PUBLISH], suite=ev["suite_code"]))  # fmt: skip
        now = {str(r["id"]): r for r in _all(db, "SELECT id, code, document->>'name' AS name, document_sha256, snapshot_sha256 FROM applicability_scenario WHERE id = ANY(:i)", i=[uuid.UUID(x["scenario_id"]) for x in ev["scenario_fingerprints"]])}  # fmt: skip
        for x in ev["scenario_fingerprints"]:
            cur = now.get(x["scenario_id"])
            if cur is None or cur["document_sha256"] != x["document"] or cur["snapshot_sha256"] != x["snapshot"]:
                out.append(_blocker("EVIDENCE_CHANGED", f"Scenario '{(cur or {}).get('name') or x['scenario_id']}' of the evidence suite was changed after this candidate was submitted", again, [APPROVE, PUBLISH], scenario=x["scenario_id"]))  # fmt: skip
        # the exact revisions the run recorded — an item edited and put back is NOT the evidence that was reviewed
        named = {(b["at"].get("suite"), b["at"].get("scenario")) for b in out if b["code"] == "EVIDENCE_CHANGED"}
        out += [b for b in _revision_drift(db, c["evidence_run_id"], "EVIDENCE_CHANGED", again, [APPROVE, PUBLISH]) if (b["at"].get("suite"), b["at"].get("scenario")) not in named]  # fmt: skip
        proof = sc.verify(db, markets, c["evidence_run_id"])
        if not proof["reproduced"]:
            out.append(
                _blocker(
                    "EVIDENCE_NOT_REPRODUCIBLE",
                    "The evidence run can no longer be reproduced from its own record",
                    again,
                    [APPROVE, PUBLISH],
                )
            )
        _, rows = sc._stored(db, c["evidence_run_id"])  # noqa: SLF001
        out += [{**b, "prevents": [APPROVE, PUBLISH]} for b in independence(c["document"], rows)["blockers"]]
    return out


def _same_person(db: Session, c: Mapping[str, Any], actor: Actor, step: str, meta: RequestMeta | None) -> None:
    me = _ref(actor)
    clash = (
        "you submitted this candidate"
        if me == c["submitted_by"]
        else "you approved this candidate"
        if step == "publish" and me == c["decided_by"]
        else None
    )
    if clash:
        raise _refuse(
            "SAME_PERSON",
            f"You cannot {step} this candidate: {clash}. Submitting, approving and publishing are done by three different people",
        )


def decide(db: Session, markets: Sequence[str], cid: uuid.UUID, verdict: str, comment: str, expected_sha: str, actor: Actor, meta: RequestMeta | None = None) -> None:  # fmt: skip
    c = candidate_row(db, cid, markets, lock=True)
    if c["status"] != "SUBMITTED":
        raise _refuse(
            "NOT_SUBMITTED", f"This candidate is {c['status'].lower()}; only a submitted candidate can be decided"
        )
    _same_person(db, c, actor, "decide on", meta)
    if expected_sha != c["candidate_sha256"]:
        raise _refuse(
            "MANIFEST_CHANGED",
            "That is not the fingerprint of this candidate; review it again",
            details=[{"candidate_sha256": c["candidate_sha256"]}],
        )
    if verdict not in ("APPROVE", "RETURN"):
        raise SurveyError(422, "INVALID_VERDICT", "Approve or return")
    if verdict == "RETURN" and len(comment.strip()) < 10:
        raise SurveyError(422, "COMMENT_REQUIRED", "Say what must change, in at least 10 characters")
    if verdict == "APPROVE":
        stop = [b for b in revalidate(db, markets, c) if APPROVE in b["prevents"]]
        if stop:
            raise _refuse(
                "PUBLICATION_BLOCKED",
                f"This candidate cannot be approved: {len(stop)} problem{'' if len(stop) == 1 else 's'} found on revalidation",
                details=stop,
            )
    status = "APPROVED" if verdict == "APPROVE" else "RETURNED"
    db.execute(text("UPDATE applicability_policy_candidate SET status = :s, decided_by = :by, decided_at = now(), decision_comment = :c, closed_at = CASE WHEN :closed THEN now() ELSE NULL END WHERE id = :i"),
               {"s": status, "closed": status == "RETURNED", "by": _ref(actor), "c": comment.strip(), "i": cid})  # fmt: skip
    _event(
        db,
        cid,
        status,
        actor,
        comment,
        {"candidate_sha256": c["candidate_sha256"], "run_sha256": c["evidence_run_sha256"]},
    )
    _audit(
        db, actor, meta, f"APPLICABILITY.POLICY_{status}", CANDIDATE, cid, {"candidate_sha256": c["candidate_sha256"]}
    )


def withdraw(
    db: Session, markets: Sequence[str], cid: uuid.UUID, reason: str, actor: Actor, meta: RequestMeta | None = None
) -> None:
    c = candidate_row(db, cid, markets, lock=True)
    if c["status"] not in ("SUBMITTED", "APPROVED"):
        raise _refuse("NOT_OPEN", f"This candidate is {c['status'].lower()}; it cannot be withdrawn")
    if _ref(actor) != c["submitted_by"]:
        raise _refuse("NOT_SUBMITTER", "Only the person who submitted a candidate can withdraw it")
    if len(reason.strip()) < 10:
        raise SurveyError(422, "COMMENT_REQUIRED", "Say why, in at least 10 characters")
    db.execute(
        text("UPDATE applicability_policy_candidate SET status = 'WITHDRAWN', closed_at = now() WHERE id = :i"),
        {"i": cid},
    )
    _event(db, cid, "WITHDRAWN", actor, reason, {"candidate_sha256": c["candidate_sha256"]})
    _audit(
        db, actor, meta, "APPLICABILITY.POLICY_WITHDRAWN", CANDIDATE, cid, {"candidate_sha256": c["candidate_sha256"]}
    )


def publish(db: Session, markets: Sequence[str], cid: uuid.UUID, expected_sha: str, version_no: int, actor: Actor, meta: RequestMeta | None = None) -> uuid.UUID:  # fmt: skip
    """Publish the APPROVED candidate, after revalidating exactly it. The version is written from the candidate's own
    frozen document, manifest and evidence — the working draft is not read."""
    c = candidate_row(db, cid, markets, lock=True)
    if c["status"] != "APPROVED":
        raise _refuse(
            "NOT_APPROVED", f"This candidate is {c['status'].lower()}; only an approved candidate can be published"
        )
    _same_person(db, c, actor, "publish", meta)
    if expected_sha != c["candidate_sha256"]:
        raise _refuse(
            "MANIFEST_CHANGED",
            "That is not the fingerprint of the approved candidate",
            details=[{"candidate_sha256": c["candidate_sha256"]}],
        )
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"applicability-publish:{c['policy_id']}"})
    number = (_one(db, "SELECT coalesce(max(version_no), 0) + 1 AS n FROM applicability_policy_version WHERE policy_id = :p", p=c["policy_id"]) or {"n": 1})["n"]  # fmt: skip
    if version_no != number:
        raise _refuse(
            "VERSION_CHANGED",
            f"This would be version {number}, not version {version_no}; confirm it again",
            details=[{"version_no": number}],
        )
    stop = [b for b in revalidate(db, markets, c) if PUBLISH in b["prevents"]]
    if stop:
        raise _refuse("PUBLICATION_BLOCKED", f"This candidate cannot be published: {len(stop)} problem{'' if len(stop) == 1 else 's'} found on revalidation. Nothing was refreshed or substituted", details=stop)  # fmt: skip
    vid = uuid.uuid4()
    previous = _published(db, c["policy_id"])
    if previous:
        db.execute(
            text("UPDATE applicability_policy_version SET status = 'SUPERSEDED', superseded_at = now() WHERE id = :i"),
            {"i": previous["id"]},
        )
        _event(
            db,
            previous["candidate_id"],
            "SUPERSEDED",
            actor,
            f"Superseded by version {number}",
            {"version_no": previous["version_no"], "by_version": number},
        )
    db.execute(
        text(
            "UPDATE applicability_policy_candidate SET status = 'PUBLISHED', published_by = :by, published_at = now(), closed_at = now() WHERE id = :i"
        ),
        {"by": _ref(actor), "i": cid},
    )
    version_sha = sha256_hex({"candidate": c["candidate_sha256"], "version_no": number, "policy": str(c["policy_id"])})
    db.execute(
        text("INSERT INTO applicability_policy_version (id, policy_id, candidate_id, market_code, version_no, document, document_sha256, manifest, manifest_sha256, evidence, evidence_run_id, candidate_sha256, version_sha256, published_by) "
             "SELECT :v, c.policy_id, c.id, c.market_code, :n, c.document, c.document_sha256, c.manifest, c.manifest_sha256, c.evidence, c.evidence_run_id, c.candidate_sha256, :vh, c.published_by FROM applicability_policy_candidate c WHERE c.id = :i"),
        {"v": vid, "n": number, "vh": version_sha, "i": cid},
    )  # fmt: skip
    _event(db, cid, "PUBLISHED", actor, "", {"candidate_sha256": c["candidate_sha256"], "version_no": number, "version_sha256": version_sha, "run_sha256": c["evidence_run_sha256"], "supersedes": previous["version_no"] if previous else None})  # fmt: skip
    _audit(db, actor, meta, "APPLICABILITY.POLICY_PUBLISHED", VERSION, vid, {"policy": str(c["policy_id"]), "version_no": number, "candidate_sha256": c["candidate_sha256"], "run_sha256": c["evidence_run_sha256"]})  # fmt: skip
    return vid


def refused(
    db: Session,
    markets: Sequence[str],
    cid: uuid.UUID,
    step: str,
    exc: SurveyError,
    actor: Actor,
    meta: RequestMeta | None = None,
) -> None:
    """A refused decision or publication is part of the candidate's history: it is recorded in a transaction of its own,
    after the refused one was rolled back."""
    try:
        c = candidate_row(db, cid, markets)
    except SurveyError:
        return
    _event(db, cid, "REFUSED", actor, exc.message, {"step": step, "code": exc.code, "problems": [{"code": d.get("code"), "message": d.get("message")} for d in (exc.details or []) if isinstance(d, Mapping)][:20], "candidate_sha256": c["candidate_sha256"]})  # fmt: skip
    _audit(
        db,
        actor,
        meta,
        "APPLICABILITY.POLICY_TRANSITION_REFUSED",
        CANDIDATE,
        cid,
        {"step": step, "code": exc.code},
        outcome="DENIED",
        reason=exc.message[:200],
    )


# ------------------------------------------------------------------------------------------------ presenting
def _people(db: Session, rows: Sequence[Mapping[str, Any]], *keys: str) -> dict[str, str]:
    return lib._names(db, [r[k] for r in rows for k in keys if r.get(k)])  # noqa: SLF001


def _candidate_summary(c: Mapping[str, Any], names: Mapping[str, str]) -> dict[str, Any]:
    ev = c["evidence"]
    return {
        "id": str(c["id"]), "policy_id": str(c["policy_id"]), "policy_code": c["policy_code"], "policy_name": c["document"].get("name") or c["policy_code"], "market_code": c["market_code"],
        "candidate_no": c["candidate_no"], "status": c["status"], "draft_revision": c["draft_revision"], "document_sha256": c["document_sha256"], "manifest_sha256": c["manifest_sha256"],
        "candidate_sha256": c["candidate_sha256"], "evidence_run_id": str(c["evidence_run_id"]), "evidence_run_sha256": c["evidence_run_sha256"],
        "evidence_suite": ev["suite_name"], "evidence_recorded_at": ev["recorded_at"], "requirements": len(c["document"].get("requirements") or []),
        "submitted_by": names.get(str(c["submitted_by"]), str(c["submitted_by"])), "submitted_by_ref": str(c["submitted_by"]), "submitted_at": c["submitted_at"], "submission_note": c["submission_note"],
        "decided_by": names.get(str(c["decided_by"]), str(c["decided_by"])) if c["decided_by"] else None, "decided_by_ref": str(c["decided_by"]) if c["decided_by"] else None, "decided_at": c["decided_at"],
        "decision_comment": c["decision_comment"], "published_by": names.get(str(c["published_by"]), str(c["published_by"])) if c["published_by"] else None, "published_at": c["published_at"],
    }  # fmt: skip


def candidates(db: Session, markets: Sequence[str], *, policy_id: uuid.UUID | None = None, status: str | None = None, limit: int = 50, offset: int = 0) -> dict[str, Any]:  # fmt: skip
    where = "WHERE c.market_code = ANY(:m) AND (CAST(:p AS uuid) IS NULL OR c.policy_id = :p) AND (CAST(:s AS text) IS NULL OR c.status = :s) "
    args = {"m": list(markets), "p": policy_id, "s": status}
    total = (_one(db, "SELECT count(*) AS n FROM applicability_policy_candidate c " + where, **args) or {"n": 0})["n"]
    rows = _all(
        db,
        C_SQL + where + "ORDER BY c.submitted_at DESC, c.id LIMIT :l OFFSET :o",
        **args,
        l=max(1, min(limit, 100)),
        o=max(0, offset),
    )
    names = _people(db, rows, "submitted_by", "decided_by", "published_by")
    return {
        "items": [_candidate_summary(c, names) for c in rows],
        "total": total,
        "limit": max(1, min(limit, 100)),
        "offset": max(0, offset),
    }


def _selection(doc: Mapping[str, Any]) -> list[dict[str, Any]]:
    """What the policy says, requirement by requirement — for a reviewer who reads the candidate, not the designer."""
    out = []
    for r in doc.get("requirements") or []:
        action = r.get("action") or {}
        surveys = action.get("surveys") or [a.get("survey") for a in action.get("alternatives") or []]
        out.append({"id": str(r.get("id")), "name": r.get("name") or str(r.get("id")), "kind": action.get("kind") or "INCLUDE", "replaces": [str(x) for x in r.get("replaces") or []],
                    "surveys": [{"code": s.get("code"), "name": s.get("name"), "version": s.get("version"), "label": s.get("label"), "fingerprint": s.get("fingerprint"), "version_id": s.get("version_id")} for s in surveys if isinstance(s, Mapping)]})  # fmt: skip
    return out


def candidate_detail(db: Session, markets: Sequence[str], cid: uuid.UUID, actor: Actor | None = None) -> dict[str, Any]:
    c = candidate_row(db, cid, markets)
    names = _people(db, [c], "submitted_by", "decided_by", "published_by")
    events = _all(db, "SELECT e.seq, e.event, e.actor_ref, e.comment, e.detail, e.occurred_at, pr.display_name FROM applicability_policy_candidate_event e LEFT JOIN principal pr ON CAST(pr.id AS text) = e.actor_ref WHERE e.candidate_id = :c ORDER BY e.seq", c=cid)  # fmt: skip
    version = _one(db, "SELECT id, version_no, status FROM applicability_policy_version WHERE candidate_id = :c", c=cid)
    live = _published(db, c["policy_id"])
    me = _ref(actor) if actor else None
    out = _candidate_summary(c, names)
    out.update({
        "document": c["document"], "selection": _selection(c["document"]), "dependencies": c["manifest"]["snapshot"].get("dependencies") or [], "evidence": c["evidence"],
        "revalidation": revalidate(db, markets, c) if c["status"] in ("SUBMITTED", "APPROVED") else [],
        "events": [{"seq": e["seq"], "event": e["event"], "actor": e["display_name"] or e["actor_ref"], "comment": e["comment"], "detail": e["detail"], "occurred_at": e["occurred_at"]} for e in events],
        "version": {"id": str(version["id"]), "version_no": version["version_no"], "status": version["status"]} if version else None,
        "next_version_no": (_one(db, "SELECT coalesce(max(version_no), 0) + 1 AS n FROM applicability_policy_version WHERE policy_id = :p", p=c["policy_id"]) or {"n": 1})["n"],
        "published_now": {"id": str(live["id"]), "version_no": live["version_no"]} if live else None,
        # what THIS person may do with it — the server's answer, from their identity, not from a role switch
        "you_submitted": me == str(c["submitted_by"]), "you_decided": bool(c["decided_by"]) and me == str(c["decided_by"]),
    })  # fmt: skip
    return out


def _version_summary(v: Mapping[str, Any], names: Mapping[str, str]) -> dict[str, Any]:
    return {
        "id": str(v["id"]), "policy_id": str(v["policy_id"]), "policy_code": v["policy_code"], "policy_name": v["document"].get("name") or v["policy_code"], "market_code": v["market_code"],
        "version_no": v["version_no"], "status": v["status"], "candidate_id": str(v["candidate_id"]), "document_sha256": v["document_sha256"], "manifest_sha256": v["manifest_sha256"],
        "candidate_sha256": v["candidate_sha256"], "version_sha256": v["version_sha256"], "evidence_run_id": str(v["evidence_run_id"]), "evidence_run_sha256": v["evidence"]["run_sha256"],
        "requirements": len(v["document"].get("requirements") or []), "published_by": names.get(str(v["published_by"]), str(v["published_by"])), "published_at": v["published_at"], "superseded_at": v["superseded_at"],
    }  # fmt: skip


def versions(db: Session, markets: Sequence[str], policy_id: uuid.UUID) -> dict[str, Any]:
    pol.policy_row(db, policy_id, markets)
    rows = _all(db, V_SQL + "WHERE v.policy_id = :p ORDER BY v.version_no DESC", p=policy_id)
    names = _people(db, rows, "published_by")
    return {"items": [_version_summary(v, names) for v in rows]}


def version_detail(db: Session, markets: Sequence[str], vid: uuid.UUID) -> dict[str, Any]:
    v = version_row(db, vid, markets)
    c = candidate_row(db, v["candidate_id"], markets)
    names = _people(db, [v, c], "published_by", "submitted_by", "decided_by")
    events = _all(db, "SELECT e.seq, e.event, e.actor_ref, e.comment, e.detail, e.occurred_at, pr.display_name FROM applicability_policy_candidate_event e LEFT JOIN principal pr ON CAST(pr.id AS text) = e.actor_ref WHERE e.candidate_id = :c ORDER BY e.seq", c=v["candidate_id"])  # fmt: skip
    out = _version_summary(v, names)
    out.update({
        "document": v["document"], "selection": _selection(v["document"]), "dependencies": v["manifest"]["snapshot"].get("dependencies") or [], "evidence": v["evidence"],
        "submitted_by": names.get(str(c["submitted_by"]), str(c["submitted_by"])), "submitted_at": c["submitted_at"], "approved_by": names.get(str(c["decided_by"]), str(c["decided_by"])), "approved_at": c["decided_at"],
        "draft_revision": c["draft_revision"],
        "events": [{"seq": e["seq"], "event": e["event"], "actor": e["display_name"] or e["actor_ref"], "comment": e["comment"], "detail": e["detail"], "occurred_at": e["occurred_at"]} for e in events],
    })  # fmt: skip
    return out


def verify_version(db: Session, markets: Sequence[str], vid: uuid.UUID) -> dict[str, Any]:
    """A published version checked against itself: its fingerprints, its candidate, and its evidence run re-evaluated
    from the run's own record."""
    v = version_row(db, vid, markets)
    c = candidate_row(db, v["candidate_id"], markets)
    policy = {"id": v["policy_id"], "market_code": v["market_code"], "code": v["policy_code"]}
    intact = (sha256_hex(v["document"]) == v["document_sha256"] and sha256_hex(v["manifest"]["snapshot"]) == v["manifest_sha256"]
              and _candidate_fingerprint(v["document_sha256"], v["manifest_sha256"], v["evidence"], policy, c["draft_revision"]) == v["candidate_sha256"]
              and v["version_sha256"] == sha256_hex({"candidate": v["candidate_sha256"], "version_no": v["version_no"], "policy": str(v["policy_id"])}))  # fmt: skip
    same = (c["document"], c["manifest"], c["evidence"], c["candidate_sha256"]) == (
        v["document"],
        v["manifest"],
        v["evidence"],
        v["candidate_sha256"],
    )
    proof = sc.verify(db, markets, v["evidence_run_id"])
    return {"version_id": str(vid), "version_no": v["version_no"], "status": v["status"], "fingerprints_intact": intact, "identical_to_candidate": same,
            "evidence_reproduced": proof["reproduced"], "results_checked": proof["results_checked"], "results_reproduced": proof["results_reproduced"],
            "verified": intact and same and proof["reproduced"], "note": "The version was checked against its own stored content and its evidence run was re-evaluated from the run's record. The library was not read."}  # fmt: skip


def usage(
    db: Session, markets: Sequence[str], *, kind: str | None = None, code: str | None = None
) -> list[dict[str, Any]]:
    """Which published policy versions (current or superseded) pin a library item or a survey, and at which version."""
    rows = _all(
        db,
        "SELECT v.id, v.version_no, v.status, p.code AS policy_code, p.document->>'name' AS policy_name, d.kind, d.code, d.version_no AS pinned, d.content_sha256 FROM applicability_policy_candidate_dependency d "
        "JOIN applicability_policy_version v ON v.candidate_id = d.candidate_id JOIN applicability_policy p ON p.id = v.policy_id WHERE v.market_code = ANY(:m) AND (CAST(:k AS text) IS NULL OR d.kind = :k) "
        "AND (CAST(:c AS text) IS NULL OR lower(d.code) = lower(:c)) ORDER BY p.code, v.version_no DESC, d.kind, d.code",
        m=list(markets), k=kind, c=code,
    )  # fmt: skip
    return [{"version_id": str(r["id"]), "policy_code": r["policy_code"], "policy_name": r["policy_name"] or r["policy_code"], "version_no": r["version_no"], "status": r["status"],
             "kind": r["kind"], "code": r["code"], "pinned_version_no": r["pinned"], "content_sha256": r["content_sha256"]} for r in rows]  # fmt: skip


# ------------------------------------------------------------------------------------ run targets and impact
def targets(db: Session, markets: Sequence[str], policy_id: uuid.UUID) -> dict[str, Any]:
    """Everything a suite run of this policy can be aimed at, each with its status and fingerprints. When more than the
    working draft exists, the person must choose: nothing is chosen for them."""
    p = pol.policy_row(db, policy_id, markets)
    out = [{"kind": "DRAFT", "id": None, "label": f"Saved working draft · revision {p['draft_revision']}", "status": "DRAFT", "revision": p["draft_revision"], "version_no": None,
            "document_sha256": p["document_sha256"], "manifest_sha256": p["snapshot_sha256"]}]  # fmt: skip
    for c in _all(
        db,
        C_SQL + "WHERE c.policy_id = :p AND c.status IN ('SUBMITTED', 'APPROVED') ORDER BY c.candidate_no DESC",
        p=policy_id,
    ):
        out.append({"kind": "CANDIDATE", "id": str(c["id"]), "label": f"Candidate {c['candidate_no']} · {c['status'].lower()} · frozen from revision {c['draft_revision']}", "status": c["status"],
                    "revision": c["draft_revision"], "version_no": None, "document_sha256": c["document_sha256"], "manifest_sha256": c["manifest_sha256"]})  # fmt: skip
    for v in _all(db, V_SQL + "WHERE v.policy_id = :p ORDER BY v.version_no DESC", p=policy_id):
        out.append({"kind": "VERSION", "id": str(v["id"]), "label": f"Published version {v['version_no']}" + ("" if v["status"] == "PUBLISHED" else " · superseded"), "status": v["status"],
                    "revision": None, "version_no": v["version_no"], "document_sha256": v["document_sha256"], "manifest_sha256": v["manifest_sha256"]})  # fmt: skip
    return {"policy_id": str(policy_id), "items": out, "must_choose": len(out) > 1}


def _frozen(db: Session, markets: Sequence[str], policy: Mapping[str, Any], target: Mapping[str, Any]) -> tuple[sc.Evaluator, dict[str, Any], Mapping[str, Any], str, int]:  # fmt: skip
    """The evaluator of one explicit target, and how that target is recorded."""
    kind = str(target.get("kind") or "")
    if kind == "DRAFT":
        if target.get("revision") is not None and int(target["revision"]) != policy["draft_revision"]:
            raise _refuse("STALE_TARGET", f"The working draft is now at revision {policy['draft_revision']}, not {target['revision']}; choose the target again", details=[{"current_revision": policy["draft_revision"]}])  # fmt: skip
        ev = sc.Evaluator(db, policy, policy["document"], policy["snapshot"], source="SAVED")
        rec = {
            "kind": "DRAFT",
            "revision": policy["draft_revision"],
            "document_sha256": policy["document_sha256"],
            "manifest_sha256": sha256_hex(ev.snapshot),
        }
        return ev, rec, policy["document"], policy["document_sha256"], policy["draft_revision"]
    try:
        tid = uuid.UUID(str(target.get("id")))
    except ValueError as exc:
        raise SurveyError(422, "INVALID_TARGET", "Name the candidate or the published version to evaluate") from exc
    if kind == "CANDIDATE":
        row: Mapping[str, Any] = candidate_row(db, tid, markets)
        rec = {
            "kind": "CANDIDATE",
            "id": str(tid),
            "candidate_no": row["candidate_no"],
            "status": row["status"],
            "revision": row["draft_revision"],
        }
        revision = row["draft_revision"]
    elif kind == "VERSION":
        row = version_row(db, tid, markets)
        rec = {"kind": "VERSION", "id": str(tid), "version_no": row["version_no"], "status": row["status"]}
        revision = candidate_row(db, row["candidate_id"], markets)["draft_revision"]
    else:
        raise SurveyError(
            422, "INVALID_TARGET", "A run evaluates the working draft, a candidate or a published version"
        )
    if row["policy_id"] != policy["id"]:
        raise _refuse("OTHER_POLICY", "That candidate or version belongs to another policy", 422)
    ev = sc.Evaluator.frozen(db, policy, row["document"], row["manifest"], source="FROZEN")
    rec |= {"document_sha256": row["document_sha256"], "manifest_sha256": row["manifest_sha256"]}
    return ev, rec, row["document"], row["document_sha256"], revision


def run_subject(
    db: Session, markets: Sequence[str], suite_id: uuid.UUID, target: Mapping[str, Any] | None
) -> sc.Subject | None:
    """What a suite run evaluates. Once a candidate or a published version exists the person MUST say which target —
    the working draft is not assumed (owner ruling Q-h)."""
    suite = sc.suite_row(db, suite_id, markets)
    policy = pol.policy_row(db, suite["policy_id"], markets)
    options = targets(db, markets, policy["id"])
    if target is None:
        if options["must_choose"]:
            raise SurveyError(422, "TARGET_REQUIRED", "This policy has a candidate or a published version. Say exactly what this run evaluates: the saved working draft, the candidate, or a published version", [{"targets": options["items"]}])  # fmt: skip
        return None
    ev, rec, doc, sha, revision = _frozen(db, markets, policy, target)
    return (
        None
        if rec["kind"] == "DRAFT"
        else sc.Subject(evaluator=ev, revision=revision, document=doc, document_sha256=sha, target=rec)
    )


def impact(db: Session, markets: Sequence[str], policy_id: uuid.UUID, dataset_run_id: uuid.UUID, before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:  # fmt: skip
    """What changes between two exact targets of one policy, over ONE fixed dataset: the scenarios of a recorded run,
    exactly as they were recorded, evaluated on both sides. The dataset is never different on the two sides. Nothing
    is recorded."""
    policy = pol.policy_row(db, policy_id, markets)
    run = sc.run_row(db, dataset_run_id, markets)
    if run["policy_id"] != policy_id:
        raise _refuse("OTHER_POLICY", "The dataset must be a recorded run of this policy", 422)
    _, rows = sc._stored(db, dataset_run_id)  # noqa: SLF001
    sides = []
    for target in (before, after):
        ev, rec, doc, _sha, _rev = _frozen(db, markets, policy, target)
        out = []
        for x in rows:
            row: dict[str, Any] = {"state": "EVALUATED", "plan": None}
            if ev.blocked:
                row["state"] = "COULD_NOT_EVALUATE"
            else:
                frozen = sc.Resolved()
                frozen.profiles = {p_["code"]: p_ for p_ in (x["actual"] or {}).get("profiles") or []}
                row = ev.plan(row, sc._workspace(ev.res.workspace, frozen), x["scenario_document"])  # noqa: SLF001
            plan = row["plan"]
            outcome = (
                "COULD_NOT_EVALUATE"
                if row["state"] != "EVALUATED" or plan is None
                else "NO_EXPECTATION"
                if x["expectation"] is None
                else "FAILED"
                if sc.check(x["expectation"], plan)
                else "PASSED"
            )
            out.append({**x, "plan": plan, "plan_fingerprint": (plan or {}).get("fingerprint"), "outcome": outcome})
        sides.append(
            (
                rec
                | {
                    "evaluable": not ev.blocked,
                    "reason": (ev.reasons[0]["message"] if ev.blocked and ev.reasons else None),
                    "policy_fingerprint": ev.fingerprint,
                },
                out,
                ev,
                doc,
            )
        )
    (ra, xa, ea, da), (rb, xb, eb, db_) = sides
    pairs = sc._pairs(xa, xb)  # noqa: SLF001
    ids_a, ids_b = (
        {str(r.get("id")): r for r in da.get("requirements") or []},
        {str(r.get("id")): r for r in db_.get("requirements") or []},
    )
    return {
        "policy_id": str(policy_id), "before": ra, "after": rb,
        "dataset": {"run_id": str(dataset_run_id), "suite_name": run["suite_name"] or run["suite_code"], "scenarios": len(rows), "recorded_at": run["created_at"].isoformat(timespec="seconds"), "run_sha256": run["run_sha256"]},
        "reproducible": bool(ra["evaluable"] and rb["evaluable"]),
        "why_not_reproducible": None if ra["evaluable"] and rb["evaluable"] else "One side cannot be evaluated: " + str(ra["reason"] or rb["reason"]),
        "document_changed": ra["document_sha256"] != rb["document_sha256"], "dependency_changes": sc._dependency_changes(ea.snapshot, eb.snapshot),  # noqa: SLF001
        "requirements_added": [ids_b[k].get("name") or k for k in ids_b if k not in ids_a], "requirements_removed": [ids_a[k].get("name") or k for k in ids_a if k not in ids_b],
        "requirements_changed": [ids_b[k].get("name") or k for k in ids_b if k in ids_a and ids_a[k] != ids_b[k]],
        "scope_changed": da.get("scope") != db_.get("scope"), **pairs,
        "note": "Both sides were evaluated now on the SAME recorded scenarios; nothing was recorded.",
    }  # fmt: skip
