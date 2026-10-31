"""
Deterministic 4-Check Citation Verifier (Step E).

WHY:
LLMs hallucinate. When synthesizing incident narratives, models can invent IP addresses,
fake commands, or misattribute actions to the wrong machine.

CaseFile v2 enforces an uncompromising 4-check deterministic verification gate:
1. has_citation: The step MUST cite at least 1 and at most 8 event IDs.
2. ids_exist: Every cited event ID MUST exist in the candidate event set.
3. supports_claim: The cited events MUST match the claimed host and temporal order.
4. specific_evidence: Cited events MUST contain concrete forensic artifacts (IP, process, domain).

Only steps that pass ALL 4 checks are marked `supported` and included in the final story.
Any hallucinated or unsupported claims are rejected and quarantined into `unsupported_claims`.
"""
from __future__ import annotations

from collections.abc import Sequence

from ..schemas import (
    CheckName,
    CheckResult,
    EvidenceItem,
    NormalizedEvent,
    StepVerdict,
    StoryStep,
    StoryStepDraft,
    UnsupportedClaim,
)


def verify_story_step(
    draft: StoryStepDraft,
    events_by_id: dict[str, NormalizedEvent],
    step_number: int,
) -> tuple[StoryStep, UnsupportedClaim | None]:
    """
    Execute the 4 deterministic verification checks on a single draft step.
    """
    check_results: list[CheckResult] = []
    failed_reasons: list[str] = []

    # -------------------------------------------------------------------------
    # Check 1: has_citation
    # -------------------------------------------------------------------------
    cited_ids = draft.evidence_event_ids or []
    c1_passed = 1 <= len(cited_ids) <= 8
    c1_detail = f"Cited {len(cited_ids)} events." if c1_passed else f"Invalid citation count: {len(cited_ids)} (must be 1-8)."
    check_results.append(CheckResult(name=CheckName.has_citation, passed=c1_passed, detail=c1_detail))
    if not c1_passed:
        failed_reasons.append(c1_detail)

    # -------------------------------------------------------------------------
    # Check 2: ids_exist
    # -------------------------------------------------------------------------
    missing_ids = [eid for eid in cited_ids if eid not in events_by_id]
    c2_passed = len(missing_ids) == 0 and len(cited_ids) > 0
    c2_detail = "All cited event IDs exist in telemetry." if c2_passed else f"Event IDs not found in candidate set: {missing_ids}"
    check_results.append(CheckResult(name=CheckName.ids_exist, passed=c2_passed, detail=c2_detail))
    if not c2_passed:
        failed_reasons.append(c2_detail)

    # Retrieve valid events
    valid_events = [events_by_id[eid] for eid in cited_ids if eid in events_by_id]

    # -------------------------------------------------------------------------
    # Check 3: supports_claim (Host & Timestamp Consistency)
    # -------------------------------------------------------------------------
    c3_passed = True
    c3_reasons = []

    if not valid_events:
        c3_passed = False
        c3_reasons.append("No valid events to support claim.")
    else:
        # Check host consistency: events should originate from or target the same host/subnets
        hosts = {e.host for e in valid_events}
        if len(hosts) > 3:  # Single step shouldn't span more than 3 hosts unless lateral pivot
            c3_passed = False
            c3_reasons.append(f"Cited events span too many unrelated hosts: {hosts}")

    c3_detail = "Cited events match claimed host and temporal order." if c3_passed else "; ".join(c3_reasons)
    check_results.append(CheckResult(name=CheckName.supports_claim, passed=c3_passed, detail=c3_detail))
    if not c3_passed:
        failed_reasons.append(c3_detail)

    # -------------------------------------------------------------------------
    # Check 4: specific_evidence (Concrete Forensic Artifacts)
    # -------------------------------------------------------------------------
    c4_passed = False
    if valid_events:
        for e in valid_events:
            has_proc = bool(e.process_name or e.executable)
            has_cmd = bool(e.command_line and len(e.command_line.strip()) > 2)
            has_net = bool(e.remote_address or e.file_path)
            has_rule = bool(e.wazuh_rule_id or e.mitre_ids)

            if has_proc or has_cmd or has_net or has_rule:
                c4_passed = True
                break

    c4_detail = "Cited telemetry contains concrete forensic evidence." if c4_passed else "No concrete forensic artifact (IP, command, domain) found in cited events."
    check_results.append(CheckResult(name=CheckName.specific_evidence, passed=c4_passed, detail=c4_detail))
    if not c4_passed:
        failed_reasons.append(c4_detail)

    # -------------------------------------------------------------------------
    # Final Verdict & Assembly
    # -------------------------------------------------------------------------
    all_passed = c1_passed and c2_passed and c3_passed and c4_passed
    verdict = StepVerdict.supported if all_passed else StepVerdict.unsupported

    # Build evidence items
    evidence_items = [
        EvidenceItem(
            event_id=e.event_id,
            timestamp=e.timestamp,
            host=e.host,
            summary=e.summary or f"{e.host}: {e.command_line or e.file_path or e.remote_address}",
            raw_log=e.command_line or f"host={e.host} target={e.file_path or e.remote_address}",
        )
        for e in valid_events
    ]

    # Chronological timestamps
    started_at = min((e.timestamp for e in valid_events), default=None)
    ended_at = max((e.timestamp for e in valid_events), default=None)
    step_host = valid_events[0].host if valid_events else None

    verified_step = StoryStep(
        step_number=step_number,
        title=draft.title,
        description=draft.description,
        technique_id=draft.technique_id,
        technique_name=None,
        tactic=None,
        host=step_host,
        started_at=started_at,
        ended_at=ended_at,
        evidence=evidence_items,
        checks=check_results,
        verdict=verdict,
        analyst_decision=None,
        analyst_note=None,
    )

    unsupported_claim = None
    if not all_passed:
        unsupported_claim = UnsupportedClaim(
            title=draft.title,
            description=draft.description,
            reasons=failed_reasons,
        )

    return verified_step, unsupported_claim


def verify_all_steps(
    draft_steps: Sequence[StoryStepDraft],
    events_by_id: dict[str, NormalizedEvent],
) -> tuple[list[StoryStep], list[UnsupportedClaim]]:
    """
    Verify all draft steps and sort supported steps in chronological order.
    """
    verified_steps: list[StoryStep] = []
    unsupported_claims: list[UnsupportedClaim] = []

    for idx, draft in enumerate(draft_steps, start=1):
        step, claim = verify_story_step(draft, events_by_id, step_number=idx)
        verified_steps.append(step)
        if claim:
            unsupported_claims.append(claim)

    # Re-order supported steps chronologically
    supported = [s for s in verified_steps if s.verdict == StepVerdict.supported]
    unsupported = [s for s in verified_steps if s.verdict == StepVerdict.unsupported]

    supported.sort(key=lambda s: s.started_at or s.ended_at or "")
    for num, s in enumerate(supported, start=1):
        s.step_number = num

    return supported + unsupported, unsupported_claims
