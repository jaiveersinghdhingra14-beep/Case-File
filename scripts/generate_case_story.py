#!/usr/bin/env python3
"""
CLI Tool to run the complete End-to-End Incident Reconstruction & Story Verification Pipeline (Step E).

Usage:
    python scripts/generate_case_story.py ds_46a8444f
    python scripts/generate_case_story.py
"""
import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.schemas import (
    Case,
    CaseStats,
    CaseStatus,
    Method,
    Story,
    StoryStatus,
)
from backend.app.services.correlator import correlate_incident_paths
from backend.app.services.expander import expand_neighborhood
from backend.app.services.reducer import get_top_k_seeds
from backend.app.services.story_writer import write_story_for_events
from backend.app.services.verifier import verify_all_steps
from backend.app.store import db


def main():
    parser = argparse.ArgumentParser(description="Run End-to-End Case & Verified Attack Story Pipeline.")
    parser.add_argument("dataset_id", nargs="?", default="", help="Dataset ID (e.g. ds_46a8444f). Picks latest ready if omitted.")
    parser.add_argument("--top-k", type=int, default=30, help="Top-K anomaly seeds (default: 30)")
    parser.add_argument("--chunk-size", type=int, default=20, help="Events per LLM chunk (default: 20)")
    args = parser.parse_args()

    db.init_db()
    ds_id = args.dataset_id

    if not ds_id:
        ready = [d for d in db.list_datasets() if d.status == "ready"]
        if not ready:
            print("[ERROR] No ready datasets found. Run scripts/ingest_file.py first.", file=sys.stderr)
            sys.exit(1)
        ds_id = ready[-1].dataset_id

    ds = db.get_dataset(ds_id)
    if not ds:
        print(f"[ERROR] Dataset {ds_id} not found.", file=sys.stderr)
        sys.exit(1)

    print("=" * 80)
    print("   CaseFile v2 - Complete End-to-End Incident Story Pipeline (Step E)")
    print("=" * 80)
    print(f"Dataset ID     : {ds.dataset_id}")
    print(f"Dataset Name   : {ds.name}")
    print(f"Events Ingested: {ds.events_total:,}")
    print(f"Log Format     : {ds.format.upper()}")

    # 1. Create Case
    case_id = db.generate_id("case_")
    now = datetime.now(timezone.utc)
    print(f"\n[1/4] Initializing Case {case_id}...")

    case = Case(
        case_id=case_id,
        dataset_id=ds_id,
        name=f"Autonomous Investigation {case_id}",
        status=CaseStatus.correlating,
        created_at=now,
        updated_at=now,
        window=None,
        has_ground_truth=False,
        stats=None,
        error_message=None,
    )
    db.save_case(case)

    # 2. Mathematical Reduction & Expansion
    t0 = time.perf_counter()
    print(f"\n[2/4] Noise Reduction (Top-{args.top_k} Seeds) & 2-Hop Graph Expansion...")
    seeds = get_top_k_seeds(ds_id, top_k=args.top_k, min_rarity_score=0.1)
    expanded = expand_neighborhood(ds_id, seeds, window_seconds=120, max_expanded_events=2000)
    events_by_id = {e.event_id: e for e in expanded}

    # 3. Correlate Attack Paths
    incidents = correlate_incident_paths(ds_id, expanded, all_known_hosts=ds.hosts)
    for inc in incidents:
        db.save_incident(inc)

    comp_hosts = sorted({e.host for e in expanded})
    sources = sorted({e.source for e in expanded})
    case.stats = CaseStats(
        events_ingested=ds.events_total,
        events_after_noise_filter=len(expanded),
        noise_removed=max(0, ds.events_total - len(expanded)),
        groups=len(incidents),
        hosts=comp_hosts[:25],
        sources=sources,
    )
    case.status = CaseStatus.ready
    case.updated_at = datetime.now(timezone.utc)
    db.save_case(case)

    t_corr = time.perf_counter() - t0
    print(f"  Incident Campaigns Identified: {len(incidents)}")
    print(f"  Candidate Evidence Subgraph  : {len(expanded)} events (Pruned {case.stats.noise_removed:,} noise)")
    print(f"  Correlation Execution Time   : {t_corr:.3f}s")

    # 4. Synthesize Story & Run 4-Check Verifier
    print(f"\n[3/4] Synthesizing Attack Narrative (Bounded Chunks <= {args.chunk_size}) & 4-Check Verification...")
    t1 = time.perf_counter()
    draft, usage = write_story_for_events(expanded, chunk_size=args.chunk_size)
    verified_steps, unsupported = verify_all_steps(draft.steps, events_by_id)
    t_story = time.perf_counter() - t1

    supported_count = sum(1 for s in verified_steps if s.verdict == "supported")
    story_id = db.generate_id("story_")

    story = Story(
        story_id=story_id,
        case_id=case_id,
        method=Method.casefile,
        status=StoryStatus.awaiting_review,
        created_at=now,
        updated_at=datetime.now(timezone.utc),
        model_name="gemini-2.0-flash" if not db.settings.USE_MOCK_LLM else "MockLLM-Verified",
        attempts_used=1,
        max_attempts=3,
        summary=draft.summary,
        steps=verified_steps,
        unsupported_claims=unsupported,
        assumptions=draft.assumptions,
        usage=usage,
        duration_seconds=round(t_story, 2),
        evaluation_id=None,
        review_outcome=None,
        failure_reason=None,
    )
    db.save_story(story)

    print(f"  Story ID Generated  : {story_id}")
    print(f"  Supported Steps     : {supported_count} (Verified with forensic citations)")
    print(f"  Rejected/Hallucinated: {len(unsupported)} claims quarantined")
    print(f"  LLM Calls & Caching : {usage.llm_calls} calls, {usage.input_tokens + usage.output_tokens} tokens")
    print(f"  Synthesis Time      : {t_story:.3f}s")

    # 5. Display Executive Report
    print("\n" + "=" * 80)
    print("   EXECUTIVE ATTACK INCIDENT REPORT")
    print("=" * 80)
    print(f"CASE: {case_id} | STORY: {story_id}")
    print(f"\nSummary:\n  {draft.summary}\n")

    print("Chronological Incident Steps (Verified by 4 Deterministic Citation Checks):")
    for s in verified_steps[:10]:
        t_str = s.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if s.started_at else "N/A"
        tech_str = f" [{s.technique_id}]" if s.technique_id else ""
        citations = ", ".join(e.event_id for e in s.evidence[:3])
        print(f"  Step {s.step_number}. [{t_str}] Host: {s.host}{tech_str}")
        print(f"    Action: {s.description}")
        print(f"    Verdict: [VERIFIED: {s.verdict.upper()}] (Citing: {citations})")

    if incidents and incidents[0].lookahead:
        lh = incidents[0].lookahead
        print("\nContainment Directives (PRD FR-6):")
        for rec in lh.recommended_containment:
            print(f"  * {rec}")

    print("\n" + "=" * 80)
    print("Pipeline Step E Complete! Both interactive graph and verified story are fully linked.")


if __name__ == "__main__":
    main()
