#!/usr/bin/env python3
"""
CLI Tool to test Step D (Mathematical Noise Reduction, Top-K Seed Selection,
Neighborhood Expansion, and Lookahead Analysis) on any ingested dataset.

Usage:
    python scripts/run_step_d.py ds_812ee6b0
    python scripts/run_step_d.py --top-k 10
"""
import argparse
from pathlib import Path
import sys
import time

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.services.expander import expand_neighborhood
from backend.app.services.lookahead import analyze_blast_radius
from backend.app.services.reducer import get_top_k_seeds
from backend.app.store import db


def main():
    parser = argparse.ArgumentParser(description="Test Step D on an ingested dataset.")
    parser.add_argument("dataset_id", nargs="?", default="", help="Dataset ID (e.g. ds_812ee6b0). If empty, picks latest ready dataset.")
    parser.add_argument("--top-k", type=int, default=20, help="Number of suspicious seeds to display (default: 20)")
    parser.add_argument("--window", type=int, default=120, help="Neighborhood expansion window in seconds (default: 120)")
    args = parser.parse_args()

    db.init_db()
    ds_id = args.dataset_id

    if not ds_id:
        datasets = db.list_datasets()
        ready_ds = [d for d in datasets if d.status == "ready"]
        if not ready_ds:
            print("[ERROR] No ready datasets found in database. Ingest a dataset first using scripts/ingest_file.py.", file=sys.stderr)
            sys.exit(1)
        ds = ready_ds[-1]
        ds_id = ds.dataset_id
    else:
        ds = db.get_dataset(ds_id)
        if not ds:
            print(f"[ERROR] Dataset {ds_id} not found in database.", file=sys.stderr)
            sys.exit(1)

    print("=" * 75)
    print("   CaseFile v2 - Step D: Mathematical Noise Reduction & Graph Expansion")
    print("=" * 75)
    print(f"Dataset ID     : {ds.dataset_id}")
    print(f"Dataset Name   : {ds.name}")
    print(f"Total Events   : {ds.events_total:,}")
    print(f"Format         : {ds.format.upper()}")

    # 1. Top-K Seed Selection via DuckDB Pushdown
    print(f"\n[1/3] Running Out-of-Core Mathematical Noise Reduction (Top-{args.top_k} Seeds)...")
    t0 = time.perf_counter()
    seeds = get_top_k_seeds(ds_id, top_k=args.top_k, min_rarity_score=0.1)
    t_reduce = time.perf_counter() - t0

    print(f"  Seeds Identified : {len(seeds)} high-confidence attack seeds")
    print(f"  Calculation Time : {t_reduce:.3f}s across {ds.events_total:,} rows (Vectorized DuckDB)")

    if not seeds:
        print("  No anomalies met the threshold.")
        return

    print("\n  Sample Suspicious Seeds:")
    for idx, s in enumerate(seeds[:7], start=1):
        target = s.file_path or s.remote_address or "N/A"
        mitre_str = f" [MITRE: {', '.join(s.mitre_ids)}]" if s.mitre_ids else ""
        print(f"    {idx}. [{s.timestamp}] Host: {s.host} -> Target: {target} | Rarity: {s.rarity_score:.4f}{mitre_str}")

    # 2. 2-Hop Neighborhood Expansion
    print(f"\n[2/3] Performing 2-Hop Graph Neighborhood Expansion (Window: ±{args.window}s)...")
    t1 = time.perf_counter()
    expanded = expand_neighborhood(ds_id, seeds, window_seconds=args.window, max_expanded_events=2000)
    t_expand = time.perf_counter() - t1

    print(f"  Candidate Subgraph : {len(expanded)} contextual events preserved")
    print(f"  Expansion Time     : {t_expand:.3f}s")
    print(f"  Noise Pruned       : {ds.events_total - len(expanded):,} routine background events eliminated ({(1 - len(expanded)/max(ds.events_total,1))*100:.2f}%)")

    # 3. Lookahead Reachability & Blast Radius Analysis (PRD FR-6)
    print("\n[3/3] Computing Lookahead Blast Radius & Critical Assets at Risk (FR-6)...")
    comp_hosts = list({s.host for s in seeds})
    comp_users = list({s.user for s in seeds if s.user})

    reach = analyze_blast_radius(
        compromised_hosts=comp_hosts,
        compromised_accounts=comp_users,
        events=expanded,
        all_known_hosts=ds.hosts,
    )

    print(f"  Compromised Hosts       : {', '.join(reach.compromised_hosts[:5]) or 'None'}")
    print(f"  Reachable Hosts         : {', '.join(reach.reachable_hosts[:6]) or 'None'}")
    print(f"  Critical Assets at Risk : {', '.join(reach.critical_assets_at_risk) or 'None'}")
    print("\n  Recommended Containment Actions:")
    for act in reach.recommended_containment:
        print(f"    * {act}")

    print("\n" + "=" * 75)
    print("   Step D Verification Complete - Ready for Step E Attack Path Correlation")
    print("=" * 75)


if __name__ == "__main__":
    main()
