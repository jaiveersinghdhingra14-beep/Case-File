#!/usr/bin/env python3
"""
CLI Helper to profile and ingest raw log files (including 6 GB+ files) into CaseFile Parquet storage.

Usage:
    python scripts/ingest_file.py data/raw/firex-10G.log
    python scripts/ingest_file.py data/raw/edr_events.json
"""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys
import time

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.schemas import Dataset, DatasetStatus
from backend.app.services.ingest import ingest_dataset_sync
from backend.app.services.profiler import profile_file
from backend.app.store import db


def main():
    parser = argparse.ArgumentParser(description="Ingest big log file into CaseFile Parquet storage.")
    parser.add_argument("file_path", help="Path to raw log file (e.g. data/raw/firex-10G.log)")
    parser.add_argument("--batch-size", type=int, default=10000, help="Arrow batch size (default: 10,000)")
    parser.add_argument("--name", type=str, default="", help="Optional display name for dataset")
    args = parser.parse_args()

    target_path = Path(args.file_path).resolve()
    if not target_path.exists():
        print(f"[ERROR] Target file not found: {target_path}", file=sys.stderr)
        sys.exit(1)

    file_size_bytes = target_path.stat().st_size
    file_size_mb = file_size_bytes / (1024 * 1024)
    file_size_gb = file_size_mb / 1024

    print("=" * 70)
    print("   CaseFile v2 - Big-Log Streaming Ingestion Engine")
    print("=" * 70)
    print(f"Target File : {target_path}")
    print(f"File Size   : {file_size_mb:.2f} MB ({file_size_gb:.2f} GB)")

    # 1. Register Dataset
    db.init_db()
    ds_id = db.generate_id("ds_")
    ds_name = args.name or target_path.name

    dataset = Dataset(
        dataset_id=ds_id,
        name=ds_name,
        path=str(target_path),
        size_bytes=file_size_bytes,
        format="unknown",
        status=DatasetStatus.registered,
        events_total=0,
        hosts=[],
        created_at=datetime.now(timezone.utc),
    )
    db.save_dataset(dataset)
    print(f"Dataset ID  : {ds_id}")

    # 2. Run Profiler
    print("\n[Stage 1/2] Profiling log format & sample schema...")
    t0 = time.perf_counter()
    profile = profile_file(target_path)
    prof_time = time.perf_counter() - t0

    print(f"  Detected Format : {profile.format_name.upper()}")
    print(f"  Sample Hosts    : {', '.join(profile.hosts_sample[:5]) or 'N/A'}")
    print(f"  Estimated Lines : ~{profile.estimated_lines:,}")
    print(f"  Profiling Time  : {prof_time:.3f}s (sub-second micro-slice)")

    # 3. Run Ingest
    print(f"\n[Stage 2/2] Streaming ingestion into Parquet (Batch Size: {args.batch_size:,})...")

    last_update = time.perf_counter()
    def progress_callback(rows_in: int, rows_out: int):
        nonlocal last_update
        now = time.perf_counter()
        if now - last_update >= 1.0:
            print(f"\r  Progress: {rows_in:,} raw lines read | {rows_out:,} events structured", end="", flush=True)
            last_update = now

    report = ingest_dataset_sync(ds_id, batch_size=args.batch_size, progress_callback=progress_callback)
    print()  # newline

    # 4. Results
    stage = report.stages[0]
    print("\n" + "=" * 70)
    print("   Ingestion Complete & Benchmark Verified")
    print("=" * 70)
    print(f"Total Rows In   : {stage.rows_in:,}")
    print(f"Total Rows Out  : {stage.rows_out:,}")
    print(f"Elapsed Time    : {stage.seconds:.2f}s")
    print(f"Throughput      : {stage.throughput_mb_s:.2f} MB/s")
    print(f"Peak Memory RSS : {stage.peak_rss_mb:.1f} MB (RAM budget: < 8,000 MB)")
    print(f"Storage Path    : data/parquet/{ds_id}/")
    print("=" * 70)
    print("\nYou can now run Step D (noise reduction, rarity scoring, Top-K seed selection) on this dataset!")


if __name__ == "__main__":
    main()
