#!/usr/bin/env python3
"""
CLI Tool to list all registered and ingested datasets in CaseFile v2.

Usage:
    python scripts/list_datasets.py
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.store import db


def main():
    db.init_db()
    datasets = db.list_datasets()

    print("=" * 85)
    print("   CaseFile v2 - Registered Datasets")
    print("=" * 85)

    if not datasets:
        print("  No datasets registered yet. Use: python scripts/ingest_file.py <path_to_log>")
        print("=" * 85)
        return

    print(f"{'Dataset ID':<15} {'Name':<22} {'Format':<12} {'Size (MB)':<12} {'Events':<14} {'Status':<10}")
    print("-" * 85)

    for d in datasets:
        size_mb = f"{d.size_bytes / (1024 * 1024):.1f}"
        events_str = f"{d.events_total:,}" if d.events_total else "0"
        print(
            f"{d.dataset_id:<15} {d.name[:20]:<22} {d.format.upper():<12} {size_mb:<12} {events_str:<14} {d.status.upper():<10}"
        )

    print("=" * 85)
    print("To analyze a dataset, run:")
    print("  python scripts/run_step_d.py <dataset_id>")
    print("  python scripts/generate_graph_html.py <dataset_id>")


if __name__ == "__main__":
    main()
