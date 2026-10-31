#!/usr/bin/env python3
"""
Quick utility to update any datasets registered with format 'unknown' to their profiled format.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.services.profiler import profile_file
from backend.app.store import db


def main():
    db.init_db()
    datasets = db.list_datasets()
    updated = 0

    for ds in datasets:
        if ds.format == "unknown" and Path(ds.path).exists():
            prof = profile_file(ds.path)
            if prof.format_name != "unknown":
                ds.format = prof.format_name
                db.save_dataset(ds)
                print(f"Updated {ds.dataset_id} ({ds.name}) format -> {ds.format.upper()}")
                updated += 1

    if updated == 0:
        print("All registered datasets already have valid detected formats.")


if __name__ == "__main__":
    main()
