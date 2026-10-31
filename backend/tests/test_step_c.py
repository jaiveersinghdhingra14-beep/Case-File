from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend.app.config import settings
from backend.app.schemas import Dataset, DatasetStatus
from backend.app.services.ingest import (
    get_newline_aligned_shards,
    ingest_dataset_sync,
    stream_shard_lines,
)
from backend.app.store import db
from backend.app.store.duckdb_store import duckdb_store


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    test_db = tmp_path / "test_casefile.db"
    test_parquet = tmp_path / "parquet"
    monkeypatch.setattr("backend.app.config.settings.DATABASE_PATH", str(test_db))
    monkeypatch.setattr("backend.app.config.settings.PARQUET_STORAGE_DIR", str(test_parquet))
    db.init_db()
    yield
    db.clear_all(keep_datasets=False)


def test_newline_aligned_sharding(tmp_path: Path):
    sample_content = (
        b"line1-hello\n"
        b"line2-world\n"
        b"line3-testing-sharding\n"
        b"line4-fourth-line\n"
        b"line5-fifth-line\n"
    )
    test_file = tmp_path / "shard_test.log"
    test_file.write_bytes(sample_content)

    # Shard size smaller than file to create multiple shards
    shards = get_newline_aligned_shards(test_file, shard_size_bytes=20)
    assert len(shards) > 1

    # Verify shards cover entire file exactly
    total_lines = []
    for start, end in shards:
        for _offset, _length, line in stream_shard_lines(test_file, start, end):
            if line.strip():
                total_lines.append(line.rstrip("\r\n"))

    expected_lines = [
        "line1-hello",
        "line2-world",
        "line3-testing-sharding",
        "line4-fourth-line",
        "line5-fifth-line",
    ]
    assert total_lines == expected_lines


def test_ingest_dataset_fortigate(tmp_path: Path):
    fixture_path = Path(__file__).parent / "fixtures" / "sample_fortigate.log"
    assert fixture_path.exists()

    # Register dataset in DB
    ds_id = "ds_fortigate_test"
    dataset = Dataset(
        dataset_id=ds_id,
        name="FortiGate Test Log",
        path=str(fixture_path.resolve()),
        size_bytes=fixture_path.stat().st_size,
        format="fortigate",
        status=DatasetStatus.registered,
        events_total=0,
        hosts=[],
        created_at=datetime.now(timezone.utc),
    )
    db.save_dataset(dataset)

    # Run streaming ingest with small batch size
    report = ingest_dataset_sync(ds_id, batch_size=2)

    assert report.dataset_id == ds_id
    assert report.total_seconds >= 0.0
    assert len(report.stages) == 1

    stage = report.stages[0]
    assert stage.stage == "ingest"
    assert stage.rows_in == 3
    assert stage.rows_out == 3
    assert stage.peak_rss_mb > 0
    assert stage.throughput_mb_s >= 0

    # Verify Dataset status in SQLite
    updated_ds = db.get_dataset(ds_id)
    assert updated_ds.status == DatasetStatus.ready
    assert updated_ds.events_total == 3
    assert "10.10.40.156" in updated_ds.hosts
    assert "10.10.20.11" in updated_ds.hosts

    # Verify Parquet files created on disk
    pq_dir = settings.abs_parquet_dir / ds_id
    assert pq_dir.exists()
    pq_files = list(pq_dir.glob("*.parquet"))
    assert len(pq_files) > 0

    # Query Parquet via DuckDB analytical store
    events, total = duckdb_store.query_events(ds_id, limit=10)
    assert total == 3
    assert len(events) == 3
    assert events[0].event_id is not None
    assert events[0].host is not None


def test_ingest_dataset_jsonlines(tmp_path: Path):
    fixture_path = Path(__file__).parent / "fixtures" / "sample_jsonl.log"
    assert fixture_path.exists()

    ds_id = "ds_jsonlines_test"
    dataset = Dataset(
        dataset_id=ds_id,
        name="JSONLines Test Log",
        path=str(fixture_path.resolve()),
        size_bytes=fixture_path.stat().st_size,
        format="jsonlines",
        status=DatasetStatus.registered,
        events_total=0,
        hosts=[],
        created_at=datetime.now(timezone.utc),
    )
    db.save_dataset(dataset)

    report = ingest_dataset_sync(ds_id, batch_size=2)
    assert report.dataset_id == ds_id
    stage = report.stages[0]
    assert stage.rows_in == 12
    assert stage.rows_out == 12

    updated_ds = db.get_dataset(ds_id)
    assert updated_ds.status == DatasetStatus.ready
    assert updated_ds.events_total == 12
