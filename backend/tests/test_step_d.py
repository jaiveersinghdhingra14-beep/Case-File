from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend.app.schemas import Dataset, DatasetStatus, EventCategory, NormalizedEvent
from backend.app.services.expander import expand_neighborhood
from backend.app.services.ingest import ingest_dataset_sync
from backend.app.services.lookahead import analyze_blast_radius
from backend.app.services.reducer import calculate_entropy, get_top_k_seeds
from backend.app.store import db


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    test_db = tmp_path / "test_casefile.db"
    test_parquet = tmp_path / "parquet"
    monkeypatch.setattr("backend.app.config.settings.DATABASE_PATH", str(test_db))
    monkeypatch.setattr("backend.app.config.settings.PARQUET_STORAGE_DIR", str(test_parquet))
    db.init_db()
    yield
    db.clear_all(keep_datasets=False)


def test_calculate_entropy():
    # Low entropy: repetitive characters
    assert calculate_entropy("aaaaaaa") == 0.0
    # High entropy: random characters
    h_rand = calculate_entropy("7x9qzp21bm")
    h_word = calculate_entropy("google.com")
    assert h_rand > h_word


def test_top_k_seeds_fortigate():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_fortigate.log"
    assert fixture_path.exists()

    ds_id = "ds_forti_seeds"
    ds = Dataset(
        dataset_id=ds_id,
        name="FortiGate Test",
        path=str(fixture_path.resolve()),
        size_bytes=fixture_path.stat().st_size,
        format="fortigate",
        status=DatasetStatus.registered,
        events_total=0,
        hosts=[],
        created_at=datetime.now(timezone.utc),
    )
    db.save_dataset(ds)
    ingest_dataset_sync(ds_id, batch_size=2)

    seeds = get_top_k_seeds(ds_id, top_k=10, min_rarity_score=0.1)
    assert len(seeds) > 0

    # Top seed should be the blocked C2 event or high anomaly
    top_seed = seeds[0]
    assert top_seed.is_seed is True
    assert top_seed.host in ["10.10.40.156", "10.10.20.11", "10.10.30.15"]
    assert top_seed.rarity_score >= 0.0


def test_top_k_seeds_jsonlines():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_jsonl.log"
    assert fixture_path.exists()

    ds_id = "ds_jsonl_seeds"
    ds = Dataset(
        dataset_id=ds_id,
        name="JSONL Test",
        path=str(fixture_path.resolve()),
        size_bytes=fixture_path.stat().st_size,
        format="jsonlines",
        status=DatasetStatus.registered,
        events_total=0,
        hosts=[],
        created_at=datetime.now(timezone.utc),
    )
    db.save_dataset(ds)
    ingest_dataset_sync(ds_id, batch_size=5)

    seeds = get_top_k_seeds(ds_id, top_k=5, min_rarity_score=0.1)
    assert len(seeds) > 0
    # MITRE-tagged events should be picked up as seeds
    has_mitre_seed = any(len(s.mitre_ids) > 0 for s in seeds)
    assert has_mitre_seed is True


def test_expand_neighborhood():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_jsonl.log"
    assert fixture_path.exists()

    ds_id = "ds_expand_test"
    ds = Dataset(
        dataset_id=ds_id,
        name="JSONL Expand",
        path=str(fixture_path.resolve()),
        size_bytes=fixture_path.stat().st_size,
        format="jsonlines",
        status=DatasetStatus.registered,
        events_total=0,
        hosts=[],
        created_at=datetime.now(timezone.utc),
    )
    db.save_dataset(ds)
    ingest_dataset_sync(ds_id, batch_size=5)

    seeds = get_top_k_seeds(ds_id, top_k=2, min_rarity_score=0.1)
    assert len(seeds) > 0

    expanded = expand_neighborhood(ds_id, seeds, window_seconds=600, max_expanded_events=50)
    assert len(expanded) >= len(seeds)
    # Check that events in expanded are chronologically sorted
    for i in range(len(expanded) - 1):
        assert expanded[i].timestamp <= expanded[i + 1].timestamp


def test_lookahead_reach_analysis():
    now = datetime.now(timezone.utc)
    mock_events = [
        NormalizedEvent(
            event_id="evt_01",
            timestamp=now,
            host="10.10.40.156",
            source="utm",
            category=EventCategory.network,
            user="attacker",
            remote_address="10.10.0.10",  # DC-01
            mitre_ids=["T1078"],
            summary="Access to DC-01",
        ),
        NormalizedEvent(
            event_id="evt_02",
            timestamp=now,
            host="10.10.40.156",
            source="utm",
            category=EventCategory.network,
            remote_address="evil-c2.example.com",
            mitre_ids=["T1071"],
            summary="Outbound connection to C2",
        ),
    ]

    reach = analyze_blast_radius(
        compromised_hosts=["10.10.40.156"],
        compromised_accounts=["attacker"],
        events=mock_events,
        all_known_hosts=["SRV-DC-01", "SRV-DB-01", "WS-FIN-010"],
    )

    assert "10.10.40.156" in reach.compromised_hosts
    assert "attacker" in reach.compromised_accounts
    assert any("DC" in h or "10.10.0.10" in h for h in reach.reachable_hosts)
    assert any("DC" in h or "DB" in h for h in reach.critical_assets_at_risk)
    assert len(reach.recommended_containment) >= 3
