from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from backend.app.api.routes.demo import DemoResetRequest, demo_reset
from backend.app.api.routes.health import get_health
from backend.app.schemas import (
    CaseCreateRequest,
    Dataset,
    DatasetStatus,
    IncidentPath,
    LookaheadReach,
    TimeWindow,
)
from backend.app.store import db


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    test_db = tmp_path / "test_casefile.db"
    monkeypatch.setattr("backend.app.config.settings.DATABASE_PATH", str(test_db))
    db.init_db()
    yield
    db.clear_all(keep_datasets=False)


def test_timewindow_validation():
    now = datetime.now(timezone.utc)
    # Valid window
    w = TimeWindow(start=now, end=now + timedelta(hours=1))
    assert w.end > w.start

    # Invalid window: end <= start
    with pytest.raises(ValidationError):
        TimeWindow(start=now, end=now)

    with pytest.raises(ValidationError):
        TimeWindow(start=now, end=now - timedelta(seconds=1))


def test_case_create_request_validation():
    # Valid request
    req = CaseCreateRequest(dataset_id="ds_12345678", padding_seconds=45, seed_top_k=500)
    assert req.padding_seconds == 45

    # Out of range padding_seconds (> 300)
    with pytest.raises(ValidationError):
        CaseCreateRequest(dataset_id="ds_12345678", padding_seconds=500)

    # Out of range group_gap_seconds (< 10)
    with pytest.raises(ValidationError):
        CaseCreateRequest(dataset_id="ds_12345678", group_gap_seconds=5)


def test_db_dataset_crud():
    ds_id = db.generate_id("ds_")
    ds = Dataset(
        dataset_id=ds_id,
        name="Test 15GB Log",
        path="/tmp/logs/15gb.log",
        size_bytes=16106127360,
        format="auditd",
        status=DatasetStatus.registered,
        events_total=12000000,
        time_range=None,
        hosts=["HR-07", "FS-02"],
        created_at=datetime.now(timezone.utc),
    )
    db.save_dataset(ds)

    retrieved = db.get_dataset(ds_id)
    assert retrieved is not None
    assert retrieved.name == "Test 15GB Log"
    assert retrieved.size_bytes == 16106127360
    assert "HR-07" in retrieved.hosts

    all_ds = db.list_datasets()
    assert len(all_ds) >= 1
    assert any(d.dataset_id == ds_id for d in all_ds)


def test_db_incident_and_lookahead():
    inc_id = db.generate_id("inc_")
    incident = IncidentPath(
        incident_id=inc_id,
        dataset_id="ds_12345678",
        title="Lateral Movement and Data Exfiltration",
        risk_score=85.5,
        kill_chain_progression=[],
        hosts_involved=["HR-07", "FS-02", "DC-01"],
        users_involved=["jdoe", "svc_backup"],
        timeline=[],
        lookahead=LookaheadReach(
            compromised_accounts=["svc_backup"],
            compromised_hosts=["HR-07", "FS-02"],
            reachable_hosts=["DC-01", "DB-01", "MAIL-01"],
            critical_assets_at_risk=["Domain Controller DC-01"],
            recommended_containment=["Isolate FS-02", "Reset svc_backup credentials"],
        ),
        events_merged_count=1420,
        reduction_ratio=150.0,
    )
    db.save_incident(incident)

    fetched = db.get_incident(inc_id)
    assert fetched is not None
    assert fetched.risk_score == 85.5
    assert "DC-01" in fetched.lookahead.reachable_hosts

    summaries = db.list_incidents()
    assert len(summaries) >= 1
    assert summaries[0].incident_id == inc_id


def test_health_route_logic():
    health = get_health()
    assert health.status in ["ok", "degraded"]
    assert health.app_version == "2.0.0"
    assert health.database.ok is True
    assert health.duckdb.ok is True
    assert health.dataset_store.ok is True
    assert health.llm.ok is True


def test_demo_reset_logic():
    # Insert dummy case
    c_id = db.generate_id("case_")
    now = datetime.now(timezone.utc)
    from backend.app.schemas import Case, CaseStatus
    db.save_case(Case(
        case_id=c_id,
        dataset_id="ds_123",
        name="Demo Case",
        status=CaseStatus.ready,
        created_at=now,
        updated_at=now,
    ))
    assert db.get_case(c_id) is not None

    res = demo_reset(DemoResetRequest(clear_history=True, clear_datasets=False))
    assert res.history_cleared is True
    assert res.datasets_preserved is True
    assert db.get_case(c_id) is None
