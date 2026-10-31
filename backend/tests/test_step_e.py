from datetime import datetime, timezone

import pytest

from backend.app.schemas import (
    CheckName,
    EventCategory,
    KillChainStage,
    NormalizedEvent,
    StepVerdict,
    StoryStepDraft,
)
from backend.app.services.correlator import (
    build_attack_graph,
    correlate_incident_paths,
    export_graph_to_vis_json,
)
from backend.app.services.stage_mapper import map_technique_and_stage
from backend.app.services.story_writer import write_story_for_events
from backend.app.services.verifier import verify_story_step
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


def test_stage_mapper():
    # 1. Direct MITRE ID
    tid, _name, stage = map_technique_and_stage(mitre_ids=["T1190"])
    assert tid == "T1190"
    assert stage == KillChainStage.INITIAL_ACCESS

    # 2. Command line regex pattern
    tid, _name, stage = map_technique_and_stage(mitre_ids=[], command_line="powershell -enc JABh...")
    assert tid == "T1059.001"
    assert stage == KillChainStage.EXECUTION

    # 3. Lateral movement command
    tid, _name, stage = map_technique_and_stage(mitre_ids=[], command_line="ssh admin@10.10.0.20")
    assert tid == "T1021.004"
    assert stage == KillChainStage.LATERAL_MOVEMENT


def test_attack_graph_and_vis_export():
    now = datetime.now(timezone.utc)
    events = [
        NormalizedEvent(
            event_id="evt_01",
            timestamp=now,
            host="10.10.40.156",
            source="utm",
            category=EventCategory.network,
            remote_address="198.51.100.23",
            mitre_ids=["T1190"],
            summary="Exploit against web app",
        ),
        NormalizedEvent(
            event_id="evt_02",
            timestamp=now,
            host="10.10.40.156",
            source="utm",
            category=EventCategory.network,
            remote_address="10.10.0.10",
            mitre_ids=["T1021"],
            summary="Lateral pivot to DC",
        ),
    ]

    G = build_attack_graph(events)
    assert len(G.nodes) == 3
    assert len(G.edges) == 2

    vis_data = export_graph_to_vis_json(G)
    assert len(vis_data["nodes"]) == 3
    assert len(vis_data["edges"]) == 2
    assert "timestamp" in vis_data["edges"][0]
    assert "technique_id" in vis_data["edges"][0]


def test_correlate_incident_paths():
    now = datetime.now(timezone.utc)
    events = [
        NormalizedEvent(
            event_id="evt_01",
            timestamp=now,
            host="10.10.20.38",
            source="utm",
            category=EventCategory.network,
            remote_address="2.94.174.249",
            mitre_ids=["T1190"],
            summary="Initial exploitation",
        ),
        NormalizedEvent(
            event_id="evt_02",
            timestamp=now,
            host="10.10.20.38",
            source="utm",
            category=EventCategory.network,
            remote_address="10.10.0.10",
            mitre_ids=["T1021"],
            summary="Lateral movement to Domain Controller",
        ),
    ]

    incidents = correlate_incident_paths(dataset_id="ds_test", events=events)
    assert len(incidents) >= 1

    top_inc = incidents[0]
    assert top_inc.risk_score > 0
    assert "10.10.20.38" in top_inc.hosts_involved
    assert len(top_inc.timeline) == 2
    assert top_inc.lookahead is not None


def test_verifier_4_checks():
    now = datetime.now(timezone.utc)
    valid_event = NormalizedEvent(
        event_id="evt_valid_01",
        timestamp=now,
        host="10.10.10.125",
        source="utm",
        category=EventCategory.network,
        remote_address="10.10.0.10",
        command_line="action=deny policyid=4",
        mitre_ids=["T1071"],
        summary="C2 blocked traffic",
    )
    events_map = {"evt_valid_01": valid_event}

    # 1. Valid Draft Step -> Should pass all 4 checks
    valid_draft = StoryStepDraft(
        title="Command and Control Blocked",
        description="Firewall denied unauthorized C2 connection.",
        technique_id="T1071",
        evidence_event_ids=["evt_valid_01"],
    )

    step, claim = verify_story_step(valid_draft, events_map, step_number=1)
    assert step.verdict == StepVerdict.supported
    assert claim is None
    assert len(step.checks) == 4
    assert all(c.passed for c in step.checks)

    # 2. Draft citing non-existent event ID -> Should fail ids_exist check
    hallucinated_draft = StoryStepDraft(
        title="Fake Privilege Escalation",
        description="Attacker ran mimikatz to dump hashes.",
        technique_id="T1003",
        evidence_event_ids=["evt_fake_9999"],
    )

    step_h, claim_h = verify_story_step(hallucinated_draft, events_map, step_number=2)
    assert step_h.verdict == StepVerdict.unsupported
    assert claim_h is not None
    assert any(c.name == CheckName.ids_exist and not c.passed for c in step_h.checks)


def test_story_writer_and_caching():
    now = datetime.now(timezone.utc)
    events = [
        NormalizedEvent(
            event_id="evt_01",
            timestamp=now,
            host="10.10.20.38",
            source="utm",
            category=EventCategory.network,
            remote_address="2.94.174.249",
            mitre_ids=["T1190"],
            summary="Public facing exploit",
        ),
    ]

    draft1, usage1 = write_story_for_events(events, chunk_size=20)
    assert len(draft1.steps) >= 1
    assert usage1.llm_calls == 1

    # Second call with same events -> Content-hash cache hit (0 new LLM calls)
    draft2, usage2 = write_story_for_events(events, chunk_size=20)
    assert len(draft2.steps) == len(draft1.steps)
    assert usage2.llm_calls == 0
