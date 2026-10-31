from datetime import datetime, timedelta, timezone

from backend.app.schemas import (
    EventCategory,
    KillChainStage,
    NormalizedEvent,
    PatternType,
)
from backend.app.services.pattern_detector import detect_patterns_from_events


def test_detect_brute_force_pattern():
    now = datetime.now(timezone.utc)
    events = [
        NormalizedEvent(
            event_id=f"evt_bf_{i}",
            timestamp=now + timedelta(seconds=i * 2),
            host="10.10.20.11",
            source="utm",
            category=EventCategory.authentication,
            remote_address="198.145.163.25",
            command_line="action=deny reason=auth_failed",
            mitre_ids=["T1110"],
            summary="Failed authentication attempt",
        )
        for i in range(5)
    ]

    patterns = detect_patterns_from_events(events)
    assert len(patterns) >= 1
    bf = next(p for p in patterns if p.pattern_type == PatternType.BRUTE_FORCE)
    assert bf.target_host == "10.10.20.11"
    assert bf.source_ip == "198.145.163.25"
    assert bf.attempt_count == 5
    assert bf.mitre_id == "T1110"
    assert bf.kill_chain_stage == KillChainStage.CREDENTIAL_ACCESS
    assert bf.status == "blocked"


def test_detect_exploit_wave_pattern():
    now = datetime.now(timezone.utc)
    events = [
        NormalizedEvent(
            event_id=f"evt_exp_{i}",
            timestamp=now + timedelta(seconds=i * 5),
            host="10.10.20.38",
            source="utm",
            category=EventCategory.network,
            remote_address="2.94.174.249",
            command_line="action=drop attack=Apache.Struts.RCE",
            mitre_ids=["T1190"],
            summary="Inbound web exploit attempt",
        )
        for i in range(4)
    ]

    patterns = detect_patterns_from_events(events)
    assert len(patterns) >= 1
    ew = next(p for p in patterns if p.pattern_type == PatternType.EXPLOIT_WAVE)
    assert ew.target_host == "10.10.20.38"
    assert ew.source_ip == "2.94.174.249"
    assert ew.attempt_count == 4
    assert ew.mitre_id == "T1190"


def test_detect_multi_host_recon_sweep():
    now = datetime.now(timezone.utc)
    # Single scanner hitting 4 different hosts
    events = [
        NormalizedEvent(
            event_id=f"evt_scan_{i}",
            timestamp=now + timedelta(seconds=i * 2),
            host=f"10.10.40.{10 + i}",
            source="utm",
            category=EventCategory.network,
            remote_address="45.33.32.156",
            command_line="action=deny dstport=445",
            mitre_ids=["T1046"],
            summary="Port scan probe",
        )
        for i in range(4)
    ]

    patterns = detect_patterns_from_events(events)
    recon = [p for p in patterns if p.pattern_type == PatternType.RECON_SWEEP]
    assert len(recon) >= 1
    assert recon[0].source_ip == "45.33.32.156"
    assert recon[0].attempt_count == 4
