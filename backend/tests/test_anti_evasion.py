from datetime import datetime, timedelta, timezone

from backend.app.schemas.events import EventCategory, NormalizedEvent
from backend.app.services.anti_evasion import (
    audit_parser_delimiters,
    calculate_entropy,
    deobfuscate_payload,
    detect_low_and_slow_jitter,
    raw_data_post_process,
)


def test_calculate_entropy():
    # Low entropy for repetitive strings
    assert calculate_entropy("AAAAAA") < 1.0
    # High entropy for random/base64 strings
    high_ent = calculate_entropy("a8F9z!kL2#pQ9xM1$vN5")
    assert high_ent > 3.5


def test_deobfuscate_base64():
    # Base64 encoded powershell whoami command
    b64_cmd = "powershell -enc d2hvYW1pIC9hbGw="
    is_evaded, decoded, reasons = deobfuscate_payload(b64_cmd)
    assert is_evaded is True
    assert "Base64" in reasons[0]
    assert "whoami" in decoded


def test_deobfuscate_carat_escaping():
    carat_cmd = "p^o^w^e^r^s^h^e^l^l.exe -nop"
    is_evaded, decoded, reasons = deobfuscate_payload(carat_cmd)
    assert is_evaded is True
    assert "Carat-escaping" in reasons[0]
    assert "powershell.exe" in decoded


def test_deobfuscate_url_traversal():
    url_payload = "/static/%2e%2e%2f%2e%2e%2fetc/passwd"
    is_evaded, decoded, reasons = deobfuscate_payload(url_payload)
    assert is_evaded is True
    assert "URL-encoded" in reasons[0]
    assert "../../etc/passwd" in decoded


def test_audit_parser_delimiters():
    ev = NormalizedEvent(
        event_id="evt_test",
        timestamp=datetime.now(timezone.utc),
        host="10.10.20.10",
        source="fortigate",
        category=EventCategory.network,
        mitre_ids=["T1190"],
        summary="Test attack",
    )
    # Delimiter spoofing attempt: embedding action="allow" inside a denied threat log
    raw_line = 'msg="Exploit detected" action="deny" url="/login?ref=action=allow" status=200'
    anomalies = audit_parser_delimiters(raw_line, ev)
    assert len(anomalies) > 0
    assert "Delimiter injection" in anomalies[0]


def test_detect_low_and_slow_jitter():
    now = datetime(2026, 10, 23, 8, 0, 0, tzinfo=timezone.utc)
    # Periodic C2 beacon every ~15 minutes (900s) with 2% jitter
    events = [
        NormalizedEvent(
            event_id=f"c2_{i}",
            timestamp=now + timedelta(seconds=i * 900 + (i % 3) * 5),
            host="10.10.20.103",
            remote_address="31.4.75.226",
            source="fortigate",
            category=EventCategory.network,
            summary="C2 beacon",
        )
        for i in range(5)
    ]
    patterns = detect_low_and_slow_jitter(events, min_beacons=3)
    assert len(patterns) == 1
    assert "Periodic C2 Beaconing" in patterns[0].technique_name
    assert "Jitter CV" in patterns[0].title


def test_raw_data_post_process(tmp_path):
    log_file = tmp_path / "test.log"
    content = 'host=10.10.20.103 cmd="p^o^w^e^r^s^h^e^l^l -enc d2hvYW1p"\n'
    log_file.write_text(content, encoding="utf-8")

    event = NormalizedEvent(
        event_id="e_001",
        timestamp=datetime.now(timezone.utc),
        host="10.10.20.103",
        source="fortigate",
        category=EventCategory.process_exec,
        command_line="p^o^w^e^r^s^h^e^l^l -enc d2hvYW1p",
        source_file=str(log_file),
        byte_offset=0,
        byte_length=len(content),
        summary="Suspicious execution",
    )

    processed, metrics = raw_data_post_process([event])
    assert metrics["evasions_unmasked"] == 1
    assert processed[0].is_evasion is True
    assert "T1027" in processed[0].mitre_ids
    assert "whoami" in str(processed[0].decoded_payload)
