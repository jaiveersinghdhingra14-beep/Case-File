"""
Unit tests for Universal / Adaptive Parsers (GenericLogParser, ZeekParser, CsvParser).

Validates:
1. Zeek TSV and JSON format detection and parsing.
2. GenericLogParser parsing arbitrary, unformatted, and exotic logs (Web, Auth, Custom).
3. CsvParser parsing CSV directly via parse_line().
4. Zero-Crash Guarantee: get_parser never returns None for any text file.
"""

from __future__ import annotations

from backend.app.connectors.parsers import get_format_name, get_parser
from backend.app.connectors.parsers.csv_parser import CsvParser
from backend.app.connectors.parsers.generic_parser import GenericLogParser
from backend.app.connectors.parsers.zeek_parser import ZeekParser


def test_zeek_parser_tsv():
    zeek_lines = [
        "#separator \\x09",
        "#set_separator ,",
        "#empty_field (empty)",
        "#unset_field -",
        "#path conn",
        "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state",
        "#types time string addr port addr port string string interval count count string",
        "1540450000.123456\tC12345\t192.168.1.50\t49152\t10.10.20.20\t22\ttcp\tssh\t0.5\t100\t200\tREJ",
    ]
    parser = ZeekParser()
    assert parser.can_parse(zeek_lines) is True

    # Parse headers (should return None)
    for h in zeek_lines[:7]:
        assert parser.parse_line(h) is None

    # Parse data row
    data = parser.parse_line(zeek_lines[7])
    assert data is not None
    assert data["host"] == "10.10.20.20"
    assert data["remote_address"] == "192.168.1.50"
    assert data["remote_port"] == 22
    assert "T1110" in data["mitre_ids"]


def test_zeek_parser_json():
    json_line = (
        '{"ts": 1540450000.12, "uid": "C999", "id.orig_h": "203.0.113.5", '
        '"id.orig_p": 55123, "id.resp_h": "10.10.0.5", "id.resp_p": 443, "proto": "tcp", "service": "ssl"}'
    )
    parser = ZeekParser()
    assert parser.can_parse([json_line]) is True
    res = parser.parse_line(json_line)
    assert res is not None
    assert res["host"] == "10.10.0.5"
    assert res["remote_address"] == "203.0.113.5"
    assert res["remote_port"] == 443


def test_generic_parser_apache_access_log():
    raw_log = '198.51.100.23 - - [31/Oct/2026:14:32:10 +0000] "GET /admin/config.php?id=1%27%20OR%201=1 HTTP/1.1" 200 4521 "sql injection exploit"'
    parser = GenericLogParser()
    assert parser.can_parse([raw_log]) is True
    res = parser.parse_line(raw_log)
    assert res is not None
    assert res["remote_address"] == "198.51.100.23"
    assert "T1190" in res["mitre_ids"]  # Exploit / SQL injection detected


def test_generic_parser_powershell_execution():
    raw_log = '2026-10-31 16:45:00 WARNING [WS-ENG-007] powershell.exe -ExecutionPolicy Bypass -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...'
    parser = GenericLogParser()
    res = parser.parse_line(raw_log)
    assert res is not None
    assert res["host"] == "WS-ENG-007"
    assert "T1059" in res["mitre_ids"]  # Powershell execution detected
    assert "T1027" in res["mitre_ids"]  # Obfuscation / bypass detected


def test_generic_parser_unstructured_text_never_crashes():
    garbage_lines = [
        "Something completely random happened on host SRV-DATABASE-01 at 2026-10-31 12:00:00",
        "Error in worker thread: connection reset by peer 172.16.5.10:8080",
        "--- START OF REPLAY BUFFER ---",
        "Random line with no numbers or keywords whatsoever",
    ]
    parser = GenericLogParser()
    for line in garbage_lines:
        res = parser.parse_line(line)
        if line.startswith("---"):
            continue
        assert res is not None
        assert "event_id" in res
        assert "timestamp" in res
        assert "host" in res
        assert "summary" in res


def test_csv_parser_direct_parse_line():
    csv_header = "timestamp,host,user,exe,command_line,remote_address,remote_port"
    csv_row = "2026-10-31 10:00:00,WS-FIN-01,admin,cmd.exe,cmd.exe /c whoami,10.10.1.1,445"

    parser = CsvParser()
    # First line should be recognized as header and return None
    assert parser.parse_line(csv_header) is None
    # Subsequent line parsed into event
    res = parser.parse_line(csv_row)
    assert res is not None
    assert res["host"] == "WS-FIN-01"
    assert res["user"] == "admin"
    assert res["command_line"] == "cmd.exe /c whoami"
    assert res["remote_address"] == "10.10.1.1"


def test_parser_registry_universal_fallback():
    weird_lines = ["2026-10-31 11:22:33 CustomVendorLog: event occurred on 10.0.0.1"]
    p = get_parser(weird_lines)
    assert p is not None
    assert get_format_name(p) == "generic_log"
