"""
Step B tests — Profiler and Parser Plugin Interface.

Tests validate:
  1. Each parser correctly sniffs its own format from sample lines.
  2. Each parser extracts the right fields from real log lines.
  3. The profiler reads small byte slices and identifies format without loading full file.
  4. The parser registry selects the correct parser for each format.
"""
from __future__ import annotations

from pathlib import Path

from backend.app.connectors.parsers import get_format_name, get_parser
from backend.app.connectors.parsers.auditd_parser import AuditdParser
from backend.app.connectors.parsers.csv_parser import CsvParser
from backend.app.connectors.parsers.jsonlines_parser import JsonLinesParser
from backend.app.connectors.parsers.syslog_parser import SyslogParser
from backend.app.services.profiler import profile_file

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# 1. Format Detection (can_parse)
# ---------------------------------------------------------------------------

class TestFormatDetection:
    def test_jsonlines_detected(self):
        lines = (FIXTURES / "sample_jsonl.log").read_text().splitlines()
        parser = JsonLinesParser()
        assert parser.can_parse(lines[:5]) is True

    def test_auditd_detected(self):
        lines = (FIXTURES / "sample_auditd.log").read_text().splitlines()
        parser = AuditdParser()
        assert parser.can_parse(lines[:5]) is True

    def test_syslog_detected(self):
        lines = (FIXTURES / "sample_syslog.log").read_text().splitlines()
        parser = SyslogParser()
        assert parser.can_parse(lines[:5]) is True

    def test_csv_detected(self):
        lines = (FIXTURES / "sample_csv.log").read_text().splitlines()
        parser = CsvParser()
        assert parser.can_parse(lines[:5]) is True

    def test_no_cross_detection(self):
        """auditd parser should NOT claim JSON lines are auditd, etc."""
        json_lines = (FIXTURES / "sample_jsonl.log").read_text().splitlines()[:5]
        assert AuditdParser().can_parse(json_lines) is False
        assert SyslogParser().can_parse(json_lines) is False

        audit_lines = (FIXTURES / "sample_auditd.log").read_text().splitlines()[:5]
        assert JsonLinesParser().can_parse(audit_lines) is False
        assert SyslogParser().can_parse(audit_lines) is False


# ---------------------------------------------------------------------------
# 2. Field Extraction (parse_line)
# ---------------------------------------------------------------------------

class TestJsonLinesParsing:
    def test_extracts_host_and_mitre(self):
        line = (FIXTURES / "sample_jsonl.log").read_text().splitlines()[0]
        parser = JsonLinesParser()
        result = parser.parse_line(line, source_file="test.log", byte_offset=0, byte_length=len(line))
        assert result is not None
        assert result["host"] == "HR-07"
        assert result["event_id"] == "evt_00001"
        assert "T1110" in result["mitre_ids"]
        assert result["source_file"] == "test.log"
        assert result["byte_offset"] == 0

    def test_extracts_process_fields(self):
        line = (FIXTURES / "sample_jsonl.log").read_text().splitlines()[3]  # whoami event
        parser = JsonLinesParser()
        result = parser.parse_line(line)
        assert result is not None
        assert result["pid"] == 2345
        assert result["ppid"] == 1234
        assert result["executable"] == "/usr/bin/whoami"
        assert result["user"] == "1000"

    def test_lateral_movement_host(self):
        line = (FIXTURES / "sample_jsonl.log").read_text().splitlines()[6]  # FS-02 login
        parser = JsonLinesParser()
        result = parser.parse_line(line)
        assert result is not None
        assert result["host"] == "FS-02"
        assert "T1078" in result["mitre_ids"]

    def test_blank_line_returns_none(self):
        parser = JsonLinesParser()
        assert parser.parse_line("") is None
        assert parser.parse_line("   ") is None

    def test_invalid_json_returns_none(self):
        parser = JsonLinesParser()
        assert parser.parse_line("not json at all") is None


class TestAuditdParsing:
    def test_extracts_syscall_fields(self):
        line = (FIXTURES / "sample_auditd.log").read_text().splitlines()[0]
        parser = AuditdParser()
        result = parser.parse_line(line)
        assert result is not None
        assert result["host"] == "HR-07"
        assert result["pid"] == 2345
        assert result["ppid"] == 1234
        assert result["executable"] == "/usr/bin/whoami"
        assert result["category"] == "process_exec"

    def test_user_auth_event(self):
        line = (FIXTURES / "sample_auditd.log").read_text().splitlines()[5]
        parser = AuditdParser()
        result = parser.parse_line(line)
        assert result is not None
        assert result["category"] == "authentication"
        assert result["remote_address"] == "10.0.0.55"


class TestSyslogParsing:
    def test_extracts_basic_fields(self):
        line = (FIXTURES / "sample_syslog.log").read_text().splitlines()[0]
        parser = SyslogParser()
        result = parser.parse_line(line)
        assert result is not None
        assert result["host"] == "HR-07"
        assert result["process_name"] == "sshd"
        assert result["pid"] == 1234
        assert result["category"] == "authentication"


# ---------------------------------------------------------------------------
# 3. Parser Registry (auto-selection)
# ---------------------------------------------------------------------------

class TestParserRegistry:
    def test_selects_jsonlines(self):
        lines = (FIXTURES / "sample_jsonl.log").read_text().splitlines()[:5]
        parser = get_parser(lines)
        assert parser is not None
        assert get_format_name(parser) == "jsonlines"

    def test_selects_auditd(self):
        lines = (FIXTURES / "sample_auditd.log").read_text().splitlines()[:5]
        parser = get_parser(lines)
        assert parser is not None
        assert get_format_name(parser) == "auditd"

    def test_selects_syslog(self):
        lines = (FIXTURES / "sample_syslog.log").read_text().splitlines()[:5]
        parser = get_parser(lines)
        assert parser is not None
        assert get_format_name(parser) == "syslog"


# ---------------------------------------------------------------------------
# 4. Profiler (file-level sampling)
# ---------------------------------------------------------------------------

class TestProfiler:
    def test_profiles_jsonl_file(self):
        result = profile_file(FIXTURES / "sample_jsonl.log")
        assert result.format_name == "jsonlines"
        assert result.parser is not None
        assert result.size_bytes > 0
        assert result.estimated_lines > 0
        assert "HR-07" in result.hosts_sample
        assert result.time_range_hint is not None

    def test_profiles_auditd_file(self):
        result = profile_file(FIXTURES / "sample_auditd.log")
        assert result.format_name == "auditd"
        assert result.parser is not None
        assert "HR-07" in result.hosts_sample

    def test_profiles_syslog_file(self):
        result = profile_file(FIXTURES / "sample_syslog.log")
        assert result.format_name == "syslog"
        assert result.parser is not None
        assert result.size_bytes > 0

    def test_multihost_detection(self):
        """Profiler should detect multiple hosts (HR-07, FS-02) from JSONL sample."""
        result = profile_file(FIXTURES / "sample_jsonl.log")
        assert "HR-07" in result.hosts_sample
        assert "FS-02" in result.hosts_sample
