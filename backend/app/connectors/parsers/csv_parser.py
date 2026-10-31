"""
CSV / tab-delimited log parser.

WHY: Some datasets and exported log archives use CSV/TSV format (e.g., Windows
Security Event Logs exported from Event Viewer, Splunk CSV exports). This parser
handles arbitrary delimiters and maps columns to normalized event fields.

HOW: Reads the first line as a header row, then maps columns by name using a
priority-ordered lookup table. If no header is present, falls back to positional
column mapping for common formats.
"""

from __future__ import annotations

import csv
import hashlib
import io
from typing import Any

from .base import BaseParser

# Common column name mappings (case-insensitive)
_TIMESTAMP_COLS = ("timestamp", "@timestamp", "time", "datetime", "date", "eventtime", "event_time")
_HOST_COLS = ("host", "hostname", "computer", "computername", "computer_name", "agent_name", "source_host")
_USER_COLS = ("user", "username", "account", "account_name", "user_name", "subject_username")
_PID_COLS = ("pid", "process_id", "processid")
_PPID_COLS = ("ppid", "parent_pid", "parentprocessid", "parent_process_id")
_EXE_COLS = ("exe", "executable", "image", "process_path", "newprocessname")
_CMD_COLS = ("command_line", "commandline", "cmd", "command", "process_command_line")
_FILE_COLS = ("file", "file_path", "filepath", "objectname", "target_filename")
_IP_COLS = ("remote_address", "source_ip", "src_ip", "sourceaddress", "ipaddress", "destinationip")
_PORT_COLS = ("remote_port", "source_port", "src_port", "sourceport", "destinationport")
_EVENT_ID_COLS = ("event_id", "eventid", "id", "record_id", "recordnumber")


class CsvParser(BaseParser):
    """Parses CSV or TSV log files with auto-detected delimiter and header mapping."""

    def can_parse(self, sample_lines: list[str]) -> bool:
        """Returns True if lines look like delimited data with a consistent column count."""
        if not sample_lines:
            return False

        non_blank = [line.strip() for line in sample_lines if line.strip()]
        if len(non_blank) < 2:
            return False

        # Try to detect delimiter
        for delimiter in (",", "\t", "|", ";"):
            try:
                reader = csv.reader(io.StringIO("\n".join(non_blank[:5])), delimiter=delimiter)
                rows = list(reader)
                if len(rows) >= 2:
                    col_counts = [len(r) for r in rows]
                    # Consistent column count >= 3 columns
                    if col_counts[0] >= 3 and all(c == col_counts[0] for c in col_counts[:3]):
                        return True
            except csv.Error:
                continue
        return False

    def parse_line(
        self,
        line: str,
        source_file: str | None = None,
        byte_offset: int = 0,
        byte_length: int = 0,
    ) -> dict[str, Any] | None:
        # CSV parsing requires header context; handled by the ingest pipeline
        # which calls parse_line_with_header instead
        return None

    def detect_delimiter(self, sample_lines: list[str]) -> str:
        """Auto-detect the delimiter used in the CSV file."""
        for delimiter in (",", "\t", "|", ";"):
            try:
                reader = csv.reader(io.StringIO("\n".join(sample_lines[:3])), delimiter=delimiter)
                rows = list(reader)
                if len(rows) >= 2 and len(rows[0]) >= 3 and len(rows[0]) == len(rows[1]):
                    return delimiter
            except csv.Error:
                continue
        return ","

    def parse_header(self, header_line: str, delimiter: str = ",") -> list[str]:
        """Parse the header row and return lowercase column names."""
        reader = csv.reader(io.StringIO(header_line), delimiter=delimiter)
        row = next(reader, [])
        return [c.strip().lower() for c in row]

    def parse_data_line(
        self,
        line: str,
        columns: list[str],
        delimiter: str = ",",
        source_file: str | None = None,
        byte_offset: int = 0,
        byte_length: int = 0,
    ) -> dict[str, Any] | None:
        """Parse a data row using pre-extracted column names."""
        stripped = line.strip()
        if not stripped:
            return None

        try:
            reader = csv.reader(io.StringIO(stripped), delimiter=delimiter)
            values = next(reader, [])
        except csv.Error:
            return None

        if len(values) != len(columns):
            return None

        row = dict(zip(columns, values))

        # Extract fields using column name lookups
        ts_raw = _first_match(row, _TIMESTAMP_COLS)
        ts = self.safe_timestamp(ts_raw)
        if ts is None:
            return None

        host = _first_match(row, _HOST_COLS) or "unknown"
        user = _first_match(row, _USER_COLS)
        pid = self.safe_int(_first_match(row, _PID_COLS))
        ppid = self.safe_int(_first_match(row, _PPID_COLS))
        exe = _first_match(row, _EXE_COLS)
        cmd = _first_match(row, _CMD_COLS)
        fpath = _first_match(row, _FILE_COLS)
        remote = _first_match(row, _IP_COLS)
        port = self.safe_int(_first_match(row, _PORT_COLS))
        eid = (
            _first_match(row, _EVENT_ID_COLS) or hashlib.md5(stripped.encode(), usedforsecurity=False).hexdigest()[:16]
        )

        category = "process_exec" if (exe or cmd) else ("network" if remote else "other")

        parts = [f"[{host}]"]
        if user:
            parts.append(f"user={user}")
        if cmd:
            parts.append(f"cmd={cmd[:80]}")
        elif exe:
            parts.append(f"exe={exe}")
        parts.append(f"({category})")
        summary = " ".join(parts)

        return {
            "event_id": str(eid),
            "timestamp": ts,
            "host": host,
            "source": "csv",
            "category": category,
            "user": user,
            "pid": pid,
            "ppid": ppid,
            "process_name": None,
            "executable": exe,
            "command_line": cmd,
            "file_path": fpath,
            "remote_address": remote,
            "remote_port": port,
            "wazuh_rule_id": None,
            "wazuh_rule_level": None,
            "mitre_ids": [],
            "kill_chain_stage": None,
            "is_noise": False,
            "noise_reason": None,
            "group_id": None,
            "summary": summary,
            "raw_log": stripped,
            "source_file": source_file,
            "byte_offset": byte_offset,
            "byte_length": byte_length,
            "rarity_score": None,
            "is_seed": False,
        }


def _first_match(row: dict[str, str], candidates: tuple[str, ...]) -> str | None:
    """Return the first non-empty value from a row matching any candidate column name."""
    for col in candidates:
        val = row.get(col, "").strip()
        if val:
            return val
    return None
