"""
Parser plugin interface for CaseFile v2.

WHY: The official PRD does not specify which log format the evaluation dataset will
use. By defining an abstract base class, we can add new formats (auditd, JSON lines,
syslog, CSV) as simple drop-in modules without touching any pipeline code. The profiler
auto-detects the format and selects the right parser at runtime.

ENGINEERING PRINCIPLE: Open/Closed Principle — open for extension (new parsers),
closed for modification (existing pipeline code never changes).
"""

from __future__ import annotations

import abc
from datetime import datetime, timezone
from typing import Any


class BaseParser(abc.ABC):
    """
    Every parser plugin must implement two methods:
      1. can_parse(sample_lines) -> bool : Sniff a few lines and say "yes, this is my format"
      2. parse_line(line, ...) -> dict    : Parse one raw line into a normalized event dict

    This keeps the ingest pipeline format-agnostic. The profiler tests each parser
    against a sample and picks the one that returns True.
    """

    @abc.abstractmethod
    def can_parse(self, sample_lines: list[str]) -> bool:
        """Return True if this parser recognises the format from a sample of lines."""
        ...

    @abc.abstractmethod
    def parse_line(
        self,
        line: str,
        source_file: str | None = None,
        byte_offset: int = 0,
        byte_length: int = 0,
    ) -> dict[str, Any] | None:
        """
        Parse a single raw log line into a flat dict with NormalizedEvent-compatible keys.
        Returns None if the line is unparseable (e.g., blank, header, comment).

        Required output keys: event_id, timestamp, host, source, category, summary
        Optional keys: user, pid, ppid, process_name, executable, command_line,
                       file_path, remote_address, remote_port, mitre_ids, raw_log,
                       source_file, byte_offset, byte_length
        """
        ...

    @staticmethod
    def safe_int(value: Any, default: int | None = None) -> int | None:
        """Safely convert a value to int, returning default on failure."""
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def safe_timestamp(value: Any) -> datetime | None:
        """Try common timestamp formats; return None if all fail."""
        if value is None:
            return None
        if isinstance(value, datetime):
            return value

        s = str(value).strip()
        # ISO 8601 variants
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        # Unix epoch (seconds or milliseconds)
        try:
            val = float(s)
            if val > 1e12:  # milliseconds
                val = val / 1000
            return datetime.fromtimestamp(val, tz=timezone.utc)
        except (ValueError, OSError):
            pass
        return None
