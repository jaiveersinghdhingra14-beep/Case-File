"""
Zeek / Bro network log parser for CaseFile v2.

WHY: Zeek (formerly Bro) is the standard network security monitoring format used in
DFIR competitions, Boss of the SOC (BOTS), and SOC operations.
Handles tab-separated (#fields header) and JSON formats (conn.log, http.log, dns.log, notice.log).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .base import BaseParser

_ZEEK_FIELD_MAP = {
    "ts": "timestamp",
    "id.orig_h": "source_ip",
    "id.orig_p": "source_port",
    "id.resp_h": "target_host",
    "id.resp_p": "target_port",
    "proto": "protocol",
    "service": "service",
    "conn_state": "conn_state",
    "history": "history",
    "orig_bytes": "orig_bytes",
    "resp_bytes": "resp_bytes",
    "note": "alert_note",
    "msg": "alert_msg",
    "sub": "alert_sub",
}


class ZeekParser(BaseParser):
    """Parses Zeek/Bro TSV and JSON formatted network logs."""

    def __init__(self) -> None:
        self.fields: list[str] = []
        self.delimiter: str = "\t"

    def can_parse(self, sample_lines: list[str]) -> bool:
        """Returns True if lines contain Zeek headers (#fields, #separator) or Zeek JSON."""
        for line in sample_lines[:20]:
            stripped = line.strip()
            if stripped.startswith(("#fields", "#separator")):
                return True
            if stripped.startswith("{") and ("id.orig_h" in stripped or "id.resp_h" in stripped):
                return True
        return False

    def parse_line(
        self,
        line: str,
        source_file: str | None = None,
        byte_offset: int = 0,
        byte_length: int = 0,
    ) -> dict[str, Any] | None:
        stripped = line.strip()
        if not stripped:
            return None

        # Ignore Zeek comments, but capture the #fields line
        if stripped.startswith("#"):
            if stripped.startswith("#fields"):
                parts = stripped.split()
                if len(parts) > 1:
                    self.fields = parts[1:]
            elif stripped.startswith("#separator"):
                if "\\x09" in stripped:
                    self.delimiter = "\t"
                elif " " in stripped:
                    self.delimiter = " "
            return None

        # Handle Zeek JSON line
        if stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
                return self._parse_json_dict(obj, stripped, source_file, byte_offset, byte_length)
            except (json.JSONDecodeError, ValueError):
                return None

        # Handle Zeek TSV / Space-delimited line
        parts = stripped.split(self.delimiter)
        if len(parts) < 3:
            parts = stripped.split("\t")
        if len(parts) < 3:
            parts = stripped.split()

        # If fields not yet initialized, use default standard conn.log layout
        if not self.fields or len(self.fields) != len(parts):
            if len(parts) >= 8:
                self.fields = [
                    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                    "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
                ][: len(parts)]
            else:
                return None

        row = dict(zip(self.fields, parts))
        return self._parse_row_dict(row, stripped, source_file, byte_offset, byte_length)

    def _parse_row_dict(
        self,
        row: dict[str, str],
        raw_log: str,
        source_file: str | None,
        byte_offset: int,
        byte_length: int,
    ) -> dict[str, Any] | None:
        # Timestamp
        ts_raw = row.get("ts")
        ts = self.safe_timestamp(ts_raw)
        if ts is None:
            ts = datetime.now(timezone.utc)

        src_ip = row.get("id.orig_h") or row.get("orig_h") or "unknown"
        dst_ip = row.get("id.resp_h") or row.get("resp_h") or "unknown"
        src_port = self.safe_int(row.get("id.orig_p") or row.get("orig_p"))
        dst_port = self.safe_int(row.get("id.resp_p") or row.get("resp_p"))
        proto = (row.get("proto") or "tcp").lower()
        service = row.get("service") or ""
        conn_state = row.get("conn_state") or ""

        # Map to enterprise host and remote attacker
        # Protected internal host is target (or source if internal pivot)
        host = dst_ip if dst_ip != "unknown" else src_ip
        remote_address = src_ip if host == dst_ip else dst_ip

        eid = row.get("uid") or hashlib.md5(raw_log.encode(), usedforsecurity=False).hexdigest()[:16]

        category = "network_session"
        mitre_ids = []
        kill_chain_stage = None

        if dst_port in (22, 3389, 445, 135) and conn_state in ("REJ", "S0", "RSTO"):
            mitre_ids.append("T1110")
            kill_chain_stage = "INITIAL_ACCESS"
        elif dst_port in (80, 443, 8080, 8443) and service in ("http", "ssl"):
            category = "web_traffic"

        summary = f"[{host}] Zeek {proto.upper()} {service or 'session'} {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({conn_state})"

        return {
            "event_id": str(eid),
            "timestamp": ts,
            "host": host,
            "source": "zeek",
            "category": category,
            "user": None,
            "pid": None,
            "ppid": None,
            "process_name": service or proto,
            "executable": None,
            "command_line": None,
            "file_path": None,
            "remote_address": remote_address,
            "remote_port": dst_port or src_port,
            "wazuh_rule_id": None,
            "wazuh_rule_level": None,
            "mitre_ids": mitre_ids,
            "kill_chain_stage": kill_chain_stage,
            "is_noise": False,
            "noise_reason": None,
            "group_id": None,
            "summary": summary,
            "raw_log": raw_log,
            "source_file": source_file,
            "byte_offset": byte_offset,
            "byte_length": byte_length,
            "rarity_score": None,
            "is_seed": False,
        }

    def _parse_json_dict(
        self,
        obj: dict[str, Any],
        raw_log: str,
        source_file: str | None,
        byte_offset: int,
        byte_length: int,
    ) -> dict[str, Any] | None:
        str_row = {k: str(v) for k, v in obj.items() if v is not None}
        return self._parse_row_dict(str_row, raw_log, source_file, byte_offset, byte_length)
