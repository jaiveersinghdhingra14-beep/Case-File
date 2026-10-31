"""
Syslog (RFC 3164 / RFC 5424) parser.

WHY: Syslog is the universal transport for Linux system logs, firewall logs,
and network device logs. Many datasets include syslog-formatted entries even
when they contain structured data in the message body.

HOW: Uses a simple regex to extract priority, timestamp, hostname, process, and
message. If the message body contains JSON, delegates to the JSON parser for
deeper field extraction.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from .base import BaseParser

# RFC 3164: <priority>Mon DD HH:MM:SS hostname process[pid]: message
# RFC 5424: <priority>1 ISO-timestamp hostname app-name procid msgid ...
_SYSLOG_3164_RE = re.compile(
    r"^<(\d+)>"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"(\S+?)(?:\[(\d+)\])?:\s*"
    r"(.*)$"
)
_SYSLOG_5424_RE = re.compile(
    r"^<(\d+)>\d+\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"\S+\s*"
    r"(?:\[.*?\])?\s*"
    r"(.*)$"
)


class SyslogParser(BaseParser):
    """Parses syslog (RFC 3164 and RFC 5424) formatted log lines."""

    def can_parse(self, sample_lines: list[str]) -> bool:
        """Returns True if >= 50% of non-blank lines match syslog format (start with '<')."""
        hits = 0
        total = 0
        for line in sample_lines:
            stripped = line.strip()
            if not stripped:
                continue
            total += 1
            if stripped.startswith("<") and (_SYSLOG_3164_RE.match(stripped) or _SYSLOG_5424_RE.match(stripped)):
                hits += 1
        return total > 0 and (hits / total) >= 0.5

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

        # Try RFC 5424 first (more specific), then 3164
        m = _SYSLOG_5424_RE.match(stripped)
        if m:
            _pri, ts_str, host, app, proc_id, msg = m.groups()
            ts = self.safe_timestamp(ts_str)
            pid = self.safe_int(proc_id)
        else:
            m = _SYSLOG_3164_RE.match(stripped)
            if not m:
                return None
            _pri, ts_str, host, app, pid_str, msg = m.groups()
            # RFC 3164 timestamps lack year; assume current year
            year = datetime.now(timezone.utc).year
            ts = self.safe_timestamp(f"{year} {ts_str}")
            if ts is None:
                for fmt in ("%Y %b %d %H:%M:%S", "%Y %b  %d %H:%M:%S"):
                    try:
                        ts = datetime.strptime(f"{year} {ts_str}", fmt)
                        break
                    except ValueError:
                        continue
            pid = self.safe_int(pid_str)

        if ts is None:
            return None

        event_id = hashlib.md5(stripped.encode(), usedforsecurity=False).hexdigest()[:16]
        category = _syslog_app_to_category(app or "", msg)

        summary = f"[{host}] {app}: {msg[:120]}" if msg else f"[{host}] {app}"
        summary += f" ({category})"

        return {
            "event_id": event_id,
            "timestamp": ts,
            "host": host or "unknown",
            "source": "syslog",
            "category": category,
            "user": None,
            "pid": pid,
            "ppid": None,
            "process_name": app,
            "executable": None,
            "command_line": None,
            "file_path": None,
            "remote_address": None,
            "remote_port": None,
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


def _syslog_app_to_category(app: str, msg: str) -> str:
    """Deterministic category from syslog app name and message keywords."""
    app_lower = app.lower()
    msg_lower = msg.lower() if msg else ""

    if any(k in app_lower for k in ("sshd", "login", "pam", "sudo", "auth")):
        return "authentication"
    if any(k in msg_lower for k in ("authentication", "login", "password", "session opened", "session closed")):
        return "authentication"
    if any(k in app_lower for k in ("cron", "at", "systemd-timer")):
        return "scheduled_task"
    if any(k in app_lower for k in ("iptables", "firewalld", "ufw", "nftables")):
        return "network"
    if any(k in msg_lower for k in ("connection", "connect", "port", "tcp", "udp")):
        return "network"
    if any(k in app_lower for k in ("kernel", "systemd")):
        return "process_exec"
    return "other"
