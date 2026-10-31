"""
Linux auditd log parser.

WHY: auditd is the native kernel-level audit framework on Linux. It produces
structured key=value lines with type prefixes (SYSCALL, EXECVE, PATH, USER_AUTH).
Many enterprise SOC environments and the Wazuh agent consume auditd logs directly.

HOW: Parses key=value pairs using simple string splitting — no regex overhead for
the hot path. Handles hex-encoded fields (e.g., proctitle, cmd) that auditd produces
when arguments contain special characters.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from .base import BaseParser

# auditd lines look like:
# type=SYSCALL msg=audit(1698753600.123:456): arch=... syscall=59 ... pid=1234 ppid=999 ...
_AUDIT_MSG_RE = re.compile(r"msg=audit\((\d+\.\d+):\d+\)")
_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


class AuditdParser(BaseParser):
    """Parses Linux auditd log lines (key=value format with type= prefix)."""

    def can_parse(self, sample_lines: list[str]) -> bool:
        """Returns True if >= 50% of non-blank lines start with 'type=' and contain 'msg=audit('."""
        hits = 0
        total = 0
        for line in sample_lines:
            stripped = line.strip()
            if not stripped:
                continue
            total += 1
            if stripped.startswith("type=") and "msg=audit(" in stripped:
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
        if not stripped or not stripped.startswith("type="):
            return None

        # Extract key-value pairs
        kvs: dict[str, str] = {}
        for match in _KV_RE.finditer(stripped):
            key = match.group(1)
            val = match.group(2).strip('"')
            kvs[key] = val

        audit_type = kvs.get("type", "UNKNOWN")

        # Extract timestamp from msg=audit(epoch:serial)
        ts_match = _AUDIT_MSG_RE.search(stripped)
        if ts_match:
            ts = datetime.fromtimestamp(float(ts_match.group(1)), tz=timezone.utc)
        else:
            ts = self.safe_timestamp(kvs.get("time"))
            if ts is None:
                return None

        # Event ID from audit serial or content hash
        serial = ts_match.group(0) if ts_match else None
        event_id = serial or hashlib.md5(stripped.encode(), usedforsecurity=False).hexdigest()[:16]

        host = kvs.get("node", kvs.get("hostname", "localhost"))
        user = kvs.get("auid", kvs.get("uid", kvs.get("acct")))
        pid = self.safe_int(kvs.get("pid"))
        ppid = self.safe_int(kvs.get("ppid"))
        exe = _decode_hex_field(kvs.get("exe", ""))
        comm = kvs.get("comm", "")
        command_line = _decode_hex_field(kvs.get("proctitle", "")) or comm

        file_path = kvs.get("name", kvs.get("path"))
        remote_address = kvs.get("addr") if kvs.get("addr") != "?" else None
        remote_port = self.safe_int(kvs.get("port"))

        # Category from audit type
        category = _audit_type_to_category(audit_type)

        summary = f"[{host}] audit.{audit_type}"
        if user and user != "4294967295":  # -1 in unsigned = unset
            summary += f" user={user}"
        if command_line:
            summary += f" cmd={command_line}"
        elif exe:
            summary += f" exe={exe}"
        if file_path:
            summary += f" file={file_path}"
        summary += f" ({category})"

        return {
            "event_id": str(event_id),
            "timestamp": ts,
            "host": host,
            "source": "auditd",
            "category": category,
            "user": user if user and user != "4294967295" else None,
            "pid": pid,
            "ppid": ppid,
            "process_name": comm or None,
            "executable": exe or None,
            "command_line": command_line or None,
            "file_path": file_path,
            "remote_address": remote_address,
            "remote_port": remote_port,
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


def _decode_hex_field(value: str) -> str:
    """auditd hex-encodes fields with special chars (e.g., 2F62696E2F626173 = /bin/bash)."""
    if not value:
        return ""
    # If all chars are hex digits and even length, decode
    cleaned = value.strip('"')
    if cleaned and all(c in "0123456789ABCDEFabcdef" for c in cleaned) and len(cleaned) % 2 == 0 and len(cleaned) > 4:
        try:
            decoded = bytes.fromhex(cleaned).decode("utf-8", errors="replace")
            # Replace null bytes used as argument separators
            return decoded.replace("\x00", " ").strip()
        except (ValueError, UnicodeDecodeError):
            pass
    return cleaned


def _audit_type_to_category(audit_type: str) -> str:
    """Map auditd record type to event category. Deterministic, no ML."""
    t = audit_type.upper()
    if t in ("SYSCALL", "EXECVE", "CWD", "PROCTITLE"):
        return "process_exec"
    if t in ("PATH", "CREATE", "DELETE"):
        return "file_access"
    if t in ("USER_AUTH", "USER_LOGIN", "USER_ACCT", "CRED_ACQ", "CRED_DISP", "USER_START", "USER_END"):
        return "authentication"
    if t in ("SOCKADDR", "NETFILTER_PKT"):
        return "network"
    if t in ("ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP", "CHGRP_ID", "USER_CHAUTHTOK"):
        return "account_change"
    if t == "CONFIG_CHANGE":
        return "file_change"
    return "other"
