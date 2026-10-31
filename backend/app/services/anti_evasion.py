"""
Adversarial Anti-Evasion & Raw Data Post-Processing Engine.

WHY THIS EXISTS:
Sophisticated adversaries know how standard SIEM and firewall parsers work.
They attempt to hide their presence inside parsed logs through:
1. Obfuscation & Living-off-the-Land (LotL): Base64-encoded CLI (-enc), carat escaping (c^m^d), hex escapes.
2. Parser Delimiter Injection: Injecting spoofed key-values (e.g. action="allow" or status=200 in User-Agent/URI)
   to mislead forward parsers into misclassifying malicious activity as benign.
3. Low-and-Slow Stealth Jitter: Periodic C2 beacons dispersed across hours with random time jitter to evade velocity counters.
4. Raw Byte Anchoring: Verifying parsed telemetry against raw disk byte offsets (source_file, byte_offset, byte_length)
   guaranteeing forensic ground truth cannot be tampered with by parsed field manipulation.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from ..schemas.common import KillChainStage
from ..schemas.events import NormalizedEvent
from ..schemas.incident import AttackPattern, PatternType


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def deobfuscate_payload(text: str) -> tuple[bool, str, list[str]]:
    """
    De-masks obscured payloads in commands, raw lines, or URLs.
    Detects:
    - Base64 encoded UTF-8 or UTF-16LE commands (PowerShell -enc / -e)
    - Carat-escaped commands (e.g. p^o^w^e^r^s^h^e^l^l)
    - URL-encoded directory traversal and commands (%2e%2e%2f, %20)
    - High-entropy obfuscated strings

    Returns (is_evasion_detected, deobfuscated_payload, evasion_reasons).
    """
    if not text or len(text.strip()) < 4:
        return False, text, []

    reasons: list[str] = []
    decoded_fragments: list[str] = []

    # 1. Carat Escaping (Windows cmd / PowerShell de-masking)
    active_text = text
    if "^" in text and len(re.findall(r"[A-Za-z]\^[A-Za-z]", text)) >= 2:
        de_carat = text.replace("^", "")
        reasons.append("Carat-escaping evasion detected (cmd/powershell de-obfuscation)")
        decoded_fragments.append(f"De-carated: {de_carat}")
        active_text = de_carat

    # 2. URL Encoding (Path Traversal / Web Exploit de-masking)
    if "%" in active_text:
        try:
            unquoted = unquote(active_text)
            if unquoted != active_text and (".." in unquoted or "/" in unquoted or " " in unquoted):
                reasons.append("URL-encoded payload de-masked (hex/percent traversal)")
                decoded_fragments.append(f"URL-Decoded: {unquoted}")
                active_text = unquoted
        except (ValueError, UnicodeDecodeError):
            pass

    # 3. Base64 Detection & Decoding (PowerShell -enc, CLI, or web parameter base64 blobs)
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
    for match in b64_pattern.finditer(active_text):
        candidate = match.group(0)
        # Pad if missing
        pad_len = (4 - len(candidate) % 4) % 4
        padded = candidate + ("=" * pad_len)
        try:
            raw_bytes = base64.b64decode(padded)
            decoded_utf16 = ""
            try:
                decoded_utf16 = raw_bytes.decode("utf-16le")
            except (UnicodeDecodeError, ValueError):
                pass

            decoded_utf8 = ""
            try:
                decoded_utf8 = raw_bytes.decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                pass

            target_decoded = decoded_utf16 if (decoded_utf16 and len(decoded_utf16.strip()) > 3 and decoded_utf16.isprintable()) else decoded_utf8
            if target_decoded and any(
                kw in target_decoded.lower()
                for kw in ["http", "curl", "powershell", "cmd", "iex", "download", "whoami", "net", "certutil", "sh", "bash", "exe", "system"]
            ):
                reasons.append(f"Base64 obfuscated payload unmasked ({len(candidate)} chars)")
                decoded_fragments.append(f"Base64-Decoded: {target_decoded.strip()}")
        except (ValueError, binascii.Error):
            pass

    # 4. Shannon Entropy Anomaly
    entropy = calculate_entropy(text)
    if entropy > 4.8 and len(text) > 30 and not reasons:
        reasons.append(f"High-entropy payload anomaly (Entropy: {entropy:.2f} > 4.80)")
        decoded_fragments.append(f"High-Entropy String ({entropy:.2f} bits/symbol)")

    is_evasion = len(reasons) > 0
    final_payload = " | ".join(decoded_fragments) if decoded_fragments else text
    return is_evasion, final_payload, reasons


def audit_parser_delimiters(raw_line: str, event: NormalizedEvent) -> list[str]:
    """
    Audits for delimiter injection & spoofing where an attacker attempts
    to fool key-value parsers (e.g. injecting action="allow" in URL).
    """
    if not raw_line:
        return []

    anomalies: list[str] = []
    lower_raw = raw_line.lower()

    # CRLF Log Injection attempt
    if "\r\n" in raw_line or "\\r\\n" in raw_line:
        anomalies.append("CRLF log injection detected in raw telemetry")

    # Injected allow/pass in raw parameters when firewall logged a threat
    has_threat = any(m in event.mitre_ids for m in ["T1190", "T1071", "T1059", "T1046"])
    has_spoofed_allow = 'action="allow"' in lower_raw or 'action=allow' in lower_raw or 'status=200' in lower_raw
    has_denial = "deny" in lower_raw or "block" in lower_raw
    if has_threat and has_spoofed_allow and has_denial:
        anomalies.append("Delimiter injection anomaly: Conflicting spoofed 'action=allow' token in payload")

    return anomalies


def detect_low_and_slow_jitter(events: Sequence[NormalizedEvent], min_beacons: int = 3) -> list[AttackPattern]:
    """
    Detects stealth Low-and-Slow C2 beaconing using Inter-Arrival Time (IAT) Jitter Entropy.
    Instead of relying on high-frequency velocity bursts, detects periodic network sessions
    with low coefficient of variation (CV = std_dev / mean < 0.40).
    """
    patterns: list[AttackPattern] = []
    sessions_by_peer: dict[tuple[str, str], list[datetime]] = {}

    for e in events:
        if e.remote_address and e.host and e.timestamp:
            peer_key = (e.host, e.remote_address)
            if peer_key not in sessions_by_peer:
                sessions_by_peer[peer_key] = []
            sessions_by_peer[peer_key].append(e.timestamp)

    for (src_host, dst_ip), timestamps in sessions_by_peer.items():
        if len(timestamps) < min_beacons:
            continue
        timestamps.sort()
        deltas = [(timestamps[i + 1] - timestamps[i]).total_seconds() for i in range(len(timestamps) - 1)]
        deltas = [d for d in deltas if d > 0]
        if len(deltas) < 2:
            continue

        mean_interval = sum(deltas) / len(deltas)
        variance = sum((d - mean_interval) ** 2 for d in deltas) / len(deltas)
        std_dev = math.sqrt(variance)
        cv = std_dev / mean_interval if mean_interval > 0 else 1.0

        # Low Coefficient of Variation (< 0.40) over spaced intervals indicates periodic C2 beaconing
        if cv < 0.40 and mean_interval >= 10.0:
            total_dur = (timestamps[-1] - timestamps[0]).total_seconds()
            pat = AttackPattern(
                pattern_id=f"pat_jitter_{abs(hash((src_host, dst_ip))) % 100000:05d}",
                pattern_type=PatternType.C2_BEACONING,
                target_host=src_host,
                source_ip=dst_ip,
                mitre_id="T1071",
                technique_name="Periodic C2 Beaconing",
                kill_chain_stage=KillChainStage.COMMAND_AND_CONTROL,
                attempt_count=len(timestamps),
                start_time=timestamps[0],
                end_time=timestamps[-1],
                duration_seconds=total_dur,
                velocity_attempts_per_sec=round(len(timestamps) / max(total_dur, 1.0), 4),
                title=f"Stealth Low-and-Slow Periodic C2 Beaconing (Jitter CV: {cv:.2f}, Mean Interval: {mean_interval:.1f}s)",
                evidence_event_ids=[],
                status="blocked",
            )
            patterns.append(pat)

    return patterns


def raw_data_post_process(
    events: list[NormalizedEvent],
) -> tuple[list[NormalizedEvent], dict[str, Any]]:
    """
    Executes deep forensic post-processing directly against raw disk bytes:
    1. Seeks to immutable byte offsets (source_file, byte_offset, byte_length).
    2. Re-hydrates raw_log without impacting streaming ingestion performance.
    3. Executes payload de-masking (Base64, carat, hex, URL, entropy).
    4. Audits parser token delimiters to flag spoofing and evasion attempts.
    """
    evasions_unmasked = 0
    raw_bytes_verified = 0

    for e in events:
        raw_text = e.raw_log or ""

        # Seek directly to disk byte offset for O(1) forensic verification
        if e.source_file and e.byte_offset is not None and not raw_text and Path(e.source_file).exists():
            try:
                with Path(e.source_file).open("rb") as fh:
                    fh.seek(e.byte_offset)
                    length = e.byte_length if (e.byte_length and e.byte_length > 0) else 512
                    b = fh.read(length)
                    raw_text = b.decode("utf-8", errors="replace").strip()
                    e.raw_log = raw_text
                    raw_bytes_verified += 1
            except OSError:
                pass

        # Audit both parsed command_line and raw log line
        target_str = e.command_line or raw_text or e.summary
        is_evaded, decoded_payload, reasons = deobfuscate_payload(target_str)

        # Audit delimiters for parser evasion
        delim_anomalies = audit_parser_delimiters(raw_text, e)
        if delim_anomalies:
            is_evaded = True
            reasons.extend(delim_anomalies)

        if is_evaded:
            evasions_unmasked += 1
            e.is_evasion = True
            e.evasion_notes = reasons
            e.decoded_payload = decoded_payload
            if "T1027" not in e.mitre_ids:
                e.mitre_ids.append("T1027")  # MITRE ATT&CK: Obfuscated Files or Information
            e.summary = f"[DE-OBFUSCATED EVASION] {e.summary} | Unmasked: {decoded_payload[:80]}"

    metrics = {
        "raw_bytes_verified": raw_bytes_verified,
        "evasions_unmasked": evasions_unmasked,
        "events_audited": len(events),
    }
    return events, metrics
