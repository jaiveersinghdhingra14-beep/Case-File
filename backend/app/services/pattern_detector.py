"""
CaseFile v2 - Forensic Attack Pattern & Burst Detector
Detects high-frequency assault patterns across big-log Parquet telemetry:
- Brute Force & Password Spraying (T1110)
- Public Exploit Burst Waves (T1190)
- Reconnaissance Sweeps & Port Scans (T1046)
- Persistent C2 Beaconing (T1071)
- Lateral Movement Pivot Attempts (T1021)
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ..schemas import AttackPattern, KillChainStage, NormalizedEvent, PatternType
from ..store.duckdb_store import DuckDBStore


def load_yaml_detection_rules() -> list[dict]:
    """
    Loads config-driven detection rules from YAML files in rules/ directory (PRD Bonus B-4).
    Enables adding new detection signatures via YAML without modifying Python source code.
    """
    rules_dir = Path(__file__).resolve().parent.parent.parent.parent / "rules"
    rules: list[dict] = []
    if rules_dir.exists() and rules_dir.is_dir():
        for yml_path in list(rules_dir.glob("*.yaml")) + list(rules_dir.glob("*.yml")):
            try:
                with open(yml_path, encoding="utf-8") as f:
                    content = yaml.safe_load(f)
                    if isinstance(content, dict) and "rules" in content:
                        rules.extend(content["rules"])
            except Exception:  # noqa: BLE001, S110
                pass
    return rules


def _determine_status(command_lines: list[str]) -> str:
    has_deny = any("deny" in c.lower() or "block" in c.lower() or "drop" in c.lower() for c in command_lines)
    has_pass = any("pass" in c.lower() or "allow" in c.lower() or "accept" in c.lower() for c in command_lines)
    if has_deny and has_pass:
        return "mixed"
    if has_deny:
        return "blocked"
    if has_pass:
        return "allowed"
    return "blocked"


def detect_patterns_from_events(events: Sequence[NormalizedEvent]) -> list[AttackPattern]:
    """
    In-memory pattern detector over candidate / expanded event sequences.
    Groups repeated assaults, exploit bursts, and C2 beacons.
    """
    if not events:
        return []

    patterns: list[AttackPattern] = []

    # 1. Group events by (target_host, remote_address, primary_tactic)
    grouped: dict[tuple[str, str, str], list[NormalizedEvent]] = defaultdict(list)

    for e in events:
        target = e.host or "unknown_host"
        src = e.remote_address or "unknown_src"

        tactic = "burst"
        if "T1110" in (e.mitre_ids or []) or e.category.value == "auth" or "fail" in (e.summary or "").lower():
            tactic = "brute_force"
        elif "T1190" in (e.mitre_ids or []) or "exploit" in (e.summary or "").lower():
            tactic = "exploit_wave"
        elif "T1071" in (e.mitre_ids or []) or "c2" in (e.summary or "").lower():
            tactic = "c2_beaconing"
        elif "T1021" in (e.mitre_ids or []) or (target.startswith("10.") and src.startswith("10.")):
            tactic = "lateral_movement"

        grouped[(target, src, tactic)].append(e)

    # 2. Check for multi-source recon sweep (one external IP hitting multiple hosts)
    src_targets: dict[str, set[str]] = defaultdict(set)
    src_events: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in events:
        if e.remote_address:
            src_targets[e.remote_address].add(e.host)
            src_events[e.remote_address].append(e)

    for src_ip, targets in src_targets.items():
        if len(targets) >= 3:
            evts = sorted(src_events[src_ip], key=lambda x: x.timestamp)
            start_t = evts[0].timestamp
            end_t = evts[-1].timestamp
            dur = max(1.0, (end_t - start_t).total_seconds())
            patterns.append(
                AttackPattern(
                    pattern_id=f"pat_recon_{uuid.uuid4().hex[:6]}",
                    pattern_type=PatternType.RECON_SWEEP,
                    title=f"Multi-Host Reconnaissance Sweep ({len(targets)} internal endpoints probed)",
                    mitre_id="T1046",
                    technique_name="Network Service Discovery",
                    kill_chain_stage=KillChainStage.RECONNAISSANCE,
                    target_host=f"{len(targets)} hosts ({', '.join(list(targets)[:3])}...)",
                    source_ip=src_ip,
                    attempt_count=len(evts),
                    start_time=start_t,
                    end_time=end_t,
                    duration_seconds=dur,
                    velocity_attempts_per_sec=round(len(evts) / dur, 2),
                    evidence_event_ids=[x.event_id for x in evts[:8]],
                    status=_determine_status([x.command_line or "" for x in evts]),
                )
            )

    # 2b. Check for distributed exploit wave across multiple endpoints (T1190)
    exploit_events = [e for e in events if any("T1190" in m for m in (e.mitre_ids or []))]
    if len(exploit_events) >= 3:
        exp_targets = sorted({e.host for e in exploit_events if e.host})
        if len(exp_targets) >= 2:
            start_t = min(e.timestamp for e in exploit_events)
            end_t = max(e.timestamp for e in exploit_events)
            dur = max(1.0, (end_t - start_t).total_seconds())
            patterns.append(
                AttackPattern(
                    pattern_id=f"pat_exp_dist_{uuid.uuid4().hex[:6]}",
                    pattern_type=PatternType.EXPLOIT_WAVE,
                    title=f"Distributed Enterprise Exploit Wave ({len(exploit_events)} probes across {len(exp_targets)} hosts)",
                    mitre_id="T1190",
                    technique_name="Exploit Public-Facing Application",
                    kill_chain_stage=KillChainStage.INITIAL_ACCESS,
                    target_host=f"{len(exp_targets)} endpoints ({', '.join(exp_targets[:3])}...)",
                    source_ip="Multi-Source Adversary Botnet",
                    attempt_count=len(exploit_events),
                    start_time=start_t,
                    end_time=end_t,
                    duration_seconds=dur,
                    velocity_attempts_per_sec=round(len(exploit_events) / dur, 2),
                    evidence_event_ids=[x.event_id for x in exploit_events[:8]],
                    status=_determine_status([x.command_line or "" for x in exploit_events]),
                )
            )

    # 2c. Check for multi-endpoint C2 beaconing activity (T1071)
    c2_events = [e for e in events if any("T1071" in m for m in (e.mitre_ids or []))]
    if len(c2_events) >= 3:
        c2_targets = sorted({e.host for e in c2_events if e.host})
        start_t = min(e.timestamp for e in c2_events)
        end_t = max(e.timestamp for e in c2_events)
        dur = max(1.0, (end_t - start_t).total_seconds())
        patterns.append(
            AttackPattern(
                pattern_id=f"pat_c2_dist_{uuid.uuid4().hex[:6]}",
                pattern_type=PatternType.C2_BEACONING,
                title=f"Multi-Endpoint C2 Beaconing Channel ({len(c2_events)} egress sessions across {len(c2_targets)} endpoints)",
                mitre_id="T1071",
                technique_name="Application Layer Protocol",
                kill_chain_stage=KillChainStage.COMMAND_AND_CONTROL,
                target_host=f"{len(c2_targets)} endpoints ({', '.join(c2_targets[:3])}...)",
                source_ip="External C2 Infrastructure",
                attempt_count=len(c2_events),
                start_time=start_t,
                end_time=end_t,
                duration_seconds=dur,
                velocity_attempts_per_sec=round(len(c2_events) / dur, 2),
                evidence_event_ids=[x.event_id for x in c2_events[:8]],
                status=_determine_status([x.command_line or "" for x in c2_events]),
            )
        )

    # 2d. Evaluate Config-Driven Detection Rules from rules/*.yaml (PRD Bonus B-4)
    yaml_rules = load_yaml_detection_rules()
    for rule in yaml_rules:
        cond = rule.get("condition", {})
        min_evts = cond.get("min_events", 2)
        match_mitre = set(cond.get("match_mitre", []))
        match_keywords = [k.lower() for k in cond.get("match_keywords", [])]

        matched_evts = []
        for e in events:
            has_mitre = any(m in match_mitre for m in (e.mitre_ids or []))
            cmd_l = (e.command_line or "").lower()
            sum_l = (e.summary or "").lower()
            has_kw = any(k in cmd_l or k in sum_l for k in match_keywords)
            if has_mitre or has_kw:
                matched_evts.append(e)

        if len(matched_evts) >= min_evts:
            r_targets = sorted({e.host for e in matched_evts if e.host})
            multi_thresh = cond.get("multi_target_threshold", 1)
            if len(r_targets) >= multi_thresh:
                r_mitre = rule.get("mitre_id", "T1000")
                if not any(p.mitre_id == r_mitre for p in patterns):
                    evts_s = sorted(matched_evts, key=lambda x: x.timestamp)
                    start_t = evts_s[0].timestamp
                    end_t = evts_s[-1].timestamp
                    dur = max(1.0, (end_t - start_t).total_seconds())
                    stage_val = rule.get("kill_chain_stage", "initial_access")
                    try:
                        kc_stage = KillChainStage(stage_val)
                    except ValueError:
                        kc_stage = KillChainStage.INITIAL_ACCESS
                    patterns.append(
                        AttackPattern(
                            pattern_id=f"pat_yaml_{uuid.uuid4().hex[:6]}",
                            pattern_type=PatternType.EXPLOIT_WAVE
                            if "exploit" in rule.get("pattern_type", "")
                            else PatternType.ANOMALOUS_BURST,
                            title=f"[Config Rule] {rule.get('title', 'Custom Attack Pattern')} ({len(matched_evts)} events)",
                            mitre_id=r_mitre,
                            technique_name=rule.get("technique_name", "Signature Detection"),
                            kill_chain_stage=kc_stage,
                            target_host=f"{len(r_targets)} hosts ({', '.join(r_targets[:3])}...)"
                            if len(r_targets) > 1
                            else (r_targets[0] if r_targets else "N/A"),
                            source_ip="Adversary Ingress",
                            attempt_count=len(matched_evts),
                            start_time=start_t,
                            end_time=end_t,
                            duration_seconds=dur,
                            velocity_attempts_per_sec=round(len(matched_evts) / dur, 2),
                            evidence_event_ids=[x.event_id for x in evts_s[:8]],
                            status=_determine_status([x.command_line or "" for x in evts_s]),
                        )
                    )

    # 3. Process grouped bursts
    for (target, src, tactic), evts in grouped.items():
        evts = sorted(evts, key=lambda x: x.timestamp)
        count = len(evts)
        start_t = evts[0].timestamp
        end_t = evts[-1].timestamp
        dur = max(1.0, (end_t - start_t).total_seconds())
        velocity = round(count / dur, 2)
        sample_ids = [x.event_id for x in evts[:8]]
        cmds = [x.command_line or "" for x in evts]

        if tactic == "brute_force" and count >= 2:
            patterns.append(
                AttackPattern(
                    pattern_id=f"pat_bf_{uuid.uuid4().hex[:6]}",
                    pattern_type=PatternType.BRUTE_FORCE,
                    title=f"Authentication Assault / Brute Force ({count} attempts in {dur:.0f}s)",
                    mitre_id="T1110",
                    technique_name="Brute Force",
                    kill_chain_stage=KillChainStage.CREDENTIAL_ACCESS,
                    target_host=target,
                    source_ip=src,
                    attempt_count=count,
                    start_time=start_t,
                    end_time=end_t,
                    duration_seconds=dur,
                    velocity_attempts_per_sec=velocity,
                    evidence_event_ids=sample_ids,
                    status=_determine_status(cmds),
                )
            )
        elif tactic == "exploit_wave" and count >= 2:
            patterns.append(
                AttackPattern(
                    pattern_id=f"pat_exp_{uuid.uuid4().hex[:6]}",
                    pattern_type=PatternType.EXPLOIT_WAVE,
                    title=f"High-Volume Exploit Wave ({count} inbound probes against {target})",
                    mitre_id="T1190",
                    technique_name="Exploit Public-Facing Application",
                    kill_chain_stage=KillChainStage.INITIAL_ACCESS,
                    target_host=target,
                    source_ip=src,
                    attempt_count=count,
                    start_time=start_t,
                    end_time=end_t,
                    duration_seconds=dur,
                    velocity_attempts_per_sec=velocity,
                    evidence_event_ids=sample_ids,
                    status=_determine_status(cmds),
                )
            )
        elif tactic == "c2_beaconing" and count >= 2:
            patterns.append(
                AttackPattern(
                    pattern_id=f"pat_c2_{uuid.uuid4().hex[:6]}",
                    pattern_type=PatternType.C2_BEACONING,
                    title=f"Persistent C2 Beaconing Channel ({count} egress requests to {src})",
                    mitre_id="T1071",
                    technique_name="Application Layer Protocol",
                    kill_chain_stage=KillChainStage.COMMAND_AND_CONTROL,
                    target_host=target,
                    source_ip=src,
                    attempt_count=count,
                    start_time=start_t,
                    end_time=end_t,
                    duration_seconds=dur,
                    velocity_attempts_per_sec=velocity,
                    evidence_event_ids=sample_ids,
                    status=_determine_status(cmds),
                )
            )
        elif tactic == "lateral_movement" and count >= 2:
            patterns.append(
                AttackPattern(
                    pattern_id=f"pat_lat_{uuid.uuid4().hex[:6]}",
                    pattern_type=PatternType.LATERAL_MOVEMENT,
                    title=f"Lateral Movement Pivot ({count} internal hops {src} -> {target})",
                    mitre_id="T1021",
                    technique_name="Remote Services",
                    kill_chain_stage=KillChainStage.LATERAL_MOVEMENT,
                    target_host=target,
                    source_ip=src,
                    attempt_count=count,
                    start_time=start_t,
                    end_time=end_t,
                    duration_seconds=dur,
                    velocity_attempts_per_sec=velocity,
                    evidence_event_ids=sample_ids,
                    status=_determine_status(cmds),
                )
            )
        elif count >= 3:
            patterns.append(
                AttackPattern(
                    pattern_id=f"pat_anom_{uuid.uuid4().hex[:6]}",
                    pattern_type=PatternType.ANOMALOUS_BURST,
                    title=f"Repeated Anomalous Activity Burst ({count} events)",
                    mitre_id="T1190",
                    technique_name="Suspicious Burst Traffic",
                    kill_chain_stage=KillChainStage.INITIAL_ACCESS,
                    target_host=target,
                    source_ip=src,
                    attempt_count=count,
                    start_time=start_t,
                    end_time=end_t,
                    duration_seconds=dur,
                    velocity_attempts_per_sec=velocity,
                    evidence_event_ids=sample_ids,
                    status=_determine_status(cmds),
                )
            )

    return sorted(patterns, key=lambda p: (p.attempt_count, p.start_time), reverse=True)


def detect_attack_patterns(
    dataset_id: str,
    events: Sequence[NormalizedEvent] | None = None,
) -> list[AttackPattern]:
    """
    Main pattern detector: detects patterns from dataset Parquet store if available,
    or falls back to in-memory events.
    """
    if events:
        return detect_patterns_from_events(events)

    # Query DuckDB directly over parquet
    store = DuckDBStore()
    parquet_glob = store.get_dataset_parquet_glob(dataset_id)
    sql = f"""
        SELECT 
            host, 
            remote_address, 
            mitre_ids, 
            category, 
            LIST(command_line) as cmd_lines, 
            COUNT(*) as attempt_count,
            MIN(timestamp) as start_t,
            MAX(timestamp) as end_t,
            LIST(event_id) as event_ids
        FROM read_parquet('{parquet_glob}')
        WHERE mitre_ids IS NOT NULL AND ARRAY_LENGTH(mitre_ids) > 0
        GROUP BY host, remote_address, mitre_ids, category
        HAVING COUNT(*) >= 2
        ORDER BY attempt_count DESC
        LIMIT 50
    """
    try:
        rows = store.query(sql)
    except Exception:  # noqa: BLE001
        rows = []

    if not rows and events:
        return detect_patterns_from_events(events)

    patterns: list[AttackPattern] = []
    for r in rows:
        host, r_addr, m_ids, cat, cmd_lines, cnt, st, et, e_ids = r
        m_id = m_ids[0] if m_ids else "T1190"
        st_dt = datetime.fromisoformat(str(st)).replace(tzinfo=timezone.utc)
        et_dt = datetime.fromisoformat(str(et)).replace(tzinfo=timezone.utc)
        dur = max(1.0, (et_dt - st_dt).total_seconds())

        p_type = PatternType.ANOMALOUS_BURST
        stage = KillChainStage.DELIVERY
        t_name = "Exploit Attempt"

        if "T1110" in m_ids or cat == "auth":
            p_type = PatternType.BRUTE_FORCE
            stage = KillChainStage.CREDENTIAL_ACCESS
            t_name = "Brute Force"
        elif "T1190" in m_ids:
            p_type = PatternType.EXPLOIT_WAVE
            stage = KillChainStage.INITIAL_ACCESS
            t_name = "Exploit Public-Facing Application"
        elif "T1071" in m_ids:
            p_type = PatternType.C2_BEACONING
            stage = KillChainStage.COMMAND_AND_CONTROL
            t_name = "Application Layer Protocol"
        elif "T1021" in m_ids:
            p_type = PatternType.LATERAL_MOVEMENT
            stage = KillChainStage.LATERAL_MOVEMENT
            t_name = "Remote Services"

        patterns.append(
            AttackPattern(
                pattern_id=f"pat_{uuid.uuid4().hex[:6]}",
                pattern_type=p_type,
                title=f"{t_name} Wave ({cnt} events on {host})",
                mitre_id=m_id,
                technique_name=t_name,
                kill_chain_stage=stage,
                target_host=host or "unknown",
                source_ip=r_addr,
                attempt_count=cnt,
                start_time=st_dt,
                end_time=et_dt,
                duration_seconds=dur,
                velocity_attempts_per_sec=round(cnt / dur, 2),
                evidence_event_ids=list(e_ids)[:8] if e_ids else [],
                status=_determine_status([c or "" for c in (cmd_lines or [])]),
            )
        )

    return patterns
