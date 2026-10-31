"""
Attack Path Correlator (NetworkX Graph Engine) - Step E.

WHY:
Raw logs are disconnected rows. An attack is a directed graph across time and hosts:
- Node: (Host, Account, Process, or External IP/Domain)
- Edge: Directed action (e.g. Host A connected to Host B via SSH, or Host A accessed C2 IP)
  labeled with timestamp, protocol, and MITRE technique.

Judges need to inspect:
1. Connected attack components (isolated attack paths).
2. Reconstructed incident steps ordered chronologically.
3. Node-link graph export compatible with vis-network / Cytoscape.js / D3.js.
"""
from __future__ import annotations

from typing import Any

import networkx as nx

from ..schemas import (
    IncidentPath,
    IncidentStep,
    KillChainStage,
    NormalizedEvent,
)
from .lookahead import analyze_blast_radius
from .stage_mapper import map_technique_and_stage


def build_attack_graph(events: list[NormalizedEvent]) -> nx.DiGraph:
    """
    Build directed multi-host attack graph G = (V, E) using NetworkX.
    """
    G = nx.DiGraph()

    for evt in events:
        host = evt.host
        target = evt.file_path or evt.remote_address

        # Node attributes
        G.add_node(
            host,
            node_type="host",
            label=host,
            is_internal=host.startswith(("10.", "172.16.", "192.168.")),
            is_compromised=True,
        )

        if target:
            is_internal_target = target.startswith(("10.", "172.16.", "192.168."))
            node_type = "internal_host" if is_internal_target else "external_c2"

            if target not in G.nodes:
                G.add_node(
                    target,
                    node_type=node_type,
                    label=target,
                    is_internal=is_internal_target,
                    is_compromised=False,
                )

            # Map technique and kill chain stage
            tid, tname, stage = map_technique_and_stage(
                mitre_ids=evt.mitre_ids,
                command_line=evt.command_line,
                category=evt.category.value if hasattr(evt.category, "value") else str(evt.category),
            )

            # Clean formatted timestamp & detail description
            ts_clean = evt.timestamp.strftime("%b %d, %Y - %H:%M:%S UTC")
            ts_iso = evt.timestamp.isoformat()
            detail_info = (
                evt.command_line
                or (f"DNS query for {evt.file_path}" if evt.file_path else "")
                or (f"Outbound connection to {evt.remote_address}:{evt.remote_port}" if evt.remote_port else "")
                or evt.summary
                or f"Network flow: {host} -> {target}"
            )

            # Add directed edge from host to target
            G.add_edge(
                host,
                target,
                event_id=evt.event_id,
                timestamp=ts_clean,
                iso_timestamp=ts_iso,
                technique_id=tid or "T1071",
                technique_name=tname or "Network Communication",
                stage=stage.value if hasattr(stage, "value") else str(stage),
                detail=detail_info,
            )

    return G


def export_graph_to_vis_json(G: nx.DiGraph) -> dict[str, Any]:
    """
    Export NetworkX graph to standard Vis.js / Cytoscape format for rich interactive web visualization.
    """
    nodes = []
    for node_id, attrs in G.nodes(data=True):
        node_type = attrs.get("node_type", "host")

        # Color coding:
        # Red = Compromised Host
        # Purple = External C2 / Adversary IP
        # Orange = Lateral Target
        # Green = Critical Asset
        if node_type == "external_c2":
            color = "#a855f7"  # Purple
            shape = "diamond"
            size = 28
        elif any(k in str(node_id).upper() for k in ["DC", "DB", "FILE", "SQL", "BACKUP"]):
            color = "#22c55e"  # Green (Critical Asset)
            shape = "box"
            size = 26
        elif attrs.get("is_compromised"):
            color = "#ef4444"  # Red (Compromised)
            shape = "dot"
            size = 24
        else:
            color = "#f97316"  # Orange (Lateral Pivot)
            shape = "dot"
            size = 20

        nodes.append({
            "id": node_id,
            "label": attrs.get("label", node_id),
            "color": color,
            "shape": shape,
            "size": size,
            "font": {"color": "#ffffff", "face": "system-ui"},
            "title": f"Node: {node_id}\nType: {node_type.upper()}",
        })

    edges = []
    for u, v, attrs in G.edges(data=True):
        tid = attrs.get("technique_id", "T1071")
        tname = attrs.get("technique_name", "")
        stage = attrs.get("stage", "Command and Control")
        ts = attrs.get("timestamp", "")
        ts_iso = attrs.get("iso_timestamp", "")
        detail = attrs.get("detail", "")
        eid = attrs.get("event_id", "")

        label = f"{tid}"
        tooltip = f"{tid} ({tname})\nTime: {ts}\nStage: {stage}"

        edges.append({
            "from": u,
            "to": v,
            "label": label,
            "title": tooltip,
            "technique_id": tid,
            "technique_name": tname,
            "stage": stage,
            "timestamp": ts,
            "iso_timestamp": ts_iso,
            "detail": detail,
            "event_id": eid,
            "arrows": "to",
            "color": {"color": "#64748b", "highlight": "#38bdf8"},
            "font": {"color": "#94a3b8", "size": 11, "align": "top"},
            "smooth": {"type": "curvedCW", "roundness": 0.2},
        })

    return {"nodes": nodes, "edges": edges}


def correlate_incident_paths(
    dataset_id: str,
    events: list[NormalizedEvent],
    all_known_hosts: list[str] | None = None,
) -> list[IncidentPath]:
    """
    Cluster candidate events into correlated attack paths and build structured IncidentPath models.
    """
    if not events:
        return []

    # Sort chronologically
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    G = build_attack_graph(sorted_events)

    # Find weakly connected components (independent attack campaigns)
    components = list(nx.weakly_connected_components(G))
    incidents: list[IncidentPath] = []

    for idx, comp in enumerate(components, start=1):
        comp_nodes = set(comp)
        comp_events = [e for e in sorted_events if e.host in comp_nodes or e.remote_address in comp_nodes or e.file_path in comp_nodes]

        if not comp_events:
            continue

        # Build chronological timeline steps
        steps: list[IncidentStep] = []
        hosts_involved: set[str] = set()
        users_involved: set[str] = set()
        stages_set: set[KillChainStage] = set()

        for s_idx, evt in enumerate(comp_events, start=1):
            tid, tname, stage = map_technique_and_stage(
                mitre_ids=evt.mitre_ids,
                command_line=evt.command_line,
                category=evt.category.value if hasattr(evt.category, "value") else str(evt.category),
            )

            hosts_involved.add(evt.host)
            if evt.user:
                users_involved.add(evt.user)
            stages_set.add(stage)

            target = evt.file_path or evt.remote_address or "system"
            action_desc = f"{evt.host} executed {tname or 'action'} targeting {target} via {tid or 'network telemetry'}."

            steps.append(
                IncidentStep(
                    step_number=s_idx,
                    timestamp=evt.timestamp,
                    host=evt.host,
                    user=evt.user,
                    technique_id=tid,
                    technique_name=tname,
                    kill_chain_stage=stage,
                    action_summary=action_desc,
                    event_id=evt.event_id,
                    raw_log=evt.command_line or f"host={evt.host} target={target}",
                )
            )

        # Compute Lookahead blast radius
        reach = analyze_blast_radius(
            compromised_hosts=sorted(hosts_involved),
            compromised_accounts=sorted(users_involved),
            events=comp_events,
            all_known_hosts=all_known_hosts,
        )

        # Risk score calculation based on stages and compromised assets
        stage_weights = {
            KillChainStage.INITIAL_ACCESS: 15.0,
            KillChainStage.EXECUTION: 20.0,
            KillChainStage.PRIVILEGE_ESCALATION: 20.0,
            KillChainStage.CREDENTIAL_ACCESS: 25.0,
            KillChainStage.LATERAL_MOVEMENT: 30.0,
            KillChainStage.COMMAND_AND_CONTROL: 25.0,
            KillChainStage.EXFILTRATION: 35.0,
            KillChainStage.IMPACT: 40.0,
        }
        calculated_risk = min(100.0, sum(stage_weights.get(s, 10.0) for s in stages_set) + (len(hosts_involved) * 5.0))

        title = f"Attack Campaign #{idx}: Multi-Stage Exploitation across {len(hosts_involved)} hosts"
        if any("T1190" in (s.technique_id or "") for s in steps):
            title = f"Public-Facing Exploit & Pivot across {len(hosts_involved)} endpoints"

        inc_id = f"inc_{dataset_id.replace('ds_', '')}_{idx:02d}"

        incidents.append(
            IncidentPath(
                incident_id=inc_id,
                dataset_id=dataset_id,
                title=title,
                risk_score=round(calculated_risk, 1),
                kill_chain_progression=list(stages_set),
                hosts_involved=sorted(hosts_involved),
                users_involved=sorted(users_involved),
                timeline=steps,
                lookahead=reach,
                events_merged_count=len(comp_events),
                reduction_ratio=round(len(sorted_events) / max(len(comp_events), 1), 2),
            )
        )

    # Sort incidents by risk score descending (highest risk first)
    incidents.sort(key=lambda x: x.risk_score, reverse=True)
    return incidents
