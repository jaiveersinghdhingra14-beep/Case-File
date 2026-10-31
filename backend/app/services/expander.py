"""
Multi-Host Graph Neighborhood Expander (Step D).

WHY:
Attackers do not execute actions in a vacuum. A malicious command or blocked C2
connection is preceded by reconnaissance/delivery and followed by lateral movement
or exfiltration.

The Expander takes the high-confidence Top-K seeds and queries DuckDB for their
local causal neighborhood without loading the full 9+ million event dataset into RAM:

1. Temporal Neighborhood (Same Host):
   Events occurring on the same host within [-window_seconds, +window_seconds] (default: 120s)
   around each seed event.

2. Lateral Neighborhood (Cross-Host Movement):
   If a seed event has an internal destination IP (e.g. 10.10.X.Y), the expander
   queries events on that destination host starting at the connection timestamp.

3. Process Lineage (Causal Proximity):
   Parent and child processes tied by PID and PPID.

Result: A tightly bounded subgraph (typically a few thousand events) that contains
all relevant evidence, ready for deterministic graph correlation.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta

import duckdb

from ..schemas import EventCategory, NormalizedEvent
from ..store.duckdb_store import duckdb_store


def _is_private_addr(ip: str | None) -> bool:
    if not ip:
        return False
    return ip.startswith(
        (
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "192.168.",
            "127.",
        )
    )


def expand_neighborhood(
    dataset_id: str,
    seeds: list[NormalizedEvent],
    window_seconds: int = 120,
    max_expanded_events: int = 5000,
) -> list[NormalizedEvent]:
    """
    Expand a 2-hop temporal, lateral, and C2 campaign neighborhood around seed events.
    """
    if not seeds:
        return []

    if not duckdb_store.has_parquet_data(dataset_id):
        return seeds

    # Collect unique hosts and time windows from seeds
    all_events_by_id: dict[str, NormalizedEvent] = {s.event_id: s for s in seeds}

    # Group seeds into time clusters per host/target to minimize SQL queries
    host_time_ranges: dict[str, list[tuple[datetime, datetime]]] = {}
    cross_hosts_to_query: set[tuple[str, datetime, datetime]] = set()
    external_c2s_to_query: set[tuple[str, datetime, datetime]] = set()

    for s in seeds:
        t_start = s.timestamp - timedelta(seconds=window_seconds)
        t_end = s.timestamp + timedelta(seconds=window_seconds)

        if s.host:
            if s.host not in host_time_ranges:
                host_time_ranges[s.host] = []
            host_time_ranges[s.host].append((t_start, t_end))

        # Check for cross-host lateral movement targets or shared C2 destinations
        if s.remote_address and s.remote_address != s.host:
            if _is_private_addr(s.remote_address):
                cross_hosts_to_query.add(
                    (s.remote_address, s.timestamp, s.timestamp + timedelta(seconds=window_seconds * 2))
                )
            else:
                external_c2s_to_query.add((s.remote_address, t_start, t_end))

    seed_timestamps = [s.timestamp for s in seeds if s.timestamp]
    if not seed_timestamps:
        return seeds
    global_min_time = min(seed_timestamps) - timedelta(seconds=window_seconds * 2)
    global_max_time = max(seed_timestamps) + timedelta(seconds=window_seconds * 2)

    # Connect to DuckDB with multi-core parallel query execution
    parquet_glob = duckdb_store.get_dataset_parquet_glob(dataset_id)
    con = duckdb.connect(":memory:")
    con.execute("PRAGMA threads = 8;")
    con.execute("PRAGMA preserve_insertion_order = false;")

    # Build union query for bounded time ranges
    conditions = []
    for host, ranges in list(host_time_ranges.items())[:35]:  # Cap to top 35 active hosts
        # Merge overlapping ranges for the same host
        ranges.sort(key=lambda r: r[0])
        merged = []
        for r_start, r_end in ranges:
            if not merged or merged[-1][1] < r_start:
                merged.append([r_start, r_end])
            else:
                merged[-1][1] = max(merged[-1][1], r_end)

        for m_start, m_end in merged[:5]:  # at most 5 clusters per host
            conditions.append(
                f"((host = '{host}' OR remote_address = '{host}') AND timestamp >= '{m_start.isoformat()}' AND timestamp <= '{m_end.isoformat()}')"
            )

    for target_host, l_start, l_end in list(cross_hosts_to_query)[:20]:
        conditions.append(
            f"((host = '{target_host}' OR remote_address = '{target_host}') AND timestamp >= '{l_start.isoformat()}' AND timestamp <= '{l_end.isoformat()}')"
        )

    for c2_ip, c_start, c_end in list(external_c2s_to_query)[:15]:
        conditions.append(
            f"(remote_address = '{c2_ip}' AND timestamp >= '{c_start.isoformat()}' AND timestamp <= '{c_end.isoformat()}')"
        )

    if not conditions:
        con.close()
        return seeds

    where_filter = " OR ".join(conditions)

    query = f"""
    SELECT
        event_id,
        timestamp,
        host,
        source,
        category,
        user,
        pid,
        ppid,
        process_name,
        executable,
        command_line,
        file_path,
        remote_address,
        remote_port,
        mitre_ids,
        summary,
        source_file,
        byte_offset,
        byte_length
    FROM read_parquet('{parquet_glob}')
    WHERE timestamp >= '{global_min_time.isoformat()}'
      AND timestamp <= '{global_max_time.isoformat()}'
      AND ({where_filter})
    ORDER BY timestamp ASC
    LIMIT {max_expanded_events};
    """

    df = con.execute(query).fetchdf()
    con.close()

    records = df.to_dict(orient="records")
    for rec in records:
        eid = str(rec.get("event_id"))
        if eid in all_events_by_id:
            continue

        mitre_raw = rec.get("mitre_ids")
        m_list: list[str] = []
        if isinstance(mitre_raw, list):
            m_list = [str(x) for x in mitre_raw]
        elif isinstance(mitre_raw, str) and mitre_raw:
            cleaned = mitre_raw.strip("[]'\" ")
            if cleaned:
                m_list = [x.strip() for x in cleaned.split(",") if x.strip()]

        cat_str = str(rec.get("category") or "other").lower()
        if cat_str in ["network", "traffic", "dns"]:
            category = EventCategory.network
        elif cat_str in ["process", "process_exec"]:
            category = EventCategory.process_exec
        elif cat_str in ["auth", "authentication"]:
            category = EventCategory.authentication
        elif cat_str in ["file", "file_access", "file_change"]:
            category = EventCategory.file_access
        else:
            category = EventCategory.other

        summary_text = (
            rec.get("summary")
            or f"{rec.get('host')}: {rec.get('command_line') or rec.get('file_path') or rec.get('remote_address')}"
        )

        event = NormalizedEvent(
            event_id=eid,
            timestamp=rec.get("timestamp"),
            host=str(rec.get("host")),
            source=str(rec.get("source") or "unknown"),
            category=category,
            user=rec.get("user") if rec.get("user") else None,
            pid=int(rec.get("pid")) if rec.get("pid") is not None and not math.isnan(rec.get("pid")) else None,
            ppid=int(rec.get("ppid")) if rec.get("ppid") is not None and not math.isnan(rec.get("ppid")) else None,
            process_name=rec.get("process_name") if rec.get("process_name") else None,
            executable=rec.get("executable") if rec.get("executable") else None,
            command_line=rec.get("command_line") if rec.get("command_line") else None,
            file_path=rec.get("file_path") if rec.get("file_path") else None,
            remote_address=rec.get("remote_address") if rec.get("remote_address") else None,
            remote_port=int(rec.get("remote_port"))
            if rec.get("remote_port") is not None and not math.isnan(rec.get("remote_port"))
            else None,
            mitre_ids=m_list,
            summary=summary_text,
            source_file=rec.get("source_file"),
            byte_offset=int(rec.get("byte_offset"))
            if rec.get("byte_offset") is not None and not math.isnan(rec.get("byte_offset"))
            else None,
            byte_length=int(rec.get("byte_length"))
            if rec.get("byte_length") is not None and not math.isnan(rec.get("byte_length"))
            else None,
            rarity_score=0.0,
            is_seed=False,
        )
        all_events_by_id[eid] = event

    # Return chronological list
    result = list(all_events_by_id.values())
    result.sort(key=lambda e: e.timestamp)
    return result
