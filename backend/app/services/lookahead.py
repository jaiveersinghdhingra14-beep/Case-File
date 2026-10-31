"""
Blast Radius & Lookahead Reachability Analysis (PRD FR-6).

WHY:
Incident responders need to know not just what happened, but WHAT HAPPENS NEXT:
- If the attacker has compromised Host A with Account B, which machines can they reach next?
- What high-value servers (domain controllers, database servers, confidential shares)
  sit within their 1-hop and 2-hop radius?
- What immediate containment actions will stop lateral expansion?
"""
from __future__ import annotations

import re
from collections.abc import Sequence

from ..schemas import LookaheadReach, NormalizedEvent

# Well-known critical asset identifiers / naming conventions
CRITICAL_ASSET_PATTERNS = [
    re.compile(r"dc|domain|controller|ad", re.IGNORECASE),
    re.compile(r"db|database|sql|postgres|oracle", re.IGNORECASE),
    re.compile(r"file|share|storage|nas|san", re.IGNORECASE),
    re.compile(r"backup|recovery", re.IGNORECASE),
    re.compile(r"prod|core|infra", re.IGNORECASE),
]


def analyze_blast_radius(
    compromised_hosts: Sequence[str],
    compromised_accounts: Sequence[str],
    events: Sequence[NormalizedEvent],
    all_known_hosts: Sequence[str] | None = None,
) -> LookaheadReach:
    """
    Computes reachable hosts, critical assets at risk, and recommended containment steps (PRD FR-6).
    """
    comp_hosts_set = set(compromised_hosts)
    comp_accts_set = set(compromised_accounts)

    # 1. Identify network neighbors & observed lateral connection destinations
    reachable_hosts_set: set[str] = set()
    critical_assets_set: set[str] = set()
    external_c2s: set[str] = set()

    for evt in events:
        if evt.host in comp_hosts_set:
            if evt.user:
                comp_accts_set.add(evt.user)

            # Check where compromised hosts communicated
            target = evt.remote_address or evt.file_path
            if target:
                # Internal host
                if target.startswith(("10.", "172.16.", "192.168.")):
                    if target not in comp_hosts_set:
                        reachable_hosts_set.add(target)
                elif any(c in target for c in [".com", ".net", ".org", ".io", ".invalid", ".test"]) or not target.startswith("10."):
                    # Possible C2 destination
                    external_c2s.add(target)

    # 2. Add domain controllers / critical servers & subnet neighbors
    # Extract compromised subnet prefixes (e.g. "10.10.10.")
    comp_subnets: set[str] = set()
    for h in comp_hosts_set:
        parts = h.split(".")
        if len(parts) == 4 and parts[0] in ("10", "172", "192"):
            comp_subnets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.")

    if all_known_hosts:
        for h in all_known_hosts:
            if h not in comp_hosts_set:
                # Check for critical name patterns
                is_crit = any(pat.search(h) for pat in CRITICAL_ASSET_PATTERNS)
                # Check if host is in core server subnet (10.10.0.x)
                is_server_subnet = h.startswith(("10.10.0.", "10.0.0.", "192.168.0.", "192.168.1."))

                # Check if host shares the same layer-3 subnet with any compromised host
                is_subnet_neighbor = any(h.startswith(sub) for sub in comp_subnets)

                if is_crit or is_server_subnet:
                    reachable_hosts_set.add(h)
                    critical_assets_set.add(h)
                elif is_subnet_neighbor:
                    reachable_hosts_set.add(h)

    # If all_known_hosts has no server IPs but internal hosts are compromised,
    # infer server subnet reachability based on enterprise topology
    if not critical_assets_set and comp_subnets:
        for sub in sorted(comp_subnets):
            # The core /0 subnet is standard server segment in 10.10.x.x
            prefix = sub.rsplit(".", 2)[0]
            server_segment = f"{prefix}.0.0/24 (Identity & Database Infrastructure)"
            critical_assets_set.add(server_segment)
            reachable_hosts_set.add(f"{sub}0/24 (Local Broadcast Domain)")

    # Also evaluate reachable hosts against critical patterns
    for h in reachable_hosts_set:
        for pat in CRITICAL_ASSET_PATTERNS:
            if pat.search(h):
                critical_assets_set.add(h)

    # 3. Formulate Actionable Containment Steps
    containment_steps: list[str] = []

    if comp_accts_set:
        accts_str = ", ".join(sorted(comp_accts_set)[:5])
        containment_steps.append(
            f"Revoke active Kerberos tickets and force immediate password reset for compromised accounts: {accts_str}."
        )

    if comp_hosts_set:
        hosts_str = ", ".join(sorted(comp_hosts_set)[:5])
        containment_steps.append(
            f"Isolate compromised endpoint machines at network layer (EDR host isolation): {hosts_str}."
        )

    if external_c2s:
        c2_str = ", ".join(sorted(external_c2s)[:5])
        containment_steps.append(
            f"Block outbound egress traffic to observed adversary infrastructure: {c2_str}."
        )

    if critical_assets_set:
        crit_str = ", ".join(sorted(critical_assets_set)[:4])
        containment_steps.append(
            f"Enforce strict PAM/MFA gateway access and audit inbound connections to critical assets: {crit_str}."
        )
    else:
        containment_steps.append(
            "Enable enhanced telemetry auditing on internal domain controllers and database segments."
        )

    return LookaheadReach(
        compromised_accounts=sorted(comp_accts_set),
        compromised_hosts=sorted(comp_hosts_set),
        reachable_hosts=sorted(reachable_hosts_set)[:25],
        critical_assets_at_risk=sorted(critical_assets_set)[:10],
        recommended_containment=containment_steps,
    )
