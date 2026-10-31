from datetime import datetime, timezone

from fastapi import APIRouter

from ...schemas import (
    IncidentList,
    IncidentPath,
    ReportResponse,
)
from ...store import db
from ..errors import not_found

router = APIRouter()


@router.get("/incidents", response_model=IncidentList)
def list_incidents(dataset_id: str | None = None) -> IncidentList:
    items = db.list_incidents(dataset_id=dataset_id)
    return IncidentList(items=items, total=len(items))


@router.get("/incidents/{incident_id}/path", response_model=IncidentPath)
def get_incident_path(incident_id: str) -> IncidentPath:
    inc = db.get_incident(incident_id)
    if not inc:
        raise not_found(f"Incident {incident_id} not found.")
    return inc


@router.get("/incidents/{incident_id}/report", response_model=ReportResponse)
def get_incident_report(incident_id: str) -> ReportResponse:
    inc = db.get_incident(incident_id)
    if not inc:
        raise not_found(f"Incident {incident_id} not found.")

    # Generate Markdown report
    stages_str = " -> ".join([s.value for s in inc.kill_chain_progression]) if inc.kill_chain_progression else "Unknown"
    hosts_str = ", ".join(inc.hosts_involved) if inc.hosts_involved else "None"
    users_str = ", ".join(inc.users_involved) if inc.users_involved else "None"

    md_lines = [
        f"# Incident Report: {inc.title}",
        f"**Incident ID**: `{inc.incident_id}` | **Risk Score**: {inc.risk_score:.1f}/100",
        f"**Kill Chain Progression**: {stages_str}",
        f"**Involved Hosts**: {hosts_str} | **Accounts**: {users_str}",
        f"**Merged Raw Events**: {inc.events_merged_count} (Reduction: {inc.reduction_ratio:.1f}x)",
        "",
        "## Reconstructed Attack Path",
        "",
    ]

    for step in inc.timeline:
        t_id = step.technique_id or "Unknown"
        t_name = step.technique_name or "Suspicious Action"
        stage = step.kill_chain_stage.value if step.kill_chain_stage else "Execution"
        md_lines.append(
            f"### Step {step.step_number}: {step.action_summary}\n"
            f"- **Timestamp**: `{step.timestamp.isoformat()}`\n"
            f"- **Host**: `{step.host}` | **User**: `{step.user or 'N/A'}`\n"
            f"- **MITRE Technique**: `{t_id}` ({t_name})\n"
            f"- **Kill Chain Stage**: `{stage}`\n"
            f"- **Cited Event**: `{step.event_id}`\n"
        )

    md_lines.extend([
        "## Adversary Look-Ahead & Blast Radius",
        f"- **Reachable Systems**: {', '.join(inc.lookahead.reachable_hosts) or 'None'}",
        f"- **Critical Assets at Immediate Risk**: {', '.join(inc.lookahead.critical_assets_at_risk) or 'None'}",
        "",
        "### Recommended Immediate Containment Actions",
    ])
    for rec in inc.lookahead.recommended_containment:
        md_lines.append(f"- [ ] {rec}")

    content = "\n".join(md_lines)

    return ReportResponse(
        story_id=inc.incident_id,
        format="markdown",
        content=content,
        generated_at=datetime.now(timezone.utc),
    )
