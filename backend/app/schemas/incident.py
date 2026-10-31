from datetime import datetime

from pydantic import BaseModel, Field

from .common import KillChainStage


class IncidentStep(BaseModel):
    step_number: int = Field(description="Chronological step position starting at 1.")
    timestamp: datetime = Field(description="timezone.utc timestamp of the step.")
    host: str = Field(description="Host where step took place (e.g. Laptop HR-07, FS-02, DC-01).")
    user: str | None = Field(default=None, description="Account used in this step.")
    technique_id: str | None = Field(default=None, description="MITRE ATT&CK technique ID (e.g. T1110, T1078).")
    technique_name: str | None = Field(default=None, description="Technique name.")
    kill_chain_stage: KillChainStage | None = Field(default=None, description="Cyber Kill Chain stage.")
    action_summary: str = Field(description="One-sentence plain English description of what happened.")
    event_id: str = Field(description="Citing event ID.")
    raw_log: str | None = Field(default=None, description="Original log line loaded lazily.")


class LookaheadReach(BaseModel):
    compromised_accounts: list[str] = Field(description="Accounts verified under adversary control.")
    compromised_hosts: list[str] = Field(description="Machines compromised in this path.")
    reachable_hosts: list[str] = Field(description="Hosts the attacker could reach next via admin rights, credentials, or network routes.")
    critical_assets_at_risk: list[str] = Field(description="High-value servers or databases within attacker's reach.")
    recommended_containment: list[str] = Field(description="Immediate containment actions to stop the attack.")


class IncidentPath(BaseModel):
    incident_id: str = Field(description="Unique incident ID (prefix inc_ + 8 hex).")
    dataset_id: str = Field(description="Source dataset ID.")
    title: str = Field(description="Incident headline.")
    risk_score: float = Field(description="Incident severity score (0 to 100), worst on top.")
    kill_chain_progression: list[KillChainStage] = Field(description="Kill chain stages covered in order.")
    hosts_involved: list[str] = Field(description="Pivot path of hosts involved.")
    users_involved: list[str] = Field(description="Users involved.")
    timeline: list[IncidentStep] = Field(description="Chronological reconstructed attack path.")
    lookahead: LookaheadReach = Field(description="Predicted next reach and blast radius (FR-6).")
    events_merged_count: int = Field(description="How many raw events were clustered into this incident.")
    reduction_ratio: float = Field(description="Reduction ratio achieved for this incident.")


class IncidentSummary(BaseModel):
    incident_id: str = Field(description="Unique incident ID.")
    dataset_id: str = Field(description="Source dataset.")
    title: str = Field(description="Title of incident.")
    risk_score: float = Field(description="Risk score (0 to 100).")
    start_time: datetime = Field(description="Earliest event timestamp.")
    end_time: datetime = Field(description="Latest event timestamp.")
    hosts_involved: list[str] = Field(description="Hosts traversed.")
    step_count: int = Field(description="Number of verified steps.")
    events_merged_count: int = Field(description="Merged raw events count.")


class IncidentList(BaseModel):
    items: list[IncidentSummary] = Field(description="Incidents sorted by risk_score descending.")
    total: int = Field(description="Total incidents found.")
