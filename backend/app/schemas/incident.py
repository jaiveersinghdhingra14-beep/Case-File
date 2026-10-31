from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from .common import KillChainStage


class PatternType(str, Enum):
    BRUTE_FORCE = "brute_force"
    EXPLOIT_WAVE = "exploit_wave"
    RECON_SWEEP = "recon_sweep"
    C2_BEACONING = "c2_beaconing"
    LATERAL_MOVEMENT = "lateral_movement"
    ANOMALOUS_BURST = "anomalous_burst"


class AttackPattern(BaseModel):
    pattern_id: str = Field(description="Unique pattern cluster ID, e.g. pat_01")
    pattern_type: PatternType = Field(description="Type of pattern (e.g. brute_force, exploit_wave, c2_beaconing)")
    title: str = Field(description="Human-readable title describing the pattern burst")
    mitre_id: str = Field(description="Primary MITRE ATT&CK ID (e.g. T1110, T1190, T1071)")
    technique_name: str = Field(description="Name of MITRE technique")
    kill_chain_stage: KillChainStage = Field(description="Cyber kill chain stage")
    target_host: str = Field(description="Primary target host or IP")
    source_ip: str | None = Field(default=None, description="Source attacker or pivot IP")
    attempt_count: int = Field(description="Number of attempts/events in this burst cluster")
    start_time: datetime = Field(description="Start time of burst")
    end_time: datetime = Field(description="End time of burst")
    duration_seconds: float = Field(default=0.0, description="Duration in seconds")
    velocity_attempts_per_sec: float = Field(default=0.0, description="Rate of attack")
    evidence_event_ids: list[str] = Field(default_factory=list, description="IDs of sample events proving this pattern")
    status: str = Field(default="blocked", description="Firewall or system action (blocked, allowed, mixed)")


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
    reachable_hosts: list[str] = Field(
        description="Hosts the attacker could reach next via admin rights, credentials, or network routes."
    )
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
