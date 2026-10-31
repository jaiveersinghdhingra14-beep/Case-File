from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, model_validator


class KillChainStage(str, Enum):
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class DatasetStatus(str, Enum):
    registered = "registered"
    profiling = "profiling"
    ingesting = "ingesting"
    ready = "ready"
    failed = "failed"


class CaseStatus(str, Enum):
    created = "created"
    ingesting = "ingesting"
    normalizing = "normalizing"
    correlating = "correlating"
    ready = "ready"
    failed = "failed"


class StoryStatus(str, Enum):
    queued = "queued"
    generating = "generating"
    verifying = "verifying"
    awaiting_review = "awaiting_review"
    approved = "approved"
    rejected = "rejected"
    failed = "failed"


class Method(str, Enum):
    casefile = "casefile"
    baseline_window = "baseline_window"
    baseline_raw = "baseline_raw"


class CheckName(str, Enum):
    has_citation = "has_citation"
    ids_exist = "ids_exist"
    supports_claim = "supports_claim"
    specific_evidence = "specific_evidence"


class StepVerdict(str, Enum):
    supported = "supported"
    unsupported = "unsupported"


class EventCategory(str, Enum):
    process_exec = "process_exec"
    file_access = "file_access"
    file_change = "file_change"
    network = "network"
    authentication = "authentication"
    account_change = "account_change"
    scheduled_task = "scheduled_task"
    other = "other"


class AnalystDecision(str, Enum):
    confirmed = "confirmed"
    rejected = "rejected"


class ReviewOutcome(str, Enum):
    approved = "approved"
    rejected = "rejected"


class TimeWindow(BaseModel):
    start: datetime = Field(description="Start of the window (timezone.utc).")
    end: datetime = Field(description="End of the window (timezone.utc). Must be later than start.")

    @model_validator(mode="after")
    def validate_window(self) -> "TimeWindow":
        if self.end <= self.start:
            raise ValueError("end must be later than start")
        return self


class ErrorResponse(BaseModel):
    code: str = Field(description="Short machine-readable code, for example wrong_state.")
    detail: str = Field(description="Human-readable explanation, safe to show in the UI.")


class ComponentStatus(BaseModel):
    ok: bool = Field(description="Whether the component answered correctly.")
    detail: str | None = Field(default=None, description="Error message when ok is false.")
    latency_ms: int | None = Field(default=None, description="Response time of the check.")


class HealthResponse(BaseModel):
    status: str = Field(description="ok when everything works, degraded when any component is down.")
    app_version: str = Field(description="Version string of the backend.")
    dataset_store: ComponentStatus = Field(description="Can the parquet dataset store be read/queried?")
    duckdb: ComponentStatus = Field(description="Can DuckDB execute analytical queries?")
    database: ComponentStatus = Field(description="Can the app read and write SQLite?")
    llm: ComponentStatus = Field(description="Can the app reach the LLM provider (or mock)?")
