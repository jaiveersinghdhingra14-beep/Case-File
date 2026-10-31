from datetime import datetime

from pydantic import BaseModel, Field

from .common import CaseStatus, TimeWindow


class CaseCreateRequest(BaseModel):
    dataset_id: str = Field(description="Dataset ID to build the case from.")
    name: str | None = Field(default=None, description="Label shown in UI.")
    window: TimeWindow | None = Field(default=None, description="Optional custom time window for investigation.")
    host_names: list[str] | None = Field(
        default=None, description="Limit to specific hosts. Default: all hosts in dataset."
    )
    padding_seconds: int = Field(default=30, ge=0, le=300, description="Padding before and after time window.")
    group_gap_seconds: int = Field(
        default=60, ge=10, le=600, description="Events further apart are split into separate groups."
    )
    seed_top_k: int = Field(
        default=2000, ge=10, le=50000, description="Number of top rarity/suspicious seeds to select."
    )
    expansion_hops: int = Field(default=2, ge=1, le=5, description="Graph traversal hop limit around seeds.")
    expansion_window_seconds: int = Field(
        default=120, ge=10, le=3600, description="Time window for neighborhood expansion."
    )
    max_llm_calls: int = Field(default=200, ge=1, le=1000, description="Cap on total LLM calls per story.")


class CaseAccepted(BaseModel):
    case_id: str = Field(description="Case ID to poll.")
    status: CaseStatus = Field(description="Initial case status (created, ingesting).")


class CaseStats(BaseModel):
    events_ingested: int = Field(description="Total events in dataset window.")
    events_after_noise_filter: int = Field(description="Events left after reduction/filtering.")
    noise_removed: int = Field(description="Events filtered as benign background noise.")
    groups: int = Field(description="Activity groups found.")
    hosts: list[str] = Field(description="Hosts that appear in the events.")
    sources: list[str] = Field(description="Log sources appearing in events.")


class Case(BaseModel):
    case_id: str = Field(description="Unique Case ID (prefix case_ + 8 hex).")
    dataset_id: str = Field(description="Associated dataset ID.")
    name: str = Field(description="Case display label.")
    status: CaseStatus = Field(description="Current status.")
    created_at: datetime = Field(description="Creation time (timezone.utc).")
    updated_at: datetime = Field(description="Last update time (timezone.utc).")
    window: TimeWindow | None = Field(default=None, description="Investigation time window.")
    has_ground_truth: bool = Field(
        default=False, description="True only when ground truth labels exist for the dataset."
    )
    stats: CaseStats | None = Field(default=None, description="Summary statistics when ready.")
    error_message: str | None = Field(default=None, description="Failure reason if failed.")


class CaseList(BaseModel):
    items: list[Case] = Field(description="Cases, newest first.")
    total: int = Field(description="Total count of cases.")
