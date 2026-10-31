from datetime import datetime

from pydantic import BaseModel, Field

from .common import DatasetStatus, TimeWindow


class StageMetric(BaseModel):
    stage: str = Field(description="Pipeline stage name (profiler, ingest, reducer, expander, etc.).")
    rows_in: int = Field(description="Number of input records/events.")
    rows_out: int = Field(description="Number of surviving output records/events.")
    seconds: float = Field(description="Execution time in seconds.")
    peak_rss_mb: float = Field(description="Peak resident memory in megabytes during stage.")
    throughput_mb_s: float = Field(description="Data processing throughput in MB/s.")


class BenchmarkReport(BaseModel):
    dataset_id: str = Field(description="Dataset identifier (prefix ds_ + 8 hex).")
    stages: list[StageMetric] = Field(description="Metrics collected per processing stage.")
    total_seconds: float = Field(description="Overall runtime across all stages.")
    reduction_ratio: float = Field(description="Input raw events divided by surviving candidates (e.g. 500x).")


class DatasetCreateRequest(BaseModel):
    path: str = Field(description="Local path to raw log file or directory (no upload).")
    name: str | None = Field(default=None, description="Human-readable label for this dataset.")


class Dataset(BaseModel):
    dataset_id: str = Field(description="Unique dataset ID with prefix ds_ + 8 hex chars.")
    name: str = Field(description="Dataset display name.")
    path: str = Field(description="Path on disk where logs reside.")
    size_bytes: int = Field(description="Total file size in bytes.")
    format: str = Field(description="Detected format: auditd, jsonlines, syslog, csv, etc.")
    status: DatasetStatus = Field(description="Lifecycle status: registered, profiling, ingesting, ready, failed.")
    events_total: int = Field(default=0, description="Estimated or exact total log events.")
    time_range: TimeWindow | None = Field(default=None, description="Time span covered by events.")
    hosts: list[str] = Field(default_factory=list, description="Unique hosts detected in dataset.")
    created_at: datetime = Field(description="Registration timezone.utc timestamp.")
    error_message: str | None = Field(default=None, description="Error details if status is failed.")


class DatasetList(BaseModel):
    items: list[Dataset] = Field(description="List of registered datasets.")
    total: int = Field(description="Total number of registered datasets.")


class DatasetAccepted(BaseModel):
    dataset_id: str = Field(description="ID of the dataset being processed.")
    status: DatasetStatus = Field(description="Initial queued/ingesting status.")
