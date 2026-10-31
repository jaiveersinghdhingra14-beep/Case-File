from datetime import datetime

from pydantic import BaseModel, Field

from .common import Method, StoryStatus
from .story import TokenUsage


class GroundTruthStep(BaseModel):
    step_index: int = Field(description="Position in chain starting at 1.")
    technique_id: str = Field(description="ATT&CK ID of step.")
    technique_name: str = Field(description="Technique name.")
    tactic: str = Field(description="ATT&CK tactic.")
    started_at: datetime = Field(description="When the step started.")
    ended_at: datetime = Field(description="When the step finished.")
    executed_ok: bool = Field(default=True, description="Whether command finished without error.")
    note: str | None = Field(default=None, description="Short description of what was run.")


class EvaluateRequest(BaseModel):
    tolerance_seconds: int = Field(default=10, ge=0, le=120, description="Tolerance window in seconds.")


class StepMatch(BaseModel):
    ground_truth_step_index: int = Field(description="Step index in ground truth.")
    story_step_number: int | None = Field(
        default=None, description="Story step number it was matched to. Null if missed."
    )
    matched: bool = Field(description="True if both technique and time window matched.")
    technique_match: bool = Field(description="Whether some story step named this technique.")
    time_overlap: bool = Field(description="Whether time range overlapped.")


class Metrics(BaseModel):
    ground_truth_steps: int = Field(description="Total steps in truth chain.")
    story_steps: int = Field(description="Total steps in story.")
    matched_steps: int = Field(description="Steps successfully matched.")
    step_recall: float | None = Field(default=None, description="Matched divided by truth steps. Null if no truth.")
    step_precision: float | None = Field(default=None, description="Matched divided by story steps. Null if no steps.")
    false_steps: int = Field(description="Story steps that matched nothing. Crucial for noise_only.")
    order_accuracy: float | None = Field(default=None, description="Share of matched pairs in same relative order.")
    grounding_rate: float | None = Field(
        default=None, description="Share of cited events that fall inside the true window."
    )
    evidence_coverage: float | None = Field(default=None, description="Share of true window non-noise events cited.")


class Evaluation(BaseModel):
    evaluation_id: str = Field(description="Evaluation ID (prefix eval_ + 8 hex).")
    story_id: str = Field(description="The story scored.")
    case_id: str = Field(description="The case.")
    method: Method = Field(description="Method that produced the story.")
    tolerance_seconds: int = Field(description="Tolerance used.")
    matches: list[StepMatch] = Field(description="One row per true step.")
    metrics: Metrics = Field(description="Calculated benchmark scores.")
    created_at: datetime = Field(description="When computed.")


class MethodResult(BaseModel):
    method: Method = Field(description="Which method: casefile, baseline_window, baseline_raw.")
    story_id: str | None = Field(default=None, description="The story ID if generated.")
    status: StoryStatus | None = Field(default=None, description="Current story status.")
    metrics: Metrics | None = Field(default=None, description="Scores. Null until scored.")
    usage: TokenUsage | None = Field(default=None, description="Token use.")
    duration_seconds: float | None = Field(default=None, description="Time to produce story.")
    throughput_mb_s: float | None = Field(default=None, description="Throughput in MB/s.")
    peak_rss_mb: float | None = Field(default=None, description="Peak memory used.")


class ComparisonResponse(BaseModel):
    case_id: str = Field(description="The case ID.")
    dataset_id: str = Field(description="The dataset ID.")
    ground_truth_steps: int = Field(description="Steps in the true chain (0 if unknown).")
    results: list[MethodResult] = Field(
        description="One row per method in order: casefile, baseline_window, baseline_raw."
    )
    generated_at: datetime = Field(description="When comparison was computed.")
