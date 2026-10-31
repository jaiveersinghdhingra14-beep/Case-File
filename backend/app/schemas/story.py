from datetime import datetime

from pydantic import BaseModel, Field

from .common import (
    AnalystDecision,
    CheckName,
    Method,
    ReviewOutcome,
    StepVerdict,
    StoryStatus,
)


class EvidenceItem(BaseModel):
    event_id: str = Field(description="Event ID.")
    timestamp: datetime = Field(description="When it happened.")
    host: str = Field(description="Machine.")
    summary: str = Field(description="One-line summary.")
    raw_log: str = Field(description="The original log line, shown when a step is clicked.")


class CheckResult(BaseModel):
    name: CheckName = Field(description="Which check.")
    passed: bool = Field(description="Whether it passed.")
    detail: str = Field(description="Short result text, for example cited 3 events, 2 match T1053.003.")


class StoryStepDraft(BaseModel):
    title: str = Field(description="Short title, at most 80 characters.", max_length=80)
    description: str = Field(description="What the attacker did, in one or two sentences, using only what cited events show.")
    technique_id: str | None = Field(default=None, description="ATT&CK technique ID, only if model is confident.")
    evidence_event_ids: list[str] = Field(description="IDs of events that show it. At least 1 and at most 8.", min_length=1, max_length=8)


class StoryDraftOutput(BaseModel):
    summary: str = Field(description="At most 3 sentences about this chunk.")
    steps: list[StoryStepDraft] = Field(default_factory=list, description="Steps found. May be empty.")
    assumptions: list[str] = Field(default_factory=list, description="Anything the model guessed. Empty if none.")


class StoryStep(BaseModel):
    step_number: int = Field(description="Assigned by code from earliest cited timestamp, starting at 1.")
    title: str = Field(description="Short title.")
    description: str = Field(description="What the attacker did.")
    technique_id: str | None = Field(default=None, description="ATT&CK technique ID.")
    technique_name: str | None = Field(default=None, description="Technique name, from knowledge map.")
    tactic: str | None = Field(default=None, description="ATT&CK tactic, from knowledge map.")
    host: str | None = Field(default=None, description="Machine the evidence is on.")
    started_at: datetime | None = Field(default=None, description="Earliest cited event. Null if none.")
    ended_at: datetime | None = Field(default=None, description="Latest cited event.")
    evidence: list[EvidenceItem] = Field(default_factory=list, description="The cited events.")
    checks: list[CheckResult] = Field(default_factory=list, description="Check results. Empty for baselines.")
    verdict: StepVerdict = Field(description="supported if all checks passed. Baselines are unsupported.")
    analyst_decision: AnalystDecision | None = Field(default=None, description="Set after review.")
    analyst_note: str | None = Field(default=None, description="Analyst comment.")


class UnsupportedClaim(BaseModel):
    title: str = Field(description="The step's title.")
    description: str = Field(description="What the model claimed.")
    reasons: list[str] = Field(description="The failed checks, with details.")


class TokenUsage(BaseModel):
    input_tokens: int = Field(default=0, description="Total prompt tokens.")
    output_tokens: int = Field(default=0, description="Total output tokens.")
    llm_calls: int = Field(default=0, description="Number of LLM calls, including retries.")


class Story(BaseModel):
    story_id: str = Field(description="Unique story ID (prefix story_ + 8 hex).")
    case_id: str = Field(description="The case it describes.")
    method: Method = Field(description="How it was produced: casefile, baseline_window, baseline_raw.")
    status: StoryStatus = Field(description="Current state.")
    created_at: datetime = Field(description="When it was requested.")
    updated_at: datetime = Field(description="Last change timestamp.")
    model_name: str = Field(description="The LLM used.")
    attempts_used: int = Field(default=1, description="Highest attempt number used by any step.")
    max_attempts: int = Field(default=3, description="The retry cap in use.")
    summary: str | None = Field(default=None, description="Overall summary, written from verified steps only.")
    steps: list[StoryStep] = Field(default_factory=list, description="Steps in chronological time order.")
    unsupported_claims: list[UnsupportedClaim] = Field(default_factory=list, description="Claims the verifier rejected.")
    assumptions: list[str] = Field(default_factory=list, description="All assumptions reported by model.")
    usage: TokenUsage = Field(default_factory=TokenUsage, description="Token use for this story.")
    duration_seconds: float | None = Field(default=None, description="Time to produce story.")
    evaluation_id: str | None = Field(default=None, description="Set when story was scored.")
    review_outcome: ReviewOutcome | None = Field(default=None, description="Set after review.")
    failure_reason: str | None = Field(default=None, description="Set when status is failed.")


class StoryCreateRequest(BaseModel):
    method: Method = Field(default=Method.casefile, description="Reconstruction method.")
    max_attempts: int = Field(default=3, ge=1, le=5, description="Retry cap per step.")
    chunk_size: int = Field(default=20, ge=5, le=50, description="Events per LLM call.")
    baseline_window_seconds: int = Field(default=60, ge=10, le=600, description="Only used by baseline_window.")


class StoryAccepted(BaseModel):
    story_id: str = Field(description="Story ID to poll.")
    status: StoryStatus = Field(description="queued or generating.")


class StepReview(BaseModel):
    step_number: int = Field(description="The step being reviewed.")
    decision: AnalystDecision = Field(description="confirmed or rejected.")
    note: str | None = Field(default=None, max_length=500, description="Comment, at most 500 characters.")


class StoryReviewRequest(BaseModel):
    outcome: ReviewOutcome = Field(description="approved or rejected.")
    step_reviews: list[StepReview] = Field(default_factory=list, description="Per-step decisions.")


class StorySummary(BaseModel):
    story_id: str = Field(description="Story ID.")
    case_id: str = Field(description="The case.")
    method: Method = Field(description="How it was produced.")
    status: StoryStatus = Field(description="Current state.")
    created_at: datetime = Field(description="When requested.")
    step_count: int = Field(description="Steps in the story.")
    unsupported_count: int = Field(description="Claims the verifier removed.")


class StoryList(BaseModel):
    items: list[StorySummary] = Field(description="Stories, newest first.")
    total: int = Field(description="Number of stories.")


class ReportResponse(BaseModel):
    story_id: str = Field(description="The story ID.")
    format: str = Field(default="markdown", description="Always markdown.")
    content: str = Field(description="The report text.")
    generated_at: datetime = Field(description="When it was produced.")
