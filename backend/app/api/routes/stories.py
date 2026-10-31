import time
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, status

from ...config import settings
from ...schemas import (
    CaseStatus,
    EvaluateRequest,
    Evaluation,
    ReportResponse,
    ReviewOutcome,
    Story,
    StoryAccepted,
    StoryCreateRequest,
    StoryList,
    StoryReviewRequest,
    StoryStatus,
    StorySummary,
    TokenUsage,
)
from ...services.expander import expand_neighborhood
from ...services.reducer import get_top_k_seeds
from ...services.story_writer import write_story_for_events
from ...services.verifier import verify_all_steps
from ...store import db
from ..errors import already_in_progress, no_ground_truth, not_found, wrong_state

router = APIRouter()


def run_story_pipeline(story_id: str, case_id: str, req: StoryCreateRequest) -> None:
    story = db.get_story(story_id)
    if not story:
        return

    case = db.get_case(case_id)
    if not case:
        story.status = StoryStatus.failed
        story.failure_reason = f"Case {case_id} not found."
        db.save_story(story)
        return

    try:
        t0 = time.perf_counter()
        story.status = StoryStatus.generating
        db.save_story(story)

        # 1. Query candidate events
        seeds = get_top_k_seeds(case.dataset_id, top_k=50, min_rarity_score=0.1)
        candidate_events = expand_neighborhood(case.dataset_id, seeds, window_seconds=120)

        events_by_id = {e.event_id: e for e in candidate_events}

        # 2. Write Story drafts
        draft, usage = write_story_for_events(candidate_events, chunk_size=req.chunk_size)

        # 3. Deterministic 4-Check Verification
        story.status = StoryStatus.verifying
        db.save_story(story)

        verified_steps, unsupported = verify_all_steps(draft.steps, events_by_id)

        # 4. Final Story Assembly
        t_elapsed = time.perf_counter() - t0
        story.status = StoryStatus.awaiting_review
        story.summary = draft.summary
        story.steps = verified_steps
        story.unsupported_claims = unsupported
        story.assumptions = draft.assumptions
        story.usage = usage
        story.duration_seconds = round(t_elapsed, 2)
        story.updated_at = datetime.now(timezone.utc)
        db.save_story(story)

    except Exception as e:
        story.status = StoryStatus.failed
        story.failure_reason = str(e)
        story.updated_at = datetime.now(timezone.utc)
        db.save_story(story)


@router.post("/cases/{case_id}/stories", response_model=StoryAccepted, status_code=status.HTTP_202_ACCEPTED)
def create_story(case_id: str, req: StoryCreateRequest, background_tasks: BackgroundTasks) -> StoryAccepted:
    case = db.get_case(case_id)
    if not case:
        raise not_found(f"Case {case_id} not found.")

    if case.status != CaseStatus.ready:
        raise wrong_state(f"Cannot generate story: case is in status '{case.status.value}', expected 'ready'.")

    # Check for already in progress
    existing = db.list_stories(case_id=case_id)
    for s in existing:
        if s.method == req.method and s.status in [StoryStatus.queued, StoryStatus.generating, StoryStatus.verifying]:
            raise already_in_progress(
                f"Story generation with method '{req.method.value}' is already running for this case."
            )

    story_id = db.generate_id("story_")
    now = datetime.now(timezone.utc)

    story = Story(
        story_id=story_id,
        case_id=case_id,
        method=req.method,
        status=StoryStatus.queued,
        created_at=now,
        updated_at=now,
        model_name=settings.LLM_MODEL,
        attempts_used=1,
        max_attempts=req.max_attempts,
        summary=None,
        steps=[],
        unsupported_claims=[],
        assumptions=[],
        usage=TokenUsage(),
        duration_seconds=None,
        evaluation_id=None,
        review_outcome=None,
        failure_reason=None,
    )
    db.save_story(story)

    background_tasks.add_task(run_story_pipeline, story_id, case_id, req)
    return StoryAccepted(story_id=story_id, status=story.status)


@router.get("/cases/{case_id}/stories", response_model=StoryList)
def list_stories_for_case(case_id: str) -> StoryList:
    stories = db.list_stories(case_id=case_id)
    summaries = [
        StorySummary(
            story_id=s.story_id,
            case_id=s.case_id,
            method=s.method,
            status=s.status,
            created_at=s.created_at,
            step_count=len(s.steps),
            unsupported_count=len(s.unsupported_claims),
        )
        for s in stories
    ]
    return StoryList(items=summaries, total=len(summaries))


@router.get("/stories/{story_id}", response_model=Story)
def get_story(story_id: str) -> Story:
    story = db.get_story(story_id)
    if not story:
        raise not_found(f"Story {story_id} not found.")
    return story


@router.post("/stories/{story_id}/review", response_model=Story)
def review_story(story_id: str, req: StoryReviewRequest) -> Story:
    story = db.get_story(story_id)
    if not story:
        raise not_found(f"Story {story_id} not found.")

    if story.status != StoryStatus.awaiting_review:
        raise wrong_state(f"Review is only allowed when status is 'awaiting_review', currently '{story.status.value}'.")

    # Apply step-level reviews
    step_map = {rev.step_number: rev for rev in req.step_reviews}
    for step in story.steps:
        if step.step_number in step_map:
            rev = step_map[step.step_number]
            step.analyst_decision = rev.decision
            step.analyst_note = rev.note

    story.review_outcome = req.outcome
    story.status = StoryStatus.approved if req.outcome == ReviewOutcome.approved else StoryStatus.rejected
    story.updated_at = datetime.now(timezone.utc)
    db.save_story(story)
    return story


@router.post("/stories/{story_id}/evaluate", response_model=Evaluation)
def evaluate_story(story_id: str, req: EvaluateRequest) -> Evaluation:
    story = db.get_story(story_id)
    if not story:
        raise not_found(f"Story {story_id} not found.")

    case = db.get_case(story.case_id)
    if not case or not case.has_ground_truth:
        raise no_ground_truth(f"Case {story.case_id} has no ground truth labels.")

    eval_obj = db.get_evaluation_for_story(story_id)
    if not eval_obj:
        raise not_found(f"Evaluation for story {story_id} not found.")
    return eval_obj


@router.get("/stories/{story_id}/report", response_model=ReportResponse)
def get_story_report(story_id: str) -> ReportResponse:
    story = db.get_story(story_id)
    if not story:
        raise not_found(f"Story {story_id} not found.")

    lines = [
        f"# Attack Story Report: {story.story_id}",
        f"**Case**: `{story.case_id}` | **Method**: `{story.method.value}` | **Status**: `{story.status.value}`",
        f"**LLM Model**: `{story.model_name}` | **Duration**: {story.duration_seconds or 0.0:.2f}s",
        "",
        "## Summary",
        story.summary or "Reconstruction in progress or no verified steps found.",
        "",
        "## Verified Attack Steps",
        "",
    ]

    for st in story.steps:
        lines.append(
            f"### Step {st.step_number}: {st.title}\n"
            f"- **Description**: {st.description}\n"
            f"- **Technique**: `{st.technique_id or 'Unknown'}` ({st.technique_name or 'Unclassified'})\n"
            f"- **Tactic**: `{st.tactic or 'Unknown'}`\n"
            f"- **Evidence**: {len(st.evidence)} cited events\n"
        )

    if story.unsupported_claims:
        lines.extend(["## Unsupported Claims (Rejected by Verifier)", ""])
        for un in story.unsupported_claims:
            lines.append(f"- **{un.title}**: {un.description} (Reasons: {', '.join(un.reasons)})")

    return ReportResponse(
        story_id=story.story_id,
        format="markdown",
        content="\n".join(lines),
        generated_at=datetime.now(timezone.utc),
    )


@router.get("/evaluations/{evaluation_id}", response_model=Evaluation)
def get_evaluation(evaluation_id: str) -> Evaluation:
    evaluation = db.get_evaluation(evaluation_id)
    if not evaluation:
        raise not_found(f"Evaluation {evaluation_id} not found.")
    return evaluation
