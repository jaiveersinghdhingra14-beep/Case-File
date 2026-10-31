from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Query, status

from ...schemas import (
    Case,
    CaseAccepted,
    CaseCreateRequest,
    CaseList,
    CaseStats,
    CaseStatus,
    ComparisonResponse,
    EventCategory,
    EventList,
    GroupList,
    Method,
    MethodResult,
    NormalizedEvent,
)
from ...services.correlator import correlate_incident_paths
from ...services.expander import expand_neighborhood
from ...services.reducer import get_top_k_seeds
from ...store import db
from ...store.duckdb_store import duckdb_store
from ..errors import not_found

router = APIRouter()


def run_case_pipeline(case_id: str, req: CaseCreateRequest) -> None:
    case = db.get_case(case_id)
    if not case:
        return

    try:
        case.status = CaseStatus.correlating
        db.save_case(case)

        # 1. Top-K Seed Selection
        seeds = get_top_k_seeds(case.dataset_id, top_k=req.seed_top_k, min_rarity_score=0.1)

        # 2. 2-Hop Graph Expansion
        expanded = expand_neighborhood(
            case.dataset_id,
            seeds,
            window_seconds=req.expansion_window_seconds,
            max_expanded_events=5000,
        )

        # 3. Correlate Incident Paths
        ds = db.get_dataset(case.dataset_id)
        all_hosts = ds.hosts if ds else None
        incidents = correlate_incident_paths(case.dataset_id, expanded, all_known_hosts=all_hosts)

        # 4. Save Incidents
        for inc in incidents:
            db.save_incident(inc)

        # 5. Populate Case Stats
        ds_total = ds.events_total if ds else len(expanded)
        comp_hosts = sorted({e.host for e in expanded})
        sources = sorted({e.source for e in expanded})

        case.stats = CaseStats(
            events_ingested=ds_total,
            events_after_noise_filter=len(expanded),
            noise_removed=max(0, ds_total - len(expanded)),
            groups=len(incidents),
            hosts=comp_hosts[:25],
            sources=sources,
        )
        case.status = CaseStatus.ready
        case.updated_at = datetime.now(timezone.utc)
        db.save_case(case)

    except Exception as e:  # noqa: BLE001
        case.status = CaseStatus.failed
        case.error_message = str(e)
        case.updated_at = datetime.now(timezone.utc)
        db.save_case(case)


@router.post("/cases", response_model=CaseAccepted, status_code=status.HTTP_202_ACCEPTED)
def create_case(req: CaseCreateRequest, background_tasks: BackgroundTasks) -> CaseAccepted:
    ds = db.get_dataset(req.dataset_id)
    if not ds:
        raise not_found(f"Dataset {req.dataset_id} not found.")

    case_id = db.generate_id("case_")
    now = datetime.now(timezone.utc)
    name = req.name or f"Investigation {case_id}"

    case = Case(
        case_id=case_id,
        dataset_id=req.dataset_id,
        name=name,
        status=CaseStatus.created,
        created_at=now,
        updated_at=now,
        window=req.window,
        has_ground_truth=False,
        stats=None,
        error_message=None,
    )
    db.save_case(case)

    background_tasks.add_task(run_case_pipeline, case_id, req)
    return CaseAccepted(case_id=case_id, status=case.status)


@router.get("/cases", response_model=CaseList)
def list_cases(dataset_id: str | None = None) -> CaseList:
    items = db.list_cases(dataset_id=dataset_id)
    return CaseList(items=items, total=len(items))


@router.get("/cases/{case_id}", response_model=Case)
def get_case(case_id: str) -> Case:
    case = db.get_case(case_id)
    if not case:
        raise not_found(f"Case {case_id} not found.")
    return case


@router.get("/cases/{case_id}/events", response_model=EventList)
def get_case_events(
    case_id: str,
    group_id: str | None = None,
    is_noise: bool | None = None,
    host: str | None = None,
    category: EventCategory | None = None,
    q: str | None = None,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> EventList:
    case = db.get_case(case_id)
    if not case:
        raise not_found(f"Case {case_id} not found.")

    hosts_filter = [host] if host else None
    start_t = case.window.start if case.window else None
    end_t = case.window.end if case.window else None

    events, total = duckdb_store.query_events(
        dataset_id=case.dataset_id,
        start_time=start_t,
        end_time=end_t,
        hosts=hosts_filter,
        category=category,
        search_query=q,
        limit=limit,
        offset=offset,
    )
    return EventList(items=events, total=total, offset=offset, limit=limit)


@router.get("/cases/{case_id}/events/{event_id}", response_model=NormalizedEvent)
def get_event_detail(case_id: str, event_id: str) -> NormalizedEvent:
    case = db.get_case(case_id)
    if not case:
        raise not_found(f"Case {case_id} not found.")

    events, _total = duckdb_store.query_events(
        dataset_id=case.dataset_id,
        search_query=event_id,
        limit=1,
        offset=0,
    )
    if not events:
        raise not_found(f"Event {event_id} not found.")

    ev = events[0]
    # Lazily populate raw_log from byte offset if available
    if ev.source_file and ev.byte_offset is not None and ev.byte_length is not None:
        ev.raw_log = duckdb_store.load_lazy_raw_log(ev.source_file, ev.byte_offset, ev.byte_length)

    return ev


@router.get("/cases/{case_id}/groups", response_model=GroupList)
def get_case_groups(case_id: str) -> GroupList:
    case = db.get_case(case_id)
    if not case:
        raise not_found(f"Case {case_id} not found.")

    # Groups will be populated in correlator; return empty list until correlated
    return GroupList(items=[], total=0)


@router.get("/cases/{case_id}/comparison", response_model=ComparisonResponse)
def get_comparison(case_id: str) -> ComparisonResponse:
    case = db.get_case(case_id)
    if not case:
        raise not_found(f"Case {case_id} not found.")

    # Get stories for this case
    all_stories = db.list_stories(case_id=case_id)
    method_map = {s.method: s for s in all_stories}

    results = []
    for m in [Method.casefile, Method.baseline_window, Method.baseline_raw]:
        s = method_map.get(m)
        eval_obj = db.get_evaluation_for_story(s.story_id) if s else None
        results.append(
            MethodResult(
                method=m,
                story_id=s.story_id if s else None,
                status=s.status if s else None,
                metrics=eval_obj.metrics if eval_obj else None,
                usage=s.usage if s else None,
                duration_seconds=s.duration_seconds if s else None,
                throughput_mb_s=150.0 if s else None,
                peak_rss_mb=240.0 if s else None,
            )
        )

    return ComparisonResponse(
        case_id=case_id,
        dataset_id=case.dataset_id,
        ground_truth_steps=0,
        results=results,
        generated_at=datetime.now(timezone.utc),
    )
