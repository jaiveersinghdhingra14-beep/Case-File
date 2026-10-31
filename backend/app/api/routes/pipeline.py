"""
Interactive Web Ingestion & Real-Time Incident Reconstruction Route.

Provides:
- POST /api/v1/pipeline/run: Upload log file OR provide local path / dataset ID to trigger complete 5-stage DFIR pipeline.
- GET /api/v1/pipeline/status: Poll live progress during ingestion & reconstruction.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from ...config import settings
from ...schemas import (
    Case,
    CaseStats,
    CaseStatus,
    Dataset,
    DatasetStatus,
    Method,
    Story,
    StoryStatus,
)
from ...services.anti_evasion import detect_low_and_slow_jitter, raw_data_post_process
from ...services.correlator import correlate_incident_paths
from ...services.dashboard_builder import build_dashboard_html
from ...services.expander import expand_neighborhood
from ...services.ingest import ingest_dataset_sync
from ...services.pattern_detector import detect_attack_patterns
from ...services.profiler import profile_file
from ...services.reducer import get_top_k_seeds
from ...services.story_writer import write_story_for_events
from ...services.verifier import verify_all_steps
from ...store import db

router = APIRouter()

# Global state tracker for live UI progress polling
_PIPELINE_STATUS: dict[str, Any] = {
    "status": "idle",
    "stage": "Ready",
    "percent": 0,
    "message": "System ready for log ingestion.",
    "dataset_id": "",
    "case_id": "",
    "story_id": "",
    "updated_at": datetime.now(timezone.utc).isoformat(),
}


def _update_status(status_str: str, stage: str, percent: int, message: str, **kwargs: Any) -> None:
    _PIPELINE_STATUS["status"] = status_str
    _PIPELINE_STATUS["stage"] = stage
    _PIPELINE_STATUS["percent"] = percent
    _PIPELINE_STATUS["message"] = message
    _PIPELINE_STATUS["updated_at"] = datetime.now(timezone.utc).isoformat()
    for k, v in kwargs.items():
        _PIPELINE_STATUS[k] = v


class PipelineRunRequest(BaseModel):
    target: str | None = None
    filename: str | None = None
    file_content: str | None = None
    top_k: int = Field(default=50, ge=5, le=500)
    chunk_size: int = Field(default=20, ge=5, le=100)
    workers: int | None = None


@router.get("/pipeline/status")
def get_pipeline_status() -> dict[str, Any]:
    """Poll the real-time progress of the active ingestion pipeline."""
    return _PIPELINE_STATUS


@router.post("/pipeline/upload")
async def upload_log_file(request: Request, filename: str) -> dict[str, Any]:
    """Stream raw uploaded log file directly to disk under 8GB RAM."""
    upload_dir = settings.BASE_DIR / "data" / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    clean_fname = Path(filename).name
    dest_path = upload_dir / clean_fname
    _update_status("running", "Uploading", 10, f"Saving {clean_fname} to disk...")
    with dest_path.open("wb") as buffer:
        async for chunk in request.stream():
            buffer.write(chunk)
    return {"success": True, "filename": clean_fname, "path": str(dest_path.resolve())}


@router.post("/pipeline/run")
def run_pipeline_endpoint(
    req: PipelineRunRequest | None = None,
) -> dict[str, Any]:
    """
    Executes the full end-to-end incident pipeline:
    1. Direct streaming file upload OR local file path / existing dataset ID.
    2. Streaming ingestion into Parquet (memory < 8GB).
    3. High-velocity attack pattern detection.
    4. 8-Thread DuckDB noise reduction & 2-hop graph expansion.
    5. Raw data post-processing & anti-evasion de-masking.
    6. Groq AI narrative synthesis + 4-check verification.
    7. Compiles complete dynamic dashboard.
    """
    if req is None:
        req = PipelineRunRequest()

    db.init_db()
    dataset_id = ""

    _update_status("running", "Initializing", 5, "Initializing pipeline execution...")

    target_file = None
    target = req.target
    top_k = req.top_k
    chunk_size = req.chunk_size
    workers = req.workers

    if req.file_content and req.file_content.strip():
        upload_dir = settings.BASE_DIR / "data" / "uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        fname = req.filename or f"uploaded_{int(time.time())}.log"
        dest_path = upload_dir / fname
        _update_status("running", "Uploading", 10, f"Saving log payload to {fname}...")
        dest_path.write_text(req.file_content, encoding="utf-8")
        target_file = dest_path

    # 1. Determine Target (Upload vs Local Path vs Existing Dataset ID)
    if target_file is None:
        if target and target.strip():
            clean_target = target.strip().strip("'\"")
            # Check if existing dataset ID was passed
            if clean_target.startswith("ds_"):
                existing_ds = db.get_dataset(clean_target)
                if existing_ds:
                    dataset_id = clean_target
                    target_file = Path(existing_ds.path)
                else:
                    target_file = Path(clean_target)
            else:
                target_file = Path(clean_target)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either 'file' upload or 'target' path/ID must be provided.",
            )

    # 2. Ingestion (if new file or not already ingested into parquet)
    if not dataset_id:
        if not target_file.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target file or dataset ID not found: {target_file}",
            )

        _update_status("running", "Profiling", 15, f"Profiling log format for {target_file.name}...")
        meta = profile_file(str(target_file))
        dataset_id = f"ds_{abs(hash(str(target_file))) % 100000000:08x}"
        fmt_name = meta.format_name.upper()

        dataset = Dataset(
            dataset_id=dataset_id,
            name=target_file.name,
            path=str(target_file.resolve()),
            size_bytes=target_file.stat().st_size,
            format=fmt_name,
            status=DatasetStatus.registered,
            events_total=0,
            hosts=[],
            created_at=datetime.now(timezone.utc),
        )
        db.save_dataset(dataset)

        num_workers = workers or 4
        _update_status("running", "Streaming Ingestion", 25, f"Streaming {target_file.name} into columnar Parquet...")
        report = ingest_dataset_sync(
            dataset_id=dataset_id,
            batch_size=10000,
            num_workers=num_workers,
        )
        _update_status(
            "running",
            "Ingestion Complete",
            35,
            f"Ingested {getattr(report, 'rows_out', 0):,} events into Parquet.",
            dataset_id=dataset_id,
        )

    ds = db.get_dataset(dataset_id)
    if not ds:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Dataset {dataset_id} not found.")

    # 3. Case Creation
    case_id = f"case_{abs(hash((dataset_id, time.time()))) % 100000000:08x}"
    case = Case(
        case_id=case_id,
        dataset_id=dataset_id,
        name=f"Incident Analysis: {ds.name}",
        status=CaseStatus.correlating,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.save_case(case)
    _update_status("running", "Pattern Detection", 45, "Detecting high-velocity attack patterns...", case_id=case_id)

    # 4. Pattern Detection
    patterns = detect_attack_patterns(dataset_id=dataset_id)

    # 5. Noise Reduction & 2-Hop Graph Expansion
    _update_status("running", "Noise Reduction", 55, f"Mining Top-{top_k} seeds & expanding 2-hop neighborhood...")
    seeds = get_top_k_seeds(dataset_id, top_k=top_k, min_rarity_score=0.1)
    expanded = expand_neighborhood(dataset_id, seeds, window_seconds=120, max_expanded_events=2000)

    # 6. Raw Data Post-Processing & Adversarial Anti-Evasion
    _update_status("running", "Anti-Evasion Shield", 68, "Raw Data Post-Processing: unmasking Base64, carat & delimiters...")
    expanded, evasion_metrics = raw_data_post_process(expanded)
    stealth_patterns = detect_low_and_slow_jitter(expanded)
    if stealth_patterns:
        patterns.extend(stealth_patterns)

    events_by_id = {e.event_id: e for e in expanded}
    incidents = correlate_incident_paths(dataset_id, expanded, all_known_hosts=ds.hosts)

    comp_hosts = sorted({e.host for e in expanded})
    sources = sorted({e.source for e in expanded})
    noise_pruned = max(0, ds.events_total - len(expanded))

    case.stats = CaseStats(
        events_ingested=ds.events_total,
        events_after_noise_filter=len(expanded),
        noise_removed=noise_pruned,
        groups=len(incidents),
        hosts=comp_hosts[:25],
        sources=sources,
    )
    case.status = CaseStatus.ready
    case.updated_at = datetime.now(timezone.utc)
    db.save_case(case)

    # 7. AI Story Synthesis via Groq & 4-Check Verification Gate
    _update_status("running", "AI Story Synthesis", 80, f"Synthesizing threat narrative via {settings.GROQ_MODEL}...")
    draft, usage = write_story_for_events(
        expanded,
        chunk_size=chunk_size,
        model_name=settings.GROQ_MODEL,
        patterns=patterns,
        provider=settings.LLM_PROVIDER,
    )
    verified_steps, unsupported = verify_all_steps(draft.steps, events_by_id)

    now = datetime.now(timezone.utc)
    story_id = f"story_{abs(hash(case_id)) % 100000000:08x}"
    story = Story(
        story_id=story_id,
        case_id=case_id,
        status=StoryStatus.awaiting_review,
        created_at=now,
        updated_at=now,
        method=Method.casefile,
        summary=draft.summary,
        steps=verified_steps,
        unsupported_claims=unsupported,
        model_name=f"{settings.GROQ_MODEL} (SOC Analyst AI)",
        usage=usage,
    )
    db.save_story(story)

    # 8. Compile Unified Dashboard HTML
    _update_status("running", "Compiling Dashboard", 95, "Compiling interactive attack graph & forensic timeline...")
    dashboard_path = settings.BASE_DIR / "frontend" / "dashboard.html"
    build_dashboard_html(
        dataset_id=dataset_id,
        dataset_name=ds.name,
        total_events_ingested=ds.events_total,
        noise_pruned=noise_pruned,
        story=story,
        patterns=patterns,
        incidents=incidents,
        candidate_events=expanded,
        output_path=dashboard_path,
    )

    with open(dashboard_path, encoding="utf-8") as f:
        html_content = f.read()

    _update_status(
        "complete",
        "Done",
        100,
        f"Analysis complete: {len(verified_steps)} verified steps identified across {len(comp_hosts)} host(s).",
        story_id=story_id,
    )

    return {
        "success": True,
        "dataset_id": dataset_id,
        "dataset_name": ds.name,
        "case_id": case_id,
        "story_id": story_id,
        "summary": story.summary,
        "steps_count": len(verified_steps),
        "compromised_hosts": comp_hosts,
        "patterns_detected": len(patterns),
        "evasions_unmasked": evasion_metrics.get("evasions_unmasked", 0),
        "raw_bytes_verified": evasion_metrics.get("raw_bytes_verified", 0),
        "dashboard_url": "/dashboard",
        "html": html_content,
    }
