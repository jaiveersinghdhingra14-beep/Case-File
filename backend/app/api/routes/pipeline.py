"""
Interactive Web Ingestion & Real-Time Incident Reconstruction Route.

Provides:
- POST /api/v1/pipeline/run: Upload log file OR provide local path / dataset ID to trigger complete 5-stage DFIR pipeline.
- GET /api/v1/pipeline/status: Poll live progress during ingestion & reconstruction.

ARCHITECTURE:
The pipeline runs in a background thread so the HTTP request returns immediately.
The frontend polls GET /pipeline/status every 1 second for real-time progress.
When status reaches "complete", the frontend fetches /dashboard.
"""

from __future__ import annotations

import threading
import time
import traceback
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

# Lock to prevent multiple concurrent pipeline runs
_PIPELINE_LOCK = threading.Lock()


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


def resolve_log_path(target_str: str) -> Path | None:
    """Intelligently resolves a user-supplied log file path or directory."""
    p = Path(target_str)
    if p.exists() and p.is_file():
        return p
    for ext in [".log", ".txt", ".json", ".csv", ".jsonl"]:
        candidate = p.with_suffix(ext)
        if candidate.exists() and candidate.is_file():
            return candidate
    if p.exists() and p.is_dir():
        candidates = (
            list(p.glob("*.log"))
            + list(p.glob("*.txt"))
            + list(p.glob("*.json"))
            + list(p.glob("*.csv"))
            + list(p.glob("*"))
        )
        file_candidates = [c for c in candidates if c.is_file() and not c.name.startswith(".")]
        if file_candidates:
            file_candidates.sort(key=lambda f: f.stat().st_size, reverse=True)
            return file_candidates[0]
    return None


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


def _run_pipeline_in_background(
    target_file: Path,
    dataset_id: str,
    top_k: int,
    chunk_size: int,
    workers: int | None,
    is_existing_dataset: bool,
) -> None:
    """Execute the full DFIR pipeline in a background thread."""
    try:
        db.init_db()

        # 2. Ingestion (if new file or not already ingested into parquet)
        if not is_existing_dataset:
            _update_status("running", "Profiling", 15, f"Profiling log format for {target_file.name}...")
            meta = profile_file(str(target_file))
            dataset_id_val = dataset_id
            fmt_name = meta.format_name.upper()

            file_size_bytes = target_file.stat().st_size
            file_size_mb = file_size_bytes / (1024 * 1024)

            dataset = Dataset(
                dataset_id=dataset_id_val,
                name=target_file.name,
                path=str(target_file.resolve()),
                size_bytes=file_size_bytes,
                format=fmt_name,
                status=DatasetStatus.registered,
                events_total=0,
                hosts=[],
                created_at=datetime.now(timezone.utc),
            )
            db.save_dataset(dataset)

            num_workers = workers or 4

            # Progress callback: dynamically advances percentage from 20% to 35%
            estimated_total_lines = max(1, int(file_size_bytes / 300))

            def _ingestion_progress(rows_in: int, rows_out: int) -> None:
                frac = min(0.99, rows_in / estimated_total_lines)
                pct = 20 + int(frac * 15)  # Smoothly ranges 20% -> 35%
                _update_status(
                    "running",
                    "Streaming Ingestion",
                    pct,
                    f"Ingesting {target_file.name} — {rows_in:,} lines read, "
                    f"{rows_out:,} events parsed ({int(frac * 100)}% of ~{file_size_mb:.0f} MB)...",
                )

            _update_status(
                "running",
                "Streaming Ingestion",
                20,
                f"Streaming {target_file.name} ({file_size_mb:.0f} MB) into columnar Parquet...",
            )
            report = ingest_dataset_sync(
                dataset_id=dataset_id_val,
                batch_size=10000,
                num_workers=num_workers,
                progress_callback=_ingestion_progress,
            )

            # Clean up raw uploaded file: only retain columnar Parquet in backend storage
            upload_dir = settings.BASE_DIR / "data" / "uploads"
            try:
                if target_file.resolve().is_relative_to(upload_dir.resolve()) and target_file.exists():
                    target_file.unlink()
            except Exception:  # noqa: BLE001, S110
                pass

            _update_status(
                "running",
                "Ingestion Complete",
                35,
                f"Ingested {getattr(report, 'rows_out', 0):,} events into Parquet (raw upload purged).",
                dataset_id=dataset_id_val,
            )
        else:
            dataset_id_val = dataset_id

        ds = db.get_dataset(dataset_id_val)
        if not ds:
            _update_status("failed", "Error", 0, f"Dataset {dataset_id_val} not found after ingestion.")
            return

        # 3. Case Creation
        case_id = f"case_{abs(hash((dataset_id_val, time.time()))) % 100000000:08x}"
        case = Case(
            case_id=case_id,
            dataset_id=dataset_id_val,
            name=f"Incident Analysis: {ds.name}",
            status=CaseStatus.correlating,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.save_case(case)
        _update_status("running", "Pattern Detection", 45, "Detecting high-velocity attack patterns...", case_id=case_id)

        # 4. Pattern Detection
        patterns = detect_attack_patterns(dataset_id=dataset_id_val)

        # 5. Noise Reduction & 2-Hop Graph Expansion
        _update_status("running", "Noise Reduction", 55, f"Mining Top-{top_k} seeds & expanding 2-hop neighborhood...")
        seeds = get_top_k_seeds(dataset_id_val, top_k=top_k, min_rarity_score=0.1)
        expanded = expand_neighborhood(dataset_id_val, seeds, window_seconds=120, max_expanded_events=2000)

        # Fallback: if parquet-level query returned 0 patterns, detect from candidate events
        if not patterns and expanded:
            patterns = detect_attack_patterns(dataset_id=dataset_id_val, events=expanded)

        # 6. Raw Data Post-Processing & Adversarial Anti-Evasion
        _update_status("running", "Anti-Evasion Shield", 68, "Raw Data Post-Processing: unmasking Base64, carat & delimiters...")
        expanded, _evasion_metrics = raw_data_post_process(expanded)
        stealth_patterns = detect_low_and_slow_jitter(expanded)
        if stealth_patterns:
            patterns.extend(stealth_patterns)

        events_by_id = {e.event_id: e for e in expanded}
        incidents = correlate_incident_paths(dataset_id_val, expanded, all_known_hosts=ds.hosts)

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
            dataset_id=dataset_id_val,
            dataset_name=ds.name,
            total_events_ingested=ds.events_total,
            noise_pruned=noise_pruned,
            story=story,
            patterns=patterns,
            incidents=incidents,
            candidate_events=expanded,
            output_path=dashboard_path,
        )

        _update_status(
            "complete",
            "Done",
            100,
            f"Analysis complete: {len(verified_steps)} verified steps identified across {len(comp_hosts)} host(s).",
            story_id=story_id,
            dataset_id=dataset_id_val,
            case_id=case_id,
        )

    except Exception as e:  # noqa: BLE001
        tb = traceback.format_exc()
        _update_status(
            "failed",
            "Pipeline Error",
            0,
            f"Pipeline failed: {e}",
        )
        # Log the full traceback to stderr for debugging
        import sys
        print(f"[PIPELINE ERROR] {tb}", file=sys.stderr)
    finally:
        _PIPELINE_LOCK.release()


@router.post("/pipeline/run")
def run_pipeline_endpoint(
    req: PipelineRunRequest | None = None,
) -> dict[str, Any]:
    """
    Launches the full end-to-end incident pipeline in a background thread.
    Returns immediately — poll GET /pipeline/status for progress.

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

    # Prevent concurrent pipeline runs
    if not _PIPELINE_LOCK.acquire(blocking=False):
        return {
            "success": False,
            "status": "already_running",
            "message": "A pipeline is already running. Poll /api/v1/pipeline/status for progress.",
        }

    _update_status("running", "Initializing", 5, "Initializing pipeline execution...")

    target_file = None
    target = req.target
    top_k = req.top_k
    chunk_size = req.chunk_size
    workers = req.workers
    dataset_id = ""
    is_existing_dataset = False

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
                parquet_ds_dir = settings.abs_parquet_dir / clean_target
                if not parquet_ds_dir.exists():
                    parquet_ds_dir = settings.BASE_DIR / "data" / "parquet" / clean_target
                if not parquet_ds_dir.exists():
                    parquet_ds_dir = Path("data/parquet") / clean_target

                has_parquet = parquet_ds_dir.exists() and any(parquet_ds_dir.glob("*.parquet"))
                if existing_ds or has_parquet:
                    dataset_id = clean_target
                    is_existing_dataset = True
                    target_file = Path(existing_ds.path) if existing_ds else parquet_ds_dir
                    if not existing_ds:
                        auto_ds = Dataset(
                            dataset_id=dataset_id,
                            name=f"Pre-Indexed Dataset {dataset_id}",
                            path=str(parquet_ds_dir.resolve()),
                            size_bytes=sum(f.stat().st_size for f in parquet_ds_dir.glob("*.parquet")),
                            format="PARQUET",
                            status=DatasetStatus.ready,
                            events_total=0,
                            hosts=[],
                            created_at=datetime.now(timezone.utc),
                        )
                        db.save_dataset(auto_ds)
                elif clean_target == "ds_4d8f3f29":
                    # Fallback to raw edr_events.json if parquet directory was missing
                    raw_edr = settings.BASE_DIR / "data" / "raw" / "edr_events.json"
                    if not raw_edr.exists():
                        raw_edr = Path("data/raw/edr_events.json")
                    if raw_edr.exists():
                        target_file = raw_edr
                    else:
                        resolved = resolve_log_path(clean_target)
                        target_file = resolved or Path(clean_target)
                else:
                    resolved = resolve_log_path(clean_target)
                    target_file = resolved or Path(clean_target)
            else:
                resolved = resolve_log_path(clean_target)
                target_file = resolved or Path(clean_target)
        else:
            _PIPELINE_LOCK.release()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either 'file' upload or 'target' path/ID must be provided.",
            )

    # Pre-validate file existence before spawning thread
    if not is_existing_dataset:
        if not target_file.exists():
            _PIPELINE_LOCK.release()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target file or dataset ID not found: {target_file}",
            )
        if target_file.is_dir():
            _PIPELINE_LOCK.release()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target '{target_file}' is a directory with no readable log files. Please provide a log file.",
            )
        dataset_id = f"ds_{abs(hash(str(target_file))) % 100000000:08x}"

    # Launch pipeline in background thread
    thread = threading.Thread(
        target=_run_pipeline_in_background,
        args=(target_file, dataset_id, top_k, chunk_size, workers, is_existing_dataset),
        daemon=True,
    )
    thread.start()

    return {
        "success": True,
        "status": "started",
        "message": "Pipeline launched. Poll GET /api/v1/pipeline/status for live progress.",
        "dataset_id": dataset_id,
    }
