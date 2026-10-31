import time
from pathlib import Path

import pytest
from fastapi import HTTPException

from backend.app.api.routes.pipeline import (
    _PIPELINE_LOCK,
    _PIPELINE_STATUS,
    PipelineRunRequest,
    get_pipeline_status,
    run_pipeline_endpoint,
)
from backend.app.config import settings
from backend.app.store import db


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    test_db = tmp_path / "test_casefile.db"
    test_parquet = tmp_path / "parquet"
    (tmp_path / "uploads").mkdir(parents=True, exist_ok=True)
    test_frontend = tmp_path / "frontend"
    test_frontend.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(settings, "DATABASE_PATH", str(test_db))
    monkeypatch.setattr(settings, "PARQUET_STORAGE_DIR", test_parquet)
    monkeypatch.setattr(settings, "LLM_PROVIDER", "mock")
    monkeypatch.setattr(settings, "GROQ_API_KEY", "")
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "")
    monkeypatch.setattr(settings, "BASE_DIR", tmp_path)

    db.init_db()

    # Reset pipeline status between tests
    _PIPELINE_STATUS["status"] = "idle"
    _PIPELINE_STATUS["percent"] = 0
    # Ensure lock is released between tests
    if _PIPELINE_LOCK.locked():
        _PIPELINE_LOCK.release()

    yield
    db.clear_all(keep_datasets=False)
    # Clean up lock after test
    if _PIPELINE_LOCK.locked():
        _PIPELINE_LOCK.release()


def test_pipeline_status_endpoint():
    data = get_pipeline_status()
    assert "status" in data
    assert "stage" in data
    assert "percent" in data
    assert "message" in data


def test_pipeline_run_no_input():
    with pytest.raises(HTTPException) as exc_info:
        run_pipeline_endpoint(PipelineRunRequest())
    assert exc_info.value.status_code == 400
    assert "Either 'file' upload or 'target'" in exc_info.value.detail


def test_pipeline_run_target_not_found():
    with pytest.raises(HTTPException) as exc_info:
        run_pipeline_endpoint(PipelineRunRequest(target="non_existent_file.log"))
    assert exc_info.value.status_code == 404
    assert "Target file or dataset ID not found" in exc_info.value.detail


def test_pipeline_run_with_file_upload():
    """Pipeline now runs in background — verify it launches and completes."""
    fixture_path = Path(__file__).parent / "fixtures" / "sample_fortigate.log"
    assert fixture_path.exists()

    content = fixture_path.read_text(encoding="utf-8")
    res_data = run_pipeline_endpoint(
        PipelineRunRequest(
            filename="sample_fortigate.log",
            file_content=content,
            top_k=20,
            chunk_size=10,
        )
    )

    # Pipeline returns immediately with "started" status
    assert res_data["success"] is True
    assert res_data["status"] == "started"
    assert res_data["dataset_id"].startswith("ds_")

    # Wait for background thread to complete (small test fixture should finish quickly)
    deadline = time.time() + 30
    while time.time() < deadline:
        st = get_pipeline_status()
        if st["status"] in ("complete", "failed"):
            break
        time.sleep(0.2)

    st = get_pipeline_status()
    assert st["status"] == "complete", f"Pipeline did not complete: {st}"
    assert st["percent"] == 100
