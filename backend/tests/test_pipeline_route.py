from pathlib import Path

import pytest
from fastapi import HTTPException

from backend.app.api.routes.pipeline import (
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
    yield
    db.clear_all(keep_datasets=False)


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

    assert res_data["success"] is True
    assert res_data["dataset_id"].startswith("ds_")
    assert res_data["case_id"].startswith("case_")
    assert res_data["story_id"].startswith("story_")
    assert "html" in res_data
    assert "CaseFile v2" in res_data["html"]
    assert "Live Telemetry Ingestion" in res_data["html"]
    assert res_data["dashboard_url"] == "/"

    # Verify status after run is complete
    st = get_pipeline_status()
    assert st["status"] == "complete"
    assert st["percent"] == 100
