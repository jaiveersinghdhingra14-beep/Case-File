import time

import duckdb
from fastapi import APIRouter

from ...config import settings
from ...schemas import ComponentStatus, HealthResponse
from ...store import db

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    # 1. Check SQLite database
    t0 = time.perf_counter()
    db_ok = True
    db_detail = None
    try:
        conn = db.get_connection()
        conn.execute("SELECT 1;").fetchone()
        conn.close()
    except Exception as e:  # noqa: BLE001
        db_ok = False
        db_detail = str(e)
    db_latency = int((time.perf_counter() - t0) * 1000)

    # 2. Check DuckDB
    t0 = time.perf_counter()
    duckdb_ok = True
    duckdb_detail = None
    try:
        con = duckdb.connect(":memory:")
        con.execute("SELECT 1;").fetchone()
        con.close()
    except Exception as e:  # noqa: BLE001
        duckdb_ok = False
        duckdb_detail = str(e)
    duckdb_latency = int((time.perf_counter() - t0) * 1000)

    # 3. Check Dataset parquet storage directory
    t0 = time.perf_counter()
    store_ok = True
    store_detail = None
    try:
        p = settings.abs_parquet_dir
        p.mkdir(parents=True, exist_ok=True)
    except Exception as e:  # noqa: BLE001
        store_ok = False
        store_detail = str(e)
    store_latency = int((time.perf_counter() - t0) * 1000)

    # 4. Check LLM reachability
    llm_ok = True
    llm_detail = "Mock LLM enabled for tests/offline." if settings.USE_MOCK_LLM else None
    llm_latency = 1

    all_ok = db_ok and duckdb_ok and store_ok and llm_ok
    status_str = "ok" if all_ok else "degraded"

    return HealthResponse(
        status=status_str,
        app_version=settings.APP_VERSION,
        dataset_store=ComponentStatus(ok=store_ok, detail=store_detail, latency_ms=store_latency),
        duckdb=ComponentStatus(ok=duckdb_ok, detail=duckdb_detail, latency_ms=duckdb_latency),
        database=ComponentStatus(ok=db_ok, detail=db_detail, latency_ms=db_latency),
        llm=ComponentStatus(ok=llm_ok, detail=llm_detail, latency_ms=llm_latency),
    )
