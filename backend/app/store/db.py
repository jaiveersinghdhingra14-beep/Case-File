import json
import secrets
import sqlite3
from datetime import datetime, timezone

from ..config import settings
from ..schemas import (
    BenchmarkReport,
    Case,
    Dataset,
    DatasetStatus,
    Evaluation,
    IncidentPath,
    IncidentSummary,
    Story,
)


def generate_id(prefix: str) -> str:
    """Generate ID with prefix + 8 hex characters (e.g. ds_a1b2c3d4, case_9e8f7a6b)."""
    return f"{prefix}{secrets.token_hex(4)}"


def get_connection() -> sqlite3.Connection:
    db_path = settings.abs_db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db() -> None:
    conn = get_connection()
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS datasets (
                dataset_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                format TEXT NOT NULL,
                status TEXT NOT NULL,
                events_total INTEGER DEFAULT 0,
                time_range_json TEXT,
                hosts_json TEXT,
                created_at TEXT NOT NULL,
                error_message TEXT,
                data_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                dataset_id TEXT NOT NULL,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                window_json TEXT,
                has_ground_truth INTEGER DEFAULT 0,
                stats_json TEXT,
                error_message TEXT,
                data_json TEXT NOT NULL,
                FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id)
            );

            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                dataset_id TEXT NOT NULL,
                title TEXT NOT NULL,
                risk_score REAL NOT NULL,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS stories (
                story_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                method TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                data_json TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            );

            CREATE TABLE IF NOT EXISTS evaluations (
                evaluation_id TEXT PRIMARY KEY,
                story_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                method TEXT NOT NULL,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (story_id) REFERENCES stories(story_id)
            );

            CREATE TABLE IF NOT EXISTS benchmarks (
                dataset_id TEXT PRIMARY KEY,
                data_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id)
            );
        """)
    conn.close()


# -----------------------------------------------------------------------------
# Dataset Operations
# -----------------------------------------------------------------------------


def create_dataset(
    dataset_id: str,
    name: str,
    file_path: str,
    file_size_bytes: int,
    format_name: str,
) -> Dataset:
    """Helper to create and persist a new dataset in registered status."""
    ds = Dataset(
        dataset_id=dataset_id,
        name=name,
        path=file_path,
        size_bytes=file_size_bytes,
        format=format_name,
        status=DatasetStatus.registered,
        events_total=0,
        hosts=[],
        created_at=datetime.now(timezone.utc),
    )
    save_dataset(ds)
    return ds


def save_dataset(ds: Dataset) -> None:
    conn = get_connection()
    now_iso = ds.created_at.isoformat()
    tr_json = ds.time_range.model_dump_json() if ds.time_range else None
    hosts_json = json.dumps(ds.hosts)
    data_json = ds.model_dump_json()

    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO datasets 
            (dataset_id, name, path, size_bytes, format, status, events_total, time_range_json, hosts_json, created_at, error_message, data_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ds.dataset_id,
                ds.name,
                ds.path,
                ds.size_bytes,
                ds.format,
                ds.status.value,
                ds.events_total,
                tr_json,
                hosts_json,
                now_iso,
                ds.error_message,
                data_json,
            ),
        )
    conn.close()


def get_dataset(dataset_id: str) -> Dataset | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT data_json FROM datasets WHERE dataset_id = ?", (dataset_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return Dataset.model_validate_json(row["data_json"])


def list_datasets() -> list[Dataset]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT data_json FROM datasets ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [Dataset.model_validate_json(r["data_json"]) for r in rows]


# -----------------------------------------------------------------------------
# Case Operations
# -----------------------------------------------------------------------------


def save_case(case: Case) -> None:
    conn = get_connection()
    window_json = case.window.model_dump_json() if case.window else None
    stats_json = case.stats.model_dump_json() if case.stats else None
    data_json = case.model_dump_json()

    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO cases 
            (case_id, dataset_id, name, status, created_at, updated_at, window_json, has_ground_truth, stats_json, error_message, data_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case.case_id,
                case.dataset_id,
                case.name,
                case.status.value,
                case.created_at.isoformat(),
                case.updated_at.isoformat(),
                window_json,
                1 if case.has_ground_truth else 0,
                stats_json,
                case.error_message,
                data_json,
            ),
        )
    conn.close()


def get_case(case_id: str) -> Case | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT data_json FROM cases WHERE case_id = ?", (case_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return Case.model_validate_json(row["data_json"])


def list_cases(dataset_id: str | None = None) -> list[Case]:
    conn = get_connection()
    cur = conn.cursor()
    if dataset_id:
        cur.execute("SELECT data_json FROM cases WHERE dataset_id = ? ORDER BY created_at DESC", (dataset_id,))
    else:
        cur.execute("SELECT data_json FROM cases ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [Case.model_validate_json(r["data_json"]) for r in rows]


# -----------------------------------------------------------------------------
# Incident Operations (FR-4, FR-5, FR-6, FR-7, B-1, B-3)
# -----------------------------------------------------------------------------


def save_incident(incident: IncidentPath) -> None:
    conn = get_connection()
    data_json = incident.model_dump_json()
    now_iso = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO incidents (incident_id, dataset_id, title, risk_score, data_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                incident.incident_id,
                incident.dataset_id,
                incident.title,
                incident.risk_score,
                data_json,
                now_iso,
            ),
        )
    conn.close()


def get_incident(incident_id: str) -> IncidentPath | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT data_json FROM incidents WHERE incident_id = ?", (incident_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return IncidentPath.model_validate_json(row["data_json"])


def list_incidents(dataset_id: str | None = None) -> list[IncidentSummary]:
    conn = get_connection()
    cur = conn.cursor()
    if dataset_id:
        cur.execute(
            "SELECT data_json FROM incidents WHERE dataset_id = ? ORDER BY risk_score DESC",
            (dataset_id,),
        )
    else:
        cur.execute("SELECT data_json FROM incidents ORDER BY risk_score DESC")
    rows = cur.fetchall()
    conn.close()

    summaries: list[IncidentSummary] = []
    for r in rows:
        path = IncidentPath.model_validate_json(r["data_json"])
        start = path.timeline[0].timestamp if path.timeline else datetime.now(timezone.utc)
        end = path.timeline[-1].timestamp if path.timeline else start
        summaries.append(
            IncidentSummary(
                incident_id=path.incident_id,
                dataset_id=path.dataset_id,
                title=path.title,
                risk_score=path.risk_score,
                start_time=start,
                end_time=end,
                hosts_involved=path.hosts_involved,
                step_count=len(path.timeline),
                events_merged_count=path.events_merged_count,
            )
        )
    return summaries


# -----------------------------------------------------------------------------
# Story Operations
# -----------------------------------------------------------------------------


def save_story(story: Story) -> None:
    conn = get_connection()
    data_json = story.model_dump_json()
    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO stories (story_id, case_id, method, status, created_at, updated_at, data_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                story.story_id,
                story.case_id,
                story.method.value,
                story.status.value,
                story.created_at.isoformat(),
                story.updated_at.isoformat(),
                data_json,
            ),
        )
    conn.close()


def get_story(story_id: str) -> Story | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT data_json FROM stories WHERE story_id = ?", (story_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return Story.model_validate_json(row["data_json"])


def list_stories(case_id: str | None = None) -> list[Story]:
    conn = get_connection()
    cur = conn.cursor()
    if case_id:
        cur.execute("SELECT data_json FROM stories WHERE case_id = ? ORDER BY created_at DESC", (case_id,))
    else:
        cur.execute("SELECT data_json FROM stories ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [Story.model_validate_json(r["data_json"]) for r in rows]


# -----------------------------------------------------------------------------
# Evaluation Operations
# -----------------------------------------------------------------------------


def save_evaluation(evaluation: Evaluation) -> None:
    conn = get_connection()
    data_json = evaluation.model_dump_json()
    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO evaluations (evaluation_id, story_id, case_id, method, data_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                evaluation.evaluation_id,
                evaluation.story_id,
                evaluation.case_id,
                evaluation.method.value,
                data_json,
                evaluation.created_at.isoformat(),
            ),
        )
    conn.close()


def get_evaluation(evaluation_id: str) -> Evaluation | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT data_json FROM evaluations WHERE evaluation_id = ?", (evaluation_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return Evaluation.model_validate_json(row["data_json"])


def get_evaluation_for_story(story_id: str) -> Evaluation | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT data_json FROM evaluations WHERE story_id = ? ORDER BY created_at DESC LIMIT 1", (story_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return Evaluation.model_validate_json(row["data_json"])


# -----------------------------------------------------------------------------
# Benchmark Operations
# -----------------------------------------------------------------------------


def save_benchmark(report: BenchmarkReport) -> None:
    conn = get_connection()
    data_json = report.model_dump_json()
    now_iso = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO benchmarks (dataset_id, data_json, updated_at)
            VALUES (?, ?, ?)
            """,
            (report.dataset_id, data_json, now_iso),
        )
    conn.close()


def get_benchmark(dataset_id: str) -> BenchmarkReport | None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT data_json FROM benchmarks WHERE dataset_id = ?", (dataset_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return BenchmarkReport.model_validate_json(row["data_json"])


# -----------------------------------------------------------------------------
# Demo Reset
# -----------------------------------------------------------------------------


def clear_all(keep_datasets: bool = True) -> None:
    """Clear cases, incidents, stories, evaluations for demo reset. Keeps datasets and Parquet if keep_datasets is True."""
    conn = get_connection()
    with conn:
        conn.execute("DELETE FROM evaluations;")
        conn.execute("DELETE FROM stories;")
        conn.execute("DELETE FROM incidents;")
        conn.execute("DELETE FROM cases;")
        if not keep_datasets:
            conn.execute("DELETE FROM benchmarks;")
            conn.execute("DELETE FROM datasets;")
    conn.close()
