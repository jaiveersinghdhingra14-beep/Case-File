# CaseFile v2 API Routes Reference

Base URL prefix: `/api/v1`

| Method | Route | Request Body | Response Model | Description |
|---|---|---|---|---|
| `GET` | `/health` | none | `HealthResponse` | System health check (`database`, `duckdb`, `dataset_store`, `llm`). |
| `POST` | `/datasets` | `DatasetCreateRequest` | `Dataset` (201) | Registers local dataset path (no upload required). |
| `GET` | `/datasets` | none | `DatasetList` | Lists all registered datasets. |
| `GET` | `/datasets/{dataset_id}` | none | `Dataset` | Retrieves details and status of specific dataset. |
| `POST` | `/datasets/{dataset_id}/ingest` | none | `DatasetAccepted` (202) | Starts parallel streaming ingest to partitioned Parquet. |
| `GET` | `/datasets/{dataset_id}/benchmark` | none | `BenchmarkReport` | Per-stage metrics (rows_in, rows_out, peak_rss_mb, throughput_mb_s). |
| `GET` | `/incidents` | query params | `IncidentList` | Lists reconstructed incidents sorted by `risk_score` descending. |
| `GET` | `/incidents/{incident_id}/path` | none | `IncidentPath` | Sub-500ms graph + timeline + lookahead blast radius (FR-6 & FR-7). |
| `GET` | `/incidents/{incident_id}/report` | none | `ReportResponse` | Markdown executive report export. |
| `POST` | `/cases` | `CaseCreateRequest` | `CaseAccepted` (202) | Creates an investigation case from a ready dataset. |
| `GET` | `/cases` | none | `CaseList` | Lists all cases. |
| `GET` | `/cases/{case_id}` | none | `Case` | Details and statistics for a case. |
| `GET` | `/cases/{case_id}/events` | query params | `EventList` | Paginated normalized events with pushdown filters. |
| `GET` | `/cases/{case_id}/events/{event_id}` | none | `NormalizedEvent` | Single event with $O(1)$ lazy raw log seek. |
| `GET` | `/cases/{case_id}/groups` | none | `GroupList` | Correlated activity groups. |
| `GET` | `/cases/{case_id}/comparison` | none | `ComparisonResponse` | Side-by-side comparison across reconstruction methods. |
| `POST` | `/cases/{case_id}/stories` | `StoryCreateRequest` | `StoryAccepted` (202) | Starts attack story generation using chosen method. |
| `GET` | `/cases/{case_id}/stories` | none | `StoryList` | Reconstructed stories for a case. |
| `GET` | `/stories/{story_id}` | none | `Story` | Story details, verified steps, and rejected claims. |
| `POST` | `/stories/{story_id}/review` | `StoryReviewRequest` | `Story` | Analyst step confirmation / story approval. |
| `POST` | `/stories/{story_id}/evaluate` | `EvaluateRequest` | `Evaluation` | Evaluates story against ground truth when available. |
| `GET` | `/stories/{story_id}/report` | none | `ReportResponse` | Markdown export of story. |
| `GET` | `/evaluations/{evaluation_id}` | none | `Evaluation` | Evaluation report with per-step match details. |
| `POST` | `/demo/reset` | `DemoResetRequest` | `DemoResetResponse` | Clears cases and incidents, preserves Parquet dataset store. |

---

## Standard Error Codes

| Status | Code | Trigger |
|---|---|---|
| 404 | `not_found` | Resource ID not found. |
| 409 | `wrong_state` | Action not allowed in resource's current state. |
| 409 | `dataset_not_ready` | Ingestion or reduction still in progress. |
| 409 | `no_ground_truth` | Evaluation requested for dataset without labels. |
| 409 | `already_in_progress` | Duplicate generation or ingest job already running. |
| 422 | `validation_error` | Request body failed Pydantic validation (ranges, dates). |
| 503 | `dataset_unreachable` | Path to log files does not exist or is inaccessible. |
| 503 | `llm_unreachable` | LLM provider service unavailable. |
