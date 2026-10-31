# CaseFile API Routes Reference

Base URL prefix: `/api/v1`

| Method | Route | Request Body | Response Model / Status | Description |
|---|---|---|---|---|
| `GET` | `/health` | none | `HealthResponse` | App status & component reachability (`log_source`, `target_ssh`, `llm`, `database`). |
| `GET` | `/targets` | none | `TargetList` | Authorized lab VM targets. |
| `GET` | `/scenarios` | none | `ScenarioList` | Available attack scenarios (`chain_a`, `chain_b`, `noise_only`). |
| `GET` | `/scenarios/{scenario_id}` | none | `Scenario` | Specific scenario details and steps. |
| `POST` | `/scenario-runs` | `ScenarioRunCreateRequest` | `ScenarioRunAccepted` (202) | Starts attack scenario execution on lab VM (`confirmed: true` required). |
| `GET` | `/scenario-runs` | none | `ScenarioRunList` | List past scenario runs. |
| `GET` | `/scenario-runs/{scenario_run_id}` | none | `ScenarioRun` | Progress or completed scenario run with ground truth. |
| `POST` | `/cases` | `CaseCreateRequest` | `CaseAccepted` (202) | Ingests, normalizes, filters, and groups logs for a run or window. |
| `GET` | `/cases` | none | `CaseList` | All cases. |
| `GET` | `/cases/{case_id}` | none | `Case` | Case status and statistics (`CaseStats`). |
| `GET` | `/cases/{case_id}/events` | query params | `EventList` | Normalized events (filters: `group_id`, `is_noise`, `host`, `category`, `q`, `offset`, `limit`). |
| `GET` | `/cases/{case_id}/events/{event_id}` | none | `NormalizedEvent` | Single event with full raw log. |
| `GET` | `/cases/{case_id}/groups` | none | `GroupList` | Correlated activity groups. |
| `POST` | `/cases/{case_id}/stories` | `StoryCreateRequest` | `StoryAccepted` (202) | Starts story reconstruction using chosen method (`casefile`, `baseline_window`, `baseline_raw`). |
| `GET` | `/cases/{case_id}/stories` | none | `StoryList` | All reconstructed stories for a case. |
| `GET` | `/cases/{case_id}/comparison` | none | `ComparisonResponse` | Side-by-side metric comparison across all 3 methods. |
| `GET` | `/stories/{story_id}` | none | `Story` | Story details, verified steps, evidence citations, and unsupported claims. |
| `POST` | `/stories/{story_id}/review` | `StoryReviewRequest` | `Story` | Analyst review (confirm/reject steps, approve/reject story). |
| `POST` | `/stories/{story_id}/evaluate` | `EvaluateRequest` | `Evaluation` | Evaluate story against ground truth. |
| `GET` | `/stories/{story_id}/report` | none | `ReportResponse` | Markdown export of the story. |
| `GET` | `/evaluations/{evaluation_id}` | none | `Evaluation` | Specific evaluation record and per-step match results. |
| `POST` | `/demo/reset` | `DemoResetRequest` | `DemoResetResponse` | Clears stored runs, cases, stories, and cleans VM artifacts. |

---

## Error Codes

| Status | Code | Trigger |
|---|---|---|
| 403 | `target_not_authorized` | Target exists but `authorized == false`. |
| 404 | `not_found` | Resource ID not found. |
| 409 | `wrong_state` | Action not valid in current resource state. |
| 409 | `no_ground_truth` | Evaluation or comparison requested for case without scenario run. |
| 409 | `already_in_progress` | Story generation with same method already active. |
| 422 | `validation_error` | Missing safety confirmation, invalid time window, or out-of-range params. |
| 503 | `log_source_unreachable` | Log source unreachable. |
| 503 | `target_unreachable` | Lab VM SSH connection failed. |
| 503 | `llm_unreachable` | LLM API provider failed to answer. |
