# CaseFile

> **Evidence-Grounded Attack Story Reconstruction from Raw Security Logs**  
> *CyberForge 2026 — Problem Statement #2*

CaseFile turns raw security logs from an authorized lab VM into a verified attack story. A lab VM is attacked with a known chain of Atomic Red Team techniques mixed with benign background noise. The logs are collected, cleaned, and grouped by deterministic code, then handed to an LLM in small chunks. The LLM writes structured attack steps citing exact event IDs. The system checks every step against the logs, removes claims it cannot support, and scores the result against the known chain and against two weaker baselines.

> **AI proposes the attack story. The system proves every sentence.**

---

## Important Notice & Ground Rules

1. **Lab Data Notice**: All logs and noise are generated in a controlled lab VM environment, not captured from production networks.
2. **Deterministic Step Ordering**: Step order is computed strictly by code from the earliest cited event timestamps. The LLM never decides ordering.
3. **Ground Truth Isolation**: Ground truth is read **only** by `services/scorer.py`. No ingest, correlation, mapping, or story-writing module has access to ground truth.
4. **Tune on Chain A, Report on Chain B**: Chain B is strictly held out. The `noise_only` baseline requires zero attack steps.
5. **Authorized Labs Only**: Attacks execute solely on the authorized lab VM; `POST /scenario-runs` rejects any request lacking `confirmed: true`.

---

## Architecture Pipeline

```text
scenario_runner (Atomic tests on Lab VM)
      │
      ├─► noise_generator (seeded benign noise)
      ▼
 connectors (Wazuh archive / Wazuh indexer / raw auditd)
      ▼
 normalizer (NormalizedEvent: PID, PPID, cmd, file, net, summary)
      ▼
noise_filter (allowlist & signatures learned from noise-only run)
      ▼
 correlator (process tree + entity graph via networkx, time-gap split)
      ▼
stage_mapper (ATT&CK technique candidate hints from YAML map)
      ▼
story_writer (LLM chunk prompts with cited event IDs)
      ▼
  verifier (4 checks: has_citation, ids_exist, supports_claim, specific_evidence)
      ▼
   scorer (step_recall, step_precision, false_steps, order_accuracy, grounding_rate, evidence_coverage)
      │
      ├─► baselines (baseline_window, baseline_raw)
      └─► report (analyst Markdown summary & review)
```

---

## Quickstart & Operations

### 1. Environment Setup
```bash
cp .env.example .env
# Edit .env with your LLM key and lab VM connection details
```

### 2. Local Installation
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Running Services
```bash
# Start backend API (FastAPI + Uvicorn on port 8000)
make up

# Run test suite
make test

# Lint codebase
make lint

# Clean / reset demo state
make reset
```

---

## Known Limits & Risks

* **Self-Generated Ground Truth:** The test runner defines the true executed steps.
* **Short Chains:** Designed and verified for 4–6 step attack chains. Longer complex multi-stage attacks are outside current hackathon scope.
* **Verifiable Techniques Only:** The verifier checks techniques defined in the knowledge map (`technique_map.yaml`) or tagged by Wazuh rules.
* **Temporal Ordering:** Reflects event timestamps, not proven causality.

---

## Third-Party Components & Disclosures

* **FastAPI & Uvicorn**: Async REST API framework and ASGI web server.
* **Pydantic v2 & pydantic-settings**: Data validation, schema definitions, and typed settings.
* **SQLite3**: Embedded relational database with JSON text columns.
* **NetworkX**: Process tree representation and entity graph connected component clustering.
* **Paramiko**: SSH client library for lab VM execution.
* **PyYAML**: YAML parsing for Atomic Red Team tests, noise profiles, and technique maps.
* **HTTPX**: Async HTTP client for indexer and log queries.
* **Pytest & Ruff**: Test runner and code linter.
* **Wazuh**: Open-source security monitoring agent and manager (single-node).
* **Atomic Red Team**: MITRE ATT&CK testing library and atomic test definitions.
* **Google GenAI / Gemini API**: LLM provider for structured JSON story generation.
* **React, Vite, TailwindCSS & TanStack Query**: Frontend analyst dashboard.
