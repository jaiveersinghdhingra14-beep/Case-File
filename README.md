# CaseFile v2: Big-Log Edition

> **Kill Chain and Attack Path Analysis at Scale**  
> *CyberForge 2026 — Problem Statement #2*

CaseFile reconstructs complete end-to-end attack paths from massive security log sets (**15 GB, 30 GB, 50 GB**) on standard analyst hardware under an **8 GB peak RAM budget**.

```text
       Raw Logs (15 / 30 / 50 GB)
                  │
                  ▼
         [ 1. Profiler ] ──────► Detects format (auditd, JSON, syslog, CSV) & timestamp
                  │
                  ▼
      [ 2. Streaming Ingest ] ──► Byte-range sharding, parallel parse to partitioned Parquet
                  │
                  ▼
        [ 3. Reducer Engine ] ──► Pushdown filters, command normalization, mathematical rarity scoring (Top-K seeds)
                  │
                  ▼
     [ 4. Provenance Expander ] ─► Hops & time window expansion (captures pivots: HR-07 -> FS-02 -> DC-01)
                  │
                  ▼
      [ 5. Attack Graph Story ] ─► Graph correlation, ATT&CK + Kill Chain mapping, Lookahead blast radius (FR-6)
                  │
                  ▼
         [ 6. Verifier Engine ] ─► 4 deterministic checks (citation, existence, support, specific evidence)
```

---

## Key Capabilities (PRD Alignment)

* **Detect (FR-2):** Discovers hidden multi-stage attacks across millions of background noise events.
* **Label (FR-3):** Simultaneously tags each event with a **MITRE ATT&CK technique** and **Cyber Kill Chain stage**.
* **Connect (FR-4 & FR-5):** Reconstructs unified incident paths across distinct hosts, accounts, and time intervals.
* **Look Ahead & Blast Radius (FR-6):** Evaluates compromised credentials to determine what adjacent critical systems the attacker could reach next.
* **Sub-500ms Investigation Speed (FR-7):** Exposes `GET /api/v1/incidents/{id}/path` powered by DuckDB columnar indices and lazy raw-log offset lookups.
* **Incident Risk Scoring (Bonus B-1):** Scores each incident (0–100) based on kill chain depth and affected asset criticality.
* **Automated Plain English Reporting (Bonus B-2):** Markdown executive report export with citations and containment recommendations.
* **Configurable Detection Rules (Bonus B-4):** YAML-driven rule definitions for sequence matching (e.g., brute force thresholds).

---

## Official Targets & Performance ("Great" Standard)

| Metric | Target | CaseFile v2 Architecture |
|---|---|---|
| **Detection** | $> 90\%$ | Top-$K$ rarity heap + pattern rules |
| **Correct Labels** | $> 85\%$ | YAML ATT&CK knowledge map + verifier |
| **Attack Path** | $100\%$ | Temporal provenance neighborhood expansion |
| **False Alarms** | $< 10\%$ | Deterministic 4-check verification gate |
| **Processing Time** | $< 1$ hour | Sharded streaming ingest + DuckDB Parquet |
| **Peak RAM** | $< 8$ GB | Constant memory streaming, byte-range sharding |
| **Investigation Latency** | $< 500$ ms | Columnar pushdown + $O(1)$ lazy file seek |

---

## Third-Party Disclosures & Tech Stack

* **FastAPI & Uvicorn**: High-performance async web framework and ASGI server.
* **DuckDB**: Out-of-core columnar SQL query engine.
* **PyArrow**: Columnar Parquet serialization and hour/host partitioning.
* **orjson**: Ultra-fast SIMD-accelerated JSON parser.
* **Pydantic v2 & pydantic-settings**: Strict validation schemas and environment settings.
* **SQLite3 (stdlib)**: Small metadata storage (datasets, cases, stories, benchmarks).
* **NetworkX**: Multi-host provenance and attack path graph generation.
* **PyYAML**: Configurable detection rules and ATT&CK technique mapping.
* **psutil**: Runtime memory (RSS) and throughput benchmarking.
* **Pytest & Ruff**: Verification test suite and static code analysis.

---

## Running the Application

### 1. Requirements & Setup
```bash
python -m pip install -r requirements.txt
cp .env.example .env
```

### 2. Run Tests & Linter
```bash
# Run test suite
python -m pytest backend/tests -v

# Run linter
python -m ruff check backend/app backend/tests
```

### 3. Start the Backend Server
```bash
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```
