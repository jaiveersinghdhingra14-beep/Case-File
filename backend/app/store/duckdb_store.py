import math
from datetime import datetime
from pathlib import Path

import duckdb

from ..config import settings
from ..schemas import EventCategory, NormalizedEvent


class DuckDBStore:
    """Out-of-core columnar query engine for partitioned Parquet event sets."""

    def __init__(self, parquet_base_dir: Path | None = None):
        self._custom_base_dir = parquet_base_dir

    @property
    def base_dir(self) -> Path:
        p = self._custom_base_dir or settings.abs_parquet_dir
        p.mkdir(parents=True, exist_ok=True)
        return p

    def get_dataset_parquet_glob(self, dataset_id: str) -> str:
        ds_dir = self.base_dir / dataset_id
        # Recursively search for any parquet files
        return str(ds_dir / "**" / "*.parquet").replace("\\", "/")

    def has_parquet_data(self, dataset_id: str) -> bool:
        ds_dir = self.base_dir / dataset_id
        if not ds_dir.exists():
            return False
        return any(ds_dir.glob("**/*.parquet"))

    def query_events(
        self,
        dataset_id: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        hosts: list[str] | None = None,
        category: EventCategory | None = None,
        is_seed_only: bool = False,
        search_query: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[NormalizedEvent], int]:
        """Query normalized events from Parquet with pushdown filters."""
        if not self.has_parquet_data(dataset_id):
            return [], 0

        parquet_glob = self.get_dataset_parquet_glob(dataset_id)
        con = duckdb.connect(":memory:")

        where_clauses = []
        params = []

        if start_time:
            where_clauses.append("timestamp >= ?")
            params.append(start_time.isoformat())
        if end_time:
            where_clauses.append("timestamp <= ?")
            params.append(end_time.isoformat())
        if hosts:
            placeholders = ", ".join(["?"] * len(hosts))
            where_clauses.append(f"host IN ({placeholders})")
            params.extend(hosts)
        if category:
            where_clauses.append("category = ?")
            params.append(category.value)
        if is_seed_only:
            where_clauses.append("is_seed = true")
        if search_query:
            where_clauses.append(
                "(summary ILIKE ? OR command_line ILIKE ? OR file_path ILIKE ? OR user ILIKE ?)"
            )
            like_val = f"%{search_query}%"
            params.extend([like_val, like_val, like_val, like_val])

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        # Total count query
        count_sql = f"SELECT count(*) FROM read_parquet('{parquet_glob}') {where_sql}"
        total_count = con.execute(count_sql, params).fetchone()[0]

        # Paginated fetch
        data_sql = f"""
            SELECT * FROM read_parquet('{parquet_glob}')
            {where_sql}
            ORDER BY timestamp ASC
            LIMIT {limit} OFFSET {offset}
        """
        df = con.execute(data_sql, params).fetchdf()
        con.close()

        events: list[NormalizedEvent] = []
        for _, row in df.iterrows():
            d = row.to_dict()
            # Clean up numpy NaNs and nulls
            cleaned = {k: (None if (v is None or (isinstance(v, float) and math.isnan(v))) else v) for k, v in d.items()}
            # mitre_ids conversion if stored as array/list/string
            m_ids = cleaned.get("mitre_ids")
            if isinstance(m_ids, str):
                cleaned["mitre_ids"] = [x.strip() for x in m_ids.split(",") if x.strip()]
            elif not isinstance(m_ids, list):
                cleaned["mitre_ids"] = []

            events.append(NormalizedEvent.model_validate(cleaned))

        return events, total_count

    @staticmethod
    def load_lazy_raw_log(source_file: str, byte_offset: int, byte_length: int) -> str:
        """Fetch raw log line on-demand in O(1) time without loading entire file into memory."""
        try:
            with open(source_file, "rb") as f:
                f.seek(byte_offset)
                chunk = f.read(byte_length)
                return chunk.decode("utf-8", errors="replace").strip("\r\n")
        except Exception as e:  # noqa: BLE001
            return f"[Error reading raw log at offset {byte_offset}: {e!s}]"


duckdb_store = DuckDBStore()
