import duckdb
import sys
from pathlib import Path

sys.path.insert(0, r"D:\Case-File")
from backend.app.store.duckdb_store import DuckDBStore

store = DuckDBStore()
dataset_id = "ds_05af4a9e"
clean_glob = store.get_dataset_parquet_glob(dataset_id)
print("Glob:", clean_glob)

sql = f"""
    SELECT 
        host, 
        remote_address, 
        mitre_ids, 
        category, 
        LIST(command_line) as cmd_lines, 
        COUNT(*) as attempt_count,
        MIN(timestamp) as start_t,
        MAX(timestamp) as end_t,
        LIST(event_id) as event_ids
    FROM read_parquet('{clean_glob}')
    WHERE mitre_ids IS NOT NULL AND ARRAY_LENGTH(mitre_ids) > 0
    GROUP BY host, remote_address, mitre_ids, category
    HAVING COUNT(*) >= 2
    ORDER BY attempt_count DESC
    LIMIT 50
"""

con = duckdb.connect(":memory:")
res = con.execute(sql).fetchall()
print(f"Query returned {len(res)} pattern clusters!")
for r in res[:5]:
    print("Pattern:", r[0], "->", r[1], "MITRE:", r[2], "Count:", r[5])
