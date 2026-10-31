from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, status

from ...schemas import (
    BenchmarkReport,
    Dataset,
    DatasetAccepted,
    DatasetCreateRequest,
    DatasetList,
    DatasetStatus,
)
from ...store import db
from ..errors import dataset_unreachable, not_found

router = APIRouter()


@router.post("/datasets", response_model=Dataset, status_code=status.HTTP_201_CREATED)
def register_dataset(req: DatasetCreateRequest) -> Dataset:
    p = Path(req.path)
    if not p.exists():
        raise dataset_unreachable(f"Path does not exist: {req.path}")

    # Calculate file size or total directory size
    if p.is_file():
        size_bytes = p.stat().st_size
    else:
        size_bytes = sum(f.stat().st_size for f in p.glob("**/*") if f.is_file())

    dataset_id = db.generate_id("ds_")
    name = req.name or p.name

    dataset = Dataset(
        dataset_id=dataset_id,
        name=name,
        path=str(p.resolve()),
        size_bytes=size_bytes,
        format="unknown",
        status=DatasetStatus.registered,
        events_total=0,
        time_range=None,
        hosts=[],
        created_at=datetime.now(timezone.utc),
        error_message=None,
    )
    db.save_dataset(dataset)
    return dataset


@router.get("/datasets", response_model=DatasetList)
def list_datasets() -> DatasetList:
    items = db.list_datasets()
    return DatasetList(items=items, total=len(items))


@router.get("/datasets/{dataset_id}", response_model=Dataset)
def get_dataset(dataset_id: str) -> Dataset:
    ds = db.get_dataset(dataset_id)
    if not ds:
        raise not_found(f"Dataset {dataset_id} not found.")
    return ds


@router.post("/datasets/{dataset_id}/ingest", response_model=DatasetAccepted, status_code=status.HTTP_202_ACCEPTED)
def ingest_dataset(dataset_id: str, background_tasks: BackgroundTasks) -> DatasetAccepted:
    ds = db.get_dataset(dataset_id)
    if not ds:
        raise not_found(f"Dataset {dataset_id} not found.")

    ds.status = DatasetStatus.ingesting
    db.save_dataset(ds)

    # In Step B, background_tasks.add_task(run_ingest, dataset_id) will be wired
    return DatasetAccepted(dataset_id=dataset_id, status=ds.status)


@router.get("/datasets/{dataset_id}/benchmark", response_model=BenchmarkReport)
def get_benchmark(dataset_id: str) -> BenchmarkReport:
    bench = db.get_benchmark(dataset_id)
    if not bench:
        raise not_found(f"No benchmark report generated yet for dataset {dataset_id}.")
    return bench
