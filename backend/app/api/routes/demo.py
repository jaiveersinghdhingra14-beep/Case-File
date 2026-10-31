from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ...store import db

router = APIRouter()


class DemoResetRequest(BaseModel):
    clear_history: bool = Field(default=True, description="Deletes stored cases, stories, incidents, evaluations.")
    clear_datasets: bool = Field(default=False, description="Whether to also clear registered datasets.")


class DemoResetResponse(BaseModel):
    history_cleared: bool = Field(description="Whether stored analysis data was cleared.")
    datasets_preserved: bool = Field(description="Whether indexed parquet datasets were kept.")
    reset_at: datetime = Field(description="When reset finished.")


@router.post("/demo/reset", response_model=DemoResetResponse)
def demo_reset(req: DemoResetRequest | None = None) -> DemoResetResponse:
    request_data = req or DemoResetRequest()
    if request_data.clear_history:
        db.clear_all(keep_datasets=not request_data.clear_datasets)

    return DemoResetResponse(
        history_cleared=request_data.clear_history,
        datasets_preserved=not request_data.clear_datasets,
        reset_at=datetime.now(timezone.utc),
    )
