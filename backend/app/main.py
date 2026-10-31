from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api.errors import CaseFileException
from .api.routes import cases, datasets, demo, health, incidents, stories
from .config import settings
from .schemas import ErrorResponse
from .store import db

# Initialize database tables and parquet directory
db.init_db()
settings.abs_parquet_dir.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Evidence-Grounded Attack Path Reconstruction from Big Security Logs",
)

# Enable CORS for frontend dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception handler for domain errors
@app.exception_handler(CaseFileException)
async def casefile_exception_handler(request: Request, exc: CaseFileException):
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(code=exc.code, detail=exc.custom_detail).model_dump(),
    )


# Exception handler for Pydantic validation errors (returns HTTP 422 with validation_error code)
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    first_err = exc.errors()[0] if exc.errors() else {"msg": "Validation error"}
    msg = first_err.get("msg", "Invalid request body")
    loc = " -> ".join(str(item) for item in first_err.get("loc", []))
    detail = f"{msg} at {loc}" if loc else msg
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ErrorResponse(code="validation_error", detail=detail).model_dump(),
    )


# Wire /api/v1 routes
app.include_router(health.router, prefix="/api/v1", tags=["Health"])
app.include_router(datasets.router, prefix="/api/v1", tags=["Datasets"])
app.include_router(incidents.router, prefix="/api/v1", tags=["Incidents"])
app.include_router(cases.router, prefix="/api/v1", tags=["Cases"])
app.include_router(stories.router, prefix="/api/v1", tags=["Stories"])
app.include_router(demo.router, prefix="/api/v1", tags=["Demo"])

# Mount dynamic frontend
frontend_dir = settings.BASE_DIR / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_index():
        index_file = frontend_dir / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"status": "CaseFile API running. Place index.html in frontend/"}
