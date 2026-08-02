from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import upload, analysis, reports, dashboard, actions
from services.db import init_db

app = FastAPI(
    title="BOI Sentinel AI",
    version="1.0.0",
    description="Generative AI-powered Android APK malware investigation platform",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload.router, prefix="/api/upload", tags=["Upload"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["Analysis"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(actions.router, prefix="/api/actions", tags=["Actions"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])


@app.on_event("startup")
def on_startup():
    try:
        init_db()
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning(
            "Database unavailable on startup (is PostgreSQL running?): %s", exc
        )


@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "ok", "service": "BOI Sentinel AI"}
