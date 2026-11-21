from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.authentication import (
    router as authentication_router,
)
from app.api.routes.header_forensics import (
    router as header_forensics_router,
)
from app.api.routes.ingestion import (
    router as ingestion_router,
)
from app.api.routes.url_domain_intelligence import (
    router as url_domain_router,
)
from app.api.routes.extended_analysis import (
    router as extended_analysis_router,
)
from app.core.config import settings
from app.db.mongodb import (
    close_mongodb_connection,
    connect_to_mongodb,
)
from app.services.retention import purge_expired_emails


logger = logging.getLogger(__name__)


async def retention_worker() -> None:
    while True:
        try:
            await asyncio.to_thread(purge_expired_emails)
        except Exception:
            logger.exception("Retention cleanup failed")
        await asyncio.sleep(settings.RETENTION_CHECK_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(
    app: FastAPI,
):
    connect_to_mongodb()
    task = asyncio.create_task(retention_worker()) if settings.RETENTION_DAYS > 0 else None
    try:
        yield
    finally:
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        close_mongodb_connection()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "MailTrace AI - Email Forensics "
        "and Threat Intelligence Platform"
    ),
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.CORS_ORIGINS),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(
    ingestion_router
)

app.include_router(
    header_forensics_router
)

app.include_router(
    authentication_router
)

app.include_router(
    url_domain_router
)

app.include_router(
    extended_analysis_router
)


@app.get("/")
def root():
    return {
        "application": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "modules": [
            {"module": 1, "name": "Email Ingestion & Normalization", "status": "available"},
            {"module": 2, "name": "Email Header Forensics", "status": "available"},
            {"module": 3, "name": "Authentication Analysis", "status": "available"},
            {"module": 4, "name": "URL & Domain Intelligence", "status": "available"},
            {"module": 5, "name": "Rule-Based Threat Detection", "status": "available"},
            {"module": 6, "name": "Attachment Forensics", "status": "static-analysis"},
            {"module": 7, "name": "IP Intelligence & Geolocation", "status": "local + optional providers"},
            {"module": 8, "name": "Threat Intelligence Correlation", "status": "local + optional providers"},
            {"module": 9, "name": "Correlation & Campaign Intelligence", "status": "indicator-correlation"},
            {"module": 10, "name": "Risk & Attribution Engine", "status": "risk-scoring; actor-attribution-unavailable"},
            {"module": 11, "name": "Alerting & SOC Dashboard", "status": "in-app-alerts"},
            {"module": 12, "name": "Case Management & Forensic Reporting", "status": "available"},
            {"module": 13, "name": "Privacy, Evidence & Audit", "status": "retention-enabled" if settings.RETENTION_DAYS > 0 else "retention-disabled"},
        ],
    }


@app.get("/health")
def health():
    try:
        from app.db.mongodb import get_database
        get_database().command("ping")
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={"status": "unhealthy", "database": "unavailable"},
        ) from exc
    return {
        "status": "healthy",
        "database": "connected",
        "application": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }
