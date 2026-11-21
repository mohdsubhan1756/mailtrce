from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.db.mongodb import get_database
from app.services.extended_analysis import write_audit


logger = logging.getLogger(__name__)
ANALYSIS_COLLECTIONS = (
    "header_forensics",
    "authentication_analysis",
    "url_domain_intelligence",
    "threat_analysis",
    "attachment_analysis",
    "ip_intelligence",
    "threat_intelligence",
    "risk_analysis",
    "alerts",
    "analyst_feedback",
)


def retention_status() -> dict[str, Any]:
    if settings.RETENTION_DAYS <= 0:
        return {"enabled": False, "retention_days": 0, "due_count": 0, "policy": "Retain indefinitely"}
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.RETENTION_DAYS)
    count = get_database()["emails"].count_documents({"created_at": {"$lte": cutoff}})
    return {
        "enabled": True,
        "retention_days": settings.RETENTION_DAYS,
        "due_count": count,
        "cutoff": cutoff,
        "policy": "Expired email evidence and analysis are automatically deleted; audit events are retained.",
    }


def purge_expired_emails(batch_size: int = 100) -> int:
    if settings.RETENTION_DAYS <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.RETENTION_DAYS)
    database = get_database()
    records = list(database["emails"].find(
        {"created_at": {"$lte": cutoff}},
        {"_id": 0, "email_id": 1, "case_id": 1, "sha256": 1, "evidence.local_path": 1},
    ).limit(max(1, min(batch_size, 1000))))
    evidence_root = Path(settings.EVIDENCE_DIRECTORY).resolve()
    purged = 0
    for record in records:
        email_id = record["email_id"]
        evidence_value = (record.get("evidence") or {}).get("local_path")
        try:
            write_audit(email_id, "RETENTION_PURGE_STARTED", {
                "case_id": record.get("case_id"),
                "sha256": record.get("sha256"),
                "expired_after_days": settings.RETENTION_DAYS,
            })
            if evidence_value:
                resolved_path = Path(evidence_value).resolve()
                if not resolved_path.is_relative_to(evidence_root):
                    logger.error("Refusing to remove evidence outside the configured evidence directory for %s", email_id)
                    write_audit(email_id, "RETENTION_PURGE_FAILED", {"reason": "Evidence path is outside the configured directory"})
                    continue
                if resolved_path.is_file():
                    resolved_path.unlink()
            for collection in ANALYSIS_COLLECTIONS:
                database[collection].delete_many({"email_id": email_id})
            database["emails"].delete_one({"email_id": email_id})
            write_audit(email_id, "RETENTION_PURGE_COMPLETED", {"case_id": record.get("case_id"), "sha256": record.get("sha256")})
            purged += 1
        except Exception:
            logger.exception("Could not complete retention purge for %s", email_id)
    return purged
