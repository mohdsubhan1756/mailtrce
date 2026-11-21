import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Body, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.core.config import settings
from app.db.mongodb import get_database
from app.services.retention import retention_status
from app.services.reporting import build_pdf_report
from app.services.extended_analysis import (
    analyze_all,
    analyze_attachments,
    analyze_ips,
    analyze_threat,
    campaign,
    correlate_intelligence,
    get_email,
    get_stored,
    risk,
    serialize,
    verify_evidence,
    verify_audit_chain,
    write_audit,
    ip_analysis_version,
    intelligence_analysis_version,
    threat_analysis_version,
    risk_scoring_version,
    ATTACHMENT_ANALYSIS_VERSION,
)


router = APIRouter(prefix="/api/v1", tags=["Modules 5-13"])


@router.get("/retention/status")
def get_retention_status() -> dict[str, Any]:
    return retention_status()


def run(action):
    try:
        return action()
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def store_result(collection: str, result: dict[str, Any]) -> dict[str, Any]:
    get_database()[collection].replace_one(
        {"email_id": result["email_id"]},
        serialize(result),
        upsert=True,
    )
    return result


@router.post("/emails/{email_id}/analyze-extended")
def analyze_extended(email_id: str) -> dict[str, Any]:
    return run(lambda: analyze_all(email_id))


@router.post("/emails/{email_id}/analyze-threat")
def analyze_threat_endpoint(email_id: str) -> dict[str, Any]:
    return run(lambda: store_result("threat_analysis", analyze_threat(get_email(email_id))))


@router.get("/emails/{email_id}/threat-analysis")
def get_threat_analysis(email_id: str) -> dict[str, Any]:
    def load():
        result = get_stored("threat_analysis", email_id)
        if result is None or result.get("analysis_version") != threat_analysis_version():
            result = store_result("threat_analysis", analyze_threat(get_email(email_id)))
        return result
    return run(load)


@router.post("/emails/{email_id}/analyze-attachments")
def analyze_attachments_endpoint(email_id: str) -> dict[str, Any]:
    return run(lambda: store_result("attachment_analysis", analyze_attachments(get_email(email_id))))


@router.get("/emails/{email_id}/attachment-analysis")
def get_attachment_analysis(email_id: str) -> dict[str, Any]:
    def load():
        result = get_stored("attachment_analysis", email_id)
        if result is None or result.get("analysis_version") != ATTACHMENT_ANALYSIS_VERSION:
            result = store_result("attachment_analysis", analyze_attachments(get_email(email_id)))
        return result
    return run(load)


@router.post("/emails/{email_id}/analyze-ip-intelligence")
def analyze_ip_endpoint(email_id: str) -> dict[str, Any]:
    return run(lambda: store_result("ip_intelligence", analyze_ips(get_email(email_id))))


@router.get("/emails/{email_id}/ip-intelligence")
def get_ip_analysis(email_id: str) -> dict[str, Any]:
    def load():
        result = get_stored("ip_intelligence", email_id)
        if result is None or result.get("analysis_version") != ip_analysis_version():
            result = store_result("ip_intelligence", analyze_ips(get_email(email_id)))
        return result
    return run(load)


@router.get("/emails/{email_id}/threat-intelligence")
def get_threat_intelligence(email_id: str) -> dict[str, Any]:
    def load():
        result = get_stored("threat_intelligence", email_id)
        if result is None or result.get("analysis_version") != intelligence_analysis_version():
            email = get_email(email_id)
            threat = analyze_threat(email)
            attachments = analyze_attachments(email)
            ips = get_stored("ip_intelligence", email_id)
            if ips is None or ips.get("analysis_version") != ip_analysis_version():
                ips = store_result("ip_intelligence", analyze_ips(email))
            result = store_result("threat_intelligence", correlate_intelligence(email, threat, attachments, ips))
        return result
    return run(load)


@router.get("/emails/{email_id}/campaign")
def get_campaign(email_id: str) -> dict[str, Any]:
    return run(lambda: campaign(get_email(email_id)))


@router.put("/emails/{email_id}/feedback")
def save_analyst_feedback(email_id: str, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    email = run(lambda: get_email(email_id))
    label = str(payload.get("label") or "").strip().upper()
    if label not in {"LEGITIMATE", "MALICIOUS"}:
        raise HTTPException(status_code=422, detail="Feedback label must be LEGITIMATE or MALICIOUS.")
    note = str(payload.get("note") or "").strip()
    if len(note) > 1000:
        raise HTTPException(status_code=422, detail="Feedback note must be 1000 characters or fewer.")
    feedback = {
        "email_id": email_id,
        "case_id": email.get("case_id"),
        "label": label,
        "note": note,
        "reviewed_at": datetime.now(timezone.utc),
        "source": "analyst_review",
    }
    get_database()["analyst_feedback"].replace_one({"email_id": email_id}, feedback, upsert=True)
    write_audit(email_id, "SAVE_ANALYST_FEEDBACK", {"label": label, "note": note})
    return feedback


@router.get("/emails/{email_id}/feedback")
def get_analyst_feedback(email_id: str) -> dict[str, Any] | None:
    run(lambda: get_email(email_id))
    return get_database()["analyst_feedback"].find_one({"email_id": email_id}, {"_id": 0})


@router.get("/evaluation/metrics")
def get_evaluation_metrics() -> dict[str, Any]:
    """Compare reviewed labels with stored risk verdicts; never used to train the model."""
    labels = list(get_database()["analyst_feedback"].find({}, {"_id": 0, "email_id": 1, "label": 1}))
    email_ids = [row["email_id"] for row in labels if row.get("email_id")]
    scores = {
        row["email_id"]: int(row.get("score", 0))
        for row in get_database()["risk_analysis"].find({"email_id": {"$in": email_ids}, "scoring_version": risk_scoring_version()}, {"_id": 0, "email_id": 1, "score": 1})
    } if email_ids else {}
    counts = {"true_positive": 0, "false_positive": 0, "true_negative": 0, "false_negative": 0, "without_score": 0}
    for row in labels:
        if row.get("email_id") not in scores:
            counts["without_score"] += 1
            continue
        actual_malicious = row.get("label") == "MALICIOUS"
        predicted_malicious = scores[row["email_id"]] >= 40
        if actual_malicious and predicted_malicious:
            counts["true_positive"] += 1
        elif not actual_malicious and predicted_malicious:
            counts["false_positive"] += 1
        elif not actual_malicious:
            counts["true_negative"] += 1
        else:
            counts["false_negative"] += 1
    reviewed = sum(counts[key] for key in ("true_positive", "false_positive", "true_negative", "false_negative"))
    negatives = counts["false_positive"] + counts["true_negative"]
    positives = counts["true_positive"] + counts["false_negative"]
    precision_denominator = counts["true_positive"] + counts["false_positive"]
    recall_denominator = positives
    minimum_class_sample = 20
    return {
        "threshold": 40,
        "threshold_meaning": "Scores of 40 or more are counted as flagged, matching the app's SUSPICIOUS verdict threshold.",
        "reviewed_with_score": reviewed,
        "negative_review_count": negatives,
        "positive_review_count": positives,
        "minimum_class_sample": minimum_class_sample,
        "evaluation_ready": negatives >= minimum_class_sample and positives >= minimum_class_sample,
        "labels_without_score": counts["without_score"],
        "counts": counts,
        "false_positive_rate": counts["false_positive"] / negatives if negatives else None,
        "precision": counts["true_positive"] / precision_denominator if precision_denominator else None,
        "recall": counts["true_positive"] / recall_denominator if recall_denominator else None,
        "note": "Metrics use only manually reviewed labels and saved risk scores; they are not a model benchmark and feedback does not train the classifier.",
    }


@router.get("/emails/{email_id}/risk")
def get_risk(email_id: str) -> dict[str, Any]:
    def load():
        result = get_stored("risk_analysis", email_id)
        if result is None or result.get("scoring_version") != risk_scoring_version():
            email = get_email(email_id)
            threat = store_result("threat_analysis", analyze_threat(email))
            attachments = store_result("attachment_analysis", analyze_attachments(email))
            ips = store_result("ip_intelligence", analyze_ips(email))
            intelligence = store_result("threat_intelligence", correlate_intelligence(email, threat, attachments, ips))
            result = store_result("risk_analysis", risk(email, refresh_auth=True, refresh_url=True, ip_result=ips, intelligence_result=intelligence))
            db = get_database()
            db["emails"].update_one(
                {"email_id": email_id},
                {"$set": {"module.risk_analysis": {
                    "status": "COMPLETED",
                    "risk_score": result["score"],
                    "risk_level": result["risk_level"],
                    "updated_at": result["calculated_at"],
                }}},
            )
            alert_filter = {"email_id": email_id, "source": "risk_analysis"}
            alert_fields = {
                "case_id": email.get("case_id"),
                "score": result["score"],
                "verdict": result["verdict"],
                "last_evaluated_at": result["calculated_at"],
            }
            if result["score"] >= 40:
                db["alerts"].update_one(
                    alert_filter,
                    {"$set": {**alert_fields, "severity": result["risk_level"]},
                     "$setOnInsert": {"email_id": email_id, "source": "risk_analysis", "created_at": result["calculated_at"], "status": "OPEN"}},
                    upsert=True,
                )
            else:
                db["alerts"].update_one(alert_filter, {"$set": {**alert_fields, "status": "RESOLVED"}})
        return result
    return run(load)


@router.get("/alerts")
def list_alerts(limit: int = Query(default=100, ge=1, le=500), skip: int = Query(default=0, ge=0)) -> list[dict[str, Any]]:
    return list(get_database()["alerts"].find({}, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit))


@router.patch("/alerts/{email_id}/{source}/status")
def update_alert_status(email_id: str, source: str, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    status_value = str(payload.get("status") or "").upper()
    if status_value not in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
        raise HTTPException(status_code=422, detail="Alert status must be OPEN, ACKNOWLEDGED, or RESOLVED.")
    alerts = get_database()["alerts"]
    alert_filter = {"email_id": email_id, "source": source}
    if alerts.find_one(alert_filter, {"_id": 1}) is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    alerts.update_one(alert_filter, {"$set": {"status": status_value, "updated_at": datetime.now(timezone.utc)}})
    write_audit(email_id, "UPDATE_ALERT_STATUS", {"source": source, "status": status_value})
    return alerts.find_one(alert_filter, {"_id": 0})


@router.get("/cases")
def list_cases(
    limit: int = Query(default=50, ge=1, le=200),
    skip: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    db = get_database()
    cases = {
        case["case_id"]: case
        for case in db["cases"].find({}, {"_id": 0})
    }
    email_groups = db["emails"].aggregate([
        {"$group": {
            "_id": "$case_id",
            "email_count": {"$sum": 1},
            "last_email_at": {"$max": "$created_at"},
        }},
    ])
    for group in email_groups:
        case_id = group.get("_id")
        if not case_id:
            continue
        case = cases.setdefault(case_id, {
            "case_id": case_id,
            "title": "Email investigation",
            "description": "",
            "status": "OPEN",
        })
        case["email_count"] = group.get("email_count", 0)
        case["last_email_at"] = group.get("last_email_at")
    for case in cases.values():
        case.setdefault("email_count", 0)
    def recency(case: dict[str, Any]) -> float:
        value = case.get("updated_at") or case.get("last_email_at") or case.get("created_at")
        if not isinstance(value, datetime):
            return 0.0
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()

    ordered = sorted(
        cases.values(),
        key=recency,
        reverse=True,
    )
    return {
        "items": ordered[skip:skip + limit],
        "total": len(ordered),
        "skip": skip,
        "limit": limit,
    }


@router.get("/cases/{case_id}")
def get_case(case_id: str) -> dict[str, Any]:
    db = get_database()
    case = db["cases"].find_one({"case_id": case_id}, {"_id": 0})
    email_filter = {"case_id": case_id}
    email_count = db["emails"].count_documents(email_filter)
    emails = list(db["emails"].find(
        email_filter,
        {"_id": 0, "email_id": 1, "case_id": 1, "subject": 1, "sender": 1, "created_at": 1, "timestamp": 1, "status": 1},
    ).sort("created_at", -1).limit(500))
    if case is None and email_count == 0:
        raise HTTPException(status_code=404, detail="Case not found.")
    return {
        **(case or {"case_id": case_id, "status": "OPEN"}),
        "email_count": email_count,
        "emails": emails,
    }


@router.post("/cases/{case_id}/emails/{email_id}")
def assign_email_to_case(case_id: str, email_id: str) -> dict[str, Any]:
    db = get_database()
    email = db["emails"].find_one({"email_id": email_id}, {"_id": 0, "case_id": 1})
    if email is None:
        raise HTTPException(status_code=404, detail="Email evidence not found.")

    case_exists = db["cases"].find_one({"case_id": case_id}, {"_id": 1}) or db["emails"].find_one(
        {"case_id": case_id}, {"_id": 1}
    )
    if not case_exists:
        raise HTTPException(status_code=404, detail="Case not found.")

    db["emails"].update_one({"email_id": email_id}, {"$set": {"case_id": case_id, "updated_at": datetime.now(timezone.utc)}})
    db["cases"].update_one({"case_id": case_id}, {"$set": {"updated_at": datetime.now(timezone.utc)}})
    for collection in (
        "header_forensics", "authentication_analysis", "url_domain_intelligence",
        "threat_analysis", "attachment_analysis", "ip_intelligence",
        "threat_intelligence", "risk_analysis",
    ):
        db[collection].update_one({"email_id": email_id}, {"$set": {"case_id": case_id}})
    db["alerts"].update_many({"email_id": email_id}, {"$set": {"case_id": case_id}})
    write_audit(email_id, "ASSIGN_EMAIL_TO_CASE", {"from_case_id": email.get("case_id"), "to_case_id": case_id})
    return {"email_id": email_id, "case_id": case_id, "status": "ASSIGNED"}


@router.post("/cases")
def create_case(payload: dict[str, Any] = Body(default_factory=dict)) -> dict[str, Any]:
    case_id = str(payload.get("case_id") or f"CASE-{uuid.uuid4().hex[:12].upper()}")
    status_value = str(payload.get("status") or "OPEN").upper()
    title = str(payload.get("title") or "MailTrace investigation").strip()[:120]
    if status_value not in {"OPEN", "CLOSED"}:
        raise HTTPException(status_code=422, detail="Case status must be OPEN or CLOSED.")
    if not title:
        raise HTTPException(status_code=422, detail="Case title cannot be empty.")
    cases = get_database()["cases"]
    if cases.find_one({"case_id": case_id}, {"_id": 1}) or get_database()["emails"].find_one(
        {"case_id": case_id}, {"_id": 1}
    ):
        raise HTTPException(
            status_code=409,
            detail=f"Case '{case_id}' already exists.",
        )
    document = {
        "case_id": case_id,
        "title": title,
        "description": str(payload.get("description") or "")[:2000],
        "status": status_value,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    cases.insert_one(document)
    document.pop("_id", None)
    write_audit(None, "CREATE_CASE", {"title": title, "status": status_value}, case_id=case_id)
    return document


@router.patch("/cases/{case_id}")
def update_case(case_id: str, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    allowed = {key: payload[key] for key in ("title", "description") if key in payload}
    if "title" in allowed:
        allowed["title"] = str(allowed["title"]).strip()[:120]
        if not allowed["title"]:
            raise HTTPException(status_code=422, detail="Case title cannot be empty.")
    if "description" in allowed:
        allowed["description"] = str(allowed["description"])[:2000]
    if "status" in payload:
        status_value = str(payload["status"]).upper()
        if status_value not in {"OPEN", "CLOSED"}:
            raise HTTPException(status_code=422, detail="Case status must be OPEN or CLOSED.")
        allowed["status"] = status_value
    if not allowed:
        raise HTTPException(status_code=422, detail="Provide at least one case field to update.")
    allowed["updated_at"] = datetime.now(timezone.utc)
    result = get_database()["cases"].update_one({"case_id": case_id}, {"$set": allowed})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Case not found.")
    write_audit(None, "UPDATE_CASE", {key: value for key, value in allowed.items() if key != "updated_at"}, case_id=case_id)
    return get_database()["cases"].find_one({"case_id": case_id}, {"_id": 0})


def build_complete_report(email_id: str) -> dict[str, Any]:
    email = get_email(email_id)
    threat = analyze_threat(email)
    attachments = analyze_attachments(email)
    ips = analyze_ips(email)
    intelligence = correlate_intelligence(email, threat, attachments, ips)
    return {
        "report_version": "1.1",
        "email": email,
        "authentication": get_stored("authentication_analysis", email_id),
        "url_domain": get_stored("url_domain_intelligence", email_id),
        "threat": threat,
        "attachments": attachments,
        "ips": ips,
        "intelligence": intelligence,
        "campaign": campaign(email),
        "risk": risk(email, ip_result=ips, intelligence_result=intelligence),
        "generated_at": datetime.now(timezone.utc),
    }


@router.get("/emails/{email_id}/report")
def get_report(email_id: str) -> dict[str, Any]:
    return run(lambda: build_complete_report(email_id))


@router.get("/emails/{email_id}/report/pdf")
def get_report_pdf(email_id: str):
    report = run(lambda: build_complete_report(email_id))
    pdf_data = build_pdf_report(report)
    filename = f"mailtrace-report-{email_id}.pdf"
    return StreamingResponse(
        iter([pdf_data]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/emails/{email_id}/audit")
def get_audit(email_id: str) -> list[dict[str, Any]]:
    return list(get_database()["audit_log"].find({"email_id": email_id}, {"_id": 0}).sort("timestamp", -1).limit(500))


@router.get("/emails/{email_id}/audit/verify")
def verify_email_audit(email_id: str) -> dict[str, Any]:
    return verify_audit_chain(email_id)


@router.get("/cases/{case_id}/audit")
def get_case_audit(case_id: str) -> list[dict[str, Any]]:
    if not get_database()["cases"].find_one({"case_id": case_id}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="Case not found.")
    return list(get_database()["audit_log"].find({"case_id": case_id}, {"_id": 0}).sort("timestamp", -1).limit(500))


@router.get("/cases/{case_id}/audit/verify")
def verify_case_audit(case_id: str) -> dict[str, Any]:
    if not get_database()["cases"].find_one({"case_id": case_id}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="Case not found.")
    return verify_audit_chain(case_id, target_type="case")


@router.post("/emails/{email_id}/verify-evidence")
def verify_email_evidence(email_id: str) -> dict[str, Any]:
    return run(lambda: verify_evidence(email_id))


@router.get("/emails/{email_id}/privacy")
def get_privacy_view(email_id: str) -> dict[str, Any]:
    email = run(lambda: get_email(email_id))
    sender = email.get("sender") or {}

    def mask_address(value: Any) -> str:
        address = str(value or "")
        if "@" not in address:
            return "[masked]" if address else ""
        local, domain = address.rsplit("@", 1)
        return f"{local[:1]}***@{domain}"

    return {
        "email_id": email_id,
        "case_id": email.get("case_id"),
        "sender": {
            "display_name": "[masked]" if sender.get("display_name") else "",
            "address": mask_address(sender.get("address")),
            "domain": sender.get("domain"),
        },
        "recipients": [mask_address(item) for item in email.get("recipients", [])],
        "subject": "[masked]" if email.get("subject") else "",
        "message_id": "[masked]" if email.get("message_id") else "",
        "body": "[masked]" if email.get("body") else "",
        "headers": "[masked]" if email.get("headers") else "",
        "urls": "[masked]" if email.get("urls") else "",
        "ip_addresses": "[masked]" if email.get("ip_addresses") else "",
        "attachments": [
            {
                "filename": "[masked]",
                "content_type": item.get("content_type"),
                "sha256": item.get("sha256"),
            }
            for item in email.get("attachments", [])
        ],
        "retention_policy": {
            "enabled": settings.RETENTION_DAYS > 0,
            "retention_days": settings.RETENTION_DAYS,
            "expires_at": (
                email.get("created_at") + timedelta(days=settings.RETENTION_DAYS)
                if settings.RETENTION_DAYS > 0 and isinstance(email.get("created_at"), datetime)
                else None
            ),
            "description": "Evidence is retained indefinitely" if settings.RETENTION_DAYS <= 0 else f"Email evidence is automatically deleted after {settings.RETENTION_DAYS} days",
        },
        "privacy_mode": "MASKED",
    }
