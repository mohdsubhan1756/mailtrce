from datetime import datetime, timezone
from typing import Any

from bson import ObjectId

from app.db.mongodb import get_database
from app.models.header_forensics_document import (
    build_header_forensics_document,
)
from app.services.header_forensics.header_analyzer import (
    analyze_headers,
)
from app.services.header_forensics.routing_analyzer import (
    analyze_routing,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def serialize_mongo_document(
    document: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if document is None:
        return None

    result = dict(document)

    if "_id" in result:
        result["_id"] = str(result["_id"])

    return result


def get_email_for_analysis(
    email_id: str,
) -> dict[str, Any] | None:
    db = get_database()

    return db["emails"].find_one(
        {"email_id": email_id}
    )


def build_analysis(
    email_document: dict[str, Any],
) -> dict[str, Any]:

    email_id = email_document["email_id"]
    case_id = email_document["case_id"]

    received_headers = email_document.get(
        "received_headers",
        [],
    )

    routing_analysis = analyze_routing(
        received_headers
    )

    header_analysis = analyze_headers(
        sender=email_document.get("sender"),
        reply_to=email_document.get("reply_to"),
        return_path=email_document.get("return_path"),
        sender_header=email_document.get("sender_header"),
        message_id=email_document.get("message_id"),
        routing_analysis=routing_analysis,
    )

    findings = header_analysis.get(
        "findings",
        [],
    )

    high_count = sum(
        1
        for finding in findings
        if finding.get("severity") == "HIGH"
    )

    medium_count = sum(
        1
        for finding in findings
        if finding.get("severity") == "MEDIUM"
    )

    low_count = sum(
        1
        for finding in findings
        if finding.get("severity") == "LOW"
    )

    return {
        "email_id": email_id,
        "case_id": case_id,
        "analyzed_at": utc_now(),

        "from_analysis": header_analysis.get(
            "from_analysis"
        ),

        "reply_to_analysis": header_analysis.get(
            "reply_to_analysis"
        ),

        "return_path_analysis": header_analysis.get(
            "return_path_analysis"
        ),

        "sender_analysis": header_analysis.get(
            "sender_analysis"
        ),

        "message_id_analysis": header_analysis.get(
            "message_id_analysis"
        ),

        "routing_analysis": routing_analysis,

        "consistency_analysis": header_analysis.get(
            "consistency_analysis"
        ),

        "findings": findings,

        "risk_indicator_count": len(findings),

        "high_severity_count": high_count,

        "medium_severity_count": medium_count,

        "low_severity_count": low_count,

        "status": "ANALYZED",
    }


def analyze_email_headers(
    email_id: str,
) -> dict[str, Any]:

    email_document = get_email_for_analysis(
        email_id
    )

    if email_document is None:
        raise ValueError(
            f"Email '{email_id}' was not found."
        )

    analysis = build_analysis(
        email_document
    )

    document = build_header_forensics_document(
        email_id=email_document["email_id"],
        case_id=email_document["case_id"],
        analysis=analysis,
    )

    db = get_database()

    db["header_forensics"].replace_one(
        {"email_id": email_id},
        document,
        upsert=True,
    )

    # Update the original email with module status.
    db["emails"].update_one(
        {"email_id": email_id},
        {
            "$set": {
                "module.header_forensics": {
                    "status": "ANALYZED",
                    "analyzed_at": analysis[
                        "analyzed_at"
                    ],
                    "risk_indicator_count": (
                        analysis[
                            "risk_indicator_count"
                        ]
                    ),
                },
                "updated_at": utc_now(),
            }
        },
    )

    return document


def get_header_analysis(
    email_id: str,
) -> dict[str, Any] | None:

    db = get_database()

    document = db["header_forensics"].find_one(
        {"email_id": email_id}
    )

    return serialize_mongo_document(document)


def list_header_analyses(
    *,
    limit: int = 50,
    skip: int = 0,
) -> list[dict[str, Any]]:

    db = get_database()

    documents = (
        db["header_forensics"]
        .find({})
        .sort("analyzed_at", -1)
        .skip(skip)
        .limit(limit)
    )

    return [
        serialize_mongo_document(document)
        for document in documents
    ]