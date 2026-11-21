from __future__ import annotations

from pymongo import MongoClient
from pymongo.database import Database

from app.core.config import settings


_client: MongoClient | None = None


def connect_to_mongodb() -> None:
    global _client

    if _client is not None:
        return

    _client = MongoClient(
        settings.MONGODB_URI,
        serverSelectionTimeoutMS=5000,
    )

    _client.admin.command("ping")

    database = _client[
        settings.MONGODB_DATABASE
    ]

    create_indexes(database)


def close_mongodb_connection() -> None:
    global _client

    if _client is not None:
        _client.close()
        _client = None


def get_database() -> Database:
    global _client

    if _client is None:
        connect_to_mongodb()

    return _client[
        settings.MONGODB_DATABASE
    ]


def _deduplicate_collection(
    database: Database,
    collection_name: str,
    key: str,
) -> None:
    collection = database[collection_name]
    duplicates = list(
        collection.aggregate(
            [
                {
                    "$group": {
                        "_id": f"${key}",
                        "ids": {"$push": "$_id"},
                        "count": {"$sum": 1},
                    }
                },
                {"$match": {"count": {"$gt": 1}}},
            ]
        )
    )

    for duplicate in duplicates:
        document_ids = duplicate["ids"]
        if not document_ids:
            continue

        keep_document = (
            collection.find({"_id": {"$in": document_ids}})
            .sort([
                ("updated_at", -1),
                ("created_at", -1),
                ("_id", -1),
            ])
            .limit(1)
            .next()
        )

        if keep_document is None:
            continue

        collection.delete_many(
            {"_id": {"$in": [doc_id for doc_id in document_ids if doc_id != keep_document["_id"]]}}
        )


def create_indexes(
    database: Database,
) -> None:
    for collection_name, key in (
        ("emails", "email_id"),
        ("header_forensics", "email_id"),
        ("authentication_analysis", "email_id"),
        ("url_domain_intelligence", "email_id"),
        ("threat_analysis", "email_id"),
        ("attachment_analysis", "email_id"),
        ("ip_intelligence", "email_id"),
        ("threat_intelligence", "email_id"),
        ("risk_analysis", "email_id"),
        ("analyst_feedback", "email_id"),
        ("cases", "case_id"),
    ):
        _deduplicate_collection(database, collection_name, key)

    emails = database["emails"]

    emails.create_index(
        "email_id",
        unique=True,
    )

    emails.create_index(
        "case_id"
    )

    emails.create_index(
        "message_id"
    )

    emails.create_index(
        "sender_domain"
    )

    emails.create_index(
        "sha256"
    )

    emails.create_index(
        "created_at"
    )

    header_forensics = database[
        "header_forensics"
    ]

    header_forensics.create_index(
        "email_id",
        unique=True,
    )

    header_forensics.create_index(
        "case_id"
    )

    authentication = database[
        "authentication_analysis"
    ]

    authentication.create_index(
        "email_id",
        unique=True,
    )

    authentication.create_index(
        "case_id"
    )

    authentication.create_index(
        "overall_result"
    )

    url_domain = database[
        "url_domain_intelligence"
    ]

    url_domain.create_index(
        "email_id",
        unique=True,
    )

    url_domain.create_index(
        "case_id"
    )

    url_domain.create_index(
        "sender_domain"
    )

    url_domain.create_index(
        "risk.score"
    )

    url_domain.create_index(
        "risk.risk_level"
    )

    url_domain.create_index(
        "domains.domain"
    )

    url_domain.create_index(
        "urls.hostname"
    )

    url_domain.create_index(
        "analyzed_at"
    )

    for collection in (
        "threat_analysis",
        "attachment_analysis",
        "ip_intelligence",
        "threat_intelligence",
        "risk_analysis",
    ):
        database[collection].create_index(
            "email_id",
            unique=True,
        )

    database["audit_log"].create_index(
        [("email_id", 1), ("timestamp", -1)]
    )

    database["alerts"].create_index(
        [("created_at", -1)]
    )

    database["cases"].create_index(
        "case_id",
        unique=True,
    )

    database["analyst_feedback"].create_index(
        "email_id",
        unique=True,
    )
