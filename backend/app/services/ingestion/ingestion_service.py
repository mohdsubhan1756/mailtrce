# backend/app/services/ingestion/ingestion_service.py

import hashlib
import logging
import re
import uuid
from pathlib import Path

from pymongo.errors import DuplicateKeyError

from app.core.config import settings
from app.db.mongodb import get_database
from app.services.extended_analysis import write_audit

from app.models.email_document import (
    build_email_document
)

from app.services.ingestion.eml_parser import (
    parse_eml
)

from app.services.ingestion.extractor import (
    extract_email_data
)

from app.services.ingestion.normalizer import (
    normalize_email_data
)


logger = logging.getLogger(__name__)


FILENAME_REGEX = re.compile(
    r"[^a-zA-Z0-9._-]"
)


def generate_email_id() -> str:

    return (
        "EMAIL-"
        + uuid.uuid4().hex[:12].upper()
    )


def generate_case_id() -> str:

    return (
        "CASE-"
        + uuid.uuid4().hex[:12].upper()
    )


def calculate_sha256(
    data: bytes
) -> str:

    return hashlib.sha256(
        data
    ).hexdigest()


def sanitize_filename(
    filename: str
) -> str:

    filename = Path(
        filename
    ).name

    filename = FILENAME_REGEX.sub(
        "_",
        filename
    )

    if not filename:

        filename = "uploaded_email.eml"

    return filename


def validate_eml_file(
    filename: str,
    data: bytes
) -> None:

    if not filename:

        raise ValueError(
            "Filename is required."
        )

    extension = (
        Path(filename)
        .suffix
        .lower()
    )

    if extension not in (
        settings.ALLOWED_EXTENSIONS
    ):

        raise ValueError(
            "Only .eml files are supported."
        )

    if not data:

        raise ValueError(
            "Uploaded file is empty."
        )

    if len(data) > (
        settings.MAX_EMAIL_SIZE_BYTES
    ):

        raise ValueError(
            f"Email exceeds the maximum "
            f"allowed size of "
            f"{settings.MAX_EMAIL_SIZE_MB} MB."
        )


def save_original_evidence(
    email_id: str,
    filename: str,
    raw_email: bytes
) -> str:

    evidence_root = Path(
        settings.EVIDENCE_DIRECTORY
    )

    email_directory = (
        evidence_root
        / "emails"
        / email_id
    )

    email_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    safe_filename = sanitize_filename(
        filename
    )

    evidence_path = (
        email_directory
        / safe_filename
    )

    evidence_path.write_bytes(
        raw_email
    )

    return str(
        evidence_path
    )


def ingest_email(
    filename: str,
    raw_email: bytes,
    case_id: str | None = None
) -> dict:

    # --------------------------------------------------
    # 1. Validate
    # --------------------------------------------------

    validate_eml_file(
        filename,
        raw_email
    )

    # --------------------------------------------------
    # 2. Generate identifiers
    # --------------------------------------------------

    email_id = generate_email_id()

    if not case_id:

        case_id = generate_case_id()

    # --------------------------------------------------
    # 3. SHA-256
    # --------------------------------------------------

    sha256 = calculate_sha256(
        raw_email
    )

    # --------------------------------------------------
    # 4. Parse EML
    # --------------------------------------------------

    try:

        message = parse_eml(
            raw_email
        )

    except Exception as exc:

        raise ValueError(
            f"Unable to parse EML file: {exc}"
        ) from exc

    # --------------------------------------------------
    # 5. Extract
    # --------------------------------------------------

    extracted = extract_email_data(
        message
    )

    # --------------------------------------------------
    # 6. Normalize
    # --------------------------------------------------

    normalized = normalize_email_data(
        extracted
    )

    # --------------------------------------------------
    # 7. Save original evidence locally
    # --------------------------------------------------

    safe_filename = sanitize_filename(
        filename
    )

    evidence_path = (
        save_original_evidence(
            email_id=email_id,
            filename=safe_filename,
            raw_email=raw_email
        )
    )

    # --------------------------------------------------
    # 8. MongoDB document
    # --------------------------------------------------

    document = build_email_document(
        email_id=email_id,
        case_id=case_id,
        filename=safe_filename,
        original_size=len(raw_email),
        sha256=sha256,
        evidence_path=evidence_path,
        normalized_email=normalized
    )

    # --------------------------------------------------
    # 9. MongoDB
    # --------------------------------------------------

    database = get_database()

    try:

        database["emails"].insert_one(
            document
        )

    except DuplicateKeyError as exc:

        raise RuntimeError(
            "Email identifier collision occurred."
        ) from exc

    try:
        write_audit(email_id, "EMAIL_INGESTED", {"case_id": case_id, "sha256": sha256, "size": len(raw_email)})
    except Exception:
        logger.exception("Could not write ingestion audit event for %s", email_id)

    # --------------------------------------------------
    # 10. Return
    # --------------------------------------------------

    return {

        "success": True,

        "email_id": email_id,

        "case_id": case_id,

        "filename": safe_filename,

        "sha256": sha256,

        "status": "INGESTED",

        "message": (
            "Email successfully ingested "
            "and normalized."
        )
    }


def get_email(
    email_id: str
) -> dict | None:

    database = get_database()

    return database[
        "emails"
    ].find_one(
        {
            "email_id": email_id
        }
    )


def list_emails(
    limit: int = 50,
    skip: int = 0,
    case_id: str | None = None,
) -> list[dict]:

    database = get_database()

    cursor = (
        database["emails"]
        .find(
            {"case_id": case_id} if case_id else {},
            {
                "_id": 0,
                "email_id": 1,
                "case_id": 1,
                "filename": 1,
                "sha256": 1,
                "sender": 1,
                "recipients": 1,
                "subject": 1,
                "timestamp": 1,
                "message_id": 1,
                "status": 1,
                "module": 1,
                "created_at": 1
            }
        )
        .sort(
            "created_at",
            -1
        )
        .skip(skip)
        .limit(limit)
    )

    return list(cursor)


def get_raw_email(
    email_id: str
) -> bytes:

    email_document = get_email(
        email_id
    )

    if not email_document:

        raise LookupError(
            "Email not found."
        )

    evidence_path = (
        email_document
        .get("evidence", {})
        .get("local_path")
    )

    if not evidence_path:

        raise RuntimeError(
            "Evidence path is missing."
        )

    path = Path(
        evidence_path
    )

    if not path.exists():

        raise FileNotFoundError(
            "Original evidence file does not exist."
        )

    return path.read_bytes()
