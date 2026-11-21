# backend/app/api/routes/ingestion.py

import logging

from fastapi import (
    APIRouter,
    File,
    HTTPException,
    Query,
    UploadFile
)

from fastapi.responses import Response
from starlette import status

from app.schemas.email_schema import (
    EmailSummaryResponse,
    IngestionResponse
)
from app.core.config import settings
from app.db.mongodb import get_database

from app.services.ingestion.ingestion_service import (
    get_email,
    get_raw_email,
    ingest_email,
    list_emails
)


logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/api/v1/emails",
    tags=["Email Ingestion"]
)


@router.post(
    "/ingest",
    response_model=IngestionResponse
)
async def ingest_email_endpoint(
    file: UploadFile = File(...),
    case_id: str | None = Query(
        default=None
    )
):

    filename = file.filename or ""

    raw_email = await file.read(settings.MAX_EMAIL_SIZE_BYTES + 1)
    if len(raw_email) > settings.MAX_EMAIL_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Email exceeds the maximum allowed size of {settings.MAX_EMAIL_SIZE_MB} MB.",
        )

    if case_id and not (
        get_database()["cases"].find_one({"case_id": case_id}, {"_id": 1})
        or get_database()["emails"].find_one({"case_id": case_id}, {"_id": 1})
    ):
        raise HTTPException(status_code=404, detail="Case not found.")

    try:

        result = ingest_email(
            filename=filename,
            raw_email=raw_email,
            case_id=case_id
        )

        return result

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    except Exception:

        logger.exception("Email ingestion failed")

        raise HTTPException(
            status_code=500,
            detail="Email ingestion failed. Check the backend logs for details."
        )


@router.get(
    "/",
    response_model=list[EmailSummaryResponse]
)
def list_emails_endpoint(
    limit: int = Query(
        default=50,
        ge=1,
        le=100
    ),
    skip: int = Query(
        default=0,
        ge=0
    ),
    case_id: str | None = Query(default=None, min_length=1, max_length=128),
):

    return list_emails(
        limit=limit,
        skip=skip,
        case_id=case_id,
    )


@router.get(
    "/{email_id}",
    response_model=dict
)
def get_email_endpoint(
    email_id: str
):

    document = get_email(
        email_id
    )

    if not document:

        raise HTTPException(
            status_code=404,
            detail="Email not found."
        )

    document.pop(
        "_id",
        None
    )

    return document


@router.get(
    "/{email_id}/raw"
)
def get_raw_email_endpoint(
    email_id: str
):

    try:

        raw_email = get_raw_email(
            email_id
        )

        return Response(
            content=raw_email,
            media_type="message/rfc822"
        )

    except LookupError as exc:

        raise HTTPException(
            status_code=404,
            detail=str(exc)
        )

    except FileNotFoundError as exc:

        raise HTTPException(
            status_code=404,
            detail=str(exc)
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )
