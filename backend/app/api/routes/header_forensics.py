from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.schemas.header_forensics_schema import (
    HeaderAnalysisResult,
)
from app.services.header_forensics.header_forensics_service import (
    analyze_email_headers,
    get_header_analysis,
    list_header_analyses,
)


router = APIRouter(
    prefix="/api/v1",
    tags=["Header Forensics"],
)


@router.post(
    "/emails/{email_id}/analyze-headers",
    response_model=HeaderAnalysisResult,
)
def analyze_headers_endpoint(
    email_id: str,
) -> dict[str, Any]:

    try:
        result = analyze_email_headers(
            email_id
        )

        return result

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Header analysis failed: "
                f"{str(exc)}"
            ),
        ) from exc


@router.get(
    "/emails/{email_id}/header-analysis",
)
def get_header_analysis_endpoint(
    email_id: str,
) -> dict[str, Any]:

    result = get_header_analysis(
        email_id
    )

    if result is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No header analysis found for "
                f"email '{email_id}'."
            ),
        )

    return result


@router.get(
    "/header-analyses",
)
def list_header_analysis_endpoint(
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
    skip: int = Query(
        default=0,
        ge=0,
    ),
) -> list[dict[str, Any]]:

    return list_header_analyses(
        limit=limit,
        skip=skip,
    )