from typing import Any

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.schemas.authentication_schema import (
    AuthenticationAnalysisResponse,
)

from app.services.authentication.authentication_service import (
    AUTHENTICATION_ANALYSIS_VERSION,
    analyze_email_authentication,
    get_authentication_analysis,
    list_authentication_analyses,
)


router = APIRouter(
    prefix="/api/v1",
    tags=[
        "Authentication Analysis"
    ],
)


@router.post(
    "/emails/{email_id}/analyze-authentication",
    response_model=AuthenticationAnalysisResponse,
)
def analyze_authentication_endpoint(
    email_id: str,
) -> dict[str, Any]:

    try:

        return analyze_email_authentication(
            email_id
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Authentication analysis failed: "
                f"{str(exc)}"
            ),
        ) from exc


@router.get(
    "/emails/{email_id}/authentication-analysis",
)
def get_authentication_endpoint(
    email_id: str,
) -> dict[str, Any]:

    result = get_authentication_analysis(email_id)

    if result is not None and result.get("analysis_version") != AUTHENTICATION_ANALYSIS_VERSION:
        result = analyze_email_authentication(email_id)

    if result is None:

        raise HTTPException(
            status_code=404,
            detail=(
                "No authentication analysis "
                f"found for email '{email_id}'."
            ),
        )

    return result


@router.get(
    "/authentication-analyses",
)
def list_authentication_endpoint(
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

    return list_authentication_analyses(
        limit=limit,
        skip=skip,
    )
