from __future__ import annotations

from typing import Any

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.schemas.url_domain_intelligence_schema import (
    DomainIntelligenceResponse,
    URLDomainAnalysisResponse,
)
from app.services.url_intelligence.url_intelligence_service import (
    MODULE_VERSION,
    analyze_email_url_domain,
    get_domain_intelligence,
    get_url_domain_analysis,
    list_url_domain_analyses,
)


router = APIRouter(
    prefix="/api/v1",
    tags=["URL & Domain Intelligence"],
)


@router.post(
    "/emails/{email_id}/analyze-url-domain",
    response_model=URLDomainAnalysisResponse,
)
def analyze_url_domain_endpoint(
    email_id: str,
) -> dict[str, Any]:
    try:
        return analyze_email_url_domain(
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
                "URL and domain analysis failed: "
                f"{str(exc)}"
            ),
        ) from exc


@router.get(
    "/emails/{email_id}/url-domain-analysis",
    response_model=URLDomainAnalysisResponse,
)
def get_url_domain_endpoint(
    email_id: str,
) -> dict[str, Any]:
    result = get_url_domain_analysis(
        email_id
    )

    stored_version = ((result or {}).get("module") or {}).get("version")
    if result is not None and stored_version != MODULE_VERSION:
        result = analyze_url_domain_endpoint(email_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No URL/domain analysis found "
                f"for email '{email_id}'."
            ),
        )

    return result


@router.get(
    "/url-domain-analyses",
)
def list_url_domain_endpoint(
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
    return list_url_domain_analyses(
        limit=limit,
        skip=skip,
    )


@router.get(
    "/domains/{domain}/intelligence",
    response_model=DomainIntelligenceResponse,
)
def domain_intelligence_endpoint(
    domain: str,
) -> dict[str, Any]:
    try:
        return get_domain_intelligence(
            domain
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Domain intelligence analysis failed: "
                f"{str(exc)}"
            ),
        ) from exc
