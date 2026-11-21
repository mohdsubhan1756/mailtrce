from typing import Any

from pydantic import BaseModel, Field


class AuthenticationFinding(BaseModel):
    code: str
    severity: str
    category: str
    title: str
    description: str
    evidence: dict[str, Any] = Field(
        default_factory=dict
    )


class AuthenticationAnalysisResponse(BaseModel):
    email_id: str
    case_id: str
    analyzed_at: Any

    sender_domain: str | None = None

    sender_ip: str | None = None

    spf: dict[str, Any] = Field(
        default_factory=dict
    )

    dkim: dict[str, Any] = Field(
        default_factory=dict
    )

    dmarc: dict[str, Any] = Field(
        default_factory=dict
    )

    authentication_results: list[
        dict[str, Any]
    ] = Field(
        default_factory=list
    )

    overall_result: str

    findings: list[
        AuthenticationFinding
    ] = Field(
        default_factory=list
    )

    risk_indicator_count: int = 0

    high_severity_count: int = 0

    medium_severity_count: int = 0

    low_severity_count: int = 0

    status: str