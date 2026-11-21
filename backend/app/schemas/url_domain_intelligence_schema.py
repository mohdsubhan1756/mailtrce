from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class URLFinding(BaseModel):
    code: str
    severity: str
    category: str
    title: str
    description: str
    evidence: dict[str, Any] = Field(
        default_factory=dict
    )


class URLDomainRisk(BaseModel):
    score: int = 0
    risk_level: str = "MINIMAL"
    verdict: str = (
        "NO_SIGNIFICANT_URL_DOMAIN_RISK"
    )
    maximum_component_score: int = 0
    average_component_score: int = 0
    high_finding_count: int = 0
    medium_finding_count: int = 0
    low_finding_count: int = 0


class URLDomainAnalysisResponse(BaseModel):
    email_id: str
    case_id: str
    analyzed_at: Any
    sender_domain: str | None = None
    url_count: int = 0
    domain_count: int = 0
    urls: list[dict[str, Any]] = Field(
        default_factory=list
    )
    domains: list[dict[str, Any]] = Field(
        default_factory=list
    )
    dns: list[dict[str, Any]] = Field(
        default_factory=list
    )
    findings: list[URLFinding] = Field(
        default_factory=list
    )
    risk: URLDomainRisk
    high_severity_count: int = 0
    medium_severity_count: int = 0
    low_severity_count: int = 0
    status: str


class DomainIntelligenceResponse(BaseModel):
    domain: str
    domain_analysis: dict[str, Any] = Field(
        default_factory=dict
    )
    dns: dict[str, Any] = Field(
        default_factory=dict
    )
    analyzed_at: Any