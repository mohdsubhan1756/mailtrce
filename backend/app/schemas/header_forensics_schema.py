from typing import Any

from pydantic import BaseModel, Field


class HeaderFinding(BaseModel):
    code: str
    severity: str
    category: str
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class HeaderAddressAnalysis(BaseModel):
    display_name: str | None = None
    address: str | None = None
    domain: str | None = None
    local_part: str | None = None
    domain_parts: list[str] = Field(default_factory=list)


class MessageIdAnalysis(BaseModel):
    value: str | None = None
    present: bool = False
    valid_format: bool = False
    domain: str | None = None
    local_part: str | None = None


class ReceivedHop(BaseModel):
    position: int
    raw: str
    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    by_ip: str | None = None
    protocol: str | None = None
    with_value: str | None = None
    id_value: str | None = None
    for_value: str | None = None
    timestamp_raw: str | None = None
    timestamp: Any = None
    parsed_timestamp: bool = False
    private_ips: list[str] = Field(default_factory=list)
    public_ips: list[str] = Field(default_factory=list)


class RoutingAnalysis(BaseModel):
    hop_count: int = 0
    hops: list[ReceivedHop] = Field(default_factory=list)
    unique_ips: list[str] = Field(default_factory=list)
    unique_hosts: list[str] = Field(default_factory=list)
    chronology_valid: bool = True
    chronology_issues: list[str] = Field(default_factory=list)
    duplicate_hops: list[int] = Field(default_factory=list)
    possible_loop: bool = False


class HeaderConsistencyAnalysis(BaseModel):
    from_reply_to_match: bool = True
    from_return_path_match: bool = True
    sender_from_match: bool = True
    message_id_domain_match: bool | None = None
    reply_to_present: bool = False
    return_path_present: bool = False
    sender_present: bool = False


class HeaderAnalysisResult(BaseModel):
    email_id: str
    case_id: str
    analyzed_at: Any

    from_analysis: HeaderAddressAnalysis | None = None
    reply_to_analysis: HeaderAddressAnalysis | None = None
    return_path_analysis: HeaderAddressAnalysis | None = None
    sender_analysis: HeaderAddressAnalysis | None = None

    message_id_analysis: MessageIdAnalysis = Field(
        default_factory=MessageIdAnalysis
    )

    routing_analysis: RoutingAnalysis = Field(
        default_factory=RoutingAnalysis
    )

    consistency_analysis: HeaderConsistencyAnalysis = Field(
        default_factory=HeaderConsistencyAnalysis
    )

    findings: list[HeaderFinding] = Field(default_factory=list)

    risk_indicator_count: int = 0
    high_severity_count: int = 0
    medium_severity_count: int = 0
    low_severity_count: int = 0

    status: str = "ANALYZED"