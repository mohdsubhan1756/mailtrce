import re
from typing import Any


EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)

MESSAGE_ID_PATTERN = re.compile(
    r"^<([^@\s<>]+)@([^<>\s]+)>$"
)


def normalize_email(value: str | None) -> str | None:
    if not value:
        return None

    value = value.strip().lower()

    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1]

    return value


def parse_address(
    value: Any,
) -> dict[str, Any] | None:
    if value is None:
        return None

    if isinstance(value, dict):
        address = value.get("address")
        display_name = value.get("display_name")

    else:
        address = str(value).strip()
        display_name = None

    if not address:
        return None

    normalized = normalize_email(address)

    if not normalized:
        return None

    if "@" in normalized:
        local_part, domain = normalized.rsplit("@", 1)
    else:
        local_part = normalized
        domain = None

    domain_parts = []

    if domain:
        domain_parts = domain.split(".")

    return {
        "display_name": display_name,
        "address": normalized,
        "domain": domain,
        "local_part": local_part,
        "domain_parts": domain_parts,
    }


def analyze_message_id(
    message_id: str | None,
) -> dict[str, Any]:
    if not message_id:
        return {
            "value": None,
            "present": False,
            "valid_format": False,
            "domain": None,
            "local_part": None,
        }

    value = message_id.strip()

    match = MESSAGE_ID_PATTERN.match(value)

    if not match:
        return {
            "value": value,
            "present": True,
            "valid_format": False,
            "domain": None,
            "local_part": None,
        }

    return {
        "value": value,
        "present": True,
        "valid_format": True,
        "domain": match.group(2).lower(),
        "local_part": match.group(1),
    }


def same_domain(
    first: dict[str, Any] | None,
    second: dict[str, Any] | None,
) -> bool:
    if not first or not second:
        return True

    first_domain = first.get("domain")
    second_domain = second.get("domain")

    if not first_domain or not second_domain:
        return True

    return (
        first_domain.lower()
        == second_domain.lower()
    )


def add_finding(
    findings: list[dict[str, Any]],
    *,
    code: str,
    severity: str,
    category: str,
    title: str,
    description: str,
    evidence: dict[str, Any] | None = None,
) -> None:
    findings.append(
        {
            "code": code,
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "evidence": evidence or {},
        }
    )


def analyze_headers(
    *,
    sender: dict[str, Any] | None,
    reply_to: dict[str, Any] | None,
    return_path: str | None,
    sender_header: dict[str, Any] | None,
    message_id: str | None,
    routing_analysis: dict[str, Any],
) -> dict[str, Any]:

    findings: list[dict[str, Any]] = []

    from_analysis = parse_address(sender)

    reply_to_analysis = parse_address(reply_to)

    return_path_analysis = parse_address(
        return_path
    )

    sender_analysis = parse_address(
        sender_header
    )

    message_id_analysis = analyze_message_id(
        message_id
    )

    # ---------------------------------------------------------
    # FROM HEADER
    # ---------------------------------------------------------

    if not from_analysis:
        add_finding(
            findings,
            code="MISSING_FROM",
            severity="HIGH",
            category="HEADER",
            title="Missing From address",
            description=(
                "The email does not contain a usable From address."
            ),
        )

    elif not EMAIL_PATTERN.match(
        from_analysis["address"]
    ):
        add_finding(
            findings,
            code="INVALID_FROM",
            severity="HIGH",
            category="HEADER",
            title="Invalid From address",
            description=(
                "The From header does not appear to contain "
                "a valid email address."
            ),
            evidence={
                "from": from_analysis["address"]
            },
        )

    # ---------------------------------------------------------
    # REPLY-TO
    # ---------------------------------------------------------

    from_reply_to_match = same_domain(
        from_analysis,
        reply_to_analysis,
    )

    if reply_to_analysis:
        if not from_reply_to_match:
            add_finding(
                findings,
                code="REPLY_TO_MISMATCH",
                severity="HIGH",
                category="SPOOFING",
                title="Reply-To domain mismatch",
                description=(
                    "The Reply-To domain differs from the "
                    "From domain. This can be a phishing or "
                    "business email compromise indicator."
                ),
                evidence={
                    "from_domain": (
                        from_analysis.get("domain")
                        if from_analysis
                        else None
                    ),
                    "reply_to_domain": (
                        reply_to_analysis.get("domain")
                    ),
                },
            )

    # ---------------------------------------------------------
    # RETURN-PATH
    # ---------------------------------------------------------

    from_return_path_match = same_domain(
        from_analysis,
        return_path_analysis,
    )

    if return_path_analysis:
        if not from_return_path_match:
            add_finding(
                findings,
                code="RETURN_PATH_MISMATCH",
                severity="MEDIUM",
                category="SPOOFING",
                title="Return-Path domain mismatch",
                description=(
                    "The Return-Path domain differs from the "
                    "From domain."
                ),
                evidence={
                    "from_domain": (
                        from_analysis.get("domain")
                        if from_analysis
                        else None
                    ),
                    "return_path_domain": (
                        return_path_analysis.get("domain")
                    ),
                },
            )

    # ---------------------------------------------------------
    # SENDER
    # ---------------------------------------------------------

    sender_from_match = same_domain(
        from_analysis,
        sender_analysis,
    )

    if sender_analysis and not sender_from_match:
        add_finding(
            findings,
            code="SENDER_FROM_MISMATCH",
            severity="MEDIUM",
            category="SPOOFING",
            title="Sender and From domain mismatch",
            description=(
                "The Sender domain differs from the From domain."
            ),
            evidence={
                "from_domain": (
                    from_analysis.get("domain")
                    if from_analysis
                    else None
                ),
                "sender_domain": (
                    sender_analysis.get("domain")
                ),
            },
        )

    # ---------------------------------------------------------
    # MESSAGE ID
    # ---------------------------------------------------------

    if not message_id_analysis["present"]:
        add_finding(
            findings,
            code="MISSING_MESSAGE_ID",
            severity="LOW",
            category="HEADER",
            title="Missing Message-ID",
            description=(
                "The email does not contain a Message-ID header."
            ),
        )

    elif not message_id_analysis["valid_format"]:
        add_finding(
            findings,
            code="INVALID_MESSAGE_ID",
            severity="MEDIUM",
            category="HEADER",
            title="Malformed Message-ID",
            description=(
                "The Message-ID does not follow the expected "
                "angle-bracket and domain format."
            ),
            evidence={
                "message_id": message_id
            },
        )

    # ---------------------------------------------------------
    # MESSAGE-ID DOMAIN
    # ---------------------------------------------------------

    message_id_domain_match: bool | None = None

    if (
        from_analysis
        and message_id_analysis["domain"]
    ):
        message_id_domain_match = (
            from_analysis["domain"].lower()
            == message_id_analysis["domain"].lower()
        )

        if not message_id_domain_match:
            add_finding(
                findings,
                code="MESSAGE_ID_DOMAIN_MISMATCH",
                severity="LOW",
                category="SPOOFING",
                title="Message-ID domain differs from From",
                description=(
                    "The Message-ID domain differs from the "
                    "From domain. This is not inherently malicious, "
                    "but it is useful forensic evidence."
                ),
                evidence={
                    "from_domain": from_analysis["domain"],
                    "message_id_domain": (
                        message_id_analysis["domain"]
                    ),
                },
            )

    # ---------------------------------------------------------
    # ROUTING
    # ---------------------------------------------------------

    hop_count = routing_analysis.get(
        "hop_count",
        0,
    )

    if hop_count == 0:
        add_finding(
            findings,
            code="MISSING_RECEIVED_CHAIN",
            severity="HIGH",
            category="ROUTING",
            title="No Received headers",
            description=(
                "No Received headers were available for "
                "routing reconstruction."
            ),
        )

    if hop_count == 1:
        add_finding(
            findings,
            code="SINGLE_RECEIVED_HOP",
            severity="LOW",
            category="ROUTING",
            title="Single Received hop",
            description=(
                "Only one Received header is available. "
                "This limits routing reconstruction."
            ),
        )

    # ---------------------------------------------------------
    # CHRONOLOGY
    # ---------------------------------------------------------

    if not routing_analysis.get(
        "chronology_valid",
        True,
    ):
        add_finding(
            findings,
            code="ROUTING_CHRONOLOGY_ANOMALY",
            severity="HIGH",
            category="ROUTING",
            title="Received timestamp anomaly",
            description=(
                "The Received header timestamps do not follow "
                "the expected chronological order."
            ),
            evidence={
                "issues": routing_analysis.get(
                    "chronology_issues",
                    [],
                )
            },
        )

    # ---------------------------------------------------------
    # PRIVATE IP
    # ---------------------------------------------------------

    private_ip_count = 0

    for hop in routing_analysis.get("hops", []):
        private_ip_count += len(
            hop.get("private_ips", [])
        )

    if private_ip_count:
        add_finding(
            findings,
            code="PRIVATE_ROUTING_IP",
            severity="LOW",
            category="ROUTING",
            title="Private or reserved IP in routing chain",
            description=(
                "One or more private, loopback, link-local, "
                "reserved, or otherwise non-public IP addresses "
                "appear in the Received chain."
            ),
            evidence={
                "count": private_ip_count
            },
        )

    # ---------------------------------------------------------
    # DUPLICATE HOPS
    # ---------------------------------------------------------

    duplicate_hops = routing_analysis.get(
        "duplicate_hops",
        [],
    )

    if duplicate_hops:
        add_finding(
            findings,
            code="DUPLICATE_ROUTING_HOP",
            severity="MEDIUM",
            category="ROUTING",
            title="Duplicate routing hop",
            description=(
                "Similar Received hops appear more than once "
                "in the routing chain."
            ),
            evidence={
                "positions": duplicate_hops
            },
        )

    # ---------------------------------------------------------
    # POSSIBLE LOOP
    # ---------------------------------------------------------

    if routing_analysis.get(
        "possible_loop",
        False,
    ):
        add_finding(
            findings,
            code="POSSIBLE_MAIL_LOOP",
            severity="HIGH",
            category="ROUTING",
            title="Possible mail routing loop",
            description=(
                "The routing chain contains a repeated host "
                "pattern that may indicate a mail loop."
            ),
        )

    # ---------------------------------------------------------
    # HOSTNAME ANOMALIES
    # ---------------------------------------------------------

    suspicious_host_tokens = [
        "localhost",
        "unknown",
        "invalid",
        "test",
        "example",
    ]

    suspicious_hosts: list[str] = []

    for host in routing_analysis.get(
        "unique_hosts",
        [],
    ):
        host_lower = host.lower()

        for token in suspicious_host_tokens:
            if token in host_lower:
                suspicious_hosts.append(host)
                break

    if suspicious_hosts:
        add_finding(
            findings,
            code="SUSPICIOUS_ROUTING_HOST",
            severity="LOW",
            category="ROUTING",
            title="Suspicious routing hostname",
            description=(
                "One or more routing hostnames contain tokens "
                "commonly associated with test, invalid, or "
                "non-production systems."
            ),
            evidence={
                "hosts": suspicious_hosts
            },
        )

    return {
        "from_analysis": from_analysis,
        "reply_to_analysis": reply_to_analysis,
        "return_path_analysis": return_path_analysis,
        "sender_analysis": sender_analysis,
        "message_id_analysis": message_id_analysis,
        "findings": findings,
        "consistency_analysis": {
            "from_reply_to_match": from_reply_to_match,
            "from_return_path_match": from_return_path_match,
            "sender_from_match": sender_from_match,
            "message_id_domain_match": message_id_domain_match,
            "reply_to_present": reply_to_analysis is not None,
            "return_path_present": (
                return_path_analysis is not None
            ),
            "sender_present": sender_analysis is not None,
        },
    }