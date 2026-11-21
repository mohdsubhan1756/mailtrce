from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from bson import ObjectId

from app.db.mongodb import get_database
from app.services.url_intelligence.dns_analyzer import (
    analyze_dns,
)
from app.services.url_intelligence.domain_analyzer import (
    analyze_domain,
)
from app.services.url_intelligence.url_parser import (
    analyze_url,
    extract_domain_from_url,
    extract_urls_from_text,
)


MODULE_VERSION = "1.1.0"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def get_email_document(
    email_id: str,
) -> dict[str, Any] | None:
    database = get_database()

    document = database["emails"].find_one(
        {"email_id": email_id}
    )

    if document:
        return document

    if ObjectId.is_valid(email_id):
        return database["emails"].find_one(
            {"_id": ObjectId(email_id)}
        )

    return None


def get_sender_domain(
    email_document: dict[str, Any],
) -> str | None:
    sender_domain = (
        email_document.get("sender_domain")
    )

    if sender_domain:
        return str(sender_domain).lower()

    sender = email_document.get(
        "sender",
        {},
    )

    if isinstance(sender, dict):
        sender_domain = sender.get(
            "domain"
        )

        if sender_domain:
            return str(
                sender_domain
            ).lower()

        address = sender.get(
            "address"
        )

        if address and "@" in address:
            return address.rsplit(
                "@",
                1,
            )[1].lower()

    from_header = (
        email_document.get(
            "headers",
            {},
        ).get("From")
    )

    if from_header and "@" in from_header:
        return from_header.rsplit(
            "@",
            1,
        )[1].strip().lower()

    return None


def get_case_id(
    email_document: dict[str, Any],
) -> str:
    return str(
        email_document.get(
            "case_id",
            "",
        )
    )


def collect_urls_from_email(
    email_document: dict[str, Any],
) -> list[str]:
    urls: set[str] = set()

    direct_url_fields = [
        email_document.get("urls"),
        email_document.get("extracted_urls"),
    ]

    for value in direct_url_fields:
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    urls.add(item)

                elif isinstance(item, dict):
                    candidate = (
                        item.get("url")
                        or item.get(
                            "original_url"
                        )
                        or item.get(
                            "normalized_url"
                        )
                    )

                    if candidate:
                        urls.add(
                            str(candidate)
                        )

    url_data = email_document.get(
        "url_analysis"
    )

    if isinstance(url_data, list):
        for item in url_data:
            if isinstance(item, str):
                urls.add(item)
            elif isinstance(item, dict):
                candidate = (
                    item.get("url")
                    or item.get(
                        "original_url"
                    )
                    or item.get(
                        "normalized_url"
                    )
                )

                if candidate:
                    urls.add(
                        str(candidate)
                    )

    extracted = email_document.get(
        "extracted"
    )

    if isinstance(extracted, dict):
        nested_urls = extracted.get(
            "urls"
        )

        if isinstance(nested_urls, list):
            for item in nested_urls:
                if isinstance(item, str):
                    urls.add(item)
                elif isinstance(item, dict):
                    candidate = (
                        item.get("url")
                        or item.get(
                            "original_url"
                        )
                        or item.get(
                            "normalized_url"
                        )
                    )

                    if candidate:
                        urls.add(
                            str(candidate)
                        )

    body = email_document.get(
        "body"
    )

    if isinstance(body, dict):
        for key in (
            "text",
            "plain",
            "html",
        ):
            value = body.get(key)

            if isinstance(value, str):
                for url in extract_urls_from_text(
                    value
                ):
                    urls.add(url)

    for key in (
        "body_text",
        "body_html",
        "text_body",
        "html_body",
    ):
        value = email_document.get(key)

        if isinstance(value, str):
            for url in extract_urls_from_text(
                value
            ):
                urls.add(url)

    return sorted(
        url
        for url in urls
        if url
    )


def collect_domains(
    email_document: dict[str, Any],
    urls: list[str],
) -> list[str]:
    domains: set[str] = set()

    direct_domain_fields = [
        email_document.get("domains"),
        email_document.get(
            "extracted_domains"
        ),
    ]

    for value in direct_domain_fields:
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    domains.add(
                        item.lower().strip(".")
                    )

                elif isinstance(item, dict):
                    candidate = (
                        item.get("domain")
                        or item.get("hostname")
                    )

                    if candidate:
                        domains.add(
                            str(candidate)
                            .lower()
                            .strip(".")
                        )

    extracted = email_document.get(
        "extracted"
    )

    if isinstance(extracted, dict):
        nested_domains = extracted.get(
            "domains"
        )

        if isinstance(nested_domains, list):
            for item in nested_domains:
                if isinstance(item, str):
                    domains.add(
                        item.lower().strip(".")
                    )

                elif isinstance(item, dict):
                    candidate = (
                        item.get("domain")
                        or item.get("hostname")
                    )

                    if candidate:
                        domains.add(
                            str(candidate)
                            .lower()
                            .strip(".")
                        )

    for url in urls:
        domain = extract_domain_from_url(
            url
        )

        if domain:
            domains.add(domain)

    return sorted(
        domain
        for domain in domains
        if domain
    )


def build_trusted_domains(
    email_document: dict[str, Any],
    sender_domain: str | None,
) -> list[str]:
    trusted = set()

    if sender_domain:
        trusted.add(
            sender_domain.lower()
        )

    headers = email_document.get(
        "headers",
        {},
    )

    if isinstance(headers, dict):
        for key in (
            "From",
            "Reply-To",
            "Return-Path",
        ):
            value = headers.get(key)

            if isinstance(value, str):
                if "@" in value:
                    domain = (
                        value.rsplit(
                            "@",
                            1,
                        )[1]
                        .strip()
                        .lower()
                        .strip("<>")
                    )

                    if domain:
                        trusted.add(domain)

    return sorted(trusted)


def build_findings(
    url_results: list[dict],
    domain_results: list[dict],
) -> list[dict]:
    findings: list[dict] = []

    for result in url_results:
        url = result.get("normalized_url") or result.get("original_url", "")

        if result.get(
            "ip_address_url"
        ):
            findings.append(
                {
                    "code": "URL_IP_ADDRESS",
                    "severity": "HIGH",
                    "category": "URL",
                    "title": "URL uses an IP address",
                    "description": (
                        "The URL points directly to an IP "
                        "address instead of a normal domain."
                    ),
                    "evidence": {
                        "url": url,
                        "hostname": result.get(
                            "hostname"
                        ),
                    },
                }
            )

        if result.get(
            "punycode_domain"
        ):
            findings.append(
                {
                    "code": "URL_PUNYCODE_DOMAIN",
                    "severity": "HIGH",
                    "category": "URL",
                    "title": "URL contains a punycode domain",
                    "description": (
                        "The URL uses an IDN/punycode hostname, "
                        "which can be abused for lookalike domains."
                    ),
                    "evidence": {
                        "url": url,
                        "hostname": result.get(
                            "hostname"
                        ),
                    },
                }
            )

        if result.get(
            "url_shortener"
        ):
            findings.append(
                {
                    "code": "URL_SHORTENER",
                    "severity": "MEDIUM",
                    "category": "URL",
                    "title": "URL uses a shortening service",
                    "description": (
                        "The URL uses a known URL shortening "
                        "service, hiding the final destination."
                    ),
                    "evidence": {
                        "url": url,
                        "hostname": result.get(
                            "hostname"
                        ),
                    },
                }
            )

        if result.get(
            "suspicious_port"
        ):
            findings.append(
                {
                    "code": "SUSPICIOUS_URL_PORT",
                    "severity": "MEDIUM",
                    "category": "URL",
                    "title": "URL uses a non-standard port",
                    "description": (
                        "The URL uses a port other than "
                        "the standard HTTP or HTTPS ports."
                    ),
                    "evidence": {
                        "url": url,
                        "port": result.get(
                            "port"
                        ),
                    },
                }
            )

        if result.get(
            "username_present"
        ) or result.get(
            "password_present"
        ):
            findings.append(
                {
                    "code": "URL_CREDENTIAL_COMPONENT",
                    "severity": "HIGH",
                    "category": "URL",
                    "title": "URL contains credential-like user information",
                    "description": (
                        "The URL contains a username or password "
                        "component before the hostname."
                    ),
                    "evidence": {
                        "url": url,
                        "username_present": result.get(
                            "username_present"
                        ),
                        "password_present": result.get(
                            "password_present"
                        ),
                    },
                }
            )

        if result.get(
            "suspicious_keywords"
        ):
            findings.append(
                {
                    "code": "SUSPICIOUS_URL_KEYWORDS",
                    "severity": "MEDIUM",
                    "category": "URL",
                    "title": "URL contains suspicious keywords",
                    "description": (
                        "The URL contains terms commonly associated "
                        "with account verification, login, payment, "
                        "or credential harvesting."
                    ),
                    "evidence": {
                        "url": url,
                        "keywords": result.get(
                            "suspicious_keywords"
                        ),
                    },
                }
            )

        if result.get(
            "suspicious_query_parameters"
        ) or (
            result.get(
                "query_analysis",
                {},
            ).get(
                "suspicious_names"
            )
        ):
            findings.append(
                {
                    "code": "SUSPICIOUS_QUERY_PARAMETERS",
                    "severity": "MEDIUM",
                    "category": "URL",
                    "title": "URL contains redirect or authentication parameters",
                    "description": (
                        "The URL contains query parameters that can "
                        "be used for redirects, authentication, "
                        "sessions, or destination hiding."
                    ),
                    "evidence": {
                        "url": url,
                        "query_analysis": result.get(
                            "query_analysis",
                            {},
                        ),
                    },
                }
            )

        if result.get(
            "domain_matches_sender"
        ) is False and result.get(
            "sender_domain"
        ):
            findings.append(
                {
                    "code": "URL_DOMAIN_SENDER_MISMATCH",
                    "severity": "LOW",
                    "category": "DOMAIN",
                    "title": "URL domain differs from sender domain",
                    "description": (
                        "The destination domain is different from "
                        "the sender's domain."
                    ),
                    "evidence": {
                        "url": url,
                        "url_hostname": result.get(
                            "hostname"
                        ),
                        "sender_domain": result.get(
                            "sender_domain"
                        ),
                    },
                }
            )

    for result in domain_results:
        domain = result.get(
            "domain"
        )

        if result.get(
            "lookalike",
            {},
        ).get(
            "lookalike_detected"
        ):
            findings.append(
                {
                    "code": "LOOKALIKE_DOMAIN",
                    "severity": "HIGH",
                    "category": "DOMAIN",
                    "title": "Potential lookalike or impersonation domain",
                    "description": (
                        "The domain resembles a known brand "
                        "or trusted domain and may be used "
                        "for impersonation."
                    ),
                    "evidence": {
                        "domain": domain,
                        "lookalike": result.get(
                            "lookalike"
                        ),
                    },
                }
            )

        if result.get(
            "punycode"
        ):
            findings.append(
                {
                    "code": "PUNYCODE_DOMAIN",
                    "severity": "HIGH",
                    "category": "DOMAIN",
                    "title": "Punycode domain detected",
                    "description": (
                        "The domain contains an IDN/punycode "
                        "label that requires additional scrutiny."
                    ),
                    "evidence": {
                        "domain": domain,
                    },
                }
            )

        if result.get(
            "numeric_heavy"
        ):
            findings.append(
                {
                    "code": "NUMERIC_HEAVY_DOMAIN",
                    "severity": "MEDIUM",
                    "category": "DOMAIN",
                    "title": "Numeric-heavy domain detected",
                    "description": (
                        "The domain contains an unusually high "
                        "proportion of numeric characters."
                    ),
                    "evidence": {
                        "domain": domain,
                        "digit_count": result.get(
                            "digit_count"
                        ),
                    },
                }
            )

        if result.get(
            "excessive_subdomains"
        ):
            findings.append(
                {
                    "code": "EXCESSIVE_SUBDOMAINS",
                    "severity": "MEDIUM",
                    "category": "DOMAIN",
                    "title": "Excessive subdomain depth detected",
                    "description": (
                        "The domain contains a large number "
                        "of hierarchical labels."
                    ),
                    "evidence": {
                        "domain": domain,
                        "label_count": result.get(
                            "label_count"
                        ),
                    },
                }
            )

        if result.get(
            "suspicious_keywords"
        ):
            findings.append(
                {
                    "code": "SUSPICIOUS_DOMAIN_KEYWORDS",
                    "severity": "MEDIUM",
                    "category": "DOMAIN",
                    "title": "Suspicious keywords found in domain",
                    "description": (
                        "The domain contains keywords commonly "
                        "associated with authentication, support, "
                        "payment, or account activity."
                    ),
                    "evidence": {
                        "domain": domain,
                        "keywords": result.get(
                            "suspicious_keywords"
                        ),
                    },
                }
            )

        if (
            result.get(
                "sender_domain"
            )
            and not result.get(
                "sender_domain_match"
            )
        ):
            findings.append(
                {
                    "code": "DOMAIN_SENDER_MISMATCH",
                    "severity": "LOW",
                    "category": "DOMAIN",
                    "title": "Domain differs from sender domain",
                    "description": (
                        "The analyzed destination domain does not "
                        "match the sender domain."
                    ),
                    "evidence": {
                        "domain": domain,
                        "sender_domain": result.get(
                            "sender_domain"
                        ),
                    },
                }
            )

    return collapse_sender_domain_findings(findings)


def collapse_sender_domain_findings(
    findings: list[dict],
) -> list[dict]:
    """Combine URL-level and domain-level copies of sender mismatch findings."""
    mismatch_codes = {
        "URL_DOMAIN_SENDER_MISMATCH",
        "DOMAIN_SENDER_MISMATCH",
    }
    mismatches = [
        finding for finding in findings
        if finding.get("code") in mismatch_codes
    ]
    if not mismatches:
        return findings

    remaining = [
        finding for finding in findings
        if finding.get("code") not in mismatch_codes
    ]
    sender_domain = None
    domains = set()
    urls = set()
    for finding in mismatches:
        evidence = finding.get("evidence") or {}
        sender_domain = sender_domain or evidence.get("sender_domain")
        domain = evidence.get("domain") or evidence.get("url_hostname")
        if domain:
            domains.add(str(domain).lower())
        if evidence.get("url"):
            urls.add(str(evidence["url"]))

    domain_list = sorted(domains)
    destination_count = len(domain_list) or len(mismatches)
    remaining.append({
        "code": "DOMAIN_SENDER_MISMATCH",
        "severity": "LOW",
        "category": "DOMAIN",
        "title": "Destination domain differs from sender domain",
        "description": (
            f"{destination_count} destination domain"
            f"{'s' if destination_count != 1 else ''} differ from the sender domain."
        ),
        "evidence": {
            "sender_domain": sender_domain,
            "domains": domain_list,
            "urls": sorted(urls),
        },
    })
    return remaining


def calculate_overall_risk(
    url_results: list[dict],
    domain_results: list[dict],
    findings: list[dict],
) -> dict:
    url_scores = [
        int(
            result.get(
                "risk_score",
                0,
            )
        )
        for result in url_results
    ]

    domain_scores = [
        int(
            result.get(
                "risk_score",
                0,
            )
        )
        for result in domain_results
    ]

    maximum_score = max(
        url_scores + domain_scores + [0]
    )

    average_components = (
        url_scores + domain_scores
    )

    average_score = (
        round(
            sum(average_components)
            / len(average_components)
        )
        if average_components
        else 0
    )

    high_count = sum(
        1
        for finding in findings
        if finding.get("severity")
        == "HIGH"
    )

    medium_count = sum(
        1
        for finding in findings
        if finding.get("severity")
        == "MEDIUM"
    )

    low_count = sum(
        1
        for finding in findings
        if finding.get("severity")
        == "LOW"
    )

    score = max(
        maximum_score,
        average_score,
    )

    score += min(
        20,
        high_count * 10,
    )

    score += min(
        10,
        medium_count * 2,
    )

    score = min(
        100,
        score,
    )

    if score >= 70:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    elif score >= 15:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    if score >= 70:
        verdict = "MALICIOUS_OR_HIGHLY_SUSPICIOUS"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    elif score >= 15:
        verdict = "LOW_RISK"
    else:
        verdict = "NO_SIGNIFICANT_URL_DOMAIN_RISK"

    return {
        "score": score,
        "risk_level": risk_level,
        "verdict": verdict,
        "maximum_component_score": maximum_score,
        "average_component_score": average_score,
        "high_finding_count": high_count,
        "medium_finding_count": medium_count,
        "low_finding_count": low_count,
    }


def build_document(
    email_document: dict[str, Any],
    urls: list[str],
    url_results: list[dict],
    domain_results: list[dict],
    dns_results: list[dict],
    findings: list[dict],
    risk_summary: dict,
) -> dict:
    now = utc_now()

    email_id = str(
        email_document.get(
            "email_id"
        )
    )

    case_id = get_case_id(
        email_document
    )

    sender_domain = get_sender_domain(
        email_document
    )

    return {
        "email_id": email_id,
        "case_id": case_id,
        "module": {
            "name": "url_domain_intelligence",
            "version": MODULE_VERSION,
        },
        "analyzed_at": now,
        "sender_domain": sender_domain,
        "url_count": len(urls),
        "domain_count": len(domain_results),
        "urls": url_results,
        "domains": domain_results,
        "dns": dns_results,
        "findings": findings,
        "risk": risk_summary,
        "high_severity_count": risk_summary.get(
            "high_finding_count",
            0,
        ),
        "medium_severity_count": risk_summary.get(
            "medium_finding_count",
            0,
        ),
        "low_severity_count": risk_summary.get(
            "low_finding_count",
            0,
        ),
        "status": "COMPLETED",
        "created_at": now,
        "updated_at": now,
    }


def update_email_module_status(
    email_id: str,
    risk_summary: dict,
) -> None:
    database = get_database()

    database["emails"].update_one(
        {"email_id": email_id},
        {
            "$set": {
                "module.url_domain_intelligence": {
                    "status": "COMPLETED",
                    "risk_score": risk_summary.get(
                        "score",
                        0,
                    ),
                    "risk_level": risk_summary.get(
                        "risk_level",
                        "MINIMAL",
                    ),
                    "verdict": risk_summary.get(
                        "verdict"
                    ),
                    "updated_at": utc_now(),
                }
            }
        },
    )


def analyze_email_url_domain(
    email_id: str,
) -> dict[str, Any]:
    email_document = get_email_document(
        email_id
    )

    if not email_document:
        raise ValueError(
            f"Email '{email_id}' was not found."
        )

    sender_domain = get_sender_domain(
        email_document
    )

    trusted_domains = build_trusted_domains(
        email_document,
        sender_domain,
    )

    urls = collect_urls_from_email(
        email_document
    )

    url_results = []

    for url in urls:
        result = analyze_url(
            url,
            sender_domain=sender_domain,
        )

        url_results.append(result)

    domains = collect_domains(
        email_document,
        urls,
    )

    domain_results = []

    dns_results = []

    for domain in domains:
        domain_result = analyze_domain(
            domain,
            sender_domain=sender_domain,
            trusted_domains=trusted_domains,
        )

        domain_results.append(
            domain_result
        )

        dns_result = analyze_dns(
            domain
        )

        dns_results.append(
            dns_result
        )

    findings = build_findings(
        url_results,
        domain_results,
    )

    risk_summary = calculate_overall_risk(
        url_results,
        domain_results,
        findings,
    )

    document = build_document(
        email_document,
        urls,
        url_results,
        domain_results,
        dns_results,
        findings,
        risk_summary,
    )

    database = get_database()

    database[
        "url_domain_intelligence"
    ].replace_one(
        {
            "email_id": str(
                email_document.get(
                    "email_id"
                )
            )
        },
        document,
        upsert=True,
    )

    update_email_module_status(
        str(
            email_document.get(
                "email_id"
            )
        ),
        risk_summary,
    )

    return document


def get_url_domain_analysis(
    email_id: str,
) -> dict[str, Any] | None:
    database = get_database()

    document = database[
        "url_domain_intelligence"
    ].find_one(
        {"email_id": email_id},
        {"_id": 0},
    )
    return normalize_stored_findings(document)


def normalize_stored_findings(
    document: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Normalize older stored reports as well as newly generated reports."""
    if not document:
        return document
    findings = collapse_sender_domain_findings(
        document.get("findings") or []
    )
    document["findings"] = findings
    counts = {
        severity.lower(): sum(
            finding.get("severity") == severity
            for finding in findings
        )
        for severity in ("HIGH", "MEDIUM", "LOW")
    }
    document["high_severity_count"] = counts["high"]
    document["medium_severity_count"] = counts["medium"]
    document["low_severity_count"] = counts["low"]
    if isinstance(document.get("risk"), dict):
        document["risk"].update({
            "high_finding_count": counts["high"],
            "medium_finding_count": counts["medium"],
            "low_finding_count": counts["low"],
        })
    return document


def list_url_domain_analyses(
    limit: int = 50,
    skip: int = 0,
) -> list[dict[str, Any]]:
    database = get_database()

    cursor = (
        database[
            "url_domain_intelligence"
        ]
        .find(
            {},
            {"_id": 0},
        )
        .sort(
            "analyzed_at",
            -1,
        )
        .skip(skip)
        .limit(limit)
    )

    return [
        normalize_stored_findings(document)
        for document in cursor
    ]


def get_domain_intelligence(
    domain: str,
) -> dict[str, Any]:
    normalized = (
        str(domain or "")
        .lower()
        .strip(".")
    )

    if not normalized:
        raise ValueError(
            "Domain cannot be empty."
        )

    analysis = analyze_domain(
        normalized
    )

    dns = analyze_dns(
        normalized
    )

    return {
        "domain": normalized,
        "domain_analysis": analysis,
        "dns": dns,
        "analyzed_at": utc_now(),
    }
