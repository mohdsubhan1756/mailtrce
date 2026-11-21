from __future__ import annotations

import re

from app.services.url_intelligence.lookalike_detector import (
    detect_lookalike_domain,
)
from app.services.url_intelligence.url_parser import (
    get_domain_parts,
)


SUSPICIOUS_DOMAIN_KEYWORDS = {
    "login",
    "signin",
    "secure",
    "security",
    "verify",
    "verification",
    "account",
    "update",
    "support",
    "helpdesk",
    "service",
    "auth",
    "authentication",
    "password",
    "wallet",
    "payment",
    "billing",
    "invoice",
    "bank",
    "banking",
}


def analyze_domain(
    domain: str,
    sender_domain: str | None = None,
    trusted_domains: list[str] | None = None,
) -> dict:
    domain = (
        str(domain or "")
        .lower()
        .strip(".")
    )

    sender_domain = (
        str(sender_domain or "")
        .lower()
        .strip(".")
    )

    parts = get_domain_parts(domain)

    labels = parts["labels"]

    suspicious_keywords = []

    for keyword in SUSPICIOUS_DOMAIN_KEYWORDS:
        if keyword in domain:
            suspicious_keywords.append(
                keyword
            )

    digit_count = sum(
        char.isdigit()
        for char in domain
    )

    hyphen_count = domain.count("-")

    underscore_present = "_" in domain

    excessive_subdomains = (
        len(labels) >= 5
    )

    long_domain = len(domain) > 60

    very_long_domain = len(domain) > 100

    numeric_heavy = (
        len(domain) > 0
        and (
            digit_count / len(domain)
        ) >= 0.30
    )

    punycode = any(
        label.startswith("xn--")
        for label in labels
    )

    sender_domain_match = False

    if sender_domain and domain:
        sender_domain_match = (
            domain == sender_domain
            or domain.endswith(
                "." + sender_domain
            )
            or sender_domain.endswith(
                "." + domain
            )
        )

    lookalike = detect_lookalike_domain(
        domain,
        trusted_domains=trusted_domains,
    )

    indicators = []

    if suspicious_keywords:
        indicators.append(
            "SUSPICIOUS_DOMAIN_KEYWORDS"
        )

    if hyphen_count >= 2:
        indicators.append(
            "MULTIPLE_HYPHENS"
        )

    if underscore_present:
        indicators.append(
            "UNDERSCORE_IN_DOMAIN"
        )

    if excessive_subdomains:
        indicators.append(
            "EXCESSIVE_SUBDOMAINS"
        )

    if long_domain:
        indicators.append(
            "LONG_DOMAIN"
        )

    if very_long_domain:
        indicators.append(
            "VERY_LONG_DOMAIN"
        )

    if numeric_heavy:
        indicators.append(
            "NUMERIC_HEAVY_DOMAIN"
        )

    if punycode:
        indicators.append(
            "PUNYCODE_DOMAIN"
        )

    if lookalike["lookalike_detected"]:
        indicators.append(
            "LOOKALIKE_DOMAIN"
        )

    if (
        sender_domain
        and not sender_domain_match
    ):
        indicators.append(
            "URL_DOMAIN_DIFFERS_FROM_SENDER"
        )

    risk_score = 0

    if suspicious_keywords:
        risk_score += min(
            25,
            len(suspicious_keywords) * 5,
        )

    if hyphen_count >= 2:
        risk_score += 10

    if underscore_present:
        risk_score += 10

    if excessive_subdomains:
        risk_score += 15

    if long_domain:
        risk_score += 5

    if very_long_domain:
        risk_score += 5

    if numeric_heavy:
        risk_score += 15

    if punycode:
        risk_score += 25

    if lookalike["lookalike_detected"]:
        risk_score += lookalike[
            "risk_score"
        ]

    risk_score = min(
        100,
        risk_score,
    )

    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    elif risk_score >= 15:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    return {
        "domain": domain,
        "base_domain": parts["base_domain"],
        "tld": parts["tld"],
        "labels": labels,
        "label_count": parts["label_count"],
        "domain_length": len(domain),
        "digit_count": digit_count,
        "hyphen_count": hyphen_count,
        "underscore_present": underscore_present,
        "numeric_heavy": numeric_heavy,
        "punycode": punycode,
        "long_domain": long_domain,
        "very_long_domain": very_long_domain,
        "excessive_subdomains": excessive_subdomains,
        "suspicious_keywords": sorted(
            set(suspicious_keywords)
        ),
        "sender_domain": sender_domain,
        "sender_domain_match": sender_domain_match,
        "lookalike": lookalike,
        "indicators": indicators,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }
