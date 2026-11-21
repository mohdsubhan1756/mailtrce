from __future__ import annotations

import re


COMMON_BRANDS = {
    "microsoft",
    "office365",
    "outlook",
    "google",
    "gmail",
    "apple",
    "icloud",
    "amazon",
    "paypal",
    "linkedin",
    "facebook",
    "instagram",
    "netflix",
    "docusign",
    "dropbox",
    "adobe",
    "github",
    "bank",
    "banking",
}


CONFUSABLE_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
}


def normalize_for_similarity(value: str) -> str:
    value = (
        str(value or "")
        .lower()
        .strip()
    )

    for source, target in CONFUSABLE_MAP.items():
        value = value.replace(
            source,
            target,
        )

    value = re.sub(
        r"[^a-z0-9]",
        "",
        value,
    )

    return value


def levenshtein_distance(
    first: str,
    second: str,
) -> int:
    if first == second:
        return 0

    if not first:
        return len(second)

    if not second:
        return len(first)

    previous = list(range(len(second) + 1))

    for i, char_first in enumerate(
        first,
        start=1,
    ):
        current = [i]

        for j, char_second in enumerate(
            second,
            start=1,
        ):
            insertion = current[j - 1] + 1

            deletion = previous[j] + 1

            substitution = (
                previous[j - 1]
                + (
                    0
                    if char_first == char_second
                    else 1
                )
            )

            current.append(
                min(
                    insertion,
                    deletion,
                    substitution,
                )
            )

        previous = current

    return previous[-1]


def similarity_ratio(
    first: str,
    second: str,
) -> float:
    first = normalize_for_similarity(first)
    second = normalize_for_similarity(second)

    if not first or not second:
        return 0.0

    distance = levenshtein_distance(
        first,
        second,
    )

    maximum = max(
        len(first),
        len(second),
    )

    if maximum == 0:
        return 1.0

    return round(
        1 - (distance / maximum),
        4,
    )


def detect_brand_tokens(domain: str) -> list[str]:
    normalized = normalize_for_similarity(
        domain
    )

    found = []

    for brand in COMMON_BRANDS:
        brand_normalized = normalize_for_similarity(
            brand
        )

        if brand_normalized in normalized:
            found.append(brand)

    return sorted(set(found))


def detect_hyphenated_impersonation(
    domain: str,
) -> bool:
    normalized = str(domain or "").lower()

    if "-" not in normalized:
        return False

    parts = normalized.split(".")

    if not parts:
        return False

    host = parts[0]

    tokens = [
        token
        for token in host.split("-")
        if token
    ]

    brands = {
        brand
        for brand in COMMON_BRANDS
    }

    normalized_brands = {
        normalize_for_similarity(brand)
        for brand in brands
    }
    has_brand = any(
        normalize_for_similarity(token) in normalized_brands
        for token in tokens
    )

    suspicious_terms = {
        "login",
        "secure",
        "verify",
        "account",
        "support",
        "update",
        "auth",
        "service",
    }

    has_suspicious_term = any(
        token in suspicious_terms
        for token in tokens
    )

    return (
        has_brand
        and has_suspicious_term
    )


def detect_lookalike_domain(
    domain: str,
    trusted_domains: list[str] | None = None,
) -> dict:
    domain = (
        str(domain or "")
        .lower()
        .strip(".")
    )

    trusted_domains = trusted_domains or []

    trusted_parent_match = any(
        domain == trusted_domain
        or domain.endswith("." + trusted_domain)
        for trusted_domain in trusted_domains
        if trusted_domain
    )

    normalized_domain = normalize_for_similarity(domain)
    labels = [label for label in domain.split(".") if label]
    registrable_label = labels[-2] if len(labels) > 1 else (labels[0] if labels else "")
    candidate_labels = []
    for label in labels[:-1] if len(labels) > 1 else labels:
        candidate_labels.extend(token for token in re.split(r"[-_]", label) if token)

    brand_matches = []

    for brand in COMMON_BRANDS if not trusted_parent_match else []:
        normalized_brand = normalize_for_similarity(
            brand
        )

        if not normalized_brand:
            continue

        suspicious_candidates = []
        for candidate in candidate_labels:
            normalized_candidate = normalize_for_similarity(candidate)
            # A brand as the registered domain label is normal (google.com).
            # Brand names in subdomains, typos, or deceptive compound labels
            # remain useful impersonation signals.
            if candidate == registrable_label and candidate == brand:
                continue
            distance = levenshtein_distance(normalized_candidate, normalized_brand)
            ratio = similarity_ratio(normalized_candidate, normalized_brand)
            if (
                (normalized_candidate == normalized_brand and candidate != brand)
                or distance <= 2
                or ratio >= 0.80
            ):
                suspicious_candidates.append((distance, ratio))

        if suspicious_candidates:
            distance, ratio = min(suspicious_candidates, key=lambda item: item[0])
            brand_matches.append(
                {
                    "brand": brand,
                    "distance": distance,
                    "similarity": ratio,
                }
            )

    trusted_matches = []

    for trusted_domain in trusted_domains:
        trusted_domain = (
            str(trusted_domain or "")
            .lower()
            .strip(".")
        )

        if not trusted_domain:
            continue

        if trusted_domain == domain:
            continue

        ratio = similarity_ratio(
            domain,
            trusted_domain,
        )

        distance = levenshtein_distance(
            normalize_for_similarity(domain),
            normalize_for_similarity(trusted_domain),
        )

        if (
            ratio >= 0.75
            or distance <= 2
        ):
            trusted_matches.append(
                {
                    "trusted_domain": trusted_domain,
                    "distance": distance,
                    "similarity": ratio,
                }
            )

    hyphenated_impersonation = (
        detect_hyphenated_impersonation(
            domain
        )
    )

    brand_tokens = []
    if not trusted_parent_match:
        for brand in COMMON_BRANDS:
            if any(
                normalize_for_similarity(token) == normalize_for_similarity(brand)
                for token in candidate_labels
            ) and registrable_label not in {brand, normalize_for_similarity(brand)}:
                brand_tokens.append(brand)
    brand_tokens = sorted(set(brand_tokens))

    risk_score = 0

    if brand_matches:
        risk_score += 35

    if trusted_matches:
        risk_score += 40

    if hyphenated_impersonation:
        risk_score += 30

    if brand_tokens:
        risk_score += 10

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
        "normalized_domain": normalized_domain,
        "brand_matches": brand_matches,
        "trusted_domain_matches": trusted_matches,
        "trusted_parent_match": trusted_parent_match,
        "brand_tokens": brand_tokens,
        "hyphenated_impersonation": hyphenated_impersonation,
        "lookalike_detected": bool(
            brand_matches
            or trusted_matches
            or hyphenated_impersonation
        ),
        "risk_score": risk_score,
        "risk_level": risk_level,
    }
