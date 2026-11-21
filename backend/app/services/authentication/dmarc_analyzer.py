from typing import Any

from app.services.authentication.dns_resolver import (
    query_txt,
)

try:
    from publicsuffix2 import get_sld
except ImportError:
    get_sld = None


COMMON_SECOND_LEVEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "co.nz",
    "com.br",
    "com.cn",
    "com.sg",
}


def normalize_domain(
    domain: str | None,
) -> str | None:

    if not domain:
        return None

    return (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )


def parse_dmarc_record(
    record: str | None,
) -> dict[str, Any]:

    result = {
        "present": False,
        "valid": False,
        "version": None,
        "policy": None,
        "subdomain_policy": None,
        "percentage": 100,
        "rua": [],
        "ruf": [],
        "adkim": "r",
        "aspf": "r",
        "fo": [],
        "rf": [],
        "ri": None,
        "tags": {},
        "raw": record,
    }

    if not record:
        return result

    tokens = record.split(";")

    tags: dict[str, str] = {}

    for token in tokens:

        token = token.strip()

        if not token or "=" not in token:
            continue

        key, value = token.split(
            "=",
            1,
        )

        tags[
            key.strip().lower()
        ] = value.strip()

    result["tags"] = tags

    version = tags.get("v")

    if version:
        result["version"] = version

    if version != "DMARC1":
        return result

    result["present"] = True

    policy = tags.get("p")

    if policy in (
        "none",
        "quarantine",
        "reject",
    ):
        result["policy"] = policy

    subdomain_policy = tags.get("sp")

    if subdomain_policy in (
        "none",
        "quarantine",
        "reject",
    ):
        result["subdomain_policy"] = (
            subdomain_policy
        )

    try:
        percentage = int(
            tags.get("pct", "100")
        )

        if 0 <= percentage <= 100:
            result["percentage"] = percentage

    except ValueError:
        pass

    result["adkim"] = tags.get(
        "adkim",
        "r",
    )

    result["aspf"] = tags.get(
        "aspf",
        "r",
    )

    if tags.get("rua"):
        result["rua"] = [
            item.strip()
            for item in tags["rua"].split(",")
            if item.strip()
        ]

    if tags.get("ruf"):
        result["ruf"] = [
            item.strip()
            for item in tags["ruf"].split(",")
            if item.strip()
        ]

    if tags.get("fo"):
        result["fo"] = [
            item.strip()
            for item in tags["fo"].split(":")
            if item.strip()
        ]

    if tags.get("rf"):
        result["rf"] = [
            item.strip()
            for item in tags["rf"].split(":")
            if item.strip()
        ]

    result["ri"] = tags.get("ri")

    result["valid"] = (
        result["policy"] is not None
    )

    return result


def query_dmarc_record(
    domain: str,
) -> str | None:

    domain = normalize_domain(
        domain
    )

    if not domain:
        return None

    dmarc_domain = (
        f"_dmarc.{domain}"
    )

    records = query_txt(
        dmarc_domain
    )

    for record in records:

        if record.lower().startswith(
            "v=dmarc1"
        ):
            return record

    return None


def get_organizational_domain(
    domain: str | None,
) -> str | None:

    domain = normalize_domain(
        domain
    )

    if not domain:
        return None

    if get_sld is not None:
        organizational = get_sld(domain)
        if organizational:
            return normalize_domain(organizational)

    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    suffix = ".".join(parts[-2:])
    if suffix in COMMON_SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix


def domains_aligned(
    *,
    header_domain: str | None,
    authenticated_domain: str | None,
    alignment_mode: str,
) -> bool:

    header_domain = normalize_domain(
        header_domain
    )

    authenticated_domain = normalize_domain(
        authenticated_domain
    )

    if not header_domain or not authenticated_domain:
        return False

    if alignment_mode == "s":
        return (
            header_domain
            == authenticated_domain
        )

    return (
        get_organizational_domain(
            header_domain
        )
        ==
        get_organizational_domain(
            authenticated_domain
        )
    )


def analyze_dmarc(
    *,
    from_domain: str | None,
    spf_result: str,
    spf_domain: str | None,
    dkim_results: list[dict[str, Any]],
) -> dict[str, Any]:

    from_domain = normalize_domain(
        from_domain
    )

    record = query_dmarc_record(from_domain) if from_domain else None
    policy_domain = from_domain
    if record is None and from_domain:
        organizational_domain = get_organizational_domain(from_domain)
        if organizational_domain != from_domain:
            record = query_dmarc_record(organizational_domain)
            policy_domain = organizational_domain

    parsed = parse_dmarc_record(
        record
    )

    if not parsed["present"]:
        return {
            "domain": from_domain,
            "policy_domain": policy_domain,
            "record_found": False,
            "record": parsed,
            "spf_alignment": False,
            "dkim_alignment": False,
            "spf_aligned_pass": False,
            "dkim_aligned_pass": False,
            "result": "none",
        }

    spf_alignment = domains_aligned(
        header_domain=from_domain,
        authenticated_domain=spf_domain,
        alignment_mode=parsed[
            "aspf"
        ],
    )

    spf_aligned_pass = (
        spf_result == "pass"
        and spf_alignment
    )

    dkim_aligned_pass = False

    dkim_alignment_details = []

    for dkim in dkim_results:

        dkim_domain = dkim.get(
            "domain"
        )

        dkim_pass = (
            dkim.get("result") == "pass"
        )

        aligned = domains_aligned(
            header_domain=from_domain,
            authenticated_domain=dkim_domain,
            alignment_mode=parsed[
                "adkim"
            ],
        )

        dkim_alignment_details.append(
            {
                "domain": dkim_domain,
                "pass": dkim_pass,
                "aligned": aligned,
            }
        )

        if dkim_pass and aligned:
            dkim_aligned_pass = True

    dmarc_pass = (
        spf_aligned_pass
        or dkim_aligned_pass
    )

    return {
        "domain": from_domain,
        "policy_domain": policy_domain,
        "record_found": True,
        "record": parsed,
        "spf_alignment": spf_alignment,
        "dkim_alignment": dkim_aligned_pass,
        "spf_aligned_pass": spf_aligned_pass,
        "dkim_aligned_pass": dkim_aligned_pass,
        "dkim_alignment_details": (
            dkim_alignment_details
        ),
        "result": (
            "pass"
            if dmarc_pass
            else "fail"
        ),
    }