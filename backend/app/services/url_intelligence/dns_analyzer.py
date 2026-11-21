from __future__ import annotations

from app.services.authentication.dns_resolver import (
    query_a,
    query_aaaa,
    query_cname,
    query_mx,
    query_txt,
)


def resolve_a(domain: str) -> list[str]:
    return query_a(domain)


def resolve_aaaa(domain: str) -> list[str]:
    return query_aaaa(domain)


def resolve_mx(domain: str) -> list[dict]:
    return query_mx(domain)


def resolve_cname(domain: str) -> list[str]:
    return query_cname(domain)


def resolve_txt(domain: str) -> list[str]:
    return query_txt(domain)


def analyze_dns(domain: str) -> dict:
    domain = (
        str(domain or "")
        .strip()
        .lower()
        .rstrip(".")
    )

    if not domain:
        return {
            "domain": "",
            "resolved": False,
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "cname_records": [],
            "txt_records": [],
            "record_count": 0,
            "dns_status": "INVALID_DOMAIN",
        }

    a_records = resolve_a(domain)
    aaaa_records = resolve_aaaa(domain)
    mx_records = resolve_mx(domain)
    cname_records = resolve_cname(domain)
    txt_records = resolve_txt(domain)

    record_count = (
        len(a_records)
        + len(aaaa_records)
        + len(mx_records)
        + len(cname_records)
        + len(txt_records)
    )

    resolved = bool(
        a_records
        or aaaa_records
        or mx_records
        or cname_records
        or txt_records
    )

    if a_records or aaaa_records:
        dns_status = "RESOLVED"
    elif mx_records or cname_records:
        dns_status = "PARTIAL"
    else:
        dns_status = "NO_RESOLUTION"

    return {
        "domain": domain,
        "resolved": resolved,
        "a_records": a_records,
        "aaaa_records": aaaa_records,
        "mx_records": mx_records,
        "cname_records": cname_records,
        "txt_records": txt_records,
        "record_count": record_count,
        "dns_status": dns_status,
    }
