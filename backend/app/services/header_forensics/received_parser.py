import ipaddress
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any


IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

IPV6_PATTERN = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}"
    r"[0-9a-fA-F]{0,4}\b"
)


FROM_PATTERN = re.compile(
    r"\bfrom\s+([^\s]+)",
    re.IGNORECASE,
)

BY_PATTERN = re.compile(
    r"\bby\s+([^\s]+)",
    re.IGNORECASE,
)

WITH_PATTERN = re.compile(
    r"\bwith\s+([^\s;]+)",
    re.IGNORECASE,
)

ID_PATTERN = re.compile(
    r"\bid\s+([^\s;]+)",
    re.IGNORECASE,
)

FOR_PATTERN = re.compile(
    r"\bfor\s+<?([^>;,\s]+@[^>;,\s]+)>?",
    re.IGNORECASE,
)


def clean_host(value: str | None) -> str | None:
    if not value:
        return None

    value = value.strip()

    value = value.strip("[]")

    value = value.rstrip(";,:")

    return value or None


def extract_ips(value: str) -> list[str]:
    if not value:
        return []

    found: list[str] = []

    for match in IPV4_PATTERN.findall(value):
        try:
            ipaddress.ip_address(match)
            found.append(match)
        except ValueError:
            pass

    for match in IPV6_PATTERN.findall(value):
        candidate = match.rstrip(":")
        try:
            ipaddress.ip_address(candidate)
            found.append(candidate)
        except ValueError:
            pass

    unique: list[str] = []

    for ip in found:
        if ip not in unique:
            unique.append(ip)

    return unique


def classify_ips(ips: list[str]) -> tuple[list[str], list[str]]:
    private_ips: list[str] = []
    public_ips: list[str] = []

    for value in ips:
        try:
            ip_obj = ipaddress.ip_address(value)

            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                private_ips.append(value)
            else:
                public_ips.append(value)

        except ValueError:
            continue

    return private_ips, public_ips


def extract_timestamp(raw_header: str) -> str | None:
    if not raw_header:
        return None

    # Received headers normally contain a semicolon before the timestamp.
    if ";" in raw_header:
        timestamp_part = raw_header.rsplit(";", 1)[1].strip()
    else:
        timestamp_part = raw_header.strip()

    return timestamp_part or None


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None


def parse_received_header(
    raw_header: str,
    position: int,
) -> dict[str, Any]:
    raw_header = raw_header.strip()

    from_match = FROM_PATTERN.search(raw_header)
    by_match = BY_PATTERN.search(raw_header)
    with_match = WITH_PATTERN.search(raw_header)
    id_match = ID_PATTERN.search(raw_header)
    for_match = FOR_PATTERN.search(raw_header)

    from_host = (
        clean_host(from_match.group(1))
        if from_match
        else None
    )

    by_host = (
        clean_host(by_match.group(1))
        if by_match
        else None
    )

    with_value = (
        with_match.group(1).strip()
        if with_match
        else None
    )

    id_value = (
        id_match.group(1).strip()
        if id_match
        else None
    )

    for_value = (
        for_match.group(1).strip()
        if for_match
        else None
    )

    ips = extract_ips(raw_header)

    from_ip = None
    by_ip = None

    if from_match:
        from_ips = extract_ips(from_match.group(1))
        if from_ips:
            from_ip = from_ips[0]

    if by_match:
        by_ips = extract_ips(by_match.group(1))
        if by_ips:
            by_ip = by_ips[0]

    if from_ip is None and ips:
        from_ip = ips[0]

    private_ips, public_ips = classify_ips(ips)

    timestamp_raw = extract_timestamp(raw_header)
    timestamp = parse_timestamp(timestamp_raw)

    return {
        "position": position,
        "raw": raw_header,
        "from_host": from_host,
        "from_ip": from_ip,
        "by_host": by_host,
        "by_ip": by_ip,
        "protocol": None,
        "with_value": with_value,
        "id_value": id_value,
        "for_value": for_value,
        "timestamp_raw": timestamp_raw,
        "timestamp": timestamp,
        "parsed_timestamp": timestamp is not None,
        "private_ips": private_ips,
        "public_ips": public_ips,
    }


def parse_received_chain(
    received_headers: list[str],
) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []

    for index, header in enumerate(received_headers):
        if not header:
            continue

        hop = parse_received_header(
            raw_header=header,
            position=index + 1,
        )

        hops.append(hop)

    return hops