from datetime import datetime
from typing import Any


def _unique(values: list[str]) -> list[str]:
    result: list[str] = []

    for value in values:
        if value and value not in result:
            result.append(value)

    return result


def analyze_routing(
    received_headers: list[str],
) -> dict[str, Any]:
    from app.services.header_forensics.received_parser import (
        parse_received_chain,
    )

    hops = parse_received_chain(received_headers)

    unique_ips: list[str] = []
    unique_hosts: list[str] = []

    for hop in hops:
        for ip in hop.get("private_ips", []):
            unique_ips.append(ip)

        for ip in hop.get("public_ips", []):
            unique_ips.append(ip)

        if hop.get("from_host"):
            unique_hosts.append(hop["from_host"])

        if hop.get("by_host"):
            unique_hosts.append(hop["by_host"])

    unique_ips = _unique(unique_ips)
    unique_hosts = _unique(unique_hosts)

    chronology_valid = True
    chronology_issues: list[str] = []

    parsed_hops: list[tuple[int, datetime]] = []

    for hop in hops:
        timestamp = hop.get("timestamp")

        if timestamp is not None:
            parsed_hops.append(
                (
                    hop["position"],
                    timestamp,
                )
            )

    # A Received header chain is usually newest first.
    # Therefore, timestamps should normally move backwards
    # as we move down the list.
    for index in range(len(parsed_hops) - 1):
        current_position, current_time = parsed_hops[index]
        next_position, next_time = parsed_hops[index + 1]

        if current_time < next_time:
            chronology_valid = False

            chronology_issues.append(
                (
                    f"Hop {current_position} has an earlier timestamp "
                    f"than hop {next_position}."
                )
            )

    duplicate_hops: list[int] = []

    seen_signatures: dict[str, int] = {}

    for hop in hops:
        signature = "|".join(
            [
                str(hop.get("from_host") or ""),
                str(hop.get("from_ip") or ""),
                str(hop.get("by_host") or ""),
                str(hop.get("by_ip") or ""),
                str(hop.get("with_value") or ""),
            ]
        )

        if signature and signature != "||||":
            if signature in seen_signatures:
                duplicate_hops.append(
                    hop["position"]
                )
            else:
                seen_signatures[signature] = hop["position"]

    possible_loop = False

    if len(unique_hosts) >= 2:
        host_sequence = []

        for hop in hops:
            if hop.get("by_host"):
                host_sequence.append(
                    hop["by_host"].lower()
                )

        for index in range(len(host_sequence) - 2):
            if (
                host_sequence[index]
                == host_sequence[index + 2]
            ):
                possible_loop = True
                break

    return {
        "hop_count": len(hops),
        "hops": hops,
        "unique_ips": unique_ips,
        "unique_hosts": unique_hosts,
        "chronology_valid": chronology_valid,
        "chronology_issues": chronology_issues,
        "duplicate_hops": duplicate_hops,
        "possible_loop": possible_loop,
    }