import ipaddress
import re
from typing import Any

from app.services.authentication.dns_resolver import (
    query_a,
    query_aaaa,
    query_mx,
    query_ptr,
    query_txt,
)


SPF_PREFIX = "v=spf1"

MAX_DNS_LOOKUPS = 10


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


def extract_spf_record(
    domain: str,
) -> str | None:

    domain = normalize_domain(domain)

    if not domain:
        return None

    records = query_txt(domain)

    spf_records = [
        record.strip()
        for record in records
        if record.lower().startswith(
            SPF_PREFIX
        )
    ]

    if not spf_records:
        return None

    return spf_records[0]


def parse_spf_record(
    record: str | None,
) -> dict[str, Any]:

    result = {
        "present": False,
        "version": None,
        "mechanisms": [],
        "qualifier": None,
        "all_policy": None,
        "redirect": None,
        "exp": None,
        "raw": record,
    }

    if not record:
        return result

    tokens = record.split()

    if not tokens:
        return result

    if tokens[0].lower() != SPF_PREFIX:
        return result

    result["present"] = True
    result["version"] = "spf1"

    mechanisms = []

    for token in tokens[1:]:
        if "=" in token:
            key, value = token.split(
                "=",
                1,
            )

            if key.lower() == "redirect":
                result["redirect"] = value

            elif key.lower() == "exp":
                result["exp"] = value

            else:
                mechanisms.append(
                    {
                        "token": token,
                        "type": key.lower(),
                        "value": value,
                    }
                )

            continue

        qualifier = "+"

        if token[0] in (
            "+",
            "-",
            "~",
            "?",
        ):
            qualifier = token[0]
            token_body = token[1:]
        else:
            token_body = token

        match = re.match(
            r"^([a-zA-Z0-9]+)"
            r"(?:[:/](.*))?$",
            token_body,
        )

        if match:
            mechanism_type = (
                match.group(1).lower()
            )

            mechanism_value = (
                match.group(2)
            )

            mechanisms.append(
                {
                    "token": token,
                    "type": mechanism_type,
                    "value": mechanism_value,
                    "qualifier": qualifier,
                }
            )

            if mechanism_type == "all":
                result["all_policy"] = qualifier

    result["mechanisms"] = mechanisms

    return result


def _qualifier_result(
    qualifier: str,
) -> str:

    mapping = {
        "+": "pass",
        "-": "fail",
        "~": "softfail",
        "?": "neutral",
    }

    return mapping.get(
        qualifier,
        "neutral",
    )


def ip_matches_network(
    ip: str,
    network: str,
) -> bool:

    try:
        return ipaddress.ip_address(
            ip
        ) in ipaddress.ip_network(
            network,
            strict=False,
        )
    except ValueError:
        return False


def evaluate_spf_record(
    *,
    record: str | None,
    sender_ip: str | None,
    sender_domain: str | None,
) -> dict[str, Any]:

    parsed = parse_spf_record(record)

    result = {
        "result": "none",
        "matched_mechanism": None,
        "matched_qualifier": None,
        "lookup_count": 0,
        "evaluated_domain": sender_domain,
        "record": parsed,
    }

    if not parsed["present"]:
        return result

    if not sender_ip:
        result["result"] = "none"
        return result

    state = {"lookup_count": 0}
    visited: set[str] = set()

    def consume_lookup() -> bool:
        state["lookup_count"] += 1
        return state["lookup_count"] <= MAX_DNS_LOOKUPS

    def address_matches(hostname: str, address: str, cidr: str | None = None) -> bool:
        networks = [cidr] if cidr else None
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            return False
        if networks is None:
            networks = [str(parsed_address.max_prefixlen)]
        for prefix in networks:
            try:
                network = ipaddress.ip_network(
                    f"{parsed_address}/{prefix}",
                    strict=False,
                )
            except ValueError:
                return False
            if ip_matches_network(address, str(network)):
                return True
        return False

    def host_addresses(hostname: str) -> list[str]:
        if not consume_lookup():
            return []
        return query_a(hostname) + query_aaaa(hostname)

    def mechanism_matches(mechanism_type: str, value: str | None) -> bool:
        target_domain = normalize_domain(value) or normalize_domain(sender_domain)
        if mechanism_type == "a":
            if not target_domain:
                return False
            target, *prefixes = target_domain.split("/", 1)
            return any(address_matches(target, address, prefixes[0] if prefixes else None) for address in host_addresses(target))
        if mechanism_type == "mx":
            if not target_domain or not consume_lookup():
                return False
            target, *prefixes = target_domain.split("/", 1)
            for record in query_mx(target):
                exchange = normalize_domain(record.get("exchange"))
                if exchange and any(address_matches(exchange, address, prefixes[0] if prefixes else None) for address in host_addresses(exchange)):
                    return True
            return False
        if mechanism_type == "exists":
            return bool(target_domain and host_addresses(target_domain))
        if mechanism_type == "ptr":
            if not target_domain or not consume_lookup():
                return False
            for hostname in query_ptr(sender_ip):
                hostname = normalize_domain(hostname)
                if hostname and (hostname == target_domain or hostname.endswith(f".{target_domain}")):
                    if any(sender_ip == address for address in host_addresses(hostname)):
                        return True
            return False
        return False

    def evaluate_record(record_value: str | None, domain: str | None) -> dict[str, Any]:
        nested = parse_spf_record(record_value)
        if not nested["present"] or not domain:
            return {"result": "none", "matched_mechanism": None, "matched_qualifier": None}
        domain = normalize_domain(domain)
        if domain in visited:
            return {"result": "permerror", "matched_mechanism": None, "matched_qualifier": None}
        visited.add(domain)
        for nested_mechanism in nested["mechanisms"]:
            mechanism_type = nested_mechanism.get("type")
            value = nested_mechanism.get("value")
            qualifier = nested_mechanism.get("qualifier", "+")
            matches = mechanism_type == "all"
            if mechanism_type in {"ip4", "ip6"} and value:
                matches = ip_matches_network(sender_ip, value)
            elif mechanism_type in {"a", "mx", "exists", "ptr"}:
                matches = mechanism_matches(mechanism_type, value)
            if matches:
                return {"result": _qualifier_result(qualifier), "matched_mechanism": nested_mechanism["token"], "matched_qualifier": qualifier}
            if mechanism_type == "include" and value:
                included = normalize_domain(value)
                included_record = extract_spf_record(included) if included else None
                included_result = evaluate_record(included_record, included)
                if included:
                    visited.discard(included)
                if included_result["result"] == "pass":
                    return {"result": _qualifier_result(qualifier), "matched_mechanism": nested_mechanism["token"], "matched_qualifier": qualifier}
                if included_result["result"] == "permerror":
                    return included_result
        if nested.get("redirect"):
            redirect = normalize_domain(nested["redirect"])
            redirected = evaluate_record(extract_spf_record(redirect) if redirect else None, redirect)
            if redirect:
                visited.discard(redirect)
            if redirected["result"] != "none":
                return redirected
        return {"result": "neutral", "matched_mechanism": None, "matched_qualifier": None}

    evaluation = evaluate_record(record, sender_domain)
    result["lookup_count"] = state["lookup_count"]
    result.update(evaluation)
    return result


def analyze_spf(
    *,
    domain: str | None,
    sender_ip: str | None,
) -> dict[str, Any]:

    domain = normalize_domain(domain)

    record = (
        extract_spf_record(domain)
        if domain
        else None
    )

    evaluation = evaluate_spf_record(
        record=record,
        sender_ip=sender_ip,
        sender_domain=domain,
    )

    result = {
        "domain": domain,
        "record_found": record is not None,
        "raw_record": record,
        "parsed_record": evaluation[
            "record"
        ],
        "result": evaluation[
            "result"
        ],
        "matched_mechanism": evaluation[
            "matched_mechanism"
        ],
        "matched_qualifier": evaluation[
            "matched_qualifier"
        ],
        "lookup_count": evaluation[
            "lookup_count"
        ],
        "sender_ip": sender_ip,
    }

    return result