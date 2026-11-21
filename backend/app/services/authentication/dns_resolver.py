import dns.exception
import dns.resolver
import json
import time
from pathlib import Path

from app.core.config import settings


DEFAULT_TIMEOUT = 5.0
_CACHE: dict[tuple[str, str], tuple[float, list]] = {}


def clear_dns_cache() -> None:
    _CACHE.clear()


def _cached(record_type: str, name: str) -> list | None:
    cached = _CACHE.get((record_type, name.rstrip(".").lower()))
    if not cached:
        return None
    timestamp, values = cached
    if time.monotonic() - timestamp >= settings.DNS_CACHE_TTL_SECONDS:
        _CACHE.pop((record_type, name.rstrip(".").lower()), None)
        return None
    return list(values)


def _store(record_type: str, name: str, values: list) -> list:
    _CACHE[(record_type, name.rstrip(".").lower())] = (time.monotonic(), list(values))
    return list(values)


def _resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()

    resolver.timeout = DEFAULT_TIMEOUT
    resolver.lifetime = DEFAULT_TIMEOUT

    return resolver


def _local_records(record_type: str, name: str) -> list:
    path = Path(settings.DNS_RECORDS_PATH)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        values = data.get(record_type, {}).get(name.rstrip(".").lower(), [])
        return values if isinstance(values, list) else []
    except (OSError, ValueError, TypeError):
        return []


def _should_use_network() -> bool:
    return not settings.OFFLINE_MODE


def query_txt(
    domain: str,
) -> list[str]:
    if not domain:
        return []

    cached = _cached("TXT", domain)
    if cached is not None:
        return cached

    local = _local_records("TXT", domain)
    if local or not _should_use_network():
        return _store("TXT", domain, [str(item) for item in local])

    try:
        answers = _resolver().resolve(
            domain,
            "TXT",
        )
    except (
        dns.exception.DNSException,
        OSError,
    ):
        return _store("TXT", domain, [])

    records: list[str] = []

    for answer in answers:
        try:
            parts = answer.strings

            value = "".join(
                part.decode("utf-8", errors="replace")
                if isinstance(part, bytes)
                else str(part)
                for part in parts
            )

            records.append(value)

        except AttributeError:
            value = str(answer)

            value = value.strip('"')

            records.append(value)

    return _store("TXT", domain, records)


def query_a(
    hostname: str,
) -> list[str]:
    if not hostname:
        return []

    cached = _cached("A", hostname)
    if cached is not None:
        return cached

    local = _local_records("A", hostname)
    if local or not _should_use_network():
        return _store("A", hostname, [str(item) for item in local])

    try:
        answers = _resolver().resolve(
            hostname,
            "A",
        )
    except (
        dns.exception.DNSException,
        OSError,
    ):
        return _store("A", hostname, [])

    return _store("A", hostname, [
        answer.address
        for answer in answers
    ])


def query_aaaa(
    hostname: str,
) -> list[str]:
    if not hostname:
        return []

    cached = _cached("AAAA", hostname)
    if cached is not None:
        return cached

    local = _local_records("AAAA", hostname)
    if local or not _should_use_network():
        return _store("AAAA", hostname, [str(item) for item in local])

    try:
        answers = _resolver().resolve(
            hostname,
            "AAAA",
        )
    except (
        dns.exception.DNSException,
        OSError,
    ):
        return _store("AAAA", hostname, [])

    return _store("AAAA", hostname, [
        answer.address
        for answer in answers
    ])


def query_mx(
    domain: str,
) -> list[dict]:
    if not domain:
        return []

    cached = _cached("MX", domain)
    if cached is not None:
        return cached

    local = _local_records("MX", domain)
    if local or not _should_use_network():
        return _store("MX", domain, local)

    try:
        answers = _resolver().resolve(
            domain,
            "MX",
        )
    except (
        dns.exception.DNSException,
        OSError,
    ):
        return _store("MX", domain, [])

    records = []

    for answer in answers:
        records.append(
            {
                "preference": int(
                    answer.preference
                ),
                "exchange": str(
                    answer.exchange
                ).rstrip("."),
            }
        )

    return _store("MX", domain, records)


def query_cname(
    hostname: str,
) -> list[str]:
    if not hostname:
        return []

    cached = _cached("CNAME", hostname)
    if cached is not None:
        return cached

    local = _local_records("CNAME", hostname)
    if local or not _should_use_network():
        return _store("CNAME", hostname, [str(item) for item in local])

    try:
        answers = _resolver().resolve(
            hostname,
            "CNAME",
        )
    except (
        dns.exception.DNSException,
        OSError,
    ):
        return _store("CNAME", hostname, [])

    return _store("CNAME", hostname, [
        str(answer.target).rstrip(".")
        for answer in answers
    ])


def query_ptr(
    address: str,
) -> list[str]:
    try:
        import ipaddress

        reverse_name = ipaddress.ip_address(address).reverse_pointer
    except ValueError:
        return []

    cached = _cached("PTR", reverse_name)
    if cached is not None:
        return cached

    local = _local_records("PTR", reverse_name)
    if local or not _should_use_network():
        return _store("PTR", reverse_name, [str(item).rstrip(".") for item in local])

    try:
        answers = _resolver().resolve(reverse_name, "PTR")
    except (dns.exception.DNSException, OSError):
        return _store("PTR", reverse_name, [])

    return _store("PTR", reverse_name, [str(answer.target).rstrip(".") for answer in answers])