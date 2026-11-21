from __future__ import annotations

from functools import wraps
from threading import Lock
from time import monotonic
from typing import Any

import httpx

from app.core.config import settings


class ProviderUnavailable(RuntimeError):
    pass


def _cache_for(seconds: float):
    def decorate(function):
        cache = {}
        lock = Lock()

        @wraps(function)
        def wrapped(value: str):
            timestamp = monotonic()
            with lock:
                cached = cache.get(value)
                if cached and cached[0] > timestamp:
                    return cached[1]
            result = function(value)
            with lock:
                if len(cache) >= 2048 and value not in cache:
                    cache.pop(next(iter(cache)))
                cache[value] = (timestamp + seconds, result)
            return result

        return wrapped
    return decorate


@_cache_for(settings.INTELLIGENCE_CACHE_TTL_SECONDS)
def lookup_ip(ip: str) -> dict[str, Any]:
    if not settings.IPINFO_TOKEN:
        return {"provider": None, "available": False, "reason": "IPINFO_TOKEN is not configured"}
    try:
        response = httpx.get(
            f"https://ipinfo.io/{ip}/json",
            headers={"Authorization": f"Bearer {settings.IPINFO_TOKEN}"},
            timeout=settings.INTELLIGENCE_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        return {"provider": "ipinfo", "available": True, "data": data}
    except (httpx.HTTPError, ValueError) as exc:
        return {"provider": "ipinfo", "available": False, "reason": str(exc)}


@_cache_for(settings.INTELLIGENCE_CACHE_TTL_SECONDS)
def check_ip_reputation(ip: str) -> dict[str, Any]:
    if not settings.ABUSEIPDB_API_KEY:
        return {"provider": None, "available": False, "reason": "ABUSEIPDB_API_KEY is not configured"}
    try:
        response = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": settings.ABUSEIPDB_MAX_AGE_DAYS},
            headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=settings.INTELLIGENCE_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return {"provider": "abuseipdb", "available": True, "data": response.json().get("data", {})}
    except (httpx.HTTPError, ValueError) as exc:
        return {"provider": "abuseipdb", "available": False, "reason": str(exc)}


@_cache_for(settings.INTELLIGENCE_CACHE_TTL_SECONDS)
def check_url_reputation(url: str) -> dict[str, Any]:
    if not settings.URLSCAN_API_KEY:
        return {"provider": None, "available": False, "reason": "URLSCAN_API_KEY is not configured"}
    try:
        response = httpx.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"page.url:{url}"},
            headers={"api-key": settings.URLSCAN_API_KEY},
            timeout=settings.INTELLIGENCE_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return {"provider": "urlscan", "available": True, "data": response.json()}
    except (httpx.HTTPError, ValueError) as exc:
        return {"provider": "urlscan", "available": False, "reason": str(exc)}
