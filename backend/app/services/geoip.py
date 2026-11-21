from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import settings


@lru_cache(maxsize=4)
def _reader(database_path: str):
    import geoip2.database

    return geoip2.database.Reader(database_path)


def lookup_local(ip: str) -> dict[str, Any]:
    """Look up an IP in the configured local city MMDB database."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "available": False,
            "source": "local city database",
            "reason": "Invalid IP address",
        }

    if not address.is_global:
        return {
            "available": False,
            "source": "local city database",
            "reason": "Non-public IP address has no geographic location",
        }

    database_path = Path(settings.GEOIP_DATABASE_PATH)

    if not database_path.exists():
        return {
            "available": False,
            "source": "local city database",
            "reason": "Local city database is not installed",
        }

    try:
        response = _reader(str(database_path)).city(ip)
        return {
            "available": True,
            "source": "local city database",
            "country": response.country.name,
            "country_code": response.country.iso_code,
            "region": response.subdivisions.most_specific.name,
            "region_code": response.subdivisions.most_specific.iso_code,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
            "timezone": response.location.time_zone,
        }
    except ImportError:
        return {
            "available": False,
            "source": "local city database",
            "reason": "geoip2 package is not installed",
        }
    except Exception as exc:
        return {
            "available": False,
            "source": "local city database",
            "reason": str(exc),
        }
