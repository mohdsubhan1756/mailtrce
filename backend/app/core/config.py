# backend/app/core/config.py

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


BACKEND_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BACKEND_DIR / ".env")

BASE_DIR = Path(
    __file__
).resolve().parents[3]


@dataclass(frozen=True)
class Settings:

    APP_NAME: str = os.getenv(
        "APP_NAME",
        "MailTrace AI"
    )

    APP_VERSION: str = os.getenv(
        "APP_VERSION",
        "1.0.0"
    )

    ENVIRONMENT: str = os.getenv(
        "ENVIRONMENT",
        "development"
    )

    CORS_ORIGINS: tuple[str, ...] = tuple(
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173",
        ).split(",")
        if origin.strip()
    )

    # MongoDB
    MONGODB_URI: str = os.getenv(
        "MONGODB_URI",
        "mongodb://localhost:27017"
    )

    MONGODB_DATABASE: str = os.getenv(
        "MONGODB_DATABASE",
        "mailtrace"
    )

    # Local evidence storage
    EVIDENCE_DIRECTORY: str = os.getenv(
        "EVIDENCE_DIRECTORY",
        str(BASE_DIR / "backend" / "evidence")
    )

    # Upload limit
    MAX_EMAIL_SIZE_MB: int = int(
        os.getenv(
            "MAX_EMAIL_SIZE_MB",
            "25"
        )
    )

    MAX_EMAIL_SIZE_BYTES: int = (
        MAX_EMAIL_SIZE_MB * 1024 * 1024
    )

    # Zero disables automatic deletion. Evidence is otherwise retained indefinitely.
    RETENTION_DAYS: int = max(0, int(os.getenv("RETENTION_DAYS", "0")))

    RETENTION_CHECK_INTERVAL_SECONDS: int = max(
        60,
        int(os.getenv("RETENTION_CHECK_INTERVAL_SECONDS", "3600")),
    )

    EXPERIMENTAL_EMAIL_MODEL_PATH: str = os.getenv(
        "EXPERIMENTAL_EMAIL_MODEL_PATH",
        str(BACKEND_DIR / "models" / "email-classifier-proxy" / "model.joblib"),
    )

    ALLOWED_EXTENSIONS: tuple = (
        ".eml",
    )

    # Optional external intelligence providers. Disabled by default.
    IPINFO_TOKEN: str | None = os.getenv("IPINFO_TOKEN")

    ABUSEIPDB_API_KEY: str | None = os.getenv("ABUSEIPDB_API_KEY")

    ABUSEIPDB_MAX_AGE_DAYS: int = int(
        os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90")
    )

    URLSCAN_API_KEY: str | None = os.getenv("URLSCAN_API_KEY")

    INTELLIGENCE_TIMEOUT_SECONDS: float = float(
        os.getenv("INTELLIGENCE_TIMEOUT_SECONDS", "5")
    )

    INTELLIGENCE_CACHE_TTL_SECONDS: int = max(
        0,
        int(os.getenv("INTELLIGENCE_CACHE_TTL_SECONDS", "300")),
    )

    GEOIP_DATABASE_PATH: str = os.getenv(
        "GEOIP_DATABASE_PATH",
        str(BASE_DIR / "backend" / "data" / "dbip-city-lite.mmdb"),
    )

    OFFLINE_MODE: bool = os.getenv(
        "OFFLINE_MODE",
        "true",
    ).lower() in {"1", "true", "yes", "on"}

    DNS_RECORDS_PATH: str = os.getenv(
        "DNS_RECORDS_PATH",
        str(BASE_DIR / "backend" / "data" / "dns_records.json"),
    )

    DNS_CACHE_TTL_SECONDS: float = float(
        os.getenv("DNS_CACHE_TTL_SECONDS", "300")
    )


settings = Settings()
