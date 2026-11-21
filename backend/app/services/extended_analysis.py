from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from email.utils import getaddresses
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.db.mongodb import get_database
from app.services.geoip import lookup_local
from app.services.experimental_email_model import classify_experimental_email
from app.services.intelligence_providers import (
    check_ip_reputation,
    check_url_reputation,
    lookup_ip,
)
from app.core.config import settings
from app.services.authentication.authentication_service import (
    AUTHENTICATION_ANALYSIS_VERSION,
    analyze_email_authentication,
)
from app.services.url_intelligence.url_intelligence_service import (
    MODULE_VERSION,
    analyze_email_url_domain,
)


IP_ANALYSIS_VERSION = "1.1.0"
INTELLIGENCE_ANALYSIS_VERSION = "1.2.0"
THREAT_ANALYSIS_VERSION = "1.7.0"
ATTACHMENT_ANALYSIS_VERSION = "1.1.0"
RISK_SCORING_VERSION = "1.9.0"


def threat_analysis_version() -> str:
    return f"{THREAT_ANALYSIS_VERSION}-rules"


def risk_scoring_version() -> str:
    providers = "online" if not settings.OFFLINE_MODE and any((settings.IPINFO_TOKEN, settings.ABUSEIPDB_API_KEY, settings.URLSCAN_API_KEY)) else "offline"
    return f"{RISK_SCORING_VERSION}-rules-{providers}"


def ip_analysis_version() -> str:
    providers = "online" if not settings.OFFLINE_MODE and any((settings.IPINFO_TOKEN, settings.ABUSEIPDB_API_KEY)) else "offline"
    return f"{IP_ANALYSIS_VERSION}-{providers}"


def intelligence_analysis_version() -> str:
    providers = "online" if not settings.OFFLINE_MODE and any((settings.ABUSEIPDB_API_KEY, settings.URLSCAN_API_KEY)) else "offline"
    return f"{INTELLIGENCE_ANALYSIS_VERSION}-{providers}"


URL_RE = re.compile(r"https?://[^\s<>\"'()]+", re.IGNORECASE)
IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
    r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f:.]{0,17}(?![\w:])"
)
URGENT_RE = re.compile(
    r"\b(urgent|immediately|asap|action required|account suspended|verify|"
    r"unusual activity|deadline|final notice)\b",
    re.IGNORECASE,
)
CREDENTIAL_RE = re.compile(
    r"\b(password|passcode|credential|login|sign in|verify your account|"
    r"confirm your identity|security code)\b",
    re.IGNORECASE,
)
PAYMENT_RE = re.compile(
    r"\b(invoice|payment|wire transfer|bank account|gift card|refund|"
    r"purchase order|money transfer)\b",
    re.IGNORECASE,
)
IMPERSONATION_RE = re.compile(
    r"\b(ceo|cfo|director|security team|it department|help desk|"
    r"executive|company administrator)\b",
    re.IGNORECASE,
)
SECRECY_RE = re.compile(r"\b(keep (?:this|it) (?:secret|confidential)|do not tell|don't tell|confidential request)\b", re.IGNORECASE)
PAYMENT_CHANGE_RE = re.compile(r"\b(?:change|new|updated?)\s+(?:bank|wire|payment|account)\s+(?:details|information|number)\b", re.IGNORECASE)
LOGIN_LINK_RE = re.compile(r"\b(?:click|use|follow)\b.{0,80}\b(?:link|button)\b.{0,80}\b(?:sign in|log in|login|password|credentials)\b", re.IGNORECASE)
NEGATED_URGENCY_PREFIX_RE = re.compile(
    r"\b(?:no|not|never|without)\s+(?:[a-z]+\s+){0,2}$",
    re.IGNORECASE,
)
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd",
    ".msi", ".jar", ".hta", ".lnk", ".iso", ".img", ".docm", ".xlsm",
    ".pptm",
}
SCRIPT_EXTENSIONS = {".js", ".vbs", ".ps1", ".bat", ".cmd", ".hta"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}


def now() -> datetime:
    return datetime.now(timezone.utc)


def serialize(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [serialize(item) for item in value]
    if isinstance(value, dict):
        # MongoDB requires document keys to be strings. Model metadata and
        # classifier score maps can use integer class IDs as dictionary keys.
        return {str(key): serialize(item) for key, item in value.items()}
    return value


def get_email(email_id: str) -> dict[str, Any]:
    document = get_database()["emails"].find_one({"email_id": email_id}, {"_id": 0})
    if not document:
        raise ValueError(f"Email '{email_id}' was not found.")
    return document


def body_text(email: dict[str, Any]) -> str:
    body = email.get("body") or {}
    if not isinstance(body, dict):
        return str(body)
    return "\n".join(str(body.get(key) or "") for key in ("plain_text", "html", "plain", "text"))


def finding(code: str, severity: str, title: str, description: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"code": code, "severity": severity, "title": title, "description": description, "evidence": evidence or {}}


def _calibrated_language_score(findings: list[dict[str, Any]]) -> int:
    """Treat language cues as evidence; require combinations before strong scoring."""
    codes = {item.get("code") for item in findings}
    weights = {
        "URGENCY": 8,
        "CREDENTIAL_REQUEST": 10,
        "PAYMENT_REQUEST": 8,
        "IMPERSONATION_LANGUAGE": 8,
        "SECRECY_REQUEST": 8,
        "PAYMENT_DETAILS_CHANGE": 15,
        "LOGIN_LINK_INSTRUCTION": 8,
    }
    heuristic = min(30, sum(weight for code, weight in weights.items() if code in codes))
    if "CREDENTIAL_REQUEST" in codes and codes & {"URGENCY", "LOGIN_LINK_INSTRUCTION", "IMPERSONATION_LANGUAGE"}:
        heuristic += 8
    if "PAYMENT_DETAILS_CHANGE" in codes and codes & {"IMPERSONATION_LANGUAGE", "SECRECY_REQUEST", "URGENCY"}:
        heuristic += 12
    if "PAYMENT_REQUEST" in codes and codes & {"SECRECY_REQUEST", "PAYMENT_DETAILS_CHANGE"}:
        heuristic += 8

    return min(55, heuristic)


def analyze_threat(email: dict[str, Any]) -> dict[str, Any]:
    text = f"{email.get('subject') or ''}\n{body_text(email)}"
    experimental_model = classify_experimental_email(email)
    findings: list[dict[str, Any]] = []
    checks = [
        ("URGENCY", URGENT_RE, "Urgency or pressure language detected.", 20),
        ("CREDENTIAL_REQUEST", CREDENTIAL_RE, "Credential or account-verification language detected.", 30),
        ("PAYMENT_REQUEST", PAYMENT_RE, "Payment or financial-request language detected.", 25),
        ("IMPERSONATION_LANGUAGE", IMPERSONATION_RE, "Executive, security, or support impersonation language detected.", 15),
        ("SECRECY_REQUEST", SECRECY_RE, "The message asks the recipient to keep the request secret.", 15),
        ("PAYMENT_DETAILS_CHANGE", PAYMENT_CHANGE_RE, "The message asks the recipient to change payment or bank details.", 30),
        ("LOGIN_LINK_INSTRUCTION", LOGIN_LINK_RE, "The message directs the recipient to sign in through a link.", 20),
    ]
    for code, pattern, description, score in checks:
        matches = sorted({
            match.group().lower()
            for match in pattern.finditer(text)
            if code != "URGENCY"
            or not NEGATED_URGENCY_PREFIX_RE.search(text[max(0, match.start() - 40):match.start()])
        })
        if matches:
            findings.append(finding(code, "MEDIUM", code.replace("_", " ").title(), description, {"matches": matches, "score": score}))
    urls = email.get("urls") or []
    sender_domain = (email.get("sender") or {}).get("domain")
    external_destinations = [
        {"url": item.get("url"), "hostname": item.get("hostname"), "sender_domain": sender_domain}
        for item in urls
        if isinstance(item, dict) and item.get("hostname") and item.get("hostname") != sender_domain
    ]
    if external_destinations:
        findings.append(finding("EXTERNAL_DESTINATION", "LOW", "External destination detected", "A message URL points outside the sender domain.", {"destinations": external_destinations, "score": 10}))
    score = _calibrated_language_score(findings)
    signal_level = "STRONGER_LANGUAGE_SIGNALS" if score >= 35 else "SOME_LANGUAGE_SIGNALS" if score > 0 else "NO_LANGUAGE_SIGNALS"
    return {"email_id": email["email_id"], "case_id": email.get("case_id"), "analysis_version": threat_analysis_version(), "analyzed_at": now(), "analysis_method": "RULE_BASED_LANGUAGE_HEURISTICS", "experimental_model": experimental_model, "score": score, "signal_level": signal_level, "findings": findings, "status": "COMPLETED"}


def analyze_attachments(email: dict[str, Any]) -> dict[str, Any]:
    results = []
    findings = []
    for attachment in email.get("attachments") or []:
        filename = str(attachment.get("filename") or "")
        suffixes = [suffix.lower() for suffix in Path(filename).suffixes]
        extension = suffixes[-1] if suffixes else ""
        dangerous = extension in DANGEROUS_EXTENSIONS
        double_extension = len(suffixes) > 1 and suffixes[-2] in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt"} and dangerous
        archive = attachment.get("archive_analysis") or {}
        signature = attachment.get("detected_file_type")
        expected_signatures = {
            ".pdf": "PDF", ".exe": "Windows executable", ".dll": "Windows executable",
            ".docx": "ZIP archive", ".xlsx": "ZIP archive", ".pptx": "ZIP archive",
            ".docm": "ZIP archive", ".xlsm": "ZIP archive", ".pptm": "ZIP archive",
            ".zip": "ZIP archive", ".rtf": "RTF document",
        }
        signature_mismatch = bool(signature and extension in expected_signatures and signature != expected_signatures[extension])
        result = {**attachment, "extension": extension, "dangerous_extension": dangerous, "script": extension in SCRIPT_EXTENSIONS, "macro_document": extension in MACRO_EXTENSIONS, "double_extension": double_extension, "signature_mismatch": signature_mismatch}
        results.append(result)
        if dangerous:
            severity = "HIGH" if extension in SCRIPT_EXTENSIONS or double_extension else "MEDIUM"
            findings.append(finding("DANGEROUS_ATTACHMENT", severity, "Potentially dangerous attachment", f"Attachment '{filename}' has a potentially executable or macro-enabled type.", result))
        if double_extension:
            findings.append(finding("DOUBLE_EXTENSION", "HIGH", "Double-extension attachment", f"Attachment '{filename}' uses a misleading double extension.", result))
        if signature_mismatch:
            findings.append(finding("ATTACHMENT_SIGNATURE_MISMATCH", "HIGH", "Attachment type does not match its extension", f"Attachment '{filename}' is labeled as {extension or 'an unknown type'} but its file signature identifies it as {signature}.", result))
        if archive.get("dangerous_members"):
            findings.append(finding("ARCHIVE_CONTAINS_EXECUTABLE", "HIGH", "Archive contains executable content", f"Attachment '{filename}' contains potentially executable archive members.", {"members": archive["dangerous_members"]}))
        if archive.get("macro_project_present"):
            findings.append(finding("ARCHIVE_CONTAINS_MACRO_PROJECT", "HIGH", "Archive contains a macro project", f"Attachment '{filename}' contains a VBA macro project.", result))
        if archive.get("path_traversal_members"):
            findings.append(finding("ARCHIVE_PATH_TRAVERSAL", "HIGH", "Archive contains unsafe paths", f"Attachment '{filename}' includes paths that attempt to leave the archive directory.", {"members": archive["path_traversal_members"]}))
    score = min(100, sum(50 if item["severity"] == "HIGH" else 25 for item in findings))
    return {"email_id": email["email_id"], "case_id": email.get("case_id"), "analysis_version": ATTACHMENT_ANALYSIS_VERSION, "analyzed_at": now(), "attachments": results, "findings": findings, "score": score, "status": "COMPLETED"}


def analyze_ips(email: dict[str, Any]) -> dict[str, Any]:
    values = set(str(value) for value in email.get("ip_addresses") or [])
    for header in email.get("received_headers") or []:
        values.update(IP_RE.findall(str(header)))
    results = []
    external_ip_lookups = 0
    for value in sorted(values):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            # Header text includes dates and times that can resemble IP
            # literals. Never present an invalid parse as an address.
            continue
        documentation = any(
            address in network
            for network in (
                ipaddress.ip_network("192.0.2.0/24"),
                ipaddress.ip_network("198.51.100.0/24"),
                ipaddress.ip_network("203.0.113.0/24"),
                ipaddress.ip_network("2001:db8::/32"),
            )
        )
        six_to_four = (
            address.version == 6
            and address in ipaddress.ip_network("2002::/16")
        )
        embedded_ipv4 = None
        if six_to_four:
            embedded_ipv4 = ipaddress.IPv4Address(
                (int(address) >> 80) & 0xFFFFFFFF
            )
        private = address.is_private
        reserved = address.is_reserved
        public = address.is_global and (
            not six_to_four or bool(embedded_ipv4 and embedded_ipv4.is_global)
        )
        result = {
            "ip": value,
            "valid": True,
            "public": public,
            "private": private,
            "reserved": reserved,
            "special_use": six_to_four,
            "six_to_four": six_to_four,
            "embedded_ipv4": str(embedded_ipv4) if embedded_ipv4 else None,
            "documentation_range": documentation,
            "loopback": bool(address and address.is_loopback),
            "link_local": bool(address and address.is_link_local),
            "multicast": bool(address and address.is_multicast),
            "unspecified": bool(address and address.is_unspecified),
            "reputation": "UNKNOWN",
            "source": "local parsing only",
        }
        if documentation:
            # Documentation-only addresses are examples, never real endpoints.
            pass
        elif six_to_four and embedded_ipv4 and not embedded_ipv4.is_global:
            result["geolocation"] = {
                "available": False,
                "source": "local classification",
                "reason": f"6to4 address embeds non-public IPv4 address {embedded_ipv4}",
            }
        else:
            lookup_address = str(embedded_ipv4) if six_to_four and embedded_ipv4 else value
            result["geolocation"] = lookup_local(lookup_address)
        if public and not settings.OFFLINE_MODE and external_ip_lookups < 3:
            external_ip_lookups += 1
            provider_ip = str(embedded_ipv4) if six_to_four and embedded_ipv4 else value
            ipinfo = lookup_ip(provider_ip)
            if ipinfo.get("available"):
                data = ipinfo.get("data") or {}
                city_location = result.get("geolocation") or {}
                privacy = data.get("privacy") or {}
                location_parts = str(data.get("loc") or "").split(",", 1)
                coordinates = None
                if len(location_parts) == 2:
                    try:
                        coordinates = {"latitude": float(location_parts[0]), "longitude": float(location_parts[1])}
                    except ValueError:
                        coordinates = None
                result["provider_intelligence"] = {
                    "provider": ipinfo.get("provider"),
                    "asn": data.get("org"),
                    "hostname": data.get("hostname"),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "timezone": (data.get("timezone") or {}).get("id") if isinstance(data.get("timezone"), dict) else data.get("timezone"),
                    "coordinates": coordinates,
                    "privacy": privacy,
                    "is_vpn": privacy.get("vpn"),
                    "is_proxy": privacy.get("proxy"),
                    "is_tor": privacy.get("tor"),
                }
                if not city_location.get("available"):
                    result["geolocation"] = {
                        "available": bool(data.get("country") or data.get("city")),
                        "source": "ipinfo",
                        "city": data.get("city"),
                        "region": data.get("region"),
                        "country": data.get("country"),
                        **(coordinates or {}),
                        "timezone": result["provider_intelligence"]["timezone"],
                        "reason": None if data.get("country") or data.get("city") else "Provider returned no location fields",
                    }
            reputation = check_ip_reputation(provider_ip)
            if reputation.get("available"):
                result["ip_reputation"] = reputation.get("data") or {}
                result["reputation"] = "ABUSE_REPORTED" if int(result["ip_reputation"].get("abuseConfidenceScore") or 0) >= 25 else "NO_SIGNIFICANT_REPORTS"
            result["external_intelligence_checked"] = bool(ipinfo.get("available") or reputation.get("available"))
        results.append(result)
    return {"email_id": email["email_id"], "case_id": email.get("case_id"), "analysis_version": ip_analysis_version(), "analyzed_at": now(), "ips": results, "external_reputation_queried": any(item.get("external_intelligence_checked") for item in results), "status": "COMPLETED"}


def correlate_intelligence(email: dict[str, Any], threat: dict[str, Any], attachments: dict[str, Any], ips: dict[str, Any]) -> dict[str, Any]:
    indicators_by_key: dict[tuple[str, str], dict[str, Any]] = {}

    def add_indicator(kind: str, value: Any, source: str) -> None:
        if value is None or not str(value).strip():
            return
        normalized_value = str(value).strip().lower() if kind == "domain" else str(value).strip()
        key = (kind, normalized_value)
        if key in indicators_by_key:
            indicators_by_key[key]["occurrence_count"] += 1
        else:
            indicators_by_key[key] = {"type": kind, "value": key[1], "source": source, "occurrence_count": 1}

    for item in email.get("urls") or []:
        if isinstance(item, dict) and item.get("hostname"):
            add_indicator("domain", item["hostname"], "email URL")
    for item in ips.get("ips") or []:
        add_indicator("ip", item.get("ip"), "email headers")
    for item in attachments.get("attachments") or []:
        if item.get("sha256"):
            add_indicator("sha256", item["sha256"], "attachment")
    indicators = list(indicators_by_key.values())
    matches = []
    seen_matches = set()
    db = get_database()
    for indicator in indicators:
        value = indicator["value"]
        if indicator["type"] == "domain":
            query = {"urls.hostname": value}
        elif indicator["type"] == "ip":
            query = {"ip_addresses": value}
        else:
            query = {"attachments.sha256": value}
        query["email_id"] = {"$ne": email["email_id"]}
        for related in db["emails"].find(
            query,
            {"_id": 0, "email_id": 1, "case_id": 1, "subject": 1},
        ).limit(100):
            key = (indicator["type"], value, related.get("email_id"))
            if key in seen_matches:
                continue
            seen_matches.add(key)
            matches.append({
                "type": indicator["type"],
                "value": value,
                "source": indicator["source"],
                "matched_email": related,
            })
    external_matches = []
    external_sources = []
    if not settings.OFFLINE_MODE:
        for item in (email.get("urls") or [])[:3]:
            url = item.get("url") if isinstance(item, dict) else None
            if not url:
                continue
            lookup = check_url_reputation(url)
            if lookup.get("available"):
                external_sources.append(lookup.get("provider"))
                data = lookup.get("data") or {}
                results = data.get("results") or []
                if results:
                    external_matches.append({"type": "url", "value": url, "provider": lookup.get("provider"), "result_count": len(results), "results": [{"task": row.get("task"), "verdicts": row.get("verdicts"), "page": row.get("page")} for row in results[:5] if isinstance(row, dict)]})
        for item in (ips.get("ips") or []):
            reputation = item.get("ip_reputation") if isinstance(item, dict) else None
            if reputation and int(reputation.get("abuseConfidenceScore") or 0) >= 25:
                external_sources.append("abuseipdb")
                external_matches.append({"type": "ip", "value": item["ip"], "provider": "abuseipdb", "abuse_confidence_score": reputation.get("abuseConfidenceScore"), "usage_type": reputation.get("usageType"), "country_code": reputation.get("countryCode")})
    external_sources = sorted(set(filter(None, external_sources)))
    return {"email_id": email["email_id"], "case_id": email.get("case_id"), "analysis_version": intelligence_analysis_version(), "checked_at": now(), "provider": "local email corpus" + (" + external providers" if external_sources else ""), "external_sources_queried": external_sources, "matches": matches, "external_matches": external_matches, "indicators": indicators, "status": "COMPLETED"}


CAMPAIGN_HEADER_FIELDS = {
    "header_return_path_domain": "return_path",
    "header_reply_to_domain": "reply_to",
    "header_message_id_domain": "message_id",
}


def _campaign_header_domains(record: dict[str, Any]) -> dict[str, set[str]]:
    extracted: dict[str, set[str]] = {}
    for indicator_type, field in CAMPAIGN_HEADER_FIELDS.items():
        raw = record.get(field)
        raw_values = raw if isinstance(raw, list) else [raw]
        domains: set[str] = set()
        for raw_value in raw_values:
            value = str(raw_value or "")
            if field == "message_id":
                match = re.search(r"@([^>\s]+)", value)
                if match:
                    domains.add(match.group(1).strip().lower().strip("."))
            else:
                for _, address in getaddresses([value]):
                    if "@" in address:
                        domains.add(address.rsplit("@", 1)[1].lower().strip(".> "))
        extracted[indicator_type] = domains
    return extracted


def campaign(email: dict[str, Any]) -> dict[str, Any]:
    db = get_database()
    sender = (email.get("sender") or {}).get("domain")
    domains = list(dict.fromkeys(str(item.get("hostname")).lower() for item in email.get("urls") or [] if isinstance(item, dict) and item.get("hostname")))
    sender_address = (email.get("sender") or {}).get("address")
    current_header_domains = _campaign_header_domains(email)
    ip_values = {str(value) for value in email.get("ip_addresses") or []}
    for header in email.get("received_headers") or []:
        ip_values.update(IP_RE.findall(str(header)))
    ips = sorted({str(ipaddress.ip_address(value)) for value in ip_values if _is_ip_address(value)})
    hashes = [str(item.get("sha256")) for item in email.get("attachments") or [] if item.get("sha256")]
    header_clauses = []
    for indicator_type, values in current_header_domains.items():
        field = CAMPAIGN_HEADER_FIELDS[indicator_type]
        header_clauses.extend({field: {"$regex": re.escape(value), "$options": "i"}} for value in values)
    clauses = ([{"sender.domain": sender}] if sender else []) + ([{"sender.address": sender_address}] if sender_address else []) + ([{"urls.hostname": {"$in": domains}}] if domains else []) + ([{"ip_addresses": {"$in": ips}}] if ips else []) + ([{"received_headers": {"$regex": re.escape(value)}} for value in ips] if ips else []) + ([{"attachments.sha256": {"$in": hashes}}] if hashes else []) + header_clauses
    query = {"email_id": {"$ne": email["email_id"]}, "$or": clauses}
    candidates = list(db["emails"].find(query, {"_id": 0, "email_id": 1, "case_id": 1, "subject": 1, "sender": 1, "return_path": 1, "reply_to": 1, "message_id": 1, "urls.hostname": 1, "ip_addresses": 1, "received_headers": 1, "attachments.sha256": 1}).limit(100)) if clauses else []
    related = []
    best_match_categories = 0
    for candidate in candidates:
        candidate_sender = candidate.get("sender") or {}
        candidate_domains = {str(item.get("hostname")).lower() for item in candidate.get("urls") or [] if isinstance(item, dict) and item.get("hostname")}
        candidate_ip_values = {str(value) for value in candidate.get("ip_addresses") or []}
        for header in candidate.get("received_headers") or []:
            candidate_ip_values.update(IP_RE.findall(str(header)))
        candidate_ips = {str(ipaddress.ip_address(value)) for value in candidate_ip_values if _is_ip_address(value)}
        candidate_hashes = {item.get("sha256") for item in candidate.get("attachments") or [] if isinstance(item, dict)}
        candidate_headers = _campaign_header_domains(candidate)
        matched = []
        if sender and candidate_sender.get("domain") == sender:
            matched.append("sender_domain")
        if sender_address and candidate_sender.get("address") == sender_address:
            matched.append("sender_address")
        if set(domains) & candidate_domains:
            matched.append("url_domain")
        if set(ips) & candidate_ips:
            matched.append("ip")
        if set(hashes) & candidate_hashes:
            matched.append("attachment_hash")
        shared_header_domains = {
            kind: current_header_domains[kind] & candidate_headers[kind]
            for kind in CAMPAIGN_HEADER_FIELDS
            if current_header_domains[kind] & candidate_headers[kind]
        }
        if shared_header_domains:
            matched.append("header_domain")
        matched_values = []
        if sender and candidate_sender.get("domain") == sender:
            matched_values.append({"type": "sender_domain", "value": sender})
        if sender_address and candidate_sender.get("address") == sender_address:
            matched_values.append({"type": "sender_address", "value": sender_address})
        matched_values.extend({"type": "domain", "value": value} for value in set(domains) & candidate_domains)
        matched_values.extend({"type": "ip", "value": value} for value in set(ips) & candidate_ips)
        matched_values.extend({"type": "sha256", "value": value} for value in set(hashes) & candidate_hashes)
        matched_values.extend({"type": kind, "value": value} for kind, values in shared_header_domains.items() for value in values)
        category_groups = set()
        if "sender_domain" in matched or "sender_address" in matched:
            category_groups.add("sender_identity")
        if "url_domain" in matched:
            category_groups.add("url_domain")
        if "ip" in matched:
            category_groups.add("ip")
        if "attachment_hash" in matched:
            category_groups.add("attachment_hash")
        if "header_domain" in matched:
            category_groups.add("header_domain")
        best_match_categories = max(best_match_categories, len(category_groups))
        related.append({key: candidate.get(key) for key in ("email_id", "case_id", "subject", "sender")} | {"matched_indicators": matched, "matched_values": matched_values})
    confidence = "HIGH" if best_match_categories >= 3 else "MEDIUM" if best_match_categories == 2 else "LOW" if best_match_categories == 1 else "NONE"
    # Keep the graph readable while retaining the full related-email list above.
    graph_related = related[:15]
    indicator_map: dict[tuple[str, str], dict[str, Any]] = {}
    current_values = []
    if sender:
        current_values.append(("sender_domain", sender))
    if sender_address:
        current_values.append(("sender_address", sender_address))
    current_values.extend(("domain", value) for value in domains)
    current_values.extend((kind, value) for kind, values in current_header_domains.items() for value in sorted(values))
    current_values.extend(("ip", value) for value in ips)
    current_values.extend(("sha256", value) for value in hashes)
    for item in graph_related:
        for value in item["matched_values"]:
            key = (value["type"], value["value"])
            indicator_map[key] = {"type": "indicator", "indicator_type": key[0], "value": key[1]}
    for kind, value in current_values:
        indicator_map.setdefault((kind, value), {"type": "indicator", "indicator_type": kind, "value": value})
    graph_indicators = list(indicator_map.items())[:24]
    email_nodes = [{"id": f"email:{email['email_id']}", "type": "email", "email_id": email["email_id"], "label": email.get("subject") or email["email_id"], "current": True}]
    email_nodes.extend({"id": f"email:{item['email_id']}", "type": "email", "email_id": item["email_id"], "label": item.get("subject") or item["email_id"], "current": False} for item in graph_related)
    indicator_nodes = [{"id": f"indicator:{kind}:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]}", **node} for (kind, value), node in graph_indicators]
    node_ids = {(node["indicator_type"], node["value"]): node["id"] for node in indicator_nodes}
    graph_edges = []
    for kind, value in current_values:
        if (kind, value) in node_ids:
            graph_edges.append({"source": f"email:{email['email_id']}", "target": node_ids[(kind, value)], "label": "contains"})
    for item in graph_related:
        for value in item["matched_values"]:
            key = (value["type"], value["value"])
            if key in node_ids:
                graph_edges.append({"source": f"email:{item['email_id']}", "target": node_ids[key], "label": "shares"})
    graph = {"nodes": email_nodes + indicator_nodes, "edges": graph_edges, "omitted_related_count": max(0, len(related) - len(graph_related)), "omitted_indicator_count": max(0, len(indicator_map) - len(graph_indicators))}
    return {"email_id": email["email_id"], "case_id": email.get("case_id"), "related_emails": related, "shared_sender_domain": sender, "shared_sender_address": sender_address, "shared_header_domains": {kind: sorted(values) for kind, values in current_header_domains.items() if values}, "shared_url_domains": domains, "shared_ip_addresses": ips, "shared_attachment_hashes": hashes, "correlation_confidence": confidence, "confidence_note": "Confidence describes shared evidence categories, not threat-actor attribution.", "graph": graph, "status": "COMPLETED"}


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _risk_verdict(
    *,
    score: int,
    threat_score: int,
    attachment_score: int,
    url_score: int,
    external_ip_score: int,
    malicious_url: bool,
) -> tuple[str, str, str]:
    """Keep score severity distinct from a verdict requiring corroboration."""
    risk_level = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW" if score > 0 else "MINIMAL"
    corroborating_sources = sum((
        threat_score >= 30,
        attachment_score >= 40,
        url_score >= 40,
        external_ip_score >= 70,
    ))
    if malicious_url:
        verdict = "MALICIOUS_OR_HIGHLY_SUSPICIOUS"
        reason = "An enabled external URL intelligence provider returned a malicious verdict."
    elif score >= 70 and corroborating_sources >= 2:
        verdict = "MALICIOUS_OR_HIGHLY_SUSPICIOUS"
        reason = f"High score supported by {corroborating_sources} independent evidence categories."
    elif score >= 40:
        verdict = "SUSPICIOUS"
        reason = "The combined triage score warrants review; this is not a confirmed malicious classification."
    else:
        verdict = "NO_SIGNIFICANT_RISK"
        reason = "Available evidence did not reach the suspicious review threshold. This is not a safety guarantee."
    return risk_level, verdict, reason


def _combined_risk_score(
    *,
    threat_score: int,
    attachment_score: int,
    authentication_result: str,
    url_score: int,
    external_ip_score: int,
    malicious_url: bool,
) -> tuple[int, int]:
    """Combine signals with explicit caps for weak/indirect evidence."""
    score = max(threat_score, attachment_score, url_score)
    authentication_contribution = 5 if authentication_result == "FAIL" else 0
    score += authentication_contribution
    score = max(score, min(60, external_ip_score))
    if malicious_url:
        score = max(score, 90)
    return min(100, score), authentication_contribution


def risk(email: dict[str, Any], *, refresh_auth: bool = False, refresh_url: bool = False, ip_result: dict[str, Any] | None = None, intelligence_result: dict[str, Any] | None = None) -> dict[str, Any]:
    threat = analyze_threat(email)
    attachments = analyze_attachments(email)
    score = max(threat["score"], attachments["score"])
    explanations = [
        {"signal": "Threat language", "source": "Rule-based message text checks", "score": threat["score"], "effect": f"Sets the base score to {score}." if threat["score"] >= attachments["score"] else f"Did not raise the base score; attachment analysis set it to {score}.", "evidence": threat.get("findings", [])},
        {"signal": "Attachment forensics", "source": "Attachment metadata and archive inspection", "score": attachments["score"], "effect": f"Sets the base score to {score}." if attachments["score"] >= threat["score"] else f"Did not raise the base score; threat analysis set it to {score}.", "evidence": attachments.get("findings", [])},
    ]
    auth = get_database()["authentication_analysis"].find_one({"email_id": email["email_id"]}, {"_id": 0})
    if auth is None or refresh_auth or auth.get("analysis_version") != AUTHENTICATION_ANALYSIS_VERSION:
        auth = analyze_email_authentication(email["email_id"])
    before = score
    authentication_contribution = 5 if auth.get("overall_result") == "FAIL" else 0
    if authentication_contribution:
        score = min(100, score + authentication_contribution)
    authentication_evidence = {
        "overall_result": auth.get("overall_result"),
        "spf_result": (auth.get("spf") or {}).get("result"),
        "dkim_result": (auth.get("dkim") or {}).get("result"),
        "dmarc_result": (auth.get("dmarc") or {}).get("result"),
        "findings": auth.get("findings", []),
    }
    explanations.append({"signal": "Email authentication", "source": "SPF, DKIM, and DMARC analysis", "score": auth.get("overall_result"), "effect": f"Added {score - before} points (up to 5) for an explicit FAIL. Missing records or unverified signatures do not independently create a high-risk verdict.", "evidence": authentication_evidence})
    url = get_database()["url_domain_intelligence"].find_one({"email_id": email["email_id"]}, {"_id": 0})
    if url is None or refresh_url or ((url.get("module") or {}).get("version") != MODULE_VERSION):
        url = analyze_email_url_domain(email["email_id"])
    before = score
    url_score = int((url.get("risk") or {}).get("score", 0))
    score = min(100, max(score, url_score))
    explanations.append({"signal": "URL and domain analysis", "source": "URL/domain findings", "score": url_score, "effect": f"Raised score by {score - before} points when its score was higher.", "evidence": url.get("findings", [])})
    if ip_result is None:
        ip_result = get_database()["ip_intelligence"].find_one({"email_id": email["email_id"]}, {"_id": 0})
        if ip_result is None and not settings.OFFLINE_MODE:
            ip_result = analyze_ips(email)
    external_ip_score = max((int((item.get("ip_reputation") or {}).get("abuseConfidenceScore") or 0) for item in (ip_result or {}).get("ips", [])), default=0)
    before = score
    if external_ip_score:
        score = max(score, min(60, external_ip_score))
    explanations.append({"signal": "External IP reputation", "source": "AbuseIPDB (only when configured and online mode is enabled)", "score": external_ip_score, "effect": f"Raised score by {score - before} points, capped at 60 so IP reputation alone cannot produce a high-risk verdict.", "evidence": [{"ip": item.get("ip"), "reputation": {key: (item.get("ip_reputation") or {}).get(key) for key in ("abuseConfidenceScore", "totalReports", "lastReportedAt", "usageType", "countryCode") if key in (item.get("ip_reputation") or {})}} for item in (ip_result or {}).get("ips", []) if item.get("ip_reputation")]})
    if intelligence_result is None:
        intelligence_result = get_database()["threat_intelligence"].find_one({"email_id": email["email_id"]}, {"_id": 0})
    malicious_url = any(
        bool(((row.get("verdicts") or {}).get("overall") or {}).get("malicious"))
        for match in (intelligence_result or {}).get("external_matches", [])
        for row in match.get("results", [])
    )
    before = score
    if malicious_url:
        score = max(score, 90)
    explanations.append({"signal": "External URL verdict", "source": "URLScan (only when configured and online mode is enabled)", "score": 90 if malicious_url else 0, "effect": f"Raised score by {score - before} points when a malicious verdict was returned.", "evidence": [match for match in (intelligence_result or {}).get("external_matches", []) if match.get("type") == "url"]})
    score, authentication_contribution = _combined_risk_score(
        threat_score=int(threat["score"]),
        attachment_score=int(attachments["score"]),
        authentication_result=str(auth.get("overall_result") or ""),
        url_score=int((url.get("risk") or {}).get("score", 0)),
        external_ip_score=external_ip_score,
        malicious_url=malicious_url,
    )
    url_score = int((url.get("risk") or {}).get("score", 0))
    risk_level, verdict, verdict_reason = _risk_verdict(
        score=score,
        threat_score=int(threat["score"]),
        attachment_score=int(attachments["score"]),
        url_score=url_score,
        external_ip_score=external_ip_score,
        malicious_url=malicious_url,
    )
    explanations.append({"signal": "Verdict corroboration", "source": "Independent evidence categories", "score": verdict, "effect": verdict_reason, "evidence": {"threat_score": threat["score"], "attachment_score": attachments["score"], "url_domain_score": url_score, "external_ip_abuse_confidence": external_ip_score, "malicious_url_intelligence": malicious_url}})
    return {"email_id": email["email_id"], "case_id": email.get("case_id"), "scoring_version": risk_scoring_version(), "calculated_at": now(), "score": score, "risk_level": risk_level, "verdict": verdict, "verdict_reason": verdict_reason, "components": {"threat": threat["score"], "attachments": attachments["score"], "authentication": auth.get("overall_result", "NOT_ANALYZED"), "authentication_contribution": authentication_contribution, "url_domain": url_score, "external_ip_abuse_confidence": external_ip_score, "external_url_malicious": malicious_url}, "explanations": explanations, "attribution_confidence": None, "attribution_note": "Actor attribution is not assessed; shared infrastructure correlation is reported separately.", "status": "COMPLETED"}


def write_audit(email_id: str | None, action: str, details: dict[str, Any] | None = None, *, case_id: str | None = None) -> None:
    collection = get_database()["audit_log"]
    target_field = "email_id" if email_id else "case_id"
    target_id = email_id or case_id
    if not target_id:
        raise ValueError("An email ID or case ID is required for an audit event.")
    target_filter = {target_field: target_id}
    previous = collection.find_one(target_filter, sort=[("_id", -1)])
    previous_hash = None
    if previous:
        # Preserve the stored prior digest as the chain anchor. For legacy
        # unhashed rows, derive a canonical anchor from their saved contents.
        previous_hash = previous.get("event_hash") or _audit_event_hash(previous)
    event = {
        "event_id": str(uuid.uuid4()),
        target_field: target_id,
        "target_type": "email" if email_id else "case",
        "action": action,
        "details": details or {},
        "timestamp": now(),
        "previous_hash": previous_hash,
        "hash_version": 2,
    }
    event["event_hash"] = _audit_event_hash(event)
    collection.insert_one(event)


def _audit_event_hash(event: dict[str, Any]) -> str:
    def canonicalize(value: Any) -> Any:
        if isinstance(value, datetime):
            normalized = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
            normalized = normalized.replace(microsecond=(normalized.microsecond // 1000) * 1000)
            return normalized.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        if isinstance(value, dict):
            return {str(key): canonicalize(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [canonicalize(item) for item in value]
        return serialize(value)

    payload = {key: canonicalize(value) for key, value in event.items() if key not in {"_id", "event_hash"}}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_audit_chain(target_id: str, *, target_type: str = "email") -> dict[str, Any]:
    target_field = "case_id" if target_type == "case" else "email_id"
    events = list(get_database()["audit_log"].find({target_field: target_id}).sort("_id", 1))
    previous_anchor = None
    verified = 0
    legacy_unhashed = 0
    legacy_hash_format = 0
    broken = []
    for index, event in enumerate(events):
        stored_hash = event.get("event_hash")
        if event.get("hash_version") != 2:
            if stored_hash:
                # Version 1 hashes were generated before BSON timestamp
                # normalization and cannot be reliably revalidated now.
                legacy_hash_format += 1
                previous_anchor = stored_hash
            else:
                legacy_unhashed += 1
                previous_anchor = _audit_event_hash(event)
            continue
        if event.get("previous_hash") != previous_anchor:
            broken.append(index)
        calculated_hash = _audit_event_hash(event)
        if stored_hash != calculated_hash:
            broken.append(index)
        else:
            verified += 1
        previous_anchor = stored_hash
    valid = bool(events) and not broken and legacy_unhashed == 0 and legacy_hash_format == 0
    return {
        target_field: target_id,
        "event_count": len(events),
        "verified_event_count": verified,
        "legacy_unhashed_event_count": legacy_unhashed,
        "legacy_hash_format_event_count": legacy_hash_format,
        "broken_event_indexes": sorted(set(broken)),
        "integrity_valid": valid,
        "status": "NO_AUDIT_EVENTS" if not events else "FAILED" if broken else "LEGACY_EVENTS_PRESENT" if legacy_unhashed or legacy_hash_format else "VERIFIED",
        "checked_at": now(),
    }


def analyze_all(email_id: str) -> dict[str, Any]:
    email = get_email(email_id)
    threat = analyze_threat(email)
    attachments = analyze_attachments(email)
    ips = analyze_ips(email)
    intelligence = correlate_intelligence(email, threat, attachments, ips)
    result = {"threat": threat, "attachments": attachments, "ips": ips, "intelligence": intelligence, "risk": risk(email, refresh_auth=True, refresh_url=True, ip_result=ips, intelligence_result=intelligence)}
    db = get_database()
    for collection, value in (("threat_analysis", threat), ("attachment_analysis", attachments), ("ip_intelligence", ips), ("threat_intelligence", intelligence), ("risk_analysis", result["risk"])):
        db[collection].replace_one({"email_id": email_id}, serialize(value), upsert=True)
    db["emails"].update_one(
        {"email_id": email_id},
        {"$set": {
            "module.risk_analysis": {
                "status": "COMPLETED",
                "risk_score": result["risk"]["score"],
                "risk_level": result["risk"]["risk_level"],
                "updated_at": now(),
            }
        }},
    )
    if result["risk"]["score"] >= 40:
        db["alerts"].update_one(
            {"email_id": email_id, "source": "risk_analysis"},
            {
                "$set": {
                    "case_id": email.get("case_id"),
                    "severity": result["risk"]["risk_level"],
                    "score": result["risk"]["score"],
                    "verdict": result["risk"]["verdict"],
                    "last_evaluated_at": now(),
                },
                "$setOnInsert": {
                    "email_id": email_id,
                    "source": "risk_analysis",
                    "created_at": now(),
                    "status": "OPEN",
                },
            },
            upsert=True,
        )
    else:
        db["alerts"].update_one(
            {"email_id": email_id, "source": "risk_analysis"},
            {"$set": {
                "case_id": email.get("case_id"),
                "score": result["risk"]["score"],
                "verdict": result["risk"]["verdict"],
                "status": "RESOLVED",
                "last_evaluated_at": now(),
            }},
        )
    write_audit(email_id, "ANALYZE_EXTENDED_MODULES", {"modules": [5, 6, 7, 8, 10]})
    return result


def get_stored(collection: str, email_id: str) -> dict[str, Any] | None:
    return get_database()[collection].find_one({"email_id": email_id}, {"_id": 0})


def verify_evidence(email_id: str) -> dict[str, Any]:
    email = get_email(email_id)
    path = Path((email.get("evidence") or {}).get("local_path", ""))
    actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
    expected = email.get("sha256")
    result = {"email_id": email_id, "expected_sha256": expected, "actual_sha256": actual, "exists": path.exists(), "integrity_valid": bool(actual and actual == expected), "checked_at": now()}
    write_audit(email_id, "VERIFY_EVIDENCE", result)
    return result
