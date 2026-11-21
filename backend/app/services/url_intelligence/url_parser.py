from __future__ import annotations

import ipaddress
import re
from urllib.parse import (
    parse_qsl,
    unquote,
    urljoin,
    urlparse,
)


SUSPICIOUS_URL_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "password",
    "reset",
    "confirm",
    "confirmation",
    "authenticate",
    "authentication",
    "wallet",
    "payment",
    "invoice",
    "document",
    "attachment",
    "shared",
    "recover",
    "unlock",
    "webmail",
    "office365",
    "bank",
    "banking",
}


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "rebrand.ly",
}


SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "country",
    "gq",
    "tk",
    "ml",
    "ga",
    "cf",
    "work",
    "download",
    "stream",
    "top",
    "fit",
    "buzz",
    "rest",
    "support",
}


def ensure_scheme(url: str) -> str:
    """
    Ensure the URL can be parsed even when the scheme is missing.
    """
    url = str(url or "").strip()

    if not url:
        return ""

    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        return url

    return "http://" + url


def normalize_url(url: str) -> str:
    """
    Normalize a URL while preserving its important forensic components.
    """
    url = str(url or "").strip()

    if not url:
        return ""

    url = url.replace("\r", "").replace("\n", "")
    url = url.strip("<>\"'")

    parsed = urlparse(ensure_scheme(url))

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower().rstrip(".")

    if not hostname:
        return url

    try:
        port = parsed.port
    except ValueError:
        port = None

    netloc = hostname

    if parsed.username:
        username = parsed.username
        password = parsed.password

        if password:
            netloc = f"{username}:{password}@{netloc}"
        else:
            netloc = f"{username}@{netloc}"

    if port:
        default_port = (
            (scheme == "http" and port == 80)
            or (scheme == "https" and port == 443)
        )

        if not default_port:
            netloc = f"{netloc}:{port}"

    normalized = parsed._replace(
        scheme=scheme,
        netloc=netloc,
    ).geturl()

    return normalized


def extract_domain_from_url(url: str) -> str | None:
    try:
        parsed = urlparse(ensure_scheme(url))
        hostname = parsed.hostname

        if not hostname:
            return None

        return hostname.lower().rstrip(".")
    except Exception:
        return None


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_domain_parts(domain: str) -> dict:
    domain = (domain or "").lower().strip(".")

    if not domain:
        return {
            "hostname": "",
            "labels": [],
            "label_count": 0,
            "tld": "",
            "base_domain": "",
        }

    labels = [label for label in domain.split(".") if label]

    tld = labels[-1] if labels else ""

    if len(labels) >= 2:
        base_domain = ".".join(labels[-2:])
    else:
        base_domain = domain

    return {
        "hostname": domain,
        "labels": labels,
        "label_count": len(labels),
        "tld": tld,
        "base_domain": base_domain,
    }


def count_special_characters(value: str) -> int:
    return len(re.findall(r"[^a-zA-Z0-9]", value or ""))


def detect_percent_encoding(url: str) -> bool:
    return bool(re.search(r"%[0-9A-Fa-f]{2}", url or ""))


def detect_hex_ip(url: str) -> bool:
    """
    Detect common hexadecimal IP representation.
    """
    parsed = urlparse(ensure_scheme(url))
    hostname = parsed.hostname or ""

    if hostname.lower().startswith("0x"):
        return True

    return False


def detect_decimal_ip(url: str) -> bool:
    """
    Detect decimal integer IPv4 representation.
    Example:
    http://3232235777/
    """
    parsed = urlparse(ensure_scheme(url))
    hostname = parsed.hostname or ""

    if hostname.isdigit():
        try:
            value = int(hostname)

            return 0 <= value <= 4294967295
        except ValueError:
            return False

    return False


def extract_url_keywords(url: str) -> list[str]:
    decoded = unquote(url or "").lower()

    found = []

    for keyword in SUSPICIOUS_URL_KEYWORDS:
        if keyword in decoded:
            found.append(keyword)

    return sorted(set(found))


def analyze_query_parameters(url: str) -> dict:
    parsed = urlparse(ensure_scheme(url))

    parameters = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    parameter_names = [key for key, _ in parameters]

    suspicious_parameter_names = []

    suspicious_names = {
        "redirect",
        "url",
        "target",
        "next",
        "return",
        "returnurl",
        "continue",
        "dest",
        "destination",
        "link",
        "redirect_uri",
        "redirect_url",
        "token",
        "auth",
        "session",
        "code",
    }

    for name in parameter_names:
        if name.lower() in suspicious_names:
            suspicious_parameter_names.append(name)

    return {
        "count": len(parameters),
        "names": parameter_names,
        "suspicious_names": suspicious_parameter_names,
    }


def analyze_url(
    url: str,
    sender_domain: str | None = None,
) -> dict:
    original_url = str(url or "").strip()

    normalized_url = normalize_url(original_url)

    parsed = urlparse(ensure_scheme(normalized_url))

    hostname = (parsed.hostname or "").lower().rstrip(".")

    domain_parts = get_domain_parts(hostname)

    try:
        port = parsed.port
    except ValueError:
        port = None

    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    decoded_url = unquote(normalized_url)

    keywords = extract_url_keywords(decoded_url)

    query_analysis = analyze_query_parameters(normalized_url)

    ip_url = is_ip_address(hostname)

    username_present = bool(parsed.username)

    password_present = bool(parsed.password)

    excessive_subdomains = domain_parts["label_count"] >= 5

    punycode_domain = any(
        label.startswith("xn--")
        for label in domain_parts["labels"]
    )

    suspicious_tld = (
        domain_parts["tld"] in SUSPICIOUS_TLDS
    )

    url_shortener = hostname in SHORTENER_DOMAINS

    suspicious_port = port not in (None, 80, 443)

    encoded_content = detect_percent_encoding(normalized_url)

    hex_ip = detect_hex_ip(normalized_url)

    decimal_ip = detect_decimal_ip(normalized_url)

    at_symbol = "@" in normalized_url

    double_slash_in_path = "//" in path

    long_url = len(normalized_url) > 180

    very_long_url = len(normalized_url) > 300

    long_hostname = len(hostname) > 70

    special_character_count = count_special_characters(
        normalized_url
    )

    sender_domain_normalized = (
        (sender_domain or "")
        .lower()
        .strip(".")
    )

    domain_matches_sender = False

    if sender_domain_normalized and hostname:
        domain_matches_sender = (
            hostname == sender_domain_normalized
            or hostname.endswith(
                "." + sender_domain_normalized
            )
        )

    indicators = []

    if ip_url:
        indicators.append("IP_ADDRESS_URL")

    if username_present:
        indicators.append("URL_USERNAME")

    if password_present:
        indicators.append("URL_PASSWORD")

    if at_symbol:
        indicators.append("AT_SYMBOL")

    if punycode_domain:
        indicators.append("PUNYCODE_DOMAIN")

    if suspicious_tld:
        indicators.append("SUSPICIOUS_TLD")

    if excessive_subdomains:
        indicators.append("EXCESSIVE_SUBDOMAINS")

    if url_shortener:
        indicators.append("URL_SHORTENER")

    if suspicious_port:
        indicators.append("SUSPICIOUS_PORT")

    if encoded_content:
        indicators.append("PERCENT_ENCODING")

    if hex_ip:
        indicators.append("HEX_IP")

    if decimal_ip:
        indicators.append("DECIMAL_IP")

    if double_slash_in_path:
        indicators.append("DOUBLE_SLASH_PATH")

    if long_url:
        indicators.append("LONG_URL")

    if very_long_url:
        indicators.append("VERY_LONG_URL")

    if long_hostname:
        indicators.append("LONG_HOSTNAME")

    if keywords:
        indicators.append("SUSPICIOUS_KEYWORDS")

    if query_analysis["suspicious_names"]:
        indicators.append("SUSPICIOUS_QUERY_PARAMETERS")

    risk_score = 0

    if ip_url:
        risk_score += 30

    if username_present:
        risk_score += 20

    if password_present:
        risk_score += 30

    if punycode_domain:
        risk_score += 20

    if suspicious_tld:
        risk_score += 15

    if excessive_subdomains:
        risk_score += 15

    if url_shortener:
        risk_score += 10

    if suspicious_port:
        risk_score += 15

    if encoded_content:
        risk_score += 5

    if hex_ip:
        risk_score += 25

    if decimal_ip:
        risk_score += 25

    if double_slash_in_path:
        risk_score += 10

    if long_url:
        risk_score += 5

    if very_long_url:
        risk_score += 5

    if long_hostname:
        risk_score += 5

    if keywords:
        risk_score += min(20, len(keywords) * 5)

    if query_analysis["suspicious_names"]:
        risk_score += min(
            15,
            len(query_analysis["suspicious_names"]) * 5,
        )

    risk_score = min(100, risk_score)

    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    elif risk_score >= 15:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    return {
        "original_url": original_url,
        "normalized_url": normalized_url,
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        "domain": domain_parts["base_domain"],
        "port": port,
        "path": path,
        "query": query,
        "fragment": fragment,
        "username_present": username_present,
        "password_present": password_present,
        "ip_address_url": ip_url,
        "hex_ip_url": hex_ip,
        "decimal_ip_url": decimal_ip,
        "punycode_domain": punycode_domain,
        "suspicious_tld": suspicious_tld,
        "url_shortener": url_shortener,
        "suspicious_port": suspicious_port,
        "percent_encoded": encoded_content,
        "double_slash_path": double_slash_in_path,
        "long_url": long_url,
        "very_long_url": very_long_url,
        "long_hostname": long_hostname,
        "excessive_subdomains": excessive_subdomains,
        "suspicious_keywords": keywords,
        "query_analysis": query_analysis,
        "special_character_count": special_character_count,
        "domain_matches_sender": domain_matches_sender,
        "sender_domain": sender_domain_normalized,
        "indicators": indicators,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


def extract_urls_from_text(
    text: str,
    base_url: str | None = None,
) -> list[str]:
    """
    Extract HTTP/HTTPS URLs from arbitrary text.
    """
    if not text:
        return []

    pattern = re.compile(
        r"(?i)\b(?:https?://|www\.)"
        r"[^\s<>'\"`]+"
    )

    matches = pattern.findall(text)

    results = []

    for match in matches:
        clean = match.rstrip(
            ".,;:!?)]}>\"'"
        )

        if base_url:
            clean = urljoin(base_url, clean)

        if clean:
            results.append(clean)

    return sorted(set(results))
