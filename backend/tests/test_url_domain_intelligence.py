from app.services.url_intelligence.domain_analyzer import (
    analyze_domain,
)
from app.services.url_intelligence.lookalike_detector import (
    detect_lookalike_domain,
    levenshtein_distance,
    similarity_ratio,
)
from app.services.url_intelligence.url_parser import (
    analyze_url,
    extract_domain_from_url,
    extract_urls_from_text,
    normalize_url,
)


def test_normalize_url():
    result = normalize_url(
        "HTTPS://Example.COM/path"
    )

    assert result.startswith(
        "https://"
    )

    assert "example.com" in result


def test_extract_domain():
    result = extract_domain_from_url(
        "https://login.example.com/account"
    )

    assert result == "login.example.com"


def test_ip_address_url():
    result = analyze_url(
        "http://192.168.1.100/login"
    )

    assert result[
        "ip_address_url"
    ] is True

    assert "IP_ADDRESS_URL" in result[
        "indicators"
    ]


def test_punycode_detection():
    result = analyze_url(
        "https://xn--pple-43d.example/login"
    )

    assert result[
        "punycode_domain"
    ] is True


def test_url_shortener_detection():
    result = analyze_url(
        "https://bit.ly/test123"
    )

    assert result[
        "url_shortener"
    ] is True


def test_suspicious_keywords():
    result = analyze_url(
        "https://example.com/login/verify-account"
    )

    assert "login" in result[
        "suspicious_keywords"
    ]

    assert "verify" in result[
        "suspicious_keywords"
    ]


def test_suspicious_query_parameters():
    result = analyze_url(
        "https://example.com/login?redirect=https://evil.example"
    )

    assert result[
        "query_analysis"
    ][
        "suspicious_names"
    ]


def test_domain_analysis():
    result = analyze_domain(
        "secure-login-example.com",
        sender_domain="company.com",
    )

    assert result[
        "domain"
    ] == "secure-login-example.com"

    assert result[
        "risk_score"
    ] >= 0


def test_lookalike_similarity():
    result = similarity_ratio(
        "micr0soft",
        "microsoft",
    )

    assert result > 0.7


def test_levenshtein_distance():
    result = levenshtein_distance(
        "google",
        "goggle",
    )

    assert result == 1


def test_lookalike_domain():
    result = detect_lookalike_domain(
        "micr0soft-login.com"
    )

    assert result[
        "lookalike_detected"
    ] is True


def test_extract_urls_from_text():
    text = """
    Please verify your account:
    https://example.com/login
    """

    urls = extract_urls_from_text(
        text
    )

    assert (
        "https://example.com/login"
        in urls
    )