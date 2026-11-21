from app.services.authentication.spf_analyzer import (
    parse_spf_record,
    evaluate_spf_record,
)
import app.services.authentication.spf_analyzer as spf_analyzer

from app.services.authentication.dkim_analyzer import (
    parse_tag_value_list,
    validate_dkim_public_key,
)

from app.services.authentication.dmarc_analyzer import (
    parse_dmarc_record,
    domains_aligned,
    get_organizational_domain,
)

from app.services.authentication.authentication_results import (
    parse_authentication_results,
)
from app.services.authentication.dkim_analyzer import (
    analyze_dkim,
)


def test_parse_spf_record():

    record = (
        "v=spf1 ip4:192.0.2.10 "
        "include:_spf.example.com "
        "-all"
    )

    result = parse_spf_record(
        record
    )

    assert result["present"] is True

    assert (
        result["version"]
        == "spf1"
    )

    assert (
        result["all_policy"]
        == "-"
    )

    mechanism_types = [
        item["type"]
        for item in result[
            "mechanisms"
        ]
    ]

    assert "ip4" in mechanism_types

    assert "include" in mechanism_types


def test_spf_ip_match():

    record = (
        "v=spf1 "
        "ip4:192.0.2.10 "
        "-all"
    )

    result = evaluate_spf_record(
        record=record,
        sender_ip="192.0.2.10",
        sender_domain="example.com",
    )

    assert result["result"] == "pass"


def test_spf_ip_fail():

    record = (
        "v=spf1 "
        "ip4:192.0.2.10 "
        "-all"
    )

    result = evaluate_spf_record(
        record=record,
        sender_ip="192.0.2.20",
        sender_domain="example.com",
    )

    assert result["result"] == "fail"


def test_spf_include_is_evaluated_recursively(monkeypatch):
    records = {
        "example.com": "v=spf1 include:_spf.example.com -all",
        "_spf.example.com": "v=spf1 ip4:192.0.2.0/24 -all",
    }
    monkeypatch.setattr(
        spf_analyzer,
        "query_txt",
        lambda domain: [records[domain]],
    )

    result = evaluate_spf_record(
        record=records["example.com"],
        sender_ip="192.0.2.10",
        sender_domain="example.com",
    )

    assert result["result"] == "pass"
    assert result["matched_mechanism"] == "include:_spf.example.com"


def test_dkim_tags():

    signature = (
        "v=1; a=rsa-sha256; "
        "d=example.com; "
        "s=selector1; "
        "bh=ABC123; "
        "b=XYZ456;"
    )

    tags = parse_tag_value_list(
        signature
    )

    assert (
        tags["d"]
        == "example.com"
    )

    assert (
        tags["s"]
        == "selector1"
    )

    assert (
        tags["a"]
        == "rsa-sha256"
    )


def test_dkim_public_key():

    record = (
        "v=DKIM1; "
        "k=rsa; "
        "p=QUJDREVGRw=="
    )

    result = validate_dkim_public_key(
        record
    )

    assert result["present"] is True

    assert (
        result["public_key_present"]
        is True
    )

    assert result["valid"] is False


def test_dkim_revoked_key():

    record = (
        "v=DKIM1; "
        "k=rsa; "
        "p="
    )

    result = validate_dkim_public_key(
        record
    )

    assert (
        result["revoked"]
        is True
    )


def test_dmarc_record():

    record = (
        "v=DMARC1; "
        "p=reject; "
        "adkim=s; "
        "aspf=s; "
        "pct=100"
    )

    result = parse_dmarc_record(
        record
    )

    assert result["present"] is True

    assert result["valid"] is True

    assert (
        result["policy"]
        == "reject"
    )

    assert (
        result["adkim"]
        == "s"
    )

    assert (
        result["aspf"]
        == "s"
    )


def test_dmarc_relaxed_alignment():

    result = domains_aligned(
        header_domain="mail.example.com",
        authenticated_domain="example.com",
        alignment_mode="r",
    )

    assert result is True


def test_dmarc_strict_alignment():

    result = domains_aligned(
        header_domain="mail.example.com",
        authenticated_domain="example.com",
        alignment_mode="s",
    )

    assert result is False


def test_dmarc_uses_public_suffix_aware_organizational_domain():
    assert get_organizational_domain("mail.example.co.uk") == "example.co.uk"
    assert domains_aligned(
        header_domain="mail.example.co.uk",
        authenticated_domain="example.co.uk",
        alignment_mode="r",
    ) is True


def test_authentication_results():

    headers = [
        (
            "mx.example.com; "
            "spf=pass "
            "smtp.mailfrom=example.com; "
            "dkim=pass "
            "header.d=example.com; "
            "dmarc=pass "
            "header.from=example.com"
        )
    ]

    results = (
        parse_authentication_results(
            headers
        )
    )

    assert len(results) == 3

    methods = [
        item["method"]
        for item in results
    ]

    assert "spf" in methods
    assert "dkim" in methods
    assert "dmarc" in methods

    assert all(
        item["result"] == "pass"
        for item in results
    )


def test_dkim_signature_does_not_require_dns_key_tag(monkeypatch):
    signature = (
        "v=1; a=rsa-sha256; d=example.com; s=selector1; "
        "bh=ABC123; b=XYZ456; h=From:To:Subject"
    )

    monkeypatch.setattr(
        "app.services.authentication.dkim_analyzer.query_dkim_record",
        lambda selector, domain: None,
    )

    result = analyze_dkim(
        headers={"dkim-signature": signature}
    )

    assert result["signatures"][0]["structurally_valid"] is True