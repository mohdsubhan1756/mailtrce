from app.services.extended_analysis import (
    analyze_attachments,
    analyze_ips,
    analyze_threat,
)
from app.services.geoip import lookup_local


def make_email():
    return {
        "email_id": "EMAIL-TEST",
        "case_id": "CASE-TEST",
        "subject": "Urgent account verification required",
        "sender": {"domain": "example.com"},
        "body": {
            "plain_text": "Please verify your password immediately.",
            "html": "",
        },
        "urls": [{"hostname": "outside.example", "url": "https://outside.example/login"}],
        "attachments": [{
            "filename": "invoice.pdf.exe",
            "content_type": "application/octet-stream",
            "content_disposition": "attachment",
            "size": 10,
            "sha256": "a" * 64,
        }],
        "ip_addresses": ["203.0.113.10", "192.168.1.2"],
        "received_headers": [],
    }


def test_threat_analysis_detects_credential_urgency():
    result = analyze_threat(make_email())
    codes = {item["code"] for item in result["findings"]}
    assert "URGENCY" in codes
    assert "CREDENTIAL_REQUEST" in codes
    assert result["score"] > 0


def test_attachment_analysis_detects_double_extension():
    result = analyze_attachments(make_email())
    codes = {item["code"] for item in result["findings"]}
    assert "DANGEROUS_ATTACHMENT" in codes
    assert "DOUBLE_EXTENSION" in codes
    assert result["attachments"][0]["sha256"] == "a" * 64


def test_ip_analysis_classifies_local_and_documentation_ranges():
    result = analyze_ips(make_email())
    by_ip = {item["ip"]: item for item in result["ips"]}
    assert by_ip["192.168.1.2"]["private"] is True
    assert by_ip["203.0.113.10"]["documentation_range"] is True
    assert result["external_reputation_queried"] is False


def test_ip_analysis_does_not_geolocate_reserved_addresses():
    result = analyze_ips({
        "email_id": "EMAIL-RESERVED",
        "case_id": "CASE-TEST",
        "ip_addresses": ["192.0.2.10"],
        "received_headers": [],
    })
    item = result["ips"][0]
    assert item["documentation_range"] is True
    assert "geolocation" not in item


def test_local_geolocation_reports_missing_database_cleanly():
    result = lookup_local("8.8.8.8")
    assert result["source"] == "local city database"
    if result["available"]:
        assert result["country"]
    else:
        assert "database" in result["reason"].lower()
