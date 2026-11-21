from app.services.header_forensics.received_parser import (
    parse_received_chain,
)

from app.services.header_forensics.routing_analyzer import (
    analyze_routing,
)

from app.services.header_forensics.header_analyzer import (
    analyze_headers,
)


def test_received_parser():
    headers = [
        (
            "from mail.example.com "
            "(203.0.113.10) "
            "by mx.example.com "
            "with ESMTP id ABC123 "
            "for <user@example.com>; "
            "Mon, 14 Sep 2026 10:00:00 +0000"
        )
    ]

    hops = parse_received_chain(
        headers
    )

    assert len(hops) == 1

    assert (
        hops[0]["from_host"]
        == "mail.example.com"
    )

    assert (
        hops[0]["by_host"]
        == "mx.example.com"
    )

    assert (
        hops[0]["from_ip"]
        == "203.0.113.10"
    )

    assert (
        hops[0]["parsed_timestamp"]
        is True
    )


def test_routing_analysis():
    headers = [
        (
            "from mail.example.com "
            "(203.0.113.10) "
            "by mx.example.com "
            "with ESMTP; "
            "Mon, 14 Sep 2026 10:00:00 +0000"
        ),
        (
            "from workstation "
            "(192.168.1.20) "
            "by mail.example.com "
            "with ESMTP; "
            "Mon, 14 Sep 2026 09:59:00 +0000"
        ),
    ]

    result = analyze_routing(
        headers
    )

    assert result["hop_count"] == 2

    assert (
        "203.0.113.10"
        in result["unique_ips"]
    )

    assert (
        "192.168.1.20"
        in result["unique_ips"]
    )

    assert (
        result["chronology_valid"]
        is True
    )


def test_reply_to_mismatch():
    routing = analyze_routing(
        [
            (
                "from mail.example.com "
                "(203.0.113.10) "
                "by mx.example.com "
                "with ESMTP; "
                "Mon, 14 Sep 2026 10:00:00 +0000"
            )
        ]
    )

    result = analyze_headers(
        sender={
            "display_name": "CEO",
            "address": "ceo@example.com",
            "domain": "example.com",
        },
        reply_to={
            "display_name": None,
            "address": "attacker@evil.example",
            "domain": "evil.example",
        },
        return_path=(
            "bounce@example.com"
        ),
        sender_header=None,
        message_id=(
            "<abc123@example.com>"
        ),
        routing_analysis=routing,
    )

    codes = [
        finding["code"]
        for finding in result["findings"]
    ]

    assert (
        "REPLY_TO_MISMATCH"
        in codes
    )


def test_return_path_mismatch():
    routing = analyze_routing([])

    result = analyze_headers(
        sender={
            "display_name": "CEO",
            "address": "ceo@example.com",
            "domain": "example.com",
        },
        reply_to=None,
        return_path=(
            "bounce@another-domain.com"
        ),
        sender_header=None,
        message_id=(
            "<abc123@example.com>"
        ),
        routing_analysis=routing,
    )

    codes = [
        finding["code"]
        for finding in result["findings"]
    ]

    assert (
        "RETURN_PATH_MISMATCH"
        in codes
    )


def test_invalid_message_id():
    routing = analyze_routing([])

    result = analyze_headers(
        sender={
            "display_name": "User",
            "address": "user@example.com",
            "domain": "example.com",
        },
        reply_to=None,
        return_path=None,
        sender_header=None,
        message_id="invalid-message-id",
        routing_analysis=routing,
    )

    codes = [
        finding["code"]
        for finding in result["findings"]
    ]

    assert (
        "INVALID_MESSAGE_ID"
        in codes
    )