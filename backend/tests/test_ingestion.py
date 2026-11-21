# backend/tests/test_ingestion.py

from pathlib import Path

from app.services.ingestion.eml_parser import parse_eml
from app.services.ingestion.extractor import (
    extract_email_data
)
from app.services.ingestion.normalizer import (
    normalize_email_data
)


SAMPLE_PATH = Path(
    __file__
).parent / "sample.eml"


def load_sample() -> bytes:

    return SAMPLE_PATH.read_bytes()


def test_eml_parsing():

    raw = load_sample()

    message = parse_eml(
        raw
    )

    assert message is not None

    assert message.get("Subject")


def test_sender_extraction():

    raw = load_sample()

    message = parse_eml(
        raw
    )

    extracted = extract_email_data(
        message
    )

    assert extracted["sender"] is not None

    assert "@" in extracted["sender"]["address"]


def test_recipient_extraction():

    raw = load_sample()

    message = parse_eml(
        raw
    )

    extracted = extract_email_data(
        message
    )

    assert extracted["recipients"]


def test_subject_extraction():

    raw = load_sample()

    message = parse_eml(
        raw
    )

    extracted = extract_email_data(
        message
    )

    assert extracted["subject"]


def test_message_id_extraction():

    raw = load_sample()

    message = parse_eml(
        raw
    )

    extracted = extract_email_data(
        message
    )

    assert extracted["message_id"].startswith("<")


def test_return_path_extraction():

    raw = load_sample()

    message = parse_eml(
        raw
    )

    extracted = extract_email_data(
        message
    )

    assert extracted["return_path"]


def test_reply_to_extraction():

    raw = load_sample()

    message = parse_eml(
        raw
    )

    extracted = extract_email_data(
        message
    )

    assert extracted["reply_to"]


def test_received_header_extraction():

    raw = load_sample()

    message = parse_eml(
        raw
    )

    extracted = extract_email_data(
        message
    )

    assert len(
        extracted["received_headers"]
    ) >= 1


def test_authentication_results_extraction():

    raw = load_sample()

    message = parse_eml(
        raw
    )

    extracted = extract_email_data(
        message
    )

    assert len(
        extracted["authentication_results"]
    ) >= 1


def test_url_extraction():

    raw = load_sample()

    message = parse_eml(
        raw
    )

    extracted = extract_email_data(
        message
    )

    urls = extracted["urls"]

    assert len(urls) >= 1

    assert all(item["hostname"] for item in urls)


def test_domain_extraction():

    raw = load_sample()

    message = parse_eml(
        raw
    )

    extracted = extract_email_data(
        message
    )

    assert extracted["domains"]


def test_ip_extraction():

    raw = load_sample()

    message = parse_eml(
        raw
    )

    extracted = extract_email_data(
        message
    )

    assert extracted["ip_addresses"]


def test_attachment_extraction():

    raw = load_sample()

    message = parse_eml(
        raw
    )

    extracted = extract_email_data(
        message
    )

    attachments = extracted[
        "attachments"
    ]

    assert len(
        attachments
    ) == 1

    assert attachments[0]["filename"]


def test_normalization():

    raw = load_sample()

    message = parse_eml(
        raw
    )

    extracted = extract_email_data(
        message
    )

    normalized = normalize_email_data(
        extracted
    )

    assert "@" in normalized["sender"]["address"]

    assert normalized["sender"]["domain"]