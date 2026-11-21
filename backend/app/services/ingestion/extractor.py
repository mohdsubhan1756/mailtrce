# backend/app/services/ingestion/extractor.py

import hashlib
import ipaddress
import re
import zipfile
from io import BytesIO
from datetime import datetime
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse


URL_REGEX = re.compile(
    r"""(?i)\b(
        https?://
        [^\s<>"'()]+
    )""",
    re.VERBOSE,
)

IP_REGEX = re.compile(
    r"\b(?:"
    r"(?:25[0-5]|2[0-4][0-9]|"
    r"1[0-9]{2}|[1-9]?[0-9])\."
    r"(?:25[0-5]|2[0-4][0-9]|"
    r"1[0-9]{2}|[1-9]?[0-9])\."
    r"(?:25[0-5]|2[0-4][0-9]|"
    r"1[0-9]{2}|[1-9]?[0-9])\."
    r"(?:25[0-5]|2[0-4][0-9]|"
    r"1[0-9]{2}|[1-9]?[0-9])"
    r")\b"
)


def clean_header_value(
    value: str | None
) -> str | None:

    if value is None:
        return None

    return str(value).strip()


def parse_address_header(
    value: str | None
) -> list[str]:

    if not value:
        return []

    addresses = getaddresses(
        [value]
    )

    result = []

    for _, address in addresses:
        address = address.strip()

        if address:
            result.append(address)

    return result


def extract_sender(
    message: Message
) -> dict[str, Any] | None:

    from_header = message.get(
        "From"
    )

    if not from_header:
        return None

    addresses = getaddresses(
        [from_header]
    )

    if not addresses:
        return None

    display_name, address = addresses[0]

    address = address.strip()

    domain = None

    if "@" in address:
        domain = address.rsplit(
            "@",
            1
        )[1].lower()

    return {
        "display_name": display_name.strip(),
        "address": address,
        "domain": domain
    }


def extract_recipients(
    message: Message
) -> list[str]:

    result = []

    for header_name in [
        "To",
        "Cc"
    ]:

        values = message.get_all(
            header_name,
            []
        )

        for value in values:
            result.extend(
                parse_address_header(
                    value
                )
            )

    return result


def extract_body(
    message: Message
) -> dict[str, Any]:

    plain_text_parts = []

    html_parts = []

    if message.is_multipart():

        for part in message.walk():

            if part.is_multipart():
                continue

            content_disposition = (
                part.get_content_disposition()
            )

            if content_disposition == "attachment":
                continue

            content_type = (
                part.get_content_type()
            )

            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(
                    decode=True
                )

                if payload is None:
                    continue

                charset = (
                    part.get_content_charset()
                    or "utf-8"
                )

                content = payload.decode(
                    charset,
                    errors="replace"
                )

            if content_type == "text/plain":
                plain_text_parts.append(
                    str(content)
                )

            elif content_type == "text/html":
                html_parts.append(
                    str(content)
                )

    else:

        content_type = (
            message.get_content_type()
        )

        try:
            content = message.get_content()
        except Exception:
            payload = message.get_payload(
                decode=True
            )

            if payload:
                charset = (
                    message.get_content_charset()
                    or "utf-8"
                )

                content = payload.decode(
                    charset,
                    errors="replace"
                )
            else:
                content = ""

        if content_type == "text/plain":
            plain_text_parts.append(
                str(content)
            )

        elif content_type == "text/html":
            html_parts.append(
                str(content)
            )

    plain_text = "\n".join(
        plain_text_parts
    ).strip()

    html = "\n".join(
        html_parts
    ).strip()

    return {
        "plain_text": plain_text,
        "html": html,
        "plain_text_length": len(
            plain_text
        ),
        "html_length": len(
            html
        )
    }


def extract_urls(
    body: dict[str, Any]
) -> list[dict[str, Any]]:

    combined_text = (
        body.get("plain_text", "")
        + "\n"
        + body.get("html", "")
    )

    matches = URL_REGEX.findall(
        combined_text
    )

    results = []

    seen = set()

    for url in matches:

        url = url.rstrip(
            ".,;:!?)]}>\"'"
        )

        if not url:
            continue

        if url in seen:
            continue

        seen.add(url)

        parsed = urlparse(
            url
        )

        hostname = parsed.hostname

        if hostname:
            hostname = hostname.lower()

        results.append(
            {
                "url": url,
                "scheme": parsed.scheme.lower(),
                "hostname": hostname,
                "port": parsed.port,
                "path": parsed.path,
                "query": parsed.query,
                "fragment": parsed.fragment
            }
        )

    return results


def extract_domains(
    urls: list[dict[str, Any]]
) -> list[str]:

    domains = set()

    for item in urls:

        hostname = item.get(
            "hostname"
        )

        if not hostname:
            continue

        hostname = hostname.lower().strip()

        if hostname:
            domains.add(
                hostname
            )

    return sorted(
        domains
    )


def extract_ips(
    text: str
) -> list[str]:

    candidates = IP_REGEX.findall(
        text
    )

    valid_ips = set()

    for candidate in candidates:

        try:
            ipaddress.ip_address(
                candidate
            )

            valid_ips.add(
                candidate
            )

        except ValueError:
            continue

    return sorted(
        valid_ips
    )


def extract_received_headers(
    message: Message
) -> list[str]:

    values = message.get_all(
        "Received",
        []
    )

    return [
        str(value).strip()
        for value in values
    ]


def extract_authentication_results(
    message: Message
) -> list[str]:

    values = message.get_all(
        "Authentication-Results",
        []
    )

    return [
        str(value).strip()
        for value in values
    ]


def parse_message_date(
    message: Message
) -> datetime | None:

    value = message.get(
        "Date"
    )

    if not value:
        return None

    try:
        return parsedate_to_datetime(
            value
        )

    except (TypeError, ValueError, IndexError):
        return None


def extract_headers(
    message: Message
) -> dict[str, Any]:

    headers = {}

    for key, value in message.items():

        normalized_key = key.lower()

        if normalized_key in headers:

            if isinstance(
                headers[normalized_key],
                list
            ):
                headers[
                    normalized_key
                ].append(
                    str(value)
                )

            else:
                headers[
                    normalized_key
                ] = [
                    headers[
                        normalized_key
                    ],
                    str(value)
                ]

        else:
            headers[
                normalized_key
            ] = str(value)

    return headers


def extract_attachments(
    message: Message
) -> list[dict[str, Any]]:

    attachments = []

    if not message.is_multipart():
        return attachments

    for index, part in enumerate(
        message.walk()
    ):

        if part.is_multipart():
            continue

        disposition = (
            part.get_content_disposition()
        )

        filename = part.get_filename()

        is_attachment = (
            disposition == "attachment"
            or filename is not None
        )

        if not is_attachment:
            continue

        payload = part.get_payload(
            decode=True
        )

        if payload is None:
            payload = b""

        content_type = (
            part.get_content_type()
        )

        attachments.append(
            {
                "index": index,
                "filename": filename,
                "content_type": content_type,
                "content_disposition": disposition,
                "size": len(payload),
                "sha256": hashlib.sha256(
                    payload
                ).hexdigest(),
                **inspect_attachment(payload),
            }
        )

    return attachments


def inspect_attachment(payload: bytes) -> dict[str, Any]:
    """Inspect lightweight file signatures and archive metadata without extraction."""
    signatures = (
        (b"%PDF-", "PDF"),
        (b"MZ", "Windows executable"),
        (b"\x7fELF", "ELF executable"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document"),
        (b"{\\rtf", "RTF document"),
    )
    detected = next((name for signature, name in signatures if payload.startswith(signature)), None)
    result: dict[str, Any] = {"detected_file_type": detected, "archive_analysis": None}
    if not payload.startswith(b"PK\x03\x04"):
        return result

    try:
        with zipfile.ZipFile(BytesIO(payload)) as archive:
            members = archive.infolist()[:500]
            names = [member.filename for member in members]
            dangerous_members = [name for name in names if name.lower().endswith((".exe", ".dll", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".scr"))]
            macro_project = any(name.lower().endswith("vbaproject.bin") for name in names)
            traversal_members = [name for name in names if name.startswith(("/", "\\")) or ".." in name.replace("\\", "/").split("/")]
            result["archive_analysis"] = {
                "valid_zip": True,
                "member_count": len(archive.infolist()),
                "inspected_member_count": len(members),
                "truncated": len(archive.infolist()) > len(members),
                "encrypted_members": sum(bool(member.flag_bits & 0x1) for member in members),
                "dangerous_members": dangerous_members[:50],
                "macro_project_present": macro_project,
                "path_traversal_members": traversal_members[:50],
            }
    except (OSError, zipfile.BadZipFile, RuntimeError):
        result["archive_analysis"] = {"valid_zip": False, "reason": "ZIP signature present but archive directory could not be read"}
    return result


def extract_mime_information(
    message: Message
) -> dict[str, Any]:

    parts = []

    if message.is_multipart():

        for index, part in enumerate(
            message.walk()
        ):

            if part.is_multipart():
                continue

            payload = part.get_payload(
                decode=True
            )

            parts.append(
                {
                    "index": index,
                    "content_type": part.get_content_type(),
                    "content_disposition": (
                        part.get_content_disposition()
                    ),
                    "filename": part.get_filename(),
                    "size": len(payload)
                    if payload
                    else 0
                }
            )

    else:

        payload = message.get_payload(
            decode=True
        )

        parts.append(
            {
                "index": 0,
                "content_type": message.get_content_type(),
                "content_disposition": (
                    message.get_content_disposition()
                ),
                "filename": message.get_filename(),
                "size": len(payload)
                if payload
                else 0
            }
        )

    return {
        "is_multipart": message.is_multipart(),
        "content_type": message.get_content_type(),
        "mime_version": message.get(
            "MIME-Version"
        ),
        "parts": parts
    }


def extract_email_data(
    message: Message
) -> dict[str, Any]:

    body = extract_body(
        message
    )

    urls = extract_urls(
        body
    )

    domains = extract_domains(
        urls
    )

    all_text = (
        body.get("plain_text", "")
        + "\n"
        + body.get("html", "")
    )

    ip_addresses = extract_ips(
        all_text
    )

    received_headers = (
        extract_received_headers(
            message
        )
    )

    authentication_results = (
        extract_authentication_results(
            message
        )
    )

    received_text = "\n".join(
        received_headers
    )

    ip_addresses = sorted(
        set(
            ip_addresses
            + extract_ips(
                received_text
            )
        )
    )

    date_value = parse_message_date(
        message
    )

    return {
        "sender": extract_sender(
            message
        ),

        "recipients": parse_address_header(
            message.get("To")
        ),

        "cc": parse_address_header(
            message.get("Cc")
        ),

        "bcc": parse_address_header(
            message.get("Bcc")
        ),

        "subject": clean_header_value(
            message.get("Subject")
        ),

        "timestamp": date_value,

        "message_id": clean_header_value(
            message.get("Message-ID")
        ),

        "return_path": clean_header_value(
            message.get("Return-Path")
        ),

        "reply_to": clean_header_value(
            message.get("Reply-To")
        ),

        "sender_header": clean_header_value(
            message.get("Sender")
        ),

        "headers": extract_headers(
            message
        ),

        "received_headers": received_headers,

        "authentication_results": (
            authentication_results
        ),

        "body": body,

        "urls": urls,

        "domains": domains,

        "ip_addresses": ip_addresses,

        "attachments": extract_attachments(
            message
        ),

        "mime": extract_mime_information(
            message
        )
    }
