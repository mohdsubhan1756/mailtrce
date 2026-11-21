# backend/app/services/ingestion/normalizer.py

import re
from typing import Any
from email.utils import getaddresses


WHITESPACE_REGEX = re.compile(
    r"\s+"
)


def normalize_email_address(
    address: str
) -> str:

    return address.strip().lower()


def normalize_address_list(
    addresses: list[str]
) -> list[str]:

    normalized = []

    seen = set()

    for address in addresses:

        address = normalize_email_address(
            address
        )

        if not address:
            continue

        if address in seen:
            continue

        seen.add(address)

        normalized.append(
            address
        )

    return normalized


def normalize_domain(
    domain: str | None
) -> str | None:

    if not domain:
        return None

    return domain.strip().lower().rstrip(".")


def normalize_sender(
    sender: dict[str, Any] | None
) -> dict[str, Any] | None:

    if not sender:
        return None

    address = normalize_email_address(
        sender.get(
            "address",
            ""
        )
    )

    display_name = (
        sender.get(
            "display_name"
        )
        or ""
    ).strip()

    domain = None

    if "@" in address:

        domain = normalize_domain(
            address.rsplit(
                "@",
                1
            )[1]
        )

    return {
        "display_name": display_name,
        "address": address,
        "domain": domain
    }


def normalize_subject(
    subject: str | None
) -> str | None:

    if subject is None:
        return None

    subject = WHITESPACE_REGEX.sub(
        " ",
        subject
    )

    return subject.strip()


def normalize_received_headers(
    received_headers: list[str]
) -> list[str]:

    return [
        value.strip()
        for value in received_headers
        if value and value.strip()
    ]


def normalize_urls(
    urls: list[dict[str, Any]]
) -> list[dict[str, Any]]:

    normalized = []

    seen = set()

    for item in urls:

        url = (
            item.get("url")
            or ""
        ).strip()

        if not url:
            continue

        if url in seen:
            continue

        seen.add(url)

        normalized_item = {
            "url": url,
            "scheme": (
                item.get("scheme")
                or ""
            ).lower(),
            "hostname": normalize_domain(
                item.get("hostname")
            ),
            "port": item.get("port"),
            "path": item.get("path") or "",
            "query": item.get("query") or "",
            "fragment": item.get("fragment") or ""
        }

        normalized.append(
            normalized_item
        )

    return normalized


def normalize_domains(
    domains: list[str]
) -> list[str]:

    normalized = set()

    for domain in domains:

        domain = normalize_domain(
            domain
        )

        if domain:
            normalized.add(
                domain
            )

    return sorted(
        normalized
    )


def normalize_ip_addresses(
    ips: list[str]
) -> list[str]:

    normalized = set()

    for ip in ips:

        ip = ip.strip()

        if ip:
            normalized.add(
                ip
            )

    return sorted(
        normalized
    )


def normalize_attachments(
    attachments: list[dict[str, Any]]
) -> list[dict[str, Any]]:

    normalized = []

    for attachment in attachments:

        normalized.append(
            {
                "index": attachment.get(
                    "index"
                ),

                "filename": (
                    attachment.get(
                        "filename"
                    )
                    or ""
                ).strip(),

                "content_type": (
                    attachment.get(
                        "content_type"
                    )
                    or "application/octet-stream"
                ).lower(),

                "content_disposition": (
                    attachment.get(
                        "content_disposition"
                    )
                ),

                "size": int(
                    attachment.get(
                        "size",
                        0
                    )
                ),

                "sha256": (
                    attachment.get(
                        "sha256"
                    )
                    or ""
                ),
            }
        )

    return normalized


def normalize_email_data(
    data: dict[str, Any]
) -> dict[str, Any]:

    sender = normalize_sender(
        data.get("sender")
    )

    recipients = normalize_address_list(
        data.get(
            "recipients",
            []
        )
    )

    cc = normalize_address_list(
        data.get(
            "cc",
            []
        )
    )

    bcc = normalize_address_list(
        data.get(
            "bcc",
            []
        )
    )

    subject = normalize_subject(
        data.get("subject")
    )

    urls = normalize_urls(
        data.get(
            "urls",
            []
        )
    )

    domains = normalize_domains(
        data.get(
            "domains",
            []
        )
    )

    # Always include domains obtained
    # from normalized URLs.
    url_domains = {
        item["hostname"]
        for item in urls
        if item.get("hostname")
    }

    domains = sorted(
        set(domains)
        | url_domains
    )

    ip_addresses = normalize_ip_addresses(
        data.get(
            "ip_addresses",
            []
        )
    )

    attachments = normalize_attachments(
        data.get(
            "attachments",
            []
        )
    )

    received_headers = (
        normalize_received_headers(
            data.get(
                "received_headers",
                []
            )
        )
    )

    return {
        "sender": sender,

        "recipients": recipients,

        "cc": cc,

        "bcc": bcc,

        "subject": subject,

        "timestamp": data.get(
            "timestamp"
        ),

        "message_id": data.get(
            "message_id"
        ),

        "return_path": data.get(
            "return_path"
        ),

        "reply_to": data.get(
            "reply_to"
        ),

        "sender_header": data.get(
            "sender_header"
        ),

        "headers": data.get(
            "headers",
            {}
        ),

        "received_headers": received_headers,

        "authentication_results": data.get(
            "authentication_results",
            []
        ),

        "body": data.get(
            "body",
            {}
        ),

        "urls": urls,

        "domains": domains,

        "ip_addresses": ip_addresses,

        "attachments": attachments,

        "mime": data.get(
            "mime",
            {}
        )
    }