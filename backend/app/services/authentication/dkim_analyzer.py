import base64
import hashlib
import re
from typing import Any

from email import policy
from email.parser import BytesParser

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.services.authentication.dns_resolver import (
    query_txt,
)


DKIM_REQUIRED_TAGS = {
    "v",
    "a",
    "d",
    "s",
    "h",
    "bh",
    "b",
}
SUPPORTED_ALGORITHMS = {
    "rsa-sha1": hashes.SHA1,
    "rsa-sha256": hashes.SHA256,
}


def parse_tag_value_list(
    value: str | None,
) -> dict[str, str]:

    result: dict[str, str] = {}

    if not value:
        return result

    parts = value.split(";")

    for part in parts:
        part = part.strip()

        if not part or "=" not in part:
            continue

        key, tag_value = part.split(
            "=",
            1,
        )

        key = key.strip().lower()
        tag_value = tag_value.strip()

        result[key] = tag_value

    return result


def extract_dkim_headers(
    headers: dict[str, Any],
) -> list[str]:

    result: list[str] = []

    for key, value in headers.items():

        if key.lower() != "dkim-signature":
            continue

        if isinstance(value, list):
            result.extend(
                str(item)
                for item in value
            )
        else:
            result.append(
                str(value)
            )

    return result


def get_dkim_selector_domain(
    signature: str,
) -> tuple[str | None, str | None]:

    tags = parse_tag_value_list(
        signature
    )

    selector = tags.get("s")
    domain = tags.get("d")

    return selector, domain


def query_dkim_record(
    selector: str,
    domain: str,
) -> str | None:

    query_domain = (
        f"{selector}._domainkey.{domain}"
    )

    records = query_txt(
        query_domain
    )

    for record in records:

        if record.lower().startswith(
            "v=dkim1"
        ):
            return record

        if "p=" in record.lower():
            return record

    return None


def validate_dkim_public_key(
    record: str | None,
) -> dict[str, Any]:

    result = {
        "present": record is not None,
        "valid": False,
        "version": None,
        "key_type": None,
        "public_key_present": False,
        "revoked": False,
        "tags": {},
    }

    if not record:
        return result

    tags = parse_tag_value_list(
        record
    )

    result["tags"] = tags

    result["version"] = tags.get("v")
    result["key_type"] = tags.get(
        "k",
        "rsa",
    )

    public_key = tags.get("p")

    result["public_key_present"] = bool(
        public_key
    )

    if public_key == "":
        result["revoked"] = True

        return result

    if not public_key:
        return result

    required = (
        "p" in tags
    )

    if "v" in tags:
        version_valid = (
            tags["v"].lower()
            == "dkim1"
        )
    else:
        version_valid = True

    try:
        key_bytes = base64.b64decode(
            public_key
            + "="
            * (
                (-len(public_key))
                % 4
            ),
            validate=True,
        )
        public = serialization.load_der_public_key(key_bytes)
        base64_valid = isinstance(public, rsa.RSAPublicKey) and public.key_size >= 1024

    except (
        ValueError,
        base64.binascii.Error,
    ):
        base64_valid = False

    result["valid"] = (
        required
        and version_valid
        and result["key_type"].lower() == "rsa"
        and base64_valid
    )

    return result


def _canonicalize_body(body: bytes, mode: str) -> bytes:
    lines = body.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
    while lines and lines[-1] == b"":
        lines.pop()
    if mode == "relaxed":
        lines = [re.sub(rb"[ \t]+", b" ", line).rstrip(b" ") for line in lines]
    return b"\r\n".join(lines) + b"\r\n"


def _canonicalize_header(name: str, value: str, mode: str) -> bytes:
    if mode == "relaxed":
        value = re.sub(r"[ \t]+", " ", value).strip()
        return f"{name.lower()}:{value}".encode("utf-8")
    return f"{name}:{value}".encode("utf-8")


def _parse_raw_headers(raw_email: bytes) -> list[tuple[str, str, bytes]]:
    header_block = raw_email.split(b"\r\n\r\n", 1)[0]
    if header_block == raw_email:
        header_block = raw_email.split(b"\n\n", 1)[0]
    parsed: list[tuple[str, str, bytes]] = []
    current: list[bytes] = []

    def append_current() -> None:
        if not current:
            return
        raw = b"".join(current).rstrip(b"\r\n")
        first_line = current[0].rstrip(b"\r\n")
        if b":" not in first_line:
            return
        name, first_value = first_line.split(b":", 1)
        continuation = b"".join(line.rstrip(b"\r\n") for line in current[1:])
        value = first_value + continuation
        parsed.append((
            name.decode("ascii", errors="replace"),
            value.decode("utf-8", errors="replace"),
            raw,
        ))

    for line in header_block.splitlines(keepends=True):
        if line.startswith((b" ", b"\t")):
            current.append(line)
        else:
            append_current()
            current = [line]
    append_current()
    return parsed


def verify_dkim_signature(
    raw_email: bytes | None,
    signature: str,
    public_key_record: str | None,
) -> dict[str, Any]:
    result = {
        "checked": False,
        "valid": False,
        "body_hash_valid": False,
        "signature_valid": False,
        "reason": None,
    }
    if not raw_email or not public_key_record:
        result["reason"] = "raw evidence or public key unavailable"
        return result
    tags = parse_tag_value_list(signature)
    key_tags = parse_tag_value_list(public_key_record)
    public_key = key_tags.get("p")
    if not public_key or not tags.get("b") or not tags.get("bh"):
        result["reason"] = "signature or public key is incomplete"
        return result
    try:
        algorithm = tags.get("a", "").lower()
        hash_algorithm = SUPPORTED_ALGORITHMS.get(algorithm)
        if hash_algorithm is None:
            result["checked"] = True
            result["reason"] = f"unsupported DKIM algorithm: {algorithm or 'missing'}"
            return result
        message = BytesParser(policy=policy.default).parsebytes(raw_email)
        _, body = raw_email.split(b"\r\n\r\n", 1) if b"\r\n\r\n" in raw_email else raw_email.split(b"\n\n", 1)
        modes = (tags.get("c") or "simple/simple").split("/", 1)
        body_mode = modes[1] if len(modes) == 2 else "simple"
        if body_mode not in {"simple", "relaxed"} or modes[0] not in {"simple", "relaxed"}:
            raise ValueError("unsupported DKIM canonicalization mode")
        canonical_body = _canonicalize_body(body, body_mode)
        if "l" in tags:
            body_length = int(tags["l"])
            if body_length < 0:
                raise ValueError("invalid DKIM body length")
            canonical_body = canonical_body[:body_length]
        body_hash = hashlib.new(hash_algorithm().name, canonical_body).digest()
        expected_body_hash = base64.b64decode(tags["bh"] + "=" * ((-len(tags["bh"]) % 4)))
        result["body_hash_valid"] = body_hash == expected_body_hash
        if not result["body_hash_valid"]:
            result["reason"] = "body hash mismatch"
            result["checked"] = True
            return result
        header_mode = modes[0]
        signed_headers = [item.strip().lower() for item in tags.get("h", "").split(":") if item.strip()]
        header_lines = []
        used: set[int] = set()
        raw_headers = _parse_raw_headers(raw_email)
        for name in reversed(signed_headers):
            for index in range(len(raw_headers) - 1, -1, -1):
                header_name, header_value, raw_header = raw_headers[index]
                if index not in used and header_name.lower() == name:
                    header_lines.insert(
                        0,
                        raw_header if header_mode == "simple" else _canonicalize_header(header_name, header_value, header_mode),
                    )
                    used.add(index)
                    break
        signature_header = next(
            (item for item in reversed(raw_headers) if item[0].lower() == "dkim-signature"),
            ("DKIM-Signature", signature, b""),
        )
        empty_signature = re.sub(r"b=[^;]*", "b=", signature_header[1], flags=re.IGNORECASE)
        empty_raw_signature = re.sub(
            rb"b=[^;]*",
            b"b=",
            signature_header[2],
            flags=re.IGNORECASE,
        )
        header_lines.append(
            empty_raw_signature
            if header_mode == "simple" and signature_header[2]
            else _canonicalize_header(signature_header[0], empty_signature, header_mode)
        )
        key_bytes = base64.b64decode(public_key + "=" * ((-len(public_key) % 4)))
        public = serialization.load_der_public_key(key_bytes)
        public.verify(
            base64.b64decode(tags["b"] + "=" * ((-len(tags["b"]) % 4))),
            b"\r\n".join(header_lines),
            padding.PKCS1v15(),
            hash_algorithm(),
        )
        result["signature_valid"] = True
        result["valid"] = True
        result["checked"] = True
    except Exception as exc:
        result["checked"] = True
        result["reason"] = str(exc)
    return result


def analyze_dkim(
    *,
    headers: dict[str, Any],
    raw_email: bytes | None = None,
) -> dict[str, Any]:

    signatures = extract_dkim_headers(
        headers
    )

    analyses: list[dict[str, Any]] = []

    for signature in signatures:

        tags = parse_tag_value_list(
            signature
        )

        selector = tags.get("s")
        domain = tags.get("d")

        signature_analysis = {
            "signature": signature,
            "tags": tags,
            "selector": selector,
            "domain": domain,
            "canonicalization": tags.get(
                "c"
            ),
            "algorithm": tags.get(
                "a"
            ),
            "signed_headers": (
                tags.get("h", "")
                .split(":")
                if tags.get("h")
                else []
            ),
            "body_hash": tags.get(
                "bh"
            ),
            "signature_data": tags.get(
                "b"
            ),
            "selector_record": None,
            "public_key": {},
            "cryptographic_verification": {},
            "structurally_valid": False,
        }

        required_tags_present = all(
            tag in tags
            for tag in DKIM_REQUIRED_TAGS
        )

        structurally_valid = (
            required_tags_present
            and bool(selector)
            and bool(domain)
            and bool(tags.get("a"))
            and bool(tags.get("h"))
            and bool(tags.get("bh"))
            and bool(tags.get("b"))
            and tags.get("a", "").lower() in SUPPORTED_ALGORITHMS
        )

        signature_analysis[
            "structurally_valid"
        ] = structurally_valid

        if selector and domain:

            selector_record = query_dkim_record(
                selector,
                domain,
            )

            signature_analysis[
                "selector_record"
            ] = selector_record

            signature_analysis[
                "public_key"
            ] = validate_dkim_public_key(
                selector_record
            )

            signature_analysis[
                "cryptographic_verification"
            ] = verify_dkim_signature(
                raw_email,
                signature,
                selector_record,
            )

        analyses.append(
            signature_analysis
        )

    if not signatures:

        return {
            "present": False,
            "signature_count": 0,
            "signatures": [],
            "result": "none",
        }

    valid_structure_count = sum(
        1
        for item in analyses
        if item["structurally_valid"]
    )

    cryptographic_count = sum(
        1
        for item in analyses
        if item.get("cryptographic_verification", {}).get("valid")
    )

    if cryptographic_count > 0:
        result = "pass"
    else:
        unverifiable_count = sum(
            1
            for item in analyses
            if item["structurally_valid"]
            and (
                item.get("selector_record") is None
                or (
                    item["public_key"].get("valid", False)
                    and not item.get("cryptographic_verification", {}).get("checked", False)
                )
            )
        )
        result = "unverified" if unverifiable_count else "invalid"

    return {
        "present": True,
        "signature_count": len(
            signatures
        ),
        "signatures": analyses,
        "result": result,
        "cryptographically_verified": any(
            item.get("cryptographic_verification", {}).get("valid")
            for item in analyses
        ),
    }
