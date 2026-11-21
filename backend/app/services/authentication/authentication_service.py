from datetime import datetime, timezone
import re
from typing import Any

from app.db.mongodb import get_database
from app.models.authentication_document import (
    build_authentication_document,
)
from app.services.authentication.authentication_results import (
    get_latest_authentication_result,
    parse_authentication_results,
)
from app.services.authentication.dmarc_analyzer import (
    analyze_dmarc,
)
from app.services.authentication.dkim_analyzer import (
    analyze_dkim,
)
from app.services.authentication.spf_analyzer import (
    analyze_spf,
)


AUTHENTICATION_ANALYSIS_VERSION = "1.1.0"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def extract_sender_ip(
    email_document: dict[str, Any],
) -> str | None:

    headers = email_document.get("headers", {})

    if isinstance(headers, dict):
        received_spf = headers.get("received-spf")

        if isinstance(received_spf, list):
            received_spf = received_spf[-1]

        if received_spf:
            client_ip = re.search(
                r"\bclient-ip\s*=\s*([^;\s]+)",
                str(received_spf),
                re.IGNORECASE,
            )

            if client_ip:
                return client_ip.group(1)

    # Module 2 already reconstructed the routing chain.
    # Prefer the earliest public IP found in the chain,
    # because that is the most useful candidate for SPF
    # evaluation.

    header_analysis = (
        get_database()[
            "header_forensics"
        ].find_one(
            {
                "email_id": email_document[
                    "email_id"
                ]
            }
        )
    )

    if header_analysis:

        routing = header_analysis.get(
            "routing_analysis",
            {},
        )

        hops = routing.get(
            "hops",
            [],
        )

        # Received headers are normally newest first,
        # so inspect the chain from oldest to newest.
        for hop in reversed(hops):

            public_ips = hop.get(
                "public_ips",
                [],
            )

            if public_ips:
                return public_ips[0]

    # Fall back to Module 1 IP extraction.
    ip_addresses = email_document.get(
        "ip_addresses",
        [],
    )

    if ip_addresses:
        return ip_addresses[0]

    return None


def build_findings(
    *,
    spf: dict[str, Any],
    dkim: dict[str, Any],
    dmarc: dict[str, Any],
    authentication_results: list[
        dict[str, Any]
    ],
) -> list[dict[str, Any]]:

    findings: list[dict[str, Any]] = []

    def add(
        code: str,
        severity: str,
        title: str,
        description: str,
        evidence: dict[str, Any] | None = None,
    ):
        findings.append(
            {
                "code": code,
                "severity": severity,
                "category": "AUTHENTICATION",
                "title": title,
                "description": description,
                "evidence": evidence or {},
            }
        )

    # ---------------------------------------------------------
    # SPF
    # ---------------------------------------------------------

    if not spf["record_found"]:
        add(
            "SPF_RECORD_MISSING",
            "MEDIUM",
            "SPF record not found",
            (
                "No SPF record was found for the "
                "evaluated sender domain."
            ),
            {
                "domain": spf.get("domain")
            },
        )

    elif spf["result"] == "fail":
        add(
            "SPF_FAIL",
            "HIGH",
            "SPF authentication failed",
            (
                "The evaluated sending IP did not satisfy "
                "the SPF policy."
            ),
            {
                "domain": spf.get("domain"),
                "sender_ip": spf.get(
                    "sender_ip"
                ),
                "matched_mechanism": spf.get(
                    "matched_mechanism"
                ),
            },
        )

    elif spf["result"] == "softfail":
        add(
            "SPF_SOFTFAIL",
            "MEDIUM",
            "SPF softfail",
            (
                "The SPF policy suggests that the "
                "sending IP is probably not authorized."
            ),
            {
                "domain": spf.get("domain"),
                "sender_ip": spf.get(
                    "sender_ip"
                ),
            },
        )

    elif spf["result"] == "neutral":
        add(
            "SPF_NEUTRAL",
            "LOW",
            "SPF neutral result",
            (
                "The SPF policy did not make a definitive "
                "authorization statement for the sender."
            ),
        )

    # ---------------------------------------------------------
    # DKIM
    # ---------------------------------------------------------

    if not dkim["present"]:
        add(
            "DKIM_SIGNATURE_MISSING",
            "MEDIUM",
            "DKIM signature not found",
            (
                "The message does not contain a DKIM-Signature "
                "header."
            ),
        )

    elif dkim["result"] == "invalid":
        add(
            "DKIM_INVALID",
            "HIGH",
            "DKIM signature validation failed",
            (
                "The DKIM signature is structurally invalid "
                "or its public-key DNS record could not be "
                "validated."
            ),
        )

    elif dkim["result"] == "unverified":
        add(
            "DKIM_NOT_CRYPTOGRAPHICALLY_VERIFIED",
            "HIGH",
            "DKIM signature was not cryptographically verified",
            (
                "The DKIM public key and signature structure were inspected, "
                "but the preserved message did not produce a valid RSA/body-hash verification."
            ),
        )

    # ---------------------------------------------------------
    # DMARC
    # ---------------------------------------------------------

    if not dmarc["record_found"]:
        add(
            "DMARC_RECORD_MISSING",
            "MEDIUM",
            "DMARC record not found",
            (
                "No DMARC policy record was found for "
                "the From domain."
            ),
            {
                "domain": dmarc.get(
                    "domain"
                )
            },
        )

    elif dmarc["result"] == "fail":
        add(
            "DMARC_FAIL",
            "HIGH",
            "DMARC authentication failed",
            (
                "Neither an aligned SPF pass nor an "
                "aligned DKIM pass was available."
            ),
            {
                "spf_aligned_pass": dmarc.get(
                    "spf_aligned_pass"
                ),
                "dkim_aligned_pass": dmarc.get(
                    "dkim_aligned_pass"
                ),
            },
        )

    # ---------------------------------------------------------
    # AUTHENTICATION-RESULTS
    # ---------------------------------------------------------

    for method in (
        "spf",
        "dkim",
        "dmarc",
    ):

        header_result = (
            get_latest_authentication_result(
                authentication_results,
                method,
            )
        )

        if not header_result:
            continue

        if method == "spf":
            local_result = spf["result"]

        elif method == "dkim":
            local_result = (
                "pass"
                if dkim["result"]
                == "present"
                else (
                    "fail"
                    if dkim["result"]
                    == "invalid"
                    else "none"
                )
            )

        else:
            local_result = dmarc["result"]

        # Only flag clear contradictions.
        if (
            header_result
            in (
                "pass",
                "fail",
            )
            and local_result
            in (
                "pass",
                "fail",
            )
            and header_result
            != local_result
        ):
            add(
                "AUTHENTICATION_RESULT_MISMATCH",
                "HIGH",
                (
                    f"{method.upper()} result "
                    "mismatch"
                ),
                (
                    "The Authentication-Results header "
                    "reports a different result from the "
                    "local forensic evaluation."
                ),
                {
                    "method": method,
                    "header_result": header_result,
                    "local_result": local_result,
                },
            )

    return findings


def analyze_email_authentication(
    email_id: str,
) -> dict[str, Any]:

    db = get_database()

    email_document = db[
        "emails"
    ].find_one(
        {
            "email_id": email_id
        }
    )

    if email_document is None:
        raise ValueError(
            f"Email '{email_id}' was not found."
        )

    sender = email_document.get(
        "sender"
    ) or {}

    from_domain = sender.get(
        "domain"
    )

    sender_ip = extract_sender_ip(
        email_document
    )

    # ---------------------------------------------------------
    # SPF
    # ---------------------------------------------------------

    spf = analyze_spf(
        domain=from_domain,
        sender_ip=sender_ip,
    )

    # ---------------------------------------------------------
    # DKIM
    # ---------------------------------------------------------

    headers = email_document.get(
        "headers",
        {},
    )

    raw_email = None
    evidence_path = (
        email_document.get("evidence", {}).get("local_path")
    )
    if evidence_path:
        try:
            raw_email = open(evidence_path, "rb").read()
        except OSError:
            raw_email = None

    dkim = analyze_dkim(
        headers=headers,
        raw_email=raw_email,
    )

    # ---------------------------------------------------------
    # DMARC
    # ---------------------------------------------------------

    dkim_for_dmarc = []

    for signature in dkim.get(
        "signatures",
        [],
    ):

        public_key = signature.get(
            "public_key",
            {},
        )

        crypto = signature.get(
            "cryptographic_verification",
            {},
        )
        crypto_ok = crypto.get("valid", False)

        if (
            signature.get("structurally_valid")
            and public_key.get("valid", False)
            and crypto_ok
        ):
            dkim_result = "pass"
        else:
            dkim_result = "fail"

        dkim_for_dmarc.append(
            {
                "domain": signature.get(
                    "domain"
                ),
                "result": dkim_result,
                "structurally_valid": (
                    signature.get(
                        "structurally_valid",
                        False,
                    )
                ),
                "public_key": public_key,
            }
        )

    dmarc = analyze_dmarc(
        from_domain=from_domain,
        spf_result=spf["result"],
        spf_domain=spf.get(
            "domain"
        ),
        dkim_results=dkim_for_dmarc,
    )

    # ---------------------------------------------------------
    # Authentication-Results
    # ---------------------------------------------------------

    auth_headers = email_document.get(
        "authentication_results",
        [],
    )

    parsed_auth_results = (
        parse_authentication_results(
            auth_headers
        )
    )

    # ---------------------------------------------------------
    # Findings
    # ---------------------------------------------------------

    findings = build_findings(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        authentication_results=(
            parsed_auth_results
        ),
    )

    high_count = sum(
        1
        for item in findings
        if item["severity"] == "HIGH"
    )

    medium_count = sum(
        1
        for item in findings
        if item["severity"] == "MEDIUM"
    )

    low_count = sum(
        1
        for item in findings
        if item["severity"] == "LOW"
    )

    # ---------------------------------------------------------
    # Overall authentication state
    # ---------------------------------------------------------

    if (
        dmarc.get("result") == "pass"
        and high_count == 0
    ):
        overall_result = "PASS"

    elif (
        spf.get("result") == "pass"
        or dkim.get("result") in {"pass", "unverified"}
    ):
        overall_result = "PARTIAL"

    elif (
        spf.get("result") == "fail"
        or dkim.get("result") == "invalid"
        or dmarc.get("result") == "fail"
    ):
        overall_result = "FAIL"

    else:
        overall_result = "UNKNOWN"

    analysis = {
        "analysis_version": AUTHENTICATION_ANALYSIS_VERSION,
        "email_id": email_id,
        "case_id": email_document[
            "case_id"
        ],
        "analyzed_at": utc_now(),

        "sender_domain": from_domain,

        "sender_ip": sender_ip,

        "spf": spf,

        "dkim": dkim,

        "dmarc": dmarc,

        "authentication_results": (
            parsed_auth_results
        ),

        "overall_result": overall_result,

        "findings": findings,

        "risk_indicator_count": len(
            findings
        ),

        "high_severity_count": high_count,

        "medium_severity_count": medium_count,

        "low_severity_count": low_count,

        "status": "ANALYZED",
    }

    document = build_authentication_document(
        email_id=email_id,
        case_id=email_document[
            "case_id"
        ],
        analysis=analysis,
    )

    db[
        "authentication_analysis"
    ].replace_one(
        {
            "email_id": email_id
        },
        document,
        upsert=True,
    )

    db["emails"].update_one(
        {
            "email_id": email_id
        },
        {
            "$set": {
                "module.authentication": {
                    "status": "ANALYZED",
                    "analyzed_at": analysis[
                        "analyzed_at"
                    ],
                    "overall_result": (
                        overall_result
                    ),
                    "risk_indicator_count": (
                        len(findings)
                    ),
                },
                "updated_at": utc_now(),
            }
        },
    )

    return document


def get_authentication_analysis(
    email_id: str,
) -> dict[str, Any] | None:

    db = get_database()

    document = db[
        "authentication_analysis"
    ].find_one(
        {
            "email_id": email_id
        }
    )

    if document is None:
        return None

    document["_id"] = str(
        document["_id"]
    )

    return document


def list_authentication_analyses(
    *,
    limit: int = 50,
    skip: int = 0,
) -> list[dict[str, Any]]:

    db = get_database()

    documents = (
        db[
            "authentication_analysis"
        ]
        .find({})
        .sort(
            "analyzed_at",
            -1,
        )
        .skip(skip)
        .limit(limit)
    )

    result = []

    for document in documents:

        document["_id"] = str(
            document["_id"]
        )

        result.append(
            document
        )

    return result
