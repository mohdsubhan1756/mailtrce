import re
from typing import Any


AUTH_METHOD_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)\s*="
    r"\s*([a-zA-Z]+)",
    re.IGNORECASE,
)


def parse_authentication_results(
    headers: list[str],
) -> list[dict[str, Any]]:

    results: list[dict[str, Any]] = []

    for header in headers:

        if not header:
            continue

        matches = AUTH_METHOD_PATTERN.findall(
            header
        )

        for method, result in matches:

            results.append(
                {
                    "method": method.lower(),
                    "result": result.lower(),
                    "raw": header,
                }
            )

    return results


def get_latest_authentication_result(
    results: list[dict[str, Any]],
    method: str,
) -> str | None:

    method = method.lower()

    matching = [
        item
        for item in results
        if item.get("method") == method
    ]

    if not matching:
        return None

    return matching[-1].get(
        "result"
    )