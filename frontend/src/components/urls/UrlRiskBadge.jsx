import React from "react";

import Badge from "../common/Badge";

export default function UrlRiskBadge({
    score,
    verdict
}) {
    const numericScore =
        Number(score || 0);

    let variant = "safe";

    if (
        numericScore >= 80 ||
        String(verdict)
            .toLowerCase()
            .includes("malicious")
    ) {
        variant = "critical";
    } else if (
        numericScore >= 60 ||
        String(verdict)
            .toLowerCase()
            .includes("suspicious")
    ) {
        variant = "high";
    } else if (numericScore >= 30) {
        variant = "medium";
    }

    return (
        <Badge variant={variant}>
            {verdict ||
                (numericScore > 0
                    ? `${numericScore}/100`
                    : "Safe")}
        </Badge>
    );
}