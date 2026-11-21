import React from "react";

import Badge from "../common/Badge";

const getResultVariant = (result) => {
    const value =
        String(result || "")
            .toLowerCase();

    if (
        value.includes("pass") ||
        value.includes("valid")
    ) {
        return "success";
    }

    if (
        value.includes("fail") ||
        value.includes("invalid")
    ) {
        return "danger";
    }

    if (
        value.includes("soft") ||
        value.includes("neutral") ||
        value.includes("missing")
    ) {
        return "warning";
    }

    return "neutral";
};

export default function AuthenticationCard({
    name,
    data,
    description
}) {
    const result =
        data?.result ||
        data?.status ||
        data?.overall_result ||
        "unknown";

    return (
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-5">
            <div className="flex items-start justify-between gap-3">
                <div>
                    <h3 className="text-sm font-semibold text-slate-900">
                        {name}
                    </h3>

                    <p className="mt-1 text-xs text-slate-500">
                        {description}
                    </p>
                </div>

                <Badge
                    variant={getResultVariant(result)}
                >
                    {String(result)}
                </Badge>
            </div>

            <div className="mt-5 space-y-3">
                {Object.entries(data || {})
                    .filter(
                        ([key]) =>
                            ![
                                "result",
                                "status",
                                "overall_result"
                            ].includes(key)
                    )
                    .slice(0, 8)
                    .map(([key, value]) => (
                        <div
                            key={key}
                            className="flex items-start justify-between gap-4 border-b border-slate-200 pb-2 last:border-0"
                        >
                            <span className="text-xs text-slate-500">
                                {key.replaceAll("_", " ")}
                            </span>

                            <span className="max-w-[60%] break-all text-right text-xs text-slate-500">
                                {typeof value === "object"
                                    ? JSON.stringify(value)
                                    : String(value ?? "—")}
                            </span>
                        </div>
                    ))}
            </div>
        </div>
    );
}