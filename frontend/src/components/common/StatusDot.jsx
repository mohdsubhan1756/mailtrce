import React from "react";

export default function StatusDot({
    status = "success"
}) {
    const color =
        status === "danger"
            ? "bg-red-400"
            : status === "warning"
                ? "bg-yellow-400"
                : "bg-green-400";

    return (
        <span className="relative flex h-2.5 w-2.5">
            <span
                className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-50 ${color}`}
            />

            <span
                className={`relative inline-flex h-2.5 w-2.5 rounded-full ${color}`}
            />
        </span>
    );
}