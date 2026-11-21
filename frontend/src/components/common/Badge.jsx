import React from "react";

const styles = {
    critical: "bg-red-50 text-red-700 border-red-200",
    high: "bg-orange-50 text-orange-700 border-orange-200",
    medium: "bg-amber-50 text-amber-800 border-amber-200",
    low: "bg-blue-50 text-blue-700 border-blue-200",
    safe: "bg-emerald-50 text-emerald-700 border-emerald-200",
    success: "bg-emerald-50 text-emerald-700 border-emerald-200",
    warning: "bg-amber-50 text-amber-800 border-amber-200",
    danger: "bg-red-50 text-red-700 border-red-200",
    info: "bg-sky-50 text-sky-700 border-sky-200",
    neutral: "bg-slate-100 text-slate-600 border-slate-200"
};

export default function Badge({
    children,
    variant = "neutral"
}) {
    return (
        <span
            className={`
        inline-flex items-center
        rounded-full border
        px-2.5 py-1
        text-xs font-medium
        ${styles[variant] || styles.neutral}
      `}
        >
            {children}
        </span>
    );
}
