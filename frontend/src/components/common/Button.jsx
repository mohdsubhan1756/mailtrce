import React from "react";

const variants = {
    primary:
        "bg-blue-600 text-white shadow-sm hover:bg-blue-700",

    secondary:
        "border border-slate-200 bg-white text-slate-700 hover:bg-slate-50",

    danger:
        "border border-red-200 bg-red-50 text-red-700 hover:bg-red-100",

    success:
        "border border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-100",

    ghost:
        "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
};

export default function Button({
    children,
    variant = "primary",
    loading = false,
    disabled = false,
    className = "",
    ...props
}) {
    return (
        <button
            disabled={disabled || loading}
            className={`
        inline-flex items-center justify-center gap-2
        rounded-lg px-4 py-2.5
        text-sm font-medium
        transition focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-blue-500/20
        disabled:cursor-not-allowed
        disabled:opacity-50
        ${variants[variant]}
        ${className}
      `}
            {...props}
        >
            {loading && (
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
            )}

            {children}
        </button>
    );
}
