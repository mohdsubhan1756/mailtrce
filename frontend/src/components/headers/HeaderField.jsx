import React from "react";

import { formatValue } from "../../utils/formatters";

export default function HeaderField({
    label,
    value,
    danger = false
}) {
    return (
        <div
            className={`
        rounded-lg border p-4
        ${danger
                    ? "border-red-500/20 bg-red-500/5"
                    : "border-slate-200 bg-slate-50"
                }
      `}
        >
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                {label}
            </p>

            <p
                className={`
          mt-2 break-all text-sm
          ${danger
                        ? "text-red-300"
                        : "text-slate-700"
                    }
        `}
            >
                {formatValue(value)}
            </p>
        </div>
    );
}