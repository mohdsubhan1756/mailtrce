import React from "react";

export default function StatCard({
    title,
    value,
    subtitle,
    icon: Icon,
    iconClass = "text-sky-400",
    iconBackground = "bg-sky-500/10"
}) {
    return (
        <div className="card p-5">
            <div className="flex items-start justify-between">
                <div>
                    <p className="text-sm text-slate-500">
                        {title}
                    </p>

                    <p className="mt-2 text-2xl font-bold text-slate-900">
                        {value}
                    </p>

                    {subtitle && (
                        <p className="mt-1 text-xs text-slate-500">
                            {subtitle}
                        </p>
                    )}
                </div>

                {Icon && (
                    <div
                        className={`rounded-xl p-3 ${iconBackground}`}
                    >
                        <Icon
                            className={`h-5 w-5 ${iconClass}`}
                        />
                    </div>
                )}
            </div>
        </div>
    );
}