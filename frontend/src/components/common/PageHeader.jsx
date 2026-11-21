import React from "react";

export default function PageHeader({
    title,
    description,
    children
}) {
    return (
        <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div>
                <h1 className="text-2xl font-bold tracking-tight text-slate-900">
                    {title}
                </h1>

                {description && (
                    <p className="mt-1 text-sm text-slate-500">
                        {description}
                    </p>
                )}
            </div>

            {children && (
                <div className="flex items-center gap-3">
                    {children}
                </div>
            )}
        </div>
    );
}