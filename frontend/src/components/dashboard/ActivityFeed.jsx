import React from "react";
import {
    Mail,
} from "lucide-react";

import {
    formatDate,
    truncate,
    getSenderAddress
} from "../../utils/formatters";

export default function ActivityFeed({
    emails = []
}) {
    const recent = [...emails]
        .sort(
            (a, b) =>
                new Date(
                    b.created_at || b.ingested_at || 0
                ) -
                new Date(
                    a.created_at || a.ingested_at || 0
                )
        )
        .slice(0, 6);

    return (
        <div className="card">
            <div className="card-header">
                <div>
                    <h2 className="text-sm font-semibold text-slate-900">
                        Recent Investigations
                    </h2>

                    <p className="mt-1 text-xs text-slate-500">
                        Latest email forensic activity
                    </p>
                </div>
            </div>

            {recent.length === 0 ? (
                <div className="p-5 text-sm text-slate-500">
                    No email investigations yet.
                </div>
            ) : (
                <div>
                    {recent.map((email) => (
                        <div
                            key={email.email_id}
                            className="flex items-center gap-3 border-t border-slate-100 px-5 py-4"
                        >
                            <div className="rounded-lg bg-sky-500/10 p-2">
                                <Mail className="h-4 w-4 text-sky-400" />
                            </div>

                            <div className="min-w-0 flex-1">
                                <p className="truncate text-sm text-slate-700">
                                    {email.subject || "No subject"}
                                </p>

                                <p className="mt-1 truncate text-xs text-slate-500">
                                    {getSenderAddress(email.sender) ||
                                        "Unknown sender"}
                                </p>
                            </div>

                            <div className="hidden text-right sm:block">
                                <p className="text-xs text-slate-500">
                                    {formatDate(
                                        email.created_at ||
                                        email.ingested_at
                                    )}
                                </p>

                                <p className="mt-1 text-[11px] text-slate-500">
                                    {truncate(
                                        email.email_id,
                                        18
                                    )}
                                </p>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
