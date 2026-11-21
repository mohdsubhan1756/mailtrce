import React from "react";

import {
    Mail,
    User,
    Users,
    Globe,
    Paperclip,
    Link as LinkIcon
} from "lucide-react";

import {
    formatDate,
    getSenderAddress,
    getSenderDomain
} from "../../utils/formatters";

function Info({
    icon: Icon,
    label,
    value
}) {
    return (
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
            <div className="flex items-center gap-2 text-xs text-slate-500">
                <Icon className="h-3.5 w-3.5" />

                {label}
            </div>

            <p className="mt-2 break-all text-sm text-slate-700">
                {value || "—"}
            </p>
        </div>
    );
}

export default function EmailSummary({
    email
}) {
    const recipients =
        email.recipients ||
        email.to ||
        [];

    const attachments =
        email.attachments || [];

    const urls =
        email.urls ||
        [];

    return (
        <div className="card">
            <div className="card-header">
                <div className="flex items-center gap-3">
                    <div className="rounded-lg bg-sky-500/10 p-2.5">
                        <Mail className="h-5 w-5 text-sky-400" />
                    </div>

                    <div>
                        <h2 className="text-sm font-semibold text-slate-900">
                            Normalized Email
                        </h2>

                        <p className="mt-1 text-xs text-slate-500">
                            Parsed email record
                        </p>
                    </div>
                </div>
            </div>

            <div className="p-5">
                <div className="mb-5">
                    <p className="text-xs text-slate-500">
                        Subject
                    </p>

                    <h2 className="mt-1 text-lg font-semibold text-slate-800">
                        {email.subject || "No subject"}
                    </h2>
                </div>

                <div className="grid gap-3 md:grid-cols-2">
                    <Info
                        icon={User}
                        label="Sender"
                        value={
                            getSenderAddress(email.sender)
                        }
                    />

                    <Info
                        icon={Globe}
                        label="Sender Domain"
                        value={
                            getSenderDomain(email.sender)
                        }
                    />

                    <Info
                        icon={Users}
                        label="Recipients"
                        value={
                            Array.isArray(recipients)
                                ? recipients.join(", ")
                                : recipients
                        }
                    />

                    <Info
                        icon={Mail}
                        label="Message ID"
                        value={email.message_id}
                    />

                    <Info
                        icon={Paperclip}
                        label="Attachments"
                        value={attachments.length}
                    />

                    <Info
                        icon={LinkIcon}
                        label="Extracted URLs"
                        value={urls.length}
                    />
                </div>

                <div className="mt-4 grid gap-3 md:grid-cols-2">
                    <Info
                        icon={Mail}
                        label="Ingested At"
                        value={formatDate(
                            email.created_at ||
                            email.ingested_at
                        )}
                    />

                    <Info
                        icon={Globe}
                        label="SHA-256"
                        value={email.sha256}
                    />
                </div>
            </div>
        </div>
    );
}