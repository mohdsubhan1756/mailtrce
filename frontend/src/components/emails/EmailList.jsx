import React from "react";

import EmailRow from "./EmailRow";
import EmptyState from "../common/EmptyState";

export default function EmailList({
    emails = []
}) {
    if (!emails.length) {
        return (
            <div className="card">
                <EmptyState
                    title="No emails ingested"
                    description="Upload an .eml file to start a forensic investigation."
                />
            </div>
        );
    }

    return (
        <div className="card overflow-hidden">
            <div className="hidden border-b border-slate-200 bg-slate-50 px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-500 sm:flex">
                <div className="ml-14 flex-1">
                    Email
                </div>

                <div className="w-32 text-right">
                    Domain
                </div>

                <div className="w-40 text-right">
                    Ingested
                </div>

                <div className="w-4" />
            </div>

            {emails.map((email) => (
                <EmailRow
                    key={email.email_id}
                    email={email}
                />
            ))}
        </div>
    );
}