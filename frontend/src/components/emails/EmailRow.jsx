import React from "react";

import {
    Mail,
    ChevronRight
} from "lucide-react";

import { Link } from "react-router-dom";

import Badge from "../common/Badge";

import {
    formatDate,
    getEmailRiskScore,
    getSenderAddress,
    getSenderDomain
} from "../../utils/formatters";

import {
    getRiskLevel,
    getRiskLabel
} from "../../utils/risk";

export default function EmailRow({
    email
}) {
    const score = getEmailRiskScore(email);

    const level = getRiskLevel(score);

    return (
        <Link
            to={`/emails/${email.email_id}`}
            className="block border-t border-slate-100 transition-colors hover:bg-slate-50"
        >
            <div className="flex items-center gap-4 px-5 py-4">
                <div className="hidden rounded-lg bg-sky-500/10 p-2.5 sm:block">
                    <Mail className="h-4 w-4 text-sky-400" />
                </div>

                <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                        <p className="truncate text-sm font-medium text-slate-800">
                            {email.subject || "No subject"}
                        </p>

                        {score > 0 && (
                            <Badge variant={level}>
                                {getRiskLabel(score)}
                            </Badge>
                        )}
                    </div>

                    <p className="mt-1 truncate text-xs text-slate-500">
                        {getSenderAddress(email.sender) ||
                            "Unknown sender"}
                    </p>
                </div>

                <div className="hidden w-32 text-right md:block">
                    <p className="text-xs text-slate-500">
                        {getSenderDomain(email.sender) ||
                            "Unknown domain"}
                    </p>
                </div>

                <div className="hidden w-40 text-right sm:block">
                    <p className="text-xs text-slate-500">
                        {formatDate(
                            email.created_at ||
                            email.ingested_at
                        )}
                    </p>
                </div>

                <ChevronRight className="h-4 w-4 text-slate-500" />
            </div>
        </Link>
    );
}
