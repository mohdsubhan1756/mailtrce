import React from "react";
import {
    ShieldAlert,
    ShieldCheck,
    AlertTriangle
} from "lucide-react";
import { getEmailRiskScore } from "../../utils/formatters";

export default function ThreatOverview({
    emails = []
}) {
    const total = emails.length;

    const suspicious = emails.filter((email) => {
        const score = getEmailRiskScore(email);
        return score !== null && score >= 70;
    }).length;

    const lowerRisk = emails.filter((email) => {
        const score = getEmailRiskScore(email);
        return score !== null && score < 70;
    }).length;
    const notAnalyzed = emails.filter((email) => getEmailRiskScore(email) === null).length;

    return (
        <div className="grid gap-4 sm:grid-cols-3">
            <div className="card p-5">
                <div className="flex items-center gap-3">
                    <div className="rounded-lg bg-sky-500/10 p-2.5">
                        <ShieldAlert className="h-5 w-5 text-sky-400" />
                    </div>

                    <div>
                        <p className="text-xs text-slate-500">
                            Total Emails
                        </p>

                        <p className="text-xl font-bold text-slate-900">
                            {total}
                        </p>
                    </div>
                </div>
            </div>

            <div className="card p-5">
                <div className="flex items-center gap-3">
                    <div className="rounded-lg bg-red-500/10 p-2.5">
                        <AlertTriangle className="h-5 w-5 text-red-400" />
                    </div>

                    <div>
                        <p className="text-xs text-slate-500">
                            Suspicious
                        </p>

                        <p className="text-xl font-bold text-slate-900">
                            {suspicious}
                        </p>
                    </div>
                </div>
            </div>

            <div className="card p-5">
                <div className="flex items-center gap-3">
                    <div className="rounded-lg bg-green-500/10 p-2.5">
                        <ShieldCheck className="h-5 w-5 text-green-400" />
                    </div>

                    <div>
                        <p className="text-xs text-slate-500">
                            Lower risk
                        </p>

                        <p className="text-xl font-bold text-slate-900">
                            {lowerRisk}
                        </p>
                    </div>
                </div>
            </div>

            <p className="mt-3 text-xs text-slate-500 sm:col-span-3">
                {notAnalyzed} email{notAnalyzed === 1 ? "" : "s"} not yet analyzed
            </p>
        </div>
    );
}
