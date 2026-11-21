import React from "react";

import {
    ShieldCheck,
    AlertTriangle
} from "lucide-react";

import Badge from "../common/Badge";
import AuthenticationCard from "./AuthenticationCard";

export default function AuthenticationAnalysis({
    analysis,
    onAnalyze,
    analyzing
}) {
    if (!analysis) {
        return (
            <div className="card">
                <div className="card-body text-center">
                    <ShieldCheck className="mx-auto h-8 w-8 text-slate-500" />

                    <h3 className="mt-4 text-sm font-semibold text-slate-700">
                        Authentication analysis not available
                    </h3>

                    <p className="mt-2 text-xs text-slate-500">
                        Run SPF, DKIM and DMARC analysis for this email.
                    </p>

                    <button
                        onClick={onAnalyze}
                        disabled={analyzing}
                        className="mt-5 rounded-lg bg-sky-500 px-4 py-2 text-sm font-medium text-slate-950 disabled:opacity-50"
                    >
                        {analyzing
                            ? "Analyzing..."
                            : "Analyze Authentication"}
                    </button>
                </div>
            </div>
        );
    }

    const findings =
        analysis.findings || [];

    const overall =
        analysis.overall_result ||
        analysis.status ||
        "unknown";

    return (
        <div className="space-y-6">
            <div className="card">
                <div className="card-header">
                    <div className="flex items-center gap-3">
                        <ShieldCheck className="h-5 w-5 text-sky-400" />

                        <div>
                            <h2 className="text-sm font-semibold text-slate-900">
                                Authentication Verdict
                            </h2>

                            <p className="mt-1 text-xs text-slate-500">
                                SPF · DKIM · DMARC
                            </p>
                        </div>
                    </div>

                    <Badge
                        variant={
                            String(overall)
                                .toLowerCase()
                                .includes("pass")
                                ? "success"
                                : String(overall)
                                    .toLowerCase()
                                    .includes("fail")
                                    ? "danger"
                                    : "warning"
                        }
                    >
                        {overall}
                    </Badge>
                </div>

                <div className="grid gap-4 p-5 md:grid-cols-3">
                    <AuthenticationCard
                        name="SPF"
                        description="Sender Policy Framework"
                        data={analysis.spf || {}}
                    />

                    <AuthenticationCard
                        name="DKIM"
                        description="DomainKeys Identified Mail"
                        data={analysis.dkim || {}}
                    />

                    <AuthenticationCard
                        name="DMARC"
                        description="Domain-based Message Authentication"
                        data={analysis.dmarc || {}}
                    />
                </div>
            </div>

            <div className="card">
                <div className="card-header">
                    <div className="flex items-center gap-3">
                        <AlertTriangle className="h-4 w-4 text-orange-400" />

                        <div>
                            <h2 className="text-sm font-semibold text-slate-900">
                                Authentication Findings
                            </h2>

                            <p className="mt-1 text-xs text-slate-500">
                                Authentication inconsistencies and failures
                            </p>
                        </div>
                    </div>
                </div>

                <div className="space-y-3 p-5">
                    {findings.length === 0 ? (
                        <div className="rounded-lg border border-green-500/20 bg-green-500/5 p-5 text-sm text-green-400">
                            No authentication findings were reported.
                        </div>
                    ) : (
                        findings.map(
                            (finding, index) => (
                                <div
                                    key={
                                        finding.code ||
                                        finding.id ||
                                        index
                                    }
                                    className="rounded-lg border border-slate-200 bg-slate-50 p-4"
                                >
                                    <div className="flex items-center justify-between gap-3">
                                        <p className="text-sm font-medium text-slate-700">
                                            {finding.title ||
                                                finding.name ||
                                                finding.code}
                                        </p>

                                        <Badge
                                            variant={
                                                String(
                                                    finding.severity ||
                                                    "medium"
                                                ).toLowerCase()
                                            }
                                        >
                                            {finding.severity ||
                                                "medium"}
                                        </Badge>
                                    </div>

                                    <p className="mt-2 text-xs leading-5 text-slate-500">
                                        {finding.description ||
                                            finding.message}
                                    </p>
                                </div>
                            )
                        )
                    )}
                </div>
            </div>
        </div>
    );
}