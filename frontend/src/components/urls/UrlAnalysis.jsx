import React from "react";

import {
    Globe,
    AlertTriangle,
    ShieldCheck
} from "lucide-react";

import Badge from "../common/Badge";
import UrlTable from "./UrlTable";
import DomainCard from "./DomainCard";

export default function UrlAnalysis({
    analysis,
    onAnalyze,
    analyzing
}) {
    if (!analysis) {
        return (
            <div className="card">
                <div className="card-body text-center">
                    <Globe className="mx-auto h-8 w-8 text-slate-500" />

                    <h3 className="mt-4 text-sm font-semibold text-slate-700">
                        URL intelligence not available
                    </h3>

                    <p className="mt-2 text-xs text-slate-500">
                        Analyze URLs and domains extracted from this email.
                    </p>

                    <button
                        onClick={onAnalyze}
                        disabled={analyzing}
                        className="mt-5 rounded-lg bg-sky-500 px-4 py-2 text-sm font-medium text-slate-950 disabled:opacity-50"
                    >
                        {analyzing
                            ? "Analyzing..."
                            : "Analyze URLs"}
                    </button>
                </div>
            </div>
        );
    }

    const urls =
        analysis.urls ||
        analysis.url_results ||
        analysis.url_analysis ||
        [];

    const domains =
        analysis.domains ||
        analysis.domain_results ||
        [];

    const rawFindings = analysis.findings || [];
    const mismatchCodes = new Set([
        "URL_DOMAIN_SENDER_MISMATCH",
        "DOMAIN_SENDER_MISMATCH",
    ]);
    const mismatchFindings = rawFindings.filter((finding) => mismatchCodes.has(finding.code));
    const affectedDomains = [...new Set(mismatchFindings.flatMap((finding) => {
        const evidence = finding.evidence || {};
        return [
            ...(Array.isArray(evidence.domains) ? evidence.domains : []),
            evidence.domain,
            evidence.url_hostname,
        ].filter(Boolean).map((domain) => String(domain).toLowerCase());
    }))].sort();
    const findings = [
        ...rawFindings.filter((finding) => !mismatchCodes.has(finding.code)),
        ...(mismatchFindings.length ? [{
            code: "DOMAIN_SENDER_MISMATCH",
            severity: "LOW",
            title: "Destination domain differs from sender domain",
            description: `${affectedDomains.length || mismatchFindings.length} destination domain${(affectedDomains.length || mismatchFindings.length) === 1 ? "" : "s"} differ from the sender domain.`,
            evidence: { domains: affectedDomains },
        }] : []),
    ];

    const risk =
        Number(
            analysis.risk?.score ||
            0
        );

    return (
        <div className="space-y-6">
            <div className="grid gap-4 sm:grid-cols-4">
                <div className="card p-5">
                    <p className="text-xs text-slate-500">
                        URLs
                    </p>

                    <p className="mt-2 text-2xl font-bold text-slate-900">
                        {urls.length}
                    </p>
                </div>

                <div className="card p-5">
                    <p className="text-xs text-slate-500">
                        Domains
                    </p>

                    <p className="mt-2 text-2xl font-bold text-slate-900">
                        {domains.length}
                    </p>
                </div>

                <div className="card p-5">
                    <p className="text-xs text-slate-500">
                        Findings
                    </p>

                    <p className="mt-2 text-2xl font-bold text-slate-900">
                        {findings.length}
                    </p>
                </div>

                <div className="card p-5">
                    <p className="text-xs text-slate-500">
                        Risk Score
                    </p>

                    <p
                        className={`
              mt-2 text-2xl font-bold
              ${risk >= 70
                                ? "text-red-400"
                                : risk >= 40
                                    ? "text-yellow-400"
                                    : "text-green-400"
                            }
            `}
                    >
                        {risk}/100
                    </p>
                </div>
            </div>

            <div className="card">
                <div className="card-header">
                    <div className="flex items-center gap-3">
                        <Globe className="h-5 w-5 text-cyan-400" />

                        <div>
                            <h2 className="text-sm font-semibold text-slate-900">
                                Extracted URLs
                            </h2>

                            <p className="mt-1 text-xs text-slate-500">
                                URL-level threat intelligence
                            </p>
                        </div>
                    </div>

                    <Badge variant="info">
                        URL Intelligence
                    </Badge>
                </div>

                <UrlTable urls={urls} />
            </div>

            <div className="card">
                <div className="card-header">
                    <div>
                        <h2 className="text-sm font-semibold text-slate-900">
                            Domain Intelligence
                        </h2>

                        <p className="mt-1 text-xs text-slate-500">
                            Domain reputation and lookalike analysis
                        </p>
                    </div>
                </div>

                <div className="grid gap-4 p-5 md:grid-cols-2 xl:grid-cols-3">
                    {domains.length === 0 ? (
                        <div className="col-span-full py-10 text-center text-sm text-slate-500">
                            No domain intelligence records available.
                        </div>
                    ) : (
                        domains.map(
                            (domain, index) => (
                                <DomainCard
                                    key={
                                        domain.domain ||
                                        domain.hostname ||
                                        index
                                    }
                                    domain={
                                        typeof domain ===
                                            "string"
                                            ? {
                                                domain
                                            }
                                            : domain
                                    }
                                />
                            )
                        )
                    )}
                </div>
            </div>

            <div className="card">
                <div className="card-header">
                    <div className="flex items-center gap-3">
                        <AlertTriangle className="h-4 w-4 text-orange-400" />

                        <div>
                            <h2 className="text-sm font-semibold text-slate-900">
                                URL Intelligence Findings
                            </h2>

                            <p className="mt-1 text-xs text-slate-500">
                                Suspicious URLs and domain indicators
                            </p>
                        </div>
                    </div>
                </div>

                <div className="space-y-3 p-5">
                    {findings.length === 0 ? (
                        <div className="flex items-center gap-3 rounded-lg border border-green-500/20 bg-green-500/5 p-5">
                            <ShieldCheck className="h-5 w-5 text-green-400" />

                            <span className="text-sm text-green-400">
                                No URL intelligence findings were reported.
                            </span>
                        </div>
                    ) : (
                        findings.map(
                            (finding, index) => (
                                <div
                                    key={`${finding.code || finding.id || "finding"}-${index}`}
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
                                    {finding.code === "DOMAIN_SENDER_MISMATCH" && finding.evidence?.domains?.length > 0 && (
                                        <p className="mt-2 break-all text-xs text-slate-600">
                                            Affected domains: {finding.evidence.domains.join(", ")}
                                        </p>
                                    )}
                                </div>
                            )
                        )
                    )}
                </div>
            </div>
        </div>
    );
}
