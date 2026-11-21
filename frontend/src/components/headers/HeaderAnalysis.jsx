import React from "react";

import {
    CheckCircle2,
    AlertTriangle,
    Route,
    FileWarning
} from "lucide-react";

import Badge from "../common/Badge";
import HeaderField from "./HeaderField";
import RoutingTimeline from "./RoutingTimeline";

function Finding({ finding }) {
    const severity =
        String(
            finding.severity ||
            finding.level ||
            "medium"
        ).toLowerCase();

    return (
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
            <div className="flex items-start gap-3">
                <AlertTriangle
                    className={`
            mt-0.5 h-4 w-4
            ${severity === "high" ||
                            severity === "critical"
                            ? "text-red-400"
                            : severity === "medium"
                                ? "text-yellow-400"
                                : "text-blue-400"
                        }
          `}
                />

                <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-3">
                        <p className="text-sm font-medium text-slate-700">
                            {finding.title ||
                                finding.name ||
                                finding.code ||
                                "Header finding"}
                        </p>

                        <Badge variant={severity}>
                            {severity}
                        </Badge>
                    </div>

                    <p className="mt-2 text-xs leading-5 text-slate-500">
                        {finding.description ||
                            finding.message ||
                            "Suspicious header indicator detected."}
                    </p>
                </div>
            </div>
        </div>
    );
}

export default function HeaderAnalysis({
    analysis,
    onAnalyze,
    analyzing
}) {
    if (!analysis) {
        return (
            <div className="card">
                <div className="card-body text-center">
                    <Route className="mx-auto h-8 w-8 text-slate-500" />

                    <h3 className="mt-4 text-sm font-semibold text-slate-700">
                        Header analysis not available
                    </h3>

                    <p className="mt-2 text-xs text-slate-500">
                        Run header forensics for this email.
                    </p>

                    <button
                        onClick={onAnalyze}
                        disabled={analyzing}
                        className="mt-5 rounded-lg bg-sky-500 px-4 py-2 text-sm font-medium text-slate-950 disabled:opacity-50"
                    >
                        {analyzing
                            ? "Analyzing..."
                            : "Analyze Headers"}
                    </button>
                </div>
            </div>
        );
    }

    const findings =
        analysis.findings || [];

    const routing =
        analysis.routing_analysis || {};

    const hops =
        routing.hops || [];

    return (
        <div className="space-y-6">
            <div className="grid gap-4 sm:grid-cols-3">
                <div className="card p-5">
                    <p className="text-xs text-slate-500">
                        Analysis Status
                    </p>

                    <div className="mt-2 flex items-center gap-2">
                        <CheckCircle2 className="h-5 w-5 text-green-400" />

                        <span className="text-sm font-medium text-green-400">
                            {analysis.status ||
                                "Completed"}
                        </span>
                    </div>
                </div>

                <div className="card p-5">
                    <p className="text-xs text-slate-500">
                        Routing Hops
                    </p>

                    <p className="mt-2 text-2xl font-bold text-slate-900">
                        {hops.length}
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
            </div>

            <div className="card">
                <div className="card-header">
                    <div>
                        <h2 className="text-sm font-semibold text-slate-900">
                            Header Identity
                        </h2>

                        <p className="mt-1 text-xs text-slate-500">
                            Core message-routing identity fields
                        </p>
                    </div>

                    <Badge variant="info">
                        Header Forensics
                    </Badge>
                </div>

                <div className="grid gap-3 p-5 md:grid-cols-2">
                    <HeaderField
                        label="From"
                        value={
                            analysis.from_analysis?.address
                        }
                    />

                    <HeaderField
                        label="Return-Path"
                        value={
                            analysis.return_path_analysis?.address
                        }
                    />

                    <HeaderField
                        label="Reply-To"
                        value={
                            analysis.reply_to_analysis?.address
                        }
                    />

                    <HeaderField
                        label="Message-ID"
                        value={
                            analysis.message_id_analysis?.value
                        }
                    />
                </div>
            </div>

            <div className="card">
                <div className="card-header">
                    <div>
                        <h2 className="text-sm font-semibold text-slate-900">
                            Mail Routing
                        </h2>

                        <p className="mt-1 text-xs text-slate-500">
                            Received-header reconstruction
                        </p>
                    </div>
                </div>

                <div className="p-5">
                    <RoutingTimeline hops={hops} />
                </div>
            </div>

            <div className="card">
                <div className="card-header">
                    <div className="flex items-center gap-3">
                        <FileWarning className="h-4 w-4 text-orange-400" />

                        <div>
                            <h2 className="text-sm font-semibold text-slate-900">
                                Header Findings
                            </h2>

                            <p className="mt-1 text-xs text-slate-500">
                                Detected routing and header anomalies
                            </p>
                        </div>
                    </div>
                </div>

                <div className="space-y-3 p-5">
                    {findings.length === 0 ? (
                        <div className="rounded-lg border border-green-500/20 bg-green-500/5 p-5 text-sm text-green-400">
                            No header anomalies were reported.
                        </div>
                    ) : (
                        findings.map(
                            (finding, index) => (
                                <Finding
                                    key={
                                        finding.code ||
                                        finding.id ||
                                        index
                                    }
                                    finding={finding}
                                />
                            )
                        )
                    )}
                </div>
            </div>
        </div>
    );
}