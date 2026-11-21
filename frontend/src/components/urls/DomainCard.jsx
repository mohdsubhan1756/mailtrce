import React, { useState } from "react";

import {
    Globe2,
    AlertTriangle,
    CheckCircle2
} from "lucide-react";

import Badge from "../common/Badge";
import Button from "../common/Button";
import { getDomainIntelligence } from "../../services/urlService";

export default function DomainCard({
    domain
}) {
    const [details, setDetails] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const score =
        Number(
            domain.risk_score ||
            domain.score ||
            0
        );

    const suspicious =
        domain.suspicious ||
        domain.is_suspicious ||
        score >= 60;

    return (
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-5">
            <div className="flex items-start gap-3">
                <div
                    className={`
            rounded-lg p-2.5
            ${suspicious
                            ? "bg-red-500/10"
                            : "bg-cyan-500/10"
                        }
          `}
                >
                    <Globe2
                        className={`
              h-5 w-5
              ${suspicious
                                ? "text-red-400"
                                : "text-cyan-400"
                            }
            `}
                    />
                </div>

                <div className="min-w-0 flex-1">
                    <div className="flex items-start justify-between gap-3">
                        <div>
                            <p className="break-all font-mono text-sm text-slate-700">
                                {domain.domain ||
                                    domain.hostname ||
                                    "Unknown domain"}
                            </p>

                            <p className="mt-1 text-xs text-slate-500">
                                Domain intelligence
                            </p>
                        </div>

                        {suspicious ? (
                            <AlertTriangle className="h-4 w-4 text-red-400" />
                        ) : (
                            <CheckCircle2 className="h-4 w-4 text-green-400" />
                        )}
                    </div>

                    <div className="mt-4 flex flex-wrap gap-2">
                        <Badge
                            variant={
                                suspicious
                                    ? "danger"
                                    : "success"
                            }
                        >
                            {suspicious
                                ? "Suspicious"
                                : "Observed"}
                        </Badge>

                        {domain.lookalike && (
                            <Badge variant="warning">
                                Lookalike
                            </Badge>
                        )}

                        {domain.homograph && (
                            <Badge variant="warning">
                                Homograph
                            </Badge>
                        )}

                        {domain.mx_present && (
                            <Badge variant="info">
                                MX
                            </Badge>
                        )}
                    </div>
                </div>
            </div>

            <div className="mt-5 border-t border-slate-200 pt-4">
                <div className="flex justify-between">
                    <span className="text-xs text-slate-500">
                        Risk score
                    </span>

                    <span className="text-sm font-semibold text-slate-700">
                        {score}/100
                    </span>
                </div>

                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-100">
                    <div
                        className={`
              h-full rounded-full
              ${score >= 70
                                ? "bg-red-500"
                                : score >= 40
                                    ? "bg-yellow-500"
                                    : "bg-green-500"
                            }
            `}
                        style={{
                            width: `${Math.min(
                                score,
                                100
                            )}%`
                        }}
                    />
                </div>
                <Button
                    type="button"
                    variant="secondary"
                    className="mt-4 w-full"
                    loading={loading}
                    onClick={async () => {
                        const hostname = domain.domain || domain.hostname;
                        if (!hostname) return;
                        setLoading(true);
                        setError("");
                        try {
                            setDetails(await getDomainIntelligence(hostname));
                        } catch (requestError) {
                            setError(requestError.friendlyMessage || "Domain lookup failed.");
                        } finally {
                            setLoading(false);
                        }
                    }}
                >
                    Check domain intelligence
                </Button>
                {error && <p className="mt-2 text-xs text-red-700" role="alert">{error}</p>}
                {details && (
                    <div className="mt-3 rounded-lg border border-slate-200 bg-white p-3 text-xs text-slate-600">
                        <p className="font-medium text-slate-800">Live domain results</p>
                        <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all">{JSON.stringify(details, null, 2)}</pre>
                    </div>
                )}
            </div>
        </div>
    );
}
