import React from "react";

import {
    ExternalLink,
    Globe
} from "lucide-react";

import UrlRiskBadge from "./UrlRiskBadge";

export default function UrlTable({
    urls = []
}) {
    if (!urls.length) {
        return (
            <div className="py-10 text-center text-sm text-slate-500">
                No URLs were extracted from this email.
            </div>
        );
    }

    return (
        <div className="overflow-x-auto">
            <table className="w-full min-w-[760px]">
                <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-left">
                        <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                            URL
                        </th>

                        <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                            Domain
                        </th>

                        <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                            Verdict
                        </th>

                        <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                            Score
                        </th>
                    </tr>
                </thead>

                <tbody>
                    {urls.map((item, index) => {
                        const url =
                            item.url ||
                            item.original_url ||
                            item.value ||
                            "";

                        const domain =
                            item.domain ||
                            item.hostname ||
                            "—";

                        return (
                            <tr
                                key={`${url}-${index}`}
                                className="table-row"
                            >
                                <td className="max-w-[400px] px-5 py-4">
                                    <div className="flex items-center gap-2">
                                        <Globe className="h-4 w-4 shrink-0 text-cyan-400" />

                                        <a
                                            href={url}
                                            target="_blank"
                                            rel="noreferrer"
                                            onClick={(event) =>
                                                event.stopPropagation()
                                            }
                                            className="truncate text-xs text-slate-500 hover:text-cyan-400"
                                        >
                                            {url}
                                        </a>

                                        <ExternalLink className="h-3 w-3 shrink-0 text-slate-700" />
                                    </div>
                                </td>

                                <td className="px-5 py-4 font-mono text-xs text-slate-500">
                                    {domain}
                                </td>

                                <td className="px-5 py-4">
                                    <UrlRiskBadge
                                        score={
                                            item.risk_score ||
                                            item.score
                                        }
                                        verdict={
                                            item.verdict ||
                                            item.status ||
                                            item.classification
                                        }
                                    />
                                </td>

                                <td className="px-5 py-4 text-xs text-slate-500">
                                    {item.risk_score ??
                                        item.score ??
                                        "—"}
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
}