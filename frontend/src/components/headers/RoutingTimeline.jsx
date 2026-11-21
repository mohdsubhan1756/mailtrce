import React from "react";

import {
    Server,
    ArrowDown
} from "lucide-react";

export default function RoutingTimeline({
    hops = []
}) {
    if (!hops.length) {
        return (
            <div className="py-10 text-center text-sm text-slate-500">
                No routing hops were extracted.
            </div>
        );
    }

    return (
        <div className="space-y-1">
            {hops.map((hop, index) => {
                const ips =
                    hop.public_ips ||
                    hop.ips ||
                    [];

                return (
                    <React.Fragment key={index}>
                        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                            <div className="flex items-start gap-3">
                                <div className="rounded-lg bg-sky-500/10 p-2">
                                    <Server className="h-4 w-4 text-sky-400" />
                                </div>

                                <div className="min-w-0 flex-1">
                                    <div className="flex items-center justify-between gap-4">
                                        <h3 className="text-sm font-medium text-slate-700">
                                            Hop {hop.position || index + 1}
                                        </h3>

                                        {hop.timestamp && (
                                            <span className="text-[11px] text-slate-500">
                                                {hop.timestamp}
                                            </span>
                                        )}
                                    </div>

                                    <p className="mt-2 break-all font-mono text-xs text-slate-500">
                                        {hop.from ||
                                            hop.from_host ||
                                            "Unknown"}{" "}
                                        →{" "}
                                        {hop.by ||
                                            hop.by_host ||
                                            "Unknown"}
                                    </p>

                                    {ips.length > 0 && (
                                        <div className="mt-3 flex flex-wrap gap-2">
                                            {ips.map((ip) => (
                                                <span
                                                    key={ip}
                                                    className="rounded-md border border-slate-200 bg-slate-100 px-2 py-1 font-mono text-[11px] text-cyan-400"
                                                >
                                                    {ip}
                                                </span>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>

                        {index < hops.length - 1 && (
                            <div className="flex justify-center py-1">
                                <ArrowDown className="h-4 w-4 text-slate-700" />
                            </div>
                        )}
                    </React.Fragment>
                );
            })}
        </div>
    );
}