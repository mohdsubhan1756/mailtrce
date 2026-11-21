import React from "react";

const TYPE_COLORS = {
    sender_domain: "#7c3aed",
    sender_address: "#8b5cf6",
    domain: "#0284c7",
    ip: "#0f766e",
    sha256: "#b45309",
    header_return_path_domain: "#be123c",
    header_reply_to_domain: "#db2777",
    header_message_id_domain: "#9333ea",
};

const TYPE_LABELS = {
    sender_domain: "Sender domain",
    sender_address: "Sender address",
    domain: "URL domain",
    ip: "IP address",
    sha256: "Attachment SHA-256",
    header_return_path_domain: "Return-Path domain",
    header_reply_to_domain: "Reply-To domain",
    header_message_id_domain: "Message-ID domain",
};

function shorten(value, max = 34) {
    const text = String(value || "");
    return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export default function CampaignGraph({ graph }) {
    const nodes = graph?.nodes || [];
    const edges = graph?.edges || [];
    const emails = nodes.filter((node) => node.type === "email");
    const indicators = nodes.filter((node) => node.type === "indicator");
    const emailY = new Map(emails.map((node, index) => [node.id, 38 + index * 52]));
    const indicatorY = new Map(indicators.map((node, index) => [node.id, 38 + index * 44]));
    const height = Math.max(180, emails.length * 52 + 24, indicators.length * 44 + 24);

    if (emails.length === 0 || indicators.length === 0) {
        return <p className="text-sm text-slate-500">Not enough extracted indicators to draw a relationship graph yet.</p>;
    }

    return (
        <div>
            <div className="mb-3 flex flex-wrap gap-3 text-xs text-slate-600">
                <span>Email records</span>
                {Array.from(new Set(indicators.map((node) => node.indicator_type))).map((type) => (
                    <span key={type} className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ backgroundColor: TYPE_COLORS[type] || "#64748b" }} />{TYPE_LABELS[type] || type.replaceAll("_", " ")}</span>
                ))}
            </div>
            <div className="max-h-[540px] overflow-auto rounded-lg border border-slate-200 bg-slate-50">
                <svg role="img" aria-label="Email and shared evidence relationship graph" viewBox={`0 0 920 ${height}`} className="min-w-[760px]" style={{ height, width: "100%" }}>
                    {edges.map((edge, index) => {
                        const y1 = emailY.get(edge.source);
                        const y2 = indicatorY.get(edge.target);
                        if (y1 === undefined || y2 === undefined) return null;
                        return <line key={`${edge.source}-${edge.target}-${index}`} x1="300" y1={y1 + 12} x2="486" y2={y2 + 10} stroke="#cbd5e1" strokeWidth="1.5" />;
                    })}
                    {emails.map((node) => {
                        const y = emailY.get(node.id);
                        return <g key={node.id}><rect x="20" y={y} width="280" height="27" rx="6" fill={node.current ? "#dbeafe" : "#fff"} stroke={node.current ? "#2563eb" : "#cbd5e1"} /><text x="31" y={y + 17} fontSize="11" fill="#1e293b">{shorten(node.label, 38)}</text>{node.current && <text x="255" y={y + 17} fontSize="9" fill="#1d4ed8">CURRENT</text>}</g>;
                    })}
                    {indicators.map((node) => {
                        const y = indicatorY.get(node.id);
                        const color = TYPE_COLORS[node.indicator_type] || "#64748b";
                        const label = TYPE_LABELS[node.indicator_type] || node.indicator_type.replaceAll("_", " ");
                        return <g key={node.id}><title>{`${label}: ${node.value}`}</title><circle cx="500" cy={y + 10} r="6" fill={color} /><text x="515" y={y + 8} fontSize="9" fontWeight="600" fill={color}>{label.toUpperCase()}</text><text x="515" y={y + 23} fontSize="11" fill="#334155">{shorten(node.value, 48)}</text></g>;
                    })}
                </svg>
            </div>
            {(graph.omitted_related_count > 0 || graph.omitted_indicator_count > 0) && <p className="mt-2 text-xs text-slate-500">Graph is limited for readability: {graph.omitted_related_count || 0} related email(s) and {graph.omitted_indicator_count || 0} indicator(s) omitted. The evidence lists retain available matches.</p>}
        </div>
    );
}
