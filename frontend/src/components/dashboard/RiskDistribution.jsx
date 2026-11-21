import React from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { getEmailRiskScore } from "../../utils/formatters";

const COLORS = {
    Critical: "#dc2626",
    High: "#ea580c",
    Medium: "#d97706",
    Low: "#2563eb",
    Safe: "#16a34a",
    "Not analyzed": "#94a3b8",
};

export default function RiskDistribution({ emails = [] }) {
    const groups = [
        { name: "Critical", test: (score) => score >= 90 },
        { name: "High", test: (score) => score >= 70 && score < 90 },
        { name: "Medium", test: (score) => score >= 40 && score < 70 },
        { name: "Low", test: (score) => score > 0 && score < 40 },
        { name: "Safe", test: (score) => score === 0 },
    ];
    const data = groups
        .map(({ name, test }) => ({
            name,
            value: emails.filter((email) => {
                const score = getEmailRiskScore(email);
                return score !== null && test(score);
            }).length,
        }))
        .concat({
            name: "Not analyzed",
            value: emails.filter((email) => getEmailRiskScore(email) === null).length,
        })
        .filter((item) => item.value > 0);

    return (
        <section className="card">
            <div className="card-header">
                <div>
                    <h2 className="text-sm font-semibold text-slate-900">Risk distribution</h2>
                    <p className="mt-1 text-xs text-slate-500">Latest available risk scores</p>
                </div>
            </div>
            <div className="h-[280px] p-4">
                {data.length === 0 ? (
                    <div className="flex h-full items-center justify-center text-sm text-slate-500">
                        No email records yet.
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                            <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={65} outerRadius={95} paddingAngle={3}>
                                {data.map((entry) => <Cell key={entry.name} fill={COLORS[entry.name]} />)}
                            </Pie>
                            <Tooltip contentStyle={{ background: "#fff", border: "1px solid #e2e8f0", borderRadius: "8px", color: "#0f172a" }} />
                        </PieChart>
                    </ResponsiveContainer>
                )}
            </div>
            <div className="flex flex-wrap gap-2 px-5 pb-4">
                {data.map((item) => (
                    <span key={item.name} className="inline-flex items-center gap-1.5 text-xs text-slate-600">
                        <span className="h-2 w-2 rounded-full" style={{ backgroundColor: COLORS[item.name] }} />
                        {item.name}: {item.value}
                    </span>
                ))}
            </div>
        </section>
    );
}
