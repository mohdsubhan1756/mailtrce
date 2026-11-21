import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import {
    Mail,
    ShieldAlert,
    Globe,
    Activity,
    ArrowRight,
    ShieldCheck,
    Search,
    Radar,
    BellRing,
    FolderKanban
} from "lucide-react";

import { getEmails } from "../services/emailService";
import { extractItems, getSenderDomain } from "../utils/formatters";

import PageHeader from "../components/common/PageHeader";
import StatCard from "../components/common/StatCard";
import Loading from "../components/common/Loading";
import ErrorState from "../components/common/ErrorState";

import RiskDistribution from "../components/dashboard/RiskDistribution";
import ThreatOverview from "../components/dashboard/ThreatOverview";
import ModuleStatus from "../components/dashboard/ModuleStatus";

const quickLinks = [
    {
        title: "Email Inbox",
        description: "Review ingested mail and case evidence.",
        path: "/emails",
        icon: Mail,
        accent: "bg-blue-100 text-blue-700"
    },
    {
        title: "Header Forensics",
        description: "Inspect route paths and spoofing signals.",
        path: "/headers",
        icon: Search,
        accent: "bg-violet-100 text-violet-700"
    },
    {
        title: "Authentication",
        description: "Check SPF, DKIM, and DMARC integrity.",
        path: "/authentication",
        icon: ShieldCheck,
        accent: "bg-emerald-100 text-emerald-700"
    },
    {
        title: "URL Intelligence",
        description: "Find suspicious domains and phishing patterns.",
        path: "/urls",
        icon: Radar,
        accent: "bg-cyan-100 text-cyan-700"
    },
    {
        title: "Extended Analysis",
        description: "Run full risk, threat, attachment, and IP review.",
        path: "/extended",
        icon: Activity,
        accent: "bg-amber-100 text-amber-700"
    },
    {
        title: "Alerts",
        description: "Review emails raised by the risk engine.",
        path: "/alerts",
        icon: BellRing,
        accent: "bg-rose-100 text-rose-700"
    },
    {
        title: "Cases",
        description: "Group evidence and follow investigations.",
        path: "/cases",
        icon: FolderKanban,
        accent: "bg-indigo-100 text-indigo-700"
    }
];

export default function Dashboard() {
    const [emails, setEmails] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const loadEmails = useCallback(async () => {
        try {
            setLoading(true);
            setError("");
            const data = await getEmails({ limit: 100 });
            setEmails(extractItems(data));
        } catch (error) {
            setError(error.friendlyMessage || "Unable to load the dashboard.");
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        void loadEmails();
    }, [loadEmails]);

    const analyzed = emails.filter(
        (email) =>
            email.module?.header_forensics ||
            email.module?.authentication ||
            email.module?.url_domain_intelligence ||
            email.module?.risk_analysis
    ).length;

    const domains = new Set();
    emails.forEach((email) => {
        const domain = getSenderDomain(email.sender);
        if (domain) {
            domains.add(domain);
        }
    });

    if (loading) {
        return <Loading text="Loading dashboard..." />;
    }

    if (error) {
        return (
            <div>
                <PageHeader title="Overview" description="Your email investigation workspace" />
                <div className="card">
                    <ErrorState message={error} onRetry={loadEmails} />
                </div>
            </div>
        );
    }

    return (
        <div>
            <PageHeader
                title="Overview"
                description="A clearer view of your recent email risk and forensic activity."
            >
                <div className="inline-flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1.5 text-xs font-medium text-emerald-700">
                    <Activity className="h-3.5 w-3.5" />
                    Forensic workspace
                </div>
            </PageHeader>

            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
                <StatCard
                    title="Emails Ingested"
                    value={emails.length}
                    subtitle="Most recent 100 records"
                    icon={Mail}
                    iconClass="text-blue-600"
                    iconBackground="bg-blue-100"
                />

                <StatCard
                    title="Emails Analyzed"
                    value={analyzed}
                    subtitle="Completed checks"
                    icon={ShieldAlert}
                    iconClass="text-violet-600"
                    iconBackground="bg-violet-100"
                />

                <StatCard
                    title="Unique Domains"
                    value={domains.size}
                    subtitle="In the latest 100 records"
                    icon={Globe}
                    iconClass="text-teal-600"
                    iconBackground="bg-teal-100"
                />
            </div>

            <div className="mt-6">
                <div className="mb-4 flex items-center justify-between gap-3">
                    <h2 className="text-lg font-semibold text-slate-900">Quick actions</h2>
                    <span className="text-sm text-slate-500">Full forensic workflow</span>
                </div>

                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                    {quickLinks.map((item) => {
                        const Icon = item.icon;

                        return (
                            <Link
                                key={item.path}
                                to={item.path}
                                className="group rounded-2xl border border-slate-200 bg-white p-4 shadow-sm transition hover:-translate-y-0.5 hover:border-blue-200 hover:shadow-md"
                            >
                                <div className={`mb-4 flex h-11 w-11 items-center justify-center rounded-xl ${item.accent}`}>
                                    <Icon className="h-5 w-5" />
                                </div>

                                <div className="mb-2 flex items-center justify-between gap-2">
                                    <h3 className="text-sm font-semibold text-slate-900">{item.title}</h3>
                                    <ArrowRight className="h-4 w-4 text-slate-500 transition group-hover:translate-x-0.5 group-hover:text-blue-600" />
                                </div>

                                <p className="text-sm leading-6 text-slate-500">{item.description}</p>
                            </Link>
                        );
                    })}
                </div>
            </div>

            <div className="mt-6 grid gap-6 xl:grid-cols-[1.35fr_0.95fr]">
                <ThreatOverview emails={emails} />
                <RiskDistribution emails={emails} />
            </div>

            <ModuleStatus />
        </div>
    );
}
