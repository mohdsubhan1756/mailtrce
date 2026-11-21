import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight, History } from "lucide-react";
import PageHeader from "../components/common/PageHeader";
import Loading from "../components/common/Loading";
import { getHeaderAnalyses } from "../services/headerService";
import { getAuthenticationAnalyses } from "../services/authenticationService";
import { getUrlAnalyses } from "../services/urlService";

const sources = [
    { label: "Header forensics", path: "/headers", load: getHeaderAnalyses },
    { label: "Authentication", path: "/authentication", load: getAuthenticationAnalyses },
    { label: "URL intelligence", path: "/urls", load: getUrlAnalyses },
];

function recordsFrom(data) {
    if (Array.isArray(data)) return data;
    return data?.items || data?.analyses || [];
}

export default function AnalysisHistory() {
    const [records, setRecords] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    useEffect(() => {
        let active = true;
        Promise.all(sources.map(async (source) => {
            const data = await source.load({ limit: 100 });
            return recordsFrom(data).map((item) => ({ ...item, analysisType: source.label, analysisPath: source.path }));
        })).then((groups) => {
            if (active) setRecords(groups.flat().sort((a, b) => new Date(b.updated_at || b.created_at || 0) - new Date(a.updated_at || a.created_at || 0)));
        }).catch((requestError) => {
            if (active) setError(requestError.friendlyMessage || "Could not load analysis history.");
        }).finally(() => {
            if (active) setLoading(false);
        });
        return () => { active = false; };
    }, []);

    return <div>
        <PageHeader title="Analysis history" description="Browse saved header, authentication, and URL analyses across email evidence." />
        {error && <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">{error}</div>}
        {loading ? <Loading text="Loading analysis history..." /> : records.length === 0 ? (
            <div className="card p-8 text-center"><History className="mx-auto h-8 w-8 text-slate-400" /><p className="mt-3 font-medium text-slate-800">No saved analyses yet</p><p className="mt-1 text-sm text-slate-500">Run an analysis from an email to see it here.</p></div>
        ) : <div className="card overflow-hidden"><div className="divide-y divide-slate-100">{records.map((record, index) => {
            const emailId = record.email_id || record.emailId;
            return <div key={`${record.analysisType}-${emailId}-${index}`} className="flex flex-wrap items-center justify-between gap-3 px-5 py-4">
                <div className="min-w-0"><p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{record.analysisType}</p><p className="mt-1 truncate font-medium text-slate-800">{record.subject || emailId || "Email evidence"}</p><p className="mt-1 text-xs text-slate-500">{record.updated_at || record.created_at || "Saved analysis"}</p></div>
                {emailId && <Link className="inline-flex items-center gap-1 text-sm font-medium text-blue-700 hover:text-blue-900" to={`${record.analysisPath}?email=${encodeURIComponent(emailId)}`}>Open analysis <ArrowUpRight className="h-4 w-4" /></Link>}
            </div>;
        })}</div></div>}
    </div>;
}
