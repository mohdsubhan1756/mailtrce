import React from "react";
import { Link } from "react-router-dom";
import { Activity, BellRing, FileSearch, FolderKanban, Globe, Mail, MapPin, Network, ShieldAlert, ShieldCheck, Sparkles, Paperclip, Fingerprint } from "lucide-react";

const modules = [
    ["Email ingestion & normalization", "Upload .eml evidence and extract message data.", "/emails", Mail],
    ["Email header forensics", "Review identity fields and message routing.", "/headers", FileSearch],
    ["SPF / DKIM / DMARC", "Evaluate authentication and alignment evidence.", "/authentication", ShieldCheck],
    ["URL & domain intelligence", "Inspect links, domains, and lookalike indicators.", "/urls", Globe],
    ["AI / NLP threat signals", "Rule-based language checks; experimental corpus scoring is separate.", "/extended", Sparkles],
    ["Attachment forensics", "Static file and archive characteristics.", "/extended", Paperclip],
    ["IP intelligence & geolocation", "Local classification; provider reputation is optional.", "/extended", MapPin],
    ["Threat intelligence correlation", "Local correlation plus optional external providers.", "/extended", Fingerprint],
    ["Correlation & campaign intelligence", "Connect shared headers, domains, IPs, and hashes.", "/extended", Network],
    ["Risk & attribution", "Explainable triage score; actor attribution is unavailable.", "/extended", Activity],
    ["Alerts & SOC dashboard", "Review dashboard activity and in-app alerts.", "/alerts", BellRing],
    ["Cases & forensic reporting", "Group evidence and export JSON reports.", "/cases", FolderKanban],
    ["Privacy, evidence & audit", "Hash verification, audit records, masking, and retention settings.", "/extended", ShieldAlert],
];

export default function ModuleStatus() {
    return (
        <section className="card mt-6" aria-labelledby="module-map-title">
            <div className="card-header">
                <div>
                    <h2 id="module-map-title" className="text-sm font-semibold text-slate-900">MailTrace investigation modules</h2>
                    <p className="mt-1 text-xs text-slate-500">How the 13 project modules map to the current workspace.</p>
                </div>
            </div>
            <ol className="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-3">
                {modules.map(([name, description, path, Icon], index) => (
                    <li key={name}>
                        <Link to={path} className="flex h-full gap-3 rounded-xl border border-slate-200 p-3 transition hover:border-teal-300 hover:bg-teal-50/40">
                            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-600"><Icon className="h-4 w-4" /></span>
                            <span className="min-w-0 flex-1">
                                <span className="block text-xs font-semibold text-slate-800">{index + 1}. {name}</span>
                                <span className="mt-1 block text-xs leading-5 text-slate-500">{description}</span>
                            </span>
                        </Link>
                    </li>
                ))}
            </ol>
        </section>
    );
}
