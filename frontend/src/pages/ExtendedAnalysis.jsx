import React, { useEffect, useState } from "react";
import { Activity, CheckCircle2, Database, Download, MapPin, ShieldAlert } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";

import PageHeader from "../components/common/PageHeader";
import Button from "../components/common/Button";
import Loading from "../components/common/Loading";
import Badge from "../components/common/Badge";
import CampaignGraph from "../components/extended/CampaignGraph";
import { getEmails } from "../services/emailService";
import {
    analyzeExtended,
    downloadPdfReport,
    getAudit,
    getExtendedAnalysis,
    getAnalystFeedback,
    getEvaluationMetrics,
    saveAnalystFeedback,
    verifyEvidence,
    verifyAuditChain
} from "../services/extendedAnalysisService";
import { extractItems, formatDate, formatValue } from "../utils/formatters";
import { loadAnalysisState, saveAnalysisState } from "../utils/analysisStorage";

function Panel({ title, icon: Icon, children }) {
    return (
        <section className="card">
            <div className="card-header">
                <div className="flex items-center gap-3">
                    <Icon className="h-4 w-4 text-sky-400" />
                    <h2 className="text-sm font-semibold text-slate-900">{title}</h2>
                </div>
            </div>
            <div className="p-5">{children}</div>
        </section>
    );
}

function JsonValue({ value }) {
    return <span className="break-all text-right text-xs text-slate-500">{formatValue(value)}</span>;
}

function Metric({ label, value }) {
    return <div className="rounded-lg border border-slate-200 bg-white p-3"><p className="text-xs text-slate-500">{label}</p><p className="mt-1 text-lg font-semibold text-slate-800">{value}</p></div>;
}

function formatRate(value) {
    return typeof value === "number" ? `${(value * 100).toFixed(1)}%` : "—";
}

export default function ExtendedAnalysis() {
    const [params] = useSearchParams();
    const queryEmail = params.get("email") || "";
    const stored = loadAnalysisState("extended");
    const [emailId, setEmailId] = useState(params.get("email") || stored?.emailId || "");
    const [emails, setEmails] = useState([]);
    const [analysis, setAnalysis] = useState(
        params.get("email") === stored?.emailId ||
            (!params.get("email") && stored?.emailId)
            ? stored.analysis
            : null
    );
    const [audit, setAudit] = useState([]);
    const [evidence, setEvidence] = useState(null);
    const [auditVerification, setAuditVerification] = useState(null);
    const [feedback, setFeedback] = useState(null);
    const [feedbackNote, setFeedbackNote] = useState("");
    const [evaluationMetrics, setEvaluationMetrics] = useState(null);
    const [savingFeedback, setSavingFeedback] = useState(false);
    const [loading, setLoading] = useState(false);
    const [analyzing, setAnalyzing] = useState(false);
    const [error, setError] = useState("");

    useEffect(() => {
        getEmails({ limit: 100 })
            .then((data) => setEmails(extractItems(data)))
            .catch(() => setEmails([]));
    }, []);

    const loadStored = async (id) => {
        if (!id) {
            setAnalysis(null);
            return;
        }
        try {
            setLoading(true);
            setError("");
            const [data, auditData, feedbackData, metrics] = await Promise.all([
                getExtendedAnalysis(id),
                getAudit(id),
                getAnalystFeedback(id),
                getEvaluationMetrics(),
            ]);
            setAnalysis(data);
            setAudit(auditData);
            setFeedback(feedbackData);
            setFeedbackNote(feedbackData?.note || "");
            setEvaluationMetrics(metrics);
            saveAnalysisState("extended", { emailId: id, analysis: data });
        } catch (requestError) {
            setError(requestError.friendlyMessage || "Unable to load stored analysis.");
            setAnalysis(null);
            setAudit([]);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (queryEmail) {
            setEmailId(queryEmail);
            void loadStored(queryEmail);
        } else if (stored?.emailId) {
            void loadStored(stored.emailId);
        }
    }, [queryEmail]);

    const runAnalysis = async () => {
        if (!emailId) return;
        try {
            setAnalyzing(true);
            setError("");
            await analyzeExtended(emailId);
            const [data, auditData, feedbackData, metrics] = await Promise.all([
                getExtendedAnalysis(emailId),
                getAudit(emailId),
                getAnalystFeedback(emailId),
                getEvaluationMetrics(),
            ]);
            setAnalysis(data);
            saveAnalysisState("extended", { emailId, analysis: data });
            setAudit(auditData);
            setFeedback(feedbackData);
            setFeedbackNote(feedbackData?.note || "");
            setEvaluationMetrics(metrics);
        } catch (requestError) {
            setError(requestError.friendlyMessage || "Extended analysis failed.");
        } finally {
            setAnalyzing(false);
        }
    };

    const checkEvidence = async () => {
        try {
            setEvidence(await verifyEvidence(emailId));
            setAudit(await getAudit(emailId));
        } catch (requestError) {
            setError(requestError.friendlyMessage || "Evidence verification failed.");
        }
    };

    const checkAudit = async () => {
        try {
            setAuditVerification(await verifyAuditChain(emailId));
        } catch (requestError) {
            setError(requestError.friendlyMessage || "Audit verification failed.");
        }
    };

    const reviewEmail = async (label) => {
        if (!emailId) return;
        try {
            setSavingFeedback(true);
            const saved = await saveAnalystFeedback(emailId, { label, note: feedbackNote });
            setFeedback(saved);
            setFeedbackNote(saved.note || "");
            setEvaluationMetrics(await getEvaluationMetrics());
        } catch (requestError) {
            setError(requestError.friendlyMessage || "Unable to save analyst feedback.");
        } finally {
            setSavingFeedback(false);
        }
    };

    const downloadReport = () => {
        if (!report) return;
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `mailtrace-report-${emailId}.json`;
        link.click();
        URL.revokeObjectURL(url);
    };

    const downloadPdf = async () => {
        if (!emailId) return;
        try {
            await downloadPdfReport(emailId);
        } catch (requestError) {
            setError(requestError.friendlyMessage || "PDF report download failed.");
        }
    };

    const risk = analysis?.risk;
    const experimentalModel = analysis?.threat?.experimental_model;
    const ips = analysis?.ips?.ips || [];
    const findings = analysis?.threat?.findings || [];
    const attachments = analysis?.attachments?.attachments || [];
    const relatedEmails = analysis?.campaign?.related_emails || [];
    const intelligence = analysis?.intelligence || {};
    const indicators = intelligence.indicators || [];
    const intelligenceMatches = intelligence.matches || [];
    const report = analysis?.report;
    const privacy = analysis?.privacy;

    return (
        <div>
            <PageHeader
                title="Extended Forensics"
                description="Offline threat, attachment, IP, correlation, risk, evidence, and audit analysis"
            />

            <div className="card mb-6">
                <div className="card-body">
                    <div className="grid gap-3 md:grid-cols-[1fr_auto_auto]">
                        <select
                            value={emailId}
                            onChange={(event) => {
                                setEmailId(event.target.value);
                                setAnalysis(null);
                                loadStored(event.target.value);
                            }}
                            className="input"
                        >
                            <option value="">Select an email evidence record</option>
                            {emails.map((email) => (
                                <option key={email.email_id} value={email.email_id}>
                                    {email.subject || email.email_id}
                                </option>
                            ))}
                        </select>
                        <Button onClick={runAnalysis} disabled={!emailId} loading={analyzing}>
                            Run Full Analysis
                        </Button>
                        <Button variant="secondary" onClick={checkEvidence} disabled={!emailId}>
                            Verify Evidence
                        </Button>
                    </div>
                    {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
                </div>
            </div>

            {loading ? <Loading text="Loading extended analysis..." /> : !analysis ? (
                <div className="card p-10 text-center text-sm text-slate-500">
                    Select an email and run extended analysis.
                </div>
            ) : (
                <div className="space-y-6">
                    <div className="grid gap-4 sm:grid-cols-3">
                        <div className="card p-5"><p className="text-xs text-slate-500">Risk Score</p><p className="mt-2 text-2xl font-bold text-slate-900">{risk?.score ?? 0}/100</p><Badge variant={String(risk?.risk_level || "safe").toLowerCase()}>{risk?.risk_level || "MINIMAL"}</Badge></div>
                        <div className="card p-5"><p className="text-xs text-slate-500">Threat Findings</p><p className="mt-2 text-2xl font-bold text-slate-900">{findings.length}</p></div>
                        <div className="card p-5"><p className="text-xs text-slate-500">IP Records</p><p className="mt-2 text-2xl font-bold text-slate-900">{ips.length}</p></div>
                    </div>

                    <Panel title="Forensic report summary" icon={Activity}>
                        <div className="mb-4 flex flex-wrap justify-end gap-2">
                            <Button variant="secondary" onClick={downloadReport} disabled={!report}><Download className="h-4 w-4" />Download JSON</Button>
                            <Button variant="secondary" onClick={downloadPdf} disabled={!emailId}>Download PDF</Button>
                        </div>
                        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                            <div><p className="text-xs text-slate-500">Case</p>{report?.email?.case_id ? <Link to={`/cases?case=${encodeURIComponent(report.email.case_id)}`} className="mt-1 block break-all text-sm text-blue-700 hover:underline">{report.email.case_id}</Link> : <p className="mt-1 text-sm text-slate-800">Not assigned</p>}</div>
                            <div><p className="text-xs text-slate-500">Report generated</p><p className="mt-1 text-sm text-slate-800">{formatDate(report?.generated_at)}</p></div>
                            <div><p className="text-xs text-slate-500">Risk verdict</p><p className="mt-1 text-sm font-medium text-slate-800">{report?.risk?.verdict || risk?.verdict || "Not available"}</p></div>
                            <div><p className="text-xs text-slate-500">URLs in message</p><p className="mt-1 text-sm text-slate-800">{report?.email?.urls?.length ?? "—"}</p></div>
                            <div><p className="text-xs text-slate-500">Attachments in report</p><p className="mt-1 text-sm text-slate-800">{report?.attachments?.attachments?.length ?? attachments.length}</p></div>
                        </div>
                        {report?.risk?.components && <div className="mt-4 border-t border-slate-200 pt-4"><p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Risk components</p><div className="flex flex-wrap gap-2">{Object.entries(report.risk.components).map(([name, value]) => <span key={name} className="rounded-full bg-slate-100 px-3 py-1 text-xs text-slate-700">{name.replaceAll("_", " ")}: {formatValue(value)}</span>)}</div></div>}
                    </Panel>

                    <Panel title="Campaign correlation & investigation graph" icon={Activity}>
                        <div className="mb-4 grid gap-3 sm:grid-cols-3">
                            <div className="rounded-lg bg-slate-50 p-3"><p className="text-xs text-slate-500">Related emails</p><p className="mt-1 text-lg font-semibold text-slate-900">{relatedEmails.length}</p></div>
                            <div className="rounded-lg bg-slate-50 p-3"><p className="text-xs text-slate-500">Shared evidence strength</p><p className="mt-1 text-sm font-semibold text-slate-900">{analysis.campaign?.correlation_confidence || "NONE"}</p></div>
                            <div className="rounded-lg bg-slate-50 p-3"><p className="text-xs text-slate-500">Relationship types</p><p className="mt-1 text-sm font-semibold text-slate-900">Headers · URLs · IPs · attachment hashes</p></div>
                        </div>
                        <p className="mb-3 text-xs text-slate-500">Potential campaign links come from shared evidence across analyzed messages. {analysis.campaign?.confidence_note || "These links are not confirmed campaign or actor attribution."}</p>
                        <CampaignGraph graph={analysis.campaign?.graph} />
                        {relatedEmails.length > 0 ? <div className="mt-4"><h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Related email evidence</h3><div className="divide-y divide-slate-100 rounded-lg border border-slate-200">{relatedEmails.map((item) => <Link key={item.email_id} to={`/emails/${encodeURIComponent(item.email_id)}`} className="flex flex-wrap items-center justify-between gap-2 p-3 hover:bg-slate-50"><span className="truncate text-sm font-medium text-blue-700">{item.subject || item.email_id}</span><span className="text-xs text-slate-500">{(item.matched_indicators || []).join(", ")}</span></Link>)}</div></div> : <p className="mt-3 text-xs text-slate-500">No other analyzed email currently shares these indicators. This graph shows the selected email and its extracted indicators.</p>}
                    </Panel>

                    <Panel title="Final risk assessment" icon={ShieldAlert}>
                        <div className="flex flex-wrap items-center gap-3"><Badge variant={String(risk?.risk_level || "neutral").toLowerCase()}>{risk?.risk_level || "NOT ASSESSED"}</Badge><span className="text-sm font-semibold text-slate-900">{risk?.verdict || "No verdict available"}</span><span className="text-sm text-slate-600">Score: {risk?.score ?? "—"}/100</span></div>
                        <p className="mt-3 text-sm leading-6 text-slate-600">{risk?.verdict_reason || "Run full analysis to produce a risk assessment."}</p>
                        <p className="mt-2 text-xs text-slate-500">Forensic findings below are observations. They remain separate from this combined triage assessment; a score is not a probability or proof of maliciousness.</p>
                    </Panel>

                    <Panel title="Why this risk score?" icon={ShieldAlert}>
                        <p className="mb-4 text-xs text-slate-500">Each item shows the signal used, its source, the scoring effect, and the evidence available to review. A zero point change means that signal did not raise the final score.</p>
                        <div className="space-y-3">
                            {(risk?.explanations || []).map((item) => (
                                <details key={item.signal} className="rounded-lg border border-slate-200 bg-white p-4">
                                    <summary className="flex cursor-pointer flex-wrap items-center justify-between gap-3">
                                        <span className="text-sm font-semibold text-slate-800">{item.signal}</span>
                                        <span className="text-xs text-slate-600">Signal: {formatValue(item.score)}</span>
                                    </summary>
                                    <p className="mt-3 text-xs text-slate-600">Source: {item.source}</p>
                                    <p className="mt-1 text-xs text-slate-600">Scoring effect: {item.effect}</p>
                                    <pre className="mt-3 max-h-64 overflow-auto rounded bg-slate-50 p-3 text-xs text-slate-600">{JSON.stringify(item.evidence || [], null, 2)}</pre>
                                </details>
                            ))}
                            {!(risk?.explanations || []).length && <p className="text-sm text-slate-500">Run full analysis to create a score explanation.</p>}
                        </div>
                    </Panel>

                    <Panel title="Forensic findings: language signals" icon={ShieldAlert}>
                        <p className="mb-3 text-xs text-slate-500">These text patterns are observations for analyst review, not a standalone malicious or suspicious verdict.</p>
                        <div className="mb-4 grid gap-3 sm:grid-cols-2">
                            <Metric label="Detection method" value={analysis.threat?.analysis_method || "RULE_BASED_LANGUAGE_HEURISTICS"} />
                            <Metric label="Experimental classifier" value={experimentalModel?.available ? "Uncalibrated corpus score available" : "Not trained or unavailable"} />
                        </div>
                        <div className="mt-4 rounded-lg border border-violet-200 bg-violet-50 p-4">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                                <div>
                                    <p className="text-sm font-semibold text-slate-800">Experimental corpus score — not a reliable email verdict</p>
                                    <p className="mt-1 text-xs text-slate-600">Trained on old phishing and non-spam corpora from different sources. It may learn source/style differences instead of phishing behavior.</p>
                                </div>
                                {experimentalModel?.available && (
                                    <span className="text-xs font-medium text-slate-600">
                                        Dataset class: {experimentalModel.label}
                                    </span>
                                )}
                            </div>
                            {experimentalModel?.available ? (
                                <>
                                    <p className="mt-3 rounded border border-amber-300 bg-amber-50 p-3 text-xs font-medium text-amber-900">
                                        Do not interpret these values as calibrated probabilities that this email is phishing or legitimate. This experimental score is excluded from MailTrace’s risk score, alerts, and verdict.
                                    </p>
                                    <div className="mt-3 grid gap-2 sm:grid-cols-2">
                                        <Metric label="Phishing-class score (uncalibrated)" value={`${Math.round(experimentalModel.phishing_probability * 100)}%`} />
                                        <Metric label="Non-spam-class score (not verified benign)" value={`${Math.round(experimentalModel.nonspam_probability * 100)}%`} />
                                    </div>
                                </>
                            ) : (
                                <p className="mt-3 text-xs text-slate-600">
                                    {experimentalModel?.reason || "Experimental model is not available. Install backend/requirements-training.txt and train the proxy model."}
                                </p>
                            )}
                        </div>
                        {findings.length === 0 ? <p className="text-sm text-green-400">No threat-language findings reported.</p> : <div className="space-y-3">{findings.map((item) => <div key={item.code} className="rounded-lg border border-slate-200 bg-slate-50 p-4"><div className="flex justify-between gap-3"><span className="text-sm text-slate-700">{item.title}</span><Badge variant={String(item.severity).toLowerCase()}>{item.severity}</Badge></div><p className="mt-2 text-xs text-slate-500">{item.description}</p></div>)}</div>}
                    </Panel>

                    <Panel title="Attachment Forensics" icon={Database}>
                        {attachments.length === 0 ? <p className="text-sm text-slate-500">No attachments found.</p> : <div className="space-y-2">{attachments.map((item, index) => <div key={`${item.filename}-${index}`} className="grid gap-2 rounded-lg border border-slate-200 bg-slate-50 p-3 sm:grid-cols-4"><JsonValue value={item.filename} /><JsonValue value={item.content_type} /><JsonValue value={item.sha256} /><JsonValue value={item.dangerous_extension ? "Potentially dangerous" : "No dangerous extension"} /></div>)}</div>}
                    </Panel>

                    <Panel title="IP Intelligence & Geolocation" icon={MapPin}>
                        {ips.length === 0 ? <p className="text-sm text-slate-500">No IP addresses found.</p> : <div className="space-y-3">{ips.map((item) => { const location = item.geolocation; const locationLabel = item.documentation_range ? "Reserved for documentation; no location" : location?.available ? [location.city, location.region, location.country].filter(Boolean).join(", ") : location?.reason || "Location data not available"; const addressLabel = item.documentation_range ? "Reserved test address" : item.six_to_four ? "Non-public 6to4 address" : item.public ? "Public address" : item.private ? "Private address" : "Non-public / special-use address"; return <div key={item.ip} className="rounded-lg border border-slate-200 bg-slate-50 p-4"><div className="flex flex-wrap items-center justify-between gap-2"><span className="font-mono text-sm text-slate-700">{item.ip}</span><Badge variant={item.public ? "info" : "neutral"}>{addressLabel}</Badge></div><div className="mt-3 grid gap-3 text-xs sm:grid-cols-2 lg:grid-cols-4"><div><p className="text-slate-500">Location</p><p className="mt-1 text-slate-700">{locationLabel}</p></div><div><p className="text-slate-500">Coordinates</p><p className="mt-1 text-slate-700">{location?.latitude != null ? `${location.latitude}, ${location.longitude}` : "—"}</p></div><div><p className="text-slate-500">Timezone</p><p className="mt-1 text-slate-700">{location?.timezone || "—"}</p></div><div><p className="text-slate-500">Source</p><p className="mt-1 text-slate-700">{location?.source || "Local classification"}</p></div></div></div>; })}</div>}
                    </Panel>

                    {ips.some((item) => item.provider_intelligence || item.ip_reputation) && <Panel title="IP Provider Intelligence" icon={MapPin}>
                        <div className="space-y-3">{ips.filter((item) => item.provider_intelligence || item.ip_reputation).map((item) => <div key={item.ip} className="rounded-lg border border-slate-200 bg-slate-50 p-4"><p className="font-mono text-sm text-slate-700">{item.ip}</p><div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><div><p className="text-xs text-slate-500">ASN / organization</p><p className="mt-1 break-all text-sm text-slate-700">{item.provider_intelligence?.asn || "Unavailable"}</p></div><div><p className="text-xs text-slate-500">Hostname</p><p className="mt-1 break-all text-sm text-slate-700">{item.provider_intelligence?.hostname || "Unavailable"}</p></div><div><p className="text-xs text-slate-500">Abuse confidence</p><p className="mt-1 text-sm text-slate-700">{item.ip_reputation?.abuseConfidenceScore != null ? `${item.ip_reputation.abuseConfidenceScore}%` : "Unavailable"}</p></div><div><p className="text-xs text-slate-500">VPN / proxy / Tor indicators</p><p className="mt-1 break-all text-sm text-slate-700">{formatValue(item.provider_intelligence?.privacy || "Unavailable")}</p></div></div></div>)}</div>
                    </Panel>}

                    <Panel title="Evidence & Audit" icon={Activity}>
                        <div className="mb-4 flex flex-wrap items-center gap-3"><Button variant="secondary" onClick={checkAudit} disabled={!emailId}>Verify audit chain</Button>{auditVerification && <span className={`text-xs font-medium ${auditVerification.integrity_valid ? "text-emerald-700" : auditVerification.status === "FAILED" ? "text-red-700" : "text-amber-700"}`}>{auditVerification.status}: {auditVerification.verified_event_count}/{auditVerification.event_count} events verified{auditVerification.legacy_unhashed_event_count ? ` (${auditVerification.legacy_unhashed_event_count} legacy events lack hashes)` : ""}{auditVerification.legacy_hash_format_event_count ? ` (${auditVerification.legacy_hash_format_event_count} older-format hashes are unverifiable)` : ""}{auditVerification.broken_event_indexes?.length ? ` (${auditVerification.broken_event_indexes.length} chain integrity issue(s))` : ""}</span>}</div>
                        {evidence && <div className="mb-4 rounded-lg border border-slate-200 bg-slate-50 p-4"><div className="flex items-center gap-2 text-sm font-medium"><CheckCircle2 className={evidence.integrity_valid ? "text-green-400" : "text-red-400"} />{evidence.integrity_valid ? "Evidence integrity verified" : "Evidence integrity check failed"}</div><dl className="mt-3 grid gap-3 text-xs sm:grid-cols-2"><div><dt className="text-slate-500">Evidence exists</dt><dd className="mt-1 text-slate-700">{evidence.exists ? "Yes" : "No"}</dd></div><div><dt className="text-slate-500">Checked at</dt><dd className="mt-1 text-slate-700">{formatDate(evidence.checked_at)}</dd></div><div><dt className="text-slate-500">Expected SHA-256</dt><dd className="mt-1 break-all font-mono text-slate-700">{formatValue(evidence.expected_sha256)}</dd></div><div><dt className="text-slate-500">Actual SHA-256</dt><dd className="mt-1 break-all font-mono text-slate-700">{formatValue(evidence.actual_sha256)}</dd></div></dl></div>}
                        <div className="divide-y divide-slate-100">{audit.length === 0 ? <p className="text-sm text-slate-500">No audit events recorded yet.</p> : audit.map((item, index) => <details key={`${item.action}-${index}`} className="py-3"><summary className="flex cursor-pointer list-none justify-between gap-3 text-xs"><span className="font-medium text-slate-700">{item.action}</span><span className="text-slate-500">{formatDate(item.timestamp)}</span></summary>{item.details && <pre className="mt-2 overflow-auto rounded bg-slate-50 p-3 text-xs text-slate-600">{JSON.stringify(item.details, null, 2)}</pre>}</details>)}</div>
                    </Panel>

                    <Panel title="Threat intelligence correlation" icon={ShieldAlert}>
                        <p className="mb-4 text-xs text-slate-500">Source: {intelligence.provider || "Not available"}. External sources queried: {(intelligence.external_sources_queried || []).join(", ") || "None"}.</p>
                        <div className="grid gap-5 lg:grid-cols-2">
                            <div><h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Unique indicators ({indicators.length})</h3>{indicators.length ? <div className="space-y-2">{indicators.map((item, index) => <div key={`${item.type}-${item.value}-${index}`} className="rounded-lg border border-slate-200 bg-slate-50 p-3"><div className="flex flex-wrap justify-between gap-2"><Badge variant="neutral">{item.type}</Badge><span className="break-all font-mono text-xs text-slate-700">{item.value}</span></div><p className="mt-1 text-xs text-slate-500">{item.source}{item.occurrence_count > 1 ? ` · seen ${item.occurrence_count} times in this email` : ""}</p></div>)}</div> : <p className="text-sm text-slate-500">No indicators were extracted.</p>}</div>
                            <div><h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Matches ({intelligenceMatches.length})</h3>{intelligenceMatches.length ? <div className="space-y-2">{intelligenceMatches.map((match, index) => <div key={`${match.type}-${match.value}-${index}`} className="rounded-lg border border-amber-200 bg-amber-50 p-3"><p className="break-all font-mono text-xs text-slate-700">{match.type}: {match.value}</p>{match.matched_email?.email_id && <Link className="mt-2 block text-xs font-medium text-blue-700 hover:underline" to={`/emails/${encodeURIComponent(match.matched_email.email_id)}`}>{match.matched_email.subject || match.matched_email.email_id}</Link>}</div>)}</div> : <p className="text-sm text-slate-500">No matching indicators were found in the local email corpus.</p>}</div>
                        </div>
                        {intelligence.external_matches?.length > 0 && <div className="mt-5"><h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">External intelligence matches</h3><div className="space-y-2">{intelligence.external_matches.map((match, index) => <div key={`${match.provider}-${match.type}-${match.value}-${index}`} className="rounded-lg border border-amber-200 bg-amber-50 p-3"><div className="flex flex-wrap justify-between gap-2"><span className="font-mono text-xs text-slate-700">{match.type}: {match.value}</span><Badge variant="warning">{match.provider}</Badge></div><p className="mt-1 text-xs text-slate-600">{match.abuse_confidence_score != null ? `Abuse confidence ${match.abuse_confidence_score}%` : `${match.result_count || 0} URL scan result(s)`}</p></div>)}</div></div>}
                    </Panel>

                    <Panel title="Analyst review & corpus quality" icon={CheckCircle2}>
                        <p className="mb-4 text-xs text-slate-500">Record a human-reviewed label to measure how MailTrace performs on your reviewed corpus. This does not train or change the model.</p>
                        <div className="grid gap-5 lg:grid-cols-2">
                            <div>
                                <p className="text-xs text-slate-500">Current review</p>
                                <p className="mt-1 text-sm font-medium text-slate-800">{feedback ? `${feedback.label} · ${formatDate(feedback.reviewed_at)}` : "Not reviewed"}</p>
                                <label className="mt-3 block text-xs font-medium text-slate-600" htmlFor="analyst-note">Review note (optional)</label>
                                <textarea id="analyst-note" className="input mt-1 min-h-20 w-full" maxLength={1000} value={feedbackNote} onChange={(event) => setFeedbackNote(event.target.value)} placeholder="Why did you mark this email legitimate or malicious?" />
                                <div className="mt-3 flex flex-wrap gap-2">
                                    <Button variant={feedback?.label === "LEGITIMATE" ? "success" : "secondary"} onClick={() => reviewEmail("LEGITIMATE")} disabled={savingFeedback} loading={savingFeedback}>Mark legitimate</Button>
                                    <Button variant={feedback?.label === "MALICIOUS" ? "danger" : "secondary"} onClick={() => reviewEmail("MALICIOUS")} disabled={savingFeedback} loading={savingFeedback}>Mark malicious</Button>
                                </div>
                            </div>
                            <div className="rounded-lg bg-slate-50 p-4">
                                <p className="text-sm font-semibold text-slate-800">Reviewed-corpus metrics</p>
                                <p className="mt-1 text-xs text-slate-500">Flagged means score ≥ {evaluationMetrics?.threshold ?? 40}, matching the app’s suspicious threshold.</p>
                                <div className="mt-4 grid grid-cols-2 gap-3">
                                    <Metric label="Reviewed with score" value={evaluationMetrics?.reviewed_with_score ?? "—"} />
                                    <Metric label={`False positive rate (${evaluationMetrics?.counts?.false_positive ?? 0}/${evaluationMetrics?.negative_review_count ?? 0} legitimate)`} value={formatRate(evaluationMetrics?.false_positive_rate)} />
                                    <Metric label={`Precision (${evaluationMetrics?.counts?.true_positive ?? 0} true positives)`} value={formatRate(evaluationMetrics?.precision)} />
                                    <Metric label={`Recall (${evaluationMetrics?.counts?.true_positive ?? 0}/${evaluationMetrics?.positive_review_count ?? 0} malicious)`} value={formatRate(evaluationMetrics?.recall)} />
                                </div>
                                {evaluationMetrics && !evaluationMetrics.evaluation_ready && <p className="mt-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800">Early indication only: review at least {evaluationMetrics.minimum_class_sample} legitimate and {evaluationMetrics.minimum_class_sample} malicious emails before treating these rates as a useful evaluation sample.</p>}
                                <p className="mt-3 text-xs text-slate-500">{evaluationMetrics?.note || "Review multiple legitimate and malicious emails before interpreting these metrics."}</p>
                            </div>
                        </div>
                    </Panel>

                    <Panel title="Privacy view" icon={CheckCircle2}>
                        {!privacy ? <p className="text-sm text-slate-500">Privacy view is not available.</p> : <>
                            <div className="mb-4 flex items-center gap-2"><Badge variant="info">{privacy.privacy_mode || "MASKED"}</Badge><span className="text-xs text-slate-500">Masked fields from the backend privacy endpoint</span></div>
                            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                                {[["Sender", privacy.sender?.address], ["Sender name", privacy.sender?.display_name], ["Sender domain", privacy.sender?.domain], ["Recipients", privacy.recipients], ["Subject", privacy.subject], ["Message ID", privacy.message_id], ["Body", privacy.body], ["Headers", privacy.headers], ["URLs", privacy.urls], ["IP addresses", privacy.ip_addresses], ["Retention", privacy.retention_policy]].map(([label, value]) => <div key={label} className="rounded-lg border border-slate-200 bg-slate-50 p-3"><p className="text-xs text-slate-500">{label}</p><p className="mt-1 break-all text-sm text-slate-700">{formatValue(value)}</p></div>)}
                            </div>
                            {privacy.attachments?.length > 0 && <div className="mt-4"><p className="mb-2 text-xs font-semibold text-slate-600">Attachments (masked)</p><div className="space-y-2">{privacy.attachments.map((item, index) => <div key={`${item.sha256}-${index}`} className="grid gap-2 rounded-lg bg-slate-50 p-3 text-xs sm:grid-cols-3"><JsonValue value={item.filename} /><JsonValue value={item.content_type} /><JsonValue value={item.sha256} /></div>)}</div></div>}
                        </>}
                    </Panel>
                </div>
            )}
        </div>
    );
}
