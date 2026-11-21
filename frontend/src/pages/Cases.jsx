import React, { useEffect, useState } from "react";
import { FolderPlus, FolderOpen, Mail } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import PageHeader from "../components/common/PageHeader";
import Button from "../components/common/Button";
import Badge from "../components/common/Badge";
import Loading from "../components/common/Loading";
import EmptyState from "../components/common/EmptyState";
import { assignEmailToCase, createCase, getCase, getCases, updateCase } from "../services/caseService";
import { getEmails } from "../services/emailService";
import { extractItems, formatDate, getSenderAddress } from "../utils/formatters";

export default function Cases() {
    const [searchParams] = useSearchParams();
    const [cases, setCases] = useState([]);
    const [selectedCase, setSelectedCase] = useState(null);
    const [title, setTitle] = useState("");
    const [description, setDescription] = useState("");
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState("");
    const [emails, setEmails] = useState([]);
    const [emailToAssign, setEmailToAssign] = useState("");
    const [assigning, setAssigning] = useState(false);

    const loadCases = async () => {
        try {
            setError("");
            const result = await getCases({ limit: 100 });
            setCases(extractItems(result));
        } catch (requestError) {
            setError(requestError.friendlyMessage || "Unable to load cases.");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { void loadCases(); }, []);

    useEffect(() => {
        getEmails({ limit: 100 }).then((result) => setEmails(extractItems(result))).catch(() => setEmails([]));
    }, []);

    const openCase = async (caseId) => {
        try {
            setError("");
            setSelectedCase(await getCase(caseId));
        } catch (requestError) {
            setError(requestError.friendlyMessage || "Unable to open this case.");
        }
    };

    useEffect(() => {
        const caseId = searchParams.get("case");
        if (caseId) void openCase(caseId);
    }, [searchParams]);

    const submitCase = async (event) => {
        event.preventDefault();
        try {
            setSaving(true);
            setError("");
            const created = await createCase({ title: title.trim() || "MailTrace investigation", description: description.trim() });
            setTitle("");
            setDescription("");
            await loadCases();
            setSelectedCase({ ...created, email_count: 0, emails: [] });
        } catch (requestError) {
            setError(requestError.friendlyMessage || "Unable to create this case.");
        } finally {
            setSaving(false);
        }
    };

    const addExistingEmail = async (event) => {
        event.preventDefault();
        if (!selectedCase || !emailToAssign) return;
        try {
            setAssigning(true);
            setError("");
            await assignEmailToCase(selectedCase.case_id, emailToAssign);
            setEmailToAssign("");
            const [updatedCase] = await Promise.all([
                getCase(selectedCase.case_id),
                loadCases(),
            ]);
            setSelectedCase(updatedCase);
        } catch (requestError) {
            setError(requestError.friendlyMessage || "Unable to add email evidence to this case.");
        } finally {
            setAssigning(false);
        }
    };

    const toggleCaseStatus = async () => {
        if (!selectedCase) return;
        try {
            setError("");
            const updated = await updateCase(selectedCase.case_id, { status: String(selectedCase.status).toUpperCase() === "CLOSED" ? "OPEN" : "CLOSED" });
            setSelectedCase({ ...selectedCase, ...updated });
            await loadCases();
        } catch (requestError) {
            setError(requestError.friendlyMessage || "Unable to update case status.");
        }
    };

    return (
        <div>
            <PageHeader title="Cases" description="Group email evidence into investigations and review case activity." />
            {error && <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">{error}</div>}

            <div className="grid items-start gap-6 xl:grid-cols-[minmax(280px,0.75fr)_minmax(0,1.5fr)]">
                <div className="space-y-6">
                    <form className="card p-5" onSubmit={submitCase}>
                        <div className="mb-4 flex items-center gap-2">
                            <FolderPlus className="h-4 w-4 text-blue-600" />
                            <h2 className="text-sm font-semibold text-slate-900">Create a case</h2>
                        </div>
                        <label className="mb-3 block text-xs font-medium text-slate-600">
                            Case title
                            <input className="input mt-1.5" value={title} onChange={(event) => setTitle(event.target.value)} maxLength={120} placeholder="Example: Suspicious invoice campaign" />
                        </label>
                        <label className="mb-4 block text-xs font-medium text-slate-600">
                            Description
                            <textarea className="input mt-1.5 min-h-24 resize-y" value={description} onChange={(event) => setDescription(event.target.value)} maxLength={2000} placeholder="What is being investigated?" />
                        </label>
                        <Button type="submit" loading={saving}><FolderPlus className="h-4 w-4" />Create case</Button>
                    </form>

                    <section className="card overflow-hidden">
                        <div className="card-header"><div><h2 className="text-sm font-semibold text-slate-900">Case list</h2><p className="mt-1 text-xs text-slate-500">{cases.length} cases shown</p></div></div>
                        {loading ? <Loading text="Loading cases..." /> : cases.length === 0 ? <EmptyState title="No cases yet" description="Create a case or ingest an email to start an investigation." /> : (
                            <div className="divide-y divide-slate-100">
                                {cases.map((item) => (
                                    <button key={item.case_id} type="button" onClick={() => openCase(item.case_id)} className={`w-full p-4 text-left transition hover:bg-slate-50 ${selectedCase?.case_id === item.case_id ? "bg-blue-50" : ""}`}>
                                        <div className="flex items-start justify-between gap-3">
                                            <span className="flex min-w-0 items-center gap-2"><FolderOpen className="h-4 w-4 shrink-0 text-blue-600" /><span className="truncate text-sm font-medium text-slate-800">{item.title || item.case_id}</span></span>
                                            <Badge variant={String(item.status || "OPEN").toLowerCase() === "closed" ? "neutral" : "info"}>{item.status || "OPEN"}</Badge>
                                        </div>
                                        <div className="mt-2 flex justify-between gap-3 pl-6 text-xs text-slate-500"><span className="truncate font-mono">{item.case_id}</span><span>{item.email_count || 0} emails</span></div>
                                    </button>
                                ))}
                            </div>
                        )}
                    </section>
                </div>

                <section className="card min-h-80 overflow-hidden">
                    {!selectedCase ? <EmptyState title="Select a case" description="Choose a case to see its emails and investigation details." /> : <>
                        <div className="card-header">
                            <div className="min-w-0"><h2 className="truncate text-base font-semibold text-slate-900">{selectedCase.title || selectedCase.case_id}</h2><p className="mt-1 break-all font-mono text-xs text-slate-500">{selectedCase.case_id}</p></div>
                            <div className="flex items-center gap-2"><Badge variant={String(selectedCase.status || "OPEN").toLowerCase() === "closed" ? "neutral" : "info"}>{selectedCase.status || "OPEN"}</Badge><Button variant="secondary" onClick={toggleCaseStatus}>{String(selectedCase.status || "OPEN").toUpperCase() === "CLOSED" ? "Reopen case" : "Close case"}</Button></div>
                        </div>
                        <div className="space-y-5 p-5">
                            {selectedCase.description && <p className="whitespace-pre-wrap text-sm leading-6 text-slate-600">{selectedCase.description}</p>}
                            <div className="flex flex-wrap gap-5 text-xs text-slate-500"><span>{selectedCase.email_count || 0} emails</span>{selectedCase.created_at && <span>Created {formatDate(selectedCase.created_at)}</span>}</div>
                            <div>
                                <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-800"><Mail className="h-4 w-4" />Evidence in this case</h3>
                                <form onSubmit={addExistingEmail} className="mb-3 flex flex-col gap-2 sm:flex-row">
                                    <select className="input min-w-0 flex-1" value={emailToAssign} onChange={(event) => setEmailToAssign(event.target.value)} aria-label="Select existing email evidence">
                                        <option value="">Select an existing email to add</option>
                                        {emails.filter((email) => email.email_id && !selectedCase.emails?.some((assigned) => assigned.email_id === email.email_id)).map((email) => <option key={email.email_id} value={email.email_id}>{email.subject || "No subject"} · {email.email_id}</option>)}
                                    </select>
                                    <Button type="submit" disabled={!emailToAssign} loading={assigning}>Add evidence</Button>
                                </form>
                                <p className="mb-3 text-xs text-slate-500">Adding evidence moves it from its current case, if it has one.</p>
                                {!selectedCase.emails?.length ? <p className="rounded-lg bg-slate-50 p-4 text-sm text-slate-500">No emails are assigned to this case yet. Select an existing email above or choose this case when uploading an email.</p> : <div className="divide-y divide-slate-100 rounded-lg border border-slate-200">
                                    {selectedCase.emails.map((email) => <Link key={email.email_id} to={`/emails/${encodeURIComponent(email.email_id)}`} className="flex flex-wrap items-center justify-between gap-3 p-4 hover:bg-slate-50"><span className="min-w-0"><span className="block truncate text-sm font-medium text-slate-800">{email.subject || "No subject"}</span><span className="mt-1 block truncate text-xs text-slate-500">{getSenderAddress(email.sender) || email.email_id}</span></span><span className="text-xs text-slate-500">{formatDate(email.created_at)}</span></Link>)}
                                </div>}
                            </div>
                        </div>
                    </>}
                </section>
            </div>
        </div>
    );
}

