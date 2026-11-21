import React, {
    useCallback,
    useEffect,
    useState
} from "react";

import {
    Search
} from "lucide-react";

import {
    useSearchParams
} from "react-router-dom";

import PageHeader from "../components/common/PageHeader";
import Button from "../components/common/Button";
import Loading from "../components/common/Loading";
import HeaderAnalysis from "../components/headers/HeaderAnalysis";

import {
    getEmails
} from "../services/emailService";

import {
    getHeaderAnalysis,
    analyzeHeaders
} from "../services/headerService";

import {
    loadAnalysisState,
    saveAnalysisState
} from "../utils/analysisStorage";

export default function HeaderForensics() {
    const [params] =
        useSearchParams();

    const storedState =
        loadAnalysisState("headers");

    const queryEmail = params.get("email") || "";

    const initialEmail =
        queryEmail ||
        storedState?.emailId ||
        "";

    const initialAnalysis =
        storedState?.emailId === initialEmail
            ? storedState.analysis
            : null;

    const [emailId, setEmailId] =
        useState(initialEmail);

    const [emails, setEmails] =
        useState([]);

    const [analysis, setAnalysis] =
        useState(initialAnalysis || null);

    const [loading, setLoading] =
        useState(false);

    const [analyzing, setAnalyzing] =
        useState(false);
    const [error, setError] = useState("");

    const loadEmails = useCallback(async () => {
        try {
            const data =
                await getEmails({
                    limit: 100
                });

            setEmails(
                Array.isArray(data)
                    ? data
                    : data?.items ||
                    data?.emails ||
                    []
            );
        } catch (error) {
            console.error(error);
        }
    }, []);

    const loadAnalysis = useCallback(async (id) => {
        if (!id) {
            setAnalysis(null);
            return;
        }

        try {
            setLoading(true);

            const data =
                await getHeaderAnalysis(id);

            setAnalysis(data);
            saveAnalysisState("headers", {
                emailId: id,
                analysis: data
            });
        } catch {
            setAnalysis(null);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        void loadEmails();
        if (initialEmail) void loadAnalysis(initialEmail);
    }, [initialEmail, loadEmails, loadAnalysis]);

    useEffect(() => {
        if (queryEmail && queryEmail !== emailId) setEmailId(queryEmail);
    }, [queryEmail, emailId]);

    const selectEmail = async (id) => {
        setEmailId(id);
        saveAnalysisState("headers", {
            emailId: id,
            analysis: null
        });
        await loadAnalysis(id);
    };

    const runAnalysis = async () => {
        if (!emailId) {
            return;
        }

        try {
            setAnalyzing(true);
            setError("");

            const data =
                await analyzeHeaders(emailId);

            setAnalysis(data);
            saveAnalysisState("headers", {
                emailId,
                analysis: data
            });
        } catch (requestError) {
            setError(requestError.friendlyMessage || "Header analysis failed.");
        } finally {
            setAnalyzing(false);
        }
    };

    return (
        <div>
            <PageHeader
                title="Email Header Forensics"
                description="Reconstruct routing paths and detect forged or anomalous header fields"
            />

            {error && <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">{error}</div>}

            <div className="card mb-6">
                <div className="card-body">
                    <div className="grid gap-3 md:grid-cols-[1fr_auto]">
                        <div className="relative">
                            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />

                            <select
                                value={emailId}
                                onChange={(event) =>
                                    selectEmail(
                                        event.target.value
                                    )
                                }
                                className="input appearance-none pl-9"
                            >
                                <option value="">
                                    Select an email evidence record
                                </option>

                                {emails.map((email) => (
                                    <option
                                        key={email.email_id}
                                        value={email.email_id}
                                    >
                                        {email.subject ||
                                            email.email_id}
                                    </option>
                                ))}
                            </select>
                        </div>

                        <Button
                            onClick={runAnalysis}
                            disabled={!emailId}
                            loading={analyzing}
                        >
                            Analyze Headers
                        </Button>
                    </div>
                </div>
            </div>

            {loading ? (
                <Loading text="Loading header analysis..." />
            ) : (
                <HeaderAnalysis
                    analysis={analysis}
                    onAnalyze={runAnalysis}
                    analyzing={analyzing}
                />
            )}
        </div>
    );
}
