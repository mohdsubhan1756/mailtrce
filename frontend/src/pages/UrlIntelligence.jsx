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

import {
    getEmails
} from "../services/emailService";

import {
    getUrlAnalysis,
    analyzeUrls
} from "../services/urlService";

import {
    loadAnalysisState,
    saveAnalysisState
} from "../utils/analysisStorage";

import UrlAnalysis from "../components/urls/UrlAnalysis";

export default function UrlIntelligence() {
    const [params] =
        useSearchParams();

    const storedState =
        loadAnalysisState("urls");

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
    const [errorMessage, setErrorMessage] = useState("");

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
                await getUrlAnalysis(id);

            setAnalysis(data);
            saveAnalysisState("urls", {
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
        saveAnalysisState("urls", {
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
            setErrorMessage("");

            const data =
                await analyzeUrls(emailId);

            setAnalysis(data);
            saveAnalysisState("urls", {
                emailId,
                analysis: data
            });
        } catch (error) {
            setErrorMessage(error.friendlyMessage || "URL analysis failed.");
        } finally {
            setAnalyzing(false);
        }
    };

    return (
        <div>
            <PageHeader
                title="URL & Domain Intelligence"
                description="Analyze URLs, domains, lookalikes and suspicious web infrastructure"
            />

            {errorMessage && <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">{errorMessage}</div>}

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
                            Analyze URLs
                        </Button>
                    </div>
                </div>
            </div>

            {loading ? (
                <Loading text="Loading URL intelligence..." />
            ) : (
                <UrlAnalysis
                    analysis={analysis}
                    onAnalyze={runAnalysis}
                    analyzing={analyzing}
                />
            )}
        </div>
    );
}
