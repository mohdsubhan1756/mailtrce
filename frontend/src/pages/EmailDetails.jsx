import React, {
    useCallback,
    useEffect,
    useState
} from "react";

import {
    ArrowLeft,
    Download,
    ShieldAlert,
    ShieldCheck,
    Globe,
    Activity
} from "lucide-react";

import {
    Link,
    useNavigate,
    useParams
} from "react-router-dom";

import PageHeader from "../components/common/PageHeader";
import Button from "../components/common/Button";
import Loading from "../components/common/Loading";
import Badge from "../components/common/Badge";

import EmailSummary from "../components/emails/EmailSummary";

import { formatValue } from "../utils/formatters";

import {
    getEmail,
    getRawEmail
} from "../services/emailService";

export default function EmailDetails() {
    const { emailId } = useParams();

    const navigate = useNavigate();

    const [loaded, setLoaded] = useState(null);
    const [downloadError, setDownloadError] = useState("");
    const loading = loaded?.emailId !== emailId;
    const email = !loading && !loaded?.error ? loaded?.data : null;
    const errorMessage = !loading ? loaded?.error || "" : "";

    const loadEmail = useCallback(async () => {
        try {
            const data =
                await getEmail(emailId);
            setLoaded({ emailId, data, error: "" });
        } catch (error) {
            setLoaded({ emailId, data: null, error: error.friendlyMessage || "Unable to load this email." });
        }
    }, [emailId]);

    useEffect(() => {
        void loadEmail();
    }, [loadEmail]);

    const downloadRaw = async () => {
        try {
            setDownloadError("");
            const blob =
                await getRawEmail(emailId);

            const url =
                window.URL.createObjectURL(blob);

            const link =
                document.createElement("a");

            link.href = url;

            link.download =
                `${emailId}.eml`;

            document.body.appendChild(link);

            link.click();

            link.remove();

            window.URL.revokeObjectURL(url);
        } catch (error) {
            setDownloadError(error.friendlyMessage || "Unable to download the original email.");
        }
    };

    if (loading) {
        return <Loading text="Loading email evidence..." />;
    }

    if (!email) {
        return (
            <div className="card p-10 text-center">
                <p className="text-sm text-slate-500">
                    {errorMessage || "Email evidence was not found."}
                </p>

                <Button
                    className="mt-5"
                    onClick={() => navigate("/emails")}
                >
                    Back to emails
                </Button>
            </div>
        );
    }

    return (
        <div>
            <PageHeader
                title="Email Investigation"
                description={`Evidence ID: ${emailId}`}
            >
                <Button
                    variant="secondary"
                    onClick={() =>
                        navigate("/emails")
                    }
                >
                    <ArrowLeft className="h-4 w-4" />
                    Back
                </Button>

                <Button onClick={downloadRaw}>
                    <Download className="h-4 w-4" />
                    Raw .eml
                </Button>
            </PageHeader>

            {downloadError && <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">{downloadError}</div>}

            <EmailSummary email={email} />

            <div className="mt-6 grid gap-4 md:grid-cols-3">
                <Link
                    to={`/headers?email=${emailId}`}
                    className="card p-5 transition hover:border-sky-500/40"
                >
                    <ShieldAlert className="h-5 w-5 text-orange-400" />

                    <h3 className="mt-3 text-sm font-semibold text-slate-900">
                        Header Forensics
                    </h3>

                    <p className="mt-1 text-xs text-slate-500">
                        Analyze routing and forged header indicators.
                    </p>
                </Link>

                <Link
                    to={`/authentication?email=${emailId}`}
                    className="card p-5 transition hover:border-sky-500/40"
                >
                    <ShieldCheck className="h-5 w-5 text-green-400" />

                    <h3 className="mt-3 text-sm font-semibold text-slate-900">
                        Authentication
                    </h3>

                    <p className="mt-1 text-xs text-slate-500">
                        Analyze SPF, DKIM, DMARC and authentication results.
                    </p>
                </Link>

                <Link
                    to={`/urls?email=${emailId}`}
                    className="card p-5 transition hover:border-sky-500/40"
                >
                    <Globe className="h-5 w-5 text-cyan-400" />

                    <h3 className="mt-3 text-sm font-semibold text-slate-900">
                        URL Intelligence
                    </h3>

                    <p className="mt-1 text-xs text-slate-500">
                        Investigate URLs, domains and lookalike indicators.
                    </p>
                </Link>

                <Link
                    to={`/extended?email=${emailId}`}
                    className="card p-5 transition hover:border-sky-500/40"
                >
                    <Activity className="h-5 w-5 text-violet-400" />

                    <h3 className="mt-3 text-sm font-semibold text-slate-900">
                        Extended Analysis
                    </h3>

                    <p className="mt-1 text-xs text-slate-500">
                        Run threat, attachment, IP, risk, and evidence analysis.
                    </p>
                </Link>
            </div>

            <div className="mt-6 card">
                <div className="card-header">
                    <h2 className="text-sm font-semibold text-slate-900">
                        Email Body
                    </h2>

                    <Badge variant="info">
                        Normalized Content
                    </Badge>
                </div>

                <div className="p-5">
                    <pre className="max-h-[500px] overflow-auto whitespace-pre-wrap rounded-lg border border-slate-200 bg-slate-50 p-5 font-mono text-xs leading-6 text-slate-500">
                        {formatValue(
                            email.body?.plain ||
                            email.body?.text ||
                            email.body_text ||
                            email.plain_text ||
                            email.body ||
                            "No plain-text body available."
                        )}
                    </pre>
                </div>
            </div>
        </div>
    );
}
