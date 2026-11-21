import React, { useEffect, useState } from "react";

import {
    RefreshCw,
    Search
} from "lucide-react";

import PageHeader from "../components/common/PageHeader";
import Button from "../components/common/Button";
import Loading from "../components/common/Loading";
import ErrorState from "../components/common/ErrorState";
import EmailUpload from "../components/emails/EmailUpload";
import EmailList from "../components/emails/EmailList";

import {
    getEmails
} from "../services/emailService";

import {
    getSenderAddress,
    getSenderDomain,
    extractItems
} from "../utils/formatters";

export default function Emails() {
    const [emails, setEmails] = useState([]);
    const [loading, setLoading] = useState(true);
    const [search, setSearch] = useState("");
    const [error, setError] = useState("");

    const loadEmails = async () => {
        try {
            setError("");

            const data = await getEmails({
                limit: 100
            });

            setEmails(extractItems(data));
        } catch (error) {
            setError(error.friendlyMessage || "Unable to load email evidence.");
        } finally {
            setLoading(false);
        }
    };

    const refreshEmails = async () => {
        setLoading(true);
        await loadEmails();
    };

    useEffect(() => {
        loadEmails();
    }, []);

    const filteredEmails = emails.filter(
        (email) => {
            const query =
                search.toLowerCase();

            return (
                !query ||
                String(
                    email.subject || ""
                )
                    .toLowerCase()
                    .includes(query) ||
                String(
                    getSenderAddress(email.sender) ||
                    ""
                )
                    .toLowerCase()
                    .includes(query) ||
                String(
                    getSenderDomain(email.sender) ||
                    ""
                )
                    .toLowerCase()
                    .includes(query)
            );
        }
    );

    return (
        <div>
            <PageHeader
                title="Email Evidence"
                description="Ingested email messages and normalized forensic records"
            >
                <Button
                    variant="secondary"
                    onClick={refreshEmails}
                    disabled={loading}
                >
                    <RefreshCw className="h-4 w-4" />
                    Refresh
                </Button>
            </PageHeader>

            <EmailUpload
                onSuccess={refreshEmails}
            />

            <div className="mt-6">
                <div className="card mb-4">
                  <div className="card-header">
                    <div>
                        <h2 className="text-sm font-semibold text-slate-900">
                            Ingested Messages
                        </h2>

                        <p className="mt-1 text-xs text-slate-500">
                            {filteredEmails.length} message
                            {filteredEmails.length !== 1
                                ? "s"
                                : ""}
                            {emails.length === 100 ? " · latest 100 records" : ""}
                        </p>
                    </div>

                    <div className="relative w-full sm:w-72">
                        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />

                        <input
                            value={search}
                            onChange={(event) =>
                                setSearch(event.target.value)
                            }
                            placeholder="Search subject, sender, domain..."
                            className="input pl-9"
                        />
                    </div>
                  </div>
                </div>

                {error ? (
                    <div className="card">
                        <ErrorState message={error} onRetry={refreshEmails} />
                    </div>
                ) : loading ? (
                    <div className="card"><Loading text="Loading emails..." /></div>
                ) : (
                        <EmailList
                            emails={filteredEmails}
                        />
                )}
            </div>
        </div>
    );
}
