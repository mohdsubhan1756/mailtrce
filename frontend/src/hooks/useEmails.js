import { useCallback, useEffect, useState } from "react";
import { getEmails, getEmail } from "../services/emailService";
import { extractItems } from "../utils/formatters";

export function useEmails(params = { limit: 100 }) {
    const [result, setResult] = useState(null);
    const paramsKey = JSON.stringify(params);

    const load = useCallback(async () => {
        try {
            const data = await getEmails(JSON.parse(paramsKey));
            setResult({ key: paramsKey, emails: extractItems(data), error: null });
        } catch (error) {
            setResult({
                key: paramsKey,
                emails: [],
                error: error.friendlyMessage || "Unable to load emails.",
            });
        }
    }, [paramsKey]);

    useEffect(() => {
        void load();
    }, [load]);

    const current = result?.key === paramsKey;
    return {
        emails: current ? result.emails : [],
        loading: !current,
        error: current ? result.error : null,
        refresh: load,
    };
}

export function useEmail(emailId) {
    const [result, setResult] = useState(null);

    const load = useCallback(async () => {
        if (!emailId) {
            return;
        }
        try {
            const email = await getEmail(emailId);
            setResult({ emailId, email, error: null });
        } catch (error) {
            setResult({
                emailId,
                email: null,
                error: error.friendlyMessage || "Unable to load email.",
            });
        }
    }, [emailId]);

    useEffect(() => {
        void load();
    }, [load]);

    const current = Boolean(emailId) && result?.emailId === emailId;
    return {
        email: current ? result.email : null,
        loading: Boolean(emailId) && !current,
        error: current ? result.error : null,
        refresh: load,
    };
}
