import {
    useCallback,
    useState
} from "react";

export default function useAnalysis({
    fetchAnalysis,
    runAnalysis
}) {
    const [analysis, setAnalysis] =
        useState(null);

    const [loading, setLoading] =
        useState(false);

    const [analyzing, setAnalyzing] =
        useState(false);

    const [error, setError] =
        useState(null);

    const load = useCallback(
        async (emailId) => {
            if (!emailId) {
                setAnalysis(null);
                return;
            }

            try {
                setLoading(true);
                setError(null);

                const data =
                    await fetchAnalysis(emailId);

                setAnalysis(data);
            } catch (err) {
                setAnalysis(null);

                setError(
                    err.friendlyMessage ||
                    "Analysis not found."
                );
            } finally {
                setLoading(false);
            }
        },
        [fetchAnalysis]
    );

    const analyze = useCallback(
        async (emailId) => {
            try {
                setAnalyzing(true);
                setError(null);

                const data =
                    await runAnalysis(emailId);

                setAnalysis(data);

                return data;
            } catch (err) {
                setError(
                    err.friendlyMessage ||
                    "Analysis failed."
                );

                throw err;
            } finally {
                setAnalyzing(false);
            }
        },
        [runAnalysis]
    );

    return {
        analysis,
        loading,
        analyzing,
        error,
        load,
        analyze
    };
}
