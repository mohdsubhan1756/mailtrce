import api from "./api";

export async function analyzeAuthentication(emailId) {
    if (!emailId) {
        throw new Error("Email ID is required.");
    }

    const response = await api.post(
        `/emails/${encodeURIComponent(
            emailId
        )}/analyze-authentication`
    );

    return response.data;
}

export async function getAuthenticationAnalysis(emailId) {
    if (!emailId) {
        throw new Error("Email ID is required.");
    }

    const response = await api.get(
        `/emails/${encodeURIComponent(
            emailId
        )}/authentication-analysis`
    );

    return response.data;
}

export async function getAuthenticationAnalyses(
    params = {}
) {
    const response = await api.get(
        "/authentication-analyses",
        {
            params,
        }
    );

    return response.data;
}

export async function listAuthenticationAnalyses(
    params = {}
) {
    return getAuthenticationAnalyses(params);
}