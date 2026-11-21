import api from "./api";

export async function analyzeHeaders(emailId) {
    if (!emailId) {
        throw new Error("Email ID is required.");
    }

    const response = await api.post(
        `/emails/${encodeURIComponent(emailId)}/analyze-headers`
    );

    return response.data;
}

export async function getHeaderAnalysis(emailId) {
    if (!emailId) {
        throw new Error("Email ID is required.");
    }

    const response = await api.get(
        `/emails/${encodeURIComponent(emailId)}/header-analysis`
    );

    return response.data;
}

export async function getHeaderAnalyses(params = {}) {
    const response = await api.get(
        "/header-analyses",
        {
            params,
        }
    );

    return response.data;
}

export async function listHeaderAnalyses(params = {}) {
    return getHeaderAnalyses(params);
}