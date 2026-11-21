import api from "./api";

export async function analyzeUrls(emailId) {
    if (!emailId) {
        throw new Error("Email ID is required.");
    }

    const response = await api.post(
        `/emails/${encodeURIComponent(emailId)}/analyze-url-domain`
    );

    return response.data;
}

export async function getUrlAnalysis(emailId) {
    if (!emailId) {
        throw new Error("Email ID is required.");
    }

    const response = await api.get(
        `/emails/${encodeURIComponent(emailId)}/url-domain-analysis`
    );

    return response.data;
}

export async function getUrlAnalyses(params = {}) {
    const response = await api.get(
        "/url-domain-analyses",
        {
            params
        }
    );

    return response.data;
}

export async function getDomainIntelligence(domain) {
    if (!domain) {
        throw new Error("Domain is required.");
    }

    const response = await api.get(
        `/domains/${encodeURIComponent(domain)}/intelligence`
    );

    return response.data;
}

/*
 * Compatibility aliases
 */

export async function analyzeUrlDomain(emailId) {
    return analyzeUrls(emailId);
}

export async function getUrlDomainAnalysis(emailId) {
    return getUrlAnalysis(emailId);
}

export async function listUrlDomainAnalyses(params = {}) {
    return getUrlAnalyses(params);
}