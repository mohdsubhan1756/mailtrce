import api from "./api";

export async function getCases(params = {}) {
    const response = await api.get("/cases", { params });
    return response.data;
}

export async function getCase(caseId) {
    if (!caseId) throw new Error("Case ID is required.");
    const response = await api.get(`/cases/${encodeURIComponent(caseId)}`);
    return response.data;
}

export async function createCase(payload) {
    const response = await api.post("/cases", payload);
    return response.data;
}

export async function updateCase(caseId, payload) {
    if (!caseId) throw new Error("Case ID is required.");
    const response = await api.patch(`/cases/${encodeURIComponent(caseId)}`, payload);
    return response.data;
}

export async function assignEmailToCase(caseId, emailId) {
    if (!caseId || !emailId) throw new Error("Case ID and email ID are required.");
    const response = await api.post(`/cases/${encodeURIComponent(caseId)}/emails/${encodeURIComponent(emailId)}`);
    return response.data;
}
