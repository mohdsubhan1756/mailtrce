import api from "./api";

export async function getAlerts(params = {}) {
    const response = await api.get("/alerts", { params });
    return response.data;
}

export async function updateAlertStatus(emailId, source, status) {
    if (!emailId || !source) throw new Error("Email ID and alert source are required.");
    const response = await api.patch(`/alerts/${encodeURIComponent(emailId)}/${encodeURIComponent(source)}/status`, { status });
    return response.data;
}
