import api from "./api";

function requireEmailId(emailId) {
    if (!emailId) {
        throw new Error("Email ID is required.");
    }
}

export async function analyzeExtended(emailId) {
    requireEmailId(emailId);
    const response = await api.post(
        `/emails/${encodeURIComponent(emailId)}/analyze-extended`
    );
    return response.data;
}

export async function getExtendedAnalysis(emailId) {
    requireEmailId(emailId);
    const [threat, attachments, ips, intelligence, risk, campaign, report, privacy] = await Promise.all([
        api.get(`/emails/${encodeURIComponent(emailId)}/threat-analysis`),
        api.get(`/emails/${encodeURIComponent(emailId)}/attachment-analysis`),
        api.get(`/emails/${encodeURIComponent(emailId)}/ip-intelligence`),
        api.get(`/emails/${encodeURIComponent(emailId)}/threat-intelligence`),
        api.get(`/emails/${encodeURIComponent(emailId)}/risk`),
        api.get(`/emails/${encodeURIComponent(emailId)}/campaign`),
        api.get(`/emails/${encodeURIComponent(emailId)}/report`),
        api.get(`/emails/${encodeURIComponent(emailId)}/privacy`)
    ]);

    return {
        threat: threat.data,
        attachments: attachments.data,
        ips: ips.data,
        intelligence: intelligence.data,
        risk: risk.data,
        campaign: campaign.data,
        report: report.data,
        privacy: privacy.data
    };
}

export async function verifyEvidence(emailId) {
    requireEmailId(emailId);
    const response = await api.post(
        `/emails/${encodeURIComponent(emailId)}/verify-evidence`
    );
    return response.data;
}

export async function downloadPdfReport(emailId) {
    requireEmailId(emailId);
    const response = await api.get(`/emails/${encodeURIComponent(emailId)}/report/pdf`, {
        responseType: "blob",
    });

    const blob = new Blob([response.data], { type: "application/pdf" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `mailtrace-report-${emailId}.pdf`;
    link.click();
    URL.revokeObjectURL(url);
    return blob;
}

export async function getAudit(emailId) {
    requireEmailId(emailId);
    const response = await api.get(
        `/emails/${encodeURIComponent(emailId)}/audit`
    );
    return response.data;
}

export async function saveAnalystFeedback(emailId, payload) {
    requireEmailId(emailId);
    const response = await api.put(`/emails/${encodeURIComponent(emailId)}/feedback`, payload);
    return response.data;
}

export async function getAnalystFeedback(emailId) {
    requireEmailId(emailId);
    const response = await api.get(`/emails/${encodeURIComponent(emailId)}/feedback`);
    return response.data;
}

export async function getEvaluationMetrics() {
    const response = await api.get("/evaluation/metrics");
    return response.data;
}

export async function verifyAuditChain(emailId) {
    requireEmailId(emailId);
    const response = await api.get(`/emails/${encodeURIComponent(emailId)}/audit/verify`);
    return response.data;
}
