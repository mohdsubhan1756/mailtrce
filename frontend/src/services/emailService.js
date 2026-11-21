import api from "./api";

export async function uploadEmail(file, onUploadProgress, caseId) {
    if (!file) {
        throw new Error("Please select an email file.");
    }

    const formData = new FormData();

    formData.append("file", file);

    const response = await api.post(
        "/emails/ingest",
        formData,
        {
            headers: {
                "Content-Type": "multipart/form-data",
            },
            onUploadProgress,
            params: caseId ? { case_id: caseId } : undefined,
        }
    );

    return response.data;
}

export async function ingestEmail(file, onUploadProgress, caseId) {
    return uploadEmail(file, onUploadProgress, caseId);
}

export async function getEmails(params = {}) {
    const response = await api.get("/emails/", {
        params,
    });

    return response.data;
}

export async function listEmails(params = {}) {
    return getEmails(params);
}

export async function getEmail(emailId) {
    if (!emailId) {
        throw new Error("Email ID is required.");
    }

    const response = await api.get(
        `/emails/${encodeURIComponent(emailId)}`
    );

    return response.data;
}

export async function getRawEmail(emailId) {
    if (!emailId) {
        throw new Error("Email ID is required.");
    }

    const response = await api.get(
        `/emails/${encodeURIComponent(emailId)}/raw`,
        {
            responseType: "blob",
        }
    );

    return response.data;
}
