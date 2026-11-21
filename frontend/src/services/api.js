import axios from "axios";

const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL;
const normalizedBaseUrl = configuredBaseUrl?.replace(/\/$/, "");

const api = axios.create({
    baseURL:
        normalizedBaseUrl && !normalizedBaseUrl.endsWith("/api/v1")
            ? `${normalizedBaseUrl}/api/v1`
            : normalizedBaseUrl ||
            "http://localhost:8000/api/v1",
    // Full analysis performs multiple local forensic checks.
    timeout: 180000,
});

api.interceptors.response.use(
    (response) => response,
    (error) => {
        let message = "An unexpected error occurred.";

        if (error.response) {
            const data = error.response.data;

            if (typeof data?.detail === "string") {
                message = data.detail;
            } else if (Array.isArray(data?.detail)) {
                message = data.detail
                    .map((item) => item.msg || JSON.stringify(item))
                    .join(", ");
            } else if (typeof data?.message === "string") {
                message = data.message;
            } else {
                message = `Request failed with status ${error.response.status}.`;
            }
        } else if (error.code === "ECONNABORTED" || error.code === "ETIMEDOUT") {
            message =
                "The backend took too long to respond. The analysis may still be running; wait briefly, then reload the analysis before retrying.";
        } else if (error.request) {
            const backend = error.config?.baseURL || "the configured backend URL";
            message = `Cannot reach the MailTrace backend at ${backend}. Confirm that the backend server is running.`;
        } else if (error.message) {
            message = error.message;
        }

        error.friendlyMessage = message;

        return Promise.reject(error);
    }
);

export default api;
