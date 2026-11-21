export function formatDate(value) {
    if (!value) return "—";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleString();
}

export function formatShortDate(value) {
    if (!value) return "—";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleDateString();
}

export function truncate(value, length = 50) {
    const formatted = formatValue(value);

    if (!formatted) return "—";

    if (formatted.length <= length) {
        return formatted;
    }

    return `${formatted.slice(0, length)}...`;
}

export function formatBytes(bytes) {
    if (bytes === undefined || bytes === null) {
        return "—";
    }

    if (bytes === 0) {
        return "0 B";
    }

    const units = ["B", "KB", "MB", "GB"];

    const index = Math.floor(
        Math.log(bytes) / Math.log(1024)
    );

    return `${(
        bytes / Math.pow(1024, index)
    ).toFixed(index === 0 ? 0 : 2)} ${units[index] || "GB"
        }`;
}

/**
 * Safely convert API values into something
 * React can render.
 */
export function formatValue(value) {
    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {
        return "—";
    }

    if (
        typeof value === "string" ||
        typeof value === "number" ||
        typeof value === "boolean"
    ) {
        return String(value);
    }

    if (Array.isArray(value)) {
        return value
            .map((item) => formatValue(item))
            .join(", ");
    }

    if (typeof value === "object") {
        /*
         * Email address object:
         * {
         *   display_name,
         *   address,
         *   domain
         * }
         */
        if (value.display_name && value.address) {
            return `${value.display_name} <${value.address}>`;
        }

        if (value.address) {
            return String(value.address);
        }

        if (value.domain) {
            return String(value.domain);
        }

        if (value.name) {
            return String(value.name);
        }

        if (value.value) {
            return formatValue(value.value);
        }

        /*
         * Generic fallback for objects.
         */
        try {
            return JSON.stringify(value);
        } catch {
            return "—";
        }
    }

    return String(value);
}

export function getSenderAddress(sender) {
    if (!sender) return "";

    if (typeof sender === "string") {
        return sender;
    }

    if (sender.display_name && sender.address) {
        return `${sender.display_name} <${sender.address}>`;
    }

    return sender.address || "";
}

export function getSenderDomain(sender) {
    if (!sender || typeof sender === "string") return "";

    return sender.domain || "";
}

export function getEmailRiskScore(email) {
    const value = email?.module?.risk_analysis?.risk_score
        ?? email?.module?.url_domain_intelligence?.risk_score;
    return value === undefined || value === null ? null : Number(value);
}

export function safeArray(value) {
    return Array.isArray(value) ? value : [];
}

export function safeObject(value) {
    return value &&
        typeof value === "object" &&
        !Array.isArray(value)
        ? value
        : {};
}

/**
 * Handles common FastAPI list response formats.
 */
export function extractItems(value) {
    if (Array.isArray(value)) {
        return value;
    }

    if (Array.isArray(value?.items)) {
        return value.items;
    }

    if (Array.isArray(value?.data)) {
        return value.data;
    }

    if (Array.isArray(value?.results)) {
        return value.results;
    }

    return [];
}
