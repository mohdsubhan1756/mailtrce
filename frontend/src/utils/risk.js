export const normalizeRisk = (value) => {
    const score = Number(value || 0);

    return Math.max(0, Math.min(100, score));
};

export const getRiskLevel = (value) => {
    const score = normalizeRisk(value);

    if (score >= 90) {
        return "critical";
    }

    if (score >= 70) {
        return "high";
    }

    if (score >= 40) {
        return "medium";
    }

    if (score > 0) {
        return "low";
    }

    return "safe";
};

export const getRiskLabel = (value) => {
    const level = getRiskLevel(value);

    return {
        critical: "Critical",
        high: "High",
        medium: "Medium",
        low: "Low",
        safe: "Safe"
    }[level];
};