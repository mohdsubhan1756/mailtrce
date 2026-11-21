export const MODULES = [
    {
        id: 1,
        name: "Email Ingestion",
        path: "/emails"
    },
    {
        id: 2,
        name: "Header Forensics",
        path: "/headers"
    },
    {
        id: 3,
        name: "Authentication",
        path: "/authentication"
    },
    {
        id: 4,
        name: "URL Intelligence",
        path: "/urls"
    },
    {
        id: 5,
        name: "Extended Analysis",
        path: "/extended"
    }
];

export const RISK_LEVELS = {
    critical: {
        label: "Critical"
    },

    high: {
        label: "High"
    },

    medium: {
        label: "Medium"
    },

    low: {
        label: "Low"
    },

    safe: {
        label: "Safe"
    }
};