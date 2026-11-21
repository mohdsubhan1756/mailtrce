const STORAGE_PREFIX = "mailtrace.analysis.";

function getStorageKey(type) {
    return `${STORAGE_PREFIX}${type}`;
}

export function loadAnalysisState(type) {
    try {
        const stored = sessionStorage.getItem(getStorageKey(type));
        return stored ? JSON.parse(stored) : null;
    } catch {
        return null;
    }
}

export function saveAnalysisState(type, state) {
    try {
        sessionStorage.setItem(
            getStorageKey(type),
            JSON.stringify(state)
        );
    } catch {
        // Storage can be unavailable in restricted browser contexts.
    }
}