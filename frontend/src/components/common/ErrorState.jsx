import React from "react";
import { AlertTriangle } from "lucide-react";

export default function ErrorState({
    message = "Unable to load data.",
    onRetry
}) {
    return (
        <div className="flex min-h-[260px] flex-col items-center justify-center text-center">
            <div className="mb-4 rounded-full bg-red-500/10 p-4">
                <AlertTriangle className="h-7 w-7 text-red-400" />
            </div>

            <h3 className="text-sm font-semibold text-slate-800">
                Something went wrong
            </h3>

            <p className="mt-2 max-w-md text-sm text-slate-500">
                {message}
            </p>

            {onRetry && (
                <button
                    onClick={onRetry}
                    className="mt-5 rounded-lg border border-slate-200 px-4 py-2 text-sm text-slate-700 hover:bg-slate-100"
                >
                    Try again
                </button>
            )}
        </div>
    );
}