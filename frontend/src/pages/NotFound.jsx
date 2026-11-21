import React from "react";

import {
    Link
} from "react-router-dom";

import {
    ShieldAlert
} from "lucide-react";

export default function NotFound() {
    return (
        <div className="flex min-h-[70vh] items-center justify-center">
            <div className="text-center">
                <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-red-500/10">
                    <ShieldAlert className="h-8 w-8 text-red-400" />
                </div>

                <h1 className="mt-6 text-3xl font-bold text-slate-900">
                    404
                </h1>

                <p className="mt-2 text-sm text-slate-500">
                    The requested investigation page does not exist.
                </p>

                <Link
                    to="/"
                    className="mt-6 inline-flex rounded-lg bg-sky-500 px-4 py-2.5 text-sm font-medium text-slate-950"
                >
                    Return to dashboard
                </Link>
            </div>
        </div>
    );
}