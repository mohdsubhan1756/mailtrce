import React from "react";
import { Inbox } from "lucide-react";

export default function EmptyState({
    title = "No data found",
    description = "There is no information to display."
}) {
    return (
        <div className="flex min-h-[260px] flex-col items-center justify-center text-center">
            <div className="mb-4 rounded-full bg-slate-100 p-4">
                <Inbox className="h-7 w-7 text-slate-500" />
            </div>

            <h3 className="text-sm font-semibold text-slate-800">
                {title}
            </h3>

            <p className="mt-2 max-w-md text-sm text-slate-500">
                {description}
            </p>
        </div>
    );
}