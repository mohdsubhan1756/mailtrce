import React, { useState } from "react";
import {
    LayoutDashboard,
    Mail,
    ShieldAlert,
    ShieldCheck,
    Globe,
    Activity,
    BellRing,
    FolderKanban,
    History,
    Menu,
    X,
    ChevronRight
} from "lucide-react";

import {
    NavLink,
    Outlet,
    useLocation
} from "react-router-dom";

const navigation = [
    {
        name: "Dashboard",
        path: "/",
        icon: LayoutDashboard
    },
    {
        name: "Inbox",
        path: "/emails",
        icon: Mail
    },
    {
        name: "Header Forensics",
        path: "/headers",
        icon: ShieldAlert
    },
    {
        name: "Authentication",
        path: "/authentication",
        icon: ShieldCheck
    },
    {
        name: "URL Intelligence",
        path: "/urls",
        icon: Globe
    },
    {
        name: "Extended Analysis",
        path: "/extended",
        icon: Activity
    },
    {
        name: "Alerts",
        path: "/alerts",
        icon: BellRing
    },
    {
        name: "Cases",
        path: "/cases",
        icon: FolderKanban
    },
    {
        name: "Analysis history",
        path: "/history",
        icon: History
    }
];

function Sidebar({ open, onClose }) {
    return (
        <>
            {open && (
                <div
                    className="fixed inset-0 z-40 bg-slate-900/35 lg:hidden"
                    onClick={onClose}
                />
            )}

            <aside
                className={`
                    fixed inset-y-0 left-0 z-50 flex w-72 flex-col border-r border-slate-200/70
                    bg-slate-950 text-slate-100 transition-transform duration-200
                    lg:static lg:translate-x-0
                    ${open ? "translate-x-0" : "-translate-x-full"}
                `}
            >
                <div className="flex h-18 items-center justify-between border-b border-slate-800 px-5 py-4">
                    <NavLink
                        to="/"
                        className="flex items-center gap-3"
                        onClick={onClose}
                    >
                        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-teal-500/15 text-teal-300">
                            <ShieldCheck className="h-5 w-5" />
                        </div>

                        <div>
                            <div className="text-base font-semibold tracking-tight text-white">
                                MailTrace
                            </div>
                            <div className="text-[10px] uppercase tracking-[0.25em] text-teal-300/90">
                                AI FORENSICS
                            </div>
                        </div>
                    </NavLink>

                    <button
                        className="text-slate-400 lg:hidden"
                        onClick={onClose}
                    >
                        <X className="h-5 w-5" />
                    </button>
                </div>

                <div className="flex-1 overflow-y-auto px-3 py-5">
                    <p className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                        Workspace
                    </p>
                    <div className="space-y-1">
                        {navigation.map((item) => {
                            const Icon = item.icon;

                            return (
                                <NavLink
                                    key={item.path}
                                    to={item.path}
                                    end={item.path === "/"}
                                    onClick={onClose}
                                    className={({ isActive }) =>
                                        `group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition ${isActive
                                            ? "bg-teal-500/15 text-white shadow-sm"
                                            : "text-slate-300 hover:bg-white/5 hover:text-white"
                                        }`
                                    }
                                >
                                    <Icon className="h-4 w-4" />
                                    <span className="flex-1">{item.name}</span>
                                    <ChevronRight className="h-3.5 w-3.5 opacity-0 transition group-hover:opacity-100" />
                                </NavLink>
                            );
                        })}
                    </div>

                    <div className="mt-8 rounded-xl border border-slate-800 bg-slate-900/70 p-3">
                        <div className="flex items-center gap-2 text-xs font-medium text-slate-200">
                            <ShieldCheck className="h-4 w-4 text-teal-300" />
                            Evidence first
                        </div>
                        <p className="mt-1.5 text-xs leading-5 text-slate-400">
                            Preserve the original message, then review its analysis.
                        </p>
                    </div>
                </div>
            </aside>
        </>
    );
}

function Topbar({ onMenu }) {
    const location = useLocation();

    const routeNames = {
        "/": "Overview",
        "/emails": "Email evidence",
        "/headers": "Header forensics",
        "/authentication": "Authentication",
        "/urls": "URL intelligence",
        "/extended": "Extended analysis",
        "/alerts": "Alerts",
        "/cases": "Cases",
        "/history": "Analysis history",
    };
    const pathName = location.pathname.startsWith("/emails/")
        ? "Email investigation"
        : routeNames[location.pathname] || "Workspace";

    return (
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-slate-200 bg-white/90 px-4 backdrop-blur-sm md:px-6">
            <div className="flex items-center gap-3">
                <button
                    onClick={onMenu}
                    className="rounded-lg p-2 text-slate-600 hover:bg-slate-100 lg:hidden"
                    aria-label="Open navigation"
                >
                    <Menu className="h-5 w-5" />
                </button>

                <div className="text-sm text-slate-500">
                    <span className="font-medium text-slate-700">MailTrace</span>
                    <span className="mx-2 text-slate-300">/</span>
                    <span className="text-slate-600">{pathName}</span>
                </div>
            </div>

            <div className="hidden items-center gap-2 text-xs text-slate-500 sm:flex">
                <span className="h-2 w-2 rounded-full bg-blue-500" />
                Email forensics workspace
            </div>
        </header>
    );
}

export default function AppLayout() {
    const [sidebarOpen, setSidebarOpen] = useState(false);

    return (
        <div className="app-shell">
            <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

            <div className="flex min-w-0 flex-1 flex-col">
                <Topbar onMenu={() => setSidebarOpen(true)} />

                <main className="page-content">
                    <Outlet />
                </main>
            </div>
        </div>
    );
}
