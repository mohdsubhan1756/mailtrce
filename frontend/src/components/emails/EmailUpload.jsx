import React, { useEffect, useRef, useState } from "react";

import {
    Upload,
    FileText,
    X,
    CheckCircle2
} from "lucide-react";

import Button from "../common/Button";
import { ingestEmail } from "../../services/emailService";
import { getCases } from "../../services/caseService";
import { extractItems } from "../../utils/formatters";

export default function EmailUpload({
    onSuccess
}) {
    const inputRef = useRef(null);

    const [file, setFile] = useState(null);
    const [dragging, setDragging] = useState(false);
    const [uploading, setUploading] = useState(false);
    const [progress, setProgress] = useState(0);
    const [error, setError] = useState("");
    const [cases, setCases] = useState([]);
    const [caseId, setCaseId] = useState("");

    useEffect(() => {
        getCases({ limit: 100 })
            .then((data) => setCases(extractItems(data)))
            .catch(() => setCases([]));
    }, []);

    const chooseFile = (selectedFile) => {
        setError("");

        if (!selectedFile) {
            return;
        }

        if (
            !selectedFile.name
                .toLowerCase()
                .endsWith(".eml")
        ) {
            setError(
                "Please select a valid .eml email file."
            );

            return;
        }

        if (selectedFile.size === 0) {
            setError("The selected .eml file is empty.");
            return;
        }

        setFile(selectedFile);
    };

    const handleDrop = (event) => {
        event.preventDefault();

        setDragging(false);

        chooseFile(event.dataTransfer.files?.[0]);
    };

    const upload = async () => {
        if (!file) {
            return;
        }

        try {
            setUploading(true);
            setError("");
            setProgress(0);

            const result = await ingestEmail(
                file,
                (event) => {
                    if (event.total) {
                        setProgress(
                            Math.round(
                                (event.loaded / event.total) * 100
                            )
                        );
                    }
                },
                caseId || undefined
            );

            setFile(null);
            setProgress(100);

            if (inputRef.current) {
                inputRef.current.value = "";
            }

            onSuccess?.(result);
        } catch (error) {
            setError(
                error.friendlyMessage ||
                "Email ingestion failed."
            );
        } finally {
            setUploading(false);
        }
    };

    return (
        <div className="card">
            <div className="card-header">
                <div>
                    <h2 className="text-sm font-semibold text-slate-900">
                        Ingest Email Evidence
                    </h2>

                    <p className="mt-1 text-xs text-slate-500">
                        Upload an RFC-compliant .eml file for forensic analysis
                    </p>
                </div>
            </div>

            <div className="p-5">
                <label className="mb-4 block max-w-xl text-sm font-medium text-slate-700">
                    Add to case <span className="font-normal text-slate-500">(optional)</span>
                    <select className="input mt-2" value={caseId} onChange={(event) => setCaseId(event.target.value)}>
                        <option value="">Create a new case for this email</option>
                        {cases.map((item) => (
                            <option key={item.case_id} value={item.case_id}>
                                {item.title || item.case_id} · {item.case_id}
                            </option>
                        ))}
                    </select>
                </label>
                <div
                    onDragOver={(event) => {
                        event.preventDefault();
                        setDragging(true);
                    }}
                    onDragLeave={() => setDragging(false)}
                    onDrop={handleDrop}
                    onClick={() => inputRef.current?.click()}
                    onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            inputRef.current?.click();
                        }
                    }}
                    role="button"
                    tabIndex={0}
                    aria-label="Choose an EML email file"
                    className={`
            cursor-pointer rounded-xl border-2 border-dashed
            p-8 text-center transition
            ${dragging
                            ? "border-sky-400 bg-sky-500/5"
                            : "border-slate-200 hover:border-slate-600 hover:bg-white/[0.02]"
                        }
          `}
                >
                    <input
                        ref={inputRef}
                        type="file"
                        accept=".eml,message/rfc822"
                        className="hidden"
                        onChange={(event) =>
                            chooseFile(
                                event.target.files?.[0]
                            )
                        }
                    />

                    <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-sky-500/10">
                        <Upload className="h-6 w-6 text-sky-400" />
                    </div>

                    <p className="text-sm font-medium text-slate-700">
                        Drop an .eml file here
                    </p>

                    <p className="mt-1 text-xs text-slate-500">
                        or click to browse your computer
                    </p>
                </div>

                {file && (
                    <div className="mt-4 flex items-center gap-3 rounded-lg border border-slate-200 bg-slate-50 p-3">
                        <div className="rounded-lg bg-slate-100 p-2">
                            <FileText className="h-4 w-4 text-sky-400" />
                        </div>

                        <div className="min-w-0 flex-1">
                            <p className="truncate text-sm text-slate-700">
                                {file.name}
                            </p>

                            <p className="text-xs text-slate-500">
                                {(file.size / 1024).toFixed(1)} KB
                            </p>
                        </div>

                        {!uploading && (
                            <button
                                onClick={(event) => {
                                    event.stopPropagation();
                                    setFile(null);
                                }}
                                className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 hover:text-slate-700"
                            >
                                <X className="h-4 w-4" />
                            </button>
                        )}
                    </div>
                )}

                {uploading && (
                    <div className="mt-4">
                        <div className="mb-2 flex justify-between text-xs">
                            <span className="text-slate-500">
                                Uploading evidence
                            </span>

                            <span className="text-sky-400">
                                {progress}%
                            </span>
                        </div>

                        <div className="h-2 overflow-hidden rounded-full bg-slate-100">
                            <div
                                className="h-full rounded-full bg-sky-500 transition-all"
                                style={{
                                    width: `${progress}%`
                                }}
                            />
                        </div>
                    </div>
                )}

                {error && (
                    <div className="mt-4 rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-sm text-red-400">
                        {error}
                    </div>
                )}

                <div className="mt-5 flex justify-end">
                    <Button
                        onClick={upload}
                        disabled={!file}
                        loading={uploading}
                    >
                        <CheckCircle2 className="h-4 w-4" />
                        Ingest Email
                    </Button>
                </div>
            </div>
        </div>
    );
}
