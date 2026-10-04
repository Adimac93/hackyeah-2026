"use client";

import { useEffect, useRef, useState, useTransition } from "react";

import { EmptyRow, tableClass, tdClass, thClass } from "@/components/ui";
import { timeAgo } from "@/lib/format";
import {
  MAX_TEXT_PREVIEW_BYTES,
  fmtBytes,
  previewKind,
  resourceDisplayName,
} from "@/lib/resources";
import type { PreviewKind } from "@/lib/resources";

import { deleteResource, resourceUrl } from "./actions";

export interface ResourceFile {
  name: string;
  size: number | null;
  mimetype: string | null;
  createdAt: string | null;
}

interface Preview {
  file: ResourceFile;
  kind: PreviewKind;
  url: string | null;
  text: string | null;
  error: string | null;
}

async function readText(url: string): Promise<string> {
  const response = await fetch(url, {
    headers: { range: `bytes=0-${String(MAX_TEXT_PREVIEW_BYTES - 1)}` },
  });
  if (!response.ok) {
    throw new Error(String(response.status));
  }
  const text = await response.text();
  return text.length >= MAX_TEXT_PREVIEW_BYTES
    ? `${text}\n\n… (preview truncated)`
    : text;
}

function PreviewBody({ preview }: { preview: Preview }) {
  if (preview.error !== null) {
    return <p className="text-sm text-red-400">{preview.error}</p>;
  }
  if (
    preview.url === null ||
    (preview.kind === "text" && preview.text === null)
  ) {
    return <p className="text-sm text-zinc-500">Loading…</p>;
  }
  const name = resourceDisplayName(preview.file.name);
  switch (preview.kind) {
    case "image": {
      return (
        // eslint-disable-next-line @next/next/no-img-element -- signed, short-lived URL
        <img
          src={preview.url}
          alt={name}
          className="mx-auto max-h-[70vh] rounded-lg"
        />
      );
    }
    case "pdf": {
      return (
        <iframe
          src={preview.url}
          title={name}
          className="h-[70vh] w-full rounded-lg bg-white"
        />
      );
    }
    case "video": {
      return (
        <video src={preview.url} controls className="mx-auto max-h-[70vh]">
          <track kind="captions" />
        </video>
      );
    }
    case "audio": {
      return (
        <audio src={preview.url} controls className="w-full">
          <track kind="captions" />
        </audio>
      );
    }
    case "text": {
      return (
        <pre className="scrollbar-subtle max-h-[70vh] overflow-auto rounded-lg bg-zinc-950 p-4 text-xs whitespace-pre-wrap text-zinc-300">
          {preview.text}
        </pre>
      );
    }
    case "none": {
      return (
        <p className="text-sm text-zinc-400">
          No preview for this file type. Use Download to open it.
        </p>
      );
    }
  }
}

const ACTION_CLASS =
  "text-xs text-zinc-400 hover:text-zinc-100 disabled:opacity-50";

/** Modal preview: Escape or a click outside closes it; focus starts on Close. */
function PreviewDialog({
  preview,
  onClose,
  onDownload,
}: {
  preview: Preview;
  onClose: () => void;
  onDownload: () => void;
}) {
  const closeButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    closeButton.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  const name = resourceDisplayName(preview.file.name);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <button
        type="button"
        aria-label="Close preview"
        tabIndex={-1}
        className="absolute inset-0 cursor-default bg-black/70"
        onClick={onClose}
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={`Preview of ${name}`}
        className="relative w-full max-w-4xl rounded-xl border border-zinc-800 bg-zinc-900 shadow-2xl"
      >
        <header className="flex items-center justify-between gap-4 border-b border-zinc-800 px-5 py-3">
          <div className="min-w-0">
            <h2 className="truncate text-sm font-semibold text-zinc-100">
              {name}
            </h2>
            <p className="text-xs text-zinc-500">
              {preview.file.mimetype ?? "unknown type"} ·{" "}
              {fmtBytes(preview.file.size)}
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-4">
            <button className={ACTION_CLASS} onClick={onDownload}>
              Download
            </button>
            <button
              ref={closeButton}
              className={ACTION_CLASS}
              onClick={onClose}
            >
              Close
            </button>
          </div>
        </header>
        <div className="p-5">
          <PreviewBody preview={preview} />
        </div>
      </div>
    </div>
  );
}

export function ResourceList({
  files,
  canWrite,
}: {
  files: ResourceFile[];
  canWrite: boolean;
}) {
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function open(file: ResourceFile) {
    const kind = previewKind(file.name, file.mimetype);
    setPreview({ file, kind, url: null, text: null, error: null });
    void resourceUrl(file.name, false).then(async (result) => {
      if ("error" in result) {
        setPreview({ file, kind, url: null, text: null, error: result.error });
        return;
      }
      let text: string | null = null;
      if (kind === "text") {
        text = await readText(result.url).catch(
          () => "Couldn't load the file.",
        );
      }
      setPreview((current) =>
        current?.file.name === file.name
          ? { file, kind, url: result.url, text, error: null }
          : current,
      );
    });
  }

  function download(file: ResourceFile) {
    setError(null);
    void resourceUrl(file.name, true).then((result) => {
      if ("error" in result) {
        setError(result.error);
      } else {
        window.location.assign(result.url);
      }
    });
  }

  function remove(file: ResourceFile) {
    if (confirming !== file.name) {
      setConfirming(file.name);
      return;
    }
    setConfirming(null);
    startTransition(async () => {
      const result = await deleteResource(file.name);
      setError(result.error ?? null);
      if (preview?.file.name === file.name) {
        setPreview(null);
      }
    });
  }

  const action = ACTION_CLASS;

  return (
    <>
      {error === null ? null : (
        <p role="alert" className="mb-3 text-sm text-red-400">
          {error}
        </p>
      )}
      <div className="overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-900/60">
        <table className={tableClass}>
          <thead className="border-b border-zinc-800">
            <tr>
              <th className={thClass}>Name</th>
              <th className={`${thClass} hidden sm:table-cell`}>Type</th>
              <th className={`${thClass} text-right`}>Size</th>
              <th className={`${thClass} hidden text-right md:table-cell`}>
                Uploaded
              </th>
              <th className={`${thClass} text-right`}>Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {files.length === 0 && (
              <EmptyRow cols={5}>
                No files yet.{canWrite ? " Upload the first one above." : ""}
              </EmptyRow>
            )}
            {files.map((file) => (
              <tr key={file.name} className="hover:bg-zinc-800/40">
                <td className={tdClass}>
                  <button
                    onClick={() => {
                      open(file);
                    }}
                    className="text-left font-medium break-all text-zinc-100 hover:underline"
                  >
                    {resourceDisplayName(file.name)}
                  </button>
                </td>
                <td
                  className={`${tdClass} hidden text-xs text-zinc-500 sm:table-cell`}
                >
                  {file.mimetype ?? "—"}
                </td>
                <td
                  className={`${tdClass} text-right text-xs text-zinc-400 tabular-nums`}
                >
                  {fmtBytes(file.size)}
                </td>
                <td
                  className={`${tdClass} hidden text-right text-xs text-zinc-500 md:table-cell`}
                  suppressHydrationWarning
                >
                  {file.createdAt === null ? "—" : timeAgo(file.createdAt)}
                </td>
                <td className={`${tdClass} text-right whitespace-nowrap`}>
                  <span className="inline-flex gap-3">
                    <button
                      className={action}
                      onClick={() => {
                        open(file);
                      }}
                    >
                      Preview
                    </button>
                    <button
                      className={action}
                      onClick={() => {
                        download(file);
                      }}
                    >
                      Download
                    </button>
                    {canWrite ? (
                      <button
                        disabled={pending}
                        onClick={() => {
                          remove(file);
                        }}
                        onBlur={() => {
                          setConfirming(null);
                        }}
                        className={`text-xs disabled:opacity-50 ${
                          confirming === file.name
                            ? "font-semibold text-red-400"
                            : "text-zinc-400 hover:text-red-400"
                        }`}
                      >
                        {confirming === file.name ? "Delete?" : "Delete"}
                      </button>
                    ) : null}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {preview === null ? null : (
        <PreviewDialog
          preview={preview}
          onClose={() => {
            setPreview(null);
          }}
          onDownload={() => {
            download(preview.file);
          }}
        />
      )}
    </>
  );
}
