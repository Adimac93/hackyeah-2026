"use client";

import { useEffect, useState } from "react";

import { Field, inputClass } from "@/components/ui";
import {
  CHANNELS,
  EXPORT_FORMATS,
  EXPORT_GROUPS,
  MAX_EXPORT_ROWS,
  VERDICTS,
} from "@/lib/gateway";
import type { ExportFormat, ExportGroup } from "@/lib/gateway";

const ALL_GROUPS = EXPORT_GROUPS.map((g) => g.id);

/**
 * The Activity page's single Export button and the dialog behind it: format,
 * date range, filters (seeded from the page's) and which column groups to
 * include. Downloads through `/activity/export`; prompt text is never part of
 * an export because the gateway never stores it, only its hash.
 */
export function ExportDialog({
  principals,
  verdict,
  channel,
  principal,
  statusFiltered,
}: {
  principals: { id: string; display_name: string }[];
  verdict: string;
  channel: string;
  principal: string;
  /** The page's status filter is set; the export cannot apply it. */
  statusFiltered: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [format, setFormat] = useState<ExportFormat>("csv");
  const [groups, setGroups] = useState<Set<ExportGroup>>(new Set(ALL_GROUPS));

  useEffect(() => {
    if (!open) {
      return;
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  // Integrity hashes the detections, so it cannot go without them.
  const integrity = groups.has("integrity");
  const toggle = (group: ExportGroup) => {
    setGroups((current) => {
      const next = new Set(current);
      if (next.has(group)) {
        next.delete(group);
      } else {
        next.add(group);
      }
      return next;
    });
  };

  /** Query for `/activity/export` from the dialog's fields and toggles. */
  const exportUrl = (form: HTMLFormElement) => {
    const data = new FormData(form);
    const query = new URLSearchParams({ format });
    for (const key of [
      "from",
      "to",
      "verdict",
      "channel",
      "principal",
      "user",
      "control",
      "limit",
    ]) {
      const raw = data.get(key);
      const value = typeof raw === "string" ? raw.trim() : "";
      if (value !== "") {
        query.set(key, value);
      }
    }
    for (const group of groups) {
      query.append("include", group);
    }
    if (integrity && !groups.has("detections")) {
      query.append("include", "detections");
    }
    return `/activity/export?${query.toString()}`;
  };

  return (
    <>
      <button
        type="button"
        onClick={() => {
          setOpen(true);
        }}
        className="rounded-lg border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800"
      >
        Export
      </button>

      {open ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="export-title"
        >
          <form
            onSubmit={(event) => {
              event.preventDefault();
              // The route answers with an attachment: a plain link download,
              // so the page stays where it is.
              const link = document.createElement("a");
              link.href = exportUrl(event.currentTarget);
              link.click();
              setOpen(false);
            }}
            className="max-h-full w-full max-w-2xl space-y-5 overflow-y-auto rounded-xl border border-zinc-700 bg-zinc-900 p-6 shadow-2xl"
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2
                  id="export-title"
                  className="text-lg font-semibold text-zinc-50"
                >
                  Export activity
                </h2>
                <p className="mt-1 text-sm text-zinc-400">
                  Every request the gateway intercepted, with what it decided.
                  Prompt text is not included: the gateway stores only its hash.
                </p>
              </div>
              <button
                type="button"
                aria-label="Close"
                onClick={() => {
                  setOpen(false);
                }}
                className="text-zinc-500 hover:text-zinc-300"
              >
                ✕
              </button>
            </div>

            <fieldset className="space-y-1.5">
              <legend className="text-xs font-medium tracking-wide text-zinc-400 uppercase">
                Format
              </legend>
              <div className="flex gap-2">
                {EXPORT_FORMATS.map((f) => (
                  <label
                    key={f}
                    className={`cursor-pointer rounded-lg border px-3 py-1.5 text-sm ${
                      format === f
                        ? "border-emerald-500 text-emerald-300"
                        : "border-zinc-700 text-zinc-300 hover:bg-zinc-800"
                    }`}
                  >
                    <input
                      type="radio"
                      name="format"
                      value={f}
                      checked={format === f}
                      onChange={() => {
                        setFormat(f);
                      }}
                      className="sr-only"
                    />
                    {f.toUpperCase()}
                  </label>
                ))}
              </div>
            </fieldset>

            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="From (UTC)">
                <input type="date" name="from" className={inputClass} />
              </Field>
              <Field label="To (UTC, inclusive)">
                <input type="date" name="to" className={inputClass} />
              </Field>
              <Field label="Verdict">
                <select
                  name="verdict"
                  defaultValue={verdict}
                  className={inputClass}
                >
                  <option value="">All verdicts</option>
                  {VERDICTS.map((v) => (
                    <option key={v} value={v}>
                      {v}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Channel">
                <select
                  name="channel"
                  defaultValue={channel}
                  className={inputClass}
                >
                  <option value="">All channels</option>
                  {CHANNELS.map((c) => (
                    <option key={c} value={c}>
                      {c.toUpperCase()}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Principal">
                <select
                  name="principal"
                  defaultValue={principal}
                  className={inputClass}
                >
                  <option value="">All principals</option>
                  {principals.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.display_name}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="User" hint="Exactly as recorded, e.g. an email">
                <input
                  type="text"
                  name="user"
                  placeholder="Any user"
                  className={inputClass}
                />
              </Field>
              <Field label="Control" hint="Only events where it fired">
                <input
                  type="text"
                  name="control"
                  placeholder="e.g. secret.aws-access-key"
                  className={inputClass}
                />
              </Field>
              <Field
                label="Max rows"
                hint={`Oldest first, up to ${MAX_EXPORT_ROWS.toLocaleString()}`}
              >
                <input
                  type="number"
                  name="limit"
                  min={1}
                  max={MAX_EXPORT_ROWS}
                  defaultValue={MAX_EXPORT_ROWS}
                  className={inputClass}
                />
              </Field>
            </div>
            {statusFiltered ? (
              <p className="text-xs text-amber-400">
                The page&apos;s security-status filter is not applied to
                exports.
              </p>
            ) : null}

            <fieldset className="space-y-2">
              <legend className="text-xs font-medium tracking-wide text-zinc-400 uppercase">
                Include
              </legend>
              <p className="text-xs text-zinc-500">
                Event id, time, trace, hook, channel and verdict are always
                included.
              </p>
              <div className="grid gap-2 sm:grid-cols-2">
                {EXPORT_GROUPS.map((g) => {
                  const forced = g.id === "detections" && integrity;
                  return (
                    <label
                      key={g.id}
                      className="grid cursor-pointer grid-cols-[auto_1fr] items-start gap-x-2 rounded-lg border border-zinc-800 px-3 py-2 hover:bg-zinc-800/60"
                    >
                      <input
                        type="checkbox"
                        checked={forced || groups.has(g.id)}
                        disabled={forced}
                        onChange={() => {
                          toggle(g.id);
                        }}
                        className="mt-0.5 accent-emerald-500"
                      />
                      <span className="text-sm text-zinc-200">{g.label}</span>
                      <span className="col-start-2 text-xs text-zinc-500">
                        {forced ? "required by Integrity" : g.hint}
                      </span>
                    </label>
                  );
                })}
              </div>
              <p className="text-xs text-zinc-500">
                {integrity
                  ? format === "json"
                    ? "This file can be verified offline: just verify-audit --file <file>.json"
                    : "Choose JSON to verify the file offline with just verify-audit --file."
                  : "Without Integrity the file cannot be verified against the hash chain."}
              </p>
            </fieldset>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setOpen(false);
                }}
                className="rounded-lg border border-zinc-700 px-3.5 py-2 text-sm text-zinc-300 hover:bg-zinc-800"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="rounded-lg bg-emerald-500 px-3.5 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400"
              >
                Download {format.toUpperCase()}
              </button>
            </div>
          </form>
        </div>
      ) : null}
    </>
  );
}
