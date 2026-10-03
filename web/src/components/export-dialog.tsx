"use client";

import { useRef, useState } from "react";

import { Field, Select, inputClass, primaryButtonClass } from "@/components/ui";
import {
  CHANNELS,
  EXPORT_FORMATS,
  EXPORT_GROUPS,
  MAX_EXPORT_ROWS,
  VERDICTS,
} from "@/lib/gateway";
import type { ExportFormat } from "@/lib/gateway";

const secondaryButtonClass =
  "rounded-lg border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800";

/**
 * The Activity page's Export button and the dialog behind it. A plain GET form
 * to `/activity/export`: the browser downloads the attachment and the page
 * stays put. The gateway validates every setting. Prompt text is never part
 * of an export because the gateway never stores it, only its hash.
 */
export function ExportDialog({
  principals,
  verdict,
  channel,
  principal,
  statusFiltered,
}: {
  principals: { slug: string; display_name: string }[];
  verdict: string;
  channel: string;
  /** Principal slug the page is filtered by, or "". */
  principal: string;
  /** The page's status filter is set; the export cannot apply it. */
  statusFiltered: boolean;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [format, setFormat] = useState<ExportFormat>("csv");
  // Integrity hashes the detections, so it brings them along (the gateway
  // adds them); the checkbox only shows that.
  const [integrity, setIntegrity] = useState(true);

  const close = () => {
    dialog.current?.close();
  };

  return (
    <>
      <button
        type="button"
        onClick={() => dialog.current?.showModal()}
        className={secondaryButtonClass}
      >
        Export
      </button>

      <dialog
        ref={dialog}
        aria-labelledby="export-title"
        className="m-auto w-full max-w-2xl rounded-xl border border-zinc-700 bg-zinc-900 text-zinc-100 shadow-2xl backdrop:bg-black/70"
      >
        <form
          method="get"
          action="/activity/export"
          onSubmit={close}
          className="space-y-5 p-6"
        >
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

          <fieldset className="flex gap-2">
            <legend className="mb-1.5 text-xs font-medium tracking-wide text-zinc-400 uppercase">
              Format
            </legend>
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
          </fieldset>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="From (UTC)">
              <input type="date" name="from" className={inputClass} />
            </Field>
            <Field label="To (UTC, inclusive)">
              <input type="date" name="to" className={inputClass} />
            </Field>
            <Field label="Verdict">
              <Select
                name="verdict"
                defaultValue={verdict}
                options={[{ value: "", label: "All verdicts" }, ...VERDICTS]}
              />
            </Field>
            <Field label="Channel">
              <Select
                name="channel"
                defaultValue={channel}
                options={[
                  { value: "", label: "All channels" },
                  ...CHANNELS.map((c) => ({
                    value: c,
                    label: c.toUpperCase(),
                  })),
                ]}
              />
            </Field>
            <Field label="Principal">
              <Select
                name="principal"
                defaultValue={principal}
                options={[
                  { value: "", label: "All principals" },
                  ...principals.map((p) => ({
                    value: p.slug,
                    label: p.display_name,
                  })),
                ]}
              />
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
              The page&apos;s security-status filter is not applied to exports.
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
            {/* Always sent, so unticking every group means "event columns only". */}
            <input type="hidden" name="include" value="" />
            <div className="grid gap-2 sm:grid-cols-2">
              {EXPORT_GROUPS.map((g) => {
                const forced = g.id === "detections" && integrity;
                return (
                  <label
                    key={g.id}
                    className="grid cursor-pointer grid-cols-[auto_1fr] items-start gap-x-2 rounded-lg border border-zinc-800 px-3 py-2 hover:bg-zinc-800/60"
                  >
                    <input
                      // remount when forcing ends, so it comes back ticked
                      key={forced ? "forced" : "free"}
                      type="checkbox"
                      name="include"
                      value={g.id}
                      defaultChecked
                      disabled={forced}
                      onChange={
                        g.id === "integrity"
                          ? (event) => {
                              setIntegrity(event.currentTarget.checked);
                            }
                          : undefined
                      }
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
              onClick={close}
              className={secondaryButtonClass}
            >
              Cancel
            </button>
            <button type="submit" className={primaryButtonClass}>
              Download {format.toUpperCase()}
            </button>
          </div>
        </form>
      </dialog>
    </>
  );
}
