"use client";

import { useActionState, useRef, useState } from "react";

import { catalogFileProblems, diffCatalogs } from "@/lib/catalog";
import type { CatalogDiff } from "@/lib/catalog";
import type { FormState } from "@/lib/domain";
import { MAX_POLICY_BYTES, checkPolicyUpload } from "@/lib/gateway";

import { savePolicy } from "./actions";

interface Checked {
  name: string;
  text: string;
  problems: string[];
  diff: CatalogDiff;
}

function DiffList({
  title,
  ids,
  className,
}: {
  title: string;
  ids: string[];
  className: string;
}) {
  if (ids.length === 0) {
    return null;
  }
  return (
    <div>
      <p className={`text-xs font-semibold ${className}`}>
        {title} ({ids.length})
      </p>
      <ul className="mt-1 flex flex-wrap gap-1">
        {ids.map((id) => (
          <li key={id}>
            <code className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-300">
              {id}
            </code>
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * Replace every rule with an uploaded catalog file. The file is checked here
 * (readable, controls valid, ids unique) and compared with the rules in force;
 * the gateway does the full validation when it's activated.
 */
export function CatalogUpload({
  active,
  baseSha,
}: {
  active: string;
  baseSha: string;
}) {
  const [checked, setChecked] = useState<Checked | null>(null);
  const [readError, setReadError] = useState<string | null>(null);
  const [state, formAction, pending] = useActionState<FormState, FormData>(
    savePolicy,
    {},
  );
  const input = useRef<HTMLInputElement>(null);

  async function pick(file: File | undefined) {
    setChecked(null);
    setReadError(null);
    if (file === undefined) {
      return;
    }
    if (!file.name.toLowerCase().endsWith(".toml")) {
      setReadError(`${file.name}: pick a .toml file.`);
      return;
    }
    if (file.size > MAX_POLICY_BYTES) {
      setReadError(`${file.name}: larger than 256 KB.`);
      return;
    }
    const text = await file.text();
    const basic = checkPolicyUpload(text);
    setChecked({
      name: file.name,
      text,
      problems: basic.ok ? catalogFileProblems(text) : [basic.error],
      diff: diffCatalogs(active, text),
    });
  }

  function reset() {
    setChecked(null);
    setReadError(null);
    if (input.current !== null) {
      input.current.value = "";
    }
  }

  const diff = checked?.diff;
  const nothingChanges =
    diff?.added.length === 0 &&
    diff.removed.length === 0 &&
    diff.changed.length === 0;

  return (
    <div className="space-y-4">
      <label className="flex cursor-pointer flex-col items-center justify-center gap-1 rounded-xl border border-dashed border-zinc-700 px-4 py-6 text-center hover:border-zinc-500">
        <span className="text-sm font-medium text-zinc-200">
          {checked === null
            ? "Choose a catalog file (.toml)"
            : `Selected: ${checked.name}`}
        </span>
        <span className="text-xs text-zinc-500">
          Replaces every rule in the active catalog · up to 256 KB
        </span>
        <input
          ref={input}
          type="file"
          accept=".toml,application/toml,text/plain"
          className="sr-only"
          onChange={(event) => {
            void pick(event.target.files?.[0]);
          }}
        />
      </label>

      {readError === null ? null : (
        <p role="alert" className="text-sm text-red-400">
          {readError}
        </p>
      )}

      {checked === null || diff === undefined ? null : (
        <div className="space-y-3 rounded-lg border border-zinc-800 bg-zinc-950/60 p-4">
          {checked.problems.length > 0 ? (
            <div role="alert" className="space-y-1">
              <p className="text-sm font-semibold text-red-400">
                This file can&apos;t be activated:
              </p>
              <ul className="list-inside list-disc text-sm text-red-300">
                {checked.problems.map((problem) => (
                  <li key={problem}>{problem}</li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="text-sm text-emerald-400">
              File checked:{" "}
              {diff.added.length + diff.changed.length + diff.unchanged} rules,
              all valid.
            </p>
          )}

          <p className="text-xs text-zinc-400">
            Compared with the rules in force:{" "}
            {nothingChanges
              ? "the rules are identical (other settings may still differ)."
              : `${String(diff.unchanged)} unchanged.`}
          </p>
          <DiffList
            title="Added"
            ids={diff.added}
            className="text-emerald-400"
          />
          <DiffList
            title="Removed"
            ids={diff.removed}
            className="text-red-400"
          />
          {diff.changed.length === 0 ? null : (
            <div>
              <p className="text-xs font-semibold text-amber-400">
                Changed ({diff.changed.length})
              </p>
              <ul className="mt-1 space-y-0.5 text-xs text-zinc-400">
                {diff.changed.map((c) => (
                  <li key={c.id}>
                    <code className="text-zinc-300">{c.id}</code>:{" "}
                    {c.changes.join(", ")}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <form action={formAction} className="flex items-center gap-3 pt-1">
            <input type="hidden" name="catalog" value={checked.text} />
            <input type="hidden" name="base_sha" value={baseSha} />
            <button
              type="submit"
              disabled={
                pending || checked.problems.length > 0 || state.ok !== undefined
              }
              className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {pending ? "Validating…" : "Replace all rules & activate"}
            </button>
            <button
              type="button"
              disabled={pending}
              onClick={reset}
              className="text-sm text-zinc-400 hover:text-zinc-100 disabled:opacity-50"
            >
              Cancel
            </button>
          </form>
        </div>
      )}

      {state.error === undefined ? null : (
        <p
          role="alert"
          className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm whitespace-pre-wrap text-red-300"
        >
          {state.error}
        </p>
      )}
      {state.ok === undefined ? null : (
        <p
          role="status"
          className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300"
        >
          {state.ok}
        </p>
      )}
    </div>
  );
}
