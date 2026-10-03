"use client";

import { useActionState, useState } from "react";

import type { FormState } from "@/lib/domain";

import { savePolicy } from "./actions";

/** The active catalog as editable text; Save uploads the whole thing as the next version. */
export function PolicyEditor({
  active,
  canEdit,
}: {
  active: string;
  canEdit: boolean;
}) {
  // controlled, so a rejected save keeps the edits instead of resetting the form
  const [text, setText] = useState(active);
  const [state, formAction, pending] = useActionState<FormState, FormData>(
    savePolicy,
    {},
  );
  const dirty = text !== active;

  return (
    <form action={formAction} className="space-y-3">
      <textarea
        name="catalog"
        value={text}
        onChange={(event) => {
          setText(event.target.value);
        }}
        readOnly={!canEdit}
        rows={24}
        spellCheck={false}
        aria-label="Control catalog (TOML)"
        className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs leading-relaxed text-zinc-200 focus:border-emerald-500 focus:outline-none"
      />
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
      {canEdit ? (
        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={pending || !dirty}
            className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {pending ? "Validating…" : "Save & activate"}
          </button>
          <button
            type="button"
            disabled={pending || !dirty}
            onClick={() => {
              setText(active);
            }}
            className="text-sm text-zinc-400 hover:text-zinc-100 disabled:opacity-50"
          >
            Discard changes
          </button>
          <span className="text-xs text-zinc-500">
            The gateway validates the whole catalog; an invalid one is rejected
            and the active policy keeps running.
          </span>
        </div>
      ) : (
        <p className="text-xs text-zinc-500">
          Read-only: only admins can change the policy.
        </p>
      )}
    </form>
  );
}
