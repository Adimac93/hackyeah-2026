"use client";

import { useActionState } from "react";

import type { FormState } from "@/lib/domain";

/** Compact text-style action for table rows and cards, with the result shown inline. */
export function InlineAction({
  action,
  label,
  pendingLabel = "Working…",
  showOk = true,
}: {
  action: (previous: FormState, formData: FormData) => Promise<FormState>;
  label: string;
  pendingLabel?: string;
  /** false shows a short "Done" instead of the full ok message */
  showOk?: boolean;
}) {
  const [state, formAction, pending] = useActionState(action, {});
  return (
    <form action={formAction} className="flex flex-col items-end gap-0.5">
      <button
        disabled={pending}
        className="text-xs text-zinc-400 hover:text-zinc-100 disabled:opacity-50"
      >
        {pending ? pendingLabel : label}
      </button>
      {state.ok === undefined ? null : (
        <span
          role="status"
          className="max-w-56 text-right text-xs text-emerald-400"
        >
          {showOk ? state.ok : "Done"}
        </span>
      )}
      {state.error === undefined ? null : (
        <span role="alert" className="max-w-56 text-right text-xs text-red-400">
          {state.error}
        </span>
      )}
    </form>
  );
}
