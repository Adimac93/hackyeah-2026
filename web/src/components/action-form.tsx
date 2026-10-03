"use client";

import { useActionState } from "react";
import type { ReactNode } from "react";

import type { FormState } from "@/lib/domain";

interface Props {
  action: (previous: FormState, formData: FormData) => Promise<FormState>;
  submitLabel: string;
  pendingLabel?: string;
  children: ReactNode;
  className?: string;
  disabled?: boolean;
  danger?: boolean;
}

/** A form bound to a server action that reports `{ error }` / `{ ok }` inline. */
export function ActionForm({
  action,
  submitLabel,
  pendingLabel = "Saving…",
  children,
  className = "space-y-4",
  disabled,
  danger,
}: Props) {
  const [state, formAction, pending] = useActionState(action, {});

  return (
    <form action={formAction} className={className}>
      {children}
      {state.error === undefined ? null : (
        <p
          role="alert"
          className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300"
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
      <button
        type="submit"
        disabled={pending || disabled}
        className={`rounded-lg px-4 py-2 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50 ${
          danger === true
            ? "bg-red-500/90 text-white hover:bg-red-500"
            : "bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
        }`}
      >
        {pending ? pendingLabel : submitLabel}
      </button>
    </form>
  );
}
