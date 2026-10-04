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
        className={`inline-flex items-center justify-center gap-2 rounded-md px-4 py-2.5 text-[13px] font-semibold tracking-[0.02em] transition hover:-translate-y-px disabled:pointer-events-none disabled:opacity-50 ${
          danger === true
            ? "bg-red-500 text-zinc-950 hover:bg-red-400"
            : "bg-emerald-500 text-zinc-950 hover:bg-emerald-600"
        }`}
      >
        {pending ? pendingLabel : submitLabel}
      </button>
    </form>
  );
}
