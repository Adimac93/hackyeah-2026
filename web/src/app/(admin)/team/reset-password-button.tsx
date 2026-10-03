"use client";

import { useActionState } from "react";

import type { FormState } from "@/lib/domain";

/** Compact text-style action for table rows, with inline result. */
export function ResetPasswordButton({
  action,
}: {
  action: (previous: FormState, formData: FormData) => Promise<FormState>;
}) {
  const [state, formAction, pending] = useActionState(action, {});
  return (
    <form action={formAction} className="flex flex-col items-end gap-0.5">
      <button
        disabled={pending}
        className="text-xs text-zinc-400 hover:text-zinc-100 disabled:opacity-50"
      >
        {pending ? "Sending…" : "Send reset link"}
      </button>
      {state.ok === undefined ? null : (
        <span role="status" className="text-xs text-emerald-400">
          Sent
        </span>
      )}
      {state.error === undefined ? null : (
        <span role="alert" className="max-w-48 text-xs text-red-400">
          {state.error}
        </span>
      )}
    </form>
  );
}
