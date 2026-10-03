"use client";

import { useActionState } from "react";

import { loginAsDemoAdmin } from "./actions";

export function DemoAdminButton({ next }: { next?: string }) {
  const [state, action, pending] = useActionState(loginAsDemoAdmin, {});

  return (
    <form action={action} className="space-y-3">
      <input type="hidden" name="next" value={next ?? ""} />
      <button
        disabled={pending}
        className="w-full rounded-lg border border-amber-500/50 bg-amber-500/10 px-4 py-2 text-sm font-semibold text-amber-300 hover:bg-amber-500/20 disabled:opacity-50"
      >
        {pending ? "…" : "Log in as admin"}
      </button>
      {state.error === undefined ? null : (
        <p
          role="alert"
          className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300"
        >
          {state.error}
        </p>
      )}
    </form>
  );
}
