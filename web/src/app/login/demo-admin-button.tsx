"use client";

import { useActionState } from "react";

import { secondaryButtonClass } from "@/components/ui";

import { loginAsDemoAdmin } from "./actions";

export function DemoAdminButton({ next }: { next?: string }) {
  const [state, action, pending] = useActionState(loginAsDemoAdmin, {});

  return (
    <form action={action} className="space-y-3">
      <input type="hidden" name="next" value={next ?? ""} />
      <button
        disabled={pending}
        className={`${secondaryButtonClass} w-full border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10`}
      >
        {pending ? "Signing in…" : "Log in as admin"}
        <span aria-hidden className="text-lg leading-none font-normal">
          →
        </span>
      </button>
      {state.error === undefined ? null : (
        <p
          role="alert"
          className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300"
        >
          {state.error}
        </p>
      )}
    </form>
  );
}
