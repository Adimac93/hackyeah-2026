"use client";

import { useActionState } from "react";

import { inputClass } from "@/components/ui";

import { authenticate } from "./actions";

export function LoginForm({ next }: { next?: string }) {
  const [state, action, pending] = useActionState(authenticate, {});

  return (
    <form action={action} className="space-y-4">
      <input type="hidden" name="next" value={next ?? ""} />
      <label className="block space-y-1.5">
        <span className="text-xs font-medium tracking-wide text-zinc-400 uppercase">
          Work email
        </span>
        <input
          name="email"
          type="email"
          autoComplete="email"
          required
          className={inputClass}
          placeholder="you@company.com"
        />
      </label>
      <label className="block space-y-1.5">
        <span className="text-xs font-medium tracking-wide text-zinc-400 uppercase">
          Password
        </span>
        <input
          name="password"
          type="password"
          autoComplete="current-password"
          required
          className={inputClass}
        />
      </label>

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

      <div className="flex gap-3 pt-1">
        <button
          name="mode"
          value="signin"
          disabled={pending}
          className="flex-1 rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400 disabled:opacity-50"
        >
          {pending ? "…" : "Sign in"}
        </button>
        <button
          name="mode"
          value="signup"
          disabled={pending}
          className="rounded-lg border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-300 hover:bg-zinc-800 disabled:opacity-50"
        >
          Create account
        </button>
      </div>
    </form>
  );
}
