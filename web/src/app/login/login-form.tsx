"use client";

import Link from "next/link";
import { useActionState } from "react";

import { buttonClass, inputClass, secondaryButtonClass } from "@/components/ui";

import { authenticate } from "./actions";

export function LoginForm({ next }: { next?: string }) {
  const [state, action, pending] = useActionState(authenticate, {});

  return (
    <form action={action} className="space-y-4">
      <input type="hidden" name="next" value={next ?? ""} />
      <label className="block space-y-1.5">
        <span className="eyebrow text-zinc-400">Work email</span>
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
        <span className="eyebrow text-zinc-400">Password</span>
        <input
          name="password"
          type="password"
          autoComplete="current-password"
          required
          placeholder="Enter your password"
          className={inputClass}
        />
      </label>
      <p className="-mt-2 text-right">
        <Link
          href="/login/forgot"
          className="text-xs text-zinc-500 underline-offset-4 hover:text-emerald-400 hover:underline"
        >
          Forgot password?
        </Link>
      </p>

      {state.error === undefined ? null : (
        <p
          role="alert"
          className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300"
        >
          {state.error}
        </p>
      )}
      {state.ok === undefined ? null : (
        <p
          role="status"
          className="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300"
        >
          {state.ok}
        </p>
      )}

      <div className="flex gap-3 pt-1">
        <button
          name="mode"
          value="signin"
          disabled={pending}
          className={`${buttonClass} flex-1`}
        >
          {pending ? "…" : "Sign in"}
        </button>
        <button
          name="mode"
          value="signup"
          disabled={pending}
          className={secondaryButtonClass}
        >
          Create account
        </button>
      </div>
    </form>
  );
}
