"use client";

import { useActionState } from "react";

import { secondaryButtonClass } from "@/components/ui";
import type { DemoAccount } from "@/lib/demo-login";

import { loginAsDemoAdmin, loginAsDemoDeveloper } from "./actions";

const ACTIONS = { admin: loginAsDemoAdmin, developer: loginAsDemoDeveloper };
const LABELS: Record<DemoAccount, { title: string; note: string }> = {
  admin: { title: "Log in as admin", note: "the full security console" },
  developer: { title: "Log in as developer", note: "the assistant only" },
};

export function DemoLoginButton({
  account,
  next,
}: {
  account: DemoAccount;
  next?: string;
}) {
  const [state, action, pending] = useActionState(ACTIONS[account], {});
  const label = LABELS[account];

  return (
    <form action={action} className="space-y-2">
      <input type="hidden" name="next" value={next ?? ""} />
      <button
        disabled={pending}
        title={`Sign in to the demo account: ${label.note}`}
        className={`${secondaryButtonClass} w-full border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10`}
      >
        {pending ? "Signing in…" : label.title}
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
