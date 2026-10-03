import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { ShieldIcon } from "@/components/icons";
import { Field, inputClass } from "@/components/ui";

import { requestPasswordReset } from "../actions";

export default function ForgotPasswordPage() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-zinc-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 rounded-2xl bg-emerald-500/10 p-3 text-emerald-400 ring-1 ring-emerald-500/30">
            <ShieldIcon className="h-8 w-8" />
          </div>
          <h1 className="text-xl font-semibold text-zinc-50">
            Reset your password
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            We&apos;ll email you a link to choose a new one.
          </p>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-6">
          <ActionForm
            action={requestPasswordReset}
            submitLabel="Send reset link"
            pendingLabel="Sending…"
          >
            <Field label="Work email">
              <input
                name="email"
                type="email"
                autoComplete="email"
                required
                className={inputClass}
                placeholder="you@company.com"
              />
            </Field>
          </ActionForm>
        </div>
        <p className="mt-6 text-center text-sm">
          <Link href="/login" className="text-zinc-400 hover:text-zinc-200">
            ← Back to sign in
          </Link>
        </p>
      </div>
    </main>
  );
}
