import Link from "next/link";

import { ActionForm } from "@/components/action-form";
import { AuthShell } from "@/components/auth-shell";
import { Field, inputClass } from "@/components/ui";

import { requestPasswordReset } from "../actions";

export default function ForgotPasswordPage() {
  return (
    <AuthShell
      panelTitle="Reset your password"
      aside={
        <Link href="/login" className="text-zinc-400 hover:text-zinc-100">
          ← Back to sign in
        </Link>
      }
    >
      <h2 className="font-serif text-[28px] leading-tight text-zinc-50">
        Forgot it? No problem.
      </h2>
      <p className="mt-2 mb-6 text-sm leading-relaxed text-zinc-400">
        We&apos;ll email you a link to choose a new one.
      </p>
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
    </AuthShell>
  );
}
