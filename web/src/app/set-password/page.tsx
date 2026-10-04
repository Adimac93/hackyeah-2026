import { redirect } from "next/navigation";

import { ActionForm } from "@/components/action-form";
import { AuthShell } from "@/components/auth-shell";
import { Field, inputClass } from "@/components/ui";
import { getSession } from "@/lib/auth";

import { setPassword } from "./actions";

export default async function SetPasswordPage() {
  const { user } = await getSession();
  if (user === null) {
    redirect("/login");
  }

  return (
    <AuthShell panelTitle="Set your password">
      <h2 className="font-serif text-[28px] leading-tight text-zinc-50">
        Choose a new password.
      </h2>
      <p className="mt-2 mb-6 text-sm leading-relaxed text-zinc-400">
        Signed in as <span className="text-zinc-200">{user.email}</span>. Use it
        for future sign-ins.
      </p>
      <ActionForm
        action={setPassword}
        submitLabel="Save password"
        pendingLabel="Saving…"
      >
        <Field label="New password" hint="At least 12 characters.">
          <input
            name="password"
            type="password"
            autoComplete="new-password"
            minLength={12}
            required
            className={inputClass}
          />
        </Field>
        <Field label="Confirm password">
          <input
            name="confirm"
            type="password"
            autoComplete="new-password"
            minLength={12}
            required
            className={inputClass}
          />
        </Field>
      </ActionForm>
    </AuthShell>
  );
}
