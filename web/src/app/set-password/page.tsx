import { redirect } from "next/navigation";

import { ActionForm } from "@/components/action-form";
import { ShieldIcon } from "@/components/icons";
import { Field, inputClass } from "@/components/ui";
import { getSession } from "@/lib/auth";

import { setPassword } from "./actions";

export default async function SetPasswordPage() {
  const { user } = await getSession();
  if (user === null) {
    redirect("/login");
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-zinc-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 rounded-2xl bg-emerald-500/10 p-3 text-emerald-400 ring-1 ring-emerald-500/30">
            <ShieldIcon className="h-8 w-8" />
          </div>
          <h1 className="text-xl font-semibold text-zinc-50">
            Set your password
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Signed in as {user.email}. Choose a password for future sign-ins.
          </p>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-6">
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
        </div>
      </div>
    </main>
  );
}
