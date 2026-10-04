import { redirect } from "next/navigation";

import { AuthShell } from "@/components/auth-shell";
import { getSession } from "@/lib/auth";
import { availableDemoAccounts } from "@/lib/demo-login";

import { DemoLoginButton } from "./demo-login-button";
import { LoginForm } from "./login-form";

export default async function LoginPage({ searchParams }: PageProps<"/login">) {
  const { user } = await getSession();
  if (user !== null) {
    redirect("/dashboard");
  }
  const { next, error } = await searchParams;
  const demoAccounts = availableDemoAccounts();

  return (
    <AuthShell
      panelTitle="Sign in to the console"
      aside="New accounts have no access until an admin adds them to the security team."
    >
      <h2 className="font-serif text-[28px] leading-tight text-zinc-50">
        Welcome back.
      </h2>
      <p className="mt-1.5 mb-5 text-sm leading-relaxed text-zinc-400">
        Security team access only.
      </p>
      {error === undefined ? null : (
        <p className="mb-4 rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">
          Sign-in link was invalid or expired.
        </p>
      )}
      <LoginForm next={typeof next === "string" ? next : undefined} />
      {demoAccounts.length === 0 ? null : (
        <div className="mt-5 border-t border-zinc-800 pt-5">
          <p className="eyebrow mb-3 text-center text-zinc-500">
            Demo access — no account needed
          </p>
          <div
            className={`grid gap-2 ${demoAccounts.length > 1 ? "sm:grid-cols-2" : ""}`}
          >
            {demoAccounts.map((account) => (
              <DemoLoginButton
                key={account}
                account={account}
                next={typeof next === "string" ? next : undefined}
              />
            ))}
          </div>
        </div>
      )}
    </AuthShell>
  );
}
