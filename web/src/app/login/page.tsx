import { redirect } from "next/navigation";

import { ShieldIcon } from "@/components/icons";
import { getSession } from "@/lib/auth";

import { LoginForm } from "./login-form";

export default async function LoginPage({ searchParams }: PageProps<"/login">) {
  const { user } = await getSession();
  if (user !== null) {
    redirect("/dashboard");
  }
  const { next, error } = await searchParams;

  return (
    <main className="flex min-h-screen items-center justify-center bg-zinc-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 rounded-2xl bg-emerald-500/10 p-3 text-emerald-400 ring-1 ring-emerald-500/30">
            <ShieldIcon className="h-8 w-8" />
          </div>
          <h1 className="text-xl font-semibold text-zinc-50">SecOps Console</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Security team access only
          </p>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-6">
          {error === undefined ? null : (
            <p className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">
              Sign-in link was invalid or expired.
            </p>
          )}
          <LoginForm next={typeof next === "string" ? next : undefined} />
        </div>
        <p className="mt-6 text-center text-xs text-zinc-500">
          New accounts have no access until an admin adds them to the security
          team.
        </p>
      </div>
    </main>
  );
}
