import { redirect } from "next/navigation";

import { getSession } from "@/lib/auth";

import { signOut } from "../login/actions";

export default async function NoAccessPage() {
  const { user, member } = await getSession();
  if (user === null) {
    redirect("/login");
  }
  if (member !== null) {
    redirect("/dashboard");
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-zinc-950 px-4">
      <div className="max-w-md rounded-xl border border-zinc-800 bg-zinc-900/60 p-8 text-center">
        <h1 className="text-lg font-semibold text-zinc-50">Access pending</h1>
        <p className="mt-2 text-sm text-zinc-400">
          You&apos;re signed in as{" "}
          <span className="text-zinc-200">{user.email}</span>, but you&apos;re
          not on the security team yet. Ask a console admin to add you on the
          Team page.
        </p>
        <form action={signOut} className="mt-6">
          <button className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800">
            Sign out
          </button>
        </form>
      </div>
    </main>
  );
}
