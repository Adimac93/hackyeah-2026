import { redirect } from "next/navigation";

import { AuthShell } from "@/components/auth-shell";
import { secondaryButtonClass } from "@/components/ui";
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
    <AuthShell panelTitle="Access pending">
      <h2 className="font-serif text-[28px] leading-tight text-zinc-50">
        You&apos;re almost in.
      </h2>
      <p className="mt-3 text-sm leading-relaxed text-zinc-400">
        You&apos;re signed in as{" "}
        <span className="text-zinc-200">{user.email}</span>, but you&apos;re not
        on the security team yet. Ask a console admin to add you on the Team
        page.
      </p>
      <form action={signOut} className="mt-6">
        <button className={secondaryButtonClass}>Sign out</button>
      </form>
    </AuthShell>
  );
}
