import { redirect } from "next/navigation";
import { cache } from "react";

import { canAccessConsole, canWrite } from "@/lib/domain";
import type { TeamMember } from "@/lib/domain";
import { createClient } from "@/lib/supabase/server";

/** Current user + their security-team membership (null if not on the team). Deduped per request. */
export const getSession = cache(async () => {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (user === null) {
    return { supabase, user: null, member: null };
  }

  const { data } = await supabase
    .from("team_members")
    .select("*")
    .eq("user_id", user.id)
    .maybeSingle<TeamMember>();
  return { supabase, user, member: data };
});

/** For pages open to every role, developers included (layout, assistant). */
export async function requireAnyMember() {
  const session = await getSession();
  if (session.user === null) {
    redirect("/login");
  }
  if (session.member === null) {
    redirect("/no-access");
  }
  return { ...session, user: session.user, member: session.member };
}

/** For console pages: must be on the security team. Developers are sent to the assistant. */
export async function requireMember() {
  const session = await requireAnyMember();
  if (!canAccessConsole(session.member.role)) {
    redirect("/chat");
  }
  return session;
}

/** For assistant server actions: any member, returns an error string instead of redirecting. */
export async function requireChatUser() {
  const session = await getSession();
  if (session.user === null || session.member === null) {
    return { error: "You are not signed in as a team member." } as const;
  }
  return {
    ...session,
    user: session.user,
    member: session.member,
    error: null,
  } as const;
}

/** For server actions: returns an error string instead of redirecting. RLS enforces the same rule in the DB. */
export async function requireWriter() {
  const session = await getSession();
  if (session.user === null || session.member === null) {
    return { error: "You are not signed in as a team member." } as const;
  }
  if (!canWrite(session.member.role)) {
    return { error: "Your role is read-only." } as const;
  }
  return {
    ...session,
    user: session.user,
    member: session.member,
    error: null,
  } as const;
}
