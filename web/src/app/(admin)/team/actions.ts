"use server";

import { revalidatePath } from "next/cache";
import { headers } from "next/headers";

import { getSession } from "@/lib/auth";
import { TEAM_ROLES, formString } from "@/lib/domain";
import type { FormState } from "@/lib/domain";
import { createAdminClient } from "@/lib/supabase/admin";

async function requireAdmin() {
  const session = await getSession();
  if (session.user === null || session.member?.role !== "admin") {
    return { error: "Only admins can manage the team." } as const;
  }
  return { ...session, user: session.user, error: null } as const;
}

function parseRole(v: FormDataEntryValue | null) {
  const role = typeof v === "string" ? v : "";
  return (TEAM_ROLES as readonly string[]).includes(role) ? role : null;
}

export async function changeRole(
  userId: string,
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await requireAdmin();
  if (session.error) {
    return { error: session.error };
  }
  if (userId === session.user.id) {
    return { error: "You can't change your own role." };
  }

  const role = parseRole(formData.get("role"));
  if (role === null) {
    return { error: "Pick a role." };
  }

  // upserts, so this also grants access to users who aren't on the team yet
  const { error } = await session.supabase.rpc("set_user_role", {
    target_user_id: userId,
    new_role: role,
  });
  if (error !== null) {
    return { error: error.message };
  }
  revalidatePath("/team");
  return { ok: "Role updated." };
}

export async function removeMember(userId: string): Promise<void> {
  const session = await requireAdmin();
  if (session.error || userId === session.user.id) {
    return;
  }
  await session.supabase.from("team_members").delete().eq("user_id", userId);
  revalidatePath("/team");
}

/** Invite by email: grants the role now if the account exists, otherwise when they sign up. */
export async function inviteMember(
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await requireAdmin();
  if (session.error) {
    return { error: session.error };
  }

  const email = formString(formData, "email").trim().toLowerCase();
  const role = parseRole(formData.get("role"));
  if (!email.includes("@")) {
    return { error: "Enter a valid email." };
  }
  if (role === null) {
    return { error: "Pick a role." };
  }

  const { data, error } = await session.supabase
    .rpc("invite_team_member", { member_email: email, member_role: role })
    .overrideTypes<string, { merge: false }>();
  if (error !== null) {
    return { error: error.message };
  }

  revalidatePath("/team");
  if (data === "granted") {
    return {
      ok: `${email} already has an account and now has ${role} access.`,
    };
  }

  // the invite is stored either way; the email is a convenience on top
  const admin = createAdminClient();
  if (admin === null) {
    return {
      ok: `Invite saved for ${email} as ${role}. No email sent (SUPABASE_SECRET_KEY isn't set) — ask them to sign up at /login.`,
    };
  }
  const requestHeaders = await headers();
  const origin = requestHeaders.get("origin") ?? "";
  const { error: mailError } = await admin.auth.admin.inviteUserByEmail(email, {
    redirectTo: `${origin}/auth/accept`,
  });
  if (mailError !== null) {
    console.error(
      "[team] invite email failed",
      mailError.status,
      mailError.code,
    );
    return {
      error: `Invite saved for ${email}, but the email couldn't be sent (${mailError.message}). They can still sign up at /login.`,
    };
  }
  return {
    ok: `Invitation email sent to ${email}. They get ${role} access once they accept it.`,
  };
}

export async function cancelInvite(email: string): Promise<void> {
  const session = await requireAdmin();
  if (session.error) {
    return;
  }
  await session.supabase.from("team_invites").delete().eq("email", email);
  revalidatePath("/team");
}
