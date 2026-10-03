"use server";

import { revalidatePath } from "next/cache";

import { getSession } from "@/lib/auth";
import { TEAM_ROLES, formString } from "@/lib/domain";
import type { FormState } from "@/lib/domain";

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

export async function addMember(
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await requireAdmin();
  if (session.error) {
    return { error: session.error };
  }

  const email = formString(formData, "email").trim();
  const role = parseRole(formData.get("role"));
  if (!email.includes("@")) {
    return { error: "Enter a valid email." };
  }
  if (role === null) {
    return { error: "Pick a role." };
  }

  const { error } = await session.supabase.rpc("add_team_member", {
    member_email: email,
    member_role: role,
  });
  if (error !== null) {
    return { error: error.message };
  }

  revalidatePath("/team");
  return { ok: `${email} now has ${role} access.` };
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

  const { error } = await session.supabase
    .from("team_members")
    .update({ role })
    .eq("user_id", userId);
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
