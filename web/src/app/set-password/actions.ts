"use server";

import { redirect } from "next/navigation";

import { formString } from "@/lib/domain";
import type { FormState } from "@/lib/domain";
import { createClient } from "@/lib/supabase/server";

/** Invited users arrive signed in but without a password; this sets one. */
export async function setPassword(
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const password = formString(formData, "password");
  const confirm = formString(formData, "confirm");
  // same rule as sign-up
  if (password.length < 12) {
    return { error: "Use a password of at least 12 characters." };
  }
  if (password !== confirm) {
    return { error: "Passwords don't match." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (user === null) {
    redirect("/login");
  }

  const { error } = await supabase.auth.updateUser({ password });
  if (error !== null) {
    return { error: error.message };
  }
  redirect("/dashboard");
}
