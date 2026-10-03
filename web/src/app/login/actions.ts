"use server";

import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { formString } from "@/lib/domain";
import type { FormState } from "@/lib/domain";
import { createClient } from "@/lib/supabase/server";

function safeNext(next: FormDataEntryValue | null): string {
  const path = typeof next === "string" ? next : "";
  // only same-origin relative paths — never `//evil.com`
  return path.startsWith("/") && !path.startsWith("//") ? path : "/dashboard";
}

export async function authenticate(
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const email = formString(formData, "email").trim();
  const password = formString(formData, "password");
  const mode = formData.get("mode") === "signup" ? "signup" : "signin";

  if (!email || !password) {
    return { error: "Email and password are required." };
  }
  if (mode === "signup" && password.length < 12) {
    return { error: "Use a password of at least 12 characters." };
  }

  const supabase = await createClient();

  if (mode === "signup") {
    const requestHeaders = await headers();
    const origin = requestHeaders.get("origin") ?? "";
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: { emailRedirectTo: `${origin}/auth/callback` },
    });
    if (error !== null) {
      return { error: error.message };
    }
    if (data.session === null) {
      return { ok: "Check your inbox to confirm your email, then sign in." };
    }
  } else {
    const { error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    // deliberately generic: don't reveal whether the account exists
    if (error !== null) {
      return { error: "Invalid email or password." };
    }
  }

  redirect(safeNext(formData.get("next")));
}

export async function signOut() {
  const supabase = await createClient();
  await supabase.auth.signOut();
  redirect("/login");
}
