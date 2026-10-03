"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { requireWriter } from "@/lib/auth";
import {
  formToObject,
  nextPolicyVersion,
  parsePolicyInput,
} from "@/lib/domain";
import type { FormState, Policy } from "@/lib/domain";

export async function createPolicy(
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await requireWriter();
  if (session.error) {
    return { error: session.error };
  }

  const parsed = parsePolicyInput(formToObject(formData));
  if (!parsed.ok) {
    return { error: parsed.error };
  }

  const { data, error } = await session.supabase
    .from("policies")
    .insert({
      ...parsed.value,
      owner_id: parsed.value.owner_id ?? session.user.id,
    })
    .select("id")
    .single();
  if (error !== null) {
    return { error: error.message };
  }

  revalidatePath("/", "layout");
  redirect(`/policies/${data.id as string}`);
}

export async function updatePolicy(
  id: string,
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await requireWriter();
  if (session.error) {
    return { error: session.error };
  }

  const parsed = parsePolicyInput(formToObject(formData));
  if (!parsed.ok) {
    return { error: parsed.error };
  }

  const { data: before } = await session.supabase
    .from("policies")
    .select("body, status, version")
    .eq("id", id)
    .single<Pick<Policy, "body" | "status" | "version">>();
  if (before === null) {
    return { error: "Policy not found." };
  }

  const version = nextPolicyVersion(before, parsed.value);
  const { error } = await session.supabase
    .from("policies")
    .update({ ...parsed.value, version })
    .eq("id", id);
  if (error !== null) {
    return { error: error.message };
  }

  revalidatePath("/", "layout");
  return {
    ok:
      version === before.version
        ? "Saved."
        : `Saved as version ${String(version)}.`,
  };
}
