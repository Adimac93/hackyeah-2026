"use server";

import { revalidatePath } from "next/cache";

import { getSession } from "@/lib/auth";
import type { FormState } from "@/lib/domain";
import { checkPolicyUpload, describePolicySave } from "@/lib/gateway";
import type { PolicySaveResult } from "@/lib/gateway";
import { gatewayFetch } from "@/lib/gateway-live-fetch";

/** Validating and storing a whole catalog takes longer than a live read. */
const UPLOAD_TIMEOUT_MS = 15_000;

/**
 * Save the edited control catalog (TOML) through `POST /admin/policy`, as the
 * signed-in admin. The gateway validates it, stores it as a new policy version
 * and hot-swaps it; an invalid catalog is rejected and the active one keeps running.
 */
export async function savePolicy(
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await getSession();
  if (session.user === null || session.member?.role !== "admin") {
    return { error: "Only admins can change the gateway policy." };
  }

  const text = formData.get("catalog");
  const checked = checkPolicyUpload(typeof text === "string" ? text : "");
  if (!checked.ok) {
    return { error: checked.error };
  }

  const saved = await gatewayFetch<PolicySaveResult>("/admin/policy", {
    body: { catalog_toml: checked.value },
    timeoutMs: UPLOAD_TIMEOUT_MS,
  });
  if (!saved.ok) {
    return { error: `${saved.error} The active policy is unchanged.` };
  }
  revalidatePath("/controls");
  return { ok: describePolicySave(saved.data) };
}
