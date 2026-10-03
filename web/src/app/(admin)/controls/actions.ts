"use server";

import { revalidatePath } from "next/cache";

import { getSession } from "@/lib/auth";
import type { FormState } from "@/lib/domain";
import { checkPolicyUpload, describePolicyUpload } from "@/lib/gateway";
import { gatewayAsUser } from "@/lib/gateway-admin";

const UPLOAD_TIMEOUT_MS = 15_000;

/**
 * Import a control catalog (TOML) into the running gateway via `POST /admin/policy`.
 * The gateway validates it, stores it as a new policy version and hot-swaps it; an invalid
 * catalog is rejected and the active policy keeps running.
 */
export async function importPolicy(
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await getSession();
  if (session.user === null || session.member?.role !== "admin") {
    return { error: "Only admins can import gateway policies." };
  }

  const gateway = await gatewayAsUser();
  if ("error" in gateway) {
    return { error: gateway.error };
  }

  // a chosen file wins over pasted text
  const file = formData.get("file");
  const pasted = formData.get("catalog");
  let text = "";
  if (file instanceof File && file.size > 0) {
    if (!file.name.toLowerCase().endsWith(".toml")) {
      return { error: "Choose a .toml file." };
    }
    text = await file.text();
  } else if (typeof pasted === "string") {
    text = pasted;
  }
  const checked = checkPolicyUpload(text);
  if (!checked.ok) {
    return { error: checked.error };
  }

  let response: Response;
  try {
    response = await fetch(`${gateway.base}/admin/policy`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${gateway.token}`,
      },
      body: JSON.stringify({ catalog_toml: checked.value }),
      signal: AbortSignal.timeout(UPLOAD_TIMEOUT_MS),
      redirect: "error",
    });
  } catch (error) {
    console.error(
      "[policy] gateway unreachable",
      error instanceof Error ? error.name : "unknown",
    );
    return {
      error:
        "The gateway is unreachable. Is it running? The active policy is unchanged.",
    };
  }

  const body: unknown = await response.json().catch(() => null);
  const outcome = describePolicyUpload(response.status, body);
  if (!outcome.ok) {
    return { error: outcome.error };
  }
  revalidatePath("/controls");
  return { ok: outcome.message };
}
