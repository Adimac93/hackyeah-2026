"use server";

import { revalidatePath } from "next/cache";

import { getSession } from "@/lib/auth";
import { addControl, editControl } from "@/lib/catalog";
import type { ControlFields } from "@/lib/catalog";
import type { FormState } from "@/lib/domain";
import { checkPolicyUpload, describePolicySave } from "@/lib/gateway";
import type { PolicySaveResult } from "@/lib/gateway";
import { gatewayFetch } from "@/lib/gateway-live-fetch";

/** Validating and storing a whole catalog takes longer than a live read. */
const UPLOAD_TIMEOUT_MS = 15_000;

/**
 * Replace the control catalog with an uploaded TOML file through
 * `POST /admin/policy`, as the signed-in admin. Every rule is replaced. The
 * gateway validates it, stores it as a new policy version and hot-swaps it; an
 * invalid catalog is rejected and the active one keeps running. `base_sha` (the
 * version the upload was compared against) guards against replacing a version
 * someone saved in the meantime.
 */
export async function savePolicy(
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await getSession();
  if (session.user === null || session.member?.role !== "admin") {
    return { error: "Only admins can change the gateway policy." };
  }

  const baseSha = formData.get("base_sha");
  if (typeof baseSha === "string" && baseSha !== "") {
    const { data: active } = await session.supabase
      .from("policy_versions")
      .select("sha256")
      .eq("active", true)
      .maybeSingle<{ sha256: string }>();
    if (active !== null && active.sha256 !== baseSha) {
      return {
        error:
          "The catalog changed since this page loaded. Reload and upload again to compare against the current version.",
      };
    }
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

/** The active catalog, if an admin may change it and nobody saved since `baseSha`. */
async function editableCatalog(
  baseSha: string,
): Promise<{ toml: string } | { error: string }> {
  const session = await getSession();
  if (session.user === null || session.member?.role !== "admin") {
    return { error: "Only admins can change the gateway policy." };
  }
  const { data: active } = await session.supabase
    .from("policy_versions")
    .select("sha256, catalog_toml")
    .eq("active", true)
    .maybeSingle<{ sha256: string; catalog_toml: string | null }>();
  if (active === null || typeof active.catalog_toml !== "string") {
    return { error: "There is no stored catalog to edit." };
  }
  if (active.sha256 !== baseSha) {
    return {
      error:
        "The catalog changed since this page loaded. Reload to edit the current version.",
    };
  }
  return { toml: active.catalog_toml };
}

/** A control's settings as the editor and the add form post them. */
function fieldsFromForm(formData: FormData): ControlFields {
  const kind =
    formData.get("kind") === "semantic" ? "semantic" : "deterministic";
  const text = (key: string) => {
    const value = formData.get(key);
    return typeof value === "string" ? value : "";
  };
  return {
    kind,
    enabled: formData.get("enabled") === "on",
    severity: text("severity"),
    action: text("action"),
    hooks: formData.getAll("hooks").filter((h) => typeof h === "string"),
    ...(kind === "deterministic"
      ? { pattern: text("pattern") }
      : {
          threshold: Number.parseFloat(text("threshold")),
          escalateWhen: text("escalate_when"),
        }),
  };
}

/** Upload the whole edited catalog; the gateway validates and activates it. */
async function activateCatalog(toml: string): Promise<FormState> {
  const checked = checkPolicyUpload(toml);
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

/**
 * Edit one control from the Controls table: rewrite just its lines in the
 * active catalog, then save the whole file like the editor does. `baseSha` is
 * the version the form was opened on; a newer version wins, so concurrent
 * edits are never silently overwritten.
 */
export async function saveControl(
  baseSha: string,
  id: string,
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const catalog = await editableCatalog(baseSha);
  if ("error" in catalog) {
    return { error: catalog.error };
  }
  const edited = editControl(catalog.toml, id, fieldsFromForm(formData));
  if (!edited.ok) {
    return { error: edited.error };
  }
  return activateCatalog(edited.value);
}

/**
 * Add a control to the active catalog after the last one of its kind, then
 * save the whole file. Same version guard as editing.
 */
export async function createControl(
  baseSha: string,
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const catalog = await editableCatalog(baseSha);
  if ("error" in catalog) {
    return { error: catalog.error };
  }
  const text = (key: string) => {
    const value = formData.get(key);
    return typeof value === "string" ? value.trim() : "";
  };
  const added = addControl(catalog.toml, {
    ...fieldsFromForm(formData),
    id: text("id"),
    detector: text("detector"),
    describes: text("describes"),
  });
  if (!added.ok) {
    return { error: added.error };
  }
  return activateCatalog(added.value);
}
