"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { getSession } from "@/lib/auth";
import { formString } from "@/lib/domain";
import type { FormState } from "@/lib/domain";
import { loadModels } from "@/lib/llm/catalog";
import { listProviderModels } from "@/lib/llm/discover";
import type { ModelList } from "@/lib/llm/discover";
import { findModel } from "@/lib/llm/models";
import {
  PRESETS,
  isPresetId,
  parseProviderInput,
  validateBaseUrl,
} from "@/lib/llm/presets";
import { loadConnectionSecret } from "@/lib/llm/secrets";

/** Where a new connection's form may send the admin back to. Anything else is /models. */
const RETURN_PATHS = new Set(["/models", "/chat"]);

async function requireAdmin() {
  const session = await getSession();
  if (session.user === null || session.member?.role !== "admin") {
    return { error: "Only admins can manage model connections." } as const;
  }
  return { ...session, user: session.user, error: null } as const;
}

function fieldsOf(formData: FormData): Record<string, string | undefined> {
  const fields: Record<string, string | undefined> = {};
  for (const key of [
    "preset",
    "name",
    "base_url",
    "api_key",
    "models",
    "enabled",
  ]) {
    const value = formData.get(key);
    fields[key] = typeof value === "string" ? value : undefined;
  }
  return fields;
}

type Supabase = Awaited<ReturnType<typeof getSession>>["supabase"];

/** Encrypt the key into Vault; the table only gets a reference, last-4 hint and fingerprint. */
async function storeKey(
  supabase: Supabase,
  id: string,
  key: string,
): Promise<string | null> {
  const { error } = await supabase.rpc("set_llm_provider_key", {
    provider_id: id,
    new_key: key,
  });
  return error === null
    ? null
    : `Couldn't store the API key (${error.message}).`;
}

function refresh() {
  revalidatePath("/models");
  revalidatePath("/chat");
}

export async function createConnection(
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await requireAdmin();
  if (session.error) {
    return { error: session.error };
  }
  const parsed = parseProviderInput(fieldsOf(formData), true);
  if (!parsed.ok) {
    return { error: parsed.error };
  }
  const input = parsed.value;

  const { data, error } = await session.supabase
    .from("llm_providers")
    .insert({
      name: input.name,
      preset: input.preset,
      kind: input.kind,
      base_url: input.baseUrl,
      models: input.models,
      enabled: input.enabled,
      created_by: session.user.id,
    })
    .select("id")
    .single<{ id: string }>();
  if (error !== null) {
    return { error: error.message };
  }
  if (input.apiKey !== null) {
    const keyError = await storeKey(session.supabase, data.id, input.apiKey);
    if (keyError !== null) {
      // don't leave a connection behind that silently has no key
      await session.supabase.from("llm_providers").delete().eq("id", data.id);
      return { error: keyError };
    }
  }
  refresh();
  const returnTo = formString(formData, "return_to");
  redirect(RETURN_PATHS.has(returnTo) ? returnTo : "/models");
}

export async function updateConnection(
  id: string,
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await requireAdmin();
  if (session.error) {
    return { error: session.error };
  }
  const parsed = parseProviderInput(fieldsOf(formData), false);
  if (!parsed.ok) {
    return { error: parsed.error };
  }
  const input = parsed.value;

  const { error } = await session.supabase
    .from("llm_providers")
    .update({
      name: input.name,
      preset: input.preset,
      kind: input.kind,
      base_url: input.baseUrl,
      models: input.models,
      enabled: input.enabled,
    })
    .eq("id", id);
  if (error !== null) {
    return { error: error.message };
  }
  // blank key field = keep the stored one
  if (input.apiKey !== null) {
    const keyError = await storeKey(session.supabase, id, input.apiKey);
    if (keyError !== null) {
      return { error: keyError };
    }
  }
  refresh();
  redirect("/models");
}

export async function setConnectionEnabled(
  id: string,
  enabled: boolean,
): Promise<void> {
  const session = await requireAdmin();
  if (session.error) {
    return;
  }
  await session.supabase.from("llm_providers").update({ enabled }).eq("id", id);
  refresh();
}

export async function deleteConnection(id: string): Promise<void> {
  const session = await requireAdmin();
  if (session.error) {
    return;
  }
  await session.supabase.from("llm_providers").delete().eq("id", id);
  refresh();
}

/** Cheap credential check: list the provider's models (no tokens spent). */
export async function testConnection(
  id: string,
  _previous: FormState,
  _formData: FormData,
): Promise<FormState> {
  const session = await requireAdmin();
  if (session.error) {
    return { error: session.error };
  }
  const connection = await loadConnectionSecret(id);
  if (connection === "no-service-key") {
    return { error: "Testing needs SUPABASE_SECRET_KEY on the server." };
  }
  if (connection === null) {
    return { error: "Connection not found." };
  }
  const result = await listProviderModels(connection);
  if (!result.ok) {
    return { error: result.error };
  }
  return {
    ok:
      result.models.length === 0
        ? "Connected"
        : `Connected · ${String(result.models.length)} models visible`,
  };
}

/**
 * The model ids an endpoint serves, for the form's "Fetch models". Uses the typed key, or
 * the stored one when editing a connection and the key field is blank.
 */
export async function discoverModels(input: {
  preset: string;
  baseUrl: string;
  apiKey: string;
  connectionId?: string;
}): Promise<ModelList> {
  const session = await requireAdmin();
  if (session.error) {
    return { ok: false, error: session.error };
  }
  if (!isPresetId(input.preset)) {
    return { ok: false, error: "Pick a provider." };
  }
  const preset = PRESETS[input.preset];

  let baseUrl: string | null = null;
  if (preset.kind !== "anthropic") {
    const candidate = input.baseUrl.trim() || preset.baseUrl;
    if (candidate === null) {
      return { ok: false, error: "Enter the base URL first." };
    }
    const checked = validateBaseUrl(candidate);
    if (!checked.ok) {
      return checked;
    }
    baseUrl = checked.value;
  }

  let apiKey: string | null = input.apiKey.trim() || null;
  if (apiKey === null && input.connectionId !== undefined) {
    const stored = await loadConnectionSecret(input.connectionId);
    if (stored !== null && stored !== "no-service-key") {
      apiKey = stored.apiKey;
    }
  }
  if (apiKey === null && preset.requiresKey) {
    return { ok: false, error: "Enter the API key first." };
  }

  const result = await listProviderModels({
    kind: preset.kind,
    baseUrl,
    apiKey,
  });
  if (result.ok && result.models.length === 0) {
    return { ok: false, error: "The provider didn't list any models." };
  }
  return result;
}

/** Set the model new chats start on. Must be one of the currently available models. */
export async function setDefaultModel(
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await requireAdmin();
  if (session.error) {
    return { error: session.error };
  }
  const model = findModel(
    formString(formData, "default_model"),
    await loadModels(session.supabase),
  );
  if (model === null) {
    return { error: "Pick one of the available models." };
  }
  const { error } = await session.supabase
    .from("chat_settings")
    .upsert({ id: true, default_model: model.id, updated_by: session.user.id });
  if (error !== null) {
    return { error: `Couldn't save the default (${error.message}).` };
  }
  refresh();
  return { ok: `New chats now start on ${model.label}.` };
}
