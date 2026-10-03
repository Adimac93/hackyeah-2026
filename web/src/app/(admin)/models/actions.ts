"use server";

import Anthropic from "@anthropic-ai/sdk";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { getSession } from "@/lib/auth";
import type { FormState } from "@/lib/domain";
import { keyHint, parseProviderInput } from "@/lib/llm/presets";
import { createAdminClient } from "@/lib/supabase/admin";

const TEST_TIMEOUT_MS = 10_000;

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

  const { error } = await session.supabase.from("llm_providers").insert({
    name: input.name,
    preset: input.preset,
    kind: input.kind,
    base_url: input.baseUrl,
    api_key: input.apiKey,
    api_key_hint: input.apiKey === null ? null : keyHint(input.apiKey),
    models: input.models,
    enabled: input.enabled,
    created_by: session.user.id,
  });
  if (error !== null) {
    return { error: error.message };
  }
  refresh();
  redirect("/models");
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
      // blank key field = keep the stored one
      ...(input.apiKey === null
        ? {}
        : { api_key: input.apiKey, api_key_hint: keyHint(input.apiKey) }),
    })
    .eq("id", id);
  if (error !== null) {
    return { error: error.message };
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
  const admin = createAdminClient();
  if (admin === null) {
    return { error: "Testing needs SUPABASE_SECRET_KEY on the server." };
  }
  const { data } = await admin
    .from("llm_providers")
    .select("kind, base_url, api_key")
    .eq("id", id)
    .maybeSingle<{
      kind: string;
      base_url: string | null;
      api_key: string | null;
    }>();
  if (data === null) {
    return { error: "Connection not found." };
  }

  try {
    if (data.kind === "anthropic") {
      const client = new Anthropic({
        apiKey: data.api_key ?? undefined,
        timeout: TEST_TIMEOUT_MS,
        maxRetries: 0,
      });
      const page = await client.models.list({ limit: 100 });
      return { ok: `Connected · ${String(page.data.length)} models visible` };
    }

    const base = (data.base_url ?? "https://api.openai.com/v1").replace(
      /\/+$/,
      "",
    );
    const response = await fetch(`${base}/models`, {
      headers:
        data.api_key === null
          ? {}
          : { authorization: `Bearer ${data.api_key}` },
      signal: AbortSignal.timeout(TEST_TIMEOUT_MS),
      redirect: "error",
    });
    if (response.status === 401 || response.status === 403) {
      return { error: "The provider rejected the API key." };
    }
    if (!response.ok) {
      return {
        error: `The provider answered HTTP ${String(response.status)}.`,
      };
    }
    const body = (await response.json().catch(() => null)) as {
      data?: unknown[];
    } | null;
    const count = Array.isArray(body?.data) ? body.data.length : null;
    return {
      ok:
        count === null
          ? "Connected"
          : `Connected · ${String(count)} models visible`,
    };
  } catch (error) {
    if (error instanceof Anthropic.APIError) {
      return {
        error:
          error.status === 401
            ? "The provider rejected the API key."
            : `The provider answered HTTP ${String(error.status)}.`,
      };
    }
    // network errors: don't echo internals, just the kind
    return {
      error: `Couldn't reach the provider (${error instanceof Error ? error.name : "unknown error"}).`,
    };
  }
}
