import type { createClient } from "@/lib/supabase/server";

import { availableModels } from "./models";
import type { LlmConnection, ModelOption } from "./models";

type Supabase = Awaited<ReturnType<typeof createClient>>;

/** Env-configured models plus the console-managed connections the caller may see. */
export async function loadModels(supabase: Supabase): Promise<ModelOption[]> {
  const { data } = await supabase
    .from("llm_providers")
    .select("id, name, preset, kind, base_url, models, enabled")
    .eq("enabled", true)
    .order("created_at");
  return availableModels(process.env, (data ?? []) as LlmConnection[]);
}

/** The organisation's default chat model id (Models page), or null when unset. */
export async function loadDefaultModelId(
  supabase: Supabase,
): Promise<string | null> {
  const { data } = await supabase
    .from("chat_settings")
    .select("default_model")
    .maybeSingle<{ default_model: string | null }>();
  return data?.default_model ?? null;
}
