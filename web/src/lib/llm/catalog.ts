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
