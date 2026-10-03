import { createAdminClient } from "@/lib/supabase/admin";

import type { ConnectionKind } from "./presets";

export interface ConnectionSecret {
  kind: ConnectionKind;
  baseUrl: string | null;
  /** decrypted from Vault; null when the connection has no key (e.g. Ollama) */
  apiKey: string | null;
  enabled: boolean;
}

/**
 * A console connection with its decrypted key — server only. Keys live in Supabase Vault and
 * `llm_provider_key()` is executable by the service role alone.
 * "no-service-key" when SUPABASE_SECRET_KEY isn't set; null when the connection doesn't exist.
 */
export async function loadConnectionSecret(
  connectionId: string,
): Promise<ConnectionSecret | "no-service-key" | null> {
  const admin = createAdminClient();
  if (admin === null) {
    return "no-service-key";
  }
  const [{ data: row }, { data: key, error: keyError }] = await Promise.all([
    admin
      .from("llm_providers")
      .select("kind, base_url, enabled")
      .eq("id", connectionId)
      .maybeSingle<{
        kind: ConnectionKind;
        base_url: string | null;
        enabled: boolean;
      }>(),
    admin
      .rpc("llm_provider_key", { provider_id: connectionId })
      .overrideTypes<string | null, { merge: false }>(),
  ]);
  if (row === null) {
    return null;
  }
  if (keyError !== null) {
    // never log the key or the response body, just that decryption failed
    console.error("[llm] key decryption failed", keyError.code);
  }
  return {
    kind: row.kind,
    baseUrl: row.base_url,
    apiKey: typeof key === "string" ? key : null,
    enabled: row.enabled,
  };
}
