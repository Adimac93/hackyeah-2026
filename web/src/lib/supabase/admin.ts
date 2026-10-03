import { createClient } from "@supabase/supabase-js";

import { supabaseEnv } from "./env";

/**
 * Service client that bypasses RLS — server actions only, and only after the caller's
 * own permissions were checked. Null when SUPABASE_SECRET_KEY isn't configured.
 */
export function createAdminClient() {
  const secret = process.env.SUPABASE_SECRET_KEY;
  if (secret === undefined || secret === "") {
    return null;
  }
  return createClient(supabaseEnv().url, secret, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
}
