// Server-only: talks to the gateway's admin API. Never import from a client component.
import { createClient } from "@/lib/supabase/server";

/** The gateway's base URL, or null when GATEWAY_URL is unset. */
export function gatewayUrl(): string | null {
  const base = (process.env.GATEWAY_URL ?? "").trim().replace(/\/+$/, "");
  return base === "" ? null : base;
}

/**
 * As the `secops-console` principal (GATEWAY_ADMIN_KEY): the approvals routes, which
 * take a security_admin principal's API key.
 */
export function gatewayAdmin(): { base: string; key: string } | null {
  const base = gatewayUrl();
  const key = (process.env.GATEWAY_ADMIN_KEY ?? "").trim();
  if (base === null || key === "") {
    return null;
  }
  return { base, key };
}

/**
 * As the signed-in console user: `/policy`, `/metrics` and `/admin/*` (except approvals)
 * take their Supabase access token, and the gateway checks their team role itself.
 */
export async function gatewayAsUser(): Promise<
  { base: string; token: string } | { error: string }
> {
  const base = gatewayUrl();
  if (base === null) {
    return { error: "GATEWAY_URL not configured." };
  }
  const supabase = await createClient();
  const {
    data: { session },
  } = await supabase.auth.getSession();
  if (session === null) {
    return { error: "You are not signed in." };
  }
  return { base, token: session.access_token };
}
