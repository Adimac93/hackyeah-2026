// Server-only: talks to the gateway's admin API as the signed-in console user.
// The gateway verifies their Supabase access token and team role itself, so no
// shared secret is involved. Never import from a client component.
import { liveError } from "./gateway-live";
import type {
  GatewayHealth,
  GatewayInfo,
  Live,
  LivePolicy,
  MetricsReport,
} from "./gateway-live";
import { createClient } from "./supabase/server";

const TIMEOUT_MS = 8000;

export function gatewayBase(): string | null {
  const base = (process.env.GATEWAY_URL ?? "").trim().replace(/\/+$/, "");
  return base === "" ? null : base;
}

async function accessToken(): Promise<string | null> {
  const supabase = await createClient();
  const { data } = await supabase.auth.getSession();
  return data.session?.access_token ?? null;
}

/** Call the gateway; `auth` sends the user's access token, `body` makes it a POST. */
export async function gatewayFetch<T>(
  path: string,
  { auth = true, body }: { auth?: boolean; body?: unknown } = {},
): Promise<Live<T>> {
  const base = gatewayBase();
  if (base === null) {
    return { ok: false, error: "GATEWAY_URL is not configured." };
  }
  const token = auth ? await accessToken() : null;
  if (auth && token === null) {
    return { ok: false, error: "Your session has expired. Sign in again." };
  }
  let response: Response;
  try {
    response = await fetch(`${base}${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        Accept: "application/json",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(token === null ? {} : { Authorization: `Bearer ${token}` }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    console.error(
      "[gateway] fetch failed",
      path,
      error instanceof Error ? error.name : "unknown",
    );
    return { ok: false, error: "The gateway is unreachable." };
  }
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    return {
      ok: false,
      error: gatewayMessage(payload) ?? liveError(response.status),
    };
  }
  if (payload === null) {
    return { ok: false, error: "The gateway sent a response that isn't JSON." };
  }
  return { ok: true, data: payload as T };
}

/** The gateway's own refusal message (`{ error: { message } }`), if it sent one. */
function gatewayMessage(payload: unknown): string | null {
  const message = (payload as { error?: { message?: unknown } } | null)?.error
    ?.message;
  return typeof message === "string" ? message : null;
}

/** Everything the Gateway page shows, fetched in parallel. */
export async function gatewayLive() {
  const [info, health, policy, metrics] = await Promise.all([
    gatewayFetch<GatewayInfo>("/", { auth: false }),
    gatewayFetch<GatewayHealth>("/health", { auth: false }),
    gatewayFetch<LivePolicy>("/policy"),
    gatewayFetch<MetricsReport>("/metrics"),
  ]);
  return { base: gatewayBase(), info, health, policy, metrics };
}
