// Server-only: talks to the gateway as the signed-in console user. Never import
// from a client component — the user's access token must not be logged or echoed.
import { gatewayAsUser, gatewayUrl } from "./gateway-admin";
import { gatewayRequest } from "./gateway-http";
import { liveError } from "./gateway-live";
import type {
  GatewayHealth,
  GatewayInfo,
  Live,
  LivePolicy,
  MetricsReport,
} from "./gateway-live";

const TIMEOUT_MS = 8000;

/** Call the gateway; `auth` sends the user's access token, `body` makes it a POST. */
export async function gatewayFetch<T>(
  path: string,
  {
    auth = true,
    body,
    timeoutMs = TIMEOUT_MS,
  }: { auth?: boolean; body?: unknown; timeoutMs?: number } = {},
): Promise<Live<T>> {
  let base: string;
  let token: string | null = null;
  if (auth) {
    const gateway = await gatewayAsUser();
    if ("error" in gateway) {
      return { ok: false, error: gateway.error };
    }
    ({ base, token } = gateway);
  } else {
    const url = gatewayUrl();
    if (url === null) {
      return { ok: false, error: "GATEWAY_URL not configured." };
    }
    base = url;
  }
  let response: Response;
  try {
    response = await gatewayRequest(`${base}${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        Accept: "application/json",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(token === null ? {} : { Authorization: `Bearer ${token}` }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
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
    return { ok: false, error: liveError(response.status, payload) };
  }
  if (payload === null) {
    return { ok: false, error: "The gateway sent a response that isn't JSON." };
  }
  return { ok: true, data: payload as T };
}

/** Everything the Gateway page shows, fetched in parallel. */
export async function gatewayLive() {
  const [info, health, policy, metrics] = await Promise.all([
    gatewayFetch<GatewayInfo>("/", { auth: false }),
    gatewayFetch<GatewayHealth>("/health", { auth: false }),
    gatewayFetch<LivePolicy>("/policy"),
    gatewayFetch<MetricsReport>("/metrics"),
  ]);
  return { base: gatewayUrl(), info, health, policy, metrics };
}
