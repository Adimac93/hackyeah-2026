// Server-only: fetches live state from the gateway. Never import from a client
// component — the user's access token must not be logged or echoed.
import { gatewayAsUser, gatewayUrl } from "./gateway-admin";
import { liveError } from "./gateway-live";
import type {
  GatewayHealth,
  GatewayInfo,
  Live,
  LivePolicy,
  MetricsReport,
} from "./gateway-live";

const TIMEOUT_MS = 8000;

async function get<T>(path: string, auth: boolean): Promise<Live<T>> {
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
    response = await fetch(`${base}${path}`, {
      headers: {
        Accept: "application/json",
        ...(token === null ? {} : { Authorization: `Bearer ${token}` }),
      },
      cache: "no-store",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    console.error("[gateway] live fetch failed", path, error);
    return { ok: false, error: "The gateway is unreachable." };
  }
  if (!response.ok) {
    const body: unknown = await response.json().catch(() => null);
    return { ok: false, error: liveError(response.status, body) };
  }
  try {
    return { ok: true, data: (await response.json()) as T };
  } catch {
    return { ok: false, error: "The gateway sent a response that isn't JSON." };
  }
}

/** Everything the Gateway page shows, fetched in parallel. */
export async function gatewayLive() {
  const [info, health, policy, metrics] = await Promise.all([
    get<GatewayInfo>("/", false),
    get<GatewayHealth>("/health", false),
    get<LivePolicy>("/policy", true),
    get<MetricsReport>("/metrics", true),
  ]);
  return { base: gatewayUrl(), info, health, policy, metrics };
}
