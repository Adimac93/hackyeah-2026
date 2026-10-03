// Server-only: fetches live state from the gateway. Never import from a client
// component — the admin key must not reach the browser.
import { gatewayAdmin } from "./gateway-admin";
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
  const gateway = gatewayAdmin();
  if (gateway === null) {
    return {
      ok: false,
      error: "GATEWAY_URL / GATEWAY_ADMIN_KEY not configured.",
    };
  }
  let response: Response;
  try {
    response = await fetch(`${gateway.base}${path}`, {
      headers: {
        Accept: "application/json",
        ...(auth ? { Authorization: `Bearer ${gateway.key}` } : {}),
      },
      cache: "no-store",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    console.error("[gateway] live fetch failed", path, error);
    return { ok: false, error: "The gateway is unreachable." };
  }
  if (!response.ok) {
    return { ok: false, error: liveError(response.status) };
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
  return { base: gatewayAdmin()?.base ?? null, info, health, policy, metrics };
}
