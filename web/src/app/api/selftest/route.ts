import { getSession } from "@/lib/auth";
import { canAccessConsole } from "@/lib/domain";
import { gatewayAsUser } from "@/lib/gateway-admin";
import { gatewayRequest } from "@/lib/gateway-http";

// Starts the gateway's full-system self-test as the signed-in user and relays its log as it
// is written. The gateway checks the admin role itself. Through `gatewayRequest`, not fetch:
// the log stays open for the whole run.
export async function POST(request: Request) {
  const { member } = await getSession();
  if (member === null || !canAccessConsole(member.role)) {
    return new Response("forbidden", { status: 403 });
  }
  const gateway = await gatewayAsUser();
  if ("error" in gateway) {
    return new Response(gateway.error, { status: 503 });
  }

  let upstream: Response;
  try {
    upstream = await gatewayRequest(`${gateway.base}/admin/selftest`, {
      method: "POST",
      headers: { authorization: `Bearer ${gateway.token}` },
      signal: request.signal,
    });
  } catch {
    return new Response("gateway unreachable", { status: 502 });
  }
  if (upstream.status !== 200 || upstream.body === null) {
    const detail = await upstream.text().catch(() => "");
    return new Response(
      `gateway refused the self-test (${String(upstream.status)}) ${detail}`,
      { status: 502 },
    );
  }

  return new Response(upstream.body, {
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      "x-accel-buffering": "no",
    },
  });
}
