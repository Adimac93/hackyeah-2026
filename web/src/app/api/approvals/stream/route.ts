import { getSession } from "@/lib/auth";
import { canAccessConsole } from "@/lib/domain";
import { gatewayAdmin } from "@/lib/gateway-admin";

// Relays the gateway's access-request feed to a signed-in security team member.
// The admin key stays on the server; the browser only ever sees this route.
export async function GET(request: Request) {
  const { member } = await getSession();
  if (member === null || !canAccessConsole(member.role)) {
    return new Response("forbidden", { status: 403 });
  }
  const gateway = gatewayAdmin();
  if (gateway === null) {
    return new Response("GATEWAY_URL / GATEWAY_ADMIN_KEY not configured", {
      status: 503,
    });
  }

  let upstream: Response;
  try {
    upstream = await fetch(`${gateway.base}/admin/approvals/stream`, {
      headers: {
        authorization: `Bearer ${gateway.key}`,
        accept: "text/event-stream",
      },
      signal: request.signal,
      cache: "no-store",
    });
  } catch {
    return new Response("gateway unreachable", { status: 502 });
  }
  if (!upstream.ok || upstream.body === null) {
    return new Response(
      `gateway refused the stream (${String(upstream.status)})`,
      {
        status: 502,
      },
    );
  }

  return new Response(upstream.body, {
    headers: {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      "x-accel-buffering": "no",
    },
  });
}
