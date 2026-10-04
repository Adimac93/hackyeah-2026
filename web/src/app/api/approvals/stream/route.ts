import { request as httpRequest } from "node:http";
import type { IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { Readable } from "node:stream";

import { getSession } from "@/lib/auth";
import { canAccessConsole } from "@/lib/domain";
import { gatewayAdmin } from "@/lib/gateway-admin";

/**
 * Open the gateway's SSE feed on its own socket. Not `fetch`: while one fetch response to
 * an origin stays open, Node's fetch stalls every other request to that origin, so an open
 * console tab would hang the assistant's gateway calls until they time out.
 */
async function openFeed(
  url: string,
  key: string,
  signal: AbortSignal,
): Promise<IncomingMessage> {
  const send = url.startsWith("https:") ? httpsRequest : httpRequest;
  return new Promise((resolve, reject) => {
    const outgoing = send(url, {
      headers: { authorization: `Bearer ${key}`, accept: "text/event-stream" },
      signal,
    });
    outgoing.on("response", resolve);
    outgoing.on("error", reject);
    outgoing.end();
  });
}

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

  let upstream: IncomingMessage;
  try {
    upstream = await openFeed(
      `${gateway.base}/admin/approvals/stream`,
      gateway.key,
      request.signal,
    );
  } catch {
    return new Response("gateway unreachable", { status: 502 });
  }
  if (upstream.statusCode !== 200) {
    upstream.resume();
    return new Response(
      `gateway refused the stream (${String(upstream.statusCode)})`,
      {
        status: 502,
      },
    );
  }

  return new Response(Readable.toWeb(upstream) as ReadableStream<Uint8Array>, {
    headers: {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      "x-accel-buffering": "no",
    },
  });
}
