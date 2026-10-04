// Server-only: HTTP to the gateway over node:http(s) instead of `fetch`. Never import from a
// client component.
//
// Node's fetch stalls every request to the gateway's HTTPS origin while one response from it
// stays open. A streamed chat reply or the approvals feed would then freeze every other
// console→gateway call (other users' chats included) until it ends. Here each request gets its
// own connection, so a long response holds up nothing else.
import { request as httpRequest } from "node:http";
import type { IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { Readable } from "node:stream";

export interface GatewayRequestInit {
  method?: "GET" | "POST";
  headers?: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
}

function responseHeaders(incoming: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming.headers)) {
    if (value !== undefined) {
      headers.set(name, Array.isArray(value) ? value.join(", ") : value);
    }
  }
  return headers;
}

/**
 * `fetch` for the gateway: resolves once the response headers arrive, and the body streams.
 * Redirects are not followed (the gateway sends none). An abort rejects like `fetch` does,
 * and also ends a body that is still streaming.
 */
export async function gatewayRequest(
  url: string,
  init: GatewayRequestInit = {},
): Promise<Response> {
  const send = url.startsWith("https:") ? httpsRequest : httpRequest;
  const incoming = await new Promise<IncomingMessage>((resolve, reject) => {
    const outgoing = send(url, {
      method: init.method ?? "GET",
      headers: init.headers,
      signal: init.signal,
    });
    outgoing.on("response", resolve);
    outgoing.on("error", reject);
    outgoing.end(init.body);
  });
  const status = incoming.statusCode ?? 502;
  const empty = status === 204 || status === 304;
  if (empty) {
    incoming.resume();
  }
  return new Response(
    empty ? null : (Readable.toWeb(incoming) as ReadableStream<Uint8Array>),
    { status, headers: responseHeaders(incoming) },
  );
}
