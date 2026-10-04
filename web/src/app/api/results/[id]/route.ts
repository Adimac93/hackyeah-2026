import { requireChatUser } from "@/lib/auth";
import { gatewayRequest } from "@/lib/gateway-http";

const UUID = /^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i;

/**
 * Rows of a `resources__query` the assistant ran, for the user it ran them for. The gateway
 * keeps them for an hour and hands them only to the identity that asked, acting for the same
 * user — so this route asks as the console's chat identity on behalf of the signed-in user,
 * exactly as the chat did. The model never sees these rows.
 */
export async function GET(
  _request: Request,
  { params }: RouteContext<"/api/results/[id]">,
) {
  const { id } = await params;
  const session = await requireChatUser();
  if (session.error) {
    return Response.json({ error: session.error }, { status: 401 });
  }
  if (!UUID.test(id)) {
    return Response.json({ error: "No such result." }, { status: 404 });
  }

  const base = (process.env.GATEWAY_URL ?? "").replace(/\/+$/, "");
  let upstream: Response;
  try {
    upstream = await gatewayRequest(`${base}/v1/results/${id}`, {
      headers: {
        accept: "application/json",
        authorization: `Bearer ${(process.env.GATEWAY_API_KEY ?? "").trim()}`,
        // the same user the chat named, so only their own results come back
        "x-on-behalf-of": session.user.email ?? session.user.id,
      },
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return Response.json(
      { error: "The gateway is unreachable." },
      { status: 502 },
    );
  }
  if (upstream.status === 404) {
    await upstream.body?.cancel();
    return Response.json(
      { error: "These results expired or aren't yours." },
      { status: 404 },
    );
  }
  if (!upstream.ok) {
    await upstream.body?.cancel();
    return Response.json(
      { error: `The gateway answered ${String(upstream.status)}.` },
      { status: 502 },
    );
  }
  return new Response(upstream.body, {
    headers: {
      "content-type": "application/json",
      "cache-control": "private, no-store",
    },
  });
}
