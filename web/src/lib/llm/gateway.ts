// Talking to the AI Control Layer gateway (`gateway/`, Rust). Pure: the HTTP call lives in
// `providers.ts`; this file only turns the gateway's answers into chat replies, so it's unit-testable.
//
// The gateway speaks the OpenAI chat API, so a request is a normal completion. What it adds:
// refusals (`{ error: { type, message }, trace_id }`) when a control blocks the prompt or the
// answer, and an `x_control_layer` block on success saying which controls fired. With
// `"mcp": true` the gateway also runs the model's MCP tool calls and lists them in
// `x_control_layer.tool_calls`.
import type { ToolCallSummary } from "@/lib/assistant";

interface ControlSummary {
  verdict?: string;
  controls_fired?: string[];
}

interface GatewayCompletion {
  choices?: { message?: { content?: string | null } }[];
  x_control_layer?: {
    trace_id?: string;
    prompt_in?: ControlSummary;
    response_out?: ControlSummary;
    tool_calls?: unknown;
  };
}

interface GatewayRefusal {
  error?: { type?: string; message?: string; stage?: string };
  trace_id?: string;
}

/**
 * `reply` is shown in the chat and stored like any answer — a block is a result the user
 * should see, not a failure. `error` means the gateway or its upstream misbehaved.
 */
export type GatewayOutcome =
  { ok: true; reply: string } | { ok: false; error: string; status?: number };

/** Refusal types the gateway emits on purpose; anything else is a transport problem. */
const POLICY_REFUSALS = new Set([
  "blocked_by_control",
  "model_not_allowed",
  "budget_exceeded",
]);

function shortTrace(traceId: string | undefined): string {
  return traceId === undefined ? "" : ` (trace ${traceId.slice(0, 8)})`;
}

function firedControls(summary: ControlSummary | undefined): string[] {
  return summary?.verdict === "redact" ? (summary.controls_fired ?? []) : [];
}

/** Interpret one gateway response. `body` is the parsed JSON, or null if it wasn't JSON. */
export function interpretGatewayResponse(
  status: number,
  body: unknown,
): GatewayOutcome {
  if (status >= 200 && status < 300) {
    const completion = (body ?? {}) as GatewayCompletion;
    const content = completion.choices?.[0]?.message?.content?.trim() ?? "";
    if (content === "") {
      return { ok: false, error: "The gateway returned an empty reply." };
    }
    const layer = completion.x_control_layer;
    const redacted = [
      ...new Set([
        ...firedControls(layer?.prompt_in),
        ...firedControls(layer?.response_out),
      ]),
    ];
    if (redacted.length === 0) {
      return { ok: true, reply: content };
    }
    return {
      ok: true,
      reply: `${content}\n\n— 🛡 AI Control Layer redacted content (${redacted.join(", ")})${shortTrace(layer?.trace_id)}.`,
    };
  }

  const refusal = (body ?? {}) as GatewayRefusal;
  const type = refusal.error?.type;
  if (type !== undefined && POLICY_REFUSALS.has(type)) {
    const reason = refusal.error?.message ?? type;
    if (refusal.error?.stage === "deterministic") {
      return {
        ok: true,
        reply: `🛡 This prompt doesn't meet the deterministic security requirements: ${reason}${shortTrace(refusal.trace_id)}. Remove the flagged content (secrets, personal data, injection patterns) and try again.`,
      };
    }
    return {
      ok: true,
      reply: `🛡 The AI Control Layer stopped this: ${reason}${shortTrace(refusal.trace_id)}. Rephrase without the flagged content, or ask the security team if you think this is a mistake.`,
    };
  }
  return {
    ok: false,
    status,
    error:
      type === "upstream_unavailable"
        ? "The gateway is up but its model is unreachable. Is Ollama running?"
        : `The gateway answered ${String(status)}. Try again or pick another model.`,
  };
}

// --- streamed answers (`stream: true`) ---------------------------------------------
// The gateway releases text only after its response_out controls saw it, then ends with
// a final chunk carrying `x_control_layer`, or the same `error` object a refusal has —
// which retracts what was shown. The ending, not the deltas, decides the stored reply.

export type GatewayStreamEvent =
  | { type: "delta"; text: string }
  | { type: "final"; layer: GatewayCompletion["x_control_layer"] }
  | { type: "refusal"; body: GatewayRefusal }
  | { type: "done" };

interface GatewayChunk {
  choices?: {
    delta?: { content?: string | null };
    finish_reason?: string | null;
  }[];
  x_control_layer?: GatewayCompletion["x_control_layer"];
  error?: GatewayRefusal["error"];
}

function chunkEvent(data: string): GatewayStreamEvent | null {
  if (data === "[DONE]") {
    return { type: "done" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(data);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) {
    return null;
  }
  const chunk = parsed as GatewayChunk;
  if (chunk.error !== undefined) {
    return { type: "refusal", body: chunk as GatewayRefusal };
  }
  if (chunk.x_control_layer !== undefined) {
    return { type: "final", layer: chunk.x_control_layer };
  }
  const text = chunk.choices?.[0]?.delta?.content ?? "";
  return text === "" ? null : { type: "delta", text };
}

/** Split buffered SSE text into events. `rest` is the unfinished last line; prepend it to the next chunk. */
export function decodeGatewaySse(buffer: string): {
  events: GatewayStreamEvent[];
  rest: string;
} {
  const lines = buffer.split("\n");
  const rest = lines.pop() ?? "";
  const events: GatewayStreamEvent[] = [];
  for (const line of lines) {
    const data = line.trim();
    if (!data.startsWith("data:")) {
      continue;
    }
    const event = chunkEvent(data.slice("data:".length).trim());
    if (event !== null) {
      events.push(event);
    }
  }
  return { events, rest };
}

/** The stored reply for a streamed answer: `text` is every delta, `ending` the last verdict event. */
export function finishGatewayStream(
  text: string,
  ending?: Extract<GatewayStreamEvent, { type: "final" | "refusal" }>,
): GatewayOutcome {
  if (ending === undefined) {
    return { ok: false, error: "The gateway's answer broke off. Try again." };
  }
  if (ending.type === "refusal") {
    return interpretGatewayResponse(403, ending.body);
  }
  return interpretGatewayResponse(200, {
    choices: [{ message: { content: text } }],
    x_control_layer: ending.layer,
  });
}

/** A `resources__query` acknowledgement's row count, if `content` is one. */
function ackRowCount(content: string): number | null {
  try {
    const ack = JSON.parse(content) as { row_count?: unknown };
    return typeof ack.row_count === "number" ? ack.row_count : null;
  } catch {
    return null;
  }
}

/** The MCP tool calls the gateway ran for this answer (`x_control_layer.tool_calls`). */
export function gatewayToolCalls(body: unknown): ToolCallSummary[] {
  const calls = (body as GatewayCompletion | null)?.x_control_layer?.tool_calls;
  if (!Array.isArray(calls)) {
    return [];
  }
  return calls.flatMap((raw: unknown) => {
    if (typeof raw !== "object" || raw === null) {
      return [];
    }
    const call = raw as Record<string, unknown>;
    if (typeof call.tool !== "string") {
      return [];
    }
    const content = typeof call.content === "string" ? call.content : "";
    const refused = call.status !== "ok";
    return [
      {
        tool: call.tool,
        status: refused ? "refused" : "ok",
        resultId: typeof call.result_id === "string" ? call.result_id : null,
        rowCount: refused ? null : ackRowCount(content),
        detail: refused ? content.replace(/^refused:\s*/, "") || null : null,
      },
    ];
  });
}
