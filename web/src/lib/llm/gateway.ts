// Talking to the AI Control Layer gateway (`gateway/`, Rust). Pure: the HTTP call lives in
// `providers.ts`; this file only turns the gateway's answers into chat replies, so it's unit-testable.
//
// The gateway speaks the OpenAI chat API, so a request is a normal completion. What it adds:
// refusals (`{ error: { type, message }, trace_id }`) when a control blocks the prompt or the
// answer, and an `x_control_layer` block on success saying which controls fired.

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
