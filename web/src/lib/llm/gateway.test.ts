import assert from "node:assert/strict";
import { test } from "node:test";

import {
  decodeGatewaySse,
  finishGatewayStream,
  interpretGatewayResponse,
} from "./gateway.ts";
import type { GatewayOutcome } from "./gateway.ts";

function replyOf(outcome: GatewayOutcome): string {
  if (!outcome.ok) {
    assert.fail(`expected a reply, got error: ${outcome.error}`);
  }
  return outcome.reply;
}

const completion = (content: string, layer?: object) => ({
  choices: [{ message: { content } }],
  ...(layer === undefined ? {} : { x_control_layer: layer }),
});

void test("a clean completion passes through untouched", () => {
  assert.deepEqual(
    interpretGatewayResponse(
      200,
      completion("  hi  ", {
        trace_id: "abcdef1234",
        prompt_in: { verdict: "allow", controls_fired: [] },
        response_out: { verdict: "allow", controls_fired: [] },
      }),
    ),
    { ok: true, reply: "hi" },
  );
});

void test("redactions on either hook are disclosed once each, with the trace", () => {
  const outcome = interpretGatewayResponse(
    200,
    completion("ok", {
      trace_id: "abcdef1234",
      prompt_in: { verdict: "redact", controls_fired: ["pii.email"] },
      response_out: {
        verdict: "redact",
        controls_fired: ["pii.email", "secret.api_key"],
      },
    }),
  );
  const reply = replyOf(outcome);
  assert.ok(reply.startsWith("ok\n\n"));
  assert.ok(reply.includes("pii.email, secret.api_key"));
  assert.ok(reply.includes("trace abcdef12"));
});

void test("controls that only warned are not reported as redactions", () => {
  assert.deepEqual(
    interpretGatewayResponse(
      200,
      completion("ok", {
        prompt_in: { verdict: "allow", controls_fired: ["injection.warn"] },
      }),
    ),
    { ok: true, reply: "ok" },
  );
});

void test("an empty completion is an error, not a blank reply", () => {
  assert.equal(interpretGatewayResponse(200, completion("   ")).ok, false);
  assert.equal(interpretGatewayResponse(200, null).ok, false);
});

void test("policy refusals become a chat reply naming the reason", () => {
  for (const [status, type] of [
    [403, "blocked_by_control"],
    [403, "model_not_allowed"],
    [429, "budget_exceeded"],
  ] as const) {
    const outcome = interpretGatewayResponse(status, {
      error: { type, message: `reason for ${type}` },
      trace_id: "12345678-aaaa",
    });
    const reply = replyOf(outcome);
    assert.ok(reply.includes(`reason for ${type}`), type);
    assert.ok(reply.includes("trace 12345678"));
  }
});

void test("transport failures stay errors", () => {
  const down = interpretGatewayResponse(502, {
    error: { type: "upstream_unavailable", message: "x" },
  });
  assert.match(down.ok ? "" : down.error, /Ollama/);

  const weird = interpretGatewayResponse(500, null);
  assert.deepEqual(weird, {
    ok: false,
    status: 500,
    error: "The gateway answered 500. Try again or pick another model.",
  });
});

void test("a deterministic refusal says the prompt fails the deterministic requirements", () => {
  const outcome = interpretGatewayResponse(403, {
    error: {
      type: "blocked_by_control",
      message: "request blocked by secret.aws-access-key",
      stage: "deterministic",
    },
  });
  assert.ok(
    outcome.ok &&
      outcome.reply.includes(
        "doesn't meet the deterministic security requirements",
      ),
  );
});

const sse = (...chunks: unknown[]) =>
  chunks
    .map((c) => `data: ${typeof c === "string" ? c : JSON.stringify(c)}\n\n`)
    .join("");
const delta = (content: string) => ({ choices: [{ delta: { content } }] });

void test("decodeGatewaySse reads deltas, the final chunk and [DONE], across splits", () => {
  const layer = {
    trace_id: "abcdef1234",
    response_out: { verdict: "allow", controls_fired: [] },
  };
  const wire = sse(
    delta("Hel"),
    delta("lo"),
    { choices: [{ delta: {}, finish_reason: "stop" }], x_control_layer: layer },
    "[DONE]",
  );
  const first = decodeGatewaySse(wire.slice(0, 25));
  const second = decodeGatewaySse(first.rest + wire.slice(25));
  assert.deepEqual(
    [...first.events, ...second.events],
    [
      { type: "delta", text: "Hel" },
      { type: "delta", text: "lo" },
      { type: "final", layer },
      { type: "done" },
    ],
  );
  assert.equal(second.rest, "");
});

void test("decodeGatewaySse skips keep-alives and garbage", () => {
  assert.deepEqual(decodeGatewaySse(":\n\ndata: nope\n\n").events, []);
});

void test("finishGatewayStream: clean, redacted, refused and broken-off endings", () => {
  assert.deepEqual(
    finishGatewayStream("hi", {
      type: "final",
      layer: { response_out: { verdict: "allow", controls_fired: [] } },
    }),
    { ok: true, reply: "hi" },
  );
  assert.match(
    replyOf(
      finishGatewayStream("mail [REDACTED:pii.email]", {
        type: "final",
        layer: {
          trace_id: "abcdef1234",
          response_out: { verdict: "redact", controls_fired: ["pii.email"] },
        },
      }),
    ),
    /redacted content \(pii\.email\) \(trace abcdef12\)/,
  );
  assert.match(
    replyOf(
      finishGatewayStream("partial text", {
        type: "refusal",
        body: {
          error: {
            type: "blocked_by_control",
            message: "response blocked by secrets.private-key",
            stage: "deterministic",
          },
          trace_id: "abcdef1234",
        },
      }),
    ),
    /^🛡 .*secrets\.private-key/,
  );
  assert.equal(finishGatewayStream("partial").ok, false);
});
