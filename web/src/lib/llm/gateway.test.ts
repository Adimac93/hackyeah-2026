import assert from "node:assert/strict";
import { test } from "node:test";

import { interpretGatewayResponse } from "./gateway.ts";
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
