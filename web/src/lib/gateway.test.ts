import assert from "node:assert/strict";
import { test } from "node:test";

import {
  MAX_POLICY_BYTES,
  budgetSpend,
  checkPolicyUpload,
  describePolicyUpload,
  fmtMicros,
  fmtWindow,
  gatewayStats,
  overheadUs,
  percentile,
  shortHash,
} from "./gateway.ts";
import type { Budget, UsageRow } from "./gateway.ts";

void test("overheadUs counts controls, not the upstream call", () => {
  assert.equal(
    overheadUs({
      deterministic_us: 180,
      semantic_us: 41_200,
      upstream_us: 910,
    }),
    41_380,
  );
  assert.equal(overheadUs({}), 0);
});

void test("percentile uses nearest rank and handles edges", () => {
  assert.equal(percentile([], 50), null);
  assert.equal(percentile([7], 95), 7);
  assert.equal(percentile([5, 1, 4, 2, 3], 50), 3);
  assert.equal(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95), 10);
  assert.equal(percentile([1, 2, 3, 4], 0), 1);
});

void test("gatewayStats counts verdicts, interventions and semantic share", () => {
  const stats = gatewayStats([
    { verdict: "allow", latency: { deterministic_us: 100 } },
    { verdict: "allow", latency: { deterministic_us: 300, semantic_us: 0 } },
    { verdict: "redact", latency: { deterministic_us: 200 } },
    { verdict: "block", latency: { deterministic_us: 400, semantic_us: 2000 } },
  ]);
  assert.deepEqual(stats.byVerdict, { allow: 2, redact: 1, block: 1 });
  assert.equal(stats.total, 4);
  assert.equal(stats.interventionRate, 0.5);
  assert.equal(stats.semanticShare, 0.25);
  assert.equal(stats.p50OverheadUs, 200);
  assert.equal(stats.p95OverheadUs, 2400);
});

void test("gatewayStats on no events is all zeros", () => {
  const stats = gatewayStats([]);
  assert.equal(stats.total, 0);
  assert.equal(stats.interventionRate, 0);
  assert.equal(stats.p50OverheadUs, null);
});

const NOW = Date.parse("2026-10-03T12:00:00Z");
const principals = [
  { id: "p1", slug: "demo-agent" },
  { id: "p2", slug: "red-team" },
];
function budget(over: Partial<Budget>): Budget {
  return {
    id: 1,
    scope: "global",
    scope_id: null,
    window_secs: 3600,
    limit_usd: null,
    limit_tokens: 1000,
    hard: true,
    enabled: true,
    created_at: "2026-10-01T00:00:00Z",
    ...over,
  };
}
function usage(over: Partial<UsageRow>): UsageRow {
  return {
    ts: "2026-10-03T11:30:00Z",
    principal_id: "p1",
    model: "llama3.1:8b",
    prompt_tokens: 100,
    completion_tokens: 50,
    cost_usd: "0.010000",
    ...over,
  };
}

void test("budgetSpend only counts usage inside the window", () => {
  const spend = budgetSpend(
    budget({}),
    [usage({}), usage({ ts: "2026-10-03T10:59:00Z" })],
    principals,
    NOW,
  );
  assert.equal(spend.tokens, 150);
  assert.equal(spend.used, 0.15);
});

void test("budgetSpend scopes to a principal by slug and to a model", () => {
  const rows = [
    usage({}),
    usage({ principal_id: "p2", model: "qwen2.5:7b", prompt_tokens: 400 }),
  ];
  assert.equal(
    budgetSpend(
      budget({ scope: "principal", scope_id: "red-team" }),
      rows,
      principals,
      NOW,
    ).tokens,
    450,
  );
  assert.equal(
    budgetSpend(
      budget({ scope: "model", scope_id: "llama3.1:8b" }),
      rows,
      principals,
      NOW,
    ).tokens,
    150,
  );
  // unknown principal slug matches nothing rather than everything
  assert.equal(
    budgetSpend(
      budget({ scope: "principal", scope_id: "ghost" }),
      rows,
      principals,
      NOW,
    ).tokens,
    0,
  );
});

void test("budgetSpend reports the tighter of token and USD limits", () => {
  const spend = budgetSpend(
    budget({ limit_tokens: 1000, limit_usd: 0.02 }),
    [usage({})],
    principals,
    NOW,
  );
  assert.equal(spend.used, 0.5);
  assert.equal(
    budgetSpend(budget({ limit_tokens: null }), [], principals, NOW).used,
    null,
  );
});

void test("formatters", () => {
  assert.equal(fmtMicros(180), "180 µs");
  assert.equal(fmtMicros(2184), "2.2 ms");
  assert.equal(fmtMicros(41_200), "41 ms");
  assert.equal(fmtMicros(null), "—");
  assert.equal(fmtWindow(3600), "1h");
  assert.equal(fmtWindow(86_400), "24h");
  assert.equal(fmtWindow(90), "90s");
  assert.equal(shortHash(String.raw`\xdeadbeef00112233aabb`, 8), "deadbeef");
  assert.equal(shortHash(null), "—");
});

void test("checkPolicyUpload wants a complete, text, size-limited catalog", () => {
  assert.equal(checkPolicyUpload("   ").ok, false);
  assert.equal(checkPolicyUpload("[defaults]\non_detect = 'block'").ok, false);
  assert.equal(checkPolicyUpload("schema_version = 1\0").ok, false);
  assert.equal(
    checkPolicyUpload(`schema_version = 1\n# ${"x".repeat(MAX_POLICY_BYTES)}`)
      .ok,
    false,
  );
  assert.ok(checkPolicyUpload("# catalog\n  schema_version = 1\n").ok);
});

void test("describePolicyUpload maps gateway answers", () => {
  const accepted = describePolicyUpload(200, {
    accepted: true,
    changed: true,
    diff: "policy a -> b",
  });
  assert.ok(accepted.ok);
  assert.match(accepted.message, /policy a -> b/);

  const same = describePolicyUpload(200, { accepted: true, changed: false });
  assert.ok(same.ok);
  assert.match(same.message, /nothing changed/);

  const invalid = describePolicyUpload(422, {
    error: "invalid_policy",
    message: "unknown field `on_detct`",
  });
  assert.equal(invalid.ok, false);
  assert.match(invalid.error, /on_detct/);

  const forbidden = describePolicyUpload(403, {});
  assert.equal(forbidden.ok, false);
  assert.match(forbidden.error, /GATEWAY_ADMIN_KEY/);

  assert.equal(describePolicyUpload(500, null).ok, false);
});
