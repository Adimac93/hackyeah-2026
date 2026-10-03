import assert from "node:assert/strict";
import { test } from "node:test";

import {
  blockRate,
  budgetUsed,
  liveError,
  parseGatewayTime,
} from "./gateway-live.ts";

void test("blockRate is 0 with no traffic and the blocked share otherwise", () => {
  const totals = {
    events: 0,
    allowed: 0,
    redacted: 0,
    blocked: 0,
    detections: 0,
    tokens: 0,
  };
  assert.equal(blockRate(totals), 0);
  assert.equal(blockRate({ ...totals, events: 8, blocked: 2 }), 0.25);
});

void test("budgetUsed is null without a token cap", () => {
  const budget = {
    scope: "global",
    scope_id: null,
    limit_tokens: null,
    used_tokens: 50,
    hard: true,
  };
  assert.equal(budgetUsed(budget), null);
  assert.equal(budgetUsed({ ...budget, limit_tokens: 0 }), null);
  assert.equal(budgetUsed({ ...budget, limit_tokens: 200 }), 0.25);
});

void test("liveError explains auth failures distinctly", () => {
  assert.match(liveError(401), /rejected your session/);
  assert.match(liveError(403), /team role/);
  assert.match(liveError(500), /HTTP 500/);
});

void test("parseGatewayTime reads zone-less gateway timestamps as UTC", () => {
  assert.equal(
    parseGatewayTime("2026-10-03 20:20:34"),
    "2026-10-03T20:20:34.000Z",
  );
  assert.equal(
    parseGatewayTime("2026-10-03 21:27:11 UTC"),
    "2026-10-03T21:27:11.000Z",
  );
  assert.equal(
    parseGatewayTime("2026-10-03T21:27:11Z"),
    "2026-10-03T21:27:11.000Z",
  );
  assert.equal(
    parseGatewayTime("2026-10-03T23:27:11+02:00"),
    "2026-10-03T21:27:11.000Z",
  );
  assert.equal(parseGatewayTime("garbage"), "garbage");
});
