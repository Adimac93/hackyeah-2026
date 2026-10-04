import assert from "node:assert/strict";
import { test } from "node:test";

import {
  applyEvent,
  clampTtl,
  parseApprovalEvent,
  requestTarget,
  secondsLeft,
} from "./approvals.ts";
import type { AccessRequest } from "./approvals.ts";

const request = (id: string, at: number): AccessRequest => ({
  id,
  principal_id: "p1",
  principal: "red-team",
  end_user: "red-team",
  tool: "docs__read",
  resource: null,
  reason: "need the Q3 summary",
  ttl_minutes: 15,
  requested_at_ms: at,
  deadline_ms: at + 120_000,
});

void test("parseApprovalEvent accepts the three gateway event shapes", () => {
  const parsed = parseApprovalEvent(
    JSON.stringify({ type: "request", ...request("a", 1) }),
  );
  assert.equal(parsed?.type, "request");
  assert.deepEqual(
    parseApprovalEvent(
      '{"type":"decided","id":"a","approved":true,"decided_by":"x@y"}',
    ),
    { type: "decided", id: "a", approved: true, decided_by: "x@y" },
  );
  assert.deepEqual(parseApprovalEvent('{"type":"expired","id":"a"}'), {
    type: "expired",
    id: "a",
  });
});

void test("parseApprovalEvent drops malformed payloads", () => {
  assert.equal(parseApprovalEvent("not json"), null);
  assert.equal(parseApprovalEvent('{"type":"request","id":"a"}'), null);
  assert.equal(parseApprovalEvent('{"type":"other","id":"a"}'), null);
  assert.equal(parseApprovalEvent('{"type":"expired"}'), null);
});

void test("applyEvent queues oldest first and dedupes replays", () => {
  let queue = applyEvent([], { type: "request", ...request("b", 2) });
  queue = applyEvent(queue, { type: "request", ...request("a", 1) });
  queue = applyEvent(queue, { type: "request", ...request("b", 2) });
  assert.deepEqual(
    queue.map((r) => r.id),
    ["a", "b"],
  );
  assert.equal("type" in queue[0], false);
});

void test("applyEvent removes decided and expired requests", () => {
  const queue = [request("a", 1), request("b", 2)];
  assert.deepEqual(
    applyEvent(queue, {
      type: "decided",
      id: "a",
      approved: false,
      decided_by: "x",
    }).map((r) => r.id),
    ["b"],
  );
  assert.deepEqual(
    applyEvent(queue, { type: "expired", id: "b" }).map((r) => r.id),
    ["a"],
  );
});

void test("secondsLeft counts down and floors at zero", () => {
  const r = request("a", 0);
  assert.equal(secondsLeft(r, 0), 120);
  assert.equal(secondsLeft(r, 119_001), 1);
  assert.equal(secondsLeft(r, 500_000), 0);
});

void test("clampTtl keeps TTLs within the gateway's 1-60 minutes", () => {
  assert.equal(clampTtl(0), 1);
  assert.equal(clampTtl(15), 15);
  assert.equal(clampTtl(999), 60);
  assert.equal(clampTtl(Number.NaN), 15);
});

void test("a table request for an end user parses and displays as a table", () => {
  const wire = {
    type: "request",
    ...request("t", 1),
    tool: null,
    resource: "customers",
    end_user: "anna@example.com",
  };
  const parsed = parseApprovalEvent(JSON.stringify(wire));
  assert.ok(parsed !== null && parsed.type === "request");
  assert.equal(parsed.end_user, "anna@example.com");
  assert.deepEqual(requestTarget(parsed), { kind: "table", name: "customers" });
  assert.deepEqual(requestTarget(request("a", 1)), {
    kind: "tool",
    name: "docs__read",
  });
  // exactly one target
  assert.equal(
    parseApprovalEvent(JSON.stringify({ ...wire, tool: "docs__read" })),
    null,
  );
  assert.equal(
    parseApprovalEvent(JSON.stringify({ ...wire, resource: null })),
    null,
  );
  // an older gateway without end_user: the grant is for the principal
  const { end_user: _, ...old } = { ...request("o", 1), type: "request" };
  const parsedOld = parseApprovalEvent(JSON.stringify(old));
  assert.equal(parsedOld?.type === "request" && parsedOld.end_user, "red-team");
});
