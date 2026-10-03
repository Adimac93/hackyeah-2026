import assert from "node:assert/strict";
import { test } from "node:test";

import { effectiveStatus, splitTool, toolSummary } from "./mcp.ts";

void test("splitTool separates the federated server prefix", () => {
  assert.deepEqual(splitTool("docs__read"), { server: "docs", name: "read" });
  assert.deepEqual(splitTool("a__b__c"), { server: "a", name: "b__c" });
  assert.deepEqual(splitTool("ping"), { server: "gateway", name: "ping" });
  assert.deepEqual(splitTool("__x"), { server: "gateway", name: "__x" });
  assert.deepEqual(splitTool("x__"), { server: "gateway", name: "x__" });
});

void test("toolSummary counts calls per tool and verdicts across hooks", () => {
  const rows = toolSummary([
    {
      tool: "docs__read",
      hook: "tool_call",
      verdict: "allow",
      ts: "2026-10-03T10:00:00Z",
    },
    {
      tool: "docs__read",
      hook: "tool_result",
      verdict: "redact",
      ts: "2026-10-03T10:00:01Z",
    },
    {
      tool: "docs__read",
      hook: "tool_call",
      verdict: "block",
      ts: "2026-10-03T09:00:00Z",
    },
    {
      tool: "fs__write",
      hook: "tool_call",
      verdict: "block",
      ts: "2026-10-03T08:00:00Z",
    },
    {
      tool: null,
      hook: "tool_call",
      verdict: "allow",
      ts: "2026-10-03T11:00:00Z",
    },
  ]);
  assert.equal(rows.length, 2);
  const [read, write] = rows;
  assert.equal(read.tool, "docs__read");
  assert.equal(read.server, "docs");
  assert.equal(read.calls, 2);
  assert.deepEqual(read.byVerdict, { allow: 1, redact: 1, block: 1 });
  assert.equal(read.lastSeen, "2026-10-03T10:00:01Z");
  assert.equal(write.calls, 1);
});

void test("toolSummary breaks call-count ties by name", () => {
  const rows = toolSummary([
    {
      tool: "b__x",
      hook: "tool_call",
      verdict: "allow",
      ts: "2026-10-03T10:00:00Z",
    },
    {
      tool: "a__x",
      hook: "tool_call",
      verdict: "allow",
      ts: "2026-10-03T10:00:00Z",
    },
  ]);
  assert.deepEqual(
    rows.map((r) => r.tool),
    ["a__x", "b__x"],
  );
});

void test("effectiveStatus expires a lapsed grant", () => {
  const now = Date.parse("2026-10-03T12:00:00Z");
  assert.equal(
    effectiveStatus(
      { status: "approved", expires_at: "2026-10-03T11:59:59Z" },
      now,
    ),
    "expired",
  );
  assert.equal(
    effectiveStatus(
      { status: "approved", expires_at: "2026-10-03T12:15:00Z" },
      now,
    ),
    "approved",
  );
  assert.equal(
    effectiveStatus({ status: "pending", expires_at: null }, now),
    "pending",
  );
  assert.equal(
    effectiveStatus({ status: "denied", expires_at: null }, now),
    "denied",
  );
});
