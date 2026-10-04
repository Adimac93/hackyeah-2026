import assert from "node:assert/strict";
import { test } from "node:test";

import {
  cellText,
  mergeResults,
  parseResult,
  sortRows,
  storedSteps,
  toSteps,
} from "./tool-steps.ts";
import type { StepResult } from "./tool-steps.ts";

// what the gateway reports for the access-request walk (gateway/src/proxy/agent.rs)
const walk = [
  {
    tool: "resources__describe",
    arguments: { tables: ["customers"] },
    status: "refused",
    trace_id: null,
    result_id: null,
    content:
      'refused: table customers needs approval: call control__request_access with {"table": "customers", "reason": "<why>"}, then retry',
  },
  {
    tool: "control__request_access",
    arguments: { table: "customers", reason: "overdue accounts" },
    status: "ok",
    result_id: null,
    content: '{"expires_at_ms":1,"status":"granted"}',
  },
  {
    tool: "resources__query",
    arguments: { sql: "select full_name,\n  email\nfrom customers" },
    status: "ok",
    result_id: "r-1",
    content:
      '{"columns":["full_name","email"],"row_count":42,"result_id":"r-1"}',
  },
];

void test("toSteps summarises each kind of call", () => {
  const steps = toSteps(walk);
  assert.deepEqual(
    steps.map((s) => s.summary),
    [
      "describe customers → refused",
      "requested table customers → granted",
      "select full_name, email from customers → 42 rows",
    ],
  );
  assert.match(steps[0].detail ?? "", /^table customers needs approval/);
  assert.equal(steps[1].detail, undefined);
  assert.equal(steps[2].resultId, "r-1");
  assert.deepEqual(steps[2].arguments, walk[2].arguments);
});

void test("toSteps covers refusals, listings and unknown tools", () => {
  const steps = toSteps([
    {
      tool: "resources__describe",
      arguments: {},
      status: "ok",
      content: "tables: a",
    },
    {
      tool: "resources__query",
      arguments: { sql: "select 1" },
      status: "refused",
      content: "refused: tool call blocked by mcp.runaway",
    },
    {
      tool: "control__request_access",
      arguments: { tool: "docs__read" },
      status: "ok",
      content: '{"status":"already_permitted"}',
    },
    { tool: "docs__read", arguments: { id: 1 }, status: "ok", content: "text" },
  ]);
  assert.deepEqual(
    steps.map((s) => s.summary),
    [
      "list tables",
      "select 1 → refused",
      "requested docs__read → already permitted",
      "docs__read",
    ],
  );
  assert.equal(steps[1].detail, "tool call blocked by mcp.runaway");
});

void test("toSteps drops what is not a tool call", () => {
  assert.deepEqual(toSteps(null), []);
  assert.deepEqual(toSteps({ tool: "x" }), []);
  assert.deepEqual(toSteps([null, 1, { status: "ok" }]), []);
});

void test("mergeResults attaches rows and marks a failed fetch", () => {
  const rows: StepResult = {
    columns: ["full_name"],
    row_count: 1,
    rows: [{ full_name: "Anna" }],
  };
  const steps = toSteps([walk[2], { ...walk[2], result_id: "r-2" }, walk[0]]);
  const merged = mergeResults(
    steps,
    new Map<string, StepResult | null>([
      ["r-1", rows],
      ["r-2", null],
    ]),
  );
  assert.deepEqual(merged[0].result, rows);
  assert.equal(merged[0].resultId, undefined);
  assert.equal(merged[1].result, undefined);
  assert.equal(merged[1].resultError, "result unavailable");
  assert.deepEqual(merged[2], steps[2]);
});

void test("parseResult accepts the results endpoint and nothing else", () => {
  assert.deepEqual(
    parseResult({
      id: "r",
      columns: ["a"],
      row_count: 1,
      rows: [{ a: 1 }, "junk"],
      created_at: "t",
    }),
    { columns: ["a"], row_count: 1, rows: [{ a: 1 }] },
  );
  assert.equal(parseResult({ error: { type: "not_found" } }), null);
  assert.equal(parseResult(null), null);
});

void test("storedSteps keeps only well-formed steps", () => {
  const steps = toSteps(walk);
  assert.deepEqual(storedSteps(steps), steps);
  assert.deepEqual(storedSteps(null), []);
  assert.deepEqual(storedSteps([{ tool: "x" }]), []);
});

void test("cells keep redaction markers and sorting handles numbers and gaps", () => {
  assert.equal(cellText("[REDACTED:pii.email]"), "[REDACTED:pii.email]");
  assert.equal(cellText(null), "");
  assert.equal(cellText({ a: 1 }), '{"a":1}');

  const rows = [
    { n: 10, s: "b" },
    { n: 9, s: null },
    { n: 100, s: "a" },
  ];
  assert.deepEqual(
    sortRows(rows, "n", "asc").map((r) => r.n),
    [9, 10, 100],
  );
  assert.deepEqual(
    sortRows(rows, "n", "desc").map((r) => r.n),
    [100, 10, 9],
  );
  assert.deepEqual(
    sortRows(rows, "s", "asc").map((r) => r.s),
    ["a", "b", null],
  );
  assert.deepEqual(
    sortRows(rows, "s", "desc").map((r) => r.s),
    ["b", "a", null],
  );
});
