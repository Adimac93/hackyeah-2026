import assert from "node:assert/strict";
import { test } from "node:test";

import {
  activityQueryString,
  applyActivityFilters,
  distinctUsers,
  hasActivityFilters,
  parseActivityFilters,
  pdfSafe,
  worstSeverity,
} from "./activity.ts";

void test("parseActivityFilters keeps known values and drops the rest", () => {
  const filters = parseActivityFilters({
    status: "blocked",
    verdict: "nope",
    channel: ["llm", "mcp"],
    user: "  ana@example.com ",
    principal: "p-1",
  });
  assert.deepEqual(filters, {
    status: "blocked",
    verdict: "",
    channel: "",
    principal: "p-1",
    user: "ana@example.com",
  });
  assert.equal(hasActivityFilters(parseActivityFilters({})), false);
});

void test("activityQueryString round-trips only the set filters", () => {
  const filters = parseActivityFilters({ user: "a b@x.io", status: "flagged" });
  const qs = activityQueryString(filters);
  assert.equal(qs, "?status=flagged&user=a+b%40x.io");
  assert.deepEqual(
    parseActivityFilters(Object.fromEntries(new URLSearchParams(qs))),
    filters,
  );
  assert.equal(activityQueryString(parseActivityFilters({})), "");
});

void test("applyActivityFilters maps user to end_user", () => {
  const calls: [string, string][] = [];
  const query = {
    eq(column: string, value: string) {
      calls.push([column, value]);
      return query;
    },
  };
  applyActivityFilters(
    query,
    parseActivityFilters({ user: "u", channel: "mcp" }),
  );
  assert.deepEqual(calls, [
    ["channel", "mcp"],
    ["end_user", "u"],
  ]);
});

void test("worstSeverity and distinctUsers", () => {
  assert.equal(worstSeverity([]), null);
  assert.equal(
    worstSeverity([
      { severity: "low" },
      { severity: "critical" },
      { severity: "high" },
    ]),
    "critical",
  );
  assert.deepEqual(
    distinctUsers([
      { end_user: "b" },
      { end_user: null },
      { end_user: "a" },
      { end_user: "b" },
    ]),
    ["a", "b"],
  );
});

void test("pdfSafe leaves only what Helvetica's WinAnsi can draw", () => {
  assert.equal(pdfSafe("Stanisław Żółć — ok…"), "Stanislaw Zolc - ok...");
  assert.equal(pdfSafe("llama3.1:8b"), "llama3.1:8b");
  assert.equal(pdfSafe("日本 🚀"), "?? ?");
});
