import assert from "node:assert/strict";
import { test } from "node:test";

import {
  incidentStats,
  isReviewOverdue,
  nextPolicyVersion,
  parseIncidentInput,
  parsePolicyInput,
  triageSort,
} from "./domain.ts";

const NOW = new Date("2026-10-03T12:00:00Z");

void test("parseIncidentInput accepts a valid incident and fills defaults", () => {
  const r = parseIncidentInput(
    { title: " Phishing wave ", severity: "high", category: "Phishing" },
    NOW,
  );
  assert.ok(r.ok);
  assert.equal(r.value.title, "Phishing wave");
  assert.equal(r.value.source, "manual");
  assert.equal(r.value.policy_id, null);
  assert.equal(r.value.detected_at, NOW.toISOString());
});

void test("parseIncidentInput rejects bad title, severity, category, future date", () => {
  assert.equal(
    parseIncidentInput(
      { title: "ab", severity: "high", category: "Phishing" },
      NOW,
    ).ok,
    false,
  );
  assert.equal(
    parseIncidentInput(
      { title: "abc", severity: "urgent", category: "Phishing" },
      NOW,
    ).ok,
    false,
  );
  assert.equal(
    parseIncidentInput(
      { title: "abc", severity: "low", category: "Aliens" },
      NOW,
    ).ok,
    false,
  );
  assert.equal(
    parseIncidentInput(
      {
        title: "abc",
        severity: "low",
        category: "Other",
        detected_at: "2027-01-01T00:00",
      },
      NOW,
    ).ok,
    false,
  );
  assert.equal(
    parseIncidentInput(
      { title: "abc", severity: "low", category: "Other", detected_at: "nope" },
      NOW,
    ).ok,
    false,
  );
});

void test("parsePolicyInput requires a body for active policies", () => {
  const base = { title: "MFA policy", category: "Access control" };
  assert.ok(parsePolicyInput({ ...base, status: "draft" }).ok);
  assert.equal(
    parsePolicyInput({ ...base, status: "active", body: "short" }).ok,
    false,
  );
  assert.ok(
    parsePolicyInput({ ...base, status: "active", body: "Use MFA everywhere." })
      .ok,
  );
  assert.equal(parsePolicyInput({ ...base, status: "deleted" }).ok, false);
  assert.equal(
    parsePolicyInput({ ...base, review_due: "03/10/2026" }).ok,
    false,
  );
});

void test("nextPolicyVersion bumps only when a published body changes", () => {
  const after = parsePolicyInput({
    title: "MFA",
    category: "Access control",
    body: "new body text",
  });
  assert.ok(after.ok);
  assert.equal(
    nextPolicyVersion(
      { status: "active", body: "old", version: 2 },
      after.value,
    ),
    3,
  );
  assert.equal(
    nextPolicyVersion(
      { status: "draft", body: "old", version: 1 },
      after.value,
    ),
    1,
  );
  assert.equal(
    nextPolicyVersion(
      { status: "active", body: "new body text", version: 2 },
      after.value,
    ),
    2,
  );
});

void test("isReviewOverdue only for active policies past their date", () => {
  assert.equal(
    isReviewOverdue({ status: "active", review_due: "2026-10-02" }, NOW),
    true,
  );
  assert.equal(
    isReviewOverdue({ status: "active", review_due: "2026-10-03" }, NOW),
    false,
  );
  assert.equal(
    isReviewOverdue({ status: "draft", review_due: "2020-01-01" }, NOW),
    false,
  );
  assert.equal(
    isReviewOverdue({ status: "active", review_due: null }, NOW),
    false,
  );
});

void test("triageSort: unresolved first, then severity, then oldest", () => {
  const sorted = triageSort([
    {
      id: "a",
      severity: "critical",
      status: "resolved",
      detected_at: "2026-10-01T00:00:00Z",
    },
    {
      id: "b",
      severity: "low",
      status: "open",
      detected_at: "2026-10-01T00:00:00Z",
    },
    {
      id: "c",
      severity: "critical",
      status: "open",
      detected_at: "2026-10-02T00:00:00Z",
    },
    {
      id: "d",
      severity: "critical",
      status: "investigating",
      detected_at: "2026-10-01T00:00:00Z",
    },
  ] as const);
  assert.deepEqual(
    sorted.map((index) => index.id),
    ["d", "c", "b", "a"],
  );
});

void test("incidentStats counts open by severity and computes MTTR", () => {
  const s = incidentStats(
    [
      {
        severity: "high",
        status: "open",
        detected_at: "2026-10-03T00:00:00Z",
        resolved_at: null,
      },
      {
        severity: "high",
        status: "contained",
        detected_at: "2026-10-03T00:00:00Z",
        resolved_at: null,
      },
      {
        severity: "low",
        status: "resolved",
        detected_at: "2026-10-01T00:00:00Z",
        resolved_at: "2026-10-01T04:00:00Z",
      },
      {
        severity: "low",
        status: "resolved",
        detected_at: "2026-08-01T00:00:00Z",
        resolved_at: "2026-08-01T02:00:00Z",
      },
    ],
    NOW,
  );
  assert.equal(s.open, 2);
  assert.equal(s.bySeverity.high, 2);
  assert.equal(s.resolvedLast30d, 1);
  assert.equal(s.mttrHours, 3);
});

void test("incidentStats with no resolved incidents has null MTTR", () => {
  assert.equal(incidentStats([], NOW).mttrHours, null);
});
