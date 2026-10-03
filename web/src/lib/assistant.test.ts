import assert from "node:assert/strict";
import { test } from "node:test";

import {
  MAX_MESSAGE_LENGTH,
  buildSystemPrompt,
  containsSecret,
  conversationTitle,
  mockReply,
  parseChatMessage,
  relevantPolicies,
} from "./assistant.ts";

const POLICIES = [
  {
    title: "Password & MFA Policy",
    category: "Access control",
    summary:
      "All employees must use MFA and passwords of at least 14 characters.",
    body: "1. MFA is mandatory.\n2. Minimum password length: 14 characters.",
  },
  {
    title: "Data Classification & Handling",
    category: "Data protection",
    summary: "Public / Internal / Confidential / Restricted classes.",
    body: "Confidential data must be encrypted at rest and in transit.",
  },
];

void test("parseChatMessage trims, rejects empty and oversized input", () => {
  assert.deepEqual(parseChatMessage("  hi  "), { ok: true, value: "hi" });
  assert.equal(parseChatMessage("   ").ok, false);
  assert.equal(parseChatMessage().ok, false);
  assert.equal(parseChatMessage("x".repeat(MAX_MESSAGE_LENGTH + 1)).ok, false);
});

void test("conversationTitle uses the first line and truncates long ones", () => {
  assert.equal(
    conversationTitle("How do I hash passwords?\nmore context"),
    "How do I hash passwords?",
  );
  const long = conversationTitle("a ".repeat(100));
  assert.ok(long.length <= 60);
  assert.ok(long.endsWith("…"));
});

void test("containsSecret flags common credential shapes but not ordinary text", () => {
  assert.ok(containsSecret("aws key AKIAIOSFODNN7EXAMPLE"));
  assert.ok(containsSecret("DB_PASSWORD=hunter2hunter2"));
  assert.ok(containsSecret("-----BEGIN RSA PRIVATE KEY-----"));
  assert.ok(containsSecret("token: ghp_abcdefghijklmnopqrstuvwxyz0123456789"));
  assert.equal(containsSecret("How long should a password be?"), false);
});

void test("relevantPolicies ranks by keyword overlap and ignores unrelated questions", () => {
  assert.equal(
    relevantPolicies("minimum password length for MFA?", POLICIES)[0].title,
    "Password & MFA Policy",
  );
  assert.equal(
    relevantPolicies("should I encrypt confidential data?", POLICIES)[0].title,
    "Data Classification & Handling",
  );
  assert.deepEqual(relevantPolicies("what's for lunch", POLICIES), []);
  assert.deepEqual(relevantPolicies("", POLICIES), []);
});

void test("mockReply cites matching policies, falls back to general advice, and warns on secrets", () => {
  const cited = mockReply(
    [{ role: "user", content: "What password length do we require?" }],
    POLICIES,
  );
  assert.match(cited, /Password & MFA Policy/);

  const general = mockReply(
    [{ role: "user", content: "kubernetes ingress setup" }],
    POLICIES,
  );
  assert.match(general, /general secure-coding guidance/);

  const leaked = mockReply(
    [{ role: "user", content: "why does api_key=abcdef123456 fail" }],
    POLICIES,
  );
  assert.match(leaked, /rotate it/);
});

void test("buildSystemPrompt embeds every active policy", () => {
  const prompt = buildSystemPrompt(POLICIES);
  for (const p of POLICIES) {
    assert.ok(prompt.includes(p.title));
  }
  assert.match(buildSystemPrompt([]), /none published yet/);
});
