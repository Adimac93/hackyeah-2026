import assert from "node:assert/strict";
import { test } from "node:test";

import {
  PRESETS,
  keyHint,
  parseProviderInput,
  presetForBaseUrl,
  validateBaseUrl,
} from "./presets.ts";

void test("presetForBaseUrl recognises providers by host", () => {
  assert.equal(
    presetForBaseUrl(
      "https://generativelanguage.googleapis.com/v1beta/openai/",
    ),
    "gemini",
  );
  assert.equal(presetForBaseUrl("https://api.groq.com/openai/v1"), "groq");
  assert.equal(presetForBaseUrl("http://localhost:11434/v1"), "ollama");
  assert.equal(presetForBaseUrl("https://evil-openai.com/v1"), "custom");
  assert.equal(presetForBaseUrl("not a url"), "custom");
  assert.equal(presetForBaseUrl(), "custom");
});

void test("validateBaseUrl allows https and local http only", () => {
  assert.ok(validateBaseUrl("https://api.mistral.ai/v1").ok);
  assert.ok(validateBaseUrl("http://localhost:11434/v1").ok);
  assert.equal(validateBaseUrl("http://example.com/v1").ok, false);
  assert.equal(validateBaseUrl("http://169.254.169.254/latest").ok, false);
  assert.equal(validateBaseUrl("https://user:pw@api.x.ai/v1").ok, false);
  assert.equal(validateBaseUrl("ftp://api.x.ai").ok, false);
  assert.equal(validateBaseUrl("api.x.ai").ok, false);
});

void test("parseProviderInput fills preset defaults", () => {
  const parsed = parseProviderInput(
    { preset: "gemini", api_key: " k-123 ", models: "a, b\nb", enabled: "on" },
    true,
  );
  assert.ok(parsed.ok);
  assert.equal(parsed.value.name, "Google Gemini");
  assert.equal(parsed.value.kind, "compatible");
  assert.equal(parsed.value.baseUrl, PRESETS.gemini.baseUrl);
  assert.equal(parsed.value.apiKey, "k-123");
  assert.deepEqual(parsed.value.models, ["a", "b"]);
  assert.equal(parsed.value.enabled, true);
});

void test("parseProviderInput: anthropic has no base url, keys required on create only", () => {
  const created = parseProviderInput(
    { preset: "anthropic", models: "claude-opus-5-5" },
    true,
  );
  assert.equal(created.ok, false);
  const edited = parseProviderInput(
    { preset: "anthropic", models: "claude-opus-5-5", base_url: "https://x" },
    false,
  );
  assert.ok(edited.ok);
  assert.equal(edited.value.baseUrl, null);
  assert.equal(edited.value.apiKey, null);
  assert.equal(edited.value.enabled, false);
});

void test("parseProviderInput rejects bad input", () => {
  assert.equal(
    parseProviderInput({ preset: "nope", models: "m" }, true).ok,
    false,
  );
  assert.equal(
    parseProviderInput({ preset: "ollama", models: " , " }, true).ok,
    false,
  );
  // custom has no default endpoint
  assert.equal(
    parseProviderInput({ preset: "custom", models: "m" }, true).ok,
    false,
  );
  assert.equal(
    parseProviderInput(
      { preset: "custom", models: "m", base_url: "http://10.0.0.5/v1" },
      true,
    ).ok,
    false,
  );
  // keyless preset needs no key
  assert.ok(
    parseProviderInput({ preset: "ollama", models: "llama3.1:8b" }, true).ok,
  );
});

void test("keyHint never reveals short keys", () => {
  assert.equal(keyHint("sk-ant-api03-abcdefgh1234"), "sk-a…1234");
  assert.equal(keyHint("short"), "••••");
});
