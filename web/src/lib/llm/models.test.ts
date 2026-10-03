import assert from "node:assert/strict";
import { test } from "node:test";

import {
  MOCK_MODEL_ID,
  availableModels,
  defaultModel,
  describeProviderError,
  findModel,
  modelLabel,
  normalizeHistory,
  parseModelList,
} from "./models.ts";

void test("only the offline mock is available without any keys", () => {
  const models = availableModels({});
  assert.deepEqual(
    models.map((m) => m.id),
    [MOCK_MODEL_ID],
  );
});

void test("providers appear when their key is set, Claude first, mock last", () => {
  const ids = availableModels({
    ANTHROPIC_API_KEY: "k",
    OPENAI_API_KEY: "k",
    OPENAI_MODELS: "gpt-5, gpt-5 ,o4-mini",
  }).map((m) => m.id);
  assert.equal(ids[0], "anthropic:claude-opus-5-5");
  assert.ok(ids.includes("openai:gpt-5"));
  assert.ok(ids.includes("openai:o4-mini"));
  assert.equal(ids.filter((id) => id === "openai:gpt-5").length, 1);
  assert.equal(ids.at(-1), MOCK_MODEL_ID);
});

void test("blank keys don't count, compatible needs a base url and models", () => {
  assert.equal(availableModels({ OPENAI_API_KEY: "  " }).length, 1);
  assert.equal(
    availableModels({ LLM_COMPATIBLE_BASE_URL: "http://localhost:11434/v1" })
      .length,
    1,
  );
  const compat = availableModels({
    LLM_COMPATIBLE_BASE_URL: "https://api.groq.com/openai/v1",
    LLM_COMPATIBLE_NAME: "Groq",
    LLM_COMPATIBLE_MODELS: "llama-3.3-70b",
  });
  assert.equal(compat[0].id, "compatible:llama-3.3-70b");
  assert.equal(compat[0].label, "Groq llama-3.3-70b");
});

void test("the gateway, when configured, is the default ahead of direct providers", () => {
  const ids = availableModels({
    GATEWAY_URL: "http://localhost:8080",
    GATEWAY_API_KEY: "k",
    ANTHROPIC_API_KEY: "k",
  }).map((m) => m.id);
  assert.equal(ids[0], "gateway:llama3.1:8b");
  assert.equal(
    availableModels({ GATEWAY_URL: " ", GATEWAY_MODELS: "x" }).length,
    1,
  );
  // without a principal key the gateway answers 401, so it is not offered
  assert.equal(
    availableModels({ GATEWAY_URL: "http://gw" }).some(
      (m) => m.provider === "gateway",
    ),
    false,
  );
  assert.deepEqual(
    availableModels({
      GATEWAY_URL: "http://gw",
      GATEWAY_API_KEY: "k",
      GATEWAY_MODELS: "qwen2.5:7b,mistral:7b",
    })
      .filter((m) => m.provider === "gateway")
      .map((m) => m.model),
    ["qwen2.5:7b", "mistral:7b"],
  );
});

void test("parseModelList falls back when empty", () => {
  assert.deepEqual(parseModelList(undefined, ["a"]), ["a"]);
  assert.deepEqual(parseModelList(" , ", ["a"]), ["a"]);
  assert.deepEqual(parseModelList("x,y", ["a"]), ["x", "y"]);
});

void test("findModel rejects ids that aren't currently offered", () => {
  const models = availableModels({ ANTHROPIC_API_KEY: "k" });
  assert.equal(findModel("openai:gpt-5", models), null);
  assert.equal(findModel("", models), null);
  assert.equal(
    findModel("anthropic:claude-haiku-4-5", models)?.label,
    "Claude Haiku 4.5",
  );
});

void test("defaultModel keeps the conversation's model while it's available", () => {
  const models = availableModels({ ANTHROPIC_API_KEY: "k" });
  assert.equal(
    defaultModel("anthropic:claude-sonnet-5-5", models).id,
    "anthropic:claude-sonnet-5-5",
  );
  assert.equal(defaultModel("openai:gpt-5", models).id, models[0].id);
  assert.equal(defaultModel(null, models).id, models[0].id);
});

void test("modelLabel falls back to the raw model name for removed providers", () => {
  assert.equal(modelLabel("openai:gpt-5", availableModels({})), "gpt-5");
});

void test("normalizeHistory merges repeated roles, trims, and starts with the user", () => {
  const out = normalizeHistory([
    { role: "assistant", content: "hi" },
    { role: "user", content: "a" },
    { role: "user", content: "b" },
    { role: "assistant", content: "c" },
  ]);
  assert.deepEqual(out, [
    { role: "user", content: "a\n\nb" },
    { role: "assistant", content: "c" },
  ]);

  const long = Array.from({ length: 30 }, (_, index) => ({
    role: index % 2 === 0 ? ("user" as const) : ("assistant" as const),
    content: String(index),
  }));
  const trimmed = normalizeHistory(long, 5);
  assert.ok(trimmed.length <= 5);
  assert.equal(trimmed[0].role, "user");
  assert.equal(trimmed.at(-1)?.content, "29");
});

void test("describeProviderError maps statuses to safe messages", () => {
  assert.match(describeProviderError("X", 401), /API key/);
  assert.match(describeProviderError("X", 429), /rate limited/);
  assert.match(describeProviderError("X", 503), /having problems/);
  assert.match(describeProviderError("X"), /could not be reached/);
});

const CONNECTION = {
  id: "11111111-2222-3333-4444-555555555555",
  name: "Mistral AI",
  preset: "mistral",
  kind: "compatible" as const,
  base_url: "https://api.mistral.ai/v1",
  models: ["mistral-large-latest", "mistral-small-latest"],
  enabled: true,
};

void test("console connections add their models before the mock, with logo and id", () => {
  const models = availableModels({ ANTHROPIC_API_KEY: "k" }, [
    CONNECTION,
    { ...CONNECTION, id: "off", enabled: false },
  ]);
  const consoleModels = models.filter((m) => m.connectionId !== undefined);
  assert.deepEqual(
    consoleModels.map((m) => m.id),
    [
      `db:${CONNECTION.id}:mistral-large-latest`,
      `db:${CONNECTION.id}:mistral-small-latest`,
    ],
  );
  assert.equal(consoleModels[0].label, "Mistral AI mistral-large-latest");
  assert.equal(consoleModels[0].icon, "mistral");
  assert.equal(consoleModels[0].provider, "compatible");
  assert.equal(models.at(-1)?.id, MOCK_MODEL_ID);
});

void test("icons: env providers get their logo, unknown presets fall back to custom", () => {
  const models = availableModels(
    {
      ANTHROPIC_API_KEY: "k",
      LLM_COMPATIBLE_BASE_URL:
        "https://generativelanguage.googleapis.com/v1beta/openai/",
      LLM_COMPATIBLE_MODELS: "gemini-2.5-pro",
    },
    [{ ...CONNECTION, preset: "something-new" }],
  );
  assert.equal(models[0].icon, "anthropic");
  assert.equal(models.find((m) => m.provider === "compatible")?.icon, "gemini");
  assert.equal(
    models.find((m) => m.connectionId !== undefined)?.icon,
    "custom",
  );
  assert.equal(models.at(-1)?.icon, "mock");
});

void test("modelLabel strips the connection id for removed console models", () => {
  assert.equal(
    modelLabel(`db:${CONNECTION.id}:llama3.1:8b`, []),
    "llama3.1:8b",
  );
  assert.equal(modelLabel("openai:gpt-5", []), "gpt-5");
});
