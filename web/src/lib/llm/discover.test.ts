import assert from "node:assert/strict";
import { test } from "node:test";

import { MAX_MODELS, parseModelList } from "./discover.ts";

void test("parseModelList reads OpenAI-style bodies", () => {
  assert.deepEqual(
    parseModelList({
      object: "list",
      data: [
        { id: "gpt-5-mini", object: "model" },
        { id: "gpt-5", object: "model" },
      ],
    }),
    ["gpt-5", "gpt-5-mini"],
  );
  // Ollama's /v1/models
  assert.deepEqual(
    parseModelList({ data: [{ id: "llama3.1:8b", owned_by: "library" }] }),
    ["llama3.1:8b"],
  );
});

void test("parseModelList ignores anything that isn't a model list", () => {
  assert.deepEqual(parseModelList(null), []);
  assert.deepEqual(parseModelList("models"), []);
  assert.deepEqual(parseModelList({ models: [{ name: "x" }] }), []);
  assert.deepEqual(parseModelList({ data: "x" }), []);
  assert.deepEqual(
    parseModelList({ data: [null, 3, { id: 7 }, { id: "  " }, { id: "ok" }] }),
    ["ok"],
  );
  assert.deepEqual(parseModelList({ data: [{ id: "x".repeat(121) }] }), []);
});

void test("parseModelList de-duplicates and caps at the table limit", () => {
  assert.deepEqual(parseModelList({ data: [{ id: "a" }, { id: " a " }] }), [
    "a",
  ]);
  const many = Array.from({ length: 80 }, (_, index) => ({
    id: `m${String(index).padStart(2, "0")}`,
  }));
  const ids = parseModelList({ data: many });
  assert.equal(ids.length, MAX_MODELS);
  assert.equal(ids[0], "m00");
});
