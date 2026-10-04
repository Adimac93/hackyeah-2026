import assert from "node:assert/strict";
import { test } from "node:test";

import { parseCatalogControls, reconcileControls } from "./catalog.ts";
import type { LiveControl } from "./gateway-live.ts";

const TOML = [
  "schema_version = 1",
  "[models]",
  'allowed = ["x"]',
  "",
  "[[controls.deterministic]]",
  'id = "secret.aws"',
  'severity = "critical"',
  "",
  "# [[controls.deterministic]]",
  '# id = "pii.phone"',
  "",
  "[[controls.deterministic]] # trailing comment",
  'id = "pii.email"',
  "enabled = false",
  "",
  "[[controls.semantic]]",
  'id = "injection.prompt-guard"',
  'escalate_when = "suspicious"',
  "",
  "[mcp]",
  'unknown_principal = "deny"',
  "[[mcp.server]]",
  'name = "docs"',
].join("\r\n");

void test("parseCatalogControls reads ids in order, skips comments, sees enabled = false", () => {
  assert.deepEqual(parseCatalogControls(TOML), [
    { id: "secret.aws", kind: "deterministic", enabled: true },
    { id: "pii.email", kind: "deterministic", enabled: false },
    { id: "injection.prompt-guard", kind: "semantic", enabled: true },
  ]);
});

function live(id: string, feed?: string): LiveControl {
  return {
    id,
    kind: "deterministic",
    action: "block",
    severity: "high",
    hooks: ["prompt_in"],
    feed: feed ?? null,
  };
}

void test("reconcileControls joins catalog and gateway, feed controls apart", () => {
  const { rows, feed } = reconcileControls(parseCatalogControls(TOML), [
    live("secret.aws"),
    live("sig.cve-2024-1", "signatures.toml"),
    live("legacy.rule"),
  ]);
  assert.deepEqual(
    rows.map((r) => [r.id, r.status]),
    [
      ["secret.aws", "active"],
      ["pii.email", "disabled"],
      ["injection.prompt-guard", "missing"],
      ["legacy.rule", "extra"],
    ],
  );
  assert.deepEqual(
    feed.map((c) => c.id),
    ["sig.cve-2024-1"],
  );
});
