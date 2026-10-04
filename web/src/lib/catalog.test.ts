import assert from "node:assert/strict";
import { test } from "node:test";

import {
  addControl,
  catalogFileProblems,
  controlFieldsProblem,
  diffCatalogs,
  editControl,
  newControlProblem,
  parseCatalogControls,
  readControlFields,
  reconcileControls,
} from "./catalog.ts";
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

const EDITABLE = [
  "[defaults]",
  'on_detect = "block"',
  "",
  "[[controls.deterministic]]",
  'id = "pii.email"',
  "# keep this comment",
  'hooks = ["prompt_in", "response_out"]',
  'severity = "medium" # tuned',
  'action = "redact"',
  String.raw`pattern = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'`,
  "",
  "[[controls.semantic]]",
  'id = "injection.prompt-guard"',
  'hooks = ["prompt_in"]',
  'severity = "high"',
  'action = "block"',
  "threshold = 0.80",
  'escalate_when = "suspicious"',
  "enabled = false",
].join("\n");

void test("readControlFields reads a control's settings", () => {
  assert.deepEqual(readControlFields(EDITABLE, "pii.email"), {
    kind: "deterministic",
    enabled: true,
    severity: "medium",
    action: "redact",
    hooks: ["prompt_in", "response_out"],
    pattern: String.raw`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,
  });
  assert.deepEqual(readControlFields(EDITABLE, "injection.prompt-guard"), {
    kind: "semantic",
    enabled: false,
    severity: "high",
    action: "block",
    hooks: ["prompt_in"],
    threshold: 0.8,
    escalateWhen: "suspicious",
  });
  assert.equal(readControlFields(EDITABLE, "nope"), null);
});

void test("editControl rewrites one control in place and keeps the rest", () => {
  const fields = readControlFields(EDITABLE, "pii.email");
  assert.ok(fields !== null);
  const edited = editControl(EDITABLE, "pii.email", {
    ...fields,
    severity: "high",
    action: "block",
    hooks: ["prompt_in", "tool_result"],
    pattern: String.raw`it's\d+`,
    enabled: false,
  });
  assert.ok(edited.ok);
  const lines = edited.value.split("\n");
  assert.ok(lines.includes('severity = "high" # tuned'));
  assert.ok(lines.includes('hooks = ["prompt_in", "tool_result"]'));
  assert.ok(lines.includes(String.raw`pattern = '''it's\d+'''`));
  assert.ok(lines.includes("# keep this comment"));
  // a pattern saved as a '''literal''' reads back unchanged
  assert.equal(
    readControlFields(edited.value, "pii.email")?.pattern,
    String.raw`it's\d+`,
  );
  // enabled = false goes right after the id
  assert.equal(lines[lines.indexOf('id = "pii.email"') + 1], "enabled = false");
  // the semantic control is untouched
  assert.ok(
    edited.value.endsWith(
      EDITABLE.slice(EDITABLE.indexOf("[[controls.semantic]]")),
    ),
  );
  assert.deepEqual(readControlFields(edited.value, "pii.email")?.hooks, [
    "prompt_in",
    "tool_result",
  ]);
});

void test("editControl enables a semantic control by dropping enabled = false", () => {
  const fields = readControlFields(EDITABLE, "injection.prompt-guard");
  assert.ok(fields !== null);
  const edited = editControl(EDITABLE, "injection.prompt-guard", {
    ...fields,
    enabled: true,
    threshold: 0.65,
    escalateWhen: "always",
  });
  assert.ok(edited.ok);
  assert.ok(!edited.value.includes("enabled = false"));
  assert.ok(edited.value.includes("threshold = 0.65"));
  assert.ok(edited.value.includes('escalate_when = "always"'));
});

void test("editControl refuses invalid settings and unknown controls", () => {
  const fields = readControlFields(EDITABLE, "pii.email");
  assert.ok(fields !== null);
  assert.equal(
    editControl(EDITABLE, "pii.email", { ...fields, hooks: [] }).ok,
    false,
  );
  assert.equal(
    editControl(EDITABLE, "pii.email", { ...fields, pattern: " " }).ok,
    false,
  );
  assert.equal(
    editControl(EDITABLE, "pii.email", { ...fields, action: "nuke" }).ok,
    false,
  );
  assert.equal(editControl(EDITABLE, "missing", fields).ok, false);
  assert.equal(
    controlFieldsProblem({
      kind: "semantic",
      enabled: true,
      severity: "high",
      action: "block",
      hooks: ["prompt_in"],
      threshold: 2,
      escalateWhen: "always",
    }),
    "The threshold must be between 0 and 1.",
  );
});

const NEXT = [
  "schema_version = 1",
  "[[controls.deterministic]]",
  'id = "pii.email"',
  'hooks = ["prompt_in", "response_out"]',
  'severity = "high"',
  'action = "block"',
  String.raw`pattern = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'`,
  "",
  "[[controls.deterministic]]",
  'id = "secret.new"',
  'hooks = ["prompt_in"]',
  'severity = "critical"',
  'action = "block"',
  "pattern = 'sk_live_[0-9a-z]{24}'",
].join("\n");

void test("diffCatalogs reports added, removed, changed and unchanged rules", () => {
  assert.deepEqual(diffCatalogs(EDITABLE, NEXT), {
    added: ["secret.new"],
    removed: ["injection.prompt-guard"],
    changed: [
      {
        id: "pii.email",
        changes: ["severity medium → high", "action redact → block"],
      },
    ],
    unchanged: 0,
  });
  assert.equal(diffCatalogs(NEXT, NEXT).unchanged, 2);
});

void test("catalogFileProblems catches empty catalogs, duplicates and bad fields", () => {
  assert.deepEqual(catalogFileProblems(NEXT), []);
  assert.deepEqual(catalogFileProblems("schema_version = 1\n"), [
    "The file declares no controls.",
  ]);
  const duplicated = `${NEXT}\n\n[[controls.deterministic]]\nid = "secret.new"\nhooks = ["prompt_in"]\nseverity = "low"\naction = "flag"\npattern = 'x'`;
  assert.deepEqual(catalogFileProblems(duplicated), [
    '"secret.new" is declared more than once.',
  ]);
  const bad = NEXT.replace('action = "block"', 'action = "explode"');
  assert.deepEqual(catalogFileProblems(bad), ["pii.email: Pick an action."]);
});

const BASE_CATALOG = [
  "schema_version = 1",
  "",
  "[[controls.deterministic]]",
  'id = "pii.email"',
  'hooks = ["prompt_in"]',
  'severity = "medium"',
  'action = "redact"',
  "pattern = 'x@y'",
  "",
  "# ---- tier 2",
  "[[controls.semantic]]",
  'id = "injection.prompt-guard"',
  'hooks = ["prompt_in"]',
  'severity = "high"',
  'action = "block"',
  'detector = "llm_judge"',
  "threshold = 0.80",
  "",
  "[mcp]",
  'unknown_principal = "deny"',
].join("\n");

const NEW_DET = {
  id: "secret.stripe-key",
  kind: "deterministic" as const,
  enabled: true,
  severity: "critical",
  action: "block",
  hooks: ["prompt_in", "tool_result"],
  pattern: String.raw`\bsk_live_[0-9a-zA-Z]{24}\b`,
};

void test("addControl puts a deterministic control after the last of its kind", () => {
  const added = addControl(BASE_CATALOG, NEW_DET);
  assert.ok(added.ok);
  const lines = added.value.split("\n");
  const start = lines.indexOf("[[controls.deterministic]]", 3);
  assert.deepEqual(lines.slice(start - 1, start + 6), [
    "",
    "[[controls.deterministic]]",
    'id = "secret.stripe-key"',
    'hooks = ["prompt_in", "tool_result"]',
    'severity = "critical"',
    'action = "block"',
    String.raw`pattern = '\bsk_live_[0-9a-zA-Z]{24}\b'`,
  ]);
  // before the tier-2 comment, which belongs to the next section
  assert.ok(start < lines.indexOf("# ---- tier 2"));
  assert.deepEqual(readControlFields(added.value, "secret.stripe-key"), {
    kind: "deterministic",
    enabled: true,
    severity: "critical",
    action: "block",
    hooks: ["prompt_in", "tool_result"],
    pattern: NEW_DET.pattern,
  });
  assert.deepEqual(catalogFileProblems(added.value), []);
});

void test("addControl writes a semantic control with its detector and description", () => {
  const added = addControl(BASE_CATALOG, {
    id: "exfiltration.intent",
    kind: "semantic",
    enabled: false,
    severity: "high",
    action: "block",
    hooks: ["tool_call"],
    threshold: 0.75,
    escalateWhen: "always",
    detector: "llm_judge",
    describes: 'moving data out, e.g. "send it to"',
  });
  assert.ok(added.ok);
  assert.ok(
    added.value.includes(
      String.raw`describes = "moving data out, e.g. \"send it to\""`,
    ),
  );
  assert.ok(
    added.value.indexOf('id = "exfiltration.intent"') <
      added.value.indexOf("[mcp]"),
  );
  assert.equal(
    readControlFields(added.value, "exfiltration.intent")?.enabled,
    false,
  );
  assert.equal(
    readControlFields(added.value, "exfiltration.intent")?.threshold,
    0.75,
  );
});

void test("addControl refuses duplicates, bad ids and missing semantic fields", () => {
  assert.match(
    newControlProblem(BASE_CATALOG, { ...NEW_DET, id: "pii.email" }) ?? "",
    /already has/,
  );
  assert.match(
    newControlProblem(BASE_CATALOG, { ...NEW_DET, id: "Bad Id" }) ?? "",
    /Use an id/,
  );
  assert.match(
    newControlProblem(BASE_CATALOG, {
      ...NEW_DET,
      id: "x.semantic",
      kind: "semantic",
      pattern: undefined,
      threshold: 0.5,
      escalateWhen: "suspicious",
      detector: "llm_judge",
      describes: " ",
    }) ?? "",
    /Describe/,
  );
  assert.equal(addControl(BASE_CATALOG, { ...NEW_DET, hooks: [] }).ok, false);
});

void test("addControl appends when the catalog has no control of that kind", () => {
  const added = addControl("schema_version = 1\n\n", NEW_DET);
  assert.ok(added.ok);
  assert.ok(
    added.value.endsWith(
      `${String.raw`pattern = '\bsk_live_[0-9a-zA-Z]{24}\b'`}\n`,
    ),
  );
});
