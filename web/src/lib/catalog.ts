// Lines the Controls page up with the catalog TOML: which controls the file
// declares (in its order, disabled ones included) versus what the gateway
// reports as enforced. Pure, so it's unit-testable. Not a TOML parser: it only
// reads the `[[controls.*]]` blocks' `id` and `enabled` keys, which the
// gateway's own schema keeps one per line.
import type { LiveControl } from "./gateway-live.ts";

export interface CatalogControl {
  id: string;
  kind: "deterministic" | "semantic";
  enabled: boolean;
}

const BLOCK = /^\[\[controls\.(deterministic|semantic)\]\]\s*(?:#.*)?$/;
const ID = /^id\s*=\s*"([^"]+)"/;
const DISABLED = /^enabled\s*=\s*false\b/;

/** Controls declared in a catalog, in file order. Commented-out blocks don't count. */
export function parseCatalogControls(toml: string): CatalogControl[] {
  const controls: CatalogControl[] = [];
  let current: CatalogControl | null = null;
  let kind: CatalogControl["kind"] | null = null;
  const flush = () => {
    if (current !== null) {
      controls.push(current);
    }
    current = null;
  };
  for (const raw of toml.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) {
      continue;
    }
    const block = BLOCK.exec(line);
    if (block !== null) {
      flush();
      kind = block[1] as CatalogControl["kind"];
      continue;
    }
    if (line.startsWith("[")) {
      // any other table ends the control block
      flush();
      kind = null;
      continue;
    }
    if (kind === null) {
      continue;
    }
    const id = ID.exec(line);
    if (id !== null) {
      current = { id: id[1], kind, enabled: true };
    } else if (DISABLED.test(line) && current !== null) {
      current.enabled = false;
    }
  }
  flush();
  return controls;
}

export type ControlRow =
  /** declared and enforced */
  | { id: string; status: "active"; control: LiveControl }
  /** declared with `enabled = false` */
  | { id: string; status: "disabled"; kind: CatalogControl["kind"] }
  /** declared, but the gateway doesn't enforce it (it runs another version) */
  | { id: string; status: "missing"; kind: CatalogControl["kind"] }
  /** enforced, but not declared in this catalog */
  | { id: string; status: "extra"; control: LiveControl };

/**
 * One row per catalog control, in catalog order, joined with what the gateway
 * enforces. Controls the gateway compiles from the signature feed
 * (`signatures.toml`, `feed` set) aren't in the catalog file; they come back
 * separately.
 */
export function reconcileControls(
  catalog: CatalogControl[],
  live: LiveControl[],
): { rows: ControlRow[]; feed: LiveControl[] } {
  const feed = live.filter((c) => typeof c.feed === "string");
  const enforced = new Map(
    live.filter((c) => typeof c.feed !== "string").map((c) => [c.id, c]),
  );
  const rows: ControlRow[] = catalog.map((c): ControlRow => {
    const control = enforced.get(c.id);
    enforced.delete(c.id);
    if (!c.enabled) {
      return { id: c.id, status: "disabled", kind: c.kind };
    }
    return control === undefined
      ? { id: c.id, status: "missing", kind: c.kind }
      : { id: c.id, status: "active", control };
  });
  for (const control of enforced.values()) {
    rows.push({ id: control.id, status: "extra", control });
  }
  return { rows, feed };
}

// ---------------------------------------------------------------- editing
//
// Edit one control's settings in place, keeping every other line (comments,
// ordering, line endings) as the author wrote it, so a UI edit produces the
// same diff a person editing the file would.

export const CONTROL_ACTION_VALUES = [
  "allow",
  "flag",
  "redact",
  "block",
] as const;
export const CONTROL_SEVERITY_VALUES = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
] as const;
export const HOOK_VALUES = [
  "prompt_in",
  "response_out",
  "tool_call",
  "tool_result",
] as const;
export const ESCALATE_VALUES = ["always", "suspicious", "never"] as const;

export interface ControlFields {
  kind: CatalogControl["kind"];
  enabled: boolean;
  severity: string;
  action: string;
  hooks: string[];
  /** deterministic only */
  pattern?: string;
  /** semantic only */
  threshold?: number;
  escalateWhen?: string;
}

interface Block {
  kind: CatalogControl["kind"];
  /** line index of `[[controls.*]]` */
  start: number;
  /** first line after the block */
  end: number;
  /** line index of `id = "…"` */
  idLine: number;
}

function findBlock(lines: string[], id: string): Block | null {
  let kind: CatalogControl["kind"] | null = null;
  let start = -1;
  let idLine = -1;
  for (const [index, raw] of lines.entries()) {
    const line = raw.trim();
    if (line.startsWith("#") || line === "") {
      continue;
    }
    const block = BLOCK.exec(line);
    if (block !== null || line.startsWith("[")) {
      if (kind !== null && idLine !== -1) {
        return { kind, start, end: index, idLine };
      }
      kind = block === null ? null : (block[1] as CatalogControl["kind"]);
      start = index;
      idLine = -1;
      continue;
    }
    if (kind !== null && ID.exec(line)?.[1] === id) {
      idLine = index;
    }
  }
  return kind !== null && idLine !== -1
    ? { kind, start, end: lines.length, idLine }
    : null;
}

/** A TOML string value: '''multi''', 'literal' or "basic" (with \\ and \" unescaped). */
function readString(value: string): string | undefined {
  const triple = /^'''(.*?)'''/.exec(value);
  if (triple !== null) {
    return triple[1];
  }
  const single = /^'([^']*)'/.exec(value);
  if (single !== null) {
    return single[1];
  }
  const basic = /^"((?:[^"\\]|\\.)*)"/.exec(value);
  return basic === null ? undefined : basic[1].replaceAll(/\\(["\\])/g, "$1");
}

function keyLine(line: string): { key: string; value: string } | null {
  const match = /^([a-z_]+)\s*=(.*)$/.exec(line.trim());
  return match === null ? null : { key: match[1], value: match[2].trim() };
}

/** The editable settings of one control, or null when the catalog doesn't declare it. */
export function readControlFields(
  toml: string,
  id: string,
): ControlFields | null {
  const lines = toml.split(/\r?\n/);
  const block = findBlock(lines, id);
  if (block === null) {
    return null;
  }
  const fields: ControlFields = {
    kind: block.kind,
    enabled: true,
    severity: "medium",
    action: "block",
    hooks: [],
  };
  for (const line of lines.slice(block.start + 1, block.end)) {
    if (line.trim().startsWith("#")) {
      continue;
    }
    const entry = keyLine(line);
    if (entry === null) {
      continue;
    }
    switch (entry.key) {
      case "enabled": {
        fields.enabled = !entry.value.startsWith("false");
        break;
      }
      case "severity":
      case "action": {
        fields[entry.key] = readString(entry.value) ?? fields[entry.key];
        break;
      }
      case "hooks": {
        fields.hooks = [...entry.value.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
        break;
      }
      case "pattern": {
        fields.pattern = readString(entry.value);
        break;
      }
      case "threshold": {
        fields.threshold = Number.parseFloat(entry.value);
        break;
      }
      case "escalate_when": {
        fields.escalateWhen = readString(entry.value);
        break;
      }
    }
  }
  return fields;
}

/** Why these settings can't be saved, or null when they can. */
export function controlFieldsProblem(fields: ControlFields): string | null {
  if (
    !(CONTROL_SEVERITY_VALUES as readonly string[]).includes(fields.severity)
  ) {
    return "Pick a severity.";
  }
  if (!(CONTROL_ACTION_VALUES as readonly string[]).includes(fields.action)) {
    return "Pick an action.";
  }
  if (
    fields.hooks.length === 0 ||
    fields.hooks.some((h) => !(HOOK_VALUES as readonly string[]).includes(h))
  ) {
    return "Pick at least one hook.";
  }
  if (fields.kind === "deterministic") {
    if (fields.pattern === undefined || fields.pattern.trim() === "") {
      return "The pattern can't be empty.";
    }
    if (/[\r\n]/.test(fields.pattern) || fields.pattern.includes("'''")) {
      return "Keep the pattern on one line, without '''.";
    }
  } else {
    if (
      fields.threshold === undefined ||
      !Number.isFinite(fields.threshold) ||
      fields.threshold < 0 ||
      fields.threshold > 1
    ) {
      return "The threshold must be between 0 and 1.";
    }
    if (
      !(ESCALATE_VALUES as readonly string[]).includes(
        fields.escalateWhen ?? "",
      )
    ) {
      return "Pick when the semantic tier runs.";
    }
  }
  return null;
}

/** A regex as a TOML literal string, so backslashes stay as written. */
function literal(value: string): string {
  return value.includes("'") ? `'''${value}'''` : `'${value}'`;
}

/**
 * The catalog with one control's settings replaced. Existing lines are
 * rewritten where they are (trailing comments kept); missing keys go right
 * after the control's `id`. `enabled = true` is the default, so enabling a
 * control removes its `enabled = false` line.
 */
export function editControl(
  toml: string,
  id: string,
  fields: ControlFields,
): { ok: true; value: string } | { ok: false; error: string } {
  const problem = controlFieldsProblem(fields);
  if (problem !== null) {
    return { ok: false, error: problem };
  }
  const eol = toml.includes("\r\n") ? "\r\n" : "\n";
  const lines = toml.split(/\r?\n/);
  const block = findBlock(lines, id);
  if (block === null) {
    return { ok: false, error: `The catalog has no control "${id}".` };
  }
  if (block.kind !== fields.kind) {
    return { ok: false, error: `"${id}" is a ${block.kind} control.` };
  }

  const values = new Map<string, string | null>([
    ["severity", `"${fields.severity}"`],
    ["action", `"${fields.action}"`],
    ["hooks", `[${fields.hooks.map((h) => `"${h}"`).join(", ")}]`],
    ["enabled", fields.enabled ? null : "false"],
  ]);
  if (fields.kind === "deterministic") {
    values.set("pattern", literal(fields.pattern ?? ""));
  } else {
    values.set("threshold", (fields.threshold ?? 0).toFixed(2));
    values.set("escalate_when", `"${fields.escalateWhen ?? "suspicious"}"`);
  }

  const out: string[] = [];
  const seen = new Set<string>();
  for (const [index, line] of lines.entries()) {
    const inside = index > block.start && index < block.end;
    const entry = inside && !line.trim().startsWith("#") ? keyLine(line) : null;
    if (entry === null || !values.has(entry.key)) {
      out.push(line);
      if (index === block.idLine) {
        // placeholder: missing keys are inserted here after the scan
        out.push("\u0000INSERT\u0000");
      }
      continue;
    }
    seen.add(entry.key);
    const next = values.get(entry.key) ?? null;
    if (next === null) {
      continue; // drop `enabled = false`
    }
    const indent = /^\s*/.exec(line)?.[0] ?? "";
    // keep a trailing comment after simple values (not after patterns, which may contain #)
    const comment =
      entry.key === "pattern" ? "" : (/\s+#.*$/.exec(entry.value)?.[0] ?? "");
    out.push(`${indent}${entry.key} = ${next}${comment}`);
  }
  const missing = [...values.entries()]
    .filter(([key, value]) => value !== null && !seen.has(key))
    .map(([key, value]) => `${key} = ${String(value)}`);
  const result = out.flatMap((line) =>
    line === "\u0000INSERT\u0000" ? missing : [line],
  );
  return { ok: true, value: result.join(eol) };
}

// ---------------------------------------------------------------- replacing
//
// Uploading a catalog file replaces every rule. Before it goes to the gateway
// (which does the real validation), check the file's controls and show what
// the swap does to the rules in force.

/** Problems that make a catalog file unfit to upload; empty when it looks fine. */
export function catalogFileProblems(toml: string): string[] {
  const controls = parseCatalogControls(toml);
  const problems: string[] = [];
  if (controls.length === 0) {
    problems.push("The file declares no controls.");
  }
  const seen = new Set<string>();
  for (const control of controls) {
    if (seen.has(control.id)) {
      problems.push(`"${control.id}" is declared more than once.`);
      continue;
    }
    seen.add(control.id);
    const fields = readControlFields(toml, control.id);
    const problem = fields === null ? null : controlFieldsProblem(fields);
    if (problem !== null) {
      problems.push(`${control.id}: ${problem}`);
    }
  }
  return problems;
}

export interface CatalogDiff {
  added: string[];
  removed: string[];
  changed: { id: string; changes: string[] }[];
  unchanged: number;
}

function describeChanges(
  before: ControlFields,
  after: ControlFields,
): string[] {
  const changes: string[] = [];
  if (before.kind !== after.kind) {
    changes.push(`${before.kind} → ${after.kind}`);
  }
  if (before.enabled !== after.enabled) {
    changes.push(after.enabled ? "enabled" : "disabled");
  }
  for (const key of ["severity", "action", "escalateWhen"] as const) {
    if (before[key] !== after[key]) {
      changes.push(`${key} ${before[key] ?? "—"} → ${after[key] ?? "—"}`);
    }
  }
  if (before.hooks.join(",") !== after.hooks.join(",")) {
    changes.push(`hooks ${after.hooks.join(", ") || "—"}`);
  }
  if (before.threshold !== after.threshold) {
    changes.push(
      `threshold ${String(before.threshold ?? "—")} → ${String(after.threshold ?? "—")}`,
    );
  }
  if (before.pattern !== after.pattern) {
    changes.push("pattern changed");
  }
  return changes;
}

/** What replacing `current` with `next` does to each rule, by control id. */
export function diffCatalogs(current: string, next: string): CatalogDiff {
  const before = new Map(
    parseCatalogControls(current).map((c) => [
      c.id,
      readControlFields(current, c.id),
    ]),
  );
  const diff: CatalogDiff = {
    added: [],
    removed: [],
    changed: [],
    unchanged: 0,
  };
  const nextIds = new Set<string>();
  for (const control of parseCatalogControls(next)) {
    if (nextIds.has(control.id)) {
      continue;
    }
    nextIds.add(control.id);
    const old = before.get(control.id);
    const now = readControlFields(next, control.id);
    if (old === undefined || old === null) {
      diff.added.push(control.id);
    } else if (now !== null) {
      const changes = describeChanges(old, now);
      if (changes.length === 0) {
        diff.unchanged += 1;
      } else {
        diff.changed.push({ id: control.id, changes });
      }
    }
  }
  for (const id of before.keys()) {
    if (!nextIds.has(id)) {
      diff.removed.push(id);
    }
  }
  return diff;
}
