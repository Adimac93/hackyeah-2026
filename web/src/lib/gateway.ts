// AI gateway data (written by the gateway, read-only here). Pure types + helpers, unit-testable.

export const VERDICTS = ["allow", "redact", "block"] as const;
export const CONTROL_ACTIONS = ["allow", "flag", "redact", "block"] as const;
export const HOOKS = [
  "prompt_in",
  "response_out",
  "tool_call",
  "tool_result",
] as const;
export const CHANNELS = ["llm", "mcp", "a2a"] as const;
/** `activity.status`: what the gateway did to the request, from hash-chained fields. */
export const SECURITY_STATUSES = [
  "secure",
  "flagged",
  "redacted",
  "blocked",
] as const;
export const CONTROL_SEVERITIES = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
] as const;

export type Verdict = (typeof VERDICTS)[number];
export type ControlAction = (typeof CONTROL_ACTIONS)[number];
export type Hook = (typeof HOOKS)[number];
export type Channel = (typeof CHANNELS)[number];
export type SecurityStatus = (typeof SECURITY_STATUSES)[number];
export type ControlSeverity = (typeof CONTROL_SEVERITIES)[number];

/** Per-stage microseconds, e.g. {"deterministic_us": 180, "semantic_us": 41200, "upstream_us": 910}. */
export type Latency = Partial<Record<string, number>>;

export interface Principal {
  id: string;
  slug: string;
  display_name: string;
  kind: string;
  allowed_models: string[];
  allowed_tools: string[];
  enabled: boolean;
  created_at: string;
}

export interface Detection {
  id: number;
  event_id: number;
  control_id: string;
  kind: "deterministic" | "semantic";
  severity: ControlSeverity;
  score: number | null;
  action: ControlAction;
  evidence: Record<string, unknown>;
  created_at: string;
}

export interface GatewayEvent {
  id: number;
  ts: string;
  trace_id: string;
  hook: Hook;
  channel: Channel;
  principal_id: string | null;
  /** the user the request is attributed to: delegated end user or principal slug */
  end_user: string | null;
  model: string | null;
  tool: string | null;
  verdict: Verdict;
  policy_version_id: number | null;
  latency: Latency;
  payload_sha256: string | null;
  prev_hash: string | null;
  hash: string;
}

export interface Budget {
  id: number;
  /** `user`: a delegated end user, or a principal acting for no one under its slug */
  scope: "global" | "user" | "model";
  scope_id: string | null;
  window_secs: number;
  /** Postgres numeric: may arrive as a string */
  limit_usd: number | string | null;
  limit_tokens: number | null;
  limit_requests: number | null;
  limit_concurrency: number | null;
  hard: boolean;
  enabled: boolean;
  created_at: string;
}

export interface UsageRow {
  ts: string;
  principal_id: string | null;
  /** the user the spend is attributed to */
  end_user: string | null;
  model: string;
  prompt_tokens: number;
  completion_tokens: number;
  cost_usd: number | string;
}

export interface PolicyVersion {
  id: number;
  sha256: string;
  source: string;
  loaded_at: string;
  active: boolean;
  note: string | null;
  /** set for versions imported through the console / `POST /admin/policy` */
  diff_summary?: string | null;
}

export interface AttackSignature {
  id: number;
  external_id: string;
  source: string;
  kind: "deterministic" | "semantic";
  severity: ControlSeverity;
  title: string;
  pattern: string | null;
  cve: string | null;
  enabled: boolean;
  synced_at: string;
}

/** Time the gateway itself added (controls only, not the upstream call). */
export function overheadUs(latency: Latency): number {
  return (latency.deterministic_us ?? 0) + (latency.semantic_us ?? 0);
}

/** Nearest-rank percentile; null for an empty list. */
export function percentile(values: number[], p: number): number | null {
  if (values.length === 0) {
    return null;
  }
  const sorted = values.toSorted((a, b) => a - b);
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(sorted.length, Math.max(1, rank)) - 1];
}

export interface GatewayStats {
  total: number;
  byVerdict: Record<Verdict, number>;
  /** share of events not allowed through unchanged, 0..1 */
  interventionRate: number;
  p50OverheadUs: number | null;
  p95OverheadUs: number | null;
  /** events where the semantic tier ran, 0..1 — the rest were settled by cheap deterministic checks */
  semanticShare: number;
}

export function gatewayStats(
  events: Pick<GatewayEvent, "verdict" | "latency">[],
): GatewayStats {
  const byVerdict: Record<Verdict, number> = { allow: 0, redact: 0, block: 0 };
  for (const event of events) {
    byVerdict[event.verdict] += 1;
  }
  const overheads = events.map((event) => overheadUs(event.latency));
  const semantic = events.filter(
    (event) => (event.latency.semantic_us ?? 0) > 0,
  );
  const total = events.length;
  return {
    total,
    byVerdict,
    interventionRate: total === 0 ? 0 : (total - byVerdict.allow) / total,
    p50OverheadUs: percentile(overheads, 50),
    p95OverheadUs: percentile(overheads, 95),
    semanticShare: total === 0 ? 0 : semantic.length / total,
  };
}

export interface BudgetSpend {
  tokens: number;
  usd: number;
  /** fraction of the tighter limit used, 0..∞ (null when the budget has no limit) */
  used: number | null;
}

/** Spend that counts against a budget within its rolling window. */
export function budgetSpend(
  budget: Budget,
  usage: UsageRow[],
  now = Date.now(),
): BudgetSpend {
  const since = now - budget.window_secs * 1000;
  let tokens = 0;
  let usd = 0;
  for (const u of usage) {
    if (new Date(u.ts).getTime() < since) {
      continue;
    }
    if (budget.scope === "user" && u.end_user !== budget.scope_id) {
      continue;
    }
    if (budget.scope === "model" && u.model !== budget.scope_id) {
      continue;
    }
    tokens += u.prompt_tokens + u.completion_tokens;
    usd += Number(u.cost_usd);
  }

  const ratios = [
    budget.limit_tokens === null ? null : tokens / budget.limit_tokens,
    budget.limit_usd === null ? null : usd / Number(budget.limit_usd),
  ].filter((r): r is number => r !== null && Number.isFinite(r));
  return {
    tokens,
    usd,
    used: ratios.length === 0 ? null : Math.max(...ratios),
  };
}

/** 41200 → "41.2 ms", 180 → "180 µs". */
export function fmtMicros(us: number | null | undefined): string {
  if (us === null || us === undefined) {
    return "—";
  }
  if (us < 1000) {
    return `${String(Math.round(us))} µs`;
  }
  const ms = us / 1000;
  return `${ms < 10 ? ms.toFixed(1) : String(Math.round(ms))} ms`;
}

/** 3600 → "1h", 86400 → "24h", 90 → "90s". */
export function fmtWindow(secs: number): string {
  if (secs % 3600 === 0) {
    return `${String(secs / 3600)}h`;
  }
  if (secs % 60 === 0) {
    return `${String(secs / 60)}m`;
  }
  return `${String(secs)}s`;
}

/** Short form of a hex hash as PostgREST returns bytea (`\x0123…`). */
export function shortHash(hash: string | null, length = 12): string {
  if (hash === null) {
    return "—";
  }
  return hash.replace(/^\\x/, "").slice(0, length);
}

/** Gateway's `POST /admin/policy` takes the whole catalog; keep uploads well under the action limit. */
export const MAX_POLICY_BYTES = 256 * 1024;

/** Cheap checks before sending a catalog to the gateway, which does the real validation. */
export function checkPolicyUpload(
  text: string,
): { ok: true; value: string } | { ok: false; error: string } {
  if (text.trim() === "") {
    return { ok: false, error: "The file is empty." };
  }
  if (new TextEncoder().encode(text).length > MAX_POLICY_BYTES) {
    return { ok: false, error: "The catalog is larger than 256 KB." };
  }
  if (text.includes("\u0000")) {
    return { ok: false, error: "That doesn't look like a text TOML file." };
  }
  if (!/^\s*schema_version\s*=/m.test(text)) {
    return {
      ok: false,
      error:
        "Missing `schema_version` — upload a complete control catalog, not a fragment.",
    };
  }
  return { ok: true, value: text };
}

/** What `POST /admin/policy` answers when it accepts a catalog. */
export interface PolicySaveResult {
  accepted: boolean;
  changed: boolean;
  version: string;
  version_id: number;
  /** control-level diff: `+ added`, `- removed or disabled`, `~ changed` */
  diff: string[];
}

/** Human-readable outcome of an accepted save; never echoes the catalog back. */
export function describePolicySave(result: PolicySaveResult): string {
  if (!result.changed) {
    return "Saved — identical to the active policy, nothing changed.";
  }
  const changes = result.diff.length === 0 ? "" : ` ${result.diff.join("; ")}`;
  return `Saved and active as version #${String(result.version_id)}.${changes}`;
}

/** Formats `GET /admin/audit/export` serves. */
export const EXPORT_FORMATS = ["csv", "json"] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

/** The export's optional column groups (`include=`), as the dialog lists them. */
export const EXPORT_GROUPS = [
  {
    id: "identity",
    label: "Identity",
    hint: "principal (agent or app) and the end user",
  },
  { id: "target", label: "Target", hint: "model and MCP tool" },
  {
    id: "detections",
    label: "Detections",
    hint: "controls that fired and what they did",
  },
  { id: "usage", label: "Usage", hint: "tokens and cost" },
  { id: "performance", label: "Performance", hint: "per-stage latency" },
  { id: "policy", label: "Policy", hint: "catalog version that decided" },
  {
    id: "integrity",
    label: "Integrity",
    hint: "payload hash and chain hashes, to verify the file",
  },
] as const;
export type ExportGroup = (typeof EXPORT_GROUPS)[number]["id"];

/** The gateway's cap on one export; it clamps `limit` to this itself. */
export const MAX_EXPORT_ROWS = 10_000;

/**
 * Path for the gateway's audit export from the export dialog's fields. Values
 * pass through as they are (URL-encoded, so none can add parameters of its
 * own) and the gateway validates them. The repeated `include` checkboxes
 * become the one comma-separated list the gateway reads.
 */
export function auditExportPath(search: URLSearchParams): string {
  const query = new URLSearchParams();
  for (const [key, value] of search) {
    if (key !== "include" && value.trim() !== "") {
      query.set(key, value.trim());
    }
  }
  if (search.has("include")) {
    query.set("include", search.getAll("include").filter(Boolean).join(","));
  }
  return `/admin/audit/export?${query.toString()}`;
}

/** Download name for an export: `audit-log-2026-10-04.csv`. */
export function auditExportFilename(format: ExportFormat, now: Date): string {
  return `audit-log-${now.toISOString().slice(0, 10)}.${format}`;
}
