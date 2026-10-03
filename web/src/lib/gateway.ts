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
  scope: "global" | "principal" | "model";
  scope_id: string | null;
  window_secs: number;
  /** Postgres numeric: may arrive as a string */
  limit_usd: number | string | null;
  limit_tokens: number | null;
  hard: boolean;
  enabled: boolean;
  created_at: string;
}

export interface UsageRow {
  ts: string;
  principal_id: string | null;
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

/** Imported versions keep their TOML in the database and can be downloaded again. */
export function isUploadedVersion(source: string): boolean {
  return source.startsWith("uploaded:");
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
  principals: Pick<Principal, "id" | "slug">[],
  now = Date.now(),
): BudgetSpend {
  const since = now - budget.window_secs * 1000;
  const principalId =
    budget.scope === "principal"
      ? (principals.find((p) => p.slug === budget.scope_id)?.id ?? null)
      : null;

  let tokens = 0;
  let usd = 0;
  for (const u of usage) {
    if (new Date(u.ts).getTime() < since) {
      continue;
    }
    if (budget.scope === "principal" && u.principal_id !== principalId) {
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

/** Human-readable outcome of `POST /admin/policy`; never echoes the catalog back. */
export function describePolicyUpload(
  status: number,
  body: unknown,
): { ok: true; message: string } | { ok: false; error: string } {
  const record =
    typeof body === "object" && body !== null
      ? (body as Record<string, unknown>)
      : {};
  if (status === 200 && record.accepted === true) {
    const diff = typeof record.diff === "string" ? record.diff : "";
    return {
      ok: true,
      message:
        record.changed === false
          ? "Imported — identical to the active policy, nothing changed."
          : `Imported and active. ${diff}`.trim(),
    };
  }
  if (status === 422) {
    const detail =
      typeof record.message === "string" ? record.message : "invalid catalog";
    return {
      ok: false,
      error: `The gateway rejected the catalog: ${detail}. The active policy is unchanged.`,
    };
  }
  if (status === 401 || status === 403) {
    return {
      ok: false,
      error:
        "The gateway refused the admin key. Check GATEWAY_ADMIN_KEY (a principal with role security_admin).",
    };
  }
  if (status === 503) {
    return {
      ok: false,
      error:
        "The gateway can't persist policies right now (no database). The active policy is unchanged.",
    };
  }
  return {
    ok: false,
    error: `The gateway answered HTTP ${String(status)}. The active policy is unchanged.`,
  };
}
