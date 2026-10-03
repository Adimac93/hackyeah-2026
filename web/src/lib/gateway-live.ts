// Live state read straight from the running gateway (not from Supabase): what it
// enforces right now (`GET /policy`), its 24h report (`GET /metrics`), and
// liveness (`GET /`, `GET /health`). Shapes mirror gateway/src/admin/mod.rs and
// gateway/src/metrics.rs. Pure types + helpers here; fetching is in
// gateway-live-fetch.ts so this file stays unit-testable.
import type { ControlAction, ControlSeverity, Hook } from "./gateway.ts";

export interface GatewayInfo {
  service: string;
  version: string;
  description: string;
  endpoints?: Record<string, string>;
  policy: {
    version: string;
    deterministic_controls: number;
    semantic_controls: number;
    fail_mode: string;
  };
}

export interface GatewayHealth {
  status: string;
  database: string;
}

export interface LiveControl {
  id: string;
  kind: "deterministic" | "semantic";
  action: ControlAction;
  severity: ControlSeverity;
  hooks: Hook[];
  feed?: string | null;
  detector?: string;
  threshold?: number;
  escalate_when?: string[];
  fail_mode?: string;
}

export interface LivePolicy {
  version: string;
  version_id?: number | null;
  source: string;
  profile?: string | null;
  on_detect: string;
  fail_mode: string;
  models?: { allowed: string[]; denied: string[] };
  signature_feed?: {
    source: string;
    version: string;
    signatures: number;
  } | null;
  risk?: {
    window_secs: number;
    escalate_at: number | null;
    block_at: number | null;
  };
  runaway?: {
    window_secs: number;
    max_tool_calls: number | null;
    max_identical_calls: number | null;
    max_depth: number | null;
  };
  mcp_servers?: { name: string; enabled: boolean; pinned_tools: number }[];
  /** Newer builds list every control; the deployed one only counts them. */
  controls: LiveControl[] | { deterministic: number; semantic: number };
  /** Deployed build's signature feed (newer builds send `signature_feed`). */
  signatures?: {
    enabled: boolean;
    source: string;
    path?: string;
    refresh_secs?: number;
  };
}

export interface MetricsReport {
  window_hours: number;
  generated_at: string;
  totals: {
    events: number;
    allowed: number;
    redacted: number;
    blocked: number;
    detections: number;
    tokens: number;
  };
  by_control: {
    control_id: string;
    kind: string;
    severity: string;
    hits: number;
  }[];
  by_principal: {
    slug: string;
    events: number;
    blocked: number;
    tokens: number;
  }[];
  latency: {
    deterministic_p50_us: number;
    deterministic_p95_us: number;
    semantic_p50_us: number;
    semantic_p95_us: number;
    /** percent, 0–100 */
    escalation_rate: number;
  };
  budgets: {
    scope: string;
    scope_id: string | null;
    limit_tokens: number | null;
    used_tokens: number;
    hard: boolean;
  }[];
  incidents: {
    at: string;
    hook: string;
    channel: string;
    principal: string | null;
    tool: string | null;
    control_id: string;
    severity: string;
    evidence: string;
  }[];
  chain: {
    events_checked: number;
    intact: boolean;
    first_broken: number | null;
  };
  policy_version: string | null;
}

export type Live<T> = { ok: true; data: T } | { ok: false; error: string };

/** The `error.message` of a gateway refusal body, if it has one. */
export function gatewayMessage(body: unknown): string | null {
  if (typeof body !== "object" || body === null || !("error" in body)) {
    return null;
  }
  const error = (body as { error: unknown }).error;
  if (typeof error !== "object" || error === null || !("message" in error)) {
    return null;
  }
  const message = (error as { message: unknown }).message;
  return typeof message === "string" && message !== "" ? message : null;
}

/** Why a gateway call failed, in words an analyst can act on. */
export function liveError(status: number, body?: unknown): string {
  const detail = gatewayMessage(body);
  switch (status) {
    case 401: {
      return `The gateway didn't accept your session${detail === null ? "" : ` (${detail})`}. Sign out and in again.`;
    }
    case 403: {
      return "Your security team role doesn't allow this on the gateway.";
    }
    case 404: {
      return "This gateway build doesn't expose that endpoint.";
    }
    default: {
      return detail === null
        ? `The gateway answered HTTP ${String(status)}.`
        : `The gateway answered HTTP ${String(status)}: ${detail}`;
    }
  }
}

/** Share of the window's traffic that was blocked, 0–1. */
export function blockRate(totals: MetricsReport["totals"]): number {
  return totals.events === 0 ? 0 : totals.blocked / totals.events;
}

/** Used share of a token budget, 0–1; null when the budget has no token cap. */
export function budgetUsed(
  budget: MetricsReport["budgets"][number],
): number | null {
  if (budget.limit_tokens === null || budget.limit_tokens <= 0) {
    return null;
  }
  return budget.used_tokens / budget.limit_tokens;
}

/**
 * The gateway's report timestamps: RFC 3339, or Postgres-style
 * `2026-10-03 20:20:34` / `… UTC`. Zone-less values are UTC — `new Date()`
 * would read them as local time.
 */
export function parseGatewayTime(value: string): string {
  const trimmed = value.trim().replace(/\s+UTC$/i, "");
  const iso = trimmed.includes("T") ? trimmed : trimmed.replace(" ", "T");
  const zoned = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(iso) ? iso : `${iso}Z`;
  const date = new Date(zoned);
  return Number.isNaN(date.getTime()) ? value : date.toISOString();
}
