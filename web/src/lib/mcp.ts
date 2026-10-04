// MCP traffic as the gateway recorded it (read-only here). Pure types + helpers, unit-testable.
import type { GatewayEvent, Verdict } from "./gateway.ts";

export const ACCESS_STATUSES = [
  "pending",
  "approved",
  "denied",
  "expired",
] as const;
export type AccessStatus = (typeof ACCESS_STATUSES)[number];

/** A row of `access_requests`: an agent asking a human for a tool or table it lacks. */
export interface AccessRequestRow {
  id: string;
  principal_id: string;
  /** exactly one of `tool` and `resource` (a table) is set */
  tool: string | null;
  resource: string | null;
  /** the end user the grant covers */
  end_user: string;
  reason: string;
  ttl_minutes: number;
  status: AccessStatus;
  requested_at: string;
  decided_at: string | null;
  decided_by: string | null;
  note: string | null;
  expires_at: string | null;
}

/** The gateway federates servers as `<server>__<tool>`; anything without the separator is its own. */
export function splitTool(tool: string): { server: string; name: string } {
  const at = tool.indexOf("__");
  if (at <= 0 || at + 2 >= tool.length) {
    return { server: "gateway", name: tool };
  }
  return { server: tool.slice(0, at), name: tool.slice(at + 2) };
}

export interface ToolSummary {
  tool: string;
  server: string;
  name: string;
  /** tool_call events: each is one invocation attempt */
  calls: number;
  byVerdict: Record<Verdict, number>;
  lastSeen: string;
}

/**
 * Per-tool totals over MCP events, busiest first. Calls count only `tool_call`;
 * verdicts count every hook, so a clean call with a redacted result shows both.
 */
export function toolSummary(
  events: Pick<GatewayEvent, "tool" | "hook" | "verdict" | "ts">[],
): ToolSummary[] {
  const byTool = new Map<string, ToolSummary>();
  for (const event of events) {
    if (event.tool === null) {
      continue;
    }
    let row = byTool.get(event.tool);
    if (row === undefined) {
      row = {
        tool: event.tool,
        ...splitTool(event.tool),
        calls: 0,
        byVerdict: { allow: 0, redact: 0, block: 0 },
        lastSeen: event.ts,
      };
      byTool.set(event.tool, row);
    }
    if (event.hook === "tool_call") {
      row.calls += 1;
    }
    row.byVerdict[event.verdict] += 1;
    if (Date.parse(event.ts) > Date.parse(row.lastSeen)) {
      row.lastSeen = event.ts;
    }
  }
  return [...byTool.values()].toSorted(
    (a, b) => b.calls - a.calls || a.tool.localeCompare(b.tool),
  );
}

/** An approved grant past `expires_at` no longer opens the tool, even before the gateway marks it expired. */
export function effectiveStatus(
  row: Pick<AccessRequestRow, "status" | "expires_at">,
  now = Date.now(),
): AccessStatus {
  if (row.status === "approved" && row.expires_at !== null) {
    return Date.parse(row.expires_at) <= now ? "expired" : "approved";
  }
  return row.status;
}
