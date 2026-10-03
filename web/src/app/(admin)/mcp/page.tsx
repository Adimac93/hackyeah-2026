import Link from "next/link";

import {
  Card,
  ControlSeverityBadge,
  EmptyRow,
  PageHeader,
  VerdictBadge,
  tableClass,
  tdClass,
  thClass,
} from "@/components/ui";
import { requireMember } from "@/lib/auth";
import { fmtDateTime, timeAgo } from "@/lib/format";
import { VERDICTS } from "@/lib/gateway";
import type {
  ControlSeverity,
  Detection,
  GatewayEvent,
  Principal,
} from "@/lib/gateway";
import { effectiveStatus, splitTool, toolSummary } from "@/lib/mcp";
import type { AccessRequestRow, AccessStatus } from "@/lib/mcp";

const FILTER_CLASS =
  "rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm text-zinc-200 focus:border-emerald-500 focus:outline-none";

const MCP_HOOKS = ["tool_call", "tool_result"] as const;

/** Enough history for the per-tool totals without paging the whole audit log. */
const SUMMARY_WINDOW = 1000;
const LIST_LIMIT = 200;

const SEVERITY_RANK: Record<ControlSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const ACCESS_STYLE: Record<AccessStatus, string> = {
  pending: "bg-amber-500/10 text-amber-300 ring-amber-500/30",
  approved: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30",
  denied: "bg-red-500/10 text-red-300 ring-red-500/30",
  expired: "bg-zinc-700/30 text-zinc-500 ring-zinc-600/30",
};

type PrincipalName = Pick<Principal, "slug" | "display_name">;

type EventRow = GatewayEvent & {
  principals: PrincipalName | null;
  detections: Pick<Detection, "id" | "severity" | "control_id">[];
};

type RequestRow = AccessRequestRow & { principals: PrincipalName | null };

function AccessBadge({ status }: { status: AccessStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset ${ACCESS_STYLE[status]}`}
    >
      {status}
    </span>
  );
}

function ToolName({ tool }: { tool: string }) {
  const { server, name } = splitTool(tool);
  return (
    <span className="font-mono text-sm">
      <span className="text-zinc-500">{server}/</span>
      <span className="text-zinc-100">{name}</span>
    </span>
  );
}

export default async function McpPage({ searchParams }: PageProps<"/mcp">) {
  const { supabase } = await requireMember();
  const sp = await searchParams;
  const verdict = typeof sp.verdict === "string" ? sp.verdict : "";
  const hook = typeof sp.hook === "string" ? sp.hook : "";
  const tool = typeof sp.tool === "string" ? sp.tool : "";

  let listQuery = supabase
    .from("events")
    .select(
      "*, principals(slug, display_name), detections(id, severity, control_id)",
    )
    .eq("channel", "mcp")
    .order("ts", { ascending: false })
    .limit(LIST_LIMIT);
  if ((VERDICTS as readonly string[]).includes(verdict)) {
    listQuery = listQuery.eq("verdict", verdict);
  }
  if ((MCP_HOOKS as readonly string[]).includes(hook)) {
    listQuery = listQuery.eq("hook", hook);
  }
  if (tool) {
    listQuery = listQuery.eq("tool", tool);
  }

  const [{ data: listRows }, { data: summaryRows }, { data: requestRows }] =
    await Promise.all([
      listQuery,
      supabase
        .from("events")
        .select("tool, hook, verdict, ts")
        .eq("channel", "mcp")
        .order("ts", { ascending: false })
        .limit(SUMMARY_WINDOW),
      supabase
        .from("access_requests")
        .select("*, principals(slug, display_name)")
        .order("requested_at", { ascending: false })
        .limit(100),
    ]);

  const events = (listRows ?? []) as EventRow[];
  const summaryEvents = (summaryRows ?? []) as Pick<
    GatewayEvent,
    "tool" | "hook" | "verdict" | "ts"
  >[];
  const tools = toolSummary(summaryEvents);
  const requests = ((requestRows ?? []) as RequestRow[]).map((r) => ({
    ...r,
    shown: effectiveStatus(r),
  }));

  const calls = tools.reduce((n, t) => n + t.calls, 0);
  const blocked = summaryEvents.filter((e) => e.verdict === "block").length;
  const redacted = summaryEvents.filter((e) => e.verdict === "redact").length;
  const pending = requests.filter((r) => r.shown === "pending").length;
  const activeGrants = requests.filter((r) => r.shown === "approved").length;

  const tiles = [
    {
      label: "Tool calls",
      value: calls,
      tone: "text-zinc-50",
      sub: `${String(tools.length)} distinct tools`,
    },
    {
      label: "Blocked",
      value: blocked,
      tone: blocked ? "text-red-400" : "text-zinc-50",
      sub: "calls and results",
    },
    {
      label: "Redacted",
      value: redacted,
      tone: redacted ? "text-amber-300" : "text-zinc-50",
      sub: "calls and results",
    },
    {
      label: "Access requests",
      value: pending,
      tone: pending ? "text-amber-300" : "text-zinc-50",
      sub: `pending · ${String(activeGrants)} active grants`,
    },
  ];

  return (
    <>
      <PageHeader
        title="MCP"
        subtitle="Every tool call and tool result the gateway brokered, and every access request agents raised."
      />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {tiles.map((t) => (
          <div
            key={t.label}
            className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5"
          >
            <p className="text-xs font-medium tracking-wide text-zinc-500 uppercase">
              {t.label}
            </p>
            <p className={`mt-2 text-3xl font-semibold tabular-nums ${t.tone}`}>
              {t.value}
            </p>
            <p className="mt-1 text-xs text-zinc-500">{t.sub}</p>
          </div>
        ))}
      </div>
      {summaryEvents.length === SUMMARY_WINDOW ? (
        <p className="mt-2 text-xs text-zinc-500">
          Totals cover the latest {SUMMARY_WINDOW} MCP events.
        </p>
      ) : null}

      <Card className="mt-6" title="Tools">
        <div className="-mx-5 -my-5 overflow-x-auto">
          <table className={tableClass}>
            <thead className="border-b border-zinc-800">
              <tr>
                <th className={thClass}>Tool</th>
                <th className={`${thClass} text-right`}>Calls</th>
                <th className={`${thClass} text-right`}>Blocked</th>
                <th className={`${thClass} hidden text-right sm:table-cell`}>
                  Redacted
                </th>
                <th className={`${thClass} text-right`}>Last seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {tools.length === 0 && (
                <EmptyRow cols={5}>
                  No MCP traffic has gone through the gateway yet.
                </EmptyRow>
              )}
              {tools.map((t) => (
                <tr key={t.tool} className="hover:bg-zinc-800/40">
                  <td className={tdClass}>
                    <Link
                      href={`/mcp?tool=${encodeURIComponent(t.tool)}#calls`}
                      className="hover:underline"
                    >
                      <ToolName tool={t.tool} />
                    </Link>
                  </td>
                  <td className={`${tdClass} text-right tabular-nums`}>
                    {t.calls}
                  </td>
                  <td
                    className={`${tdClass} text-right tabular-nums ${t.byVerdict.block ? "text-red-400" : "text-zinc-500"}`}
                  >
                    {t.byVerdict.block}
                  </td>
                  <td
                    className={`${tdClass} hidden text-right tabular-nums sm:table-cell ${t.byVerdict.redact ? "text-amber-300" : "text-zinc-500"}`}
                  >
                    {t.byVerdict.redact}
                  </td>
                  <td
                    className={`${tdClass} text-right text-xs whitespace-nowrap text-zinc-500`}
                    title={fmtDateTime(t.lastSeen)}
                  >
                    {timeAgo(t.lastSeen)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card className="mt-6" title="Access requests">
        <div className="-mx-5 -my-5 overflow-x-auto">
          <table className={tableClass}>
            <thead className="border-b border-zinc-800">
              <tr>
                <th className={thClass}>Status</th>
                <th className={thClass}>Request</th>
                <th className={`${thClass} hidden md:table-cell`}>Decision</th>
                <th className={`${thClass} text-right`}>Requested</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {requests.length === 0 && (
                <EmptyRow cols={4}>No agent has asked for a tool yet.</EmptyRow>
              )}
              {requests.map((r) => (
                <tr key={r.id} className="align-top hover:bg-zinc-800/40">
                  <td className={tdClass}>
                    <AccessBadge status={r.shown} />
                  </td>
                  <td className={tdClass}>
                    <ToolName tool={r.tool} />
                    <span className="ml-2 text-xs text-zinc-500">
                      for {r.principals?.display_name ?? "unknown principal"} ·{" "}
                      {r.ttl_minutes} min
                    </span>
                    <p className="mt-1 max-w-xl text-xs break-words text-zinc-400">
                      {r.reason}
                    </p>
                  </td>
                  <td
                    className={`${tdClass} hidden text-xs text-zinc-400 md:table-cell`}
                  >
                    {r.decided_by === null ? (
                      <span className="text-zinc-600">—</span>
                    ) : (
                      <>
                        <p>{r.decided_by}</p>
                        {r.shown === "approved" && r.expires_at !== null ? (
                          <p className="text-zinc-500">
                            until {fmtDateTime(r.expires_at)}
                          </p>
                        ) : null}
                        {r.note ? (
                          <p className="text-zinc-500">“{r.note}”</p>
                        ) : null}
                      </>
                    )}
                  </td>
                  <td
                    className={`${tdClass} text-right text-xs whitespace-nowrap text-zinc-500`}
                    title={fmtDateTime(r.requested_at)}
                  >
                    {timeAgo(r.requested_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="mt-8 mb-3 flex items-baseline justify-between" id="calls">
        <h2 className="text-sm font-semibold text-zinc-300">
          Tool calls and results
        </h2>
      </div>

      <form
        className="mb-4 flex flex-wrap items-center gap-2"
        action="/mcp#calls"
      >
        <select name="verdict" defaultValue={verdict} className={FILTER_CLASS}>
          <option value="">All verdicts</option>
          {VERDICTS.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
        <select name="hook" defaultValue={hook} className={FILTER_CLASS}>
          <option value="">Calls and results</option>
          {MCP_HOOKS.map((h) => (
            <option key={h} value={h}>
              {h.replace("_", " ")}
            </option>
          ))}
        </select>
        <select name="tool" defaultValue={tool} className={FILTER_CLASS}>
          <option value="">All tools</option>
          {tools.map((t) => (
            <option key={t.tool} value={t.tool}>
              {t.tool}
            </option>
          ))}
        </select>
        <button className="rounded-lg border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800">
          Filter
        </button>
        {verdict || hook || tool ? (
          <Link
            href="/mcp#calls"
            className="text-sm text-zinc-500 hover:text-zinc-300"
          >
            Reset
          </Link>
        ) : null}
      </form>

      <div className="overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-900/60">
        <table className={tableClass}>
          <thead className="border-b border-zinc-800">
            <tr>
              <th className={thClass}>Verdict</th>
              <th className={thClass}>Tool</th>
              <th className={`${thClass} hidden md:table-cell`}>Principal</th>
              <th className={thClass}>Detections</th>
              <th className={`${thClass} text-right`}>When</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {events.length === 0 && (
              <EmptyRow cols={5}>No MCP events match these filters.</EmptyRow>
            )}
            {events.map((event) => {
              const worst = event.detections.reduce<ControlSeverity | null>(
                (worstSoFar, d) =>
                  worstSoFar === null ||
                  SEVERITY_RANK[d.severity] > SEVERITY_RANK[worstSoFar]
                    ? d.severity
                    : worstSoFar,
                null,
              );
              return (
                <tr key={event.id} className="hover:bg-zinc-800/40">
                  <td className={tdClass}>
                    <VerdictBadge verdict={event.verdict} />
                  </td>
                  <td className={tdClass}>
                    <Link
                      href={`/activity/${String(event.id)}`}
                      className="hover:underline"
                    >
                      {event.tool === null ? (
                        <span className="text-zinc-500">—</span>
                      ) : (
                        <ToolName tool={event.tool} />
                      )}
                    </Link>
                    <p className="text-xs text-zinc-500">
                      {event.hook.replace("_", " ")}
                    </p>
                  </td>
                  <td
                    className={`${tdClass} hidden text-zinc-400 md:table-cell`}
                  >
                    {event.principals?.display_name ?? (
                      <span className="text-zinc-600">Unknown</span>
                    )}
                  </td>
                  <td className={tdClass}>
                    {worst === null ? (
                      <span className="text-xs text-zinc-600">—</span>
                    ) : (
                      <span className="flex items-center gap-2">
                        <ControlSeverityBadge severity={worst} />
                        <span className="text-xs text-zinc-500">
                          {event.detections.length === 1
                            ? event.detections[0].control_id
                            : `${String(event.detections.length)} controls`}
                        </span>
                      </span>
                    )}
                  </td>
                  <td
                    className={`${tdClass} text-right text-xs whitespace-nowrap text-zinc-500`}
                    title={fmtDateTime(event.ts)}
                  >
                    {timeAgo(event.ts)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {events.length === LIST_LIMIT ? (
        <p className="mt-3 text-xs text-zinc-500">
          Showing the latest {LIST_LIMIT} events. Narrow the filters to see
          older ones.
        </p>
      ) : null}
    </>
  );
}
