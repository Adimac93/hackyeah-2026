import Link from "next/link";

import {
  Card,
  PageHeader,
  SeverityBadge,
  StatusBadge,
  VerdictBadge,
} from "@/components/ui";
import { requireMember } from "@/lib/auth";
import {
  SEVERITIES,
  incidentStats,
  isReviewOverdue,
  triageSort,
} from "@/lib/domain";
import type { Incident, Policy } from "@/lib/domain";
import { fmtDate, timeAgo } from "@/lib/format";
import { fmtMicros, gatewayStats } from "@/lib/gateway";
import type { GatewayEvent, Principal } from "@/lib/gateway";

const DAY_MS = 86_400_000;

type InterventionRow = Pick<
  GatewayEvent,
  "id" | "ts" | "hook" | "channel" | "tool" | "model" | "verdict"
> & { principals: Pick<Principal, "display_name"> | null };

const BAR_COLOR = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-400",
  low: "bg-sky-400",
};

export default async function DashboardPage() {
  const { supabase } = await requireMember();
  const since = new Date(Date.now() - DAY_MS).toISOString();
  const [
    { data: incidentRows },
    { data: policyRows },
    { data: eventRows },
    { data: interventionRows },
  ] = await Promise.all([
    supabase
      .from("incidents")
      .select("id, title, severity, status, category, detected_at, resolved_at")
      .order("detected_at", { ascending: false })
      .limit(500),
    supabase
      .from("policies")
      .select("id, title, status, review_due, category, version"),
    supabase
      .from("events")
      .select("verdict, latency")
      .gte("ts", since)
      .limit(10_000),
    supabase
      .from("events")
      .select(
        "id, ts, hook, channel, tool, model, verdict, principals(display_name)",
      )
      .neq("verdict", "allow")
      .order("ts", { ascending: false })
      .limit(5)
      .overrideTypes<InterventionRow[], { merge: false }>(),
  ]);
  const incidents = (incidentRows ?? []) as Incident[];
  const policies = (policyRows ?? []) as Policy[];
  const gateway = gatewayStats(
    (eventRows ?? []) as Pick<GatewayEvent, "verdict" | "latency">[],
  );
  const interventions = interventionRows ?? [];

  const stats = incidentStats(incidents);
  const urgent = stats.bySeverity.critical + stats.bySeverity.high;
  const activePolicies = policies.filter((p) => p.status === "active");
  const overdue = activePolicies.filter((p) => isReviewOverdue(p));
  const queue = triageSort(
    incidents.filter((index) => index.status !== "resolved"),
  ).slice(0, 6);
  const maxBar = Math.max(1, ...SEVERITIES.map((s) => stats.bySeverity[s]));

  const tiles = [
    {
      label: "Open incidents",
      value: stats.open,
      tone: stats.open ? "text-zinc-50" : "text-emerald-400",
    },
    {
      label: "Critical + high",
      value: urgent,
      tone: urgent ? "text-red-400" : "text-emerald-400",
    },
    {
      label: "Mean time to resolve",
      value: stats.mttrHours === null ? "—" : `${String(stats.mttrHours)}h`,
      tone: "text-zinc-50",
    },
    {
      label: "Active policies",
      value: activePolicies.length,
      tone: "text-zinc-50",
      sub:
        overdue.length > 0
          ? `${String(overdue.length)} overdue for review`
          : "all reviews current",
    },
  ];

  const gatewayTiles = [
    { label: "Requests", value: gateway.total, tone: "text-zinc-50" },
    {
      label: "Blocked",
      value: gateway.byVerdict.block,
      tone: gateway.byVerdict.block ? "text-red-400" : "text-zinc-50",
      sub: `${String(gateway.byVerdict.redact)} redacted`,
    },
    {
      label: "Intervention rate",
      value: `${String(Math.round(gateway.interventionRate * 100))}%`,
      tone: "text-zinc-50",
    },
    {
      label: "p95 overhead",
      value: fmtMicros(gateway.p95OverheadUs),
      tone: "text-zinc-50",
      sub: `p50 ${fmtMicros(gateway.p50OverheadUs)} · ${String(Math.round(gateway.semanticShare * 100))}% escalated to semantic`,
    },
  ];

  return (
    <>
      <PageHeader
        title="Security overview"
        subtitle="Live posture across the AI gateway, incidents and company policy"
      />

      <div className="mb-3 flex items-baseline justify-between">
        <h2 className="text-sm font-semibold text-zinc-300">
          AI gateway · last 24h
        </h2>
        <Link
          href="/activity"
          className="text-xs text-emerald-400 hover:underline"
        >
          All activity →
        </Link>
      </div>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {gatewayTiles.map((t) => (
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
            {t.sub === undefined ? null : (
              <p className="mt-1 text-xs text-zinc-500">{t.sub}</p>
            )}
          </div>
        ))}
      </div>

      <Card className="mt-6 mb-8" title="Latest interventions">
        {interventions.length === 0 ? (
          <p className="text-sm text-zinc-500">
            The gateway hasn&apos;t blocked or redacted anything yet.
          </p>
        ) : (
          <ul className="-my-2 divide-y divide-zinc-800">
            {interventions.map((event) => (
              <li key={event.id}>
                <Link
                  href={`/activity/${String(event.id)}`}
                  className="flex items-center gap-3 py-3 hover:opacity-80"
                >
                  <VerdictBadge verdict={event.verdict} />
                  <span className="min-w-0 flex-1 truncate text-sm text-zinc-100">
                    {event.tool ?? event.model ?? "—"}
                    <span className="ml-2 text-xs text-zinc-500">
                      {event.channel.toUpperCase()} ·{" "}
                      {event.hook.replace("_", " ")}
                    </span>
                  </span>
                  <span className="hidden text-xs text-zinc-400 sm:block">
                    {event.principals?.display_name ?? "Unknown"}
                  </span>
                  <span className="w-16 text-right text-xs text-zinc-500">
                    {timeAgo(event.ts)}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <h2 className="mb-3 text-sm font-semibold text-zinc-300">
        Incidents & policy
      </h2>

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
            {t.sub === undefined ? null : (
              <p
                className={`mt-1 text-xs ${overdue.length > 0 ? "text-amber-400" : "text-zinc-500"}`}
              >
                {t.sub}
              </p>
            )}
          </div>
        ))}
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Card
          className="lg:col-span-2"
          title="Triage queue"
          actions={
            <Link
              href="/incidents"
              className="text-xs text-emerald-400 hover:underline"
            >
              All incidents →
            </Link>
          }
        >
          {queue.length === 0 ? (
            <p className="py-6 text-center text-sm text-zinc-500">
              No open incidents. 🎉
            </p>
          ) : (
            <ul className="-my-2 divide-y divide-zinc-800">
              {queue.map((index) => (
                <li key={index.id}>
                  <Link
                    href={`/incidents/${index.id}`}
                    className="flex items-center gap-3 py-3 hover:opacity-80"
                  >
                    <SeverityBadge severity={index.severity} />
                    <span className="min-w-0 flex-1 truncate text-sm text-zinc-100">
                      {index.title}
                    </span>
                    <StatusBadge status={index.status} />
                    <span className="hidden w-16 text-right text-xs text-zinc-500 sm:block">
                      {timeAgo(index.detected_at)}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Open by severity">
          <ul className="space-y-3">
            {SEVERITIES.toReversed().map((s) => (
              <li key={s} className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="text-zinc-400 capitalize">{s}</span>
                  <span className="text-zinc-300 tabular-nums">
                    {stats.bySeverity[s]}
                  </span>
                </div>
                <div className="h-2 rounded-full bg-zinc-800">
                  <div
                    className={`h-2 rounded-full ${BAR_COLOR[s]}`}
                    style={{
                      width: `${String((stats.bySeverity[s] / maxBar) * 100)}%`,
                    }}
                  />
                </div>
              </li>
            ))}
          </ul>
          <p className="mt-5 text-xs text-zinc-500">
            {stats.resolvedLast30d} resolved in the last 30 days
          </p>
        </Card>
      </div>

      <Card
        className="mt-6"
        title="Policies due for review"
        actions={
          <Link
            href="/policies"
            className="text-xs text-emerald-400 hover:underline"
          >
            All policies →
          </Link>
        }
      >
        {overdue.length === 0 ? (
          <p className="text-sm text-zinc-500">
            Every active policy is within its review window.
          </p>
        ) : (
          <ul className="divide-y divide-zinc-800">
            {overdue.map((p) => (
              <li
                key={p.id}
                className="flex items-center justify-between gap-4 py-2.5"
              >
                <Link
                  href={`/policies/${p.id}`}
                  className="text-sm text-zinc-100 hover:underline"
                >
                  {p.title} <span className="text-zinc-500">v{p.version}</span>
                </Link>
                <span className="text-xs text-amber-400">
                  due {fmtDate(p.review_due)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
