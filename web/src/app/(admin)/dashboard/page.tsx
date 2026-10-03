import Link from "next/link";

import { Card, PageHeader, VerdictBadge } from "@/components/ui";
import { requireMember } from "@/lib/auth";
import { timeAgo } from "@/lib/format";
import { SECURITY_STATUSES, fmtMicros, gatewayStats } from "@/lib/gateway";
import type { GatewayEvent, Principal, SecurityStatus } from "@/lib/gateway";
import type { RiskReport } from "@/lib/gateway-live";
import { gatewayFetch } from "@/lib/gateway-live-fetch";

const DAY_MS = 86_400_000;

type InterventionRow = Pick<
  GatewayEvent,
  "id" | "ts" | "hook" | "channel" | "tool" | "model" | "verdict"
> & { principals: Pick<Principal, "display_name"> | null };

const STATUS_TONE: Record<SecurityStatus, string> = {
  secure: "text-emerald-400",
  flagged: "text-amber-300",
  redacted: "text-violet-300",
  blocked: "text-red-400",
};

export default async function DashboardPage() {
  const { supabase } = await requireMember();
  const since = new Date(Date.now() - DAY_MS).toISOString();
  const [
    { data: eventRows },
    { data: interventionRows },
    { data: statusRows },
    risk,
  ] = await Promise.all([
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
    supabase
      .from("activity")
      .select("status")
      .gte("ts", since)
      .limit(10_000)
      .overrideTypes<{ status: SecurityStatus }[], { merge: false }>(),
    gatewayFetch<RiskReport>("/admin/risk?limit=5"),
  ]);
  const gateway = gatewayStats(
    (eventRows ?? []) as Pick<GatewayEvent, "verdict" | "latency">[],
  );
  const interventions = interventionRows ?? [];
  const byStatus = Object.fromEntries(
    SECURITY_STATUSES.map((status) => [
      status,
      (statusRows ?? []).filter((row) => row.status === status).length,
    ]),
  ) as Record<SecurityStatus, number>;
  const riskyUsers = risk.ok ? risk.data.users.filter((u) => u.score > 0) : [];

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
        subtitle="Live posture across the AI gateway, its users and their requests"
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

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Security status · last 24h">
          <ul className="space-y-2.5">
            {SECURITY_STATUSES.map((status) => (
              <li key={status}>
                <Link
                  href={`/activity?status=${status}`}
                  className="flex items-center justify-between text-sm hover:opacity-80"
                >
                  <span className="text-zinc-400 capitalize">{status}</span>
                  <span
                    className={`font-semibold tabular-nums ${STATUS_TONE[status]}`}
                  >
                    {byStatus[status]}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </Card>

        <Card
          className="lg:col-span-2"
          title="Highest-risk users"
          actions={
            <Link
              href="/risk"
              className="text-xs text-emerald-400 hover:underline"
            >
              All users →
            </Link>
          }
        >
          {risk.ok && riskyUsers.length === 0 ? (
            <p className="text-sm text-zinc-500">
              No user has recent violations. 🎉
            </p>
          ) : risk.ok ? (
            <ul className="-my-2 divide-y divide-zinc-800">
              {riskyUsers.map((u) => (
                <li
                  key={u.user}
                  className="flex items-center justify-between gap-3 py-2.5"
                >
                  <Link
                    href={`/risk?q=${encodeURIComponent(u.user)}`}
                    className="min-w-0 truncate text-sm text-zinc-100 hover:underline"
                  >
                    {u.user}
                  </Link>
                  <span className="shrink-0 text-xs text-zinc-400 tabular-nums">
                    {u.score.toFixed(2)} · {u.status}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-zinc-500">
              Risk scores unavailable: {risk.error}
            </p>
          )}
        </Card>
      </div>
    </>
  );
}
