import Link from "next/link";

import { Card, PageHeader, SeverityBadge, StatusBadge } from "@/components/ui";
import { requireMember } from "@/lib/auth";
import {
  SEVERITIES,
  incidentStats,
  isReviewOverdue,
  triageSort,
} from "@/lib/domain";
import type { Incident, Policy } from "@/lib/domain";
import { fmtDate, timeAgo } from "@/lib/format";

const BAR_COLOR = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-400",
  low: "bg-sky-400",
};

export default async function DashboardPage() {
  const { supabase } = await requireMember();
  const [{ data: incidentRows }, { data: policyRows }] = await Promise.all([
    supabase
      .from("incidents")
      .select("id, title, severity, status, category, detected_at, resolved_at")
      .order("detected_at", { ascending: false })
      .limit(500),
    supabase
      .from("policies")
      .select("id, title, status, review_due, category, version"),
  ]);
  const incidents = (incidentRows ?? []) as Incident[];
  const policies = (policyRows ?? []) as Policy[];

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

  return (
    <>
      <PageHeader
        title="Security overview"
        subtitle="Live posture across incidents and company policy"
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
