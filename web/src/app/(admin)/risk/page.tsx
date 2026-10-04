import Link from "next/link";

import {
  EmptyRow,
  PageHeader,
  tableClass,
  tdClass,
  thClass,
} from "@/components/ui";
import { requireMember } from "@/lib/auth";
import { fmtDateTime, timeAgo } from "@/lib/format";
import { fmtWindow } from "@/lib/gateway";
import type { RiskReport, UserRisk } from "@/lib/gateway-live";
import { gatewayFetch } from "@/lib/gateway-live-fetch";

const STATUS_STYLE: Record<UserRisk["status"], string> = {
  normal: "text-emerald-400",
  escalate: "text-amber-300",
  block: "text-red-400",
};

const STATUS_LABEL: Record<UserRisk["status"], string> = {
  normal: "normal",
  escalate: "escalated to semantic checks",
  block: "blocked",
};

export default async function RiskPage({ searchParams }: PageProps<"/risk">) {
  await requireMember();
  const { q: rawQuery } = await searchParams;
  const q = typeof rawQuery === "string" ? rawQuery.trim() : "";
  const report = await gatewayFetch<RiskReport>(
    `/admin/risk${q === "" ? "" : `?q=${encodeURIComponent(q)}`}`,
  );

  return (
    <>
      <PageHeader
        eyebrow="History-aware controls"
        title="User risk"
        subtitle={
          report.ok
            ? `Sum of recent violations per user over the last ${fmtWindow(report.data.window_secs)}. At ${String(report.data.escalate_at ?? "—")} every request is escalated to the semantic tier; at ${String(report.data.block_at ?? "—")} the user is blocked.`
            : "Each user's score from recent blocked and flagged requests."
        }
      />

      <form className="mb-4 flex flex-wrap items-center gap-2">
        <input
          type="search"
          name="q"
          defaultValue={q}
          placeholder="Search users…"
          aria-label="Search users"
          className="w-full max-w-sm rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-emerald-500 focus:outline-none"
        />
        <button className="inline-flex items-center justify-center gap-2 rounded-md border border-zinc-700 px-3.5 py-2 text-[13px] font-semibold tracking-[0.02em] text-zinc-200 transition hover:-translate-y-px hover:bg-zinc-900">
          Search
        </button>
        {q === "" ? null : (
          <Link
            href="/risk"
            className="text-sm text-zinc-500 hover:text-zinc-300"
          >
            Reset
          </Link>
        )}
      </form>

      {report.ok ? (
        <div className="overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-900/60">
          <table className={tableClass}>
            <thead className="border-b border-zinc-800">
              <tr>
                <th className={thClass}>User</th>
                <th className={`${thClass} text-right`}>Score</th>
                <th className={thClass}>Status</th>
                <th className={`${thClass} hidden text-right sm:table-cell`}>
                  Violations
                </th>
                <th className={`${thClass} text-right`}>Last seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {report.data.users.length === 0 && (
                <EmptyRow cols={5}>
                  {q === ""
                    ? "No user has sent traffic through the gateway yet."
                    : "No user matches that search."}
                </EmptyRow>
              )}
              {report.data.users.map((u) => (
                <tr key={u.user}>
                  <td className={tdClass}>
                    <p className="text-zinc-100">{u.user}</p>
                    <p className="text-xs text-zinc-500">
                      via {u.principals.join(", ") || "—"}
                    </p>
                  </td>
                  <td
                    className={`${tdClass} text-right font-medium tabular-nums ${STATUS_STYLE[u.status]}`}
                  >
                    {u.score.toFixed(2)}
                  </td>
                  <td
                    className={`${tdClass} text-xs ${STATUS_STYLE[u.status]}`}
                  >
                    {STATUS_LABEL[u.status]}
                  </td>
                  <td
                    className={`${tdClass} hidden text-right text-xs text-zinc-400 tabular-nums sm:table-cell`}
                    title={
                      u.last_violation === null
                        ? undefined
                        : `last ${fmtDateTime(u.last_violation)}`
                    }
                  >
                    {u.violations}
                  </td>
                  <td
                    className={`${tdClass} text-right text-xs whitespace-nowrap text-zinc-500`}
                    title={fmtDateTime(u.last_seen)}
                  >
                    {timeAgo(u.last_seen)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-300">
          Couldn&apos;t read risk scores from the gateway: {report.error}
        </p>
      )}
    </>
  );
}
