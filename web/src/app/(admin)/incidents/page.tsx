import Link from "next/link";

import {
  ButtonLink,
  EmptyRow,
  PageHeader,
  SeverityBadge,
  StatusBadge,
  tableClass,
  tdClass,
  thClass,
} from "@/components/ui";
import { requireMember } from "@/lib/auth";
import {
  INCIDENT_STATUSES,
  SEVERITIES,
  canWrite,
  triageSort,
} from "@/lib/domain";
import type { Incident, TeamMember } from "@/lib/domain";
import { timeAgo } from "@/lib/format";

const FILTER_CLASS =
  "rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm text-zinc-200 focus:border-emerald-500 focus:outline-none";

export default async function IncidentsPage({
  searchParams,
}: PageProps<"/incidents">) {
  const { supabase, member } = await requireMember();
  const sp = await searchParams;
  const status = typeof sp.status === "string" ? sp.status : "active";
  const severity = typeof sp.severity === "string" ? sp.severity : "";
  const q = typeof sp.q === "string" ? sp.q.trim() : "";

  let query = supabase.from("incidents").select("*").limit(500);
  if (status === "active") {
    query = query.neq("status", "resolved");
  } else if ((INCIDENT_STATUSES as readonly string[]).includes(status)) {
    query = query.eq("status", status);
  }
  if ((SEVERITIES as readonly string[]).includes(severity)) {
    query = query.eq("severity", severity);
  }
  if (q) {
    query = query.ilike(
      "title",
      `%${q.replaceAll(/[%_\\]/g, String.raw`\$&`)}%`,
    );
  }

  const [{ data }, { data: team }] = await Promise.all([
    query,
    supabase.from("team_members").select("user_id, email, full_name"),
  ]);
  const incidents = triageSort((data ?? []) as Incident[]);
  const names = new Map(
    ((team ?? []) as TeamMember[]).map((m) => [
      m.user_id,
      m.full_name ?? m.email,
    ]),
  );

  return (
    <>
      <PageHeader
        title="Incidents"
        subtitle="Detect, triage and resolve security incidents"
        actions={
          canWrite(member.role) && (
            <ButtonLink href="/incidents/new">Report incident</ButtonLink>
          )
        }
      />

      <form className="mb-4 flex flex-wrap items-center gap-2">
        <input
          name="q"
          defaultValue={q}
          placeholder="Search title…"
          className={`${FILTER_CLASS} w-56`}
        />
        <select name="status" defaultValue={status} className={FILTER_CLASS}>
          <option value="active">Unresolved</option>
          <option value="all">All statuses</option>
          {INCIDENT_STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          name="severity"
          defaultValue={severity}
          className={FILTER_CLASS}
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <button className="rounded-lg border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800">
          Filter
        </button>
        {q || severity || status !== "active" ? (
          <Link
            href="/incidents"
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
              <th className={thClass}>Severity</th>
              <th className={thClass}>Incident</th>
              <th className={thClass}>Status</th>
              <th className={`${thClass} hidden md:table-cell`}>Assignee</th>
              <th className={`${thClass} text-right`}>Detected</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {incidents.length === 0 && (
              <EmptyRow cols={5}>No incidents match these filters.</EmptyRow>
            )}
            {incidents.map((index) => (
              <tr key={index.id} className="hover:bg-zinc-800/40">
                <td className={tdClass}>
                  <SeverityBadge severity={index.severity} />
                </td>
                <td className={tdClass}>
                  <Link
                    href={`/incidents/${index.id}`}
                    className="font-medium text-zinc-100 hover:underline"
                  >
                    {index.title}
                  </Link>
                  <p className="text-xs text-zinc-500">
                    {index.category} · {index.source}
                  </p>
                </td>
                <td className={tdClass}>
                  <StatusBadge status={index.status} />
                </td>
                <td className={`${tdClass} hidden text-zinc-400 md:table-cell`}>
                  {index.assignee_id === null ? (
                    <span className="text-zinc-600">Unassigned</span>
                  ) : (
                    (names.get(index.assignee_id) ?? "—")
                  )}
                </td>
                <td
                  className={`${tdClass} text-right text-xs whitespace-nowrap text-zinc-500`}
                >
                  {timeAgo(index.detected_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
