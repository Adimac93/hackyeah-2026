import Link from "next/link";

import { LiveRefresh } from "@/components/live-refresh";
import {
  ControlSeverityBadge,
  EmptyRow,
  PageHeader,
  SecurityStatusBadge,
  tableClass,
  tdClass,
  thClass,
} from "@/components/ui";
import {
  ACTIVITY_SELECT,
  activityQueryString,
  applyActivityFilters,
  distinctUsers,
  hasActivityFilters,
  parseActivityFilters,
  worstSeverity,
} from "@/lib/activity";
import type { ActivityRow } from "@/lib/activity";
import { requireMember } from "@/lib/auth";
import { fmtDateTime, timeAgo } from "@/lib/format";
import {
  CHANNELS,
  SECURITY_STATUSES,
  VERDICTS,
  fmtMicros,
  overheadUs,
} from "@/lib/gateway";
import type { Principal } from "@/lib/gateway";
import { supabaseEnv } from "@/lib/supabase/env";

const FILTER_CLASS =
  "rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm text-zinc-200 focus:border-emerald-500 focus:outline-none";

export default async function ActivityPage({
  searchParams,
}: PageProps<"/activity">) {
  const { supabase } = await requireMember();
  const filters = parseActivityFilters(await searchParams);
  const { verdict, channel, principal, status, user } = filters;

  const query = applyActivityFilters(
    supabase
      .from("activity")
      .select(ACTIVITY_SELECT)
      .order("ts", { ascending: false })
      .limit(200),
    filters,
  );

  const [{ data }, { data: principalRows }, { data: userRows }] =
    await Promise.all([
      query,
      supabase
        .from("principals")
        .select("id, slug, display_name")
        .order("slug"),
      // recent attributions are enough to fill the user picker
      supabase
        .from("events")
        .select("end_user")
        .not("end_user", "is", null)
        .order("ts", { ascending: false })
        .limit(5000),
    ]);
  const events = (data ?? []) as ActivityRow[];
  const { url, key } = supabaseEnv();
  const liveEnv = { url, anonKey: key };
  const principals = (principalRows ?? []) as Pick<
    Principal,
    "id" | "slug" | "display_name"
  >[];
  const users = distinctUsers(
    (userRows ?? []) as { end_user: string | null }[],
  );
  // keep a filtered user selectable even if they fell out of the recent window
  if (user !== "" && !users.includes(user)) {
    users.unshift(user);
  }
  const exportHref = `/activity/export${activityQueryString(filters)}`;

  return (
    <>
      <PageHeader
        eyebrow="Audit trail"
        title="Activity"
        subtitle="Every request the AI gateway intercepted, newest first and live. Append-only and hash-chained."
        actions={
          <a
            href={exportHref}
            download
            className="inline-flex items-center justify-center gap-2 rounded-md border border-zinc-700 px-3.5 py-2 text-[13px] font-semibold tracking-[0.02em] text-zinc-200 transition hover:-translate-y-px hover:bg-zinc-900"
            title="PDF of the events matching the current filters (up to 5000)"
          >
            Export PDF
          </a>
        }
      />

      <LiveRefresh {...liveEnv} />
      <form className="mb-4 flex flex-wrap items-center gap-2">
        <select name="user" defaultValue={user} className={FILTER_CLASS}>
          <option value="">All users</option>
          {users.map((u) => (
            <option key={u} value={u}>
              {u}
            </option>
          ))}
        </select>
        <select name="status" defaultValue={status} className={FILTER_CLASS}>
          <option value="">Any security status</option>
          {SECURITY_STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select name="verdict" defaultValue={verdict} className={FILTER_CLASS}>
          <option value="">All verdicts</option>
          {VERDICTS.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
        <select name="channel" defaultValue={channel} className={FILTER_CLASS}>
          <option value="">All channels</option>
          {CHANNELS.map((c) => (
            <option key={c} value={c}>
              {c.toUpperCase()}
            </option>
          ))}
        </select>
        <select
          name="principal"
          defaultValue={principal}
          className={FILTER_CLASS}
        >
          <option value="">All principals</option>
          {principals.map((p) => (
            <option key={p.id} value={p.id}>
              {p.display_name}
            </option>
          ))}
        </select>
        <button className="inline-flex items-center justify-center gap-2 rounded-md border border-zinc-700 px-3.5 py-2 text-[13px] font-semibold tracking-[0.02em] text-zinc-200 transition hover:-translate-y-px hover:bg-zinc-900">
          Filter
        </button>
        {hasActivityFilters(filters) ? (
          <Link
            href="/activity"
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
              <th className={thClass}>Status</th>
              <th className={thClass}>Request</th>
              <th className={`${thClass} hidden md:table-cell`}>User</th>
              <th className={thClass}>Detections</th>
              <th className={`${thClass} hidden text-right sm:table-cell`}>
                Overhead
              </th>
              <th className={`${thClass} text-right`}>When</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {events.length === 0 && (
              <EmptyRow cols={6}>
                No gateway events match these filters.
              </EmptyRow>
            )}
            {events.map((event) => {
              const worst = worstSeverity(event.detections);
              return (
                <tr key={event.id} className="hover:bg-zinc-800/40">
                  <td className={tdClass}>
                    <SecurityStatusBadge status={event.status} />
                  </td>
                  <td className={tdClass}>
                    <Link
                      href={`/activity/${String(event.id)}`}
                      className="font-medium text-zinc-100 hover:underline"
                    >
                      {event.tool ?? event.model ?? "—"}
                    </Link>
                    <p className="text-xs text-zinc-500">
                      {event.channel.toUpperCase()} ·{" "}
                      {event.hook.replace("_", " ")}
                    </p>
                  </td>
                  <td
                    className={`${tdClass} hidden text-zinc-400 md:table-cell`}
                  >
                    {event.end_user ?? (
                      <span className="text-zinc-600">Unknown</span>
                    )}
                    <p className="text-xs text-zinc-600">
                      via {event.principals?.display_name ?? "unregistered"}
                    </p>
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
                    className={`${tdClass} hidden text-right text-xs text-zinc-400 tabular-nums sm:table-cell`}
                  >
                    {fmtMicros(overheadUs(event.latency))}
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
      {events.length === 200 ? (
        <p className="mt-3 text-xs text-zinc-500">
          Showing the latest 200 events. Narrow the filters to see older ones.
        </p>
      ) : null}
    </>
  );
}
