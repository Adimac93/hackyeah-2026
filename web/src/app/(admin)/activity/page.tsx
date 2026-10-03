import Link from "next/link";

import {
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
import { CHANNELS, VERDICTS, fmtMicros, overheadUs } from "@/lib/gateway";
import type {
  ControlSeverity,
  Detection,
  GatewayEvent,
  Principal,
} from "@/lib/gateway";

const FILTER_CLASS =
  "rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-1.5 text-sm text-zinc-200 focus:border-emerald-500 focus:outline-none";

const SEVERITY_RANK: Record<ControlSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

type EventRow = GatewayEvent & {
  principals: Pick<Principal, "slug" | "display_name"> | null;
  detections: Pick<Detection, "id" | "severity" | "control_id">[];
};

export default async function ActivityPage({
  searchParams,
}: PageProps<"/activity">) {
  const { supabase } = await requireMember();
  const sp = await searchParams;
  const verdict = typeof sp.verdict === "string" ? sp.verdict : "";
  const channel = typeof sp.channel === "string" ? sp.channel : "";
  const principal = typeof sp.principal === "string" ? sp.principal : "";

  let query = supabase
    .from("events")
    .select(
      "*, principals(slug, display_name), detections(id, severity, control_id)",
    )
    .order("ts", { ascending: false })
    .limit(200);
  if ((VERDICTS as readonly string[]).includes(verdict)) {
    query = query.eq("verdict", verdict);
  }
  if ((CHANNELS as readonly string[]).includes(channel)) {
    query = query.eq("channel", channel);
  }
  if (principal) {
    query = query.eq("principal_id", principal);
  }

  const [{ data }, { data: principalRows }] = await Promise.all([
    query,
    supabase.from("principals").select("id, slug, display_name").order("slug"),
  ]);
  const events = (data ?? []) as EventRow[];
  const principals = (principalRows ?? []) as Pick<
    Principal,
    "id" | "slug" | "display_name"
  >[];

  return (
    <>
      <PageHeader
        title="Activity"
        subtitle="Every request the AI gateway intercepted, newest first. Append-only and hash-chained."
      />

      <form className="mb-4 flex flex-wrap items-center gap-2">
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
        <button className="rounded-lg border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800">
          Filter
        </button>
        {verdict || channel || principal ? (
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
              <th className={thClass}>Verdict</th>
              <th className={thClass}>Request</th>
              <th className={`${thClass} hidden md:table-cell`}>Principal</th>
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
