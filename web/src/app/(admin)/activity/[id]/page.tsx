import Link from "next/link";
import { notFound } from "next/navigation";

import {
  Card,
  ControlSeverityBadge,
  PageHeader,
  VerdictBadge,
} from "@/components/ui";
import { requireMember } from "@/lib/auth";
import { fmtDateTime } from "@/lib/format";
import { fmtMicros, overheadUs, shortHash } from "@/lib/gateway";
import type {
  Detection,
  GatewayEvent,
  PolicyVersion,
  Principal,
} from "@/lib/gateway";

const STAGES = [
  ["deterministic_us", "Deterministic controls"],
  ["semantic_us", "Semantic controls"],
  ["upstream_us", "Upstream call"],
] as const;

type EventDetail = GatewayEvent & {
  principals: Pick<Principal, "slug" | "display_name" | "kind"> | null;
  policy_versions: Pick<PolicyVersion, "id" | "sha256" | "loaded_at"> | null;
};

export default async function ActivityEventPage({
  params,
}: PageProps<"/activity/[id]">) {
  const { id } = await params;
  if (!/^\d+$/.test(id)) {
    notFound();
  }
  const { supabase } = await requireMember();

  const [{ data: event }, { data: detectionRows }] = await Promise.all([
    supabase
      .from("events")
      .select(
        "*, principals(slug, display_name, kind), policy_versions(id, sha256, loaded_at)",
      )
      .eq("id", id)
      .maybeSingle<EventDetail>(),
    supabase.from("detections").select("*").eq("event_id", id).order("id"),
  ]);
  if (event === null) {
    notFound();
  }
  const detections = (detectionRows ?? []) as Detection[];

  // the other hooks of the same request (e.g. tool_call → tool_result)
  const { data: traceRows } = await supabase
    .from("events")
    .select("id, ts, hook, verdict, tool, model")
    .eq("trace_id", event.trace_id)
    .order("ts");
  const trace = (traceRows ?? []) as Pick<
    GatewayEvent,
    "id" | "ts" | "hook" | "verdict" | "tool" | "model"
  >[];

  const total = STAGES.reduce(
    (sum, [key]) => sum + (event.latency[key] ?? 0),
    0,
  );

  return (
    <>
      <PageHeader
        title={`${event.tool ?? event.model ?? "Request"} · ${event.hook.replace("_", " ")}`}
        subtitle={`Event #${String(event.id)} · ${fmtDateTime(event.ts)}`}
        actions={
          <Link
            href="/activity"
            className="text-sm text-zinc-400 hover:text-zinc-200"
          >
            ← All activity
          </Link>
        }
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card
            title={`Detections (${String(detections.length)})`}
            actions={<VerdictBadge verdict={event.verdict} />}
          >
            {detections.length === 0 ? (
              <p className="text-sm text-zinc-500">
                No control fired. The request passed through unchanged.
              </p>
            ) : (
              <ul className="-my-2 divide-y divide-zinc-800">
                {detections.map((d) => (
                  <li key={d.id} className="space-y-2 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <ControlSeverityBadge severity={d.severity} />
                      <VerdictBadge verdict={d.action} />
                      <code className="text-sm text-zinc-100">
                        {d.control_id}
                      </code>
                      <span className="text-xs text-zinc-500">
                        {d.kind}
                        {d.score === null
                          ? ""
                          : ` · score ${d.score.toFixed(2)}`}
                      </span>
                    </div>
                    {Object.keys(d.evidence).length > 0 && (
                      <pre className="overflow-x-auto rounded-lg bg-zinc-950 p-3 text-xs text-zinc-400">
                        {JSON.stringify(d.evidence, null, 2)}
                      </pre>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title="Latency">
            <ul className="space-y-3">
              {STAGES.map(([key, label]) => {
                const us = event.latency[key] ?? 0;
                return (
                  <li key={key} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-zinc-400">{label}</span>
                      <span className="text-zinc-300 tabular-nums">
                        {fmtMicros(us)}
                      </span>
                    </div>
                    <div className="h-2 rounded-full bg-zinc-800">
                      <div
                        className={`h-2 rounded-full ${key === "upstream_us" ? "bg-zinc-500" : "bg-emerald-500"}`}
                        style={{
                          width: `${String(total === 0 ? 0 : (us / total) * 100)}%`,
                        }}
                      />
                    </div>
                  </li>
                );
              })}
            </ul>
            <p className="mt-4 text-xs text-zinc-500">
              Gateway overhead: {fmtMicros(overheadUs(event.latency))}
            </p>
          </Card>
        </div>

        <div className="space-y-6">
          <Card title="Request">
            <dl className="space-y-3 text-sm">
              {[
                [
                  "Principal",
                  event.principals === null
                    ? "Unknown"
                    : `${event.principals.display_name} (${event.principals.kind})`,
                ],
                ["Channel", event.channel.toUpperCase()],
                ["Hook", event.hook.replace("_", " ")],
                ["Tool", event.tool ?? "—"],
                ["Model", event.model ?? "—"],
                [
                  "Policy version",
                  event.policy_versions === null
                    ? "—"
                    : `#${String(event.policy_versions.id)} · ${event.policy_versions.sha256.slice(0, 12)}`,
                ],
              ].map(([label, value]) => (
                <div key={label} className="flex justify-between gap-4">
                  <dt className="text-zinc-500">{label}</dt>
                  <dd className="truncate text-right text-zinc-200">{value}</dd>
                </div>
              ))}
            </dl>
          </Card>

          <Card title="Trace">
            <ol className="space-y-2 text-sm">
              {trace.map((t) => (
                <li key={t.id} className="flex items-center gap-2">
                  <VerdictBadge verdict={t.verdict} />
                  {t.id === event.id ? (
                    <span className="text-zinc-100">
                      {t.hook.replace("_", " ")}
                    </span>
                  ) : (
                    <Link
                      href={`/activity/${String(t.id)}`}
                      className="text-zinc-400 hover:text-zinc-200 hover:underline"
                    >
                      {t.hook.replace("_", " ")}
                    </Link>
                  )}
                  <span className="ml-auto text-xs text-zinc-600">#{t.id}</span>
                </li>
              ))}
            </ol>
            <p className="mt-3 truncate text-xs text-zinc-600">
              trace {event.trace_id}
            </p>
          </Card>

          <Card title="Integrity">
            <dl className="space-y-2 font-mono text-xs">
              <div className="flex justify-between gap-4">
                <dt className="text-zinc-500">prev</dt>
                <dd className="text-zinc-400">
                  {shortHash(event.prev_hash, 16)}
                </dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-zinc-500">hash</dt>
                <dd className="text-zinc-200">{shortHash(event.hash, 16)}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-zinc-500">payload</dt>
                <dd className="text-zinc-400">
                  {event.payload_sha256 === null
                    ? "—"
                    : event.payload_sha256.slice(0, 16)}
                </dd>
              </div>
            </dl>
            <p className="mt-3 text-xs text-zinc-500">
              Each event hashes the previous one, so a deleted or edited row
              breaks the chain. Only the payload hash is stored, never the
              content.
            </p>
          </Card>
        </div>
      </div>
    </>
  );
}
