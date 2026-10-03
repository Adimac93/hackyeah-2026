import {
  Card,
  ControlSeverityBadge,
  EmptyRow,
  PageHeader,
  tableClass,
  tdClass,
  thClass,
} from "@/components/ui";
import { requireMember } from "@/lib/auth";
import { fmtDateTime, timeAgo } from "@/lib/format";
import { budgetSpend, fmtWindow } from "@/lib/gateway";
import type {
  AttackSignature,
  Budget,
  PolicyVersion,
  Principal,
  UsageRow,
} from "@/lib/gateway";

const DAY_MS = 86_400_000;

function Chips({ items, empty }: { items: string[]; empty: string }) {
  if (items.length === 0) {
    return <span className="text-xs text-zinc-600">{empty}</span>;
  }
  return (
    <span className="flex flex-wrap gap-1">
      {items.map((item) => (
        <code
          key={item}
          className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-300"
        >
          {item}
        </code>
      ))}
    </span>
  );
}

export default async function ControlsPage() {
  const { supabase } = await requireMember();
  // longest budget window is a day; usage older than that never counts
  const since = new Date(Date.now() - DAY_MS).toISOString();

  const [
    { data: principalRows },
    { data: budgetRows },
    { data: usageRows },
    { data: versionRows },
    { data: signatureRows },
  ] = await Promise.all([
    supabase.from("principals").select("*").order("slug"),
    supabase.from("budgets").select("*").order("id"),
    supabase
      .from("usage")
      .select(
        "ts, principal_id, model, prompt_tokens, completion_tokens, cost_usd",
      )
      .gte("ts", since)
      .limit(10_000),
    supabase
      .from("policy_versions")
      .select("id, sha256, source, loaded_at, active, note")
      .order("loaded_at", { ascending: false })
      .limit(20),
    supabase
      .from("attack_signatures")
      .select(
        "id, external_id, source, kind, severity, title, pattern, cve, enabled, synced_at",
      )
      .order("severity", { ascending: false })
      .limit(100),
  ]);
  const principals = (principalRows ?? []) as Principal[];
  const budgets = (budgetRows ?? []) as Budget[];
  const usage = (usageRows ?? []) as UsageRow[];
  const versions = (versionRows ?? []) as PolicyVersion[];
  const signatures = (signatureRows ?? []) as AttackSignature[];
  const now = Date.now();

  return (
    <>
      <PageHeader
        title="Controls"
        subtitle="Who may call the gateway, what they may spend, and which rules are enforced"
      />

      <div className="space-y-6">
        <div className="overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-900/60">
          <table className={tableClass}>
            <thead className="border-b border-zinc-800">
              <tr>
                <th className={thClass}>Principal</th>
                <th className={thClass}>Allowed models</th>
                <th className={thClass}>Allowed tools</th>
                <th className={`${thClass} text-right`}>Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {principals.length === 0 && (
                <EmptyRow cols={4}>No principals registered.</EmptyRow>
              )}
              {principals.map((p) => (
                <tr key={p.id}>
                  <td className={tdClass}>
                    <p className="text-zinc-100">{p.display_name}</p>
                    <p className="text-xs text-zinc-500">
                      {p.slug} · {p.kind}
                    </p>
                  </td>
                  <td className={tdClass}>
                    <Chips items={p.allowed_models} empty="none" />
                  </td>
                  <td className={tdClass}>
                    <Chips items={p.allowed_tools} empty="none" />
                  </td>
                  <td className={`${tdClass} text-right text-xs`}>
                    {p.enabled ? (
                      <span className="text-emerald-400">enabled</span>
                    ) : (
                      <span className="text-zinc-500">disabled</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          <Card title="Budgets">
            {budgets.length === 0 ? (
              <p className="text-sm text-zinc-500">No budgets configured.</p>
            ) : (
              <ul className="space-y-4">
                {budgets.map((b) => {
                  const spend = budgetSpend(b, usage, principals, now);
                  const pct = Math.min(100, (spend.used ?? 0) * 100);
                  const limit = [
                    b.limit_tokens === null
                      ? null
                      : `${b.limit_tokens.toLocaleString("en")} tokens`,
                    b.limit_usd === null
                      ? null
                      : `$${Number(b.limit_usd).toFixed(2)}`,
                  ]
                    .filter(Boolean)
                    .join(" / ");
                  return (
                    <li key={b.id} className="space-y-1.5">
                      <div className="flex items-baseline justify-between gap-3 text-sm">
                        <span className="text-zinc-100">
                          {b.scope === "global" ? "Global" : b.scope_id}
                          <span className="ml-2 text-xs text-zinc-500">
                            {b.scope} · per {fmtWindow(b.window_secs)} ·{" "}
                            {b.hard ? "hard" : "soft"}
                            {b.enabled ? "" : " · disabled"}
                          </span>
                        </span>
                        <span className="text-xs text-zinc-400 tabular-nums">
                          {spend.tokens.toLocaleString("en")} / {limit}
                        </span>
                      </div>
                      <div className="h-2 rounded-full bg-zinc-800">
                        <div
                          className={`h-2 rounded-full ${
                            pct >= 100
                              ? "bg-red-500"
                              : pct >= 80
                                ? "bg-amber-400"
                                : "bg-emerald-500"
                          }`}
                          style={{ width: `${String(pct)}%` }}
                        />
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
            {usage.length === 0 && budgets.length > 0 ? (
              <p className="mt-4 text-xs text-zinc-500">
                No model usage recorded in the last 24h.
              </p>
            ) : null}
          </Card>

          <Card title="Policy versions">
            {versions.length === 0 ? (
              <p className="text-sm text-zinc-500">
                The gateway hasn&apos;t loaded a policy yet.
              </p>
            ) : (
              <ul className="-my-2 divide-y divide-zinc-800">
                {versions.map((v, index) => (
                  <li
                    key={v.id}
                    className="flex items-center justify-between gap-3 py-2.5"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-sm text-zinc-100">
                        #{v.id}{" "}
                        <code className="text-zinc-400">
                          {v.sha256.slice(0, 12)}
                        </code>
                        {index === 0 && v.active ? (
                          <span className="ml-2 text-xs text-emerald-400">
                            current
                          </span>
                        ) : null}
                      </p>
                      <p
                        className="truncate text-xs text-zinc-500"
                        title={fmtDateTime(v.loaded_at)}
                      >
                        {v.note ?? v.source.split("\n")[0]} · loaded{" "}
                        {timeAgo(v.loaded_at)}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>

        <Card title={`Attack signatures (${String(signatures.length)})`}>
          {signatures.length === 0 ? (
            <p className="text-sm text-zinc-500">
              No signatures synced yet. The gateway populates these from its
              external threat feed.
            </p>
          ) : (
            <ul className="-my-2 divide-y divide-zinc-800">
              {signatures.map((s) => (
                <li key={s.id} className="flex items-center gap-3 py-2.5">
                  <ControlSeverityBadge severity={s.severity} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm text-zinc-100">{s.title}</p>
                    <p className="text-xs text-zinc-500">
                      {s.source} · {s.external_id}
                      {s.cve === null ? "" : ` · ${s.cve}`} · {s.kind}
                    </p>
                  </div>
                  <span
                    className={`text-xs ${s.enabled ? "text-emerald-400" : "text-zinc-500"}`}
                  >
                    {s.enabled ? "enabled" : "disabled"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
