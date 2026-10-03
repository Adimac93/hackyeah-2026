import {
  Card,
  ControlSeverityBadge,
  EmptyRow,
  VerdictBadge,
  tableClass,
  tdClass,
  thClass,
} from "@/components/ui";
import { budgetSpend, fmtWindow } from "@/lib/gateway";
import type { Budget, UsageRow } from "@/lib/gateway";
import type { LiveControl, LivePolicy } from "@/lib/gateway-live";

export function Chips({ items, empty }: { items: string[]; empty: string }) {
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

/** Every control the gateway enforces right now, from `GET /policy`. */
export function ControlsTable({ controls }: { controls: LiveControl[] }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-900/60">
      <table className={tableClass}>
        <thead className="border-b border-zinc-800">
          <tr>
            <th className={thClass}>Control</th>
            <th className={thClass}>Hooks</th>
            <th className={thClass}>Severity</th>
            <th className={`${thClass} text-right`}>Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800">
          {controls.length === 0 && (
            <EmptyRow cols={4}>The active policy enables no controls.</EmptyRow>
          )}
          {controls.map((c) => (
            <tr key={c.id}>
              <td className={tdClass}>
                <p className="font-mono text-xs text-zinc-100">{c.id}</p>
                <p className="text-xs text-zinc-500">
                  {c.kind}
                  {c.kind === "semantic"
                    ? ` · ${c.detector ?? "judge"} ≥ ${String(c.threshold ?? "—")}`
                    : ""}
                  {typeof c.feed === "string" ? ` · feed ${c.feed}` : ""}
                </p>
              </td>
              <td className={tdClass}>
                <Chips items={c.hooks} empty="—" />
              </td>
              <td className={tdClass}>
                <ControlSeverityBadge severity={c.severity} />
              </td>
              <td className={`${tdClass} text-right`}>
                <VerdictBadge verdict={c.action} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** `[resources]`: which tables each identity may query through the gateway. */
export function ResourceAccess({
  resources,
}: {
  resources: LivePolicy["resources"];
}) {
  const grants = Object.entries(resources?.grants ?? {});
  return (
    <Card title="Resource access">
      {grants.length === 0 ? (
        <p className="text-sm text-zinc-500">
          No identity may query protected resources (deny-by-default).
        </p>
      ) : (
        <ul className="-my-2 divide-y divide-zinc-800">
          {grants.map(([identity, tables]) => (
            <li
              key={identity}
              className="flex items-center justify-between gap-3 py-2.5"
            >
              <code className="text-xs text-zinc-300">{identity}</code>
              <Chips items={tables} empty="no tables" />
            </li>
          ))}
        </ul>
      )}
      {resources === undefined ? null : (
        <p className="mt-4 text-xs text-zinc-500">
          At most {resources.max_rows} rows per query,{" "}
          {resources.statement_timeout_ms} ms timeout. Rows go to the user,
          never to the model.
        </p>
      )}
    </Card>
  );
}

function limitText(b: Budget): string {
  return [
    b.limit_tokens === null
      ? null
      : `${b.limit_tokens.toLocaleString("en")} tokens`,
    b.limit_usd === null ? null : `$${Number(b.limit_usd).toFixed(2)}`,
    b.limit_requests === null ? null : `${String(b.limit_requests)} requests`,
    b.limit_concurrency === null
      ? null
      : `${String(b.limit_concurrency)} in flight`,
  ]
    .filter(Boolean)
    .join(" / ");
}

/** Budgets are per user: a delegated end user, or an agent under its own slug. */
export function Budgets({
  budgets,
  usage,
  now,
}: {
  budgets: Budget[];
  usage: UsageRow[];
  now: number;
}) {
  return (
    <Card title="Budgets (per user)">
      {budgets.length === 0 ? (
        <p className="text-sm text-zinc-500">No budgets configured.</p>
      ) : (
        <ul className="space-y-4">
          {budgets.map((b) => {
            const spend = budgetSpend(b, usage, now);
            const pct = Math.min(100, (spend.used ?? 0) * 100);
            return (
              <li key={b.id} className="space-y-1.5">
                <div className="flex items-baseline justify-between gap-3 text-sm">
                  <span className="min-w-0 truncate text-zinc-100">
                    {b.scope === "global" ? "Everyone" : b.scope_id}
                    <span className="ml-2 text-xs text-zinc-500">
                      {b.scope} · per {fmtWindow(b.window_secs)} ·{" "}
                      {b.hard ? "hard" : "soft"}
                      {b.enabled ? "" : " · disabled"}
                    </span>
                  </span>
                  <span className="shrink-0 text-xs text-zinc-400 tabular-nums">
                    {spend.tokens.toLocaleString("en")} tokens · {limitText(b)}
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
    </Card>
  );
}
