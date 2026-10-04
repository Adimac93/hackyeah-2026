import type { JSX, ReactNode } from "react";

import {
  Card,
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
import { CONTROL_SEVERITIES, fmtMicros, fmtWindow } from "@/lib/gateway";
import type { ControlSeverity } from "@/lib/gateway";
import { blockRate, budgetUsed, parseGatewayTime } from "@/lib/gateway-live";
import type { Live } from "@/lib/gateway-live";
import { gatewayLive } from "@/lib/gateway-live-fetch";

// always live: this page is the gateway's state right now
export const dynamic = "force-dynamic";

function severity(value: string): ControlSeverity {
  return (CONTROL_SEVERITIES as readonly string[]).includes(value)
    ? (value as ControlSeverity)
    : "info";
}

function pct(ratio: number): string {
  return `${(ratio * 100).toFixed(ratio > 0 && ratio < 0.1 ? 1 : 0)}%`;
}

function Unavailable({ error }: { error: string }) {
  return (
    <p className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-300">
      {error}
    </p>
  );
}

/** Renders `children(data)` or the reason the gateway couldn't provide it. */
function LiveData<T>({
  live,
  children,
}: {
  live: Live<T>;
  children: (data: T) => JSX.Element;
}): JSX.Element {
  return live.ok ? children(live.data) : <Unavailable error={live.error} />;
}

function Dot({ ok }: { ok: boolean }) {
  return (
    <span
      className={`inline-block h-2 w-2 rounded-full ${ok ? "bg-emerald-400" : "bg-red-500"}`}
    />
  );
}

function Tile({
  label,
  value,
  sub,
  tone = "text-zinc-50",
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  tone?: string;
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
      <p className="eyebrow text-zinc-500">{label}</p>
      <p
        className={`mt-3 font-serif text-3xl leading-none tracking-tight tabular-nums ${tone}`}
      >
        {value}
      </p>
      {sub === undefined ? null : (
        <p className="mt-1 text-xs text-zinc-500">{sub}</p>
      )}
    </div>
  );
}

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

export default async function GatewayPage() {
  await requireMember();
  const { base, info, health, policy, metrics } = await gatewayLive();

  const up = health.ok && health.data.status === "ok";
  const databaseUp = health.ok && health.data.database === "connected";

  return (
    <>
      <PageHeader
        eyebrow="Live gateway"
        title="Gateway"
        subtitle="Live state of the running AI Control Layer, read straight from the gateway"
        actions={
          base === null ? null : (
            <a
              href={`${base}/admin/docs`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center justify-center gap-2 rounded-md border border-zinc-700 px-3.5 py-2 text-[13px] font-semibold tracking-[0.02em] text-zinc-200 transition hover:-translate-y-px hover:bg-zinc-900"
            >
              API docs ↗
            </a>
          )
        }
      />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Tile
          label="Gateway"
          value={
            <span className="flex items-center gap-2">
              <Dot ok={up} />
              {up ? "Online" : "Offline"}
            </span>
          }
          sub={base ?? "GATEWAY_URL not set"}
        />
        <Tile
          label="Audit database"
          value={
            <span className="flex items-center gap-2">
              <Dot ok={databaseUp} />
              {health.ok ? health.data.database : "unknown"}
            </span>
          }
        />
        <Tile
          label="Service"
          value={info.ok ? `v${info.data.version}` : "—"}
          sub={info.ok ? info.data.service : undefined}
        />
        <Tile
          label="Controls enforced"
          value={
            info.ok
              ? info.data.policy.deterministic_controls +
                info.data.policy.semantic_controls
              : "—"
          }
          sub={
            info.ok
              ? `${String(info.data.policy.deterministic_controls)} deterministic · ${String(info.data.policy.semantic_controls)} semantic · fail ${info.data.policy.fail_mode}`
              : undefined
          }
        />
      </div>

      <h2 className="mt-10 mb-4 font-serif text-2xl text-zinc-100">
        Last 24h · from <code className="text-xs">GET /metrics</code>
      </h2>
      <LiveData live={metrics}>
        {(m) => (
          <>
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
              <Tile
                label="Events"
                value={m.totals.events}
                sub={`${String(m.totals.detections)} detections · ${m.totals.tokens.toLocaleString()} tokens`}
              />
              <Tile
                label="Blocked"
                value={m.totals.blocked}
                tone={m.totals.blocked ? "text-red-400" : "text-zinc-50"}
                sub={`${pct(blockRate(m.totals))} of traffic · ${String(m.totals.redacted)} redacted`}
              />
              <Tile
                label="Deterministic p50 / p95"
                value={fmtMicros(m.latency.deterministic_p95_us)}
                sub={`p50 ${fmtMicros(m.latency.deterministic_p50_us)}`}
              />
              <Tile
                label="Semantic p50 / p95"
                value={fmtMicros(m.latency.semantic_p95_us)}
                sub={`p50 ${fmtMicros(m.latency.semantic_p50_us)} · ${pct(m.latency.escalation_rate / 100)} escalated`}
              />
            </div>

            <Card
              className="mt-6"
              title={
                <span className="flex items-center gap-2">
                  <Dot ok={m.chain.intact} />
                  Audit hash chain
                </span>
              }
            >
              <p className="text-sm text-zinc-300">
                {m.chain.intact
                  ? m.chain.events_checked === 0
                    ? "Intact — no events in the verification window yet."
                    : `Intact — ${m.chain.events_checked.toLocaleString()} events verified.`
                  : `Broken at event #${String(m.chain.first_broken ?? "?")} (${m.chain.events_checked.toLocaleString()} checked).`}
              </p>
              <p className="mt-1 text-xs text-zinc-500">
                Report generated {fmtDateTime(parseGatewayTime(m.generated_at))}{" "}
                · policy <code>{(m.policy_version ?? "—").slice(0, 12)}</code>
              </p>
            </Card>

            <div className="mt-6 grid gap-6 lg:grid-cols-2">
              <Card title="Top controls">
                {m.by_control.length === 0 ? (
                  <p className="text-sm text-zinc-500">
                    No control fired in the window.
                  </p>
                ) : (
                  <ul className="-my-2 divide-y divide-zinc-800">
                    {m.by_control.map((c) => (
                      <li
                        key={c.control_id}
                        className="flex items-center gap-3 py-2.5"
                      >
                        <ControlSeverityBadge severity={severity(c.severity)} />
                        <code className="min-w-0 flex-1 truncate text-sm text-zinc-100">
                          {c.control_id}
                        </code>
                        <span className="text-xs text-zinc-500">{c.kind}</span>
                        <span className="w-12 text-right text-sm text-zinc-300 tabular-nums">
                          {c.hits}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </Card>

              <Card title="Identities">
                {m.by_principal.length === 0 ? (
                  <p className="text-sm text-zinc-500">
                    No traffic in the window.
                  </p>
                ) : (
                  <ul className="-my-2 divide-y divide-zinc-800">
                    {m.by_principal.map((p) => (
                      <li
                        key={p.slug}
                        className="flex items-center gap-3 py-2.5"
                      >
                        <code className="min-w-0 flex-1 truncate text-sm text-zinc-100">
                          {p.slug}
                        </code>
                        <span className="text-xs text-zinc-500">
                          {p.tokens.toLocaleString()} tok
                        </span>
                        <span className="text-xs text-red-400 tabular-nums">
                          {p.blocked} blocked
                        </span>
                        <span className="w-14 text-right text-sm text-zinc-300 tabular-nums">
                          {p.events}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </Card>
            </div>

            <Card className="mt-6" title="Budgets">
              {m.budgets.length === 0 ? (
                <p className="text-sm text-zinc-500">No budgets enforced.</p>
              ) : (
                <ul className="space-y-3">
                  {m.budgets.map((b) => {
                    const used = budgetUsed(b);
                    return (
                      <li
                        key={`${b.scope}:${b.scope_id ?? "*"}`}
                        className="space-y-1"
                      >
                        <div className="flex justify-between text-xs">
                          <span className="text-zinc-300">
                            {b.scope}
                            {b.scope_id === null ? "" : ` · ${b.scope_id}`}
                            <span className="ml-2 text-zinc-500">
                              {b.hard ? "hard" : "soft"}
                            </span>
                          </span>
                          <span className="text-zinc-400 tabular-nums">
                            {b.used_tokens.toLocaleString()} /{" "}
                            {b.limit_tokens?.toLocaleString() ?? "∞"} tok
                          </span>
                        </div>
                        <div className="h-2 rounded-full bg-zinc-800">
                          <div
                            className={`h-2 rounded-full ${used !== null && used >= 1 ? "bg-red-500" : used !== null && used >= 0.8 ? "bg-amber-400" : "bg-emerald-500"}`}
                            style={{
                              width: `${String(Math.min(1, used ?? 0) * 100)}%`,
                            }}
                          />
                        </div>
                      </li>
                    );
                  })}
                </ul>
              )}
            </Card>

            <Card className="mt-6" title="High-severity interventions">
              <div className="-m-5 overflow-x-auto">
                <table className={tableClass}>
                  <thead>
                    <tr>
                      <th className={thClass}>When</th>
                      <th className={thClass}>Control</th>
                      <th className={thClass}>Where</th>
                      <th className={thClass}>Identity</th>
                      <th className={thClass}>Evidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800">
                    {m.incidents.length === 0 ? (
                      <EmptyRow cols={5}>
                        Nothing high-severity in the window.
                      </EmptyRow>
                    ) : (
                      m.incidents.map((index, n) => (
                        <tr key={`${index.at}-${String(n)}`}>
                          <td className={`${tdClass} text-xs text-zinc-400`}>
                            {timeAgo(parseGatewayTime(index.at))}
                          </td>
                          <td className={tdClass}>
                            <span className="flex items-center gap-2">
                              <ControlSeverityBadge
                                severity={severity(index.severity)}
                              />
                              <code className="text-xs text-zinc-200">
                                {index.control_id}
                              </code>
                            </span>
                          </td>
                          <td className={`${tdClass} text-xs text-zinc-400`}>
                            {index.channel.toUpperCase()} ·{" "}
                            {index.hook.replace("_", " ")}
                            {index.tool === null ? "" : ` · ${index.tool}`}
                          </td>
                          <td className={`${tdClass} text-xs text-zinc-300`}>
                            {index.principal ?? "—"}
                          </td>
                          <td
                            className={`${tdClass} max-w-xs truncate text-xs text-zinc-500`}
                          >
                            {index.evidence}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </Card>
          </>
        )}
      </LiveData>

      <h2 className="mt-10 mb-4 font-serif text-2xl text-zinc-100">
        Enforced policy · from <code className="text-xs">GET /policy</code>
      </h2>
      <LiveData live={policy}>
        {(p) => (
          <>
            <div className="grid gap-6 lg:grid-cols-3">
              <Card title="Catalog">
                <dl className="space-y-2 text-sm">
                  <div className="flex justify-between gap-4">
                    <dt className="text-zinc-500">Version</dt>
                    <dd>
                      <code className="text-xs text-zinc-300">
                        {p.version.slice(0, 12)}
                      </code>
                    </dd>
                  </div>
                  <div className="flex justify-between gap-4">
                    <dt className="text-zinc-500">Source</dt>
                    <dd className="truncate text-zinc-300">{p.source}</dd>
                  </div>
                  <div className="flex justify-between gap-4">
                    <dt className="text-zinc-500">On detect</dt>
                    <dd className="text-zinc-300">{p.on_detect}</dd>
                  </div>
                  <div className="flex justify-between gap-4">
                    <dt className="text-zinc-500">Fail mode</dt>
                    <dd className="text-zinc-300">{p.fail_mode}</dd>
                  </div>
                  {Array.isArray(p.controls) ? null : (
                    <div className="flex justify-between gap-4">
                      <dt className="text-zinc-500">Controls</dt>
                      <dd className="text-zinc-300">
                        {p.controls.deterministic} deterministic ·{" "}
                        {p.controls.semantic} semantic
                      </dd>
                    </div>
                  )}
                  {p.signatures === undefined ? null : (
                    <div className="flex justify-between gap-4">
                      <dt className="text-zinc-500">Signature feed</dt>
                      <dd className="text-zinc-300">
                        {p.signatures.enabled ? "on" : "off"} ·{" "}
                        {p.signatures.source}
                        {p.signatures.refresh_secs === undefined
                          ? ""
                          : ` · every ${fmtWindow(p.signatures.refresh_secs)}`}
                      </dd>
                    </div>
                  )}
                  {p.signature_feed == null ? null : (
                    <div className="flex justify-between gap-4">
                      <dt className="text-zinc-500">Signature feed</dt>
                      <dd className="text-zinc-300">
                        {p.signature_feed.signatures} from{" "}
                        {p.signature_feed.source}
                      </dd>
                    </div>
                  )}
                </dl>
              </Card>

              <Card title="Models">
                <p className="mb-1 text-xs text-zinc-500">Allowed</p>
                <Chips items={p.models?.allowed ?? []} empty="any" />
                <p className="mt-3 mb-1 text-xs text-zinc-500">Denied</p>
                <Chips items={p.models?.denied ?? []} empty="none" />
              </Card>

              <Card title="Limits">
                {p.risk === undefined &&
                p.runaway === undefined &&
                p.mcp_servers === undefined ? (
                  <p className="text-sm text-zinc-500">
                    This gateway build doesn&apos;t report risk, runaway or MCP
                    limits.
                  </p>
                ) : null}
                <dl className="space-y-2 text-sm">
                  {p.risk === undefined ? null : (
                    <div className="flex justify-between gap-4">
                      <dt className="text-zinc-500">
                        Risk ({fmtWindow(p.risk.window_secs)})
                      </dt>
                      <dd className="text-zinc-300">
                        escalate {p.risk.escalate_at ?? "—"} · block{" "}
                        {p.risk.block_at ?? "—"}
                      </dd>
                    </div>
                  )}
                  {p.runaway === undefined ? null : (
                    <>
                      <div className="flex justify-between gap-4">
                        <dt className="text-zinc-500">
                          Tool calls / {fmtWindow(p.runaway.window_secs)}
                        </dt>
                        <dd className="text-zinc-300">
                          {p.runaway.max_tool_calls ?? "∞"}
                        </dd>
                      </div>
                      <div className="flex justify-between gap-4">
                        <dt className="text-zinc-500">Identical calls</dt>
                        <dd className="text-zinc-300">
                          {p.runaway.max_identical_calls ?? "∞"}
                        </dd>
                      </div>
                      <div className="flex justify-between gap-4">
                        <dt className="text-zinc-500">Agent depth</dt>
                        <dd className="text-zinc-300">
                          {p.runaway.max_depth ?? "∞"}
                        </dd>
                      </div>
                    </>
                  )}
                </dl>
                {p.mcp_servers === undefined ||
                p.mcp_servers.length === 0 ? null : (
                  <>
                    <p className="mt-4 mb-1 text-xs text-zinc-500">
                      MCP servers
                    </p>
                    <ul className="space-y-1 text-sm">
                      {p.mcp_servers.map((s) => (
                        <li key={s.name} className="flex items-center gap-2">
                          <Dot ok={s.enabled} />
                          <code className="text-zinc-300">{s.name}</code>
                          <span className="text-xs text-zinc-500">
                            {s.pinned_tools} pinned tools
                          </span>
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </Card>
            </div>

            {Array.isArray(p.controls) ? (
              <Card
                className="mt-6"
                title={`Controls (${String(p.controls.length)})`}
              >
                <div className="-m-5 overflow-x-auto">
                  <table className={tableClass}>
                    <thead>
                      <tr>
                        <th className={thClass}>Control</th>
                        <th className={thClass}>Tier</th>
                        <th className={thClass}>Severity</th>
                        <th className={thClass}>Action</th>
                        <th className={thClass}>Hooks</th>
                        <th className={thClass}>Detector</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800">
                      {p.controls.length === 0 ? (
                        <EmptyRow cols={6}>No controls loaded.</EmptyRow>
                      ) : (
                        p.controls.map((c) => (
                          <tr key={c.id}>
                            <td className={tdClass}>
                              <code className="text-xs text-zinc-100">
                                {c.id}
                              </code>
                            </td>
                            <td className={`${tdClass} text-xs text-zinc-400`}>
                              {c.kind}
                            </td>
                            <td className={tdClass}>
                              <ControlSeverityBadge
                                severity={severity(c.severity)}
                              />
                            </td>
                            <td className={tdClass}>
                              <VerdictBadge verdict={c.action} />
                            </td>
                            <td className={tdClass}>
                              <Chips items={c.hooks} empty="—" />
                            </td>
                            <td className={`${tdClass} text-xs text-zinc-400`}>
                              {c.kind === "semantic"
                                ? `${c.detector ?? "—"} ≥ ${c.threshold === undefined ? "—" : c.threshold.toFixed(2)}`
                                : (c.feed ?? "built-in")}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </Card>
            ) : null}
          </>
        )}
      </LiveData>
    </>
  );
}
