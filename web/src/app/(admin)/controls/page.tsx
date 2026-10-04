import { Card, ControlSeverityBadge, PageHeader } from "@/components/ui";
import { requireMember } from "@/lib/auth";
import {
  parseCatalogControls,
  readControlFields,
  reconcileControls,
} from "@/lib/catalog";
import type { ControlFields } from "@/lib/catalog";
import { fmtDateTime, timeAgo } from "@/lib/format";
import type {
  AttackSignature,
  Budget,
  PolicyVersion,
  UsageRow,
} from "@/lib/gateway";
import type { LivePolicy } from "@/lib/gateway-live";
import { gatewayFetch } from "@/lib/gateway-live-fetch";

import { PolicyEditor } from "./policy-editor";
import {
  Budgets,
  ControlsTable,
  FeedControlsTable,
  ResourceAccess,
} from "./sections";

const DAY_MS = 86_400_000;

type VersionRow = PolicyVersion & { catalog_toml: string | null };

export default async function ControlsPage() {
  const { supabase, member } = await requireMember();
  // longest budget window is a day; usage older than that never counts
  const since = new Date(Date.now() - DAY_MS).toISOString();

  const [
    live,
    { data: activeRow },
    { data: budgetRows },
    { data: usageRows },
    { data: versionRows },
    { data: signatureRows },
  ] = await Promise.all([
    gatewayFetch<LivePolicy>("/policy"),
    supabase
      .from("policy_versions")
      .select("id, sha256, catalog_toml")
      .eq("active", true)
      .maybeSingle<Pick<VersionRow, "id" | "sha256" | "catalog_toml">>(),
    supabase.from("budgets").select("*").order("scope").order("scope_id"),
    supabase
      .from("usage")
      .select(
        "ts, principal_id, end_user, model, prompt_tokens, completion_tokens, cost_usd",
      )
      .gte("ts", since)
      .limit(10_000),
    supabase
      .from("policy_versions")
      .select("id, sha256, source, loaded_at, active, note, diff_summary")
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
  const budgets = (budgetRows ?? []) as Budget[];
  const usage = (usageRows ?? []) as UsageRow[];
  const versions = (versionRows ?? []) as PolicyVersion[];
  const signatures = (signatureRows ?? []) as AttackSignature[];
  const liveControls =
    live.ok && Array.isArray(live.data.controls) ? live.data.controls : [];
  const catalogToml =
    typeof activeRow?.catalog_toml === "string" ? activeRow.catalog_toml : "";
  const { rows, feed } = reconcileControls(
    parseCatalogControls(catalogToml),
    liveControls,
  );
  // admins edit catalog controls in place; each row gets its settings from the TOML
  const editing =
    member.role === "admin" && activeRow !== null && catalogToml !== ""
      ? {
          baseSha: activeRow.sha256,
          fields: Object.fromEntries(
            rows.flatMap((row) => {
              const fields = readControlFields(catalogToml, row.id);
              return fields === null ? [] : [[row.id, fields]];
            }),
          ) as Record<string, ControlFields>,
        }
      : null;
  // the editor shows the stored active version; warn if the gateway runs another
  const drift =
    live.ok && activeRow !== null && live.data.version !== activeRow.sha256
      ? { enforced: live.data.version, shown: activeRow.sha256 }
      : null;
  const now = Date.now();

  return (
    <>
      <PageHeader
        title="Controls & policies"
        subtitle="The control catalog the gateway enforces, who may reach which resources, and what each user may spend"
      />

      <div className="space-y-6">
        <Card
          title={
            activeRow === null
              ? "Control catalog"
              : `Control catalog · version #${String(activeRow.id)}`
          }
          actions={
            activeRow === null ? null : (
              <a
                href={`/controls/policy/${String(activeRow.id)}`}
                className="text-xs text-zinc-400 hover:text-zinc-100"
              >
                Download .toml
              </a>
            )
          }
        >
          {typeof activeRow?.catalog_toml === "string" ? (
            <PolicyEditor
              key={activeRow.sha256}
              active={activeRow.catalog_toml}
              canEdit={member.role === "admin"}
            />
          ) : (
            <p className="text-sm text-zinc-500">
              The gateway hasn&apos;t stored a policy yet. It seeds the built-in
              catalog on first start.
            </p>
          )}
        </Card>

        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-zinc-300">
            Active controls
            <span className="ml-2 text-xs font-normal text-zinc-500">
              {rows.length} in the catalog
            </span>
            {live.ok && typeof live.data.profile === "string" ? (
              <span className="ml-2 text-xs font-normal text-zinc-500">
                profile {live.data.profile} · on detect {live.data.on_detect} ·
                fail {live.data.fail_mode}
              </span>
            ) : null}
          </h2>
          {drift === null ? null : (
            <p className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-300">
              The gateway enforces version{" "}
              <code>{drift.enforced.slice(0, 12)}</code>, not the catalog shown
              above (<code>{drift.shown.slice(0, 12)}</code>). It picks up the
              active version within a few seconds; if this persists, check the
              gateway.
            </p>
          )}
          {live.ok ? (
            <>
              <ControlsTable rows={rows} editing={editing} />
              {feed.length === 0 ? null : (
                <div className="space-y-2 pt-2">
                  <h3 className="text-xs font-semibold text-zinc-400">
                    From the signature feed ({feed.length})
                    <span className="ml-2 font-normal text-zinc-500">
                      compiled from signatures.toml, uploaded with the catalog —
                      not part of the file above
                    </span>
                  </h3>
                  <FeedControlsTable controls={feed} />
                </div>
              )}
            </>
          ) : (
            <p className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-300">
              Couldn&apos;t read the active controls from the gateway:{" "}
              {live.error}
            </p>
          )}
        </section>

        <div className="grid gap-6 lg:grid-cols-2">
          <ResourceAccess
            resources={live.ok ? live.data.resources : undefined}
          />
          <Budgets budgets={budgets} usage={usage} now={now} />
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          <Card title="Policy versions">
            {versions.length === 0 ? (
              <p className="text-sm text-zinc-500">No versions yet.</p>
            ) : (
              <ul className="-my-2 divide-y divide-zinc-800">
                {versions.map((v) => (
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
                        {v.active ? (
                          <span className="ml-2 text-xs text-emerald-400">
                            active
                          </span>
                        ) : null}
                      </p>
                      <p
                        className="truncate text-xs text-zinc-500"
                        title={v.diff_summary ?? fmtDateTime(v.loaded_at)}
                      >
                        {v.note ?? v.source.split("\n")[0]} · loaded{" "}
                        {timeAgo(v.loaded_at)}
                      </p>
                    </div>
                    <a
                      href={`/controls/policy/${String(v.id)}`}
                      className="shrink-0 text-xs text-zinc-400 hover:text-zinc-100"
                    >
                      .toml
                    </a>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title={`Attack signatures (${String(signatures.length)})`}>
            {signatures.length === 0 ? (
              <p className="text-sm text-zinc-500">
                No signatures synced yet. The gateway mirrors the feed uploaded
                with the catalog.
              </p>
            ) : (
              <ul className="-my-2 max-h-96 divide-y divide-zinc-800 overflow-y-auto">
                {signatures.map((s) => (
                  <li key={s.id} className="flex items-center gap-3 py-2.5">
                    <ControlSeverityBadge severity={s.severity} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm text-zinc-100">
                        {s.title}
                      </p>
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
      </div>
    </>
  );
}
