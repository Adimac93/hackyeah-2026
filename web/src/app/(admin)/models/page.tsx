import Link from "next/link";

import { ConfirmButton } from "@/components/confirm-button";
import { InlineAction } from "@/components/inline-action";
import { ProviderIcon } from "@/components/provider-icon";
import { Card, PageHeader } from "@/components/ui";
import { requireMember } from "@/lib/auth";
import { timeAgo } from "@/lib/format";
import { availableModels } from "@/lib/llm/models";
import type { ModelIcon } from "@/lib/llm/models";
import { PRESETS, isPresetId } from "@/lib/llm/presets";

import {
  createConnection,
  deleteConnection,
  setConnectionEnabled,
  testConnection,
} from "./actions";
import { ProviderForm } from "./provider-form";

interface ConnectionRow {
  id: string;
  name: string;
  preset: string;
  kind: string;
  base_url: string | null;
  api_key_hint: string | null;
  models: string[];
  enabled: boolean;
  updated_at: string;
}

function host(url: string | null): string {
  if (url === null) {
    return "api.anthropic.com";
  }
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

export default async function ModelsPage() {
  const { supabase, member } = await requireMember();
  const isAdmin = member.role === "admin";

  const { data } = await supabase
    .from("llm_providers")
    .select(
      "id, name, preset, kind, base_url, api_key_hint, models, enabled, updated_at",
    )
    .order("created_at");
  const connections = (data ?? []) as ConnectionRow[];

  // env-configured providers, grouped for a read-only overview
  const envGroups = new Map<string, { icon: ModelIcon; models: string[] }>();
  for (const option of availableModels(process.env)) {
    if (option.provider === "mock") {
      continue;
    }
    const group = envGroups.get(option.provider) ?? {
      icon: option.icon,
      models: [],
    };
    group.models.push(option.model);
    envGroups.set(option.provider, group);
  }

  return (
    <>
      <PageHeader
        title="Models"
        subtitle="LLM connections available to the security assistant"
      />

      <div className="grid gap-6 xl:grid-cols-5">
        <div className="space-y-4 xl:col-span-3">
          {connections.length === 0 ? (
            <Card>
              <p className="text-sm text-zinc-500">
                No connections added from the console yet.
                {isAdmin ? " Add one with the form." : ""}
              </p>
            </Card>
          ) : null}

          {connections.map((c) => {
            const icon = isPresetId(c.preset) ? c.preset : "custom";
            return (
              <section
                key={c.id}
                className={`rounded-xl border bg-zinc-900/60 p-5 ${c.enabled ? "border-zinc-800" : "border-zinc-800/60 opacity-70"}`}
              >
                <div className="flex items-start gap-4">
                  <ProviderIcon
                    icon={icon}
                    size="lg"
                    title={PRESETS[icon].name}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="font-semibold text-zinc-100">{c.name}</h2>
                      <span
                        className={`rounded-md px-1.5 py-0.5 text-xs ring-1 ring-inset ${
                          c.enabled
                            ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30"
                            : "bg-zinc-700/30 text-zinc-400 ring-zinc-600/30"
                        }`}
                      >
                        {c.enabled ? "enabled" : "disabled"}
                      </span>
                    </div>
                    <p className="mt-0.5 truncate text-xs text-zinc-500">
                      {host(c.base_url)} · key {c.api_key_hint ?? "none"} ·
                      updated {timeAgo(c.updated_at)}
                    </p>
                    <div className="mt-3 flex flex-wrap gap-1">
                      {c.models.map((m) => (
                        <code
                          key={m}
                          className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-300"
                        >
                          {m}
                        </code>
                      ))}
                    </div>
                  </div>
                  {isAdmin ? (
                    <div className="flex shrink-0 flex-col items-end gap-2">
                      <InlineAction
                        action={testConnection.bind(null, c.id)}
                        label="Test"
                        pendingLabel="Testing…"
                      />
                      <Link
                        href={`/models/${c.id}`}
                        className="text-xs text-zinc-400 hover:text-zinc-100"
                      >
                        Edit
                      </Link>
                      <form
                        action={setConnectionEnabled.bind(
                          null,
                          c.id,
                          !c.enabled,
                        )}
                      >
                        <button className="text-xs text-zinc-400 hover:text-zinc-100">
                          {c.enabled ? "Disable" : "Enable"}
                        </button>
                      </form>
                      <form action={deleteConnection.bind(null, c.id)}>
                        <ConfirmButton confirmLabel="Delete?">
                          Delete
                        </ConfirmButton>
                      </form>
                    </div>
                  ) : null}
                </div>
              </section>
            );
          })}

          {envGroups.size > 0 ? (
            <Card title="From server environment">
              <ul className="space-y-3">
                {[...envGroups.entries()].map(([provider, group]) => (
                  <li key={provider} className="flex items-center gap-3">
                    <ProviderIcon icon={group.icon} />
                    <div className="min-w-0">
                      <p className="text-sm text-zinc-200 capitalize">
                        {provider}
                      </p>
                      <p className="truncate text-xs text-zinc-500">
                        {group.models.join(", ")}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
              <p className="mt-4 text-xs text-zinc-500">
                Set in the server&apos;s env file; change them there.
              </p>
            </Card>
          ) : null}
        </div>

        {isAdmin ? (
          <div className="xl:col-span-2">
            <Card title="Add connection">
              <ProviderForm
                action={createConnection}
                submitLabel="Add connection"
              />
            </Card>
          </div>
        ) : null}
      </div>
    </>
  );
}
