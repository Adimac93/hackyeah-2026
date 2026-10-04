import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { Card, PageHeader } from "@/components/ui";
import { requireMember } from "@/lib/auth";
import { isPresetId } from "@/lib/llm/presets";

import { updateConnection } from "../actions";
import { ProviderForm } from "../provider-form";

export default async function EditConnectionPage({
  params,
}: PageProps<"/models/[id]">) {
  const { id } = await params;
  const { supabase, member } = await requireMember();
  if (member.role !== "admin") {
    redirect("/models");
  }

  const { data } = await supabase
    .from("llm_providers")
    .select("id, name, preset, base_url, api_key_hint, models, enabled")
    .eq("id", id)
    .maybeSingle<{
      id: string;
      name: string;
      preset: string;
      base_url: string | null;
      api_key_hint: string | null;
      models: string[];
      enabled: boolean;
    }>();
  if (data === null) {
    notFound();
  }

  return (
    <>
      <PageHeader
        eyebrow="LLM connections"
        title={`Edit ${data.name}`}
        actions={
          <Link
            href="/models"
            className="text-sm text-zinc-400 hover:text-zinc-200"
          >
            ← All models
          </Link>
        }
      />
      <div className="max-w-2xl">
        <Card>
          <ProviderForm
            action={updateConnection.bind(null, data.id)}
            submitLabel="Save changes"
            initial={{
              preset: isPresetId(data.preset) ? data.preset : "custom",
              name: data.name,
              baseUrl: data.base_url ?? "",
              models: data.models.join(", "),
              enabled: data.enabled,
              keyHint: data.api_key_hint,
            }}
          />
        </Card>
      </div>
    </>
  );
}
