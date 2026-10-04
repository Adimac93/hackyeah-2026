import { Card, PageHeader } from "@/components/ui";
import { requireMember } from "@/lib/auth";
import { canWrite } from "@/lib/domain";
import { RESOURCES_BUCKET } from "@/lib/resources";

import { ResourceList } from "./resource-list";
import type { ResourceFile } from "./resource-list";
import { Uploader } from "./uploader";

interface StoredObject {
  id: string | null;
  name: string;
  created_at: string | null;
  metadata: { size?: number; mimetype?: string } | null;
}

export default async function ResourcesPage() {
  const { supabase, member } = await requireMember();
  const writer = canWrite(member.role);

  const { data, error } = await supabase.storage
    .from(RESOURCES_BUCKET)
    .list("", { limit: 1000, sortBy: { column: "created_at", order: "desc" } });
  const files: ResourceFile[] = ((data ?? []) as StoredObject[])
    // folder placeholders have no id
    .filter((o) => o.id !== null)
    .map((o) => ({
      name: o.name,
      size: o.metadata?.size ?? null,
      mimetype: o.metadata?.mimetype ?? null,
      createdAt: o.created_at,
    }));

  return (
    <>
      <PageHeader
        eyebrow="Shared files"
        title="Resources"
        subtitle="Files the security team shares: runbooks, reports, evidence. Private, served through short-lived links."
      />
      {writer ? (
        <Card className="mb-6">
          <Uploader />
        </Card>
      ) : null}
      {error === null ? null : (
        <p role="alert" className="mb-3 text-sm text-red-400">
          Couldn&apos;t list files ({error.message}).
        </p>
      )}
      <ResourceList files={files} canWrite={writer} />
    </>
  );
}
