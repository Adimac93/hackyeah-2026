import { redirect } from "next/navigation";

import { ActionForm } from "@/components/action-form";
import { Card, PageHeader } from "@/components/ui";
import { requireMember } from "@/lib/auth";
import { canWrite } from "@/lib/domain";
import type { TeamMember } from "@/lib/domain";

import { createPolicy } from "../actions";
import { PolicyFields } from "../policy-fields";

export default async function NewPolicyPage() {
  const { supabase, member } = await requireMember();
  if (!canWrite(member.role)) {
    redirect("/policies");
  }
  const { data: team } = await supabase
    .from("team_members")
    .select("user_id, email, full_name")
    .order("email");

  return (
    <>
      <PageHeader
        title="New policy"
        subtitle="Drafts are visible to the security team only"
      />
      <Card className="max-w-4xl">
        <ActionForm
          action={createPolicy}
          submitLabel="Create policy"
          pendingLabel="Creating…"
        >
          <PolicyFields team={(team ?? []) as TeamMember[]} />
        </ActionForm>
      </Card>
    </>
  );
}
