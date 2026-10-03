import Link from "next/link";
import { notFound } from "next/navigation";

import { ActionForm } from "@/components/action-form";
import { Card, PageHeader, SeverityBadge, StatusBadge } from "@/components/ui";
import { requireMember } from "@/lib/auth";
import { canWrite, isReviewOverdue } from "@/lib/domain";
import type { Incident, Policy, TeamMember } from "@/lib/domain";
import { fmtDateTime, timeAgo } from "@/lib/format";

import { updatePolicy } from "../actions";
import { PolicyFields } from "../policy-fields";

export default async function PolicyPage({
  params,
}: PageProps<"/policies/[id]">) {
  const { id } = await params;
  const { supabase, member } = await requireMember();

  const [{ data }, { data: team }, { data: incidents }] = await Promise.all([
    supabase.from("policies").select("*").eq("id", id).maybeSingle<Policy>(),
    supabase
      .from("team_members")
      .select("user_id, email, full_name")
      .order("email"),
    supabase
      .from("incidents")
      .select("id, title, severity, status, detected_at")
      .eq("policy_id", id)
      .order("detected_at", { ascending: false })
      .limit(10),
  ]);
  if (data === null) {
    notFound();
  }
  const policy = data;
  const writable = canWrite(member.role);
  const related = (incidents ?? []) as Incident[];

  return (
    <>
      <Link
        href="/policies"
        className="mb-3 inline-block text-sm text-zinc-500 hover:text-zinc-300"
      >
        ← Policies
      </Link>
      <PageHeader
        title={policy.title}
        subtitle={`Version ${String(policy.version)} · last updated ${fmtDateTime(policy.updated_at)}`}
        actions={
          <div className="flex items-center gap-2">
            {isReviewOverdue(policy) && (
              <span className="text-xs font-medium text-amber-400">
                Review overdue
              </span>
            )}
            <StatusBadge status={policy.status} />
          </div>
        }
      />

      <div className="grid gap-6 xl:grid-cols-3">
        <Card
          title={writable ? "Edit policy" : "Policy"}
          className="xl:col-span-2"
        >
          <ActionForm
            action={updatePolicy.bind(null, id)}
            submitLabel="Save changes"
            disabled={!writable}
          >
            <PolicyFields
              policy={policy}
              team={(team ?? []) as TeamMember[]}
              disabled={!writable}
            />
          </ActionForm>
        </Card>

        <Card title="Related incidents" className="h-fit">
          {related.length === 0 ? (
            <p className="text-sm text-zinc-500">
              No incidents linked to this policy.
            </p>
          ) : (
            <ul className="-my-2 divide-y divide-zinc-800">
              {related.map((index) => (
                <li key={index.id}>
                  <Link
                    href={`/incidents/${index.id}`}
                    className="block py-2.5 hover:opacity-80"
                  >
                    <p className="text-sm text-zinc-100">{index.title}</p>
                    <div className="mt-1 flex items-center gap-2">
                      <SeverityBadge severity={index.severity} />
                      <StatusBadge status={index.status} />
                      <span className="text-xs text-zinc-500">
                        {timeAgo(index.detected_at)}
                      </span>
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
