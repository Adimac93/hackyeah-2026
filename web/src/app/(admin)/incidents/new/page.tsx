import { redirect } from "next/navigation";

import { ActionForm } from "@/components/action-form";
import { Card, Field, PageHeader, Select, inputClass } from "@/components/ui";
import { requireMember } from "@/lib/auth";
import { INCIDENT_CATEGORIES, SEVERITIES, canWrite } from "@/lib/domain";
import type { Policy, TeamMember } from "@/lib/domain";
import { toLocalInput } from "@/lib/format";

import { createIncident } from "../actions";

export default async function NewIncidentPage() {
  const { supabase, member } = await requireMember();
  if (!canWrite(member.role)) {
    redirect("/incidents");
  }

  const [{ data: policies }, { data: team }] = await Promise.all([
    supabase
      .from("policies")
      .select("id, title")
      .eq("status", "active")
      .order("title"),
    supabase
      .from("team_members")
      .select("user_id, email, full_name")
      .order("email"),
  ]);

  return (
    <>
      <PageHeader
        title="Report incident"
        subtitle="Log a new security incident for triage"
      />
      <Card className="max-w-3xl">
        <ActionForm
          action={createIncident}
          submitLabel="Create incident"
          pendingLabel="Creating…"
        >
          <Field label="Title">
            <input
              name="title"
              required
              minLength={3}
              maxLength={200}
              className={inputClass}
              placeholder="e.g. Suspicious login from new country"
            />
          </Field>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Severity">
              <Select
                name="severity"
                defaultValue="medium"
                options={SEVERITIES}
              />
            </Field>
            <Field label="Category">
              <Select name="category" options={INCIDENT_CATEGORIES} />
            </Field>
            <Field label="Detected at">
              <input
                name="detected_at"
                type="datetime-local"
                defaultValue={toLocalInput(new Date().toISOString())}
                className={inputClass}
              />
            </Field>
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Source">
              <input
                name="source"
                className={inputClass}
                placeholder="SIEM, EDR, employee report…"
              />
            </Field>
            <Field label="Related policy">
              <Select
                name="policy_id"
                options={[
                  { value: "", label: "None" },
                  ...((policies ?? []) as Policy[]).map((p) => ({
                    value: p.id,
                    label: p.title,
                  })),
                ]}
              />
            </Field>
            <Field label="Assignee">
              <Select
                name="assignee_id"
                defaultValue={member.user_id}
                options={[
                  { value: "", label: "Unassigned" },
                  ...((team ?? []) as TeamMember[]).map((m) => ({
                    value: m.user_id,
                    label: m.full_name ?? m.email,
                  })),
                ]}
              />
            </Field>
          </div>
          <Field label="Description">
            <textarea
              name="description"
              rows={6}
              className={inputClass}
              placeholder="What happened, what's affected, what's been done so far"
            />
          </Field>
        </ActionForm>
      </Card>
    </>
  );
}
