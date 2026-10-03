import Link from "next/link";
import { notFound } from "next/navigation";

import { ActionForm } from "@/components/action-form";
import {
  Card,
  Field,
  PageHeader,
  Select,
  SeverityBadge,
  StatusBadge,
  inputClass,
} from "@/components/ui";
import { requireMember } from "@/lib/auth";
import { INCIDENT_STATUSES, SEVERITIES, canWrite } from "@/lib/domain";
import type { Incident, IncidentEvent, TeamMember } from "@/lib/domain";
import { fmtDateTime, timeAgo } from "@/lib/format";

import { addIncidentNote, updateIncident } from "../actions";

const EVENT_DOT: Record<string, string> = {
  note: "bg-zinc-500",
  status: "bg-emerald-500",
  severity: "bg-orange-500",
  assignee: "bg-sky-500",
};

export default async function IncidentPage({
  params,
}: PageProps<"/incidents/[id]">) {
  const { id } = await params;
  const { supabase, member } = await requireMember();

  const [{ data }, { data: events }, { data: team }] = await Promise.all([
    supabase
      .from("incidents")
      .select("*, policy:policies(id, title)")
      .eq("id", id)
      .maybeSingle<
        Incident & { policy: { id: string; title: string } | null }
      >(),
    supabase
      .from("incident_events")
      .select("*")
      .eq("incident_id", id)
      .order("created_at", { ascending: false }),
    supabase
      .from("team_members")
      .select("user_id, email, full_name")
      .order("email"),
  ]);
  if (data === null) {
    notFound();
  }

  const incident = data;
  const members = (team ?? []) as TeamMember[];
  const name = (uid: string | null) => {
    const m = members.find((x) => x.user_id === uid);
    return m === undefined ? "System" : (m.full_name ?? m.email);
  };
  const writable = canWrite(member.role);

  return (
    <>
      <Link
        href="/incidents"
        className="mb-3 inline-block text-sm text-zinc-500 hover:text-zinc-300"
      >
        ← Incidents
      </Link>
      <PageHeader
        title={incident.title}
        actions={
          <div className="flex gap-2">
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
          </div>
        }
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card title="Details">
            <p className="text-sm leading-relaxed whitespace-pre-wrap text-zinc-300">
              {incident.description || (
                <span className="text-zinc-500">No description.</span>
              )}
            </p>
            <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-3 border-t border-zinc-800 pt-5 text-sm sm:grid-cols-3">
              {[
                ["Category", incident.category],
                ["Source", incident.source],
                ["Detected", fmtDateTime(incident.detected_at)],
                ["Reported by", name(incident.reported_by)],
                ["Resolved", fmtDateTime(incident.resolved_at)],
              ].map(([k, v]) => (
                <div key={k}>
                  <dt className="text-xs tracking-wide text-zinc-500 uppercase">
                    {k}
                  </dt>
                  <dd className="mt-0.5 text-zinc-200">{v}</dd>
                </div>
              ))}
              <div>
                <dt className="text-xs tracking-wide text-zinc-500 uppercase">
                  Policy
                </dt>
                <dd className="mt-0.5">
                  {incident.policy === null ? (
                    <span className="text-zinc-500">—</span>
                  ) : (
                    <Link
                      href={`/policies/${incident.policy.id}`}
                      className="text-emerald-400 hover:underline"
                    >
                      {incident.policy.title}
                    </Link>
                  )}
                </dd>
              </div>
            </dl>
          </Card>

          <Card title="Timeline">
            {writable ? (
              <ActionForm
                action={addIncidentNote.bind(null, id)}
                submitLabel="Add note"
                pendingLabel="Adding…"
                className="mb-6 space-y-3"
              >
                <textarea
                  name="message"
                  rows={3}
                  required
                  className={inputClass}
                  placeholder="Add an investigation note…"
                />
              </ActionForm>
            ) : null}
            <ol className="relative space-y-5 border-l border-zinc-800 pl-5">
              {((events ?? []) as IncidentEvent[]).map((event) => (
                <li key={event.id} className="relative">
                  <span
                    className={`absolute top-1.5 -left-[25px] h-2.5 w-2.5 rounded-full ring-4 ring-zinc-900 ${EVENT_DOT[event.kind] ?? "bg-zinc-500"}`}
                  />
                  <p
                    className={`text-sm whitespace-pre-wrap ${event.kind === "note" ? "text-zinc-200" : "text-zinc-400"}`}
                  >
                    {event.message}
                  </p>
                  <p
                    className="mt-0.5 text-xs text-zinc-500"
                    title={fmtDateTime(event.created_at)}
                  >
                    {name(event.author_id)} · {timeAgo(event.created_at)}
                  </p>
                </li>
              ))}
              {(events ?? []).length === 0 && (
                <li className="text-sm text-zinc-500">No activity yet.</li>
              )}
            </ol>
          </Card>
        </div>

        <Card title="Response" className="h-fit">
          <ActionForm
            action={updateIncident.bind(null, id)}
            submitLabel="Update incident"
            disabled={!writable}
          >
            <fieldset disabled={!writable} className="space-y-4">
              <Field label="Status">
                <Select
                  name="status"
                  defaultValue={incident.status}
                  options={INCIDENT_STATUSES}
                />
              </Field>
              <Field label="Severity">
                <Select
                  name="severity"
                  defaultValue={incident.severity}
                  options={SEVERITIES}
                />
              </Field>
              <Field label="Assignee">
                <Select
                  name="assignee_id"
                  defaultValue={incident.assignee_id ?? ""}
                  options={[
                    { value: "", label: "Unassigned" },
                    ...members.map((m) => ({
                      value: m.user_id,
                      label: m.full_name ?? m.email,
                    })),
                  ]}
                />
              </Field>
            </fieldset>
            {!writable && (
              <p className="text-xs text-zinc-500">Your role is read-only.</p>
            )}
          </ActionForm>
        </Card>
      </div>
    </>
  );
}
