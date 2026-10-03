"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { requireWriter } from "@/lib/auth";
import {
  INCIDENT_STATUSES,
  SEVERITIES,
  formString,
  formToObject,
  parseIncidentInput,
} from "@/lib/domain";
import type { FormState, Incident, TeamMember } from "@/lib/domain";

export async function createIncident(
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await requireWriter();
  if (session.error) {
    return { error: session.error };
  }

  const parsed = parseIncidentInput(formToObject(formData));
  if (!parsed.ok) {
    return { error: parsed.error };
  }

  const { supabase, user } = session;
  const { data, error } = await supabase
    .from("incidents")
    .insert({ ...parsed.value, reported_by: user.id })
    .select("id")
    .single();
  if (error !== null) {
    return { error: error.message };
  }

  await supabase.from("incident_events").insert({
    incident_id: data.id,
    author_id: user.id,
    kind: "status",
    message: "Incident reported",
  });

  revalidatePath("/", "layout");
  redirect(`/incidents/${data.id as string}`);
}

export async function updateIncident(
  id: string,
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await requireWriter();
  if (session.error) {
    return { error: session.error };
  }
  const { supabase, user } = session;

  const status = formString(formData, "status");
  const severity = formString(formData, "severity");
  const rawAssignee = formString(formData, "assignee_id");
  const assignee_id = rawAssignee === "" ? null : rawAssignee;
  if (!(INCIDENT_STATUSES as readonly string[]).includes(status)) {
    return { error: "Invalid status." };
  }
  if (!(SEVERITIES as readonly string[]).includes(severity)) {
    return { error: "Invalid severity." };
  }

  const { data: before } = await supabase
    .from("incidents")
    .select("status, severity, assignee_id")
    .eq("id", id)
    .single<Pick<Incident, "status" | "severity" | "assignee_id">>();
  if (before === null) {
    return { error: "Incident not found." };
  }

  const events: { kind: string; message: string }[] = [];
  if (before.status !== status) {
    events.push({
      kind: "status",
      message: `Status changed: ${before.status} → ${status}`,
    });
  }
  if (before.severity !== severity) {
    events.push({
      kind: "severity",
      message: `Severity changed: ${before.severity} → ${severity}`,
    });
  }
  if (before.assignee_id !== assignee_id) {
    let who = "nobody";
    if (assignee_id !== null) {
      const { data: m } = await supabase
        .from("team_members")
        .select("email")
        .eq("user_id", assignee_id)
        .single<Pick<TeamMember, "email">>();
      who = m?.email ?? "unknown";
    }
    events.push({ kind: "assignee", message: `Assigned to ${who}` });
  }
  if (events.length === 0) {
    return { ok: "Nothing changed." };
  }

  const { error } = await supabase
    .from("incidents")
    .update({ status, severity, assignee_id })
    .eq("id", id);
  if (error !== null) {
    return { error: error.message };
  }

  await supabase.from("incident_events").insert(
    events.map((event) => ({
      ...event,
      incident_id: id,
      author_id: user.id,
    })),
  );

  revalidatePath("/", "layout");
  return { ok: "Incident updated." };
}

export async function addIncidentNote(
  id: string,
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await requireWriter();
  if (session.error) {
    return { error: session.error };
  }

  const message = formString(formData, "message").trim();
  if (!message) {
    return { error: "Write something first." };
  }
  if (message.length > 4000) {
    return { error: "Note is too long (4000 characters max)." };
  }

  const { error } = await session.supabase.from("incident_events").insert({
    incident_id: id,
    author_id: session.user.id,
    kind: "note",
    message,
  });
  if (error !== null) {
    return { error: error.message };
  }

  revalidatePath(`/incidents/${id}`);
  return {};
}
