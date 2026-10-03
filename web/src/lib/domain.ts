// Pure domain types + validation. No framework imports, so it's unit-testable with `node --test`.

export const TEAM_ROLES = ["admin", "analyst", "viewer", "developer"] as const;
export const POLICY_STATUSES = ["draft", "active", "archived"] as const;
export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export const INCIDENT_STATUSES = [
  "open",
  "investigating",
  "contained",
  "resolved",
] as const;

export const POLICY_CATEGORIES = [
  "Access control",
  "Acceptable use",
  "Data protection",
  "Incident response",
  "Network security",
  "Vendor management",
  "Other",
] as const;

export const INCIDENT_CATEGORIES = [
  "Phishing",
  "Malware",
  "Data leak",
  "Account compromise",
  "Policy violation",
  "Lost device",
  "Vulnerability",
  "Other",
] as const;

export type TeamRole = (typeof TEAM_ROLES)[number];
export type PolicyStatus = (typeof POLICY_STATUSES)[number];
export type Severity = (typeof SEVERITIES)[number];
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];

export interface TeamMember {
  user_id: string;
  email: string;
  full_name: string | null;
  role: TeamRole;
  created_at: string;
}

/** Any signed-up account, as admins see it on the Team page; `role` is null without access. */
export interface RegisteredUser {
  user_id: string;
  email: string;
  full_name: string | null;
  role: TeamRole | null;
  registered_at: string;
  last_sign_in_at: string | null;
}

/** Role reserved for an email that has no account yet; claimed when that email is confirmed. */
export interface TeamInvite {
  email: string;
  role: TeamRole;
  invited_by: string | null;
  created_at: string;
}

export interface Policy {
  id: string;
  title: string;
  category: string;
  summary: string;
  body: string;
  status: PolicyStatus;
  version: number;
  review_due: string | null;
  owner_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  category: string;
  source: string;
  policy_id: string | null;
  assignee_id: string | null;
  reported_by: string | null;
  detected_at: string;
  resolved_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface IncidentEvent {
  id: number;
  incident_id: string;
  author_id: string | null;
  kind: string;
  message: string;
  created_at: string;
}

export interface FormState {
  error?: string;
  ok?: string;
}

type Input = Record<string, string | undefined>;
type Result<T> = { ok: true; value: T } | { ok: false; error: string };

export function canWrite(role: TeamRole | null | undefined): boolean {
  return role === "admin" || role === "analyst";
}

/** Developers only get the AI assistant; every other role sees the security console. */
export function canAccessConsole(role: TeamRole | null | undefined): boolean {
  return role === "admin" || role === "analyst" || role === "viewer";
}

function oneOf<T extends string>(
  list: readonly T[],
  value: string | undefined,
): value is T {
  return value !== undefined && (list as readonly string[]).includes(value);
}

function text(input: Input, key: string): string {
  return (input[key] ?? "").trim();
}

function checkTitle(title: string): string | null {
  if (title.length < 3) {
    return "Title must be at least 3 characters.";
  }
  if (title.length > 200) {
    return "Title must be at most 200 characters.";
  }
  return null;
}

export interface IncidentInput {
  title: string;
  description: string;
  severity: Severity;
  category: string;
  source: string;
  policy_id: string | null;
  assignee_id: string | null;
  detected_at: string;
}

export function parseIncidentInput(
  input: Input,
  now = new Date(),
): Result<IncidentInput> {
  const title = text(input, "title");
  const titleError = checkTitle(title);
  if (titleError !== null) {
    return { ok: false, error: titleError };
  }

  const severity = text(input, "severity");
  if (!oneOf(SEVERITIES, severity)) {
    return { ok: false, error: "Pick a valid severity." };
  }

  const category = text(input, "category");
  if (!oneOf(INCIDENT_CATEGORIES, category)) {
    return { ok: false, error: "Pick a valid category." };
  }

  let detected_at = now.toISOString();
  const rawDetected = text(input, "detected_at");
  if (rawDetected) {
    const d = new Date(rawDetected);
    if (Number.isNaN(d.getTime())) {
      return { ok: false, error: "Detection time is not a valid date." };
    }
    if (d.getTime() > now.getTime() + 60_000) {
      return { ok: false, error: "Detection time cannot be in the future." };
    }
    detected_at = d.toISOString();
  }

  return {
    ok: true,
    value: {
      title,
      description: text(input, "description"),
      severity,
      category,
      source: text(input, "source") || "manual",
      policy_id: text(input, "policy_id") || null,
      assignee_id: text(input, "assignee_id") || null,
      detected_at,
    },
  };
}

export interface PolicyInput {
  title: string;
  category: string;
  summary: string;
  body: string;
  status: PolicyStatus;
  review_due: string | null;
  owner_id: string | null;
}

export function parsePolicyInput(input: Input): Result<PolicyInput> {
  const title = text(input, "title");
  const titleError = checkTitle(title);
  if (titleError !== null) {
    return { ok: false, error: titleError };
  }

  const category = text(input, "category");
  if (!oneOf(POLICY_CATEGORIES, category)) {
    return { ok: false, error: "Pick a valid category." };
  }

  const status = text(input, "status") || "draft";
  if (!oneOf(POLICY_STATUSES, status)) {
    return { ok: false, error: "Pick a valid status." };
  }

  const body = text(input, "body");
  if (status === "active" && body.length < 10) {
    return {
      ok: false,
      error: "An active policy needs a body of at least 10 characters.",
    };
  }

  const review_due = text(input, "review_due") || null;
  if (review_due !== null && !/^\d{4}-\d{2}-\d{2}$/.test(review_due)) {
    return { ok: false, error: "Review date must be YYYY-MM-DD." };
  }

  return {
    ok: true,
    value: {
      title,
      category,
      summary: text(input, "summary"),
      body,
      status,
      review_due,
      owner_id: text(input, "owner_id") || null,
    },
  };
}

/** A content change to an already-published policy bumps its version. */
export function nextPolicyVersion(
  before: Pick<Policy, "body" | "status" | "version">,
  after: PolicyInput,
): number {
  return before.status !== "draft" && before.body !== after.body
    ? before.version + 1
    : before.version;
}

export function isReviewOverdue(
  policy: Pick<Policy, "status" | "review_due">,
  today = new Date(),
): boolean {
  if (policy.status !== "active" || policy.review_due === null) {
    return false;
  }
  return policy.review_due < today.toISOString().slice(0, 10);
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/** Triage order: unresolved first, then most severe, then oldest. */
export function triageSort<
  T extends Pick<Incident, "severity" | "status" | "detected_at">,
>(incidents: T[]): T[] {
  return incidents.toSorted((a, b) => {
    const ar = a.status === "resolved" ? 1 : 0;
    const br = b.status === "resolved" ? 1 : 0;
    if (ar !== br) {
      return ar - br;
    }
    const s = SEVERITY_WEIGHT[a.severity] - SEVERITY_WEIGHT[b.severity];
    if (s !== 0) {
      return s;
    }
    return a.detected_at.localeCompare(b.detected_at);
  });
}

export interface IncidentStats {
  open: number;
  bySeverity: Record<Severity, number>;
  resolvedLast30d: number;
  /** mean time to resolve, in hours, over resolved incidents; null if none */
  mttrHours: number | null;
}

export function incidentStats(
  incidents: Pick<
    Incident,
    "severity" | "status" | "detected_at" | "resolved_at"
  >[],
  now = new Date(),
): IncidentStats {
  const bySeverity: Record<Severity, number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  let open = 0;
  let resolvedLast30d = 0;
  let totalMs = 0;
  let resolvedCount = 0;
  const cutoff = now.getTime() - 30 * 24 * 3600 * 1000;

  for (const index of incidents) {
    if (index.status !== "resolved") {
      open++;
      bySeverity[index.severity]++;
      continue;
    }
    if (index.resolved_at === null) {
      continue;
    }
    const resolved = new Date(index.resolved_at).getTime();
    const detected = new Date(index.detected_at).getTime();
    if (resolved >= cutoff) {
      resolvedLast30d++;
    }
    if (resolved >= detected) {
      totalMs += resolved - detected;
      resolvedCount++;
    }
  }

  return {
    open,
    bySeverity,
    resolvedLast30d,
    mttrHours: resolvedCount
      ? Math.round((totalMs / resolvedCount / 3_600_000) * 10) / 10
      : null,
  };
}

/** A text field from FormData; files and missing fields read as "". */
export function formString(fd: FormData, key: string): string {
  const v = fd.get(key);
  return typeof v === "string" ? v : "";
}

export function formToObject(fd: FormData): Input {
  const out: Input = {};
  for (const [k, v] of fd.entries()) {
    if (typeof v === "string") {
      out[k] = v;
    }
  }
  return out;
}
