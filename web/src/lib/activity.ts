// Activity feed filters, shared by /activity and its PDF export so both always
// show the same rows. Pure, so it's unit-testable.
import { CHANNELS, SECURITY_STATUSES, VERDICTS } from "./gateway.ts";
import type {
  Channel,
  ControlSeverity,
  Detection,
  GatewayEvent,
  Principal,
  SecurityStatus,
  Verdict,
} from "./gateway.ts";

export interface ActivityFilters {
  status: SecurityStatus | "";
  verdict: Verdict | "";
  channel: Channel | "";
  /** principal id (the calling agent) */
  principal: string;
  /** end user the request is attributed to */
  user: string;
}

export type ActivityRow = GatewayEvent & {
  status: SecurityStatus;
  principals: Pick<Principal, "slug" | "display_name"> | null;
  detections: Pick<Detection, "id" | "severity" | "control_id">[];
};

export const ACTIVITY_SELECT =
  "*, principals(slug, display_name), detections(id, severity, control_id)";

type Parameters_ = Record<string, string | string[] | undefined>;

function one(parameters: Parameters_, key: string): string {
  const value = parameters[key];
  return typeof value === "string" ? value.trim() : "";
}

function oneOf<T extends string>(value: string, allowed: readonly T[]): T | "" {
  return (allowed as readonly string[]).includes(value) ? (value as T) : "";
}

/** Filters from a query string; unknown values are dropped, never passed to the DB. */
export function parseActivityFilters(parameters: Parameters_): ActivityFilters {
  return {
    status: oneOf(one(parameters, "status"), SECURITY_STATUSES),
    verdict: oneOf(one(parameters, "verdict"), VERDICTS),
    channel: oneOf(one(parameters, "channel"), CHANNELS),
    principal: one(parameters, "principal").slice(0, 100),
    user: one(parameters, "user").slice(0, 300),
  };
}

/** The set filters as a query string (`?a=b`), or "" when none are set. */
export function activityQueryString(filters: ActivityFilters): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(filters) as [string, string][]) {
    if (value !== "") {
      query.set(key, value);
    }
  }
  const text = query.toString();
  return text === "" ? "" : `?${text}`;
}

export function hasActivityFilters(filters: ActivityFilters): boolean {
  return Object.values(filters).some((value) => value !== "");
}

/** Narrow a PostgREST query on the `activity` view by the set filters. */
export function applyActivityFilters<
  Q extends { eq: (column: string, value: string) => Q },
>(query: Q, filters: ActivityFilters): Q {
  let q = query;
  if (filters.status !== "") {
    q = q.eq("status", filters.status);
  }
  if (filters.verdict !== "") {
    q = q.eq("verdict", filters.verdict);
  }
  if (filters.channel !== "") {
    q = q.eq("channel", filters.channel);
  }
  if (filters.principal !== "") {
    q = q.eq("principal_id", filters.principal);
  }
  if (filters.user !== "") {
    q = q.eq("end_user", filters.user);
  }
  return q;
}

const SEVERITY_RANK: Record<ControlSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Highest severity among an event's detections, or null when nothing fired. */
export function worstSeverity(
  detections: Pick<Detection, "severity">[],
): ControlSeverity | null {
  return detections.reduce<ControlSeverity | null>(
    (worst, d) =>
      worst === null || SEVERITY_RANK[d.severity] > SEVERITY_RANK[worst]
        ? d.severity
        : worst,
    null,
  );
}

/** Distinct, sorted end users, for the user filter. */
export function distinctUsers(rows: { end_user: string | null }[]): string[] {
  const users = new Set<string>();
  for (const row of rows) {
    if (row.end_user !== null && row.end_user !== "") {
      users.add(row.end_user);
    }
  }
  return [...users].toSorted((a, b) => a.localeCompare(b));
}

const PDF_REPLACEMENTS: Record<string, string> = {
  "—": "-",
  "–": "-",
  "…": "...",
  "‘": "'",
  "’": "'",
  "“": '"',
  "”": '"',
  "·": "-",
  "→": "->",
  µ: "u",
  ł: "l",
  Ł: "L",
  ß: "ss",
};

function isPrintableAscii(text: string): boolean {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.codePointAt(index) ?? 0;
    if (code < 0x20 || code > 0x7e) {
      return false;
    }
  }
  return true;
}

/**
 * Text the PDF's built-in Helvetica can draw. Its WinAnsi encoding throws on
 * anything else, and user names, tools and models are arbitrary text: strip
 * accents (ą→a), map common punctuation, replace the rest with "?".
 */
export function pdfSafe(text: string): string {
  let out = "";
  for (const char of text.normalize("NFD")) {
    if (/\p{M}/u.test(char)) {
      continue;
    }
    const mapped = PDF_REPLACEMENTS[char] ?? char;
    out += isPrintableAscii(mapped) ? mapped : "?";
  }
  return out;
}
