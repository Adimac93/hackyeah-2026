// Access requests pushed by the gateway over SSE (GET /admin/approvals/stream).
// Pure types + helpers, unit-testable. The gateway decides; this only displays.

export const TTL_CHOICES = [5, 15, 30, 60] as const;

/** A request is for exactly one tool or one table (`resource`), for one end user. */
export interface AccessRequest {
  id: string;
  principal_id: string;
  principal: string;
  /** who the grant would cover: the delegated end user, or the principal itself */
  end_user: string;
  tool: string | null;
  resource: string | null;
  reason: string;
  ttl_minutes: number;
  requested_at_ms: number;
  deadline_ms: number;
}

export type ApprovalEvent =
  | ({ type: "request" } & AccessRequest)
  | { type: "decided"; id: string; approved: boolean; decided_by: string }
  | { type: "expired"; id: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

const isString = (v: unknown): v is string => typeof v === "string";
const optionalString = (v: unknown): string | null =>
  typeof v === "string" && v !== "" ? v : null;

/** What a request asks for, for display: a tool name or a table. */
export function requestTarget(
  request: Pick<AccessRequest, "tool" | "resource">,
): { kind: "tool" | "table"; name: string } {
  return request.resource === null
    ? { kind: "tool", name: request.tool ?? "" }
    : { kind: "table", name: request.resource };
}

const isNumber = (v: unknown): v is number =>
  typeof v === "number" && Number.isFinite(v);

/** Parses one SSE `data:` payload; anything malformed is dropped (null). */
export function parseApprovalEvent(data: string): ApprovalEvent | null {
  let value: unknown;
  try {
    value = JSON.parse(data);
  } catch {
    return null;
  }
  if (!isRecord(value) || !isString(value.id)) {
    return null;
  }
  switch (value.type) {
    case "request": {
      const { principal_id, principal, reason } = value;
      const { ttl_minutes, requested_at_ms, deadline_ms } = value;
      const tool = optionalString(value.tool);
      const resource = optionalString(value.resource);
      // a gateway from before per-user grants sends no end_user: the principal itself
      const endUser = optionalString(value.end_user);
      if (
        isString(principal_id) &&
        isString(principal) &&
        (tool === null) !== (resource === null) &&
        isString(reason) &&
        isNumber(ttl_minutes) &&
        isNumber(requested_at_ms) &&
        isNumber(deadline_ms)
      ) {
        return {
          type: "request",
          id: value.id,
          principal_id,
          principal,
          end_user: endUser ?? principal,
          tool,
          resource,
          reason,
          ttl_minutes,
          requested_at_ms,
          deadline_ms,
        };
      }
      return null;
    }
    case "decided": {
      if (typeof value.approved === "boolean" && isString(value.decided_by)) {
        return {
          type: "decided",
          id: value.id,
          approved: value.approved,
          decided_by: value.decided_by,
        };
      }
      return null;
    }
    case "expired": {
      return { type: "expired", id: value.id };
    }
    default: {
      return null;
    }
  }
}

/** Pending queue, oldest first. Replays on reconnect are deduped by id. */
export function applyEvent(
  queue: readonly AccessRequest[],
  event: ApprovalEvent,
): AccessRequest[] {
  if (event.type === "request") {
    if (queue.some((r) => r.id === event.id)) {
      return [...queue];
    }
    const { type: _type, ...request } = event;
    return [...queue, request].toSorted(
      (a, b) => a.requested_at_ms - b.requested_at_ms,
    );
  }
  return queue.filter((r) => r.id !== event.id);
}

/** Whole seconds left before the agent stops waiting, never negative. */
export function secondsLeft(request: AccessRequest, nowMs: number): number {
  return Math.max(0, Math.ceil((request.deadline_ms - nowMs) / 1000));
}

/** Clamp an approver-chosen TTL to what the gateway accepts. */
export function clampTtl(minutes: number): number {
  if (!Number.isFinite(minutes)) {
    return 15;
  }
  return Math.min(60, Math.max(1, Math.round(minutes)));
}
