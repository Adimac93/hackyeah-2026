"use server";

import { clampTtl } from "@/lib/approvals";
import { requireWriter } from "@/lib/auth";
import { gatewayAdmin } from "@/lib/gateway-admin";

/** Approve or deny an agent's access request. Admin/analyst only. */
export async function decideAccess(
  id: string,
  decision: "approve" | "deny",
  ttlMinutes: number,
  note: string,
): Promise<{ error: string | null }> {
  const session = await requireWriter();
  if (session.error !== null) {
    return { error: session.error };
  }
  const gateway = gatewayAdmin();
  if (gateway === null) {
    return { error: "GATEWAY_URL / GATEWAY_ADMIN_KEY not configured." };
  }

  let response: Response;
  try {
    response = await fetch(
      `${gateway.base}/admin/approvals/${encodeURIComponent(id)}`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${gateway.key}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          decision: decision === "approve" ? "approve" : "deny",
          ttl_minutes: clampTtl(ttlMinutes),
          note: note.trim() === "" ? null : note.trim().slice(0, 500),
          decided_by: session.member.email,
        }),
        signal: AbortSignal.timeout(10_000),
      },
    );
  } catch {
    return { error: "The gateway is unreachable." };
  }

  if (response.status === 409) {
    return { error: "Already decided or expired." };
  }
  if (!response.ok) {
    return {
      error: `The gateway refused the decision (${String(response.status)}).`,
    };
  }
  return { error: null };
}
