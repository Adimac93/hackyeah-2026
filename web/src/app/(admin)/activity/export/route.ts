import { NextResponse } from "next/server";

import { getSession } from "@/lib/auth";
import { canAccessConsole } from "@/lib/domain";
import {
  EXPORT_FORMATS,
  auditExportFilename,
  auditExportPath,
} from "@/lib/gateway";
import type { ExportFormat } from "@/lib/gateway";
import { gatewayAsUser } from "@/lib/gateway-admin";

const TIMEOUT_MS = 30_000;

/**
 * Download the audit log as the Activity page currently filters it, through the
 * gateway's `GET /admin/audit/export` as the signed-in user (the gateway checks
 * their team role). Rows carry their hash-chain fields, so the file can be
 * checked offline with `just verify-audit --file`.
 */
export async function GET(request: Request) {
  const { supabase, member } = await getSession();
  if (member === null || !canAccessConsole(member.role)) {
    return new NextResponse("Not found", { status: 404 });
  }

  const sp = new URL(request.url).searchParams;
  const requested = sp.get("format") ?? "csv";
  if (!(EXPORT_FORMATS as readonly string[]).includes(requested)) {
    return new NextResponse("format must be csv or json", { status: 400 });
  }
  const format = requested as ExportFormat;

  // The page filters by principal id; the export takes the slug.
  let principal: string | undefined;
  const principalId = sp.get("principal") ?? "";
  if (principalId !== "") {
    const { data } = await supabase
      .from("principals")
      .select("slug")
      .eq("id", principalId)
      .maybeSingle<{ slug: string }>();
    if (data === null) {
      return new NextResponse("Unknown principal", { status: 400 });
    }
    principal = data.slug;
  }

  const gateway = await gatewayAsUser();
  if ("error" in gateway) {
    return new NextResponse(gateway.error, { status: 503 });
  }

  const path = auditExportPath(format, {
    verdict: sp.get("verdict") ?? undefined,
    channel: sp.get("channel") ?? undefined,
    principal,
  });
  let upstream: Response;
  try {
    upstream = await fetch(`${gateway.base}${path}`, {
      headers: { Authorization: `Bearer ${gateway.token}` },
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    console.error(
      "[gateway] audit export failed",
      error instanceof Error ? error.name : "unknown",
    );
    return new NextResponse("The gateway is unreachable.", { status: 502 });
  }
  if (!upstream.ok) {
    const status =
      upstream.status === 401 || upstream.status === 403 ? 403 : 502;
    return new NextResponse(
      status === 403
        ? "Your role may not export the audit log."
        : "The gateway could not export the audit log.",
      { status },
    );
  }

  return new NextResponse(upstream.body, {
    headers: {
      "content-type":
        format === "csv" ? "text/csv; charset=utf-8" : "application/json",
      "content-disposition": `attachment; filename="${auditExportFilename(format, new Date())}"`,
      "cache-control": "no-store",
    },
  });
}
