import { NextResponse } from "next/server";

import { getSession } from "@/lib/auth";
import { canAccessConsole } from "@/lib/domain";
import { auditExportFilename, auditExportPath } from "@/lib/gateway";
import { gatewayAsUser } from "@/lib/gateway-admin";
import { liveError } from "@/lib/gateway-live";

const TIMEOUT_MS = 30_000;

/**
 * Download the audit log with the Activity page's export settings, through the
 * gateway's `GET /admin/audit/export` as the signed-in user. The gateway checks
 * their role and validates the settings; this route only forwards them and
 * streams the file back.
 */
export async function GET(request: Request) {
  const { member } = await getSession();
  if (member === null || !canAccessConsole(member.role)) {
    return new NextResponse("Not found", { status: 404 });
  }
  const gateway = await gatewayAsUser();
  if ("error" in gateway) {
    return new NextResponse(gateway.error, { status: 503 });
  }

  const search = new URL(request.url).searchParams;
  const format = search.get("format") === "json" ? "json" : "csv";
  search.set("format", format);

  let upstream: Response;
  try {
    upstream = await fetch(`${gateway.base}${auditExportPath(search)}`, {
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
    const body: unknown = await upstream.json().catch(() => null);
    return new NextResponse(liveError(upstream.status, body), {
      status: upstream.status >= 500 ? 502 : upstream.status,
    });
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
