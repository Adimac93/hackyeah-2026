import type { NextRequest } from "next/server";

import {
  ACTIVITY_SELECT,
  applyActivityFilters,
  parseActivityFilters,
} from "@/lib/activity";
import type { ActivityRow } from "@/lib/activity";
import { activityPdf } from "@/lib/activity-pdf";
import { requireMember } from "@/lib/auth";

/** Most rows one export carries; the newest win. */
const MAX_ROWS = 5000;

/** PDF of the activity feed with the same filters as /activity (?user=…&status=…). */
export async function GET(request: NextRequest) {
  const { supabase, user } = await requireMember();
  const filters = parseActivityFilters(
    Object.fromEntries(request.nextUrl.searchParams),
  );

  const query = applyActivityFilters(
    supabase
      .from("activity")
      .select(ACTIVITY_SELECT)
      .order("ts", { ascending: false })
      .limit(MAX_ROWS + 1),
    filters,
  );
  const [{ data, error }, { data: principal }] = await Promise.all([
    query,
    filters.principal === ""
      ? Promise.resolve({ data: null })
      : supabase
          .from("principals")
          .select("display_name")
          .eq("id", filters.principal)
          .maybeSingle<{ display_name: string }>(),
  ]);
  if (error !== null) {
    console.error("[activity] export query failed", error.code);
    return new Response("Couldn't load activity for the export.", {
      status: 503,
    });
  }

  const rows = data as ActivityRow[];
  const pdf = await activityPdf({
    rows: rows.slice(0, MAX_ROWS),
    filters,
    principalName: principal?.display_name ?? null,
    truncated: rows.length > MAX_ROWS,
    generatedBy: user.email ?? user.id,
  });

  const stamp = new Date().toISOString().slice(0, 16).replaceAll(/[:T]/g, "-");
  return new Response(
    new Blob([pdf as BlobPart], { type: "application/pdf" }),
    {
      headers: {
        "content-disposition": `attachment; filename="activity-${stamp}.pdf"`,
        "cache-control": "no-store",
      },
    },
  );
}
