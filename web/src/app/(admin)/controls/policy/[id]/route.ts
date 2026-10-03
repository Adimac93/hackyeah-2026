import { NextResponse } from "next/server";

import { getSession } from "@/lib/auth";
import { canAccessConsole } from "@/lib/domain";

/** Download an imported policy version as the TOML it was uploaded as (security team only). */
export async function GET(
  _request: Request,
  { params }: RouteContext<"/controls/policy/[id]">,
) {
  const { id } = await params;
  const { supabase, member } = await getSession();
  if (member === null || !canAccessConsole(member.role)) {
    return new NextResponse("Not found", { status: 404 });
  }
  if (!/^\d+$/.test(id)) {
    return new NextResponse("Not found", { status: 404 });
  }

  // RLS limits policy_versions to the security team as well
  const { data } = await supabase
    .from("policy_versions")
    .select("sha256, catalog_toml")
    .eq("id", id)
    .maybeSingle<{ sha256: string; catalog_toml: string | null }>();
  if (data?.catalog_toml === null || data?.catalog_toml === undefined) {
    return new NextResponse("Not found", { status: 404 });
  }

  return new NextResponse(data.catalog_toml, {
    headers: {
      "content-type": "application/toml; charset=utf-8",
      "content-disposition": `attachment; filename="control-catalog-${data.sha256.slice(0, 12)}.toml"`,
      "cache-control": "no-store",
    },
  });
}
