import type { EmailOtpType } from "@supabase/supabase-js";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

import { createClient } from "@/lib/supabase/server";

/** Landing point for email confirmation links (PKCE `code` or `token_hash`). */
export async function GET(request: NextRequest) {
  const { searchParams, origin } = request.nextUrl;
  const code = searchParams.get("code");
  const tokenHash = searchParams.get("token_hash");
  const type = searchParams.get("type") as EmailOtpType | null;
  const supabase = await createClient();

  const { error } =
    code === null
      ? tokenHash === null || type === null
        ? { error: new Error("missing code") }
        : await supabase.auth.verifyOtp({ token_hash: tokenHash, type })
      : await supabase.auth.exchangeCodeForSession(code);

  return NextResponse.redirect(
    new URL(error === null ? "/dashboard" : "/login?error=link", origin),
  );
}
