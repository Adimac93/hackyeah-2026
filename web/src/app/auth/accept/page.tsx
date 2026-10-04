"use client";

import { createBrowserClient } from "@supabase/ssr";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { AuthShell } from "@/components/auth-shell";
import { supabaseEnv } from "@/lib/supabase/env";

/**
 * Landing page for invite and admin-sent reset emails. Links from the service client put the
 * session in the URL fragment (`#access_token=…`), which never reaches the server, so it's
 * picked up here; PKCE-style
 * links (`?code=` / `?token_hash=`) are forwarded to the server callback.
 */
export default function AcceptInvitePage() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const query = new URLSearchParams(window.location.search);
    if (query.has("code") || query.has("token_hash")) {
      query.set("next", "/set-password");
      window.location.replace(`/auth/callback?${query.toString()}`);
      return;
    }

    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const accessToken = fragment.get("access_token");
    const refreshToken = fragment.get("refresh_token");
    if (accessToken === null || refreshToken === null) {
      setError(
        fragment.get("error_description") ??
          "This link is invalid or has expired.",
      );
      return;
    }

    const { url, key } = supabaseEnv();
    void createBrowserClient(url, key)
      .auth.setSession({
        access_token: accessToken,
        refresh_token: refreshToken,
      })
      .then(({ error: sessionError }) => {
        if (sessionError === null) {
          // drop the tokens from history before moving on
          window.history.replaceState(null, "", "/auth/accept");
          router.replace("/set-password");
        } else {
          setError("This link is invalid or has expired.");
        }
      });
  }, [router]);

  return (
    <AuthShell panelTitle="Accepting your invitation">
      {error === null ? (
        <p className="flex items-center gap-3 font-serif text-xl text-zinc-200">
          <span className="bg-cogut h-2 w-2 animate-pulse rounded-full" />
          Signing you in…
        </p>
      ) : (
        <>
          <p className="text-sm text-red-300">{error}</p>
          <a
            href="/login"
            className="mt-4 inline-block text-sm text-emerald-400 hover:underline"
          >
            Go to sign in →
          </a>
        </>
      )}
    </AuthShell>
  );
}
