"use client";

import { createBrowserClient } from "@supabase/ssr";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { supabaseEnv } from "@/lib/supabase/env";

/**
 * Landing page for invite emails. Admin-sent invites put the session in the URL fragment
 * (`#access_token=…`), which never reaches the server, so it's picked up here; PKCE-style
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
          "This invite link is invalid or has expired.",
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
          setError("This invite link is invalid or has expired.");
        }
      });
  }, [router]);

  return (
    <main className="flex min-h-screen items-center justify-center bg-zinc-950 px-4">
      <div className="max-w-sm rounded-xl border border-zinc-800 bg-zinc-900/60 p-8 text-center">
        {error === null ? (
          <p className="text-sm text-zinc-400">Accepting your invitation…</p>
        ) : (
          <>
            <p className="text-sm text-red-300">{error}</p>
            <a
              href="/login"
              className="mt-4 inline-block text-sm text-emerald-400 hover:underline"
            >
              Go to sign in
            </a>
          </>
        )}
      </div>
    </main>
  );
}
