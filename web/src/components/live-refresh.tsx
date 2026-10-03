"use client";

import { createBrowserClient } from "@supabase/ssr";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

/** Re-renders the page whenever the gateway audits a new event (Supabase Realtime websocket). */
export function LiveRefresh({
  url,
  anonKey,
}: {
  url: string;
  anonKey: string;
}) {
  const router = useRouter();
  useEffect(() => {
    const supabase = createBrowserClient(url, anonKey);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const channel = supabase
      .channel("activity-events")
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "events" },
        () => {
          // a request writes several events at once; refresh once per burst
          clearTimeout(timer);
          timer = setTimeout(() => {
            router.refresh();
          }, 300);
        },
      )
      .subscribe();
    return () => {
      clearTimeout(timer);
      void supabase.removeChannel(channel);
    };
  }, [url, anonKey, router]);
  return null;
}
