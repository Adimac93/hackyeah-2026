"use client";

import { createBrowserClient } from "@supabase/ssr";
import { useRouter } from "next/navigation";
import { useRef, useState } from "react";

import {
  MAX_RESOURCE_BYTES,
  RESOURCES_BUCKET,
  UPLOAD_ACCEPT,
  fmtBytes,
  resourceObjectName,
  uploadContentType,
} from "@/lib/resources";
import { supabaseEnv } from "@/lib/supabase/env";

/**
 * Uploads straight from the browser to Storage as the signed-in user (RLS
 * allows admin/analyst), so large files never pass through a server action.
 */
export function Uploader() {
  const router = useRouter();
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [messages, setMessages] = useState<
    { tone: "ok" | "error"; text: string }[]
  >([]);

  async function upload(files: File[]) {
    if (files.length === 0) {
      return;
    }
    const { url, key } = supabaseEnv();
    const storage = createBrowserClient(url, key).storage.from(
      RESOURCES_BUCKET,
    );
    const results: { tone: "ok" | "error"; text: string }[] = [];
    for (const file of files) {
      const contentType = uploadContentType(file.name);
      if (contentType === null) {
        results.push({
          tone: "error",
          text: `${file.name}: only PPTX, images (PNG, JPG, GIF, WebP, AVIF) and TXT can be uploaded.`,
        });
        continue;
      }
      if (file.size > MAX_RESOURCE_BYTES) {
        results.push({
          tone: "error",
          text: `${file.name}: larger than ${fmtBytes(MAX_RESOURCE_BYTES)}.`,
        });
        continue;
      }
      setBusy(file.name);
      const { error } = await storage.upload(
        resourceObjectName(file.name, new Date()),
        file,
        { contentType, upsert: false },
      );
      results.push(
        error === null
          ? { tone: "ok", text: `${file.name} uploaded.` }
          : { tone: "error", text: `${file.name}: ${error.message}` },
      );
    }
    setBusy(null);
    setMessages(results);
    if (input.current !== null) {
      input.current.value = "";
    }
    router.refresh();
  }

  return (
    <div>
      <label
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => {
          setDragging(false);
        }}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          void upload([...event.dataTransfer.files]);
        }}
        className={`flex cursor-pointer flex-col items-center justify-center gap-1 rounded-xl border border-dashed px-4 py-8 text-center transition-colors ${
          dragging
            ? "border-emerald-500 bg-emerald-500/5"
            : "border-zinc-700 hover:border-zinc-500"
        } ${busy === null ? "" : "pointer-events-none opacity-60"}`}
      >
        <span className="text-sm font-medium text-zinc-200">
          {busy === null
            ? "Drop files here or click to upload"
            : `Uploading ${busy}…`}
        </span>
        <span className="text-xs text-zinc-500">
          PPTX, images or TXT · up to {fmtBytes(MAX_RESOURCE_BYTES)} per file
        </span>
        <input
          ref={input}
          type="file"
          multiple
          accept={UPLOAD_ACCEPT}
          className="sr-only"
          disabled={busy !== null}
          onChange={(event) => {
            void upload([...(event.target.files ?? [])]);
          }}
        />
      </label>
      {messages.length === 0 ? null : (
        <ul className="mt-3 space-y-1">
          {messages.map((m) => (
            <li
              key={m.text}
              role={m.tone === "error" ? "alert" : "status"}
              className={`text-xs ${m.tone === "error" ? "text-red-400" : "text-emerald-400"}`}
            >
              {m.text}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
