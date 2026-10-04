"use client";

import { useRef } from "react";

import { createConnection } from "../models/actions";
import { ProviderForm } from "../models/provider-form";

/**
 * Admins add an LLM connection without leaving the chat. Saving redirects back
 * to /chat, which re-renders the picker with the new models. Rendered outside
 * the composer: its form must not nest in the chat's.
 */
export function AddModelDialog() {
  const dialog = useRef<HTMLDialogElement>(null);

  return (
    <>
      <button
        type="button"
        onClick={() => dialog.current?.showModal()}
        className="text-xs text-emerald-400 hover:underline"
      >
        + Add custom model
      </button>
      <dialog
        ref={dialog}
        className="m-auto w-[min(42rem,calc(100vw-2rem))] rounded-xl border border-zinc-800 bg-zinc-900 p-0 text-zinc-100 backdrop:bg-zinc-950/70"
      >
        <div className="max-h-[85dvh] overflow-y-auto p-5">
          <div className="mb-4 flex items-start justify-between gap-4">
            <div>
              <h2 className="font-serif text-lg text-zinc-50">
                Add custom model
              </h2>
              <p className="mt-0.5 text-xs text-zinc-500">
                Any OpenAI-compatible server (Ollama, vLLM, TGI…). Its models
                are routed and audited through the gateway.
              </p>
            </div>
            <button
              type="button"
              aria-label="Close"
              onClick={() => dialog.current?.close()}
              className="text-zinc-400 hover:text-zinc-100"
            >
              ✕
            </button>
          </div>
          <ProviderForm
            action={createConnection}
            defaultPreset="custom"
            returnTo="/chat"
            submitLabel="Add model"
          />
        </div>
      </dialog>
    </>
  );
}
