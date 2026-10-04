"use client";

import { useActionState } from "react";

import { Select } from "@/components/ui";
import type { FormState } from "@/lib/domain";

/** Admin picker for the model new chats start on. */
export function DefaultModelForm({
  action,
  defaultValue,
  options,
}: {
  action: (previous: FormState, formData: FormData) => Promise<FormState>;
  defaultValue: string;
  options: { value: string; label: string }[];
}) {
  const [state, formAction, pending] = useActionState(action, {});
  return (
    <form action={formAction} className="space-y-3">
      <div className="flex gap-2">
        <Select
          name="default_model"
          defaultValue={defaultValue}
          options={options}
          aria-label="Default chat model"
        />
        <button
          disabled={pending}
          className="inline-flex shrink-0 items-center justify-center gap-2 rounded-md bg-emerald-500 px-4 py-2.5 text-[13px] font-semibold tracking-[0.02em] text-zinc-950 transition enabled:hover:-translate-y-px enabled:hover:bg-emerald-600 disabled:opacity-50"
        >
          {pending ? "Saving…" : "Save"}
        </button>
      </div>
      {state.ok === undefined ? null : (
        <p role="status" className="text-xs text-emerald-400">
          {state.ok}
        </p>
      )}
      {state.error === undefined ? null : (
        <p role="alert" className="text-xs text-red-400">
          {state.error}
        </p>
      )}
    </form>
  );
}
