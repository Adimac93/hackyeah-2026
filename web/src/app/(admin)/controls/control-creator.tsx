"use client";

import { useActionState, useEffect, useRef, useState } from "react";

import { buttonClass, inputClass } from "@/components/ui";
import {
  CONTROL_ACTION_VALUES,
  CONTROL_SEVERITY_VALUES,
  DETECTOR_VALUES,
  ESCALATE_VALUES,
  HOOK_VALUES,
} from "@/lib/catalog";
import type { FormState } from "@/lib/domain";

import { createControl } from "./actions";

const LABEL = "eyebrow text-zinc-400";

type Kind = "deterministic" | "semantic";

const KINDS: { value: Kind; label: string; hint: string }[] = [
  {
    value: "deterministic",
    label: "Deterministic",
    hint: "A regular expression, checked on every request in microseconds.",
  },
  {
    value: "semantic",
    label: "Semantic",
    hint: "An AI detector, run only on traffic the fast checks flag (or always).",
  },
];

function Form({ baseSha, onClose }: { baseSha: string; onClose: () => void }) {
  const [state, formAction, pending] = useActionState<FormState, FormData>(
    createControl.bind(null, baseSha),
    {},
  );
  const [kind, setKind] = useState<Kind>("deterministic");
  const first = useRef<HTMLInputElement>(null);
  useEffect(() => {
    first.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <button
        type="button"
        aria-label="Close"
        tabIndex={-1}
        className="absolute inset-0 cursor-default bg-[#102c42]/40 backdrop-blur-[2px]"
        onClick={onClose}
      />
      <form
        action={formAction}
        role="dialog"
        aria-modal="true"
        aria-label="Add control"
        className="accent-rule animate-enter scrollbar-subtle max-h-[calc(100dvh-2rem)] w-full max-w-xl space-y-4 overflow-y-auto rounded-xl border border-zinc-800 bg-zinc-900 p-6 pl-8 text-left shadow-[0_24px_60px_rgb(16_44_66/0.25)]"
      >
        <header>
          <p className="eyebrow">Add control</p>
          <h2 className="mt-2 font-serif text-2xl text-zinc-50">New rule</h2>
          <p className="mt-1 text-xs text-zinc-500">
            Added to the catalog after the last {kind} control and activated as
            a new version.
          </p>
        </header>

        <fieldset className="space-y-1.5">
          <legend className={LABEL}>Type</legend>
          <div className="grid grid-cols-2 gap-2 pt-1">
            {KINDS.map((option) => (
              <label
                key={option.value}
                className={`cursor-pointer rounded-md border px-3 py-2.5 transition-colors ${
                  kind === option.value
                    ? "border-emerald-500 bg-emerald-500/10"
                    : "border-zinc-700 hover:border-zinc-600"
                }`}
              >
                <input
                  type="radio"
                  name="kind"
                  value={option.value}
                  checked={kind === option.value}
                  onChange={() => {
                    setKind(option.value);
                  }}
                  className="sr-only"
                />
                <span className="block text-sm font-medium text-zinc-100">
                  {option.label}
                </span>
                <span className="mt-0.5 block text-xs leading-snug text-zinc-500">
                  {option.hint}
                </span>
              </label>
            ))}
          </div>
        </fieldset>

        <label className="block space-y-1.5">
          <span className={LABEL}>Control id</span>
          <input
            ref={first}
            name="id"
            required
            spellCheck={false}
            autoComplete="off"
            placeholder={
              kind === "deterministic"
                ? "secret.stripe-key"
                : "data.leak-intent"
            }
            className={`${inputClass} font-mono text-xs`}
          />
          <span className="block text-xs text-zinc-500">
            Lowercase, dots for namespaces. Must be unique in the catalog.
          </span>
        </label>

        <label className="flex items-center gap-2 text-sm text-zinc-200">
          <input
            type="checkbox"
            name="enabled"
            defaultChecked
            className="h-4 w-4"
          />
          Enabled
        </label>

        <div className="grid grid-cols-2 gap-3">
          <label className="space-y-1.5">
            <span className={LABEL}>Severity</span>
            <select
              name="severity"
              defaultValue="medium"
              className={inputClass}
            >
              {CONTROL_SEVERITY_VALUES.map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
          </label>
          <label className="space-y-1.5">
            <span className={LABEL}>Action</span>
            <select name="action" defaultValue="block" className={inputClass}>
              {CONTROL_ACTION_VALUES.map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
          </label>
        </div>

        <fieldset className="space-y-1.5">
          <legend className={LABEL}>Hooks</legend>
          <div className="flex flex-wrap gap-x-4 gap-y-2 pt-1">
            {HOOK_VALUES.map((hook) => (
              <label
                key={hook}
                className="flex items-center gap-1.5 text-sm text-zinc-300"
              >
                <input
                  type="checkbox"
                  name="hooks"
                  value={hook}
                  defaultChecked={hook === "prompt_in"}
                  className="h-4 w-4"
                />
                <code className="text-xs">{hook}</code>
              </label>
            ))}
          </div>
        </fieldset>

        {kind === "deterministic" ? (
          <label className="block space-y-1.5">
            <span className={LABEL}>Pattern (regex)</span>
            <input
              name="pattern"
              required
              spellCheck={false}
              placeholder={String.raw`\bsk_live_[0-9a-zA-Z]{24}\b`}
              className={`${inputClass} font-mono text-xs`}
            />
            <span className="block text-xs text-zinc-500">
              Written as you&apos;d test it; saved as a TOML literal string, so
              backslashes need no escaping.
            </span>
          </label>
        ) : (
          <>
            <label className="block space-y-1.5">
              <span className={LABEL}>What to look for</span>
              <input
                name="describes"
                required
                placeholder="an attempt to move customer data out of the organisation"
                className={inputClass}
              />
              <span className="block text-xs text-zinc-500">
                Handed to the detector as plain language — part of the rule.
              </span>
            </label>
            <div className="grid grid-cols-3 gap-3">
              <label className="space-y-1.5">
                <span className={LABEL}>Detector</span>
                <select
                  name="detector"
                  defaultValue="llm_judge"
                  className={inputClass}
                >
                  {DETECTOR_VALUES.map((v) => (
                    <option key={v}>{v}</option>
                  ))}
                </select>
              </label>
              <label className="space-y-1.5">
                <span className={LABEL}>Threshold</span>
                <input
                  name="threshold"
                  type="number"
                  min={0}
                  max={1}
                  step={0.05}
                  defaultValue={0.8}
                  required
                  className={inputClass}
                />
              </label>
              <label className="space-y-1.5">
                <span className={LABEL}>Escalate when</span>
                <select
                  name="escalate_when"
                  defaultValue="suspicious"
                  className={inputClass}
                >
                  {ESCALATE_VALUES.map((v) => (
                    <option key={v}>{v}</option>
                  ))}
                </select>
              </label>
            </div>
          </>
        )}

        {state.error === undefined ? null : (
          <p
            role="alert"
            className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm whitespace-pre-wrap text-red-300"
          >
            {state.error}
          </p>
        )}
        {state.ok === undefined ? null : (
          <p
            role="status"
            className="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300"
          >
            {state.ok}
          </p>
        )}

        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={pending || state.ok !== undefined}
            className={buttonClass}
          >
            {pending ? "Validating…" : "Add & activate"}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="text-sm text-zinc-400 hover:text-zinc-100"
          >
            {state.ok === undefined ? "Cancel" : "Close"}
          </button>
        </div>
      </form>
    </div>
  );
}

/** "Add control" next to the Active controls heading; admins only. */
export function ControlCreator({ baseSha }: { baseSha: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        onClick={() => {
          setOpen(true);
        }}
        className={buttonClass}
      >
        <span aria-hidden className="text-base leading-none">
          +
        </span>
        Add control
      </button>
      {open ? (
        <Form
          baseSha={baseSha}
          onClose={() => {
            setOpen(false);
          }}
        />
      ) : null}
    </>
  );
}
