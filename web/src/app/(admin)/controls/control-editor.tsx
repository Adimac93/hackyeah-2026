"use client";

import { useActionState, useEffect, useRef, useState } from "react";

import { PencilIcon } from "@/components/icons";
import { inputClass } from "@/components/ui";
import {
  CONTROL_ACTION_VALUES,
  CONTROL_SEVERITY_VALUES,
  ESCALATE_VALUES,
  HOOK_VALUES,
} from "@/lib/catalog";
import type { ControlFields } from "@/lib/catalog";
import type { FormState } from "@/lib/domain";

import { saveControl } from "./actions";

const LABEL = "text-xs font-medium tracking-wide text-zinc-400 uppercase";

function Form({
  id,
  baseSha,
  fields,
  onClose,
}: {
  id: string;
  baseSha: string;
  fields: ControlFields;
  onClose: () => void;
}) {
  const [state, formAction, pending] = useActionState<FormState, FormData>(
    saveControl.bind(null, baseSha, id),
    {},
  );
  const first = useRef<HTMLSelectElement>(null);
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
        aria-label="Close editor"
        tabIndex={-1}
        className="absolute inset-0 cursor-default bg-black/70"
        onClick={onClose}
      />
      <form
        action={formAction}
        role="dialog"
        aria-modal="true"
        aria-label={`Edit ${id}`}
        className="relative w-full max-w-xl space-y-4 rounded-xl border border-zinc-800 bg-zinc-900 p-5 text-left shadow-2xl"
      >
        <header>
          <h2 className="font-mono text-sm text-zinc-100">{id}</h2>
          <p className="text-xs text-zinc-500">
            {fields.kind} control · saving rewrites this control in the catalog
            and activates it as a new version
          </p>
        </header>
        <input type="hidden" name="kind" value={fields.kind} />

        <label className="flex items-center gap-2 text-sm text-zinc-200">
          <input
            type="checkbox"
            name="enabled"
            defaultChecked={fields.enabled}
            className="h-4 w-4 accent-emerald-500"
          />
          Enabled
        </label>

        <div className="grid grid-cols-2 gap-3">
          <label className="space-y-1.5">
            <span className={LABEL}>Severity</span>
            <select
              ref={first}
              name="severity"
              defaultValue={fields.severity}
              className={inputClass}
            >
              {CONTROL_SEVERITY_VALUES.map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
          </label>
          <label className="space-y-1.5">
            <span className={LABEL}>Action</span>
            <select
              name="action"
              defaultValue={fields.action}
              className={inputClass}
            >
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
                  defaultChecked={fields.hooks.includes(hook)}
                  className="h-4 w-4 accent-emerald-500"
                />
                <code className="text-xs">{hook}</code>
              </label>
            ))}
          </div>
        </fieldset>

        {fields.kind === "deterministic" ? (
          <label className="block space-y-1.5">
            <span className={LABEL}>Pattern (regex)</span>
            <input
              name="pattern"
              defaultValue={fields.pattern ?? ""}
              required
              spellCheck={false}
              className={`${inputClass} font-mono text-xs`}
            />
            <span className="block text-xs text-zinc-500">
              Written as you&apos;d test it; saved as a TOML literal string, so
              backslashes need no escaping.
            </span>
          </label>
        ) : (
          <div className="grid grid-cols-2 gap-3">
            <label className="space-y-1.5">
              <span className={LABEL}>Threshold (0–1)</span>
              <input
                name="threshold"
                type="number"
                min={0}
                max={1}
                step={0.05}
                defaultValue={fields.threshold ?? 0.8}
                required
                className={inputClass}
              />
            </label>
            <label className="space-y-1.5">
              <span className={LABEL}>Escalate when</span>
              <select
                name="escalate_when"
                defaultValue={fields.escalateWhen ?? "suspicious"}
                className={inputClass}
              >
                {ESCALATE_VALUES.map((v) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </label>
          </div>
        )}

        {state.error === undefined ? null : (
          <p
            role="alert"
            className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm whitespace-pre-wrap text-red-300"
          >
            {state.error}
          </p>
        )}
        {state.ok === undefined ? null : (
          <p
            role="status"
            className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300"
          >
            {state.ok}
          </p>
        )}

        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={pending || state.ok !== undefined}
            className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {pending ? "Validating…" : "Save & activate"}
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

/** "Edit" for one catalog control; opens a form that saves back into the catalog file. */
export function ControlEditor(props: {
  id: string;
  baseSha: string;
  fields: ControlFields;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        onClick={() => {
          setOpen(true);
        }}
        title={`Edit ${props.id}`}
        aria-label={`Edit ${props.id}`}
        className="inline-flex h-7 w-7 items-center justify-center rounded-md text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
      >
        <PencilIcon className="h-4 w-4" />
      </button>
      {open ? (
        <Form
          {...props}
          onClose={() => {
            setOpen(false);
          }}
        />
      ) : null}
    </>
  );
}
