"use client";

import { useState } from "react";

import { ActionForm } from "@/components/action-form";
import { ProviderIcon } from "@/components/provider-icon";
import { Field, inputClass } from "@/components/ui";
import type { FormState } from "@/lib/domain";
import { PRESETS, PRESET_IDS } from "@/lib/llm/presets";
import type { PresetId } from "@/lib/llm/presets";

export interface ProviderFormValues {
  preset: PresetId;
  name: string;
  baseUrl: string;
  models: string;
  enabled: boolean;
  keyHint: string | null;
}

export function ProviderForm({
  action,
  initial,
  submitLabel,
}: {
  action: (previous: FormState, formData: FormData) => Promise<FormState>;
  /** set when editing */
  initial?: ProviderFormValues;
  submitLabel: string;
}) {
  const isNew = initial === undefined;
  const [preset, setPreset] = useState<PresetId>(
    initial?.preset ?? "anthropic",
  );
  const [name, setName] = useState(initial?.name ?? PRESETS.anthropic.name);
  const [baseUrl, setBaseUrl] = useState(
    initial?.baseUrl ?? PRESETS.anthropic.baseUrl ?? "",
  );
  const [models, setModels] = useState(
    initial?.models ?? PRESETS.anthropic.models.join(", "),
  );
  // once the admin types in a field, switching presets stops overwriting it
  const [touched, setTouched] = useState({
    name: !isNew,
    baseUrl: !isNew,
    models: !isNew,
  });

  const current = PRESETS[preset];

  function choose(id: PresetId) {
    const next = PRESETS[id];
    setPreset(id);
    if (!touched.name) {
      setName(next.name);
    }
    if (!touched.baseUrl) {
      setBaseUrl(next.baseUrl ?? "");
    }
    if (!touched.models) {
      setModels(next.models.join(", "));
    }
  }

  return (
    <ActionForm
      action={action}
      submitLabel={submitLabel}
      pendingLabel="Saving…"
    >
      <fieldset>
        <legend className="mb-2 text-xs font-medium tracking-wide text-zinc-400 uppercase">
          Provider
        </legend>
        <div className="grid grid-cols-3 gap-2 sm:grid-cols-4 lg:grid-cols-5">
          {PRESET_IDS.map((id) => (
            <label
              key={id}
              className={`flex cursor-pointer flex-col items-center gap-1.5 rounded-lg border p-2.5 text-center text-xs transition-colors has-focus-visible:ring-2 has-focus-visible:ring-emerald-500 ${
                preset === id
                  ? "border-emerald-500/60 bg-emerald-500/10 text-zinc-100"
                  : "border-zinc-800 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200"
              }`}
            >
              <input
                type="radio"
                name="preset"
                value={id}
                checked={preset === id}
                onChange={() => {
                  choose(id);
                }}
                className="sr-only"
              />
              <ProviderIcon icon={id} />
              <span className="leading-tight">
                {id === "custom" ? "Custom" : PRESETS[id].name}
              </span>
            </label>
          ))}
        </div>
      </fieldset>

      <Field
        label="Display name"
        hint="Shown before each model in the chat picker."
      >
        <input
          name="name"
          value={name}
          onChange={(event) => {
            setName(event.target.value);
            setTouched((t) => ({ ...t, name: true }));
          }}
          maxLength={60}
          className={inputClass}
        />
      </Field>

      {current.kind === "anthropic" ? null : (
        <Field
          label="Base URL"
          hint="OpenAI-compatible endpoint. https only (plain http just for localhost)."
        >
          <input
            name="base_url"
            value={baseUrl}
            onChange={(event) => {
              setBaseUrl(event.target.value);
              setTouched((t) => ({ ...t, baseUrl: true }));
            }}
            placeholder="https://api.example.com/v1"
            className={inputClass}
          />
        </Field>
      )}

      <Field
        label="API key"
        hint={
          isNew || initial.keyHint === null
            ? current.keyHint
            : `Stored: ${initial.keyHint}. Leave blank to keep it.`
        }
      >
        <input
          name="api_key"
          type="password"
          autoComplete="off"
          required={isNew ? current.requiresKey : false}
          placeholder={
            current.requiresKey ? "Paste the key" : "Optional for this provider"
          }
          className={inputClass}
        />
      </Field>

      <Field
        label="Models"
        hint="Exact model ids, comma or newline separated. Check them in the provider's docs."
      >
        <textarea
          name="models"
          value={models}
          onChange={(event) => {
            setModels(event.target.value);
            setTouched((t) => ({ ...t, models: true }));
          }}
          rows={2}
          required
          className={inputClass}
        />
      </Field>

      <label className="flex items-center gap-2 text-sm text-zinc-300">
        <input
          type="checkbox"
          name="enabled"
          defaultChecked={initial?.enabled ?? true}
          className="accent-emerald-500"
        />
        Available in the assistant
      </label>
    </ActionForm>
  );
}
