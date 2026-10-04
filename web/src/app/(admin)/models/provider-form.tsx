"use client";

import { useState, useTransition } from "react";

import { ActionForm } from "@/components/action-form";
import { ProviderIcon } from "@/components/provider-icon";
import { Field, inputClass } from "@/components/ui";
import type { FormState } from "@/lib/domain";
import { PRESETS, PRESET_IDS } from "@/lib/llm/presets";
import type { PresetId } from "@/lib/llm/presets";

import { discoverModels } from "./actions";

export interface ProviderFormValues {
  preset: PresetId;
  name: string;
  baseUrl: string;
  models: string;
  enabled: boolean;
  keyHint: string | null;
}

/** The model ids in the textarea, as the server action will parse them. */
function splitModels(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((m) => m.trim())
    .filter((m) => m !== "");
}

export function ProviderForm({
  action,
  initial,
  submitLabel,
  defaultPreset = "anthropic",
  connectionId,
  returnTo,
}: {
  action: (previous: FormState, formData: FormData) => Promise<FormState>;
  /** set when editing */
  initial?: ProviderFormValues;
  submitLabel: string;
  /** preset a new connection starts on */
  defaultPreset?: PresetId;
  /** set when editing, so "Fetch models" can use the stored key */
  connectionId?: string;
  /** page to land on after creating (the action allow-lists it) */
  returnTo?: string;
}) {
  const isNew = initial === undefined;
  const start = PRESETS[defaultPreset];
  const [preset, setPreset] = useState<PresetId>(
    initial?.preset ?? defaultPreset,
  );
  const [name, setName] = useState(initial?.name ?? start.name);
  const [baseUrl, setBaseUrl] = useState(
    initial?.baseUrl ?? start.baseUrl ?? "",
  );
  const [models, setModels] = useState(
    initial?.models ?? start.models.join(", "),
  );
  const [apiKey, setApiKey] = useState("");
  const [found, setFound] = useState<string[] | null>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [fetching, startFetch] = useTransition();
  // once the admin types in a field, switching presets stops overwriting it
  const [touched, setTouched] = useState({
    name: !isNew,
    baseUrl: !isNew,
    models: !isNew,
  });

  const current = PRESETS[preset];
  const chosen = new Set(splitModels(models));

  function fetchModels() {
    setFetchError(null);
    startFetch(async () => {
      const result = await discoverModels({
        preset,
        baseUrl,
        apiKey,
        connectionId,
      }).catch(() => ({ ok: false as const, error: "The request failed." }));
      if (result.ok) {
        setFound(result.models);
      } else {
        setFound(null);
        setFetchError(result.error);
      }
    });
  }

  function toggleModel(id: string) {
    const list = splitModels(models);
    setModels(
      (chosen.has(id) ? list.filter((m) => m !== id) : [...list, id]).join(
        ", ",
      ),
    );
    setTouched((t) => ({ ...t, models: true }));
  }

  function choose(id: PresetId) {
    const next = PRESETS[id];
    setPreset(id);
    setFound(null);
    setFetchError(null);
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
      {returnTo === undefined ? null : (
        <input type="hidden" name="return_to" value={returnTo} />
      )}
      <fieldset>
        <legend className="eyebrow mb-2 text-zinc-400">Provider</legend>
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
          value={apiKey}
          onChange={(event) => {
            setApiKey(event.target.value);
          }}
          required={isNew ? current.requiresKey : false}
          placeholder={
            current.requiresKey ? "Paste the key" : "Optional for this provider"
          }
          className={inputClass}
        />
      </Field>

      <div>
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
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={fetchModels}
            disabled={fetching}
            className="rounded-md border border-zinc-700 px-2.5 py-1 text-xs text-zinc-300 transition-colors hover:border-zinc-500 hover:text-zinc-100 disabled:opacity-50"
          >
            {fetching ? "Fetching…" : "Fetch models"}
          </button>
          <span className="text-xs text-zinc-500">
            Lists what the endpoint serves; click to add or remove.
          </span>
        </div>
        {fetchError === null ? null : (
          <p role="alert" className="mt-2 text-xs text-amber-300">
            {fetchError}
          </p>
        )}
        {found === null ? null : (
          <div className="mt-2 flex max-h-40 flex-wrap gap-1 overflow-y-auto">
            {found.map((id) => (
              <button
                key={id}
                type="button"
                aria-pressed={chosen.has(id)}
                onClick={() => {
                  toggleModel(id);
                }}
                className={`rounded px-1.5 py-0.5 font-mono text-xs ring-1 transition-colors ring-inset ${
                  chosen.has(id)
                    ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40"
                    : "bg-zinc-800 text-zinc-400 ring-zinc-700 hover:text-zinc-200"
                }`}
              >
                {id}
              </button>
            ))}
          </div>
        )}
      </div>

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
