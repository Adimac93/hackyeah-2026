"use client";

import { useEffect, useState } from "react";

import { ProviderIcon } from "@/components/provider-icon";
import { inputClass } from "@/components/ui";
import type { ModelIcon } from "@/lib/llm/models";
import type { ModelCheck } from "@/lib/llm/providers";

import { checkChatModel } from "./actions";

/** Status line under the picker: checking, works, or ask an admin. */
function CheckStatus({
  check,
  showDetails,
}: {
  check: ModelCheck | undefined;
  showDetails: boolean;
}) {
  if (check === undefined) {
    return (
      <p className="mt-1.5 flex items-center gap-1.5 text-xs text-zinc-500">
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-zinc-500" />
        Testing the model configuration…
      </p>
    );
  }
  if (check.ok) {
    return (
      <p className="mt-1.5 flex items-center gap-1.5 text-xs text-emerald-400">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
        Configuration works — the model is ready.
      </p>
    );
  }
  return (
    <p
      role="alert"
      className="mt-1.5 flex items-start gap-1.5 text-xs text-amber-300"
    >
      <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400" />
      <span>
        This model&apos;s configuration isn&apos;t working. Contact your
        administrator.
        {showDetails ? (
          <span className="block text-zinc-500">{check.reason}</span>
        ) : null}
      </span>
    </p>
  );
}

/**
 * Native select (keyboard + mobile friendly) with the chosen provider's logo
 * beside it. Each model is tested once when picked, and the result shows below.
 */
export function ModelSelect({
  name,
  defaultValue,
  options,
  showDetails = false,
}: {
  name: string;
  defaultValue: string;
  options: { value: string; label: string; icon: ModelIcon }[];
  /** admins also see why a check failed */
  showDetails?: boolean;
}) {
  const [value, setValue] = useState(defaultValue);
  const [checks, setChecks] = useState<Record<string, ModelCheck>>({});
  const current = options.find((o) => o.value === value) ?? options[0];
  const tested = value in checks;

  useEffect(() => {
    if (tested) {
      return;
    }
    let cancelled = false;
    void checkChatModel(value)
      .catch((): ModelCheck => ({ ok: false, reason: "The check failed." }))
      .then((result) => {
        if (!cancelled) {
          setChecks((previous) => ({ ...previous, [value]: result }));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [value, tested]);

  return (
    <div>
      <div className="flex items-center gap-2">
        <ProviderIcon icon={current.icon} title={current.label} />
        <select
          name={name}
          value={value}
          onChange={(event) => {
            setValue(event.target.value);
          }}
          className={inputClass}
        >
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>
      <CheckStatus check={checks[value]} showDetails={showDetails} />
    </div>
  );
}
