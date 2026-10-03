"use client";

import { useState } from "react";

import { ProviderIcon } from "@/components/provider-icon";
import { inputClass } from "@/components/ui";
import type { ModelIcon } from "@/lib/llm/models";

/** Native select (keyboard + mobile friendly) with the chosen provider's logo beside it. */
export function ModelSelect({
  name,
  defaultValue,
  options,
}: {
  name: string;
  defaultValue: string;
  options: { value: string; label: string; icon: ModelIcon }[];
}) {
  const [value, setValue] = useState(defaultValue);
  const current = options.find((o) => o.value === value) ?? options[0];
  return (
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
  );
}
