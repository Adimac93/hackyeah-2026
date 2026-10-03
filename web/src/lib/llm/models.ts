// Which chat models the assistant can use. Pure (env is passed in), so it's unit-testable.
// A provider only shows up when its API key is configured; the offline mock is always there
// so the demo never depends on a third-party API.
import type { ChatTurn } from "../assistant.ts";

export type ProviderId = "anthropic" | "openai" | "compatible" | "mock";

export interface ModelOption {
  /** stable id stored in the DB: `<provider>:<model>` */
  id: string;
  provider: ProviderId;
  model: string;
  label: string;
}

type Env = Record<string, string | undefined>;

export const MOCK_MODEL_ID = "mock:security-assistant";

const DEFAULT_ANTHROPIC_MODELS = [
  "claude-opus-5-5",
  "claude-sonnet-5-5",
  "claude-haiku-4-5",
];
const DEFAULT_OPENAI_MODELS = ["gpt-5", "gpt-5-mini"];

const ANTHROPIC_LABELS: Record<string, string> = {
  "claude-fable-5-1": "Claude Fable 5.1",
  "claude-opus-5-5": "Claude Opus 5.5",
  "claude-sonnet-5-5": "Claude Sonnet 5.5",
  "claude-haiku-4-5": "Claude Haiku 4.5",
};

/** Comma-separated model list from env, or the fallback when unset/empty. */
export function parseModelList(
  raw: string | undefined,
  fallback: string[],
): string[] {
  const list = (raw ?? "")
    .split(",")
    .map((m) => m.trim())
    .filter((m) => m !== "");
  return list.length > 0 ? [...new Set(list)] : fallback;
}

function configured(value: string | undefined): value is string {
  return value !== undefined && value.trim() !== "";
}

/** Every selectable model, best default first. */
export function availableModels(env: Env): ModelOption[] {
  const options: ModelOption[] = [];

  if (configured(env.ANTHROPIC_API_KEY)) {
    for (const model of parseModelList(
      env.ANTHROPIC_MODELS,
      DEFAULT_ANTHROPIC_MODELS,
    )) {
      options.push({
        id: `anthropic:${model}`,
        provider: "anthropic",
        model,
        label: ANTHROPIC_LABELS[model] ?? model,
      });
    }
  }

  if (configured(env.OPENAI_API_KEY)) {
    for (const model of parseModelList(
      env.OPENAI_MODELS,
      DEFAULT_OPENAI_MODELS,
    )) {
      options.push({
        id: `openai:${model}`,
        provider: "openai",
        model,
        label: `OpenAI ${model}`,
      });
    }
  }

  // any OpenAI-compatible API: Groq, OpenRouter, Mistral, Ollama, vLLM…
  if (configured(env.LLM_COMPATIBLE_BASE_URL)) {
    const name = configured(env.LLM_COMPATIBLE_NAME)
      ? env.LLM_COMPATIBLE_NAME.trim()
      : "Custom";
    for (const model of parseModelList(env.LLM_COMPATIBLE_MODELS, [])) {
      options.push({
        id: `compatible:${model}`,
        provider: "compatible",
        model,
        label: `${name} ${model}`,
      });
    }
  }

  options.push({
    id: MOCK_MODEL_ID,
    provider: "mock",
    model: "security-assistant",
    label: "Offline demo (no API)",
  });
  return options;
}

/** The option for an id, or null if it isn't currently available (unknown or key removed). */
export function findModel(
  id: string,
  options: ModelOption[],
): ModelOption | null {
  return options.find((o) => o.id === id) ?? null;
}

/** Preferred id when it's still available, otherwise the first (best) option. */
export function defaultModel(
  preferred: string | null,
  options: ModelOption[],
): ModelOption {
  return (
    (preferred === null ? null : findModel(preferred, options)) ?? options[0]
  );
}

/** Label for a stored model id, even if that provider is no longer configured. */
export function modelLabel(id: string, options: ModelOption[]): string {
  return findModel(id, options)?.label ?? id.slice(id.indexOf(":") + 1);
}

/** Most recent turns only, merged so roles alternate and the first turn is the user's. */
export function normalizeHistory(
  history: ChatTurn[],
  maxTurns = 20,
): ChatTurn[] {
  const merged: ChatTurn[] = [];
  for (const turn of history) {
    const last = merged.at(-1);
    if (last?.role === turn.role) {
      last.content = `${last.content}\n\n${turn.content}`;
    } else {
      merged.push({ ...turn });
    }
  }
  const recent = merged.slice(-maxTurns);
  while (recent[0]?.role === "assistant") {
    recent.shift();
  }
  return recent;
}

/** Human-readable reason for a failed provider call; never includes provider response bodies. */
export function describeProviderError(label: string, status?: number): string {
  if (status === 401 || status === 403) {
    return `${label} rejected the API key. Check the server configuration.`;
  }
  if (status === 404) {
    return `${label} is not available for this API key.`;
  }
  if (status === 429) {
    return `${label} is rate limited right now. Try again shortly.`;
  }
  if (status !== undefined && status >= 500) {
    return `${label} is having problems right now. Try again or pick another model.`;
  }
  return `${label} could not be reached. Try again or pick another model.`;
}
