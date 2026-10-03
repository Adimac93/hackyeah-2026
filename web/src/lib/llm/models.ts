// Which chat models the assistant can use. Pure (env is passed in), so it's unit-testable.
// A provider only shows up when its API key is configured; the offline mock is always there
// so the demo never depends on a third-party API.
import type { ChatTurn } from "../assistant.ts";
import { isPresetId, presetForBaseUrl } from "./presets.ts";
import type { ConnectionKind, PresetId } from "./presets.ts";

export type ProviderId =
  "gateway" | "anthropic" | "openai" | "compatible" | "mock";

/** Logo to show next to a model. */
export type ModelIcon = PresetId | "gateway" | "mock";

export interface ModelOption {
  /** stable id stored in the DB: `<provider>:<model>`, or `db:<connection id>:<model>` */
  id: string;
  provider: ProviderId;
  model: string;
  label: string;
  icon: ModelIcon;
  /** set for console-managed connections; the server looks up their key by this id */
  connectionId?: string;
}

/** A console-managed connection, as members can read it (never includes the key). */
export interface LlmConnection {
  id: string;
  name: string;
  preset: string;
  kind: ConnectionKind;
  base_url: string | null;
  models: string[];
  enabled: boolean;
}

type Env = Record<string, string | undefined>;

export const MOCK_MODEL_ID = "mock:security-assistant";

const DEFAULT_ANTHROPIC_MODELS = [
  "claude-opus-5-5",
  "claude-sonnet-5-5",
  "claude-haiku-4-5",
];
const DEFAULT_OPENAI_MODELS = ["gpt-5", "gpt-5-mini"];
/** first entry of the gateway's `[models] allowed` list in policy/control-catalog.toml */
const DEFAULT_GATEWAY_MODELS = ["llama3.1:8b"];

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
export function availableModels(
  env: Env,
  connections: LlmConnection[] = [],
): ModelOption[] {
  const options: ModelOption[] = [];

  // through the AI Control Layer gateway: every prompt and answer is policed and audited.
  // First, so the demo default is the protected path.
  if (configured(env.GATEWAY_URL) && configured(env.GATEWAY_API_KEY)) {
    for (const model of parseModelList(
      env.GATEWAY_MODELS,
      DEFAULT_GATEWAY_MODELS,
    )) {
      options.push({
        id: `gateway:${model}`,
        provider: "gateway",
        model,
        label: `Gateway ${model} (protected)`,
        icon: "gateway",
      });
    }
  }

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
        icon: "anthropic",
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
        icon: "openai",
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
        icon: presetForBaseUrl(env.LLM_COMPATIBLE_BASE_URL),
      });
    }
  }

  // added by an admin on the Models page
  for (const connection of connections) {
    if (!connection.enabled) {
      continue;
    }
    for (const model of connection.models) {
      const anthropicLabel =
        connection.kind === "anthropic" && connection.name === "Anthropic"
          ? ANTHROPIC_LABELS[model]
          : undefined;
      options.push({
        id: `db:${connection.id}:${model}`,
        provider: connection.kind,
        model,
        label: anthropicLabel ?? `${connection.name} ${model}`,
        icon: isPresetId(connection.preset) ? connection.preset : "custom",
        connectionId: connection.id,
      });
    }
  }

  options.push({
    id: MOCK_MODEL_ID,
    provider: "mock",
    model: "security-assistant",
    label: "Offline demo (no API)",
    icon: "mock",
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

/**
 * The model to preselect: the conversation's own model while it's available,
 * then the organisation default set on the Models page, then the first (best)
 * option.
 */
export function defaultModel(
  preferred: string | null,
  options: ModelOption[],
  orgDefault: string | null = null,
): ModelOption {
  for (const id of [preferred, orgDefault]) {
    const found = id === null ? null : findModel(id, options);
    if (found !== null) {
      return found;
    }
  }
  return options[0];
}

/** Label for a stored model id, even if that provider is no longer configured. */
export function modelLabel(id: string, options: ModelOption[]): string {
  const found = findModel(id, options);
  if (found !== null) {
    return found.label;
  }
  // `db:<uuid>:<model>` — model ids can contain ":" themselves (llama3.1:8b)
  const prefixEnd = id.startsWith("db:") ? id.indexOf(":", 3) : id.indexOf(":");
  return id.slice(prefixEnd + 1);
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
