// Known LLM providers: how to reach them and which logo to show. Pure, unit-testable.

export type ConnectionKind = "anthropic" | "openai" | "compatible";

export const PRESET_IDS = [
  "anthropic",
  "openai",
  "gemini",
  "mistral",
  "deepseek",
  "xai",
  "meta",
  "groq",
  "openrouter",
  "perplexity",
  "huggingface",
  "ollama",
  "custom",
] as const;
export type PresetId = (typeof PRESET_IDS)[number];

export interface Preset {
  id: PresetId;
  name: string;
  kind: ConnectionKind;
  /** default endpoint; null = the SDK's own (Anthropic) */
  baseUrl: string | null;
  /** suggested model ids — admins can change them */
  models: string[];
  requiresKey: boolean;
  keyHint: string;
}

export const PRESETS: Record<PresetId, Preset> = {
  anthropic: {
    id: "anthropic",
    name: "Anthropic",
    kind: "anthropic",
    baseUrl: null,
    models: ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-4-5"],
    requiresKey: true,
    keyHint: "console.anthropic.com → API Keys (sk-ant-…)",
  },
  openai: {
    id: "openai",
    name: "OpenAI",
    kind: "openai",
    baseUrl: "https://api.openai.com/v1",
    models: ["gpt-5", "gpt-5-mini"],
    requiresKey: true,
    keyHint: "platform.openai.com → API keys (sk-…)",
  },
  gemini: {
    id: "gemini",
    name: "Google Gemini",
    kind: "compatible",
    baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai/",
    models: ["gemini-3.8-flash", "gemini-2.5-pro"],
    requiresKey: true,
    keyHint: "aistudio.google.com → Get API key",
  },
  mistral: {
    id: "mistral",
    name: "Mistral AI",
    kind: "compatible",
    baseUrl: "https://api.mistral.ai/v1",
    models: ["mistral-large-latest", "mistral-small-latest"],
    requiresKey: true,
    keyHint: "console.mistral.ai → API Keys",
  },
  deepseek: {
    id: "deepseek",
    name: "DeepSeek",
    kind: "compatible",
    baseUrl: "https://api.deepseek.com/v1",
    models: ["deepseek-chat", "deepseek-reasoner"],
    requiresKey: true,
    keyHint: "platform.deepseek.com → API keys",
  },
  xai: {
    id: "xai",
    name: "xAI Grok",
    kind: "compatible",
    baseUrl: "https://api.x.ai/v1",
    models: [],
    requiresKey: true,
    keyHint: "console.x.ai → API Keys",
  },
  meta: {
    id: "meta",
    name: "Meta Llama",
    kind: "compatible",
    baseUrl: "https://api.llama.com/compat/v1/",
    models: [],
    requiresKey: true,
    keyHint: "llama.developer.meta.com → API keys",
  },
  groq: {
    id: "groq",
    name: "Groq",
    kind: "compatible",
    baseUrl: "https://api.groq.com/openai/v1",
    models: [],
    requiresKey: true,
    keyHint: "console.groq.com → API Keys",
  },
  openrouter: {
    id: "openrouter",
    name: "OpenRouter",
    kind: "compatible",
    baseUrl: "https://openrouter.ai/api/v1",
    models: [],
    requiresKey: true,
    keyHint: "openrouter.ai → Keys",
  },
  perplexity: {
    id: "perplexity",
    name: "Perplexity",
    kind: "compatible",
    baseUrl: "https://api.perplexity.ai",
    models: ["sonar", "sonar-pro"],
    requiresKey: true,
    keyHint: "perplexity.ai → Settings → API",
  },
  huggingface: {
    id: "huggingface",
    name: "Hugging Face",
    kind: "compatible",
    baseUrl: "https://router.huggingface.co/v1",
    models: [],
    requiresKey: true,
    keyHint: "huggingface.co → Settings → Access Tokens",
  },
  ollama: {
    id: "ollama",
    name: "Ollama",
    kind: "compatible",
    baseUrl: "http://localhost:11434/v1",
    models: ["llama3.1:8b"],
    requiresKey: false,
    keyHint: "Local server — no key needed",
  },
  custom: {
    id: "custom",
    name: "Custom (OpenAI-compatible)",
    kind: "compatible",
    baseUrl: null,
    models: [],
    requiresKey: false,
    keyHint: "Whatever the server expects as a Bearer token",
  },
};

export function isPresetId(value: string): value is PresetId {
  return (PRESET_IDS as readonly string[]).includes(value);
}

const HOST_PRESETS: [RegExp, PresetId][] = [
  [/(^|\.)anthropic\.com$/, "anthropic"],
  [/(^|\.)openai\.com$/, "openai"],
  [/(^|\.)googleapis\.com$/, "gemini"],
  [/(^|\.)mistral\.ai$/, "mistral"],
  [/(^|\.)deepseek\.com$/, "deepseek"],
  [/(^|\.)x\.ai$/, "xai"],
  [/(^|\.)llama\.com$/, "meta"],
  [/(^|\.)groq\.com$/, "groq"],
  [/(^|\.)openrouter\.ai$/, "openrouter"],
  [/(^|\.)perplexity\.ai$/, "perplexity"],
  [/(^|\.)huggingface\.co$/, "huggingface"],
];

/** Best-guess logo for an endpoint (env-configured compatible providers have no preset). */
export function presetForBaseUrl(baseUrl?: string): PresetId {
  if (baseUrl === undefined) {
    return "custom";
  }
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    return "custom";
  }
  if (url.port === "11434") {
    return "ollama";
  }
  return HOST_PRESETS.find(([re]) => re.test(url.hostname))?.[1] ?? "custom";
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Endpoint the server will call with an admin-supplied URL. https anywhere, plain http only
 * for a local server (Ollama), and never cloud metadata / link-local addresses.
 */
export function validateBaseUrl(
  raw: string,
): { ok: true; value: string } | { ok: false; error: string } {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    return { ok: false, error: "Base URL must be a full URL, e.g. https://…" };
  }
  if (url.username !== "" || url.password !== "") {
    return {
      ok: false,
      error: "Put credentials in the API key field, not the URL.",
    };
  }
  if (
    url.hostname.startsWith("169.254.") ||
    url.hostname === "metadata.google.internal"
  ) {
    return { ok: false, error: "That address isn't allowed." };
  }
  if (url.protocol === "http:" && !LOCAL_HOSTS.has(url.hostname)) {
    return { ok: false, error: "Use https (plain http only for localhost)." };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, error: "Base URL must start with https://" };
  }
  return { ok: true, value: url.toString() };
}

export interface ProviderInput {
  name: string;
  preset: PresetId;
  kind: ConnectionKind;
  baseUrl: string | null;
  /** null = keep the stored key (edits) / none (keyless presets) */
  apiKey: string | null;
  models: string[];
  enabled: boolean;
}

/** Validate the admin form. `isNew` decides whether a missing key is an error or "keep". */
export function parseProviderInput(
  fields: Record<string, string | undefined>,
  isNew: boolean,
): { ok: true; value: ProviderInput } | { ok: false; error: string } {
  const presetRaw = (fields.preset ?? "").trim();
  if (!isPresetId(presetRaw)) {
    return { ok: false, error: "Pick a provider." };
  }
  const preset = PRESETS[presetRaw];

  const name = (fields.name ?? "").trim() || preset.name;
  if (name.length > 60) {
    return { ok: false, error: "Keep the name under 60 characters." };
  }

  let baseUrl: string | null = null;
  const rawUrl = (fields.base_url ?? "").trim();
  if (preset.kind !== "anthropic") {
    const candidate = rawUrl || preset.baseUrl;
    if (candidate === null) {
      return { ok: false, error: "This provider needs a base URL." };
    }
    const checked = validateBaseUrl(candidate);
    if (!checked.ok) {
      return checked;
    }
    baseUrl = checked.value;
  }

  const models = [
    ...new Set(
      (fields.models ?? "")
        .split(/[\n,]/)
        .map((m) => m.trim())
        .filter((m) => m !== ""),
    ),
  ];
  if (models.length === 0) {
    return { ok: false, error: "List at least one model id." };
  }
  if (models.length > 50 || models.some((m) => m.length > 120)) {
    return { ok: false, error: "That model list is too long." };
  }

  const key = (fields.api_key ?? "").trim();
  if (isNew && preset.requiresKey && key === "") {
    return { ok: false, error: `${preset.name} needs an API key.` };
  }

  return {
    ok: true,
    value: {
      name,
      preset: preset.id,
      kind: preset.kind,
      baseUrl,
      apiKey: key === "" ? null : key,
      models,
      enabled: fields.enabled === "on" || fields.enabled === "true",
    },
  };
}
