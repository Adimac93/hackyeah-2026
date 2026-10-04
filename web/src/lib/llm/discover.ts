// Ask a provider which models it serves. Server only: it calls an admin-supplied URL.
import Anthropic from "@anthropic-ai/sdk";

import type { ConnectionKind } from "./presets.ts";

const TIMEOUT_MS = 10_000;
/** `llm_providers.models` holds at most 50 ids. */
export const MAX_MODELS = 50;

export type ModelList =
  { ok: true; models: string[] } | { ok: false; error: string };

/**
 * Model ids from an OpenAI-style `/models` body (`{ data: [{ id }] }`), which
 * OpenAI, vLLM, TGI, Ollama's /v1 and most proxies answer. Sorted, de-duplicated,
 * capped at the table's limit; anything else is ignored.
 */
export function parseModelList(body: unknown): string[] {
  if (typeof body !== "object" || body === null || !("data" in body)) {
    return [];
  }
  const { data } = body as { data: unknown };
  if (!Array.isArray(data)) {
    return [];
  }
  const ids = new Set<string>();
  for (const entry of data) {
    const id =
      typeof entry === "object" && entry !== null && "id" in entry
        ? (entry as { id: unknown }).id
        : null;
    if (typeof id === "string" && id.trim() !== "" && id.length <= 120) {
      ids.add(id.trim());
    }
  }
  return [...ids].toSorted((a, b) => a.localeCompare(b)).slice(0, MAX_MODELS);
}

/** List the models a connection can reach. A cheap credential check too: no tokens spent. */
export async function listProviderModels(connection: {
  kind: ConnectionKind;
  baseUrl: string | null;
  apiKey: string | null;
}): Promise<ModelList> {
  try {
    if (connection.kind === "anthropic") {
      const client = new Anthropic({
        apiKey: connection.apiKey ?? undefined,
        timeout: TIMEOUT_MS,
        maxRetries: 0,
      });
      const page = await client.models.list({ limit: 100 });
      return { ok: true, models: parseModelList({ data: page.data }) };
    }

    const base = (connection.baseUrl ?? "https://api.openai.com/v1").replace(
      /\/+$/,
      "",
    );
    const response = await fetch(`${base}/models`, {
      headers:
        connection.apiKey === null
          ? {}
          : { authorization: `Bearer ${connection.apiKey}` },
      signal: AbortSignal.timeout(TIMEOUT_MS),
      redirect: "error",
    });
    if (response.status === 401 || response.status === 403) {
      return { ok: false, error: "The provider rejected the API key." };
    }
    if (!response.ok) {
      return {
        ok: false,
        error: `The provider answered HTTP ${String(response.status)}.`,
      };
    }
    return {
      ok: true,
      models: parseModelList(await response.json().catch(() => null)),
    };
  } catch (error) {
    if (error instanceof Anthropic.APIError) {
      return {
        ok: false,
        error:
          error.status === 401
            ? "The provider rejected the API key."
            : `The provider answered HTTP ${String(error.status)}.`,
      };
    }
    // network errors: don't echo internals, just the kind
    return {
      ok: false,
      error: `Couldn't reach the provider (${error instanceof Error ? error.name : "unknown error"}).`,
    };
  }
}
