import Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";

import { buildSystemPrompt, mockProvider } from "@/lib/assistant";
import type { AssistantProvider, ChatTurn } from "@/lib/assistant";

import { interpretGatewayResponse } from "./gateway";
import { describeProviderError, normalizeHistory } from "./models";
import type { ModelOption } from "./models";
import { loadConnectionSecret } from "./secrets";

const TIMEOUT_MS = 60_000;
const MAX_TOKENS = 16_000;

/** Claude models that take server-side refusal fallbacks and `output_config.effort`. */
const CLAUDE_5_FAMILY = new Set([
  "claude-fable-5-1",
  "claude-opus-5-5",
  "claude-sonnet-5-5",
]);

const REFUSAL_REPLY =
  "I can't help with that request. If you think this is a mistake, rephrase it or ask the security team directly.";

/** Thrown for provider failures; `message` is safe to show to the user. */
export class ProviderError extends Error {}

/** Where to send a request: env config, or a console-managed connection's stored settings. */
interface Credentials {
  apiKey: string | undefined;
  baseUrl: string | undefined;
}

/** A console connection's settings, with its key decrypted from Vault (server only). */
async function connectionCredentials(
  connectionId: string,
): Promise<Credentials> {
  const connection = await loadConnectionSecret(connectionId);
  if (connection === "no-service-key") {
    throw new ProviderError(
      "Console-managed models need SUPABASE_SECRET_KEY on the server.",
    );
  }
  if (connection?.enabled !== true) {
    throw new ProviderError("This model was removed or disabled by an admin.");
  }
  return {
    apiKey: connection.apiKey ?? undefined,
    baseUrl: connection.baseUrl ?? undefined,
  };
}

function envCredentials(option: ModelOption): Credentials {
  if (option.provider === "anthropic") {
    return { apiKey: process.env.ANTHROPIC_API_KEY, baseUrl: undefined };
  }
  if (option.provider === "openai") {
    return { apiKey: process.env.OPENAI_API_KEY, baseUrl: undefined };
  }
  return {
    apiKey: process.env.LLM_COMPATIBLE_API_KEY,
    baseUrl: process.env.LLM_COMPATIBLE_BASE_URL,
  };
}

async function callAnthropic(
  credentials: Credentials,
  model: string,
  system: string,
  messages: ChatTurn[],
): Promise<string> {
  const client = new Anthropic({
    apiKey: credentials.apiKey,
    timeout: TIMEOUT_MS,
    maxRetries: 1,
  });
  const fiveFamily = CLAUDE_5_FAMILY.has(model);
  const response = await client.beta.messages.create({
    model,
    max_tokens: MAX_TOKENS,
    system,
    messages,
    ...(fiveFamily
      ? {
          // chat answers don't need deep reasoning; keeps latency and cost down
          output_config: { effort: "medium" },
          betas: ["server-side-fallback-2026-07-01"],
          fallbacks: "default",
        }
      : {}),
  });
  if (response.stop_reason === "refusal") {
    return REFUSAL_REPLY;
  }
  return response.content
    .flatMap((block) => (block.type === "text" ? [block.text] : []))
    .join("\n")
    .trim();
}

async function callOpenAICompatible(
  client: OpenAI,
  model: string,
  system: string,
  messages: ChatTurn[],
): Promise<string> {
  const completion = await client.chat.completions.create({
    model,
    messages: [{ role: "system", content: system }, ...messages],
  });
  return completion.choices[0]?.message.content?.trim() ?? "";
}

/** Through the AI Control Layer gateway. Plain fetch: we need its refusal bodies and `x_control_layer`. */
async function callGateway(
  model: string,
  system: string,
  messages: ChatTurn[],
  principal: string | undefined,
): Promise<string> {
  const base = (process.env.GATEWAY_URL ?? "").replace(/\/+$/, "");
  let response: Response;
  try {
    response = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        // the gateway resolves the calling principal from this key; no key, no call
        authorization: `Bearer ${(process.env.GATEWAY_API_KEY ?? "").trim()}`,
        // the console-chat principal delegates: budgets, risk and activity are per user
        ...(principal === undefined ? {} : { "x-on-behalf-of": principal }),
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "system", content: system }, ...messages],
      }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    console.error(
      "[assistant] gateway unreachable",
      error instanceof Error ? error.name : "unknown",
    );
    throw new ProviderError(
      "The AI Control Layer gateway is unreachable. Is it running?",
    );
  }
  const body: unknown = await response.json().catch(() => null);
  const outcome = interpretGatewayResponse(response.status, body);
  if (!outcome.ok) {
    console.error("[assistant] gateway failed", response.status);
    throw new ProviderError(outcome.error);
  }
  return outcome.reply;
}

function openAIClient(credentials: Credentials): OpenAI {
  return new OpenAI({
    // undefined = api.openai.com
    baseURL: credentials.baseUrl,
    // local servers like Ollama ignore the key but the SDK requires one
    apiKey: credentials.apiKey ?? "not-needed",
    timeout: TIMEOUT_MS,
    maxRetries: 1,
  });
}

function statusOf(error: unknown): number | undefined {
  const status: unknown =
    error instanceof Anthropic.APIError || error instanceof OpenAI.APIError
      ? error.status
      : undefined;
  return typeof status === "number" ? status : undefined;
}

/** The assistant backed by the chosen model. */
export function getAssistant(option: ModelOption): AssistantProvider {
  if (option.provider === "mock") {
    return mockProvider;
  }

  return async ({ history, policies, principal }) => {
    const system = buildSystemPrompt(policies);
    const messages = normalizeHistory(history);
    try {
      let reply: string;
      if (option.provider === "gateway") {
        reply = await callGateway(option.model, system, messages, principal);
      } else {
        const credentials =
          option.connectionId === undefined
            ? envCredentials(option)
            : await connectionCredentials(option.connectionId);
        reply =
          option.provider === "anthropic"
            ? await callAnthropic(credentials, option.model, system, messages)
            : await callOpenAICompatible(
                openAIClient(credentials),
                option.model,
                system,
                messages,
              );
      }
      if (reply === "") {
        throw new ProviderError(`${option.label} returned an empty reply.`);
      }
      return reply;
    } catch (error) {
      if (error instanceof ProviderError) {
        throw error;
      }
      const status = statusOf(error);
      // log status only: provider error bodies can echo request content
      console.error(
        `[assistant] ${option.id} failed`,
        status ?? (error instanceof Error ? error.name : "unknown"),
      );
      throw new ProviderError(describeProviderError(option.label, status));
    }
  };
}

const CHECK_TIMEOUT_MS = 10_000;

/** Outcome of a model check; `reason` is safe to show (no keys, no response bodies). */
export type ModelCheck = { ok: true } | { ok: false; reason: string };

/** Ids the provider lists, or why it couldn't list them. Spends no tokens. */
async function listedModels(
  option: ModelOption,
  credentials: Credentials,
): Promise<string[]> {
  if (option.provider === "anthropic") {
    const client = new Anthropic({
      apiKey: credentials.apiKey,
      timeout: CHECK_TIMEOUT_MS,
      maxRetries: 0,
    });
    const page = await client.models.list({ limit: 1000 });
    return page.data.map((m) => m.id);
  }
  const page = await openAIClient(credentials).models.list({
    timeout: CHECK_TIMEOUT_MS,
    maxRetries: 0,
  });
  return page.data.map((m) => m.id);
}

/**
 * Cheap pre-flight for the chat's model picker: can this model answer right now?
 * Providers list their models (no tokens spent) and must include this one; the
 * gateway must be up with its audit database and have an API key configured.
 */
export async function checkModel(option: ModelOption): Promise<ModelCheck> {
  if (option.provider === "mock") {
    return { ok: true };
  }
  if (option.provider === "gateway") {
    if ((process.env.GATEWAY_API_KEY ?? "").trim() === "") {
      return { ok: false, reason: "GATEWAY_API_KEY is not set." };
    }
    const base = (process.env.GATEWAY_URL ?? "").replace(/\/+$/, "");
    try {
      const response = await fetch(`${base}/health`, {
        signal: AbortSignal.timeout(CHECK_TIMEOUT_MS),
        cache: "no-store",
      });
      const body = (await response.json().catch(() => null)) as {
        status?: string;
        database?: string;
      } | null;
      if (!response.ok || body?.status !== "ok") {
        return { ok: false, reason: "The gateway is not healthy." };
      }
      if (body.database !== "connected") {
        return { ok: false, reason: "The gateway's audit database is down." };
      }
      return { ok: true };
    } catch {
      return { ok: false, reason: "The gateway is unreachable." };
    }
  }

  try {
    const credentials =
      option.connectionId === undefined
        ? envCredentials(option)
        : await connectionCredentials(option.connectionId);
    const models = await listedModels(option, credentials);
    // some OpenAI-compatible servers return an empty list; don't fail on that
    if (models.length > 0 && !models.includes(option.model)) {
      return {
        ok: false,
        reason: `The provider doesn't offer ${option.model}.`,
      };
    }
    return { ok: true };
  } catch (error) {
    if (error instanceof ProviderError) {
      return { ok: false, reason: error.message };
    }
    const status = statusOf(error);
    console.error(
      `[assistant] check ${option.id} failed`,
      status ?? (error instanceof Error ? error.name : "unknown"),
    );
    if (status === 401 || status === 403) {
      return { ok: false, reason: "The provider rejected the API key." };
    }
    return {
      ok: false,
      reason:
        status === undefined
          ? "The provider is unreachable."
          : `The provider answered HTTP ${String(status)}.`,
    };
  }
}
