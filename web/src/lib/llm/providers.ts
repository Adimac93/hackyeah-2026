import Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";

import { buildSystemPrompt, mockProvider } from "@/lib/assistant";
import type { AssistantProvider, ChatTurn } from "@/lib/assistant";

import { describeProviderError, normalizeHistory } from "./models";
import type { ModelOption } from "./models";

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

async function callAnthropic(
  model: string,
  system: string,
  messages: ChatTurn[],
): Promise<string> {
  const client = new Anthropic({
    apiKey: process.env.ANTHROPIC_API_KEY,
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

function openAIClient(option: ModelOption): OpenAI {
  return option.provider === "openai"
    ? new OpenAI({
        apiKey: process.env.OPENAI_API_KEY,
        timeout: TIMEOUT_MS,
        maxRetries: 1,
      })
    : new OpenAI({
        baseURL: process.env.LLM_COMPATIBLE_BASE_URL,
        // local servers like Ollama ignore the key but the SDK requires one
        apiKey: process.env.LLM_COMPATIBLE_API_KEY ?? "not-needed",
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

  return async ({ history, policies }) => {
    const system = buildSystemPrompt(policies);
    const messages = normalizeHistory(history);
    try {
      const reply =
        option.provider === "anthropic"
          ? await callAnthropic(option.model, system, messages)
          : await callOpenAICompatible(
              openAIClient(option),
              option.model,
              system,
              messages,
            );
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
