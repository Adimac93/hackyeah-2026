// AI security assistant: pure logic shared by every model. No framework imports, so it's unit-testable.
// Real model calls live in `lib/llm/providers.ts`; `mockProvider` is the offline fallback.

export type ChatRole = "user" | "assistant";
export interface ChatTurn {
  role: ChatRole;
  content: string;
}
export interface PolicySnippet {
  title: string;
  category: string;
  summary: string;
  body: string;
}

export interface ChatConversation {
  id: string;
  user_id: string;
  title: string;
  model: string;
  created_at: string;
  updated_at: string;
}
export type ChatMessage = ChatTurn & {
  id: number;
  conversation_id: string;
  created_at: string;
  /** which model wrote an assistant reply; null for the user's messages */
  model: string | null;
};

export type AssistantProvider = (input: {
  history: ChatTurn[];
  policies: PolicySnippet[];
  /** who is asking; the gateway attributes audit events and budgets to it */
  principal?: string;
}) => Promise<string>;

type Result<T> = { ok: true; value: T } | { ok: false; error: string };

export const MAX_MESSAGE_LENGTH = 4000;

export function parseChatMessage(raw?: string): Result<string> {
  const message = (raw ?? "").trim();
  if (!message) {
    return { ok: false, error: "Type a message first." };
  }
  if (message.length > MAX_MESSAGE_LENGTH) {
    return {
      ok: false,
      error: `Keep it under ${String(MAX_MESSAGE_LENGTH)} characters.`,
    };
  }
  return { ok: true, value: message };
}

/** First line of the opening message, shortened to fit the sidebar. */
export function conversationTitle(firstMessage: string): string {
  const line = firstMessage.trim().split("\n")[0].replaceAll(/\s+/g, " ");
  return line.length > 60
    ? `${line.slice(0, 57).trimEnd()}…`
    : line || "New chat";
}

const SECRET_PATTERNS: RegExp[] = [
  /AKIA[0-9A-Z]{16}/, // AWS access key id
  /\bsk-[\w-]{20,}/, // OpenAI-style secret key
  /\bgh[pousr]_[A-Za-z0-9]{30,}/, // GitHub token
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*\S{6,}/i,
];

/** Does the text look like it contains a credential? Developers paste code; we warn, not block. */
export function containsSecret(text: string): boolean {
  return SECRET_PATTERNS.some((re) => re.test(text));
}

const STOPWORDS = new Set([
  "the",
  "and",
  "for",
  "how",
  "can",
  "our",
  "you",
  "are",
  "not",
  "why",
  "does",
  "who",
  "all",
  "any",
  "about",
  "after",
  "also",
  "could",
  "from",
  "have",
  "should",
  "that",
  "their",
  "there",
  "they",
  "this",
  "what",
  "when",
  "where",
  "which",
  "while",
  "with",
  "would",
  "your",
  "into",
  "need",
  "want",
  "make",
  "using",
  "allowed",
  "company",
  "policy",
  "policies",
]);

function keywords(text: string): string[] {
  const words = text.toLowerCase().match(/[a-z0-9]+/g) ?? [];
  return [...new Set(words.filter((w) => w.length >= 3 && !STOPWORDS.has(w)))];
}

/** Policies that share keywords with the question, best match first. Title hits count double. */
export function relevantPolicies<T extends PolicySnippet>(
  question: string,
  policies: T[],
  limit = 3,
): T[] {
  const words = keywords(question);
  if (words.length === 0) {
    return [];
  }
  return policies
    .map((p) => {
      const title = `${p.title} ${p.category}`.toLowerCase();
      const rest = `${p.summary} ${p.body}`.toLowerCase();
      const score = words.reduce(
        (s, w) => s + (title.includes(w) ? 2 : 0) + (rest.includes(w) ? 1 : 0),
        0,
      );
      return { p, score };
    })
    .filter((x) => x.score > 0)
    .toSorted((a, b) => b.score - a.score)
    .slice(0, limit)
    .map((x) => x.p);
}

/** The system prompt a real LLM provider would receive. */
export function buildSystemPrompt(policies: PolicySnippet[]): string {
  const rules = policies
    .map((p) => `### ${p.title} (${p.category})\n${p.summary}\n${p.body}`)
    .join("\n\n");
  return [
    "You are the company's internal security assistant for software developers.",
    "Help with secure coding, threat modelling and code review. Be concise and concrete.",
    "When a question touches a company policy, cite the policy by title and follow it strictly.",
    "If the user pastes a secret, tell them to rotate it and never repeat it back.",
    "",
    "Active company policies:",
    rules || "(none published yet)",
  ].join("\n");
}

const GENERAL_TIPS = [
  "Validate all input on the server and use parameterised queries — never build SQL with string concatenation.",
  "Keep secrets in the environment or a secrets manager, never in the repo.",
  "Give every service and token the least privilege it needs.",
  "Pin and review dependencies; run a vulnerability scan in CI.",
];

/** Deterministic stand-in for an LLM so the feature demos without an API key. */
export function mockReply(
  history: ChatTurn[],
  policies: PolicySnippet[],
): string {
  const question = history.findLast((t) => t.role === "user")?.content ?? "";
  const parts: string[] = [];

  if (containsSecret(question)) {
    parts.push(
      "⚠️ Your message looks like it contains a credential. Treat it as compromised: rotate it now and remove it from wherever you copied it from.",
    );
  }

  const matches = relevantPolicies(question, policies);
  if (matches.length > 0) {
    parts.push("Here's what company policy says about this:");
    for (const p of matches) {
      parts.push(
        `• ${p.title} (${p.category}) — ${p.summary}\n  ${p.body.split("\n").slice(0, 3).join("\n  ")}`,
      );
    }
    parts.push(
      "Follow these when you implement it. If something here blocks you, ask the security team for an exception rather than working around it.",
    );
  } else {
    parts.push(
      "I couldn't find a company policy that covers this directly, so here is general secure-coding guidance:",
      GENERAL_TIPS.map((t) => `• ${t}`).join("\n"),
    );
    if (policies.length > 0) {
      parts.push(
        `Policies I can answer questions about: ${policies.map((p) => p.title).join(", ")}.`,
      );
    }
  }

  parts.push(
    "(Demo mode — replies come from a built-in mock, not a live model.)",
  );
  return parts.join("\n\n");
}

// async like a real, network-bound provider would be
export const mockProvider: AssistantProvider = async ({ history, policies }) =>
  await Promise.resolve(mockReply(history, policies));
