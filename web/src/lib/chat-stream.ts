// Wire format of `POST /api/chat`: one JSON event per line (NDJSON). Pure, so both ends and
// the tests share it. The route writes `conversation` first, then `delta`s as the model
// writes and a `tool` per MCP tool call it made, then exactly one `done` (the stored reply,
// which may differ from the deltas: gateway notes, refusals) or `error`.
import type { ToolCallSummary } from "@/lib/assistant";

export type ChatStreamEvent =
  | { type: "conversation"; id: string }
  | { type: "delta"; text: string }
  | { type: "tool"; call: ToolCallSummary }
  | { type: "done"; reply: string }
  | { type: "error"; error: string };

export function encodeChatEvent(event: ChatStreamEvent): string {
  return `${JSON.stringify(event)}\n`;
}

function isToolCall(value: unknown): value is ToolCallSummary {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const call = value as Record<string, unknown>;
  return (
    typeof call.tool === "string" &&
    (call.status === "ok" || call.status === "refused") &&
    (call.resultId === null || typeof call.resultId === "string") &&
    (call.rowCount === null || typeof call.rowCount === "number") &&
    (call.detail === null || typeof call.detail === "string")
  );
}

function isChatEvent(value: unknown): value is ChatStreamEvent {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const event = value as Record<string, unknown>;
  switch (event.type) {
    case "conversation": {
      return typeof event.id === "string";
    }
    case "delta": {
      return typeof event.text === "string";
    }
    case "tool": {
      return isToolCall(event.call);
    }
    case "done": {
      return typeof event.reply === "string";
    }
    case "error": {
      return typeof event.error === "string";
    }
    default: {
      return false;
    }
  }
}

/**
 * Split buffered stream text into complete events. `rest` is the unfinished last line;
 * prepend it to the next chunk. Malformed lines are skipped rather than killing the reply.
 */
export function decodeChatEvents(buffer: string): {
  events: ChatStreamEvent[];
  rest: string;
} {
  const lines = buffer.split("\n");
  const rest = lines.pop() ?? "";
  const events: ChatStreamEvent[] = [];
  for (const line of lines) {
    if (line.trim() === "") {
      continue;
    }
    try {
      const parsed: unknown = JSON.parse(line);
      if (isChatEvent(parsed)) {
        events.push(parsed);
      }
    } catch {
      // skip a garbled line
    }
  }
  return { events, rest };
}
