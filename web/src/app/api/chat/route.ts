import { conversationTitle, parseChatMessage } from "@/lib/assistant";
import type { ChatTurn, PolicySnippet, ToolCallSummary } from "@/lib/assistant";
import { requireChatUser } from "@/lib/auth";
import { encodeChatEvent } from "@/lib/chat-stream";
import type { ChatStreamEvent } from "@/lib/chat-stream";
import { loadModels } from "@/lib/llm/catalog";
import { findModel } from "@/lib/llm/models";
import { ProviderError, getAssistant } from "@/lib/llm/providers";

/** Longest stored message; matches the chat_messages check constraint. */
const MAX_STORED_LENGTH = 32_000;

function refuse(error: string, status: number): Response {
  return Response.json({ error }, { status });
}

/**
 * Send a chat message and stream the assistant's reply back as NDJSON (`lib/chat-stream.ts`).
 * Body: `{ conversationId: string | null, message: string, model: string }`; a null id starts
 * a new conversation. The reply is stored once complete, even if the browser has gone away.
 */
export async function POST(request: Request) {
  const session = await requireChatUser();
  if (session.error) {
    return refuse(session.error, 401);
  }

  const body = (await request.json().catch(() => null)) as {
    conversationId?: unknown;
    message?: unknown;
    model?: unknown;
  } | null;
  const parsed = parseChatMessage(
    typeof body?.message === "string" ? body.message : "",
  );
  if (!parsed.ok) {
    return refuse(parsed.error, 400);
  }

  const { supabase } = session;
  const model = findModel(
    typeof body?.model === "string" ? body.model : "",
    await loadModels(supabase),
  );
  if (model === null) {
    return refuse("Pick one of the available models.", 400);
  }

  let id =
    typeof body?.conversationId === "string" ? body.conversationId : null;
  if (id === null) {
    const { data, error } = await supabase
      .from("chat_conversations")
      .insert({ title: conversationTitle(parsed.value), model: model.id })
      .select("id")
      .single();
    if (error !== null) {
      return refuse(error.message, 500);
    }
    id = data.id as string;
  }
  const conversationId = id;

  // RLS rejects this if the conversation isn't ours
  const { error: insertError } = await supabase.from("chat_messages").insert({
    conversation_id: conversationId,
    role: "user",
    content: parsed.value,
  });
  if (insertError !== null) {
    return refuse(insertError.message, 403);
  }

  const [{ data: history }, { data: policies }] = await Promise.all([
    supabase
      .from("chat_messages")
      .select("role, content")
      .eq("conversation_id", conversationId)
      .order("id"),
    supabase
      .rpc("assistant_policies")
      .overrideTypes<PolicySnippet[], { merge: false }>(),
  ]);

  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      let open = true;
      const send = (event: ChatStreamEvent) => {
        if (!open) {
          return;
        }
        try {
          controller.enqueue(encoder.encode(encodeChatEvent(event)));
        } catch {
          // the browser left; keep going so the reply still gets stored
          open = false;
        }
      };

      const finish = () => {
        try {
          controller.close();
        } catch {
          // already closed by the browser leaving
        }
      };

      send({ type: "conversation", id: conversationId });

      const toolCalls: ToolCallSummary[] = [];
      let reply: string;
      try {
        reply = await getAssistant(model)({
          history: (history ?? []) as ChatTurn[],
          principal: session.user.email ?? session.user.id,
          policies: (policies ?? []) as PolicySnippet[],
          onDelta: (text) => {
            send({ type: "delta", text });
          },
          onToolCall: (call) => {
            toolCalls.push(call);
            send({ type: "tool", call });
          },
        });
      } catch (error) {
        send({
          type: "error",
          error:
            error instanceof ProviderError
              ? error.message
              : "The assistant is unavailable right now. Try again in a moment.",
        });
        finish();
        return;
      }

      const { error: replyError } = await supabase
        .from("chat_messages")
        .insert({
          conversation_id: conversationId,
          role: "assistant",
          content: reply.slice(0, MAX_STORED_LENGTH),
          model: model.id,
          tool_calls: toolCalls,
        });
      if (replyError === null) {
        await supabase
          .from("chat_conversations")
          .update({ updated_at: new Date().toISOString(), model: model.id })
          .eq("id", conversationId);
        send({ type: "done", reply });
      } else {
        send({ type: "error", error: replyError.message });
      }
      finish();
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "application/x-ndjson; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      "x-accel-buffering": "no",
    },
  });
}
