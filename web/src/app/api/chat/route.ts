import { conversationTitle, parseChatMessage } from "@/lib/assistant";
import type { ChatTurn, PolicySnippet } from "@/lib/assistant";
import { requireChatUser } from "@/lib/auth";
import {
  ATTACHMENT_ONLY_MESSAGE,
  composeMessage,
  fileMarkers,
  parseAttachments,
  parseFiles,
  unsupportedFiles,
} from "@/lib/chat-attachments";
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
 * Body: `{ conversationId: string | null, message: string, model: string,
 * attachments?: { name, content }[] }`; a null id starts a new conversation. Text-file
 * attachments are folded into the stored message (`lib/chat-attachments.ts`). The reply is stored once complete, even if the browser has gone away.
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
    attachments?: unknown;
    files?: unknown;
  } | null;
  const attachments = parseAttachments(JSON.stringify(body?.attachments ?? []));
  if (!attachments.ok) {
    return refuse(attachments.error, 400);
  }
  const files = parseFiles(body?.files);
  if (!files.ok) {
    return refuse(files.error, 400);
  }
  const hasAttachments = attachments.value.length > 0 || files.value.length > 0;
  const typed = typeof body?.message === "string" ? body.message.trim() : "";
  const parsed = parseChatMessage(
    typed === "" && hasAttachments ? ATTACHMENT_ONLY_MESSAGE : typed,
  );
  if (!parsed.ok) {
    return refuse(parsed.error, 400);
  }
  // images/PDFs reach the model this turn only; the stored message names them
  const content = [
    composeMessage(parsed.value, attachments.value),
    fileMarkers(files.value),
  ]
    .filter((part) => part !== "")
    .join("\n\n");

  const { supabase } = session;
  const model = findModel(
    typeof body?.model === "string" ? body.model : "",
    await loadModels(supabase),
  );
  if (model === null) {
    return refuse("Pick one of the available models.", 400);
  }
  const cannotRead = unsupportedFiles(model.provider, model.label, files.value);
  if (cannotRead !== null) {
    return refuse(cannotRead, 400);
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
    content,
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

      let reply: string;
      try {
        reply = await getAssistant(model)({
          history: (history ?? []) as ChatTurn[],
          principal: session.user.email ?? session.user.id,
          policies: (policies ?? []) as PolicySnippet[],
          onDelta: (text) => {
            send({ type: "delta", text });
          },
          files: files.value,
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
