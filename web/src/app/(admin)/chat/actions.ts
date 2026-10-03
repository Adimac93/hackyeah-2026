"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { conversationTitle, parseChatMessage } from "@/lib/assistant";
import type { ChatTurn, PolicySnippet } from "@/lib/assistant";
import { requireChatUser } from "@/lib/auth";
import { formString } from "@/lib/domain";
import type { FormState } from "@/lib/domain";
import { loadModels } from "@/lib/llm/catalog";
import { findModel } from "@/lib/llm/models";
import { ProviderError, getAssistant } from "@/lib/llm/providers";

/** Longest stored message; matches the chat_messages check constraint. */
const MAX_STORED_LENGTH = 32_000;

/** Send a message (starting a new conversation when `conversationId` is null) and store the assistant's reply. */
export async function sendChatMessage(
  conversationId: string | null,
  _previous: FormState,
  formData: FormData,
): Promise<FormState> {
  const session = await requireChatUser();
  if (session.error) {
    return { error: session.error };
  }

  const parsed = parseChatMessage(formString(formData, "message"));
  if (!parsed.ok) {
    return { error: parsed.error };
  }

  const { supabase } = session;
  const model = findModel(
    formString(formData, "model"),
    await loadModels(supabase),
  );
  if (model === null) {
    return { error: "Pick one of the available models." };
  }

  let id = conversationId;
  if (id === null) {
    const { data, error } = await supabase
      .from("chat_conversations")
      .insert({ title: conversationTitle(parsed.value), model: model.id })
      .select("id")
      .single();
    if (error !== null) {
      return { error: error.message };
    }
    id = data.id as string;
  }

  // RLS rejects this if the conversation isn't ours
  const { error: insertError } = await supabase
    .from("chat_messages")
    .insert({ conversation_id: id, role: "user", content: parsed.value });
  if (insertError !== null) {
    return { error: insertError.message };
  }

  const [{ data: history }, { data: policies }] = await Promise.all([
    supabase
      .from("chat_messages")
      .select("role, content")
      .eq("conversation_id", id)
      .order("id"),
    supabase
      .rpc("assistant_policies")
      .overrideTypes<PolicySnippet[], { merge: false }>(),
  ]);

  let reply: string;
  try {
    reply = await getAssistant(model)({
      history: (history ?? []) as ChatTurn[],
      principal: session.user.email ?? session.user.id,
      policies: (policies ?? []) as PolicySnippet[],
    });
  } catch (error) {
    return {
      error:
        error instanceof ProviderError
          ? error.message
          : "The assistant is unavailable right now. Try again in a moment.",
    };
  }

  const { error: replyError } = await supabase.from("chat_messages").insert({
    conversation_id: id,
    role: "assistant",
    content: reply.slice(0, MAX_STORED_LENGTH),
    model: model.id,
  });
  if (replyError !== null) {
    return { error: replyError.message };
  }
  await supabase
    .from("chat_conversations")
    .update({ updated_at: new Date().toISOString(), model: model.id })
    .eq("id", id);

  revalidatePath("/chat");
  if (conversationId === null) {
    redirect(`/chat?c=${id}`);
  }
  return {};
}

/** Delete one conversation (messages cascade). Stays on `activeId` unless that's the one deleted. */
export async function deleteConversation(
  id: string,
  activeId: string | null = id,
): Promise<void> {
  const session = await requireChatUser();
  if (session.error) {
    return;
  }
  // RLS limits this to the caller's own conversations
  await session.supabase.from("chat_conversations").delete().eq("id", id);
  revalidatePath("/chat");
  redirect(
    activeId === null || activeId === id ? "/chat" : `/chat?c=${activeId}`,
  );
}

/** Delete every conversation the caller owns. */
export async function deleteAllConversations(): Promise<void> {
  const session = await requireChatUser();
  if (session.error) {
    return;
  }
  await session.supabase
    .from("chat_conversations")
    .delete()
    .eq("user_id", session.user.id);
  revalidatePath("/chat");
  redirect("/chat");
}
