"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { requireChatUser } from "@/lib/auth";
import { loadModels } from "@/lib/llm/catalog";
import { findModel } from "@/lib/llm/models";
import { checkModel } from "@/lib/llm/providers";
import type { ModelCheck } from "@/lib/llm/providers";

/** Pre-flight for the model picker: does the chosen model's configuration work? */
export async function checkChatModel(modelId: string): Promise<ModelCheck> {
  const session = await requireChatUser();
  if (session.error) {
    return { ok: false, reason: session.error };
  }
  const model = findModel(modelId, await loadModels(session.supabase));
  if (model === null) {
    return { ok: false, reason: "This model is no longer available." };
  }
  return checkModel(model);
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
