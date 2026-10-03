import Link from "next/link";
import { notFound } from "next/navigation";

import { ActionForm } from "@/components/action-form";
import { Card, Field, PageHeader, Select, inputClass } from "@/components/ui";
import type { ChatConversation, ChatMessage } from "@/lib/assistant";
import { requireAnyMember } from "@/lib/auth";
import { fmtDateTime, timeAgo } from "@/lib/format";
import { availableModels, defaultModel, modelLabel } from "@/lib/llm/models";

import { deleteConversation, sendChatMessage } from "./actions";

const SUGGESTIONS = [
  "What are the password requirements for a new service?",
  "How should I store confidential customer data?",
  "What do I do if I committed an API key?",
];

export default async function ChatPage({ searchParams }: PageProps<"/chat">) {
  const { supabase } = await requireAnyMember();
  const { c } = await searchParams;
  const activeId = typeof c === "string" ? c : null;

  const [{ data: convData }, { data: messageData }] = await Promise.all([
    supabase
      .from("chat_conversations")
      .select("*")
      .order("updated_at", { ascending: false })
      .limit(50),
    activeId === null
      ? Promise.resolve({ data: [] })
      : supabase
          .from("chat_messages")
          .select("*")
          .eq("conversation_id", activeId)
          .order("id"),
  ]);
  const conversations = (convData ?? []) as ChatConversation[];
  const messages = (messageData ?? []) as ChatMessage[];
  const active = conversations.find((x) => x.id === activeId) ?? null;
  const models = availableModels(process.env);
  const selected = defaultModel(active?.model ?? null, models);
  if (activeId !== null && active === null) {
    notFound();
  }

  return (
    <>
      <PageHeader
        title="Security assistant"
        subtitle="Ask about secure coding and company security policy. Your chats are private to you."
      />

      <div className="grid gap-6 lg:grid-cols-4">
        <Card
          title="Conversations"
          actions={
            <Link
              href="/chat"
              className="text-xs text-emerald-400 hover:underline"
            >
              New chat
            </Link>
          }
          className="h-fit"
        >
          <ul className="-mx-2 space-y-0.5">
            {conversations.map((conv) => (
              <li key={conv.id}>
                <Link
                  href={`/chat?c=${conv.id}`}
                  className={`block rounded-lg px-2 py-1.5 text-sm ${
                    conv.id === activeId
                      ? "bg-zinc-800 text-zinc-50"
                      : "text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-200"
                  }`}
                >
                  <span className="block truncate">{conv.title}</span>
                  <span className="text-xs text-zinc-500">
                    {timeAgo(conv.updated_at)}
                  </span>
                </Link>
              </li>
            ))}
            {conversations.length === 0 && (
              <li className="px-2 text-sm text-zinc-500">
                No conversations yet.
              </li>
            )}
          </ul>
        </Card>

        <Card
          title={active?.title ?? "New chat"}
          actions={
            active === null ? null : (
              <form action={deleteConversation.bind(null, active.id)}>
                <button className="text-xs text-red-400 hover:text-red-300">
                  Delete
                </button>
              </form>
            )
          }
          className="lg:col-span-3"
        >
          <div className="space-y-4">
            {messages.length === 0 && (
              <div className="rounded-lg border border-dashed border-zinc-800 p-5 text-sm text-zinc-400">
                <p>Try asking:</p>
                <ul className="mt-2 list-inside list-disc space-y-1 text-zinc-300">
                  {SUGGESTIONS.map((s) => (
                    <li key={s}>{s}</li>
                  ))}
                </ul>
              </div>
            )}
            {messages.map((m) => (
              <div
                key={m.id}
                className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}
              >
                <div
                  title={fmtDateTime(m.created_at)}
                  className={`max-w-[85%] rounded-xl px-4 py-2.5 text-sm leading-relaxed whitespace-pre-wrap ${
                    m.role === "user"
                      ? "bg-emerald-500/15 text-emerald-50 ring-1 ring-emerald-500/30"
                      : "bg-zinc-800/80 text-zinc-200"
                  }`}
                >
                  {m.content}
                  {m.model === null ? null : (
                    <p className="mt-2 text-xs text-zinc-500">
                      {modelLabel(m.model, models)}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>

          <ActionForm
            action={sendChatMessage.bind(null, active?.id ?? null)}
            submitLabel="Send"
            pendingLabel="Thinking…"
            className="mt-6 space-y-3 border-t border-zinc-800 pt-5"
          >
            <textarea
              name="message"
              rows={3}
              required
              className={inputClass}
              placeholder="Ask the security assistant… (never paste real secrets)"
            />
            <Field label="Model">
              <Select
                // remount when switching conversations so the default follows
                key={active?.id ?? "new"}
                name="model"
                defaultValue={selected.id}
                options={models.map((o) => ({ value: o.id, label: o.label }))}
              />
            </Field>
          </ActionForm>
        </Card>
      </div>
    </>
  );
}
