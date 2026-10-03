import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";

import { ConfirmButton } from "@/components/confirm-button";
import { ProviderIcon } from "@/components/provider-icon";
import { Card, Field, PageHeader } from "@/components/ui";
import type { ChatConversation, ChatMessage } from "@/lib/assistant";
import { requireAnyMember } from "@/lib/auth";
import { canAccessConsole } from "@/lib/domain";
import { fmtDateTime } from "@/lib/format";
import { loadDefaultModelId, loadModels } from "@/lib/llm/catalog";
import { defaultModel, modelLabel } from "@/lib/llm/models";

import {
  deleteAllConversations,
  deleteConversation,
  sendChatMessage,
} from "./actions";
import { ChatComposer } from "./chat-composer";
import { ChatHistory } from "./chat-history";
import { ModelSelect } from "./model-select";

const SUGGESTIONS = [
  "What are the password requirements for a new service?",
  "How should I store confidential customer data?",
  "What do I do if I committed an API key?",
];

export default async function ChatPage({ searchParams }: PageProps<"/chat">) {
  const { supabase, member } = await requireAnyMember();
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
  const [models, orgDefault] = await Promise.all([
    loadModels(supabase),
    loadDefaultModelId(supabase),
  ]);
  const selected = defaultModel(active?.model ?? null, models, orgDefault);
  if (activeId !== null && active === null) {
    notFound();
  }

  // developers get the history in the sidebar and only the chat here
  const consoleView = canAccessConsole(member.role);
  const chatCard = (
    <Card
      title={active?.title ?? "New chat"}
      actions={
        active === null ? null : (
          <form action={deleteConversation.bind(null, active.id, null)}>
            <ConfirmButton confirmLabel="Delete this chat?">
              Delete
            </ConfirmButton>
          </form>
        )
      }
      className={consoleView ? "lg:col-span-3" : ""}
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
                <p className="mt-2 flex items-center gap-1.5 text-xs text-zinc-500">
                  <ProviderIcon
                    icon={
                      models.find((o) => o.id === m.model)?.icon ?? "custom"
                    }
                    size="sm"
                  />
                  {modelLabel(m.model, models)}
                </p>
              )}
            </div>
          </div>
        ))}
      </div>

      <ChatComposer
        action={sendChatMessage.bind(null, active?.id ?? null)}
        placeholder="Ask anything… (never paste real secrets)"
      >
        <Field label="Model">
          <ModelSelect
            // remount when switching conversations so the default follows
            key={active?.id ?? "new"}
            name="model"
            defaultValue={selected.id}
            showDetails={member.role === "admin"}
            options={models.map((o) => ({
              value: o.id,
              label: o.label,
              icon: o.icon,
            }))}
          />
        </Field>
      </ChatComposer>
    </Card>
  );
  if (!consoleView) {
    return chatCard;
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
            <div className="flex items-center gap-3">
              {conversations.length > 0 && (
                <form action={deleteAllConversations}>
                  <ConfirmButton confirmLabel="Delete all?">
                    Delete all
                  </ConfirmButton>
                </form>
              )}
              <Link
                href="/chat"
                className="text-xs text-emerald-400 hover:underline"
              >
                New chat
              </Link>
            </div>
          }
          className="h-fit"
        >
          <div className="-mx-2">
            <Suspense>
              <ChatHistory conversations={conversations} />
            </Suspense>
          </div>
        </Card>

        {chatCard}
      </div>
    </>
  );
}
