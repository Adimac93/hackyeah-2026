"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";

import { ConfirmButton } from "@/components/confirm-button";
import { TrashIcon } from "@/components/icons";
import type { ChatConversation } from "@/lib/assistant";
import { timeAgo } from "@/lib/format";

import { deleteConversation } from "./actions";

export type ConversationSummary = Pick<
  ChatConversation,
  "id" | "title" | "updated_at"
>;

/**
 * The caller's conversations, newest first. Used in the chat page's card and,
 * for developers, as the whole sidebar. The open one comes from `?c=`.
 */
export function ChatHistory({
  conversations,
}: {
  conversations: ConversationSummary[];
}) {
  const pathname = usePathname();
  const searchParameters = useSearchParams();
  const activeId = pathname === "/chat" ? searchParameters.get("c") : null;

  if (conversations.length === 0) {
    return <p className="px-2 text-sm text-zinc-500">No conversations yet.</p>;
  }
  return (
    <ul className="space-y-0.5">
      {conversations.map((conv) => (
        <li
          key={conv.id}
          className={`group flex items-center gap-1 rounded-lg pr-2 ${
            conv.id === activeId
              ? "bg-zinc-800 text-zinc-50"
              : "text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-200"
          }`}
        >
          <Link
            href={`/chat?c=${conv.id}`}
            className="min-w-0 flex-1 px-2 py-1.5 text-sm"
          >
            <span className="block truncate">{conv.title}</span>
            <span className="text-xs text-zinc-500" suppressHydrationWarning>
              {timeAgo(conv.updated_at)}
            </span>
          </Link>
          <form
            action={deleteConversation.bind(null, conv.id, activeId)}
            className="shrink-0"
          >
            <ConfirmButton
              title="Delete conversation"
              confirmLabel="Delete?"
              className="opacity-60 group-hover:opacity-100"
            >
              <TrashIcon className="h-3.5 w-3.5" />
            </ConfirmButton>
          </form>
        </li>
      ))}
    </ul>
  );
}
