import Link from "next/link";
import { Suspense } from "react";

import { ApprovalPopup } from "@/components/approval-popup";
import { ConfirmButton } from "@/components/confirm-button";
import { ShieldIcon } from "@/components/icons";
import { Nav } from "@/components/nav";
import { StatusBadge } from "@/components/ui";
import { requireAnyMember } from "@/lib/auth";
import { canAccessConsole, canWrite } from "@/lib/domain";

import packageJson from "../../../package.json";
import { signOut } from "../login/actions";
import { deleteAllConversations } from "./chat/actions";
import { ChatHistory } from "./chat/chat-history";
import type { ConversationSummary } from "./chat/chat-history";

export default async function AdminLayout({ children }: LayoutProps<"/">) {
  const { supabase, member } = await requireAnyMember();
  const hasConsole = canAccessConsole(member.role);
  // developers only use the assistant: their sidebar is the chat history
  const { data: conversationRows } = hasConsole
    ? { data: null }
    : await supabase
        .from("chat_conversations")
        .select("id, title, updated_at")
        .order("updated_at", { ascending: false })
        .limit(50);
  const conversations = (conversationRows ?? []) as ConversationSummary[];

  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <aside className="flex shrink-0 flex-col gap-6 border-b border-zinc-800 bg-zinc-950 p-4 md:sticky md:top-0 md:h-screen md:w-60 md:border-r md:border-b-0">
        <div className="flex items-center gap-2.5 px-2">
          <div className="rounded-lg bg-emerald-500/10 p-1.5 text-emerald-400 ring-1 ring-emerald-500/30">
            <ShieldIcon className="h-5 w-5" />
          </div>
          <span className="font-semibold text-zinc-50">SecOps Console</span>
        </div>
        {hasConsole ? (
          <Nav consoleAccess />
        ) : (
          <div className="flex min-h-0 flex-1 flex-col gap-4">
            <Link
              href="/chat"
              className="flex items-center justify-center gap-2 rounded-lg bg-emerald-500 px-3 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400"
            >
              <span aria-hidden className="text-base leading-none">
                +
              </span>
              New chat
            </Link>
            <div className="flex min-h-0 flex-1 flex-col">
              <div className="mb-1 flex items-center justify-between px-2">
                <p className="text-xs font-medium tracking-wide text-zinc-500 uppercase">
                  History
                </p>
                {conversations.length > 0 && (
                  <form action={deleteAllConversations}>
                    <ConfirmButton confirmLabel="Delete all?">
                      Clear
                    </ConfirmButton>
                  </form>
                )}
              </div>
              <div className="scrollbar-subtle -mx-1 max-h-64 overflow-y-auto px-1 md:max-h-none md:flex-1">
                <Suspense>
                  <ChatHistory conversations={conversations} />
                </Suspense>
              </div>
            </div>
          </div>
        )}
        <div className="flex items-center justify-between gap-3 border-t border-zinc-800 px-2 pt-3 md:mt-auto md:block md:space-y-3 md:pt-4">
          <div className="min-w-0">
            <p className="truncate text-sm text-zinc-200">
              {member.full_name ?? member.email}
            </p>
            <div className="mt-1">
              <StatusBadge status={member.role} />
            </div>
          </div>
          <div className="flex items-center gap-3 md:justify-between">
            <Link
              href="/set-password"
              className="text-sm text-zinc-400 hover:text-zinc-100"
            >
              Change password
            </Link>
            <form action={signOut}>
              <button className="text-sm text-zinc-400 hover:text-zinc-100">
                Sign out
              </button>
            </form>
          </div>
        </div>
        <p className="px-2 text-xs text-zinc-600">v{packageJson.version}</p>
      </aside>
      <main className="min-w-0 flex-1 px-4 py-8 md:px-10">{children}</main>
      {hasConsole ? <ApprovalPopup canDecide={canWrite(member.role)} /> : null}
    </div>
  );
}
