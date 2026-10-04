import Link from "next/link";
import { Suspense } from "react";

import { ApprovalPopup } from "@/components/approval-popup";
import { ConfirmButton } from "@/components/confirm-button";
import { Nav } from "@/components/nav";
import { ThemeToggle } from "@/components/theme-toggle";
import { StatusBadge, buttonClass } from "@/components/ui";
import { Wordmark } from "@/components/wordmark";
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
      <aside className="flex shrink-0 flex-col gap-6 border-b border-zinc-800 bg-zinc-950 px-4 py-5 md:sticky md:top-0 md:h-screen md:w-64 md:border-r md:border-b-0 md:px-5 md:py-6">
        <div className="flex items-center justify-between gap-3 md:block">
          <Link href={hasConsole ? "/dashboard" : "/chat"} className="block">
            <Wordmark />
          </Link>
          <p className="hidden items-center gap-2 pt-2 text-[11px] tracking-[0.06em] text-zinc-500 md:flex">
            <span className="bg-cogut h-1.5 w-1.5 rounded-full" aria-hidden />
            {hasConsole ? "Security console" : "Security assistant"}
          </p>
        </div>
        {hasConsole ? (
          <div className="space-y-2">
            <p className="eyebrow hidden px-3 text-zinc-500 md:block">
              Console
            </p>
            <Nav consoleAccess />
          </div>
        ) : (
          <div className="flex min-h-0 flex-1 flex-col gap-4">
            <Link href="/chat" className={`${buttonClass} w-full`}>
              <span aria-hidden className="text-base leading-none">
                +
              </span>
              New chat
            </Link>
            <div className="flex min-h-0 flex-1 flex-col">
              <div className="mb-1 flex items-center justify-between px-2">
                <p className="eyebrow text-zinc-500">History</p>
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
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-zinc-800 pt-4 md:mt-auto md:block md:space-y-4">
          <div className="flex min-w-0 items-center gap-3">
            <span
              aria-hidden
              className="bg-sky-wash flex h-8 w-8 shrink-0 items-center justify-center rounded-full font-serif text-sm text-zinc-50"
            >
              {(member.full_name ?? member.email).charAt(0).toUpperCase()}
            </span>
            <div className="min-w-0">
              <p className="truncate text-[13px] font-medium text-zinc-100">
                {member.full_name ?? member.email}
              </p>
              <div className="mt-1">
                <StatusBadge status={member.role} />
              </div>
            </div>
          </div>
          <div className="md:block">
            <ThemeToggle />
          </div>
          <div className="flex items-center gap-4 text-[13px] md:justify-between">
            <Link
              href="/set-password"
              className="text-zinc-400 transition-colors hover:text-zinc-100"
            >
              Change password
            </Link>
            <form action={signOut}>
              <button className="text-zinc-400 transition-colors hover:text-zinc-100">
                Sign out
              </button>
            </form>
          </div>
          <p className="text-[11px] tracking-[0.06em] text-zinc-600">
            Cogut · v{packageJson.version}
          </p>
        </div>
      </aside>
      <main className="min-w-0 flex-1 px-4 py-8 md:px-10 md:py-10 xl:px-14">
        <div className="mx-auto w-full max-w-[1280px]">{children}</div>
      </main>
      {hasConsole ? <ApprovalPopup canDecide={canWrite(member.role)} /> : null}
    </div>
  );
}
