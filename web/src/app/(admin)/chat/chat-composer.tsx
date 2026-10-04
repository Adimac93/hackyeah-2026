"use client";

import { useRouter } from "next/navigation";
import { useRef, useState, useTransition } from "react";
import type { KeyboardEvent, ReactNode, SubmitEvent } from "react";

import { ArrowUpIcon } from "@/components/icons";
import { decodeChatEvents } from "@/lib/chat-stream";
import type { ChatStreamEvent } from "@/lib/chat-stream";

/** Three bouncing dots in an assistant bubble while the reply is on its way. */
function TypingBubble() {
  return (
    <div
      className="flex justify-start"
      role="status"
      aria-label="Assistant is typing"
    >
      <div className="flex items-center gap-1 rounded-xl bg-zinc-800/80 px-4 py-3.5">
        {[0, 150, 300].map((delay) => (
          <span
            key={delay}
            className="h-2 w-2 animate-bounce rounded-full bg-zinc-400"
            style={{ animationDelay: `${String(delay)}ms` }}
          />
        ))}
      </div>
    </div>
  );
}

/** Read `POST /api/chat`'s NDJSON reply, handing each event over as it arrives. */
async function readChatStream(
  response: Response,
  onEvent: (event: ChatStreamEvent) => void,
): Promise<void> {
  if (response.body === null) {
    return;
  }
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    const { events, rest } = decodeChatEvents(buffer + value);
    buffer = rest;
    for (const event of events) {
      onEvent(event);
    }
  }
  for (const event of decodeChatEvents(`${buffer}\n`).events) {
    onEvent(event);
  }
}

/**
 * The chat input. Sends to `/api/chat` and streams the reply into an assistant bubble
 * under the conversation as the model writes it, then reloads the page's messages.
 * Enter (or ⌘/Ctrl+Enter) sends; Shift+Enter starts a new line.
 */
export function ChatComposer({
  conversationId,
  placeholder,
  children,
}: {
  /** null starts a new conversation */
  conversationId: string | null;
  placeholder: string;
  /** extra fields under the input, e.g. the model picker */
  children?: ReactNode;
}) {
  const router = useRouter();
  const [streaming, setStreaming] = useState(false);
  const [reloading, startReload] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState("");
  const [reply, setReply] = useState("");
  const [hasText, setHasText] = useState(false);
  const textarea = useRef<HTMLTextAreaElement>(null);
  const pending = streaming || reloading;

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    // let an IME finish composing (Polish/CJK input) before Enter means "send"
    if (
      event.key !== "Enter" ||
      event.shiftKey ||
      event.nativeEvent.isComposing
    ) {
      return;
    }
    event.preventDefault();
    if (pending || event.currentTarget.value.trim() === "") {
      return;
    }
    event.currentTarget.form?.requestSubmit();
  }

  async function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) {
      return;
    }
    const form = new FormData(event.currentTarget);
    const message = form.get("message");
    const model = form.get("model");
    setSent(typeof message === "string" ? message.trim() : "");
    setReply("");
    setError(null);
    setStreaming(true);
    if (textarea.current !== null) {
      textarea.current.value = "";
    }
    setHasText(false);

    let id = conversationId;
    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ conversationId, message, model }),
      });
      if (response.ok) {
        await readChatStream(response, (chatEvent) => {
          switch (chatEvent.type) {
            case "conversation": {
              id = chatEvent.id;
              break;
            }
            case "delta": {
              setReply((text) => text + chatEvent.text);
              break;
            }
            case "done": {
              setReply(chatEvent.reply);
              break;
            }
            case "error": {
              setError(chatEvent.error);
              break;
            }
          }
        });
      } else {
        const body = (await response.json().catch(() => null)) as {
          error?: string;
        } | null;
        setError(
          body?.error ?? `The assistant answered ${String(response.status)}.`,
        );
      }
    } catch {
      setError("Lost the connection to the assistant. Try again in a moment.");
    } finally {
      setStreaming(false);
    }

    // show what was stored: the new conversation, or this one with the reply in it
    startReload(() => {
      if (id !== null && id !== conversationId) {
        router.push(`/chat?c=${id}`);
      } else {
        router.refresh();
      }
    });
  }

  return (
    <>
      {pending ? (
        <div className="mt-4 space-y-4">
          {sent === "" ? null : (
            <div className="flex justify-end">
              <div className="max-w-[85%] rounded-xl bg-emerald-500/15 px-4 py-2.5 text-sm leading-relaxed whitespace-pre-wrap text-emerald-50 ring-1 ring-emerald-500/30">
                {sent}
              </div>
            </div>
          )}
          {reply === "" ? (
            error === null ? (
              <TypingBubble />
            ) : null
          ) : (
            <div className="flex justify-start" aria-live="polite">
              <div className="max-w-[85%] rounded-xl bg-zinc-800/80 px-4 py-2.5 text-sm leading-relaxed whitespace-pre-wrap text-zinc-200">
                {reply}
                {streaming ? (
                  <span className="ml-0.5 inline-block h-4 w-1.5 animate-pulse bg-zinc-400 align-text-bottom" />
                ) : null}
              </div>
            </div>
          )}
        </div>
      ) : null}

      <form
        onSubmit={(event) => {
          void onSubmit(event);
        }}
        className="mt-6 space-y-3 border-t border-zinc-800 pt-5"
      >
        <div className="flex items-end gap-2 rounded-[28px] border border-zinc-800 bg-zinc-800/60 py-2 pr-2 pl-6 transition-colors focus-within:border-zinc-600">
          <textarea
            ref={textarea}
            name="message"
            rows={1}
            required
            onKeyDown={onKeyDown}
            onChange={(event) => {
              setHasText(event.target.value.trim() !== "");
            }}
            aria-keyshortcuts="Enter Control+Enter Meta+Enter"
            className="field-sizing-content max-h-48 min-w-0 flex-1 resize-none bg-transparent py-2.5 text-base text-zinc-100 placeholder:text-zinc-500 focus:outline-none"
            placeholder={placeholder}
          />
          <button
            type="submit"
            disabled={pending || !hasText}
            title="Send (Enter)"
            aria-label={pending ? "Sending" : "Send"}
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-emerald-500 text-zinc-950 transition-colors hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-zinc-700 disabled:text-zinc-400"
          >
            <ArrowUpIcon className="h-5 w-5" />
          </button>
        </div>
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div className="min-w-0 flex-1">{children}</div>
        </div>
        {error === null ? null : (
          <p
            role="alert"
            className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300"
          >
            {error}
          </p>
        )}
      </form>
    </>
  );
}
