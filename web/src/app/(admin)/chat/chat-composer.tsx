"use client";

import { useActionState, useEffect, useRef, useState } from "react";
import type { KeyboardEvent, ReactNode } from "react";

import { ArrowUpIcon } from "@/components/icons";
import type { FormState } from "@/lib/domain";

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

/**
 * The conversation and its input. While the server action runs, it shows the
 * sent message and a typing bubble at the end of the thread, so the wait isn't
 * a frozen screen. Enter (or ⌘/Ctrl+Enter) sends; Shift+Enter starts a new line.
 * With `fill`, the thread scrolls and the input stays pinned to the bottom.
 */
export function ChatComposer({
  action,
  placeholder,
  thread,
  messageCount,
  fill = false,
  children,
}: {
  action: (previous: FormState, formData: FormData) => Promise<FormState>;
  placeholder: string;
  /** the conversation's messages */
  thread: ReactNode;
  /** changes when a message is added, to keep the newest in view */
  messageCount: number;
  /** take the parent's full height: scrolling thread, input at the bottom */
  fill?: boolean;
  /** extra fields under the input, e.g. the model picker */
  children?: ReactNode;
}) {
  const [state, formAction, pending] = useActionState(action, {});
  const scroller = useRef<HTMLDivElement>(null);

  // open on the newest message, and follow the thread as it grows (a no-op
  // when the thread isn't its own scroll area)
  useEffect(() => {
    const element = scroller.current;
    if (element !== null) {
      element.scrollTop = element.scrollHeight;
    }
  }, [messageCount, pending]);
  const [sent, setSent] = useState("");
  const [hasText, setHasText] = useState(false);

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

  return (
    <div className={fill ? "flex min-h-0 flex-1 flex-col" : ""}>
      <div
        ref={scroller}
        className={
          fill
            ? "scrollbar-subtle -mr-3 min-h-0 flex-1 space-y-4 overflow-y-auto pr-3"
            : "space-y-4"
        }
      >
        {thread}
        {pending ? (
          <div className="space-y-4">
            {sent === "" ? null : (
              <div className="flex justify-end">
                <div className="max-w-[85%] rounded-xl bg-emerald-500/15 px-4 py-2.5 text-sm leading-relaxed whitespace-pre-wrap text-emerald-50 ring-1 ring-emerald-500/30">
                  {sent}
                </div>
              </div>
            )}
            <TypingBubble />
          </div>
        ) : null}
      </div>

      <form
        action={formAction}
        onSubmit={(event) => {
          const message = new FormData(event.currentTarget).get("message");
          setSent(typeof message === "string" ? message.trim() : "");
          // React resets the form after the action; keep the button in step
          setHasText(false);
        }}
        className="mt-6 shrink-0 space-y-3 border-t border-zinc-800 pt-5"
      >
        <div className="flex items-end gap-2 rounded-[28px] border border-zinc-800 bg-zinc-800/60 py-2 pr-2 pl-6 transition-colors focus-within:border-zinc-600">
          <textarea
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
        {state.error === undefined ? null : (
          <p
            role="alert"
            className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300"
          >
            {state.error}
          </p>
        )}
      </form>
    </div>
  );
}
