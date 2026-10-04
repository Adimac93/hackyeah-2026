"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, useTransition } from "react";
import type { KeyboardEvent, ReactNode, SubmitEvent } from "react";

import {
  ArrowUpIcon,
  DocumentIcon,
  ImageIcon,
  PaperclipIcon,
} from "@/components/icons";
import {
  CHAT_FILE_ACCEPT,
  MAX_ATTACHMENTS,
  MAX_ATTACHMENT_BYTES,
  MAX_FILES_TOTAL_BYTES,
  attachmentProblem,
  base64Bytes,
  fileProblem,
  fileTypeOf,
} from "@/lib/chat-attachments";
import type { ChatAttachment, ChatFile } from "@/lib/chat-attachments";
import { decodeChatEvents } from "@/lib/chat-stream";
import type { ChatStreamEvent } from "@/lib/chat-stream";
import type { ToolStep } from "@/lib/tool-steps";
import { cutAt, resumeAt, revealStep } from "@/lib/typewriter";

import { AttachmentChip, FileChip } from "./attachment-chip";
import { ToolSteps } from "./tool-steps";

/** Three bouncing dots in an assistant bubble while the reply is on its way. */
function TypingBubble({ status }: { status: string }) {
  return (
    <div
      className="flex justify-start"
      role="status"
      aria-label={status === "" ? "Assistant is typing" : status}
    >
      <div className="flex items-center gap-1 rounded-xl rounded-bl-sm border border-zinc-800 bg-zinc-950 px-4 py-3.5">
        {[0, 150, 300].map((delay) => (
          <span
            key={delay}
            className="h-2 w-2 animate-bounce rounded-full bg-zinc-400"
            style={{ animationDelay: `${String(delay)}ms` }}
          />
        ))}
        {status === "" ? null : (
          <span className="ml-2 text-xs text-zinc-400">{status}</span>
        )}
      </div>
    </div>
  );
}

/** A file's bytes as base64 (no `data:` prefix). */
async function readBase64(file: File): Promise<string> {
  const url = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => {
      resolve(typeof reader.result === "string" ? reader.result : "");
    });
    reader.addEventListener("error", () => {
      reject(new Error("read failed"));
    });
    reader.readAsDataURL(file);
  });
  return url.slice(url.indexOf(",") + 1);
}

/** `target`, revealed a few characters a frame, so text that arrives in bursts reads as typing. */
function useTypewriter(target: string): string {
  const [shown, setShown] = useState("");
  useEffect(() => {
    const at = resumeAt(shown, target);
    if (at >= target.length) {
      if (shown !== target) {
        setShown(target);
      }
      return;
    }
    const frame = requestAnimationFrame(() => {
      setShown(
        target.slice(0, cutAt(target, at + revealStep(target.length - at))),
      );
    });
    return () => {
      cancelAnimationFrame(frame);
    };
  }, [shown, target]);
  return shown;
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
 * The conversation and its input. Sends to `/api/chat` and streams the reply into
 * an assistant bubble at the end of the thread as the model writes it, then reloads
 * the page's messages. Enter (or ⌘/Ctrl+Enter) sends; Shift+Enter starts a new line.
 * Files can be attached (paperclip): text files are read here and folded into the
 * message; images and PDFs go to the model as base64 for this turn only.
 * With `fill`, the thread scrolls and the input stays pinned to the bottom.
 */
export function ChatComposer({
  conversationId,
  placeholder,
  thread,
  messageCount,
  fill = false,
  children,
}: {
  /** null starts a new conversation */
  conversationId: string | null;
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
  const router = useRouter();
  const [streaming, setStreaming] = useState(false);
  const [reloading, startReload] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState("");
  const [reply, setReply] = useState("");
  const [status, setStatus] = useState("");
  const [steps, setSteps] = useState<ToolStep[]>([]);
  const [hasText, setHasText] = useState(false);
  const [attachments, setAttachments] = useState<ChatAttachment[]>([]);
  const [sentAttachments, setSentAttachments] = useState<ChatAttachment[]>([]);
  const [files, setFiles] = useState<ChatFile[]>([]);
  const [sentFiles, setSentFiles] = useState<ChatFile[]>([]);
  const textarea = useRef<HTMLTextAreaElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const scroller = useRef<HTMLDivElement>(null);
  const typed = useTypewriter(reply);
  const pending = streaming || reloading;

  // open on the newest message, and follow the thread as it grows (a no-op
  // when the thread isn't its own scroll area)
  useEffect(() => {
    const element = scroller.current;
    if (element !== null) {
      element.scrollTop = element.scrollHeight;
    }
  }, [messageCount, pending, reply]);

  const attachedCount = attachments.length + files.length;
  const canSend = hasText || attachedCount > 0;

  async function attach(picked: File[]) {
    setError(null);
    const next = [...attachments];
    const nextFiles = [...files];
    for (const file of picked) {
      if (next.length + nextFiles.length >= MAX_ATTACHMENTS) {
        setError(`Attach at most ${String(MAX_ATTACHMENTS)} files.`);
        break;
      }
      const binary = fileTypeOf(file.name);
      if (binary !== null) {
        const used = nextFiles.reduce((sum, f) => sum + base64Bytes(f.data), 0);
        const problem =
          fileProblem(file.name, binary.kind, file.size) ??
          (used + file.size > MAX_FILES_TOTAL_BYTES
            ? `${file.name}: attached files would exceed ${String(MAX_FILES_TOTAL_BYTES / 1024 / 1024)} MB together.`
            : null);
        if (problem === null) {
          nextFiles.push({
            name: file.name,
            mediaType: binary.mediaType,
            data: await readBase64(file),
          });
        } else {
          setError(problem);
        }
        continue;
      }
      if (file.size > MAX_ATTACHMENT_BYTES) {
        setError(`${file.name}: the file is too large to attach.`);
        continue;
      }
      const content = await file.text();
      const problem = attachmentProblem(file.name, content);
      if (problem === null) {
        next.push({ name: file.name, content });
      } else {
        setError(problem);
      }
    }
    setAttachments(next);
    setFiles(nextFiles);
    if (fileInput.current !== null) {
      fileInput.current.value = "";
    }
  }

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
    if (pending || !canSend) {
      return;
    }
    event.currentTarget.form?.requestSubmit();
  }

  async function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending || !canSend) {
      return;
    }
    const form = new FormData(event.currentTarget);
    const texts = attachments;
    const binaries = files;
    const message = form.get("message");
    const model = form.get("model");
    setSent(typeof message === "string" ? message.trim() : "");
    setSentAttachments(texts);
    setAttachments([]);
    setSentFiles(binaries);
    setFiles([]);
    setReply("");
    setStatus("");
    setSteps([]);
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
        body: JSON.stringify({
          conversationId,
          message,
          model,
          attachments: texts,
          files: binaries,
        }),
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
            case "status": {
              setStatus(chatEvent.text);
              break;
            }
            case "tool_steps": {
              setSteps(chatEvent.steps);
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
            {sent === "" &&
            sentAttachments.length === 0 &&
            sentFiles.length === 0 ? null : (
              <div className="flex justify-end">
                <div className="max-w-[85%] rounded-xl rounded-br-sm bg-emerald-500 px-4 py-2.5 text-sm leading-relaxed whitespace-pre-wrap text-zinc-950">
                  {sent}
                  {sentAttachments.map((a) => (
                    <AttachmentChip key={a.name} attachment={a} />
                  ))}
                  {sentFiles.map((f) => (
                    <FileChip
                      key={f.name}
                      name={f.name}
                      kind={f.mediaType === "application/pdf" ? "pdf" : "image"}
                    />
                  ))}
                </div>
              </div>
            )}
            {reply === "" ? (
              error === null ? (
                <TypingBubble status={status} />
              ) : null
            ) : (
              <div
                className="flex flex-col items-start gap-2"
                aria-live="polite"
              >
                <div className="max-w-[85%] rounded-xl rounded-bl-sm border border-zinc-800 bg-zinc-950 px-4 py-2.5 text-sm leading-relaxed whitespace-pre-wrap text-zinc-200">
                  {typed}
                  {streaming || typed.length < reply.length ? (
                    <span className="ml-0.5 inline-block h-4 w-1.5 animate-pulse bg-zinc-400 align-text-bottom" />
                  ) : null}
                </div>
                <ToolSteps steps={steps} />
              </div>
            )}
          </div>
        ) : null}
      </div>

      <form
        onSubmit={(event) => {
          void onSubmit(event);
        }}
        className="mt-6 shrink-0 space-y-3 border-t border-zinc-800 pt-5"
      >
        {attachedCount === 0 ? null : (
          <ul className="flex flex-wrap gap-2">
            {files.map((f, index) => (
              <li
                key={`file-${f.name}-${String(index)}`}
                className="flex items-center gap-1.5 rounded-full border border-zinc-700 bg-zinc-900 py-1 pr-1.5 pl-3 text-xs text-zinc-200"
              >
                {f.mediaType === "application/pdf" ? (
                  <DocumentIcon className="h-3.5 w-3.5 shrink-0 text-zinc-500" />
                ) : (
                  <ImageIcon className="h-3.5 w-3.5 shrink-0 text-zinc-500" />
                )}
                <span className="max-w-48 truncate">{f.name}</span>
                <button
                  type="button"
                  aria-label={`Remove ${f.name}`}
                  onClick={() => {
                    setFiles((list) =>
                      list.filter((_, position) => position !== index),
                    );
                  }}
                  className="flex h-5 w-5 items-center justify-center rounded-full text-zinc-500 hover:bg-zinc-700 hover:text-zinc-100"
                >
                  ×
                </button>
              </li>
            ))}
            {attachments.map((a, index) => (
              <li
                key={`${a.name}-${String(index)}`}
                className="flex items-center gap-1.5 rounded-full border border-zinc-700 bg-zinc-900 py-1 pr-1.5 pl-3 text-xs text-zinc-200"
              >
                <PaperclipIcon className="h-3.5 w-3.5 shrink-0 text-zinc-500" />
                <span className="max-w-48 truncate">{a.name}</span>
                <button
                  type="button"
                  aria-label={`Remove ${a.name}`}
                  onClick={() => {
                    setAttachments((list) =>
                      list.filter((_, position) => position !== index),
                    );
                  }}
                  className="flex h-5 w-5 items-center justify-center rounded-full text-zinc-500 hover:bg-zinc-700 hover:text-zinc-100"
                >
                  ×
                </button>
              </li>
            ))}
          </ul>
        )}
        <div className="flex items-end gap-2 rounded-3xl border border-zinc-700 bg-zinc-950 p-1 shadow-[0_8px_24px_rgb(16_44_66/0.06)] transition-colors focus-within:border-emerald-500 focus-within:ring-2 focus-within:ring-emerald-500/15">
          <button
            type="button"
            title="Attach files (text, images, PDF)"
            aria-label="Attach files"
            disabled={pending || attachedCount >= MAX_ATTACHMENTS}
            onClick={() => {
              fileInput.current?.click();
            }}
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-zinc-400 transition-colors hover:bg-zinc-700/60 hover:text-zinc-100 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <PaperclipIcon className="h-4 w-4" />
          </button>
          <input
            ref={fileInput}
            type="file"
            multiple
            accept={CHAT_FILE_ACCEPT}
            className="hidden"
            onChange={(event) => {
              void attach([...(event.target.files ?? [])]);
            }}
          />
          <textarea
            ref={textarea}
            name="message"
            rows={1}
            required={attachedCount === 0}
            onKeyDown={onKeyDown}
            onChange={(event) => {
              setHasText(event.target.value.trim() !== "");
            }}
            aria-keyshortcuts="Enter Control+Enter Meta+Enter"
            className="field-sizing-content max-h-48 min-w-0 flex-1 resize-none bg-transparent py-1 text-[15px] leading-6 text-zinc-100 placeholder:text-zinc-500 focus:outline-none"
            placeholder={placeholder}
          />
          <button
            type="submit"
            disabled={pending || !canSend}
            title="Send (Enter)"
            aria-label={pending ? "Sending" : "Send"}
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-emerald-500 text-zinc-950 transition hover:-translate-y-px hover:bg-emerald-600 disabled:pointer-events-none disabled:bg-zinc-800 disabled:text-zinc-500"
          >
            <ArrowUpIcon className="h-3.5 w-3.5" />
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
    </div>
  );
}
