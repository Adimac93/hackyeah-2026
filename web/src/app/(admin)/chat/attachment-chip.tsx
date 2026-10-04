import type { ChatAttachment, FileKind } from "@/lib/chat-attachments";

/** An attached text file inside a message bubble: its name, expandable to its content. */
export function AttachmentChip({ attachment }: { attachment: ChatAttachment }) {
  return (
    <details className="group mt-2 rounded-lg border border-zinc-700/60 bg-zinc-950/40 text-xs">
      <summary className="flex cursor-pointer list-none items-center gap-1.5 px-2.5 py-1.5 text-zinc-300 hover:text-zinc-100">
        <span aria-hidden>📎</span>
        <span className="truncate">{attachment.name}</span>
        <span className="ml-auto text-zinc-500 group-open:hidden">show</span>
        <span className="ml-auto hidden text-zinc-500 group-open:inline">
          hide
        </span>
      </summary>
      <pre className="scrollbar-subtle max-h-64 overflow-auto border-t border-zinc-700/60 px-2.5 py-2 whitespace-pre-wrap text-zinc-400">
        {attachment.content}
      </pre>
    </details>
  );
}

/** An image or PDF that went to the model with the message; it isn't kept, so only its name shows. */
export function FileChip({ name, kind }: { name: string; kind: FileKind }) {
  return (
    <span
      className="mt-2 flex items-center gap-1.5 rounded-lg border border-zinc-700/60 bg-zinc-950/40 px-2.5 py-1.5 text-xs text-zinc-300"
      title="Sent to the model with this message; not kept in the history"
    >
      <span aria-hidden>{kind === "pdf" ? "📄" : "🖼️"}</span>
      <span className="truncate">{name}</span>
      <span className="ml-auto text-zinc-500">
        {kind === "pdf" ? "PDF" : "image"}
      </span>
    </span>
  );
}
