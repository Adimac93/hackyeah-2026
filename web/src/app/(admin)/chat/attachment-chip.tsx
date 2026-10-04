import { DocumentIcon, ImageIcon, PaperclipIcon } from "@/components/icons";
import type { ChatAttachment, FileKind } from "@/lib/chat-attachments";

/** An attached text file inside a message bubble: its name, expandable to its content. */
export function AttachmentChip({ attachment }: { attachment: ChatAttachment }) {
  return (
    <details className="group mt-2 rounded-md border border-current/25 bg-black/10 text-xs">
      <summary className="flex cursor-pointer list-none items-center gap-1.5 px-2.5 py-1.5 opacity-90 hover:opacity-100">
        <PaperclipIcon className="h-3.5 w-3.5 shrink-0" />
        <span className="truncate">{attachment.name}</span>
        <span className="ml-auto opacity-60 group-open:hidden">show</span>
        <span className="ml-auto hidden opacity-60 group-open:inline">
          hide
        </span>
      </summary>
      <pre className="scrollbar-subtle max-h-64 overflow-auto border-t border-current/25 px-2.5 py-2 whitespace-pre-wrap opacity-80">
        {attachment.content}
      </pre>
    </details>
  );
}

/** An image or PDF that went to the model with the message; it isn't kept, so only its name shows. */
export function FileChip({ name, kind }: { name: string; kind: FileKind }) {
  return (
    <span
      className="mt-2 flex items-center gap-1.5 rounded-md border border-current/25 bg-black/10 px-2.5 py-1.5 text-xs opacity-90"
      title="Sent to the model with this message; not kept in the history"
    >
      {kind === "pdf" ? (
        <DocumentIcon className="h-3.5 w-3.5 shrink-0" />
      ) : (
        <ImageIcon className="h-3.5 w-3.5 shrink-0" />
      )}
      <span className="truncate">{name}</span>
      <span className="ml-auto opacity-60">
        {kind === "pdf" ? "PDF" : "image"}
      </span>
    </span>
  );
}
