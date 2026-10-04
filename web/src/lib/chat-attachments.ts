// Text files attached to a chat message. They aren't stored separately: their
// content is folded into the message in a marked block, so the model reads it
// (and the gateway polices it) like the rest of the prompt, and the UI can
// fold it back into a collapsible chip. Pure, so it's unit-testable.

export interface ChatAttachment {
  name: string;
  content: string;
}

export const MAX_ATTACHMENTS = 3;
/** Per file, in characters (after reading it as text). */
export const MAX_ATTACHMENT_CHARS = 16_000;
/** All files together; with the 4000-char message this stays under the 32000-char column. */
export const MAX_ATTACHMENTS_TOTAL_CHARS = 26_000;
/** Files bigger than this aren't even read. */
export const MAX_ATTACHMENT_BYTES = 256 * 1024;

const TEXT_EXTENSIONS = [
  "txt",
  "md",
  "csv",
  "log",
  "json",
  "yaml",
  "yml",
  "toml",
  "xml",
  "ini",
  "env.example",
  "sql",
  "sh",
  "py",
  "ts",
  "tsx",
  "js",
  "jsx",
  "rs",
  "go",
  "java",
  "rb",
  "php",
  "html",
  "css",
];

/** For the file input's `accept`. */
export const ATTACHMENT_ACCEPT = TEXT_EXTENSIONS.map((s) => `.${s}`).join(",");

/** Text when the message is only attachments. */
export const ATTACHMENT_ONLY_MESSAGE = "Please review the attached file.";

export function isTextAttachmentName(name: string): boolean {
  const lower = name.toLowerCase();
  return TEXT_EXTENSIONS.some((suffix) => lower.endsWith(`.${suffix}`));
}

/** File names go into a marker line: keep them to one short, quote-free line. */
function cleanName(name: string): string {
  const cleaned = name
    .replaceAll(/["\r\n<>]/g, "")
    .trim()
    .slice(0, 120);
  return cleaned === "" ? "file.txt" : cleaned;
}

/** Why a read file can't be attached, or null when it can. */
export function attachmentProblem(
  name: string,
  content: string,
): string | null {
  if (!isTextAttachmentName(name)) {
    return `${name}: only text files (txt, md, csv, json, logs, code…) can be attached.`;
  }
  if (content.includes("\u0000")) {
    return `${name}: doesn't look like a text file.`;
  }
  if (content.trim() === "") {
    return `${name}: the file is empty.`;
  }
  if (content.length > MAX_ATTACHMENT_CHARS) {
    return `${name}: longer than ${String(MAX_ATTACHMENT_CHARS)} characters.`;
  }
  return null;
}

/** Validate the attachments a client sent (JSON). Never trust the browser's checks. */
export function parseAttachments(
  raw: string,
): { ok: true; value: ChatAttachment[] } | { ok: false; error: string } {
  if (raw.trim() === "") {
    return { ok: true, value: [] };
  }
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return { ok: false, error: "The attachments couldn't be read." };
  }
  if (!Array.isArray(data)) {
    return { ok: false, error: "The attachments couldn't be read." };
  }
  if (data.length > MAX_ATTACHMENTS) {
    return {
      ok: false,
      error: `Attach at most ${String(MAX_ATTACHMENTS)} files.`,
    };
  }
  const value: ChatAttachment[] = [];
  let total = 0;
  for (const item of data as unknown[]) {
    const { name, content } = (item ?? {}) as Record<string, unknown>;
    if (typeof name !== "string" || typeof content !== "string") {
      return { ok: false, error: "The attachments couldn't be read." };
    }
    const problem = attachmentProblem(name, content);
    if (problem !== null) {
      return { ok: false, error: problem };
    }
    total += content.length;
    value.push({ name: cleanName(name), content });
  }
  if (total > MAX_ATTACHMENTS_TOTAL_CHARS) {
    return {
      ok: false,
      error: `Attached files are too long together (max ${String(MAX_ATTACHMENTS_TOTAL_CHARS)} characters).`,
    };
  }
  return { ok: true, value };
}

const OPEN = (name: string) => `<<<attached file "${name}">>>`;
const CLOSE = "<<<end of attached file>>>";
const BLOCK =
  /\n*<<<attached file "([^"\n]*)">>>\n([\s\S]*?)\n<<<end of attached file>>>/g;

/** The message as stored and sent to the model: text, then each file in a marked block. */
export function composeMessage(
  text: string,
  attachments: ChatAttachment[],
): string {
  return [
    text,
    ...attachments.map(
      (a) => `${OPEN(cleanName(a.name))}\n${a.content}\n${CLOSE}`,
    ),
  ].join("\n\n");
}

/** Split a stored message back into its text and attachments, for display. */
export function splitMessage(content: string): {
  text: string;
  attachments: ChatAttachment[];
} {
  const attachments: ChatAttachment[] = [];
  const text = content
    .replaceAll(BLOCK, (_match, name: string, body: string) => {
      attachments.push({ name, content: body });
      return "";
    })
    .trim();
  return { text, attachments };
}

// ---------------------------------------------------------------- images & PDFs
//
// Binary files go to the model as native content blocks for the turn they're
// sent in. They aren't stored: the saved message keeps a one-line marker with
// the file name, so the history shows what was attached.

export type FileKind = "image" | "pdf";

export interface ChatFile {
  name: string;
  mediaType: string;
  /** base64, no `data:` prefix */
  data: string;
}

/** What vision/document-capable models accept natively. */
export const FILE_TYPES: Record<string, { mediaType: string; kind: FileKind }> =
  {
    png: { mediaType: "image/png", kind: "image" },
    jpg: { mediaType: "image/jpeg", kind: "image" },
    jpeg: { mediaType: "image/jpeg", kind: "image" },
    gif: { mediaType: "image/gif", kind: "image" },
    webp: { mediaType: "image/webp", kind: "image" },
    pdf: { mediaType: "application/pdf", kind: "pdf" },
  };

export const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
export const MAX_PDF_BYTES = 7 * 1024 * 1024;
/**
 * All files in one message. Base64 adds a third, so this keeps the request
 * under the 10 MB body the proxy (src/proxy.ts) buffers — past that, Next
 * silently truncates the body (`proxyClientMaxBodySize`).
 */
export const MAX_FILES_TOTAL_BYTES = 7 * 1024 * 1024;

/** For the file input's `accept`: text files plus images and PDFs. */
export const CHAT_FILE_ACCEPT = [
  ATTACHMENT_ACCEPT,
  ...Object.keys(FILE_TYPES).map((s) => `.${s}`),
].join(",");

function suffixOf(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot === -1 ? "" : name.slice(dot + 1).toLowerCase();
}

/** The image/PDF type of a file name, or null when it isn't one. */
export function fileTypeOf(
  name: string,
): { mediaType: string; kind: FileKind } | null {
  return FILE_TYPES[suffixOf(name)] ?? null;
}

export function kindOfMediaType(mediaType: string): FileKind | null {
  for (const type of Object.values(FILE_TYPES)) {
    if (type.mediaType === mediaType) {
      return type.kind;
    }
  }
  return null;
}

/** Bytes a base64 string decodes to. */
export function base64Bytes(data: string): number {
  const padding = data.endsWith("==") ? 2 : data.endsWith("=") ? 1 : 0;
  return Math.floor((data.length * 3) / 4) - padding;
}

/** Why a file of this kind and size can't be attached, or null when it can. */
export function fileProblem(
  name: string,
  kind: FileKind,
  bytes: number,
): string | null {
  const limit = kind === "image" ? MAX_IMAGE_BYTES : MAX_PDF_BYTES;
  return bytes > limit
    ? `${name}: larger than ${String(limit / 1024 / 1024)} MB.`
    : null;
}

/** Validate the images/PDFs a client sent. Never trust the browser's checks. */
export function parseFiles(
  raw: unknown,
): { ok: true; value: ChatFile[] } | { ok: false; error: string } {
  if (raw === undefined || raw === null) {
    return { ok: true, value: [] };
  }
  if (!Array.isArray(raw) || raw.length > MAX_ATTACHMENTS) {
    return {
      ok: false,
      error: `Attach at most ${String(MAX_ATTACHMENTS)} files.`,
    };
  }
  const value: ChatFile[] = [];
  let total = 0;
  for (const item of raw as unknown[]) {
    const { name, mediaType, data } = (item ?? {}) as Record<string, unknown>;
    if (
      typeof name !== "string" ||
      typeof mediaType !== "string" ||
      typeof data !== "string" ||
      !/^[\d+/a-z]+={0,2}$/i.test(data)
    ) {
      return { ok: false, error: "The attached files couldn't be read." };
    }
    const kind = kindOfMediaType(mediaType);
    if (kind === null) {
      return {
        ok: false,
        error: `${name}: only PNG, JPG, GIF, WebP and PDF files can be attached.`,
      };
    }
    const bytes = base64Bytes(data);
    const problem = fileProblem(name, kind, bytes);
    if (problem !== null) {
      return { ok: false, error: problem };
    }
    total += bytes;
    value.push({ name: cleanName(name), mediaType, data });
  }
  if (total > MAX_FILES_TOTAL_BYTES) {
    return { ok: false, error: "The attached files are too large together." };
  }
  return { ok: true, value };
}

/** Which providers read which file kinds natively. */
const FILE_SUPPORT: Partial<Record<string, readonly FileKind[]>> = {
  anthropic: ["image", "pdf"],
  openai: ["image", "pdf"],
  compatible: ["image"],
};

/** Why `provider` can't take these files, or null when it can. */
export function unsupportedFiles(
  provider: string,
  label: string,
  files: ChatFile[],
): string | null {
  const supported = FILE_SUPPORT[provider] ?? [];
  const missing = new Set(
    files
      .map((f) => kindOfMediaType(f.mediaType))
      .filter((kind) => kind !== null && !supported.includes(kind)),
  );
  if (missing.size === 0) {
    return null;
  }
  const what = [...missing]
    .map((kind) => (kind === "image" ? "images" : "PDFs"))
    .join(" or ");
  return `${label} can't read ${what}. Pick a Claude or OpenAI model, or attach text instead.`;
}

const FILE_MARKER = /\n*<<<attached (image|pdf) "([^"\n]*)">>>/g;

/** One-line markers for files that went to the model but aren't stored. */
export function fileMarkers(files: ChatFile[]): string {
  return files
    .map(
      (f) =>
        `<<<attached ${kindOfMediaType(f.mediaType) ?? "image"} "${cleanName(f.name)}">>>`,
    )
    .join("\n");
}

/** Split a stored message's file markers out, for display. */
export function splitFileMarkers(content: string): {
  text: string;
  files: { name: string; kind: FileKind }[];
} {
  const files: { name: string; kind: FileKind }[] = [];
  const text = content
    .replaceAll(FILE_MARKER, (_match, kind: FileKind, name: string) => {
      files.push({ name, kind });
      return "";
    })
    .trim();
  return { text, files };
}
