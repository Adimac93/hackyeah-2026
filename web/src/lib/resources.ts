// Resources tab (Supabase Storage bucket `resources`): naming and preview rules.
// Pure, so it's unit-testable.

export const RESOURCES_BUCKET = "resources";
/** Matches the bucket's file_size_limit (supabase/migrations/…_resources_bucket.sql). */
export const MAX_RESOURCE_BYTES = 50 * 1024 * 1024;
/** Text previews read at most this much of a file. */
export const MAX_TEXT_PREVIEW_BYTES = 512 * 1024;

export type PreviewKind = "image" | "pdf" | "video" | "audio" | "text" | "none";

const TEXT_EXTENSIONS = new Set([
  "txt",
  "md",
  "csv",
  "log",
  "json",
  "toml",
  "yaml",
  "yml",
  "xml",
  "sql",
  "sh",
  "py",
  "ts",
  "js",
  "rs",
  "html",
  "css",
]);

function extension(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot === -1 ? "" : name.slice(dot + 1).toLowerCase();
}

/** How the console can show a file, from its MIME type (or extension as a fallback). */
export function previewKind(
  name: string,
  mimetype?: string | null,
): PreviewKind {
  const type = (mimetype ?? "").toLowerCase();
  // SVG can carry script; show it as text, never render it inline
  if (type === "image/svg+xml" || extension(name) === "svg") {
    return "text";
  }
  if (type.startsWith("image/")) {
    return "image";
  }
  if (type === "application/pdf") {
    return "pdf";
  }
  if (type.startsWith("video/")) {
    return "video";
  }
  if (type.startsWith("audio/")) {
    return "audio";
  }
  if (
    type.startsWith("text/") ||
    type === "application/json" ||
    type === "application/xml" ||
    TEXT_EXTENSIONS.has(extension(name))
  ) {
    return "text";
  }
  if (type === "" || type === "application/octet-stream") {
    const suffix = extension(name);
    if (["png", "jpg", "jpeg", "gif", "webp", "avif"].includes(suffix)) {
      return "image";
    }
    if (suffix === "pdf") {
      return "pdf";
    }
  }
  return "none";
}

/**
 * Storage key for an upload: a sortable timestamp prefix (uploads never
 * collide or overwrite) plus the file name reduced to safe characters.
 */
export function resourceObjectName(fileName: string, now: Date): string {
  const base = fileName
    .normalize("NFD")
    .replaceAll(/\p{M}/gu, "")
    .replaceAll(/[^\w.-]+/g, "-")
    .replaceAll(/-{2,}/g, "-")
    .replaceAll(/^[-.]+|-+$/g, "")
    .slice(-120);
  const stamp = now.toISOString().replaceAll(/[-:.TZ]/g, "");
  return `${stamp}-${base === "" ? "file" : base}`;
}

/** The name to show: the stored key without its timestamp prefix. */
export function resourceDisplayName(objectName: string): string {
  return objectName.replace(/^\d{17}-/, "");
}

/** 1536 → "1.5 KB". */
export function fmtBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) {
    return "—";
  }
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${unit === 0 ? String(value) : value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}
