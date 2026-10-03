// Server-only: renders the filtered activity feed as a PDF (pdf-lib, built-in
// Helvetica, no font files). Rows come pre-filtered by the caller.
import { PDFDocument, StandardFonts, rgb } from "pdf-lib";
import type { PDFFont, PDFPage } from "pdf-lib";

import { pdfSafe, worstSeverity } from "./activity";
import type { ActivityFilters, ActivityRow } from "./activity";
import { SECURITY_STATUSES } from "./gateway";

// A4 landscape, in points
const PAGE: [number, number] = [842, 595];
const MARGIN = 36;
const ROW_HEIGHT = 14;
const FONT_SIZE = 8;

const COLUMNS = [
  { title: "Time (UTC)", width: 92 },
  { title: "Status", width: 56 },
  // the person the request is attributed to, not the agent it came through
  { title: "User email", width: 180 },
  { title: "Request", width: 200 },
  { title: "Channel / hook", width: 92 },
  { title: "Detections", width: 150 },
] as const;

const INK = rgb(0.1, 0.1, 0.12);
const MUTED = rgb(0.42, 0.42, 0.46);
const RULE = rgb(0.85, 0.85, 0.87);
const STATUS_INK: Record<string, ReturnType<typeof rgb>> = {
  secure: rgb(0.05, 0.5, 0.3),
  flagged: rgb(0.7, 0.45, 0),
  redacted: rgb(0.45, 0.25, 0.7),
  blocked: rgb(0.75, 0.1, 0.1),
};

/** Longest prefix of `text` that fits `width`, with "..." when cut. */
function fit(text: string, font: PDFFont, width: number): string {
  const safe = pdfSafe(text);
  if (font.widthOfTextAtSize(safe, FONT_SIZE) <= width) {
    return safe;
  }
  let end = safe.length;
  while (
    end > 0 &&
    font.widthOfTextAtSize(`${safe.slice(0, end)}...`, FONT_SIZE) > width
  ) {
    end -= 1;
  }
  return `${safe.slice(0, end)}...`;
}

function utc(iso: string): string {
  return new Date(iso).toISOString().slice(0, 19).replace("T", " ");
}

function cells(row: ActivityRow): string[] {
  const worst = worstSeverity(row.detections);
  return [
    utc(row.ts),
    row.status,
    row.end_user ?? "unknown",
    row.tool ?? row.model ?? "-",
    `${row.channel.toUpperCase()} / ${row.hook.replace("_", " ")}`,
    worst === null
      ? "-"
      : `${worst}: ${row.detections.map((d) => d.control_id).join(", ")}`,
  ];
}

function describeFilters(
  filters: ActivityFilters,
  principalName: string | null,
): string {
  const parts = [
    filters.user === "" ? null : `user ${filters.user}`,
    filters.principal === ""
      ? null
      : `principal ${principalName ?? filters.principal}`,
    filters.status === "" ? null : `status ${filters.status}`,
    filters.verdict === "" ? null : `verdict ${filters.verdict}`,
    filters.channel === "" ? null : `channel ${filters.channel.toUpperCase()}`,
  ].filter((p) => p !== null);
  return parts.length === 0 ? "none (all activity)" : parts.join(", ");
}

export async function activityPdf({
  rows,
  filters,
  principalName,
  truncated,
  generatedBy,
}: {
  rows: ActivityRow[];
  filters: ActivityFilters;
  principalName: string | null;
  /** true when more rows matched than were exported */
  truncated: boolean;
  generatedBy: string;
}): Promise<Uint8Array> {
  const document_ = await PDFDocument.create();
  document_.setTitle("Activity report");
  document_.setCreator("AI Control Layer SecOps console");
  const font = await document_.embedFont(StandardFonts.Helvetica);
  const bold = await document_.embedFont(StandardFonts.HelveticaBold);

  const pages: PDFPage[] = [];
  let page = document_.addPage(PAGE);
  pages.push(page);
  let y = PAGE[1] - MARGIN;

  const text = (
    value: string,
    x: number,
    options: {
      size?: number;
      f?: PDFFont;
      color?: ReturnType<typeof rgb>;
    } = {},
  ) => {
    page.drawText(pdfSafe(value), {
      x,
      y,
      size: options.size ?? FONT_SIZE,
      font: options.f ?? font,
      color: options.color ?? INK,
    });
  };

  // ---- summary
  text("AI Control Layer - Activity report", MARGIN, { size: 16, f: bold });
  y -= 20;
  text(
    `Generated ${utc(new Date().toISOString())} UTC by ${generatedBy}`,
    MARGIN,
    { size: 9, color: MUTED },
  );
  y -= 13;
  text(`Filters: ${describeFilters(filters, principalName)}`, MARGIN, {
    size: 9,
    color: MUTED,
  });
  y -= 13;
  const counts = SECURITY_STATUSES.map(
    (s) => `${s} ${String(rows.filter((r) => r.status === s).length)}`,
  ).join("   ");
  text(
    `${String(rows.length)} events${truncated ? " (newest only - narrow the filters for older ones)" : ""}   |   ${counts}`,
    MARGIN,
    { size: 9, color: MUTED },
  );
  y -= 22;

  const header = () => {
    let x = MARGIN;
    for (const column of COLUMNS) {
      text(column.title, x, { f: bold });
      x += column.width;
    }
    y -= 5;
    page.drawLine({
      start: { x: MARGIN, y },
      end: { x: PAGE[0] - MARGIN, y },
      thickness: 0.6,
      color: RULE,
    });
    y -= ROW_HEIGHT - 4;
  };
  header();

  if (rows.length === 0) {
    text("No gateway events match these filters.", MARGIN, { color: MUTED });
  }

  for (const row of rows) {
    if (y < MARGIN + ROW_HEIGHT) {
      page = document_.addPage(PAGE);
      pages.push(page);
      y = PAGE[1] - MARGIN;
      header();
    }
    let x = MARGIN;
    for (const [index, value] of cells(row).entries()) {
      const column = COLUMNS[index];
      text(fit(value, font, column.width - 6), x, {
        color: index === 1 ? (STATUS_INK[value] ?? INK) : INK,
      });
      x += column.width;
    }
    y -= ROW_HEIGHT;
  }

  // ---- footers
  for (const [index, p] of pages.entries()) {
    p.drawText(`Page ${String(index + 1)} of ${String(pages.length)}`, {
      x: PAGE[0] - MARGIN - 60,
      y: MARGIN / 2,
      size: 7,
      font,
      color: MUTED,
    });
  }

  return document_.save();
}
