import assert from "node:assert/strict";
import { test } from "node:test";

import {
  fmtBytes,
  previewKind,
  resourceDisplayName,
  resourceObjectName,
  uploadContentType,
} from "./resources.ts";

void test("previewKind picks a viewer from the MIME type, then the extension", () => {
  assert.equal(previewKind("a.png", "image/png"), "image");
  assert.equal(previewKind("a.pdf", "application/pdf"), "pdf");
  assert.equal(previewKind("a.mp4", "video/mp4"), "video");
  assert.equal(previewKind("notes.md", "application/octet-stream"), "text");
  assert.equal(previewKind("scan.pdf", ""), "pdf");
  assert.equal(previewKind("archive.zip", "application/zip"), "none");
  // never render SVG inline: it can carry script
  assert.equal(previewKind("logo.svg", "image/svg+xml"), "text");
});

void test("resourceObjectName is unique, sortable and safe", () => {
  const now = new Date("2026-10-04T08:30:15.123Z");
  assert.equal(
    resourceObjectName("Raport bezpieczeństwa (Q3).pdf", now),
    "20261004083015123-Raport-bezpieczenstwa-Q3-.pdf",
  );
  assert.equal(
    resourceObjectName("../../etc/passwd", now),
    "20261004083015123-etc-passwd",
  );
  assert.equal(resourceObjectName("日本", now), "20261004083015123-file");
});

void test("resourceDisplayName strips the timestamp prefix", () => {
  assert.equal(
    resourceDisplayName("20261004083015123-report.pdf"),
    "report.pdf",
  );
  assert.equal(resourceDisplayName("legacy.pdf"), "legacy.pdf");
});

void test("fmtBytes", () => {
  assert.equal(fmtBytes(512), "512 B");
  assert.equal(fmtBytes(1536), "1.5 KB");
  assert.equal(fmtBytes(52_428_800), "50 MB");
  assert.equal(fmtBytes(null), "—");
});

void test("uploadContentType allows only pptx, images and txt", () => {
  assert.equal(
    uploadContentType("Deck.PPTX"),
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  );
  assert.equal(uploadContentType("photo.jpg"), "image/jpeg");
  assert.equal(uploadContentType("notes.txt"), "text/plain");
  assert.equal(uploadContentType("logo.svg"), null);
  assert.equal(uploadContentType("report.pdf"), null);
  assert.equal(uploadContentType("noextension"), null);
});
