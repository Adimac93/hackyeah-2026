import assert from "node:assert/strict";
import { test } from "node:test";

import {
  MAX_ATTACHMENT_CHARS,
  MAX_IMAGE_BYTES,
  attachmentProblem,
  base64Bytes,
  composeMessage,
  fileMarkers,
  parseAttachments,
  parseFiles,
  splitFileMarkers,
  splitMessage,
  unsupportedFiles,
} from "./chat-attachments.ts";

void test("composeMessage and splitMessage round-trip", () => {
  const attachments = [
    { name: "notes.md", content: "# Title\nline two" },
    { name: "app.log", content: "ERROR boom\n\nsecond paragraph" },
  ];
  const stored = composeMessage("What's wrong here?", attachments);
  assert.match(stored, /<<<attached file "notes\.md">>>/);
  assert.deepEqual(splitMessage(stored), {
    text: "What's wrong here?",
    attachments,
  });
  // plain messages are untouched
  assert.deepEqual(splitMessage("hello"), { text: "hello", attachments: [] });
});

void test("file names can't break the marker", () => {
  const stored = composeMessage("x", [
    { name: 'evil">>>\nname.txt', content: "c" },
  ]);
  assert.deepEqual(splitMessage(stored).attachments, [
    { name: "evil>>>name.txt".replaceAll(">", ""), content: "c" },
  ]);
});

void test("attachmentProblem rejects non-text, binary, empty and huge files", () => {
  assert.equal(attachmentProblem("a.txt", "fine"), null);
  assert.match(attachmentProblem("a.pdf", "x") ?? "", /only text files/);
  assert.match(attachmentProblem("a.txt", "a\u0000b") ?? "", /text file/);
  assert.match(attachmentProblem("a.txt", "   ") ?? "", /empty/);
  assert.match(
    attachmentProblem("a.txt", "x".repeat(MAX_ATTACHMENT_CHARS + 1)) ?? "",
    /longer than/,
  );
});

void test("parseAttachments validates what the client sent", () => {
  assert.deepEqual(parseAttachments(""), { ok: true, value: [] });
  assert.equal(parseAttachments("not json").ok, false);
  assert.equal(parseAttachments('{"name":"a.txt"}').ok, false);
  assert.equal(
    parseAttachments(JSON.stringify([{ name: "a.exe", content: "x" }])).ok,
    false,
  );
  const four = Array.from({ length: 4 }, (_, index) => ({
    name: `${String(index)}.txt`,
    content: "x",
  }));
  assert.equal(parseAttachments(JSON.stringify(four)).ok, false);
  const tooLong = Array.from({ length: 2 }, (_, index) => ({
    name: `${String(index)}.txt`,
    content: "x".repeat(15_000),
  }));
  assert.equal(parseAttachments(JSON.stringify(tooLong)).ok, false);
  assert.deepEqual(
    parseAttachments(JSON.stringify([{ name: "a.csv", content: "a,b" }])),
    { ok: true, value: [{ name: "a.csv", content: "a,b" }] },
  );
});

void test("parseFiles validates type, encoding and size", () => {
  const png = { name: "a.png", mediaType: "image/png", data: "iVBORw0KGgo=" };
  assert.deepEqual(parseFiles([png]), { ok: true, value: [png] });
  assert.deepEqual(parseFiles(null), { ok: true, value: [] });
  assert.equal(parseFiles([{ ...png, mediaType: "image/svg+xml" }]).ok, false);
  assert.equal(parseFiles([{ ...png, data: "not base64!" }]).ok, false);
  const big = "A".repeat(Math.ceil((MAX_IMAGE_BYTES * 4) / 3) + 8);
  assert.equal(parseFiles([{ ...png, data: big }]).ok, false);
});

void test("unsupportedFiles knows which providers read images and PDFs", () => {
  const image = { name: "a.png", mediaType: "image/png", data: "AA==" };
  const pdf = { name: "a.pdf", mediaType: "application/pdf", data: "AA==" };
  assert.equal(unsupportedFiles("anthropic", "Claude", [image, pdf]), null);
  assert.equal(unsupportedFiles("compatible", "Ollama", [image]), null);
  assert.match(unsupportedFiles("compatible", "Ollama", [pdf]) ?? "", /PDFs/);
  assert.match(
    unsupportedFiles("gateway", "Gateway", [image, pdf]) ?? "",
    /images or PDFs/,
  );
  assert.equal(unsupportedFiles("gateway", "Gateway", []), null);
});

void test("file markers round-trip", () => {
  const stored = `Look at this\n\n${fileMarkers([
    { name: "scan.pdf", mediaType: "application/pdf", data: "" },
    { name: "x.png", mediaType: "image/png", data: "" },
  ])}`;
  assert.deepEqual(splitFileMarkers(stored), {
    text: "Look at this",
    files: [
      { name: "scan.pdf", kind: "pdf" },
      { name: "x.png", kind: "image" },
    ],
  });
  assert.equal(base64Bytes("AAAA"), 3);
  assert.equal(base64Bytes("AA=="), 1);
});
