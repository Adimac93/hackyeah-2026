import assert from "node:assert/strict";
import { test } from "node:test";

import { cutAt, resumeAt, revealStep } from "./typewriter.ts";

void test("revealStep types steadily and catches up with a burst", () => {
  assert.equal(revealStep(0), 0);
  assert.equal(revealStep(1), 1);
  assert.equal(
    revealStep(20),
    1,
    "a short backlog is typed a character a frame",
  );
  assert.equal(
    revealStep(300),
    10,
    "a 300-character burst clears in ~30 frames",
  );
  assert.equal(revealStep(-5), 0);

  let shown = 0;
  let frames = 0;
  while (shown < 256) {
    shown += revealStep(256 - shown);
    frames += 1;
  }
  assert.equal(shown, 256, "never overshoots");
  assert.ok(
    frames > 20 && frames < 120,
    `held-back tail types out in ${String(frames)} frames`,
  );
});

void test("resumeAt carries on when the text grows, jumps when it was replaced", () => {
  assert.equal(resumeAt("Hello", "Hello world"), 5);
  assert.equal(resumeAt("", "anything"), 0);
  const refusal = "🛡 The AI Control Layer stopped this";
  assert.equal(resumeAt("Partial answ", refusal), refusal.length);
});

void test("cutAt never splits an emoji in half", () => {
  const text = "ok 🛡 done";
  // "🛡" is two UTF-16 units at 3 and 4: stopping between them shows both
  assert.equal(cutAt(text, 4), 5);
  assert.equal(cutAt(text, 3), 3);
  assert.equal(cutAt(text, 99), text.length);
});
