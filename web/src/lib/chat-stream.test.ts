import assert from "node:assert/strict";
import { test } from "node:test";

import { decodeChatEvents, encodeChatEvent } from "./chat-stream.ts";

void test("decodeChatEvents round-trips encoded events", () => {
  const wire =
    encodeChatEvent({ type: "conversation", id: "c1" }) +
    encodeChatEvent({ type: "delta", text: "line one\nline two" }) +
    encodeChatEvent({ type: "done", reply: "full" });
  assert.deepEqual(decodeChatEvents(wire), {
    events: [
      { type: "conversation", id: "c1" },
      { type: "delta", text: "line one\nline two" },
      { type: "done", reply: "full" },
    ],
    rest: "",
  });
});

void test("decodeChatEvents keeps a partial line for the next chunk", () => {
  const wire = encodeChatEvent({ type: "delta", text: "hello" });
  const first = decodeChatEvents(wire.slice(0, 10));
  assert.deepEqual(first.events, []);
  const second = decodeChatEvents(first.rest + wire.slice(10));
  assert.deepEqual(second.events, [{ type: "delta", text: "hello" }]);
  assert.equal(second.rest, "");
});

void test("decodeChatEvents skips garbled and unknown lines", () => {
  const wire = `not json\n{"type":"delta"}\n{"type":"nope"}\n\n${encodeChatEvent({ type: "error", error: "boom" })}`;
  assert.deepEqual(decodeChatEvents(wire).events, [
    { type: "error", error: "boom" },
  ]);
});
