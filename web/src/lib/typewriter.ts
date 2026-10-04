// Pacing for the chat's typing effect. Text arrives in bursts (the gateway releases checked
// text in chunks and holds the last bit back until it has seen it), so the chat reveals it
// at a steady pace instead. Pure, so it's unit-testable.

/** At 60 frames a second: one character a frame (60/s) is the floor. */
const MIN_PER_FRAME = 1;
/** A backlog is worked off in about this many frames (~half a second), so it never lags far. */
const CATCH_UP_FRAMES = 30;

/** How many more characters to show this frame, given how many are waiting. */
export function revealStep(backlog: number): number {
  if (backlog <= 0) {
    return 0;
  }
  return Math.min(
    backlog,
    Math.max(MIN_PER_FRAME, Math.ceil(backlog / CATCH_UP_FRAMES)),
  );
}

/**
 * Where to resume typing when the text changes. If the new text extends what is shown,
 * carry on from there; if it replaced it (a refusal, a redaction note), show it whole.
 */
export function resumeAt(shown: string, next: string): number {
  return next.startsWith(shown) ? shown.length : next.length;
}

/** `end`, moved past the second half of an emoji (surrogate pair) it would split, capped at the text. */
export function cutAt(text: string, end: number): number {
  if (end >= text.length) {
    return text.length;
  }
  // a code point above 0xFFFF starting at end - 1 is a pair that `end` would cut in half
  return (text.codePointAt(end - 1) ?? 0) > 0xff_ff ? end + 1 : end;
}
