import assert from "node:assert/strict";
import { test } from "node:test";

import { isDark, parseThemeChoice } from "./theme.ts";

void test("parseThemeChoice falls back to system", () => {
  assert.equal(parseThemeChoice("dark"), "dark");
  assert.equal(parseThemeChoice("light"), "light");
  assert.equal(parseThemeChoice(null), "system");
  assert.equal(parseThemeChoice("purple"), "system");
});

void test("isDark follows the OS only for system", () => {
  assert.equal(isDark("dark", false), true);
  assert.equal(isDark("light", true), false);
  assert.equal(isDark("system", true), true);
  assert.equal(isDark("system", false), false);
});
