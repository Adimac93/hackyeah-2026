// Light/dark theme: the choice lives in localStorage ("light" | "dark" |
// "system"); the effective theme is the `dark` class on <html>. Shared by the
// pre-paint script (app/layout.tsx) and the toggle (components/theme-toggle.tsx).

export const THEME_KEY = "cogut-theme";

export type ThemeChoice = "light" | "dark" | "system";

export const THEME_CHOICES: readonly ThemeChoice[] = [
  "light",
  "dark",
  "system",
];

/** The stored choice, or "system" when nothing (or nonsense) is stored. */
export function parseThemeChoice(
  value: string | null | undefined,
): ThemeChoice {
  return value === "light" || value === "dark" ? value : "system";
}

/** Whether a choice renders dark, given the OS preference. */
export function isDark(choice: ThemeChoice, systemDark: boolean): boolean {
  return choice === "dark" || (choice === "system" && systemDark);
}

/**
 * Runs in <head> before first paint so the page never flashes the wrong
 * theme. Kept tiny and dependency-free; storage can throw (private mode).
 */
export const THEME_SCRIPT = `(function(){try{var c=localStorage.getItem("${THEME_KEY}");var d=c==="dark"||(c!=="light"&&window.matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.classList.toggle("dark",d);}catch(e){}})();`;
