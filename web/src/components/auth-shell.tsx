import type { ReactNode } from "react";

import { ThemeToggle } from "./theme-toggle";
import { Wordmark } from "./wordmark";

const BOUNDARIES = ["Prompts", "Model responses", "Tool calls", "Tool results"];

/**
 * Sign-in and account pages, laid out like the landing's hero: masthead,
 * serif headline and the four control boundaries on the left, the form in a
 * sand panel with the blue rule on the right.
 */
export function AuthShell({
  panelTitle,
  children,
  aside,
}: {
  /** small-caps label over the form */
  panelTitle: string;
  children: ReactNode;
  /** note under the panel */
  aside?: ReactNode;
}) {
  return (
    // exactly the window's height on desktop: no page scroll; the form area
    // scrolls on its own only if a window is shorter than the form
    <div className="flex min-h-dvh flex-col bg-zinc-950 lg:h-dvh">
      <header className="mx-auto flex h-16 w-full max-w-[1280px] shrink-0 items-center justify-between gap-4 border-b border-zinc-800 px-5 md:px-10 [@media(min-height:860px)]:md:h-20">
        <Wordmark />
        <div className="flex items-center gap-5">
          <p className="hidden items-center gap-2.5 text-[13px] tracking-[0.06em] text-zinc-400 sm:flex">
            <span
              className="bg-cogut h-[7px] w-[7px] rounded-full"
              aria-hidden
            />
            The AI control layer
          </p>
          <ThemeToggle compact />
        </div>
      </header>

      <main className="mx-auto grid min-h-0 w-full max-w-[1280px] flex-1 items-center gap-12 overflow-y-auto px-5 py-8 md:px-10 lg:grid-cols-[1.1fr_1fr] lg:gap-16 lg:py-4">
        <section className="animate-enter hidden lg:block">
          <p className="eyebrow">More autonomy. Clear boundaries.</p>
          <h1 className="mt-5 text-[clamp(3rem,min(5.4vw,9vh),5rem)] leading-[1.06] text-zinc-50">
            Let AI move fast.
            <br />
            <em className="text-emerald-400 not-italic">Keep control.</em>
          </h1>
          <p className="mt-5 max-w-[440px] text-[17px] leading-[1.75] text-zinc-400">
            Cogut checks prompts, responses and tool calls against your
            policies. This console is where the security team sees every
            decision and sets the rules.
          </p>
          <ol className="mt-8 grid max-w-[520px] grid-cols-2 gap-x-8 gap-y-3 border-t border-zinc-800 pt-5">
            {BOUNDARIES.map((boundary, index) => (
              <li
                key={boundary}
                className="flex items-center gap-3 text-[15px] text-zinc-200"
              >
                <b className="text-[11px] font-semibold tracking-[0.1em] text-emerald-400 tabular-nums">
                  {String(index + 1).padStart(2, "0")}
                </b>
                {boundary}
              </li>
            ))}
          </ol>
        </section>

        <section
          className="animate-enter mx-auto w-full max-w-md lg:mx-0 lg:justify-self-end"
          style={{ animationDelay: "80ms" }}
        >
          <div className="accent-rule rounded-xl border border-zinc-800 bg-zinc-900 p-6 pl-8 shadow-[0_16px_45px_rgb(16_44_66/0.06)]">
            <div className="flex items-center justify-between gap-3">
              <p className="eyebrow">{panelTitle}</p>
              <p className="hidden items-center gap-2 text-[10px] font-semibold tracking-[0.14em] text-zinc-500 uppercase sm:flex">
                <span
                  className="bg-cogut h-[5px] w-[5px] rounded-full"
                  aria-hidden
                />
                Policy enforced
              </p>
            </div>
            <div className="mt-5">{children}</div>
          </div>
          {aside === undefined ? null : (
            <div className="mt-4 text-center text-xs leading-relaxed text-zinc-500">
              {aside}
            </div>
          )}
        </section>
      </main>

      <footer className="mx-auto flex w-full max-w-[1280px] shrink-0 flex-wrap items-center justify-between gap-4 border-t border-zinc-800 px-5 py-4 md:px-10">
        <Wordmark className="text-[15px]" />
        <p className="text-[11px] tracking-[0.02em] text-zinc-500">
          Built at HackYeah 2026. Ambitious agents. Intentional boundaries.
        </p>
      </footer>
    </div>
  );
}
