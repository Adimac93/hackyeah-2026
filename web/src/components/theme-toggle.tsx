"use client";

import { useEffect, useSyncExternalStore } from "react";

import {
  THEME_CHOICES,
  THEME_KEY,
  isDark,
  parseThemeChoice,
} from "@/lib/theme";
import type { ThemeChoice } from "@/lib/theme";

import { MonitorIcon, MoonIcon, SunIcon } from "./icons";

const ICONS = { light: SunIcon, dark: MoonIcon, system: MonitorIcon };
const LABELS = { light: "Light", dark: "Dark", system: "System" };

const CHANGE = "cogut-theme-change";

function readChoice(): ThemeChoice {
  try {
    return parseThemeChoice(localStorage.getItem(THEME_KEY));
  } catch {
    return "system";
  }
}

/** The stored choice as an external store: this tab's picks and other tabs' too. */
function subscribe(onChange: () => void) {
  window.addEventListener(CHANGE, onChange);
  window.addEventListener("storage", onChange);
  return () => {
    window.removeEventListener(CHANGE, onChange);
    window.removeEventListener("storage", onChange);
  };
}

function apply(choice: ThemeChoice) {
  const systemDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.classList.toggle("dark", isDark(choice, systemDark));
}

/**
 * Light / Dark / System. The pre-paint script already applied the stored
 * choice; this keeps it in sync, persists changes, and follows the OS while
 * on "system".
 */
export function ThemeToggle({ compact = false }: { compact?: boolean }) {
  // null on the server: it can't know the stored choice
  const choice = useSyncExternalStore<ThemeChoice | null>(
    subscribe,
    readChoice,
    () => null,
  );

  useEffect(() => {
    // another tab may have changed it
    if (choice !== null) {
      apply(choice);
    }
    if (choice !== "system") {
      return;
    }
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const follow = () => {
      apply("system");
    };
    media.addEventListener("change", follow);
    return () => {
      media.removeEventListener("change", follow);
    };
  }, [choice]);

  function pick(next: ThemeChoice) {
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      // private mode: the choice lasts for this page only
    }
    apply(next);
    window.dispatchEvent(new Event(CHANGE));
  }

  if (compact) {
    const current = choice ?? "system";
    const next =
      THEME_CHOICES[
        (THEME_CHOICES.indexOf(current) + 1) % THEME_CHOICES.length
      ];
    const Icon = ICONS[current];
    return (
      <button
        type="button"
        onClick={() => {
          pick(next);
        }}
        title={`Theme: ${LABELS[current]} (switch to ${LABELS[next]})`}
        aria-label={`Theme: ${LABELS[current]}. Switch to ${LABELS[next]}`}
        className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-zinc-800 text-zinc-400 transition-colors hover:border-zinc-700 hover:text-zinc-100"
      >
        <Icon className="h-4 w-4" />
      </button>
    );
  }

  return (
    <div
      role="radiogroup"
      aria-label="Theme"
      className="grid grid-cols-3 gap-0.5 rounded-md border border-zinc-800 p-0.5"
    >
      {THEME_CHOICES.map((option) => {
        const Icon = ICONS[option];
        const active = choice === option;
        return (
          <button
            key={option}
            type="button"
            role="radio"
            aria-checked={active}
            title={LABELS[option]}
            onClick={() => {
              pick(option);
            }}
            className={`flex items-center justify-center gap-1.5 rounded-sm px-2 py-1 text-[11px] font-medium transition-colors ${
              active
                ? "bg-zinc-900 text-zinc-50 shadow-sm"
                : "text-zinc-500 hover:text-zinc-200"
            }`}
          >
            <Icon className="h-3.5 w-3.5" />
            <span className="sr-only sm:not-sr-only">{LABELS[option]}</span>
          </button>
        );
      })}
    </div>
  );
}
