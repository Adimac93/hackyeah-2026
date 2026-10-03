"use client";

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { useFormStatus } from "react-dom";

/**
 * Submit button for destructive forms: the first click arms it, the second submits.
 * Avoids `window.confirm`, and disarms itself after a few seconds.
 */
export function ConfirmButton({
  children,
  confirmLabel = "Confirm?",
  className = "",
  title,
}: {
  children: ReactNode;
  confirmLabel?: ReactNode;
  className?: string;
  title?: string;
}) {
  const [armed, setArmed] = useState(false);
  const { pending } = useFormStatus();

  useEffect(() => {
    if (!armed) {
      return;
    }
    const timer = setTimeout(() => {
      setArmed(false);
    }, 3000);
    return () => {
      clearTimeout(timer);
    };
  }, [armed]);

  return armed ? (
    <button
      type="submit"
      disabled={pending}
      className={`text-xs font-medium text-red-300 hover:text-red-200 ${className}`}
    >
      {pending ? "Deleting…" : confirmLabel}
    </button>
  ) : (
    <button
      type="button"
      title={title}
      aria-label={title}
      onClick={() => {
        setArmed(true);
      }}
      className={`text-xs text-zinc-500 hover:text-red-400 ${className}`}
    >
      {children}
    </button>
  );
}
