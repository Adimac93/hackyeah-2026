/** "COGUT" set like the landing's masthead wordmark. */
export function Wordmark({ className = "" }: { className?: string }) {
  return (
    <span
      className={`inline-flex items-center gap-2 text-[19px] leading-none font-semibold tracking-[0.075em] text-zinc-50 uppercase ${className}`}
    >
      <svg
        viewBox="0 0 24 28"
        aria-hidden
        className="h-[22px] w-[19px] shrink-0 text-emerald-500"
      >
        <path
          fill="currentColor"
          d="M12 0l11 4.3v9.6c0 2.6-.9 4.9-2.8 6.9L12 28l-8.2-7.2C1.9 18.8 1 16.5 1 13.9V4.3L12 0z"
        />
        <path
          d="M7.5 14.2l3.1 3.1 6-6.1"
          fill="none"
          stroke="var(--color-zinc-950)"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      Cogut
    </span>
  );
}
