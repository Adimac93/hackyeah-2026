import Link from "next/link";
import type { ComponentProps, ReactNode } from "react";

import type {
  IncidentStatus,
  PolicyStatus,
  Severity,
  TeamRole,
} from "@/lib/domain";
import type {
  ControlAction,
  ControlSeverity,
  SecurityStatus,
} from "@/lib/gateway";

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-300 ring-red-500/40",
  high: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
  medium: "bg-yellow-500/15 text-yellow-200 ring-yellow-500/40",
  low: "bg-sky-500/15 text-sky-300 ring-sky-500/40",
};

const STATUS_STYLE: Record<IncidentStatus | PolicyStatus | TeamRole, string> = {
  open: "bg-red-500/10 text-red-300 ring-red-500/30",
  investigating: "bg-amber-500/10 text-amber-300 ring-amber-500/30",
  contained: "bg-violet-500/10 text-violet-300 ring-violet-500/30",
  resolved: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30",
  draft: "bg-zinc-500/10 text-zinc-300 ring-zinc-500/30",
  active: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30",
  archived: "bg-zinc-700/30 text-zinc-500 ring-zinc-600/30",
  admin: "bg-fuchsia-500/10 text-fuchsia-300 ring-fuchsia-500/30",
  analyst: "bg-sky-500/10 text-sky-300 ring-sky-500/30",
  viewer: "bg-zinc-500/10 text-zinc-300 ring-zinc-500/30",
  developer: "bg-indigo-500/10 text-indigo-300 ring-indigo-500/30",
};

function Pill({
  className,
  children,
}: {
  className: string;
  children: ReactNode;
}) {
  return (
    <span
      className={`inline-flex items-center rounded-sm px-1.5 py-0.5 text-[10px] leading-4 font-semibold tracking-[0.1em] whitespace-nowrap uppercase ring-1 ring-inset ${className}`}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Pill className={SEVERITY_STYLE[severity]}>{severity}</Pill>;
}

const CONTROL_SEVERITY_STYLE: Record<ControlSeverity, string> = {
  ...SEVERITY_STYLE,
  info: "bg-zinc-500/10 text-zinc-300 ring-zinc-500/30",
};

/** Gateway detection severity (adds `info` to the incident scale). */
export function ControlSeverityBadge({
  severity,
}: {
  severity: ControlSeverity;
}) {
  return <Pill className={CONTROL_SEVERITY_STYLE[severity]}>{severity}</Pill>;
}

const VERDICT_STYLE: Record<ControlAction, string> = {
  allow: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30",
  flag: "bg-amber-500/10 text-amber-300 ring-amber-500/30",
  redact: "bg-violet-500/10 text-violet-300 ring-violet-500/30",
  block: "bg-red-500/15 text-red-300 ring-red-500/40",
};

/** Gateway event verdict or a single control's action. */
export function VerdictBadge({ verdict }: { verdict: ControlAction }) {
  return <Pill className={VERDICT_STYLE[verdict]}>{verdict}</Pill>;
}

const STATUS_ACTION: Record<SecurityStatus, ControlAction> = {
  secure: "allow",
  flagged: "flag",
  redacted: "redact",
  blocked: "block",
};

/** An event's security status, in the palette of the action that produced it. */
export function SecurityStatusBadge({ status }: { status: SecurityStatus }) {
  return <Pill className={VERDICT_STYLE[STATUS_ACTION[status]]}>{status}</Pill>;
}

export function StatusBadge({
  status,
}: {
  status: IncidentStatus | PolicyStatus | TeamRole;
}) {
  return <Pill className={STATUS_STYLE[status]}>{status}</Pill>;
}

export function Card({
  title,
  actions,
  children,
  className = "",
  bodyClassName = "p-5",
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  /** classes for the content area under the header */
  bodyClassName?: string;
}) {
  return (
    <section
      className={`rounded-xl border border-zinc-800 bg-zinc-900/60 ${className}`}
    >
      {title !== undefined || actions !== undefined ? (
        <header className="flex min-h-12 flex-wrap items-center justify-between gap-x-4 gap-y-1 border-b border-zinc-800 px-5 py-3">
          <h2 className="eyebrow flex items-center gap-2 text-zinc-200">
            {title}
          </h2>
          {actions === undefined ? null : (
            <div className="flex shrink-0 items-center gap-3 text-xs whitespace-nowrap">
              {actions}
            </div>
          )}
        </header>
      ) : null}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

/** The landing's section head: small-caps eyebrow, serif title, muted lede, hairline rule. */
export function PageHeader({
  title,
  subtitle,
  actions,
  eyebrow = "Cogut console",
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  eyebrow?: string;
}) {
  return (
    <div className="animate-enter mb-8 flex flex-wrap items-end justify-between gap-x-10 gap-y-4 border-b border-zinc-800 pb-6">
      <div className="min-w-0">
        <p className="eyebrow flex items-center gap-2.5">
          <span className="bg-cogut h-1.5 w-1.5 rounded-full" aria-hidden />
          {eyebrow}
        </p>
        <h1 className="mt-3 text-4xl leading-[1.1] text-zinc-50 md:text-[2.75rem]">
          {title}
        </h1>
        {subtitle === undefined ? null : (
          <p className="mt-3 max-w-2xl text-[15px] leading-relaxed text-zinc-400">
            {subtitle}
          </p>
        )}
      </div>
      {actions === undefined ? null : (
        <div className="flex shrink-0 items-center gap-3">{actions}</div>
      )}
    </div>
  );
}

/** The landing's primary button: navy (blue in dark), lifts on hover. */
export const buttonClass =
  "inline-flex items-center justify-center gap-2 rounded-md bg-emerald-500 px-4 py-2.5 text-[13px] font-semibold tracking-[0.02em] text-zinc-950 transition hover:-translate-y-px hover:bg-emerald-600 disabled:pointer-events-none disabled:opacity-50";

/** The landing's secondary button: hairline outline, sand on hover. */
export const secondaryButtonClass =
  "inline-flex items-center justify-center gap-2 rounded-md border border-zinc-700 px-4 py-2.5 text-[13px] font-semibold tracking-[0.02em] text-zinc-200 transition hover:-translate-y-px hover:bg-zinc-900 disabled:pointer-events-none disabled:opacity-50";

export function ButtonLink({
  href,
  children,
}: {
  href: string;
  children: ReactNode;
}) {
  return (
    <Link href={href} className={buttonClass}>
      {children}
    </Link>
  );
}

export const inputClass =
  "w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 transition-colors focus:border-emerald-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/15 disabled:opacity-60";

export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <label className="block space-y-1.5">
      <span className="eyebrow text-zinc-400">{label}</span>
      {children}
      {hint === undefined ? null : (
        <span className="block text-xs text-zinc-500">{hint}</span>
      )}
    </label>
  );
}

export function Select({
  options,
  ...props
}: ComponentProps<"select"> & {
  options: readonly (string | { value: string; label: string })[];
}) {
  return (
    <select className={inputClass} {...props}>
      {options.map((o) => {
        const { value, label } =
          typeof o === "string" ? { value: o, label: o } : o;
        return (
          <option key={value} value={value}>
            {label}
          </option>
        );
      })}
    </select>
  );
}

export function EmptyRow({
  cols,
  children,
}: {
  cols: number;
  children: ReactNode;
}) {
  return (
    <tr>
      <td
        colSpan={cols}
        className="px-4 py-12 text-center font-serif text-[15px] text-zinc-500 italic"
      >
        {children}
      </td>
    </tr>
  );
}

export const tableClass = "w-full text-left text-sm";
export const thClass =
  "px-4 py-3 text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500";
export const tdClass = "px-4 py-3 align-middle";
