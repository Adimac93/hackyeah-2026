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
      className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset ${className}`}
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
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-xl border border-zinc-800 bg-zinc-900/60 ${className}`}
    >
      {title !== undefined || actions !== undefined ? (
        <header className="flex items-center justify-between gap-4 border-b border-zinc-800 px-5 py-3">
          <h2 className="text-sm font-semibold text-zinc-200">{title}</h2>
          {actions}
        </header>
      ) : null}
      <div className="p-5">{children}</div>
    </section>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-50">
          {title}
        </h1>
        {subtitle === undefined ? null : (
          <p className="mt-1 text-sm text-zinc-400">{subtitle}</p>
        )}
      </div>
      {actions}
    </div>
  );
}

export function ButtonLink({
  href,
  children,
}: {
  href: string;
  children: ReactNode;
}) {
  return (
    <Link
      href={href}
      className="rounded-lg bg-emerald-500 px-3.5 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400"
    >
      {children}
    </Link>
  );
}

export const inputClass =
  "w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500 disabled:opacity-60";

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
      <span className="text-xs font-medium tracking-wide text-zinc-400 uppercase">
        {label}
      </span>
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
        className="px-4 py-10 text-center text-sm text-zinc-500"
      >
        {children}
      </td>
    </tr>
  );
}

export const tableClass = "w-full text-left text-sm";
export const thClass =
  "px-4 py-2.5 text-xs font-medium uppercase tracking-wide text-zinc-500";
export const tdClass = "px-4 py-3 align-middle";
