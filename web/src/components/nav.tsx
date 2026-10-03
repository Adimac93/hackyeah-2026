"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import {
  AlertIcon,
  ChatIcon,
  DocumentIcon,
  GaugeIcon,
  UsersIcon,
} from "./icons";

const LINKS = [
  { href: "/dashboard", label: "Overview", Icon: GaugeIcon },
  { href: "/incidents", label: "Incidents", Icon: AlertIcon },
  { href: "/policies", label: "Policies", Icon: DocumentIcon },
  { href: "/team", label: "Team", Icon: UsersIcon },
  { href: "/chat", label: "Assistant", Icon: ChatIcon, open: true },
];

export function Nav({
  openIncidents,
  consoleAccess,
}: {
  openIncidents: number;
  consoleAccess: boolean;
}) {
  const pathname = usePathname();
  const links = consoleAccess ? LINKS : LINKS.filter((l) => "open" in l);
  return (
    <nav className="flex gap-1 md:flex-col">
      {links.map(({ href, label, Icon }) => {
        const active = pathname === href || pathname.startsWith(`${href}/`);
        return (
          <Link
            key={href}
            href={href}
            className={`flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm ${
              active
                ? "bg-zinc-800 text-zinc-50"
                : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200"
            }`}
          >
            <Icon />
            <span>{label}</span>
            {href === "/incidents" && openIncidents > 0 && (
              <span className="ml-auto rounded-full bg-red-500/20 px-1.5 text-xs font-medium text-red-300">
                {openIncidents}
              </span>
            )}
          </Link>
        );
      })}
    </nav>
  );
}
