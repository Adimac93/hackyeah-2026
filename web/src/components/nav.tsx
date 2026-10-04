"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import {
  ActivityIcon,
  AlertIcon,
  ChatIcon,
  ChipIcon,
  FolderIcon,
  GaugeIcon,
  ServerIcon,
  SlidersIcon,
  ToolIcon,
  UsersIcon,
} from "./icons";

const LINKS = [
  { href: "/dashboard", label: "Overview", Icon: GaugeIcon },
  { href: "/activity", label: "Activity", Icon: ActivityIcon },
  { href: "/gateway", label: "Gateway", Icon: ServerIcon },
  { href: "/mcp", label: "MCP", Icon: ToolIcon },
  { href: "/controls", label: "Controls & policies", Icon: SlidersIcon },
  { href: "/risk", label: "User risk", Icon: AlertIcon },
  { href: "/team", label: "Team", Icon: UsersIcon },
  { href: "/models", label: "Models", Icon: ChipIcon },
  { href: "/resources", label: "Resources", Icon: FolderIcon },
  { href: "/chat", label: "Assistant", Icon: ChatIcon, open: true },
];

export function Nav({ consoleAccess }: { consoleAccess: boolean }) {
  const pathname = usePathname();
  const links = consoleAccess ? LINKS : LINKS.filter((l) => "open" in l);
  return (
    <nav className="-mx-1 flex gap-0.5 overflow-x-auto px-1 md:mx-0 md:flex-col md:overflow-visible md:px-0">
      {links.map(({ href, label, Icon }) => {
        const active = pathname === href || pathname.startsWith(`${href}/`);
        return (
          <Link
            key={href}
            href={href}
            aria-current={active ? "page" : undefined}
            className={`relative flex shrink-0 items-center gap-3 rounded-md px-3 py-2 text-[13px] font-medium whitespace-nowrap transition-colors ${
              active
                ? "before:bg-cogut bg-zinc-900 text-zinc-50 before:absolute before:inset-y-1.5 before:left-0 before:w-[3px] before:rounded-full"
                : "text-zinc-400 hover:bg-zinc-900/70 hover:text-zinc-100"
            }`}
          >
            <Icon
              className={`h-4 w-4 ${active ? "text-emerald-400" : "text-zinc-500"}`}
            />
            <span>{label}</span>
          </Link>
        );
      })}
    </nav>
  );
}
