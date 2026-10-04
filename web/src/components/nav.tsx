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
          </Link>
        );
      })}
    </nav>
  );
}
