interface IconProps {
  className?: string;
}

function Icon({ className = "h-4 w-4", d }: IconProps & { d: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden
    >
      <path d={d} />
    </svg>
  );
}

export function ShieldIcon(p: IconProps) {
  return (
    <Icon {...p} d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z" />
  );
}
export function GaugeIcon(p: IconProps) {
  return <Icon {...p} d="M3 13a9 9 0 1118 0M12 13l4-4M7 17h10" />;
}
export function AlertIcon(p: IconProps) {
  return (
    <Icon
      {...p}
      d="M12 9v4m0 4h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"
    />
  );
}
export function DocumentIcon(p: IconProps) {
  return (
    <Icon
      {...p}
      d="M14 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V9l-6-6zM14 3v6h6M8 13h8M8 17h5"
    />
  );
}
export function UsersIcon(p: IconProps) {
  return (
    <Icon
      {...p}
      d="M16 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2M9 11a4 4 0 100-8 4 4 0 000 8zM22 21v-2a4 4 0 00-3-3.9M16 3.1a4 4 0 010 7.8"
    />
  );
}
export function ChatIcon(p: IconProps) {
  return (
    <Icon
      {...p}
      d="M21 12a8 8 0 01-11.6 7.1L4 20l1-4.6A8 8 0 1121 12zM8 10h8M8 14h5"
    />
  );
}

export function TrashIcon(p: IconProps) {
  return (
    <Icon
      {...p}
      d="M4 7h16M10 11v6M14 11v6M5 7l1 12a2 2 0 002 2h8a2 2 0 002-2l1-12M9 7V4h6v3"
    />
  );
}

export function ActivityIcon(p: IconProps) {
  return <Icon {...p} d="M3 12h4l3-8 4 16 3-8h4" />;
}

export function SlidersIcon(p: IconProps) {
  return (
    <Icon
      {...p}
      d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0M14 4v4M8 10v4M16 16v4"
    />
  );
}

export function ChipIcon(p: IconProps) {
  return (
    <Icon
      {...p}
      d="M8 8h8v8H8zM9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3M6 6h12v12H6z"
    />
  );
}

export function ServerIcon(p: IconProps) {
  return <Icon {...p} d="M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01M12 10v4" />;
}

export function ToolIcon(p: IconProps) {
  return (
    <Icon
      {...p}
      d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"
    />
  );
}
export function ArrowUpIcon(p: IconProps) {
  return <Icon {...p} d="M12 19V5M5 12l7-7 7 7" />;
}

export function FolderIcon(p: IconProps) {
  return (
    <Icon
      {...p}
      d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"
    />
  );
}

export function PaperclipIcon(p: IconProps) {
  return (
    <Icon
      {...p}
      d="M21 12.5l-8.5 8.5a6 6 0 01-8.5-8.5l9-9a4 4 0 015.7 5.7l-9 9a2 2 0 01-2.8-2.8l8.3-8.3"
    />
  );
}

export function PencilIcon(p: IconProps) {
  return (
    <Icon
      {...p}
      d="M16.9 3.6a2 2 0 012.8 2.8L8 18l-4 1 1-4L16.9 3.6zM14 6.5l3.5 3.5"
    />
  );
}

export function SunIcon(p: IconProps) {
  return (
    <Icon
      {...p}
      d="M12 3v2M12 19v2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M3 12h2M19 12h2M5.6 18.4L7 17M17 7l1.4-1.4M12 8a4 4 0 100 8 4 4 0 000-8z"
    />
  );
}

export function MoonIcon(p: IconProps) {
  return <Icon {...p} d="M20 14.5A8 8 0 019.5 4a8 8 0 1010.5 10.5z" />;
}

export function MonitorIcon(p: IconProps) {
  return <Icon {...p} d="M3 5h18v11H3zM8 20h8M12 16v4" />;
}

/** Cogut's mark: the landing's shield, drawn as an outline. */
export function CogutMark(p: IconProps) {
  return (
    <Icon
      {...p}
      d="M12 2.5l8 3.2v5.6c0 2.4-.9 4.4-2.5 6.1L12 21.5l-5.5-4.1C4.9 15.7 4 13.7 4 11.3V5.7l8-3.2zM8.5 12l2.3 2.3 4.7-4.8"
    />
  );
}

export function ImageIcon(p: IconProps) {
  return <Icon {...p} d="M4 5h16v14H4zM4 16l5-5 4 4 3-3 4 4M15 9.5h.01" />;
}
