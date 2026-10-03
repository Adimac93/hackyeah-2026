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
