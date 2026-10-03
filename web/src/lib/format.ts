const dateFmt = new Intl.DateTimeFormat("en-GB", { dateStyle: "medium" });
const dateTimeFmt = new Intl.DateTimeFormat("en-GB", {
  dateStyle: "medium",
  timeStyle: "short",
});

export function fmtDate(iso: string | null): string {
  return iso === null ? "—" : dateFmt.format(new Date(iso));
}

export function fmtDateTime(iso: string | null): string {
  return iso === null ? "—" : dateTimeFmt.format(new Date(iso));
}

export function timeAgo(iso: string, now = Date.now()): string {
  const mins = Math.round((now - new Date(iso).getTime()) / 60_000);
  if (mins < 1) {
    return "just now";
  }
  if (mins < 60) {
    return `${String(mins)}m ago`;
  }
  const hours = Math.round(mins / 60);
  if (hours < 48) {
    return `${String(hours)}h ago`;
  }
  return `${String(Math.round(hours / 24))}d ago`;
}

/** value for <input type="datetime-local"> */
export function toLocalInput(iso: string): string {
  const d = new Date(iso);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60_000)
    .toISOString()
    .slice(0, 16);
}
