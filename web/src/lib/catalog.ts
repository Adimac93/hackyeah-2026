// Lines the Controls page up with the catalog TOML: which controls the file
// declares (in its order, disabled ones included) versus what the gateway
// reports as enforced. Pure, so it's unit-testable. Not a TOML parser: it only
// reads the `[[controls.*]]` blocks' `id` and `enabled` keys, which the
// gateway's own schema keeps one per line.
import type { LiveControl } from "./gateway-live.ts";

export interface CatalogControl {
  id: string;
  kind: "deterministic" | "semantic";
  enabled: boolean;
}

const BLOCK = /^\[\[controls\.(deterministic|semantic)\]\]\s*(?:#.*)?$/;
const ID = /^id\s*=\s*"([^"]+)"/;
const DISABLED = /^enabled\s*=\s*false\b/;

/** Controls declared in a catalog, in file order. Commented-out blocks don't count. */
export function parseCatalogControls(toml: string): CatalogControl[] {
  const controls: CatalogControl[] = [];
  let current: CatalogControl | null = null;
  let kind: CatalogControl["kind"] | null = null;
  const flush = () => {
    if (current !== null) {
      controls.push(current);
    }
    current = null;
  };
  for (const raw of toml.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) {
      continue;
    }
    const block = BLOCK.exec(line);
    if (block !== null) {
      flush();
      kind = block[1] as CatalogControl["kind"];
      continue;
    }
    if (line.startsWith("[")) {
      // any other table ends the control block
      flush();
      kind = null;
      continue;
    }
    if (kind === null) {
      continue;
    }
    const id = ID.exec(line);
    if (id !== null) {
      current = { id: id[1], kind, enabled: true };
    } else if (DISABLED.test(line) && current !== null) {
      current.enabled = false;
    }
  }
  flush();
  return controls;
}

export type ControlRow =
  /** declared and enforced */
  | { id: string; status: "active"; control: LiveControl }
  /** declared with `enabled = false` */
  | { id: string; status: "disabled"; kind: CatalogControl["kind"] }
  /** declared, but the gateway doesn't enforce it (it runs another version) */
  | { id: string; status: "missing"; kind: CatalogControl["kind"] }
  /** enforced, but not declared in this catalog */
  | { id: string; status: "extra"; control: LiveControl };

/**
 * One row per catalog control, in catalog order, joined with what the gateway
 * enforces. Controls the gateway compiles from the signature feed
 * (`signatures.toml`, `feed` set) aren't in the catalog file; they come back
 * separately.
 */
export function reconcileControls(
  catalog: CatalogControl[],
  live: LiveControl[],
): { rows: ControlRow[]; feed: LiveControl[] } {
  const feed = live.filter((c) => typeof c.feed === "string");
  const enforced = new Map(
    live.filter((c) => typeof c.feed !== "string").map((c) => [c.id, c]),
  );
  const rows: ControlRow[] = catalog.map((c): ControlRow => {
    const control = enforced.get(c.id);
    enforced.delete(c.id);
    if (!c.enabled) {
      return { id: c.id, status: "disabled", kind: c.kind };
    }
    return control === undefined
      ? { id: c.id, status: "missing", kind: c.kind }
      : { id: c.id, status: "active", control };
  });
  for (const control of enforced.values()) {
    rows.push({ id: control.id, status: "extra", control });
  }
  return { rows, feed };
}
