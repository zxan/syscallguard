// banner.ts: banner state and event text. Pure functions, no DOM, so they test under plain node.
// Contracts: ARCHITECTURE.md Contract 3 (event fields), Contract 4 (SNAPSHOT, GUARD_STATE).

export type Level = "green" | "amber" | "red";

export interface SgEvent {
  type: string;
  ts?: number | null;
  [field: string]: unknown;
}

export interface Banner {
  level: Level;
  title: string;
  detail: string;
  until: number | null; // ms timestamp when a BLOCK/WOULD_BLOCK hold ends
  sticky: boolean; // ERROR: held until the next event arrives
}

export const HOLD_MS = 5000;
export const GREEN: Banner = { level: "green", title: "NO BLOCKS", detail: "", until: null, sticky: false };

/** Banner after `ev` arrives at time `now` (ms). Only BLOCK, WOULD_BLOCK and ERROR change it. */
export function applyEvent(prev: Banner, ev: SgEvent, now: number): Banner {
  const b = prev.sticky ? GREEN : expire(prev, now); // any event clears a sticky ERROR
  switch (ev.type) {
    case "BLOCK":
      return { level: "red", title: "BLOCKED", detail: summarize(ev), until: now + HOLD_MS, sticky: false };
    case "WOULD_BLOCK":
      if (b.level === "red") return b; // a BLOCK hold outranks an audit warning
      return { level: "amber", title: "WOULD BLOCK (audit mode)", detail: summarize(ev), until: now + HOLD_MS, sticky: false };
    case "ERROR":
      return { level: "red", title: "GUARD ERROR", detail: summarize(ev), until: null, sticky: true };
    default:
      return b;
  }
}

/** End a timed hold once its 5 s are up. */
export function expire(b: Banner, now: number): Banner {
  return b.until !== null && now >= b.until ? GREEN : b;
}

/** Banner for a fresh SNAPSHOT: only a trailing ERROR is still in force; old holds are not replayed. */
export function fromSnapshot(recent: SgEvent[]): Banner {
  const last = recent[recent.length - 1];
  return last?.type === "ERROR" ? applyEvent(GREEN, last, 0) : GREEN;
}

const present = (v: unknown) => v !== null && v !== undefined && v !== "";

/** One line describing an event, leaving out every null or missing field. */
export function summarize(ev: SgEvent): string {
  const parts: string[] = [];
  const who = [ev.comm, present(ev.tgid) ? `pid ${ev.tgid}` : null].filter(present).join(" ");
  if (who) parts.push(who);
  if (present(ev.daddr)) {
    const host = ev.family === "ipv6" ? `[${ev.daddr}]` : String(ev.daddr);
    parts.push(present(ev.dport) ? `→ ${host}:${ev.dport}` : `→ ${host}`);
  }
  if (present(ev.parent_tgid)) parts.push(`from pid ${ev.parent_tgid}`);
  if (present(ev.file)) parts.push(`read ${ev.file}`);
  if (present(ev.hook)) parts.push(`via ${ev.hook}`);
  if (Array.isArray(ev.protect) && ev.protect.length) parts.push(`protect ${ev.protect.join(", ")}`);
  if (Array.isArray(ev.allow)) parts.push(`allow ${ev.allow.length ? ev.allow.join(", ") : "(none)"}`);
  if (ev.type === "READY" && present(ev.mode)) parts.push(`mode ${ev.mode}`);
  if (present(ev.message)) parts.push(String(ev.message));
  return parts.join("  ·  ");
}
