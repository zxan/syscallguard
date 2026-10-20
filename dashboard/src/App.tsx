// App.tsx: SyscallGuard dashboard. Banner + event log + two connection indicators.
// Contracts: ARCHITECTURE.md Contract 3 (event fields), Contract 4 (SNAPSHOT, GUARD_STATE).
// Real data only: every change on screen is caused by a bridge message or the socket opening or
// closing. The page never knows (or cares) whether the bridge is running --fake.
import { useEffect, useRef, useState } from "react";
import { GREEN, applyEvent, expire, fromSnapshot, summarize, type Banner, type SgEvent } from "./banner.ts";

const LOG_MAX = 100; // render cap; the bridge's SNAPSHOT carries only its last 50 (Contract 4)
const RETRY_MS = 2000;
const BRIDGE_URL = new URLSearchParams(location.search).get("bridge") || __SG_BRIDGE_URL__;

type Link = "connecting" | "up" | "down" | "invalid";
type Guard = "unknown" | "feeding" | "gone";
interface Row {
  id: number;
  ev: SgEvent;
}

function fmtTime(ts: unknown) {
  return typeof ts === "number" ? new Date(ts * 1000).toLocaleTimeString("en-GB", { hour12: false }) : "";
}

export default function App() {
  const [link, setLink] = useState<Link>("connecting");
  const [guard, setGuard] = useState<Guard>("unknown");
  const [rows, setRows] = useState<Row[]>([]);
  const [banner, setBanner] = useState<Banner>(GREEN);
  const nextId = useRef(0);

  useEffect(() => {
    let ws: WebSocket | undefined;
    let retry: number | undefined;
    let stopped = false;

    function onMessage(raw: string) {
      let msg: SgEvent;
      try {
        msg = JSON.parse(raw);
      } catch {
        return;
      }
      if (!msg || typeof msg.type !== "string") return;
      if (msg.type === "SNAPSHOT") {
        const recent = (Array.isArray(msg.recent) ? (msg.recent as SgEvent[]) : []).filter(
          (e) => e && e.type !== "GUARD_STATE",
        );
        setGuard(msg.guard_connected ? "feeding" : "gone");
        setRows(
          [...recent].reverse().slice(0, LOG_MAX).map((ev) => ({ id: nextId.current++, ev })),
        );
        setBanner(fromSnapshot(recent));
      } else if (msg.type === "GUARD_STATE") {
        setGuard(msg.connected ? "feeding" : "gone"); // indicator only: never logged
      } else {
        const ev = msg;
        setRows((r) => [{ id: nextId.current++, ev }, ...r].slice(0, LOG_MAX));
        setBanner((b) => applyEvent(b, ev, Date.now()));
      }
    }

    function connect() {
      try {
        ws = new WebSocket(BRIDGE_URL);
      } catch {
        setLink("invalid"); // malformed URL: retrying can't help
        return;
      }
      ws.onopen = () => setLink("up");
      ws.onmessage = (m) => onMessage(String(m.data));
      ws.onclose = () => {
        setLink("down");
        setGuard("unknown"); // can't know the guard's state without the bridge
        if (!stopped) retry = window.setTimeout(connect, RETRY_MS);
      };
    }

    connect();
    return () => {
      stopped = true;
      clearTimeout(retry);
      ws?.close();
    };
  }, []);

  // End a BLOCK/WOULD_BLOCK hold. Small slack so the timer can't fire just before `until`.
  useEffect(() => {
    if (banner.until === null) return;
    const t = window.setTimeout(() => setBanner((b) => expire(b, Date.now())), banner.until - Date.now() + 20);
    return () => clearTimeout(t);
  }, [banner]);

  const linkText = {
    connecting: "connecting…",
    up: "connected",
    down: `unreachable, retrying every ${RETRY_MS / 1000} s`,
    invalid: "invalid URL",
  }[link];
  const guardState = link !== "up" ? "unknown" : guard;

  return (
    <main>
      <section className={`banner ${banner.level}`} role="status">
        <div className="banner-title">{banner.title}</div>
        {banner.detail && <div className="banner-detail">{banner.detail}</div>}
      </section>

      <div className="status">
        <span className={`ind ${link === "up" ? "ok" : link === "connecting" ? "unk" : "bad"}`}>
          Bridge: {link === "up" ? "reachable" : link === "connecting" ? "connecting" : "unreachable"}
        </span>
        <span className={`ind ${guardState === "feeding" ? "ok" : guardState === "gone" ? "bad" : "unk"}`}>
          Guard: {guardState === "feeding" ? "feeding" : guardState === "gone" ? "not feeding" : "unknown"}
        </span>
        <span className="url">
          {BRIDGE_URL} · {linkText}
        </span>
      </div>

      {rows.length === 0 ? (
        <p className="empty">No events received.</p>
      ) : (
        <ol className="log">
          {rows.map(({ id, ev }) => (
            <li key={id} className={`row t-${ev.type}`}>
              <span className="time">{fmtTime(ev.ts)}</span>
              <span className="type">{ev.type}</span>
              <span className="text">{summarize(ev)}</span>
            </li>
          ))}
        </ol>
      )}
    </main>
  );
}
