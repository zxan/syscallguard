#!/usr/bin/env python3
# bridge.py: stdin JSON lines -> WebSocket broadcast, with state snapshot for new clients.
# Track: G (Guard runtime & bridge). Never imports bcc, never needs root.
# Contracts: ARCHITECTURE.md Contract 3 (input events), Contract 4 (WebSocket protocol).
#
#   sudo python3 guard/guard.py -p POLICY | python3 bridge/bridge.py [--host 0.0.0.0] [--port 8765]
#   python3 bridge/bridge.py --fake [--port 8765]        # no kernel, any OS
import argparse
import asyncio
import collections
import json
import logging
import sys
import threading
import time

RECENT_MAX = 50   # Contract 4: "the last 50 events"
FIELDS = ("hook", "tgid", "parent_tgid", "comm", "file", "family", "daddr", "dport")

log = logging.getLogger("bridge")


class State:
    """Everything a SNAPSHOT needs, driven by guard events. No sockets, no I/O."""

    def __init__(self):
        self.mode = None   # null until READY
        self.protect = []
        self.allow = []
        self.tagged = {}   # tgid -> {tgid, comm, file, since, parent_tgid}
        self.recent = collections.deque(maxlen=RECENT_MAX)
        self.guard_connected = True

    def handle_line(self, raw):
        """One stdin line (bytes or str). Returns the text to broadcast unchanged, or None if
        the line was malformed (logged and skipped)."""
        try:
            text = raw.decode() if isinstance(raw, bytes) else raw
            text = text.rstrip("\r\n")
            ev = json.loads(text)
            if not isinstance(ev, dict) or not isinstance(ev.get("type"), str):
                raise ValueError("not a JSON object with a string 'type'")
        except ValueError as e:   # covers UnicodeDecodeError and JSONDecodeError
            log.warning("skipped malformed line (%s): %.200r", e, raw)
            return None
        self.apply(ev)
        return text

    def apply(self, ev):
        t = ev["type"]
        if t == "READY":
            self.mode = ev.get("mode")
            self.protect = ev.get("protect", [])
            self.allow = ev.get("allow", [])
        elif t in ("TAG", "TAG_INHERIT"):
            old = self.tagged.get(ev.get("tgid"))
            self.tagged[ev.get("tgid")] = {
                "tgid": ev.get("tgid"), "comm": ev.get("comm"), "file": ev.get("file"),
                "since": old["since"] if old else ev.get("ts"),   # a repeat TAG keeps its since
                "parent_tgid": ev.get("parent_tgid"),
            }
        elif t == "UNTAG":
            self.tagged.pop(ev.get("tgid"), None)
        self.recent.append(ev)

    def guard_eof(self):
        """stdin closed. Returns the one GUARD_STATE message to broadcast, then None forever:
        stdin can't reopen, so there is no reconnect."""
        if not self.guard_connected:
            return None
        self.guard_connected = False
        return json.dumps({"v": 1, "type": "GUARD_STATE", "connected": False}, separators=(",", ":"))

    def snapshot(self):
        return {"v": 1, "type": "SNAPSHOT", "mode": self.mode, "guard_connected": self.guard_connected,
                "protect": self.protect, "allow": self.allow, "tagged": list(self.tagged.values()),
                "recent": list(self.recent)}


async def feed(queue, state, send):
    """Apply and broadcast stdin lines from `queue` until EOF (None), then send GUARD_STATE once
    and return. Nothing reads stdin again after this returns."""
    while (raw := await queue.get()) is not None:
        if (text := state.handle_line(raw)) is not None:
            send(text)
    log.warning("guard stdin closed; serving last state, guard_connected=false")
    if (msg := state.guard_eof()) is not None:
        send(msg)


def start_stdin_reader(loop):
    """Read stdin on a daemon thread (works for pipes, files and ttys; never blocks exit)."""
    queue = asyncio.Queue()

    def reader():
        for line in sys.stdin.buffer:
            loop.call_soon_threadsafe(queue.put_nowait, line)
        loop.call_soon_threadsafe(queue.put_nowait, None)

    threading.Thread(target=reader, daemon=True).start()
    return queue


ENV = "/home/inno/syscallguard-solo/demo/project/.env"


def fake_story():
    """One loop of the Contract 4 --fake story, as full Contract 3 events."""
    def ev(type_, **kw):
        out = {"v": 1, "ts": time.time(), "type": type_, **dict.fromkeys(FIELDS), "mode": "enforce"}
        out.update(kw)
        return out
    py = dict(tgid=4421, comm="python3", file=ENV)
    return [
        ev("READY", protect=[ENV], allow=["127.0.0.0/8", "::1/128"]),
        ev("TAG", hook="file_open", **py),
        ev("ALLOW", hook="connect", family="ipv4", daddr="127.0.0.1", dport=8080, **py),
        ev("TAG_INHERIT", hook="fork", tgid=4422, parent_tgid=4421, comm="python3", file=ENV),
        ev("BLOCK", hook="connect", tgid=4422, comm="curl", file=ENV,
           family="ipv4", daddr="192.168.122.1", dport=9999),
        ev("UNTAG", hook="exit", tgid=4422, comm="curl", file=ENV),
        ev("UNTAG", hook="exit", **py),
    ]


async def fake_feed(state, send, delay=1.5, loops=None):
    """Loop the fake story (~10 s per loop) through the same path as real stdin lines."""
    n = 0
    while loops is None or n < loops:
        for e in fake_story():
            e["ts"] = time.time()
            if (text := state.handle_line(json.dumps(e, separators=(",", ":")))) is not None:
                send(text)
            await asyncio.sleep(delay)
        n += 1


async def run(args):
    from websockets.asyncio.server import broadcast, serve
    from websockets.exceptions import ConnectionClosed

    state = State()
    clients = set()

    async def handler(ws):
        # Snapshot and join the broadcast set with no await in between, so a client never
        # misses an event or gets one twice; then SNAPSHOT is the first frame it sees.
        snap = json.dumps(state.snapshot(), separators=(",", ":"))
        clients.add(ws)
        try:
            await ws.send(snap)
            async for _ in ws:   # read-only feed: ignore client messages
                pass
        except ConnectionClosed:
            pass
        finally:
            clients.discard(ws)

    def send(msg):
        broadcast(clients, msg)

    async with serve(handler, args.host, args.port):
        log.info("listening on ws://%s:%d%s", args.host, args.port, " (fake)" if args.fake else "")
        if args.fake:
            await fake_feed(state, send)
        else:
            await feed(start_stdin_reader(asyncio.get_running_loop()), state, send)
            await asyncio.Future()   # guard gone: keep serving the last state until killed


def main():
    ap = argparse.ArgumentParser(description="SyscallGuard bridge: guard JSON lines -> WebSocket.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--fake", action="store_true", help="synthesize events; no stdin")
    args = ap.parse_args()
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="bridge: %(levelname)s %(message)s")
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
