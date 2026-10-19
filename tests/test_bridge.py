# test_bridge.py: unprivileged unit tests for bridge/bridge.py. Run anywhere:
#   python3 -m unittest tests/test_bridge.py
# Track: G (Guard runtime & bridge)
# Contracts: ARCHITECTURE.md Contract 3 (input events), Contract 4 (WebSocket protocol).
#
# Exercises State, feed() and fake_feed() directly; no sockets.
import asyncio
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bridge"))
import bridge  # noqa: E402
from bridge import State  # noqa: E402

READY = '{"v":1,"ts":1.0,"type":"READY","mode":"audit","protect":["/p/.env"],"allow":["127.0.0.0/8"]}'


def ev(type_, ts=2.0, **kw):
    return json.dumps({"v": 1, "ts": ts, "type": type_, **kw})


def run_feed(lines):
    """Feed lines then EOF (and anything after it) through feed(); return what was broadcast."""
    async def go():
        q = asyncio.Queue()
        for item in lines:
            q.put_nowait(item)
        sent = []
        state = State()
        await asyncio.wait_for(bridge.feed(q, state, sent.append), timeout=1)
        return state, sent, q
    return asyncio.run(go())


class TestBridge(unittest.TestCase):
    def test_malformed_lines_skipped_and_bridge_survives(self):
        s = State()
        with self.assertLogs("bridge", "WARNING") as logs:
            for bad in (b"not json\n", b"[1, 2]\n", b'{"no_type": 1}\n', b"\xff\xfe\n", b"\n"):
                self.assertIsNone(s.handle_line(bad))
        self.assertEqual(len(logs.output), 5)
        self.assertEqual(s.handle_line((READY + "\n").encode()), READY)   # unchanged, newline stripped
        self.assertEqual(s.mode, "audit")
        self.assertEqual(len(s.recent), 1)

    def test_snapshot_before_ready_has_null_mode(self):
        snap = State().snapshot()
        self.assertIsNone(snap["mode"])
        self.assertEqual((snap["v"], snap["type"], snap["guard_connected"]), (1, "SNAPSHOT", True))
        self.assertEqual((snap["protect"], snap["allow"], snap["tagged"], snap["recent"]), ([], [], [], []))

    def test_snapshot_after_ready(self):
        s = State()
        s.handle_line(READY)
        snap = s.snapshot()
        self.assertEqual((snap["mode"], snap["protect"], snap["allow"]), ("audit", ["/p/.env"], ["127.0.0.0/8"]))

    def test_repeat_tag_keeps_since(self):
        s = State()
        s.handle_line(ev("TAG", ts=10.0, tgid=7, comm="cat", file="/p/.env", parent_tgid=None))
        s.handle_line(ev("TAG", ts=20.0, tgid=7, comm="cat", file="/p/.env", parent_tgid=None))
        self.assertEqual(s.snapshot()["tagged"],
                         [{"tgid": 7, "comm": "cat", "file": "/p/.env", "since": 10.0, "parent_tgid": None}])

    def test_tag_inherit_and_untag(self):
        s = State()
        s.handle_line(ev("TAG", ts=1.0, tgid=7, comm="python3", file="/p/.env", parent_tgid=None))
        s.handle_line(ev("TAG_INHERIT", ts=2.0, tgid=8, comm="python3", file="/p/.env", parent_tgid=7))
        self.assertEqual([(t["tgid"], t["parent_tgid"]) for t in s.snapshot()["tagged"]], [(7, None), (8, 7)])
        s.handle_line(ev("UNTAG", tgid=8))
        s.handle_line(ev("UNTAG", tgid=99))   # unknown tgid: no error
        self.assertEqual([t["tgid"] for t in s.snapshot()["tagged"]], [7])

    def test_recent_capped_at_50(self):
        s = State()
        for i in range(60):
            s.handle_line(ev("ALLOW", ts=float(i), tgid=1))
        recent = s.snapshot()["recent"]
        self.assertEqual((len(recent), recent[0]["ts"], recent[-1]["ts"]), (50, 10.0, 59.0))

    def test_eof_sends_one_guard_state_and_never_reconnects(self):
        # Lines queued after EOF must never be read: feed() returns at the first None.
        with self.assertLogs("bridge", "WARNING"):   # "guard stdin closed"
            state, sent, q = run_feed([READY.encode(), None, ev("TAG", tgid=7).encode(), None])
        gs = {"v": 1, "type": "GUARD_STATE", "connected": False}
        self.assertEqual([sent[0], json.loads(sent[1])], [READY, gs])
        self.assertFalse(state.guard_connected)
        self.assertFalse(state.snapshot()["guard_connected"])
        self.assertEqual(q.qsize(), 2)   # the post-EOF items were left unread
        self.assertIsNone(state.guard_eof())   # a second EOF sends nothing

    def test_guard_state_not_in_recent(self):
        with self.assertLogs("bridge", "WARNING"):
            state, sent, _ = run_feed([READY.encode(), None])
        self.assertEqual([e["type"] for e in state.snapshot()["recent"]], ["READY"])

    def test_fake_reports_connected(self):
        async def go():
            s, sent = State(), []
            await bridge.fake_feed(s, sent.append, delay=0, loops=1)
            return s, sent
        s, sent = asyncio.run(go())
        types = [json.loads(m)["type"] for m in sent]
        self.assertEqual(types, ["READY", "TAG", "ALLOW", "TAG_INHERIT", "BLOCK", "UNTAG", "UNTAG"])
        snap = s.snapshot()
        self.assertTrue(snap["guard_connected"])
        self.assertEqual((snap["mode"], snap["tagged"]), ("enforce", []))
        self.assertNotIn("GUARD_STATE", types)


if __name__ == "__main__":
    unittest.main()
