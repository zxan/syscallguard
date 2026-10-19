# test_events.py: unprivileged unit tests for guard/events.py. Run anywhere:
#   python3 -m unittest tests/test_events.py
# Track: G (Guard runtime & bridge)
# Contracts: ARCHITECTURE.md Contract 1 (struct sg_event), Contract 3 (JSON event schema).
#
# Buffers are built with struct.pack against sg_common.h. Hooks B and C aren't merged yet,
# so ALLOW/BLOCK/WOULD_BLOCK buffers follow the struct definition, not observed output.
import contextlib
import io
import ipaddress
import json
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "guard"))
import events  # noqa: E402
from events import EventContext, decode_event  # noqa: E402

# struct sg_event: ts_ns ino type hook tgid parent_tgid family dport daddr[16] comm[16].
# Trailing 0Q pads to 8-byte alignment like the C compiler does.
FMT = "@QQIIIIHH16s16s0Q"
FIELDS = ("v", "ts", "type", "hook", "tgid", "parent_tgid", "comm", "file",
          "family", "daddr", "dport", "mode")
ENV = "/home/inno/syscallguard-solo/demo/project/.env"
INO = 1532


def pack(type_, hook, tgid=4421, parent_tgid=0, family=0, dport=0, daddr=b"",
         comm=b"curl", ino=INO, ts_ns=5_000_000_000):
    return struct.pack(FMT, ts_ns, ino, type_, hook, tgid, parent_tgid, family, dport,
                       daddr, comm)


def v6(text):
    return ipaddress.IPv6Address(text).packed


class TestEvents(unittest.TestCase):
    def setUp(self):
        self.ctx = EventContext(inode_paths={INO: ENV}, boot_time_epoch=1760600000.0, mode="enforce")

    def decode(self, buf, ctx=None):
        ev = decode_event(buf, ctx or self.ctx)
        self.assertIsNotNone(ev)
        self.assertEqual(set(FIELDS) - set(ev), set())   # every field present, nulls included
        json.dumps(ev)                                    # serialisable as-is
        return ev

    def test_format_matches_c_struct(self):
        # 72 = sizeof(struct sg_event) from gcc against sg_common.h (offsetof comm = 52).
        self.assertEqual(struct.calcsize(FMT), events.EVENT_SIZE)
        self.assertEqual(events.EVENT_SIZE, 72)
        self.assertEqual(events.SgEvent.comm.offset, 52)

    def test_tag(self):
        ev = self.decode(pack(1, 1, comm=b"cat"))
        self.assertEqual((ev["type"], ev["hook"], ev["tgid"], ev["comm"], ev["file"]),
                         ("TAG", "file_open", 4421, "cat", ENV))
        self.assertIsNone(ev["parent_tgid"])
        self.assertEqual((ev["family"], ev["daddr"], ev["dport"]), (None, None, None))
        self.assertEqual(ev["ts"], 1760600005.0)
        self.assertEqual(ev["v"], 1)

    def test_tag_inherit(self):
        ev = self.decode(pack(2, 4, tgid=4500, parent_tgid=4421, comm=b"python3"))
        self.assertEqual((ev["type"], ev["hook"], ev["tgid"], ev["parent_tgid"]),
                         ("TAG_INHERIT", "fork", 4500, 4421))

    def test_untag(self):
        ev = self.decode(pack(6, 5))
        self.assertEqual((ev["type"], ev["hook"], ev["file"]), ("UNTAG", "exit", ENV))
        self.assertIsNone(ev["parent_tgid"])

    def test_block_ipv4(self):
        ev = self.decode(pack(4, 2, family=2, dport=9999, daddr=bytes([192, 168, 122, 1])))
        self.assertEqual((ev["type"], ev["hook"], ev["family"], ev["daddr"], ev["dport"]),
                         ("BLOCK", "connect", "ipv4", "192.168.122.1", 9999))

    def test_allow_ipv4(self):
        ev = self.decode(pack(3, 2, family=2, dport=8080, daddr=bytes([127, 0, 0, 1])))
        self.assertEqual((ev["type"], ev["daddr"], ev["dport"]), ("ALLOW", "127.0.0.1", 8080))

    def test_would_block_native_ipv6_sendmsg(self):
        audit = EventContext(self.ctx.inode_paths, self.ctx.boot_time_epoch, "audit")
        ev = self.decode(pack(5, 3, family=10, dport=53, daddr=v6("2001:db8::1")), audit)
        self.assertEqual((ev["type"], ev["hook"], ev["family"], ev["daddr"], ev["mode"]),
                         ("WOULD_BLOCK", "sendmsg", "ipv6", "2001:db8::1", "audit"))

    def test_ipv4_mapped_ipv6_rendered_as_ipv4(self):
        ev = self.decode(pack(4, 2, family=10, dport=9999, daddr=v6("::ffff:192.168.122.1")))
        self.assertEqual((ev["family"], ev["daddr"]), ("ipv4", "192.168.122.1"))

    def test_mode_comes_from_ctx(self):
        buf = pack(4, 2, family=2, dport=9999, daddr=bytes([10, 0, 0, 1]))
        for mode in ("audit", "enforce"):
            ctx = EventContext(self.ctx.inode_paths, self.ctx.boot_time_epoch, mode)
            self.assertEqual(self.decode(buf, ctx)["mode"], mode)

    def test_unknown_inode_file_null(self):
        ev = self.decode(pack(1, 1, ino=999))
        self.assertIsNone(ev["file"])
        self.assertEqual(ev["type"], "TAG")

    def test_truncated_buffer(self):
        self.assertIsNone(decode_event(pack(1, 1)[:40], self.ctx))
        self.assertIsNone(decode_event(b"", self.ctx))

    def test_overlong_buffer_decodes_prefix(self):
        buf = pack(1, 1, comm=b"cat")
        self.assertEqual(self.decode(buf + b"\xff" * 8), self.decode(buf))

    def test_garbage_full_length(self):
        # All-0xff: type/hook/family codes sg_common.h doesn't define -> malformed.
        self.assertIsNone(decode_event(b"\xff" * events.EVENT_SIZE, self.ctx))
        # Valid codes but junk text bytes: still decodes, comm with replacement chars.
        ev = self.decode(pack(1, 1, comm=b"\xff\xfe\x80abc"))
        self.assertEqual(ev["comm"], "���abc")

    def test_ready(self):
        ev = events.ready(self.ctx, [ENV], [ipaddress.ip_network("127.0.0.0/8"), "::1/128"])
        self.assertEqual(set(FIELDS) - set(ev), set())
        self.assertEqual((ev["type"], ev["comm"], ev["hook"], ev["mode"]), ("READY", None, None, "enforce"))
        self.assertEqual((ev["protect"], ev["allow"]), ([ENV], ["127.0.0.0/8", "::1/128"]))
        self.assertIsInstance(ev["ts"], float)

    def test_error(self):
        ev = events.error(self.ctx, "verifier rejected program")
        self.assertEqual(set(FIELDS) - set(ev), set())
        self.assertEqual((ev["type"], ev["comm"], ev["message"]), ("ERROR", None, "verifier rejected program"))

    def test_never_writes_stdout(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            decode_event(pack(1, 1), self.ctx)
            decode_event(b"short", self.ctx)
            events.ready(self.ctx, [ENV], [])
            events.error(self.ctx, "x")
        self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
