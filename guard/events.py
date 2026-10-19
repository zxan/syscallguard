# events.py: decode `struct sg_event` from the ring buffer into Contract 3 JSON dicts.
# Track: G (Guard runtime & bridge)
# Contracts: ARCHITECTURE.md Contract 1 (struct sg_event, SG_EV_*/SG_HOOK_* constants),
#            Contract 3 (JSON event schema).
#
# Pure decoding: never writes to stdout. guard.py owns json.dumps and the write.
# READY and ERROR come from guard.py, not the kernel; ready() and error() build them here so
# every event has the same field set.
import ctypes
import ipaddress
import time
from dataclasses import dataclass


class SgEvent(ctypes.Structure):
    """Mirror of struct sg_event in guard/bpf/sg_common.h. Native layout, like the kernel's."""
    _fields_ = [
        ("ts_ns", ctypes.c_uint64),
        ("ino", ctypes.c_uint64),
        ("type", ctypes.c_uint32),
        ("hook", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("parent_tgid", ctypes.c_uint32),
        ("family", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("daddr", ctypes.c_uint8 * 16),
        ("comm", ctypes.c_char * 16),
    ]


EVENT_SIZE = ctypes.sizeof(SgEvent)   # 72: 68 bytes of fields + 4 tail padding

TYPES = {1: "TAG", 2: "TAG_INHERIT", 3: "ALLOW", 4: "BLOCK", 5: "WOULD_BLOCK", 6: "UNTAG"}
HOOKS = {0: None, 1: "file_open", 2: "connect", 3: "sendmsg", 4: "fork", 5: "exit"}
AF_INET, AF_INET6 = 2, 10
SG_EV_TAG_INHERIT = 2


@dataclass
class EventContext:
    inode_paths: dict[int, str]
    boot_time_epoch: float
    mode: str


def _base(ctx, type_, ts):
    return {"v": 1, "ts": ts, "type": type_, "hook": None, "tgid": None, "parent_tgid": None,
            "comm": None, "file": None, "family": None, "daddr": None, "dport": None,
            "mode": ctx.mode}


def decode_event(data: bytes, ctx: EventContext) -> dict | None:
    """Kernel event bytes -> Contract 3 dict. None only if the buffer is malformed: wrong
    length, or a type/hook/family code sg_common.h doesn't define."""
    if len(data) != EVENT_SIZE:
        return None
    ev = SgEvent.from_buffer_copy(data)
    if ev.type not in TYPES or ev.hook not in HOOKS or ev.family not in (0, AF_INET, AF_INET6):
        return None

    out = _base(ctx, TYPES[ev.type], ctx.boot_time_epoch + ev.ts_ns / 1e9)
    out["hook"] = HOOKS[ev.hook]
    out["tgid"] = ev.tgid
    if ev.type == SG_EV_TAG_INHERIT:
        out["parent_tgid"] = ev.parent_tgid
    out["comm"] = ev.comm.decode(errors="replace")   # c_char array stops at the first NUL
    out["file"] = ctx.inode_paths.get(ev.ino)        # unknown inode (or 0) -> null

    raw = bytes(ev.daddr)
    if ev.family == AF_INET:
        addr = ipaddress.IPv4Address(raw[:4])
    elif ev.family == AF_INET6:
        addr = ipaddress.IPv6Address(raw)
        addr = addr.ipv4_mapped or addr   # ::ffff:a.b.c.d -> a.b.c.d, reported as ipv4
    else:
        return out
    out["family"] = f"ipv{addr.version}"
    out["daddr"] = str(addr)
    out["dport"] = ev.dport
    return out


def ready(ctx: EventContext, protect, allow) -> dict:
    """READY event: carries the policy's protect paths and allow CIDRs."""
    out = _base(ctx, "READY", time.time())
    out["protect"] = list(protect)
    out["allow"] = [str(a) for a in allow]
    return out


def error(ctx: EventContext, message: str) -> dict:
    out = _base(ctx, "ERROR", time.time())
    out["message"] = message
    return out
