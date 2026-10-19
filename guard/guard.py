#!/usr/bin/env python3
# guard.py: SyscallGuard loader and main loop. Runs as root, inside the VM only.
# Track: G (Guard runtime & bridge)
# Contracts: ARCHITECTURE.md Contract 1 (maps), Contract 2 (policy), Contract 3 (CLI + JSON schema).
# Stdout is JSON lines only (flushed per line). All logs go to stderr.
#
#   sudo python3 guard/guard.py -p POLICY [--mode audit|enforce] [--debug]
#
# Exit codes: 0 clean shutdown on SIGINT/SIGTERM, 2 bad policy, 3 BPF load failure.
import argparse
import ctypes
import json
import logging
import os
import signal
import sys
import time

import events
import policy

BPF_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bpf")
MODE_CODES = {"audit": 1, "enforce": 2}   # SG_MODE_* in sg_common.h
# Probes defined in syscallguard.bpf.c. bcc attaches every lsm__/raw_tracepoint__/tracepoint__
# function itself when it loads the program; we only check they landed, as (bcc table, key).
REQUIRED_PROBES = (
    ("lsm_fds", b"lsm__file_open"),                      # hook A
    ("raw_tracepoint_fds", b"sched_process_fork"),       # hook D
    ("tracepoint_fds", b"sched:sched_process_exit"),     # hook E
)

log = logging.getLogger("guard")
stdout_ok = True


def emit(obj):
    """One JSON line on stdout, flushed: the bridge reads this as a stream."""
    global stdout_ok
    if not stdout_ok:
        return
    try:
        sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")   # compact, like Contract 3
        sys.stdout.flush()
    except BrokenPipeError:
        # Reader is gone. Keep running so the kernel hooks stay attached; restarting the
        # whole pipeline is the operator's job. Point stdout at /dev/null so exit can't fail.
        stdout_ok = False
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        log.error("stdout closed (bridge gone?); still enforcing, no longer emitting events")


def load_bpf(pol, protect_inos):
    from bcc import BPF   # here, so a missing bcc becomes an ERROR event like any load failure
    b = BPF(src_file=os.path.join(BPF_DIR, "syscallguard.bpf.c"),
            cflags=["-I" + BPF_DIR, "-fms-extensions"])   # 7.x headers need it, see docs/shared.md
    for table, key in REQUIRED_PROBES:
        if key not in getattr(b, table):
            raise RuntimeError(f"probe {key.decode()} did not attach")
    log.debug("attached: %s", ", ".join(k.decode() for _, k in REQUIRED_PROBES))

    prot = b["protected_inodes"]
    for i, ino in enumerate(protect_inos):   # value = index into the policy's protect list
        prot[prot.Key(ino)] = prot.Leaf(i)
    for net in pol.allow:
        t = b["allow_v4" if net.version == 4 else "allow_v6"]
        k = t.Key()
        k.prefixlen = net.prefixlen   # bcc LPM key: u32 prefixlen, then address bytes in network order
        k.addr = type(k.addr)(*net.network_address.packed)
        t[k] = t.Leaf(1)
    cfg = b["config"]
    cfg[cfg.Key(0)] = cfg.Leaf(MODE_CODES[pol.mode])
    log.debug("maps filled: %d protected, %d allowed, mode=%s", len(protect_inos), len(pol.allow), pol.mode)
    return b


def main():
    ap = argparse.ArgumentParser(description="SyscallGuard: load hooks, print JSON events.")
    ap.add_argument("-p", "--policy", required=True, help="policy TOML file")
    ap.add_argument("--mode", choices=policy.MODES, help="override the policy's mode")
    ap.add_argument("--debug", action="store_true", help="verbose logging on stderr")
    args = ap.parse_args()
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG if args.debug else logging.INFO,
                        format="guard: %(levelname)s %(message)s")

    try:
        pol = policy.load(args.policy, args.mode)
        protect_inos = [os.stat(p).st_ino for p in pol.protect]   # follows symlinks, like policy.py
    except (policy.PolicyError, OSError) as e:
        log.error("bad policy: %s", e)
        return 2
    inode_paths = dict(zip(protect_inos, pol.protect))
    for ino, path in inode_paths.items():
        log.info("protecting ino=%d %s", ino, path)

    # The hooks stamp events with bpf_ktime_get_ns (CLOCK_MONOTONIC), so pair it with that clock.
    boot_epoch = time.clock_gettime(time.CLOCK_REALTIME) - time.clock_gettime(time.CLOCK_MONOTONIC)
    ctx = events.EventContext(inode_paths=inode_paths, boot_time_epoch=boot_epoch, mode=pol.mode)

    stop = []
    signal.signal(signal.SIGINT, lambda signum, _: stop.append(signum))
    signal.signal(signal.SIGTERM, lambda signum, _: stop.append(signum))

    if os.geteuid() != 0:
        log.warning("not root: loading BPF will fail")
    try:
        b = load_bpf(pol, protect_inos)
    except Exception as e:
        emit(events.error(ctx, f"BPF load failed: {e}"))
        log.error("BPF load failed: %s", e)
        return 3

    def on_event(_cb_ctx, data, size):
        ev = events.decode_event(ctypes.string_at(data, size), ctx)
        if ev is None:
            log.warning("dropped malformed event: %d bytes (struct sg_event is %d)", size, events.EVENT_SIZE)
            return
        log.debug("%s tgid=%s comm=%s", ev["type"], ev["tgid"], ev["comm"])
        emit(ev)

    b["events"].open_ring_buffer(on_event)
    emit(events.ready(ctx, pol.protect, pol.allow))
    log.info("ready, mode=%s; Ctrl-C to stop", pol.mode)
    while not stop:
        b.ring_buffer_poll(timeout=100)   # wakes every 100 ms to check for a signal
    log.info("signal %d, shutting down", stop[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
