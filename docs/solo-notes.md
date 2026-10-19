# Solo branch notes
Fallback build of SyscallGuard on branch `solo`. Team build lives on `main`.
Log solo work here only — never in docs/shared.md or the per-person files.

## Rules
- guard/bpf/ is owned by main. Never edit it on solo.
- Sync kernel from main when a milestone lands there:
      cd /home/zxan/projects/syscallguard-solo
      git checkout main -- guard/bpf/
      git commit -m "chore: sync kernel from main"
- Never push solo to main. Never merge either direction.
- Contracts 1-4 in ARCHITECTURE.md apply unchanged. Contract changes happen on
  main first with a `contract:` commit plus a docs/shared.md entry, then sync here.
- policy/policy.toml is per-worktree and gitignored. Solo's copy points at
  /home/inno/syscallguard-solo/demo/project/.env
- Default mode audit. Enforce only in the VM.

## Directory map
- Host /home/zxan/projects/syscallguard: team repo, branch main.
- Host /home/zxan/projects/syscallguard-solo: this worktree, branch solo.
- VM /home/inno/syscallguard: a real git clone of the team repo. Git works here. Kernel work only.
- VM /home/inno/syscallguard-solo: virtiofs mount (tag `solo`) of the host worktree above.
  Git does not work here and is not meant to: a worktree's `.git` is a file holding an
  absolute host path, so git fails with "gitfile does not point to a valid repository".
  Edits happen on the host; the VM only runs code. Do not try to fix this.

## Log
### 2026-10-19
- Branch and worktree created from main at 2e80714.
- Kernel synced from main at eaa8d4f (`chore: sync kernel from main`). That brings hook A
  only: hooks D and E (71d6051) are on track/kernel, not yet on main. Sync again when they land.
- Decision: the fallback dashboard is a plain-browser Vite static build. Electron is dropped
  for solo; revisit only after the department round. (ARCHITECTURE.md "Dashboard (Track U)"
  describes Electron; that section is not one of contracts 1-4, and the renderer already has
  to work in a plain browser via `?bridge=`.)
- Decision: the VM's solo directory is a virtiofs share of the host worktree, not a clone.
- guard/policy.py implemented (Contract 2). `load(path, mode=None)` returns a Policy or raises
  PolicyError; guard.py prints the message to stderr and exits 2. That reads ARCHITECTURE.md:168
  ("print ... and exit 2") as the guard's observable behaviour, not policy.py's (decided with
  Azaan). Exit codes belong to guard.py per Contract 3.
- Inode lookup stays in guard.py: Contract 3 says guard.py fills protected_inodes from st_ino.
  policy.py only os.stat()s each protect path to prove it exists.
- Not stated in Contract 2, chosen here: a missing `allow` key means empty (most restrictive);
  a missing `protect` key is rejected like an empty one.
- tests/test_policy.py uses unittest (the repo's tooling per AGENTS.md); pytest is not installed
  on the host. Static fixtures for invalid files live in tests/fixtures/policy/.

### 2026-10-20
- guard/events.py implemented (Contracts 1 and 3) with tests/test_events.py (unittest).
  struct sg_event is 72 bytes: gcc on sg_common.h gives offsetof comm = 52, sizeof = 72
  (4 bytes tail padding). ctypes mirror and struct format `@QQIIIIHH16s16s0Q` both agree.
- `ts` is float Unix epoch seconds as Contract 3 says (boot_time_epoch + ts_ns / 1e9),
  unrounded; the contract's example shows milliseconds but sets no precision.
- Decided here, not spelled out in the contracts:
  - "Malformed" (decode_event returns None) = shorter than 72 bytes, or a type, hook or
    family code sg_common.h doesn't define. (Changed 2026-10-20: a longer buffer decodes its
    first 72 bytes and ignores the tail, so a kernel struct change degrades to stale fields.)
  - IPv4-mapped IPv6 reports `family: "ipv4"` as well as the IPv4 `daddr`, so the two
    fields agree. Hook B/C's check_dest should already normalise these before emitting.
  - `parent_tgid` is null on everything except TAG_INHERIT (sg_common.h: "TAG_INHERIT only").
  - `comm` bytes that aren't UTF-8 decode with U+FFFD replacement rather than failing.
  - READY and ERROR have no kernel type code, so events.ready() and events.error() build
    them with the same field set; guard.py calls those instead of writing dicts itself.

### 2026-10-20 
- Synced hooks D and E from main in dfc0d3f, along with the Contract 2 clarifications. 
- The 19 Oct entry saying D and E are only on track/kernel is superseded.
- guard/guard.py implemented. Timestamps: hooks A, D and E all use bpf_ktime_get_ns
  (CLOCK_MONOTONIC), so boot_time_epoch = CLOCK_REALTIME - CLOCK_MONOTONIC, sampled once at
  startup. If a hook ever switches to bpf_ktime_get_boot_ns, switch to CLOCK_BOOTTIME too.
- Probes are attached by bcc's autoload on BPF() (lsm__file_open,
  raw_tracepoint__sched_process_fork, tracepoint__sched__sched_process_exit); calling
  attach again would raise. guard.py checks all three landed and treats a miss as a load
  failure (ERROR, exit 3). Add hooks B and C to REQUIRED_PROBES when they sync from main.
- Map fill failures (e.g. more protect paths than protected_inodes holds) count as a BPF
  load failure: ERROR, exit 3. Policy still doesn't cap list lengths.
- Decided here: if stdout breaks (bridge died), guard.py logs once to stderr, stops emitting
  and keeps running, so the kernel hooks stay attached. Restart the whole pipeline as usual.
- Solo VM policy: demo/solo-policy.toml (committed; paths are the VM virtiofs mount).

### 2026-10-20 — guard.py acceptance passed in the VM, over the virtiofs mount at
/home/inno/syscallguard-solo. Verified, not reported:
  - Inode agreement: stat gave 760558; guard logged "protecting ino=760558";
    bpftool map dump name protected_inode showed key 760558, value 0.
  - Sequence: READY (mode=audit, 1 protected, 2 allowed) -> TAG tgid=5614
    comm=cat -> UNTAG same tgid -> Ctrl-C -> exit=0, and
    bpftool prog list showed no file_open/sched_process probes left.
  - Bad policy (empty protect) -> stderr "bad policy: protect must be a
    non-empty list of absolute paths", exit=2.
  - The -Wmicrosoft-anon-tag warning at load is expected: it is the
    -fms-extensions case recorded in docs/shared.md, not a fault.

### 2026-10-20 — device-check fix, verify on BOTH filesystems before trusting it.
demo/project/.env on solo lives on the virtiofs mount (ino 760558); the team
clone's copy is on btrfs (handoff records dev=52). i_sb->s_dev vs userspace
st_dev can disagree on either, and when it does tagging stops silently with no
error. A value confirmed on one branch proves nothing about the other.
- bridge/bridge.py implemented (Contract 4) with tests/test_bridge.py (unittest, no sockets:
  State, feed() and fake_feed() are tested directly). Event log cap is 50, as Contract 4
  says ("the last 50 events"), not the 100 fallback.
- Decided here, not spelled out in Contract 4:
  - Malformed = not UTF-8, not JSON, not a JSON object, or no string `type`.
  - Before READY, SNAPSHOT has `protect: []` and `allow: []` alongside `mode: null`.
  - A repeat TAG (or TAG_INHERIT) for a tagged tgid keeps `since` but refreshes comm,
    file and parent_tgid from the new event, matching the kernel's upsert.
  - A tagged entry's comm comes only from TAG/TAG_INHERIT, so an inherited child shows
    the parent's name (e.g. python3 for curl) until re-tagged. Not refreshed from later
    ALLOW/BLOCK events.
  - --fake ends each loop with two UNTAGs (curl, then python3), so the tagged set is empty
    between loops instead of keeping python3 tagged forever.
  - stdin is read on a daemon thread, so it works for pipes, files and ttys, and Ctrl-C
    never hangs on a blocked read.
- guard.py fills config and the allow tries before protected_inodes. check_dest (hook B,
  track/kernel 02a1fe8) blocks unless mode == AUDIT, so an unset config (mode 0) enforces;
  filling protect last means nothing is tagged before mode is set.

### 2026-10-20 — any test that exercises guard.py runs from
/home/inno/syscallguard-solo, not /home/inno/syscallguard. The protected inode
(760558) is the solo copy of demo/project/.env; opening the clone's copy tags
nothing, every connect takes the untagged fast path and is allowed, and the
guard looks broken when it is working correctly. Cost 30 minutes once.

### 2026-10-20 — M3 (hook B) acceptance passed through real guard.py in the VM,
enforce mode. Four probes attached (lsm__file_open, lsm__socket_connect,
sched_process_fork, sched:sched_process_exit). TAG python3 -> ALLOW
127.0.0.1:8080 -> BLOCK 192.168.122.174:9999 -> the same ALLOW/BLOCK pair again for the
two ::ffff: connects, shown as IPv4, which proves the mapped-address conversion
-> UNTAG. Nothing emitted for the untagged connect. Not --fake: real kernel,
real tgids.

### 2026-10-20
- demo kit part 1: internal_api.py (allowlisted 127.0.0.1 mock), attacker.py (host-side TCP+UDP
  listener, meant to stay empty), agent.py (simulated agent, refuses to run as root).
- Honesty: agent.py reports only what it observed. It never asserts a block; the guard's BLOCK
  event is the only proof. udp and preconnect exercise the sendmsg path (hook C, not merged), so
  they succeed today and the agent says so plainly rather than calling it a failure.
- curl mode: curl exit 7 (connection refused) is indistinguishable from a kernel connect block
  by exit code alone, so the agent says "check the guard's BLOCK event" rather than claiming a
  block. attacker.py's TCP side now reads with a 1 s timeout then returns a tiny HTTP 200, so a
  curl that DOES get through exits 0 (clean signal); a blocked connect gives curl exit 7.
- Baseline verified on the host with no guard: all six modes succeed and the attacker window
  lights up. That is correct -- it proves the kit works before the kernel is involved.
