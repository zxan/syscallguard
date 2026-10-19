/*
 * syscallguard.bpf.c: all SyscallGuard eBPF hooks and maps (compiled by bcc at load time).
 * Track: K (Kernel enforcement)
 * Contract: ARCHITECTURE.md Contract 1 (sg_common.h structs, map names) and the Hooks /
 *           Decision logic sections. Map names are part of the contract: guard.py looks them up.
 *
 * TODO (M4 Sendmsg):
 *   - Hook C: LSM_PROBE(socket_sendmsg): msg_name if set, else connected peer from sk_common
 * TODO (S1 Stretch, after M7): socket_create denies AF_PACKET/SOCK_RAW for tagged processes
 */
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/in6.h>
#include "sg_common.h"

/* Contract 1 maps. All six are declared now so guard.py can fill them from M1 on. */
BPF_HASH(protected_inodes, u64, u32, 256);
BPF_HASH(tagged, u32, struct sg_tag_info, 16384);
BPF_LPM_TRIE(allow_v4, struct sg_lpm_v4, u8, 1024);
BPF_LPM_TRIE(allow_v6, struct sg_lpm_v6, u8, 1024);
BPF_ARRAY(config, struct sg_config, 1);
BPF_RINGBUF_OUTPUT(events, 64);

/* Emit an event. Reserved in the ring buffer, not built on the 512-byte stack. Buffer full:
 * the event is lost, never the tag change or verdict the caller made. `daddr` is NULL or 16
 * bytes (IPv4 in the first 4, network order); `dport` is host byte order. */
static __always_inline void emit(u32 type, u32 hook, u32 tgid, u32 parent_tgid, u64 ino, u64 ts,
                                 u16 family, const u8 *daddr, u16 dport)
{
    struct sg_event *ev = events.ringbuf_reserve(sizeof(struct sg_event));
    if (!ev)
        return;
    __builtin_memset(ev, 0, sizeof(*ev));
    ev->ts_ns = ts;
    ev->ino = ino;
    ev->type = type;
    ev->hook = hook;
    ev->tgid = tgid;
    ev->parent_tgid = parent_tgid;
    ev->family = family;
    ev->dport = dport;
    if (daddr)
        __builtin_memcpy(ev->daddr, daddr, 16);
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    events.ringbuf_submit(ev, 0);
}

/* Decision logic, ARCHITECTURE.md. `addr` is 16 bytes (IPv4 in the first 4, network order),
 * `dport` host order. Returns the LSM verdict: 0 or -EPERM. */
static __always_inline int check_dest(u16 family, u8 *addr, u16 dport, u32 hook)
{
    int zero = 0;
    struct sg_config *cfg = config.lookup(&zero);
    if (!cfg)
        return 0;
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct sg_tag_info *tag = tagged.lookup(&tgid);
    if (!tag)
        return 0;   /* fast path: untagged */
    u64 ino = tag->ino;
    u32 mode = cfg->mode;

    /* ::ffff:a.b.c.d is IPv4 on the wire: check it against allow_v4. Unrolled, no loop. */
    if (family == AF_INET6 && addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 &&
        addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0 && addr[8] == 0 &&
        addr[9] == 0 && addr[10] == 0xff && addr[11] == 0xff) {
        family = AF_INET;
        __builtin_memcpy(addr, addr + 12, 4);
        __builtin_memset(addr + 4, 0, 12);
    }

    int allowed;
    if (family == AF_INET) {
        struct sg_lpm_v4 k = {.prefixlen = 32};
        __builtin_memcpy(k.addr, addr, 4);
        allowed = allow_v4.lookup(&k) != NULL;
    } else if (family == AF_INET6) {
        struct sg_lpm_v6 k = {.prefixlen = 128};
        __builtin_memcpy(k.addr, addr, 16);
        allowed = allow_v6.lookup(&k) != NULL;
    } else {
        return 0;   /* AF_UNIX etc.: known gap */
    }

    u64 now = bpf_ktime_get_ns();
    if (allowed) {
        if (hook == SG_HOOK_CONNECT)   /* hook C stays silent on allowed sends */
            emit(SG_EV_ALLOW, hook, tgid, 0, ino, now, family, addr, dport);
        return 0;
    }
    if (mode == SG_MODE_AUDIT) {
        emit(SG_EV_WOULD_BLOCK, hook, tgid, 0, ino, now, family, addr, dport);
        return 0;
    }
    emit(SG_EV_BLOCK, hook, tgid, 0, ino, now, family, addr, dport);
    return -EPERM;
}

/* Hook A: tag any process that opens a protected file. Never denies. */
LSM_PROBE(file_open, struct file *file)
{
    u64 ino = file->f_inode->i_ino;
    if (!protected_inodes.lookup(&ino))
        return 0;

    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u64 now = bpf_ktime_get_ns();
    struct sg_tag_info tag = {};
    tag.ts_ns = now;
    tag.ino = ino;
    tagged.update(&tgid, &tag);   /* upsert: a re-open refreshes ts and clears parent_tgid */
    emit(SG_EV_TAG, SG_HOOK_FILE_OPEN, tgid, 0, ino, now, 0, NULL, 0);
    return 0;
}

/* Hook D: a new process forked by a tagged process inherits the tag. Threads don't:
 * they share the tgid, and `tagged` is keyed by tgid. */
RAW_TRACEPOINT_PROBE(sched_process_fork)
{
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];
    pid_t ptgid = 0, ctgid = 0;
    /* raw tracepoint args are untyped u64s, so bcc can't rewrite these derefs; read explicitly */
    bpf_probe_read_kernel(&ptgid, sizeof(ptgid), &parent->tgid);
    bpf_probe_read_kernel(&ctgid, sizeof(ctgid), &child->tgid);
    if (ptgid == ctgid)
        return 0;   /* new thread, not a new process */

    u32 parent_tgid = ptgid, child_tgid = ctgid;
    struct sg_tag_info *ptag = tagged.lookup(&parent_tgid);
    if (!ptag)
        return 0;

    u64 now = bpf_ktime_get_ns();
    struct sg_tag_info tag = {};
    tag.ts_ns = now;
    tag.ino = ptag->ino;
    tag.parent_tgid = parent_tgid;
    tagged.update(&child_tgid, &tag);   /* update, not insert: overwrites a stale entry on tgid reuse */
    /* Runs before the child execs, so comm is the parent's name. TAG_INHERIT asserts no name. */
    emit(SG_EV_TAG_INHERIT, SG_HOOK_FORK, child_tgid, parent_tgid, tag.ino, now, 0, NULL, 0);
    return 0;
}

/* Hook E: untag when the thread-group leader exits. A worker thread exiting must not
 * untag the process, so delete only when pid == tgid. (Known gap: a leader that exits
 * while its threads keep running loses the tag early.) */
TRACEPOINT_PROBE(sched, sched_process_exit)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    if ((u32)id != tgid)
        return 0;

    struct sg_tag_info *tag = tagged.lookup(&tgid);
    if (!tag)
        return 0;
    u64 ino = tag->ino;   /* copy before delete frees the value */
    tagged.delete(&tgid);
    emit(SG_EV_UNTAG, SG_HOOK_EXIT, tgid, 0, ino, bpf_ktime_get_ns(), 0, NULL, 0);
    return 0;
}

/* Hook B: a tagged process may only connect to allowlisted destinations. */
LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    /* `address` is the kernel copy of the user's sockaddr (a sockaddr_storage), but its BTF
     * type is the 16-byte struct sockaddr, so read it explicitly rather than cast and deref. */
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;   /* AF_UNIX, AF_UNSPEC (UDP disconnect), ...: skip before any map lookup */

    u8 addr[16] = {};
    u16 port;
    if (family == AF_INET) {
        struct sockaddr_in sin = {};
        if (addrlen < (int)sizeof(sin))
            return 0;   /* the kernel rejects it with EINVAL after us */
        bpf_probe_read_kernel(&sin, sizeof(sin), address);
        __builtin_memcpy(addr, &sin.sin_addr.s_addr, 4);
        port = sin.sin_port;
    } else {
        struct sockaddr_in6 sin6 = {};
        if (addrlen < 24)   /* SIN6_LEN_RFC2133: the shortest length the kernel accepts */
            return 0;
        bpf_probe_read_kernel(&sin6, 24, address);
        __builtin_memcpy(addr, &sin6.sin6_addr, 16);
        port = sin6.sin6_port;
    }
    return check_dest(family, addr, bpf_ntohs(port), SG_HOOK_CONNECT);
}
