/*
 * syscallguard.bpf.c: all SyscallGuard eBPF hooks and maps (compiled by bcc at load time).
 * Track: K (Kernel enforcement)
 * Contract: ARCHITECTURE.md Contract 1 (sg_common.h structs, map names) and the Hooks /
 *           Decision logic sections. Map names are part of the contract: guard.py looks them up.
 *
 * TODO (M3 Connect enforcement):
 *   - check_dest() per ARCHITECTURE.md (untagged fast path = one map lookup; v4-mapped v6 -> v4)
 *   - Hook B: LSM_PROBE(socket_connect)
 * TODO (M4 Sendmsg):
 *   - Hook C: LSM_PROBE(socket_sendmsg): msg_name if set, else connected peer from sk_common
 * TODO (S1 Stretch, after M7): socket_create denies AF_PACKET/SOCK_RAW for tagged processes
 */
#include <linux/fs.h>
#include <linux/sched.h>
#include "sg_common.h"

/* Contract 1 maps. All six are declared now so guard.py can fill them from M1 on. */
BPF_HASH(protected_inodes, u64, u32, 256);
BPF_HASH(tagged, u32, struct sg_tag_info, 16384);
BPF_LPM_TRIE(allow_v4, struct sg_lpm_v4, u8, 1024);
BPF_LPM_TRIE(allow_v6, struct sg_lpm_v6, u8, 1024);
BPF_ARRAY(config, struct sg_config, 1);
BPF_RINGBUF_OUTPUT(events, 64);

/* Emit an event with no address fields. Reserved in the ring buffer, not built on the
 * 512-byte stack. Buffer full: the event is lost, never the tag change the caller made. */
static __always_inline void emit(u32 type, u32 hook, u32 tgid, u32 parent_tgid, u64 ino, u64 ts)
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
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    events.ringbuf_submit(ev, 0);
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
    emit(SG_EV_TAG, SG_HOOK_FILE_OPEN, tgid, 0, ino, now);
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
    emit(SG_EV_TAG_INHERIT, SG_HOOK_FORK, child_tgid, parent_tgid, tag.ino, now);
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
    emit(SG_EV_UNTAG, SG_HOOK_EXIT, tgid, 0, ino, bpf_ktime_get_ns());
    return 0;
}
