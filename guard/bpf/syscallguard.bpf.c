/*
 * syscallguard.bpf.c: all SyscallGuard eBPF hooks and maps (compiled by bcc at load time).
 * Track: K (Kernel enforcement)
 * Contract: ARCHITECTURE.md Contract 1 (sg_common.h structs, map names) and the Hooks /
 *           Decision logic sections. Map names are part of the contract: guard.py looks them up.
 *
 * TODO (M2 Inheritance & cleanup):
 *   - Hook D: RAW_TRACEPOINT_PROBE(sched_process_fork): inherit tag to new processes, emit TAG_INHERIT
 *   - Hook E: TRACEPOINT_PROBE(sched, sched_process_exit): leader exit -> delete tag, emit UNTAG
 * TODO (M3 Connect enforcement):
 *   - check_dest() per ARCHITECTURE.md (untagged fast path = one map lookup; v4-mapped v6 -> v4)
 *   - Hook B: LSM_PROBE(socket_connect)
 * TODO (M4 Sendmsg):
 *   - Hook C: LSM_PROBE(socket_sendmsg): msg_name if set, else connected peer from sk_common
 * TODO (S1 Stretch, after M7): socket_create denies AF_PACKET/SOCK_RAW for tagged processes
 */
#include <linux/fs.h>
#include "sg_common.h"

/* Contract 1 maps. All six are declared now so guard.py can fill them from M1 on. */
BPF_HASH(protected_inodes, u64, u32, 256);
BPF_HASH(tagged, u32, struct sg_tag_info, 16384);
BPF_LPM_TRIE(allow_v4, struct sg_lpm_v4, u8, 1024);
BPF_LPM_TRIE(allow_v6, struct sg_lpm_v6, u8, 1024);
BPF_ARRAY(config, struct sg_config, 1);
BPF_RINGBUF_OUTPUT(events, 64);

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

    /* Reserve in the ring buffer instead of building the event on the 512-byte stack. */
    struct sg_event *ev = events.ringbuf_reserve(sizeof(struct sg_event));
    if (!ev)
        return 0;   /* buffer full: lose the event, never the tag */
    __builtin_memset(ev, 0, sizeof(*ev));
    ev->ts_ns = now;
    ev->ino = ino;
    ev->type = SG_EV_TAG;
    ev->hook = SG_HOOK_FILE_OPEN;
    ev->tgid = tgid;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    events.ringbuf_submit(ev, 0);
    return 0;
}
