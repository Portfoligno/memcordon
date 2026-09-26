// SPDX-License-Identifier: GPL-2.0
// Qualification-only CO-RE observer. This is not installed with the product.
// The loader pins exact kernel BTF, object bytes, agent build-id and uprobe
// offsets before attach. An event lost from this ring buffer fails the run.
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MC_SECCOMP_RET_ACTION_FULL 0xffff0000U
#define MC_SECCOMP_RET_DATA 0x0000ffffU

char LICENSE[] SEC("license") = "GPL";

enum mc_event_kind {
    MC_REQUEST_ENTER = 1,
    MC_REQUEST_EXIT = 2,
    MC_ALLOCATE = 3,
    MC_SECCOMP = 4,
    MC_SYSCALL_RETURN = 5,
    MC_EXEC = 6,
    MC_FORK = 7,
    MC_EXIT = 8,
    MC_REAP = 9,
    MC_NSFD_CLOSE = 10,
};

struct mc_config_v1 {
    __u64 cgroup_id;
    __u64 broker_cgroup_id;
    __u8 request_key[32];
};

struct mc_event_v1 {
    __u64 sequence;
    __u64 monotonic_ns;
    __u64 cgroup_id;
    __u64 task_start_ns;
    __u64 image_dev;
    __u64 image_inode;
    __s64 syscall_nr;
    __s64 syscall_result;
    __u32 pid;
    __u32 other_pid;
    __u32 syscall_arch;
    __u32 seccomp_action;
    __u32 kind;
    __u8 request_key[32];
    __u64 time_ns_inode;
};
_Static_assert(sizeof(struct mc_event_v1) == 128, "private probe event wire size differs");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mc_config_v1);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lost SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} next_sequence SEC(".maps");

// A child forked by the armed agent remains in scope after it is moved into
// its private cgroup. The value records its first observed start_boottime to
// reject PID reuse; the sched exit probe removes the entry.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} tracked_descendants SEC(".maps");

// raw_syscalls:sys_exit does not carry AUDIT_ARCH. The immediately preceding
// seccomp fexit supplies the kernel-owned arch/number for this exact thread;
// a missing or mismatched pair is exported as arch 0 and fails the CI join.
struct mc_syscall_identity_v1 {
    __u32 arch;
    __s64 nr;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct mc_syscall_identity_v1);
} pending_syscall SEC(".maps");

static __always_inline void record_loss(void)
{
    __u32 zero = 0;
    __u64 *counter = bpf_map_lookup_elem(&lost, &zero);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline struct mc_config_v1 *active_config(void)
{
    __u32 zero = 0;
    struct mc_config_v1 *cfg = bpf_map_lookup_elem(&config, &zero);
    if (!cfg || !cfg->cgroup_id || !cfg->broker_cgroup_id ||
        cfg->cgroup_id == cfg->broker_cgroup_id)
        return 0;
    if (bpf_get_current_cgroup_id() != cfg->cgroup_id &&
        bpf_get_current_cgroup_id() != cfg->broker_cgroup_id) {
        __u32 pid = (__u32)bpf_get_current_pid_tgid();
        __u64 *known = bpf_map_lookup_elem(&tracked_descendants, &pid);
        if (!known)
            return 0;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        __u64 start = BPF_CORE_READ(task, start_boottime);
        if (*known && *known != start)
            return 0;
        if (!*known && bpf_map_update_elem(&tracked_descendants, &pid, &start, BPF_ANY))
            record_loss();
    }
    return cfg;
}

static __always_inline void emit(__u32 kind, __u32 other_pid, __u64 dev,
                                 __u64 ino, __u32 arch, __s64 nr,
                                 __u32 action, __s64 result)
{
    struct mc_config_v1 *cfg = active_config();
    if (!cfg)
        return;
    struct mc_event_v1 *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_loss();
        return;
    }
    __builtin_memset(event, 0, sizeof(*event));
    __u32 zero = 0;
    __u64 *sequence = bpf_map_lookup_elem(&next_sequence, &zero);
    if (sequence)
        event->sequence = __sync_fetch_and_add(sequence, 1) + 1;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    event->monotonic_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->task_start_ns = BPF_CORE_READ(task, start_boottime);
    event->pid = (__u32)bpf_get_current_pid_tgid();
    event->other_pid = other_pid;
    event->image_dev = dev;
    event->image_inode = ino;
    event->syscall_arch = arch;
    event->syscall_nr = nr;
    event->seccomp_action = action;
    event->syscall_result = result;
    event->kind = kind;
    __builtin_memcpy(event->request_key, cfg->request_key, sizeof(event->request_key));
    event->time_ns_inode = BPF_CORE_READ(task, nsproxy, time_ns, ns.inum);
    bpf_ringbuf_submit(event, 0);
}

SEC("uprobe/mc_request_enter")
int BPF_UPROBE(mc_request_enter)
{
    emit(MC_REQUEST_ENTER, 0, 0, 0, 0, 0, 0, 0);
    return 0;
}

SEC("uretprobe/mc_request_exit")
int BPF_URETPROBE(mc_request_exit)
{
    emit(MC_REQUEST_EXIT, 0, 0, 0, 0, 0, 0, 0);
    return 0;
}

SEC("uprobe/mc_allocate")
int BPF_UPROBE(mc_allocate)
{
    emit(MC_ALLOCATE, 0, 0, 0, 0, 0, 0, 0);
    return 0;
}

// This fexit is mandatory. A syscall tracepoint may not observe a syscall
// suppressed by seccomp. The supported kernel's BTF must expose this exact
// function and signature; the loader rejects a different BTF digest.
SEC("fexit/seccomp_run_filters")
int BPF_PROG(mc_seccomp_decision, const struct seccomp_data *sd,
             struct seccomp_filter **match, __u32 ret)
{
    struct seccomp_data data = {};
    if (!sd || bpf_probe_read_kernel(&data, sizeof(data), sd))
        return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mc_syscall_identity_v1 identity = {
        .arch = data.arch,
        .nr = data.nr,
    };
    if (active_config() && bpf_map_update_elem(&pending_syscall, &tid, &identity, BPF_ANY))
        record_loss();
    emit(MC_SECCOMP, 0, 0, 0, data.arch, data.nr,
         ret & MC_SECCOMP_RET_ACTION_FULL, ret & MC_SECCOMP_RET_DATA);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int mc_syscall_return(struct trace_event_raw_sys_exit *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mc_syscall_identity_v1 *identity = bpf_map_lookup_elem(&pending_syscall, &tid);
    __u32 arch = identity && identity->nr == ctx->id ? identity->arch : 0;
    emit(MC_SYSCALL_RETURN, 0, 0, 0, arch, ctx->id, 0, ctx->ret);
    bpf_map_delete_elem(&pending_syscall, &tid);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int mc_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct file *file = BPF_CORE_READ(task, mm, exe_file);
    struct inode *inode = file ? BPF_CORE_READ(file, f_inode) : 0;
    __u64 number = inode ? BPF_CORE_READ(inode, i_ino) : 0;
    __u64 dev = inode ? BPF_CORE_READ(inode, i_sb, s_dev) : 0;
    emit(MC_EXEC, 0, dev, number, 0, 0, 0, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int mc_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    if (active_config()) {
        __u32 child = ctx->child_pid;
        __u64 unknown_start = 0;
        if (child && bpf_map_update_elem(&tracked_descendants, &child, &unknown_start, BPF_ANY))
            record_loss();
        emit(MC_FORK, child, 0, 0, 0, 0, 0, 0);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int mc_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    emit(MC_EXIT, 0, 0, 0, 0, 0, 0, BPF_CORE_READ(task, exit_code));
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    bpf_map_delete_elem(&tracked_descendants, &tid);
    bpf_map_delete_elem(&pending_syscall, &tid);
    return 0;
}

// release_task is the kernel's final task reaping path, not merely an exit
// notification. The victim's raw start time is carried separately from the
// current reaper task and joined by the Rust parser to a prior exact exit.
SEC("fentry/release_task")
int BPF_PROG(mc_reap, struct task_struct *victim)
{
    emit(MC_REAP, BPF_CORE_READ(victim, pid), 0, 0, 0, 0, 0,
         BPF_CORE_READ(victim, start_boottime));
    return 0;
}

// NSFS_MAGIC from linux/magic.h. This observes the kernel close operation,
// not a later scan of the process's mutable fd table.
#define MC_NSFS_MAGIC 0x6e736673U
SEC("fexit/filp_close")
int BPF_PROG(mc_nsfd_close, struct file *file, void *owner, int ret)
{
    struct inode *inode = file ? BPF_CORE_READ(file, f_inode) : 0;
    __u64 magic = inode ? BPF_CORE_READ(inode, i_sb, s_magic) : 0;
    if (magic == MC_NSFS_MAGIC)
        emit(MC_NSFD_CLOSE, 0, 0, BPF_CORE_READ(inode, i_ino), 0, 0, 0, ret);
    return 0;
}
