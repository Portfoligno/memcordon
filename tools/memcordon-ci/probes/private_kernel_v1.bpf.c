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
    MC_UNFILTERED_SYSCALL_ENTRY = 11,
    MC_INSTALLED_FILTER_INSTRUCTION = 12,
    MC_FILTER_IDENTITY = 13,
    MC_FILTER_PROGRAM_DESCRIPTOR = 14,
    MC_HOST_SYSCTL_PIN = 15,
    MC_HOST_SYSCTL_WRITE = 16,
    MC_REUSE_SYSCALL_ENTRY = 17,
    MC_REUSE_PATH_OPERANDS = 18,
    MC_REUSE_VFS_OBJECTS = 19,
};

struct mc_config_v1 {
    __u64 cgroup_id;
    __u64 broker_cgroup_id;
    __u8 request_key[32];
    __u32 observer_tgid;
    __u32 capture_enabled;
    __u32 filter_evidence_enabled;
    __u32 host_evidence_enabled;
    __u32 host_loader_tgid;
    __u64 host_sysctl_dev[4];
    __u64 host_sysctl_ino[4];
    __u32 reuse_evidence_enabled;
    __u64 reuse_directory_dev, reuse_directory_ino;
    __u64 reuse_marker_dev, reuse_marker_ino;
    __u64 reuse_record_dev, reuse_record_ino;
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
    __u64 syscall_occurrence;
    __u64 args[6];
    __u32 tgid;
    __u32 reserved;
};
_Static_assert(sizeof(struct mc_event_v1) == 192, "private probe event wire size differs");

// Explicit feature bit8: native bind/connect entries use the existing typed
// operation union (otherwise executable/file object identity) for checked
// Linux sockaddr_in operands. Return events retain ordinary object fields.
struct mc_sockaddr_in_v1 { __u16 family; __u16 port_be; __u32 address; __u8 zero[8]; };
_Static_assert(sizeof(struct mc_sockaddr_in_v1)==16,"native IPv4 sockaddr size differs");

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
// reject PID reuse; exit retains a tombstone until release_task observes reap.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} tracked_descendants SEC(".maps");

// Persistent daemon owners are admitted only between the exact trusted
// request/allocate and request-exit markers. Owned forks have their own
// lifetime so an idle daemon read cannot become an unfinished interval call.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} marker_lifecycle_owners SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} owned_fork_lifecycle SEC(".maps");

// raw_syscalls:sys_exit does not carry AUDIT_ARCH. The immediately preceding
// seccomp fexit supplies the kernel-owned arch/number for this exact thread;
// a missing or mismatched pair is exported as arch 0 and fails the CI join.
struct mc_syscall_identity_v1 {
    __u32 arch;
    __s64 nr;
    __u64 occurrence;
    __u64 args[6];
    __u32 unfiltered;
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

// Match userspace stat.st_dev, not the kernel's internal MAJOR/MINOR packing.
static __always_inline __u64 stat_device(__u32 dev)
{
    __u32 major = dev >> 20;
    __u32 minor = dev & ((1U << 20) - 1);
    return (minor & 0xffU) | ((__u64)major << 8) | ((__u64)(minor & ~0xffU) << 12);
}

static __always_inline struct mc_config_v1 *active_config(void)
{
    __u32 zero = 0;
    struct mc_config_v1 *cfg = bpf_map_lookup_elem(&config, &zero);
    if (!cfg || !cfg->capture_enabled || !cfg->cgroup_id || !cfg->broker_cgroup_id ||
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

static __always_inline void emit_scoped(struct mc_config_v1 *cfg, __u32 kind, __u32 other_pid, __u64 dev,
                                 __u64 ino, __u32 arch, __s64 nr,
                                 __u32 action, __s64 result)
{
    if (!cfg || !cfg->capture_enabled)
        return;
    struct mc_event_v1 *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_loss();
        return;
    }
    __builtin_memset(event, 0, sizeof(*event));
    // The loader assigns sequence in ring reservation/consumption order.
    // Cross-CPU atomic counter order is not ring reservation order.
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    event->monotonic_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->task_start_ns = BPF_CORE_READ(task, start_boottime);
    event->pid = (__u32)bpf_get_current_pid_tgid();
    event->tgid = bpf_get_current_pid_tgid() >> 32;
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
    if (kind == MC_SECCOMP || kind == MC_SYSCALL_RETURN || kind == MC_UNFILTERED_SYSCALL_ENTRY || kind == MC_REUSE_SYSCALL_ENTRY ||
        kind == MC_INSTALLED_FILTER_INSTRUCTION || kind == MC_FILTER_PROGRAM_DESCRIPTOR ||
        (kind == MC_FILTER_IDENTITY && arch)) {
        __u32 tid = event->pid;
        struct mc_syscall_identity_v1 *identity = bpf_map_lookup_elem(&pending_syscall, &tid);
        if (identity) {
            event->syscall_occurrence = identity->occurrence;
            __builtin_memcpy(event->args, identity->args, sizeof(event->args));
        } else {
            record_loss();
        }
    }
    bpf_ringbuf_submit(event, 0);
}

static __always_inline void emit(__u32 kind, __u32 other_pid, __u64 dev,
                                 __u64 ino, __u32 arch, __s64 nr,
                                 __u32 action, __s64 result)
{
    emit_scoped(active_config(), kind, other_pid, dev, ino, arch, nr, action, result);
}

// Feature64 is a closed directory-relative recovery protocol, never a
// synthetic ALLOW or an inference from a userspace error label.
#define MC_REUSE_NAME_SLOT (sizeof(((struct mc_event_v1 *)0)->args) / 2)
static __always_inline int reuse_role(__u32 arch, __s64 nr)
{
    if ((arch==0xc000003e && nr==257) || (arch==0xc00000b7 && nr==56)) return 1;
    if ((arch==0xc000003e && nr==263) || (arch==0xc00000b7 && nr==35)) return 2;
    if ((arch==0xc000003e && nr==316) || (arch==0xc00000b7 && nr==276)) return 3;
    return 0;
}
static __always_inline int reuse_inode(struct inode *inode,__u64 *dev,__u64 *ino)
{
    __u32 rawdev=0;
    if (!inode || BPF_CORE_READ_INTO(ino,inode,i_ino) || BPF_CORE_READ_INTO(&rawdev,inode,i_sb,s_dev)) {record_loss();return -1;}
    *dev=stat_device(rawdev);return 0;
}
static __always_inline int reuse_directory(struct task_struct *task,__u64 fd,__u64 *dev,__u64 *ino)
{
    struct fdtable *table=0;struct file **descriptors=0;struct file *file=0;struct inode *inode=0;__u32 capacity=0;
    if (BPF_CORE_READ_INTO(&table,task,files,fdt) || !table || BPF_CORE_READ_INTO(&capacity,table,max_fds) || BPF_CORE_READ_INTO(&descriptors,table,fd)) {record_loss();return -1;}
    if (fd>=capacity) return 0;
    if (bpf_probe_read_kernel(&file,sizeof(file),descriptors+fd) || !file || BPF_CORE_READ_INTO(&inode,file,f_inode)) {record_loss();return -1;}
    if (reuse_inode(inode,dev,ino)) return -1;return 1;
}
static __always_inline int reuse_name(const void *pointer,char *bytes,int kernel,const char *expected,__u32 length)
{
    int read=kernel?bpf_probe_read_kernel_str(bytes,MC_REUSE_NAME_SLOT,pointer):bpf_probe_read_user_str(bytes,MC_REUSE_NAME_SLOT,pointer);
    if (read<0) {record_loss();return -1;}
    if (read!=(int)length) return 0;
    for (__u32 index=0;index<MC_REUSE_NAME_SLOT;index++) {if(index<length && bytes[index]!=expected[index]) return 0;}
    return 1;
}
static __always_inline void reuse_metadata(struct mc_config_v1 *cfg,__u32 kind,__u32 role,
    struct mc_syscall_identity_v1 *identity,__u64 dev,__u64 ino,__s64 result,const __u64 *operands)
{
    struct mc_event_v1 *event=bpf_ringbuf_reserve(&events,sizeof(*event),0);
    if(!event){record_loss();return;}__builtin_memset(event,0,sizeof(*event));
    struct task_struct *task=(struct task_struct*)bpf_get_current_task_btf();
    event->monotonic_ns=bpf_ktime_get_ns();event->cgroup_id=bpf_get_current_cgroup_id();
    if(BPF_CORE_READ_INTO(&event->task_start_ns,task,start_boottime) || BPF_CORE_READ_INTO(&event->time_ns_inode,task,nsproxy,time_ns,ns.inum)){bpf_ringbuf_discard(event,0);record_loss();return;}
    event->pid=(__u32)bpf_get_current_pid_tgid();event->tgid=bpf_get_current_pid_tgid()>>32;
    event->other_pid=role;event->kind=kind;event->image_dev=dev;event->image_inode=ino;
    event->syscall_arch=identity->arch;event->syscall_nr=identity->nr;event->syscall_occurrence=identity->occurrence;event->syscall_result=result;
    __builtin_memcpy(event->args,operands,sizeof(event->args));__builtin_memcpy(event->request_key,cfg->request_key,sizeof(event->request_key));bpf_ringbuf_submit(event,0);
}
static __always_inline int checked_reuse_entry(struct mc_config_v1 *cfg,struct task_struct *task,
    struct mc_syscall_identity_v1 *identity,__u64 *dev,__u64 *ino,__u64 *names)
{
    int role=reuse_role(identity->arch,identity->nr);
    if(!cfg->reuse_evidence_enabled || !role) return 0;
    int found=reuse_directory(task,identity->args[0],dev,ino);
    if(found<=0)return found;
    if(*dev!=cfg->reuse_directory_dev || *ino!=cfg->reuse_directory_ino)return 0;
    const char temporary[]="attempt.json.new";const char canonical[]="attempt.json";
    int named=reuse_name((void*)identity->args[1],(char*)names,0,temporary,sizeof(temporary));
    if(named<=0)return named;
    if(role==3){__u64 otherdev=0,otherino=0;
        if(reuse_directory(task,identity->args[2],&otherdev,&otherino)!=1 || otherdev!=*dev || otherino!=*ino){record_loss();return -1;}
        if(reuse_name((void*)identity->args[3],(char*)names+MC_REUSE_NAME_SLOT,0,canonical,sizeof(canonical))!=1){record_loss();return -1;}
    }
    return role;
}
struct renamedata___mc_reuse {struct inode *old_dir;struct dentry *old_dentry;struct inode *new_dir;struct dentry *new_dentry;unsigned int flags;} __attribute__((preserve_access_index));
SEC("fentry/vfs_unlink")
int BPF_PROG(mc_reuse_unlink_objects,struct mnt_idmap *idmap,struct inode *directory,struct dentry *dentry,struct inode **delegated)
{
    __u32 zero=0,tid=(__u32)bpf_get_current_pid_tgid();struct mc_config_v1 *cfg=bpf_map_lookup_elem(&config,&zero);struct mc_syscall_identity_v1 *identity=bpf_map_lookup_elem(&pending_syscall,&tid);
    if(!cfg || !cfg->capture_enabled || !cfg->reuse_evidence_enabled || !identity || reuse_role(identity->arch,identity->nr)!=2)return 0;
    __u64 dev=0,ino=0,objects[6]={0};struct inode *file=0;const unsigned char *name=0;char bytes[MC_REUSE_NAME_SLOT]={0};const char expected[]="attempt.json.new";
    if(reuse_inode(directory,&dev,&ino) || BPF_CORE_READ_INTO(&file,dentry,d_inode) || BPF_CORE_READ_INTO(&name,dentry,d_name.name) || reuse_name(name,bytes,1,expected,sizeof(expected))!=1 || reuse_inode(file,&objects[0],&objects[1])){record_loss();return 0;}
    if(dev!=cfg->reuse_directory_dev || ino!=cfg->reuse_directory_ino || objects[0]!=cfg->reuse_marker_dev || objects[1]!=cfg->reuse_marker_ino){record_loss();return 0;}
    reuse_metadata(cfg,MC_REUSE_VFS_OBJECTS,2,identity,dev,ino,0,objects);return 0;
}
SEC("fentry/vfs_rename")
int BPF_PROG(mc_reuse_rename_objects,struct renamedata___mc_reuse *rename)
{
    __u32 zero=0,tid=(__u32)bpf_get_current_pid_tgid();struct mc_config_v1 *cfg=bpf_map_lookup_elem(&config,&zero);struct mc_syscall_identity_v1 *identity=bpf_map_lookup_elem(&pending_syscall,&tid);
    if(!cfg || !cfg->capture_enabled || !cfg->reuse_evidence_enabled || !identity || reuse_role(identity->arch,identity->nr)!=3)return 0;
    if(!bpf_core_field_exists(struct renamedata___mc_reuse,old_dir) || !bpf_core_field_exists(struct renamedata___mc_reuse,new_dentry)){record_loss();return 0;}
    struct inode *old_dir=0,*new_dir=0,*source=0,*target=0;struct dentry *old_dentry=0,*new_dentry=0;const unsigned char *old_name=0,*new_name=0;char old_bytes[MC_REUSE_NAME_SLOT]={0},new_bytes[MC_REUSE_NAME_SLOT]={0};__u64 dev=0,ino=0,objects[6]={0};
    const char temporary[]="attempt.json.new";const char canonical[]="attempt.json";
    if(BPF_CORE_READ_INTO(&old_dir,rename,old_dir) || BPF_CORE_READ_INTO(&new_dir,rename,new_dir) || BPF_CORE_READ_INTO(&old_dentry,rename,old_dentry) || BPF_CORE_READ_INTO(&new_dentry,rename,new_dentry) || reuse_inode(old_dir,&dev,&ino) || reuse_inode(new_dir,&objects[4],&objects[5]) || BPF_CORE_READ_INTO(&source,old_dentry,d_inode) || BPF_CORE_READ_INTO(&target,new_dentry,d_inode) || reuse_inode(source,&objects[0],&objects[1]) || reuse_inode(target,&objects[2],&objects[3]) || BPF_CORE_READ_INTO(&old_name,old_dentry,d_name.name) || BPF_CORE_READ_INTO(&new_name,new_dentry,d_name.name) || reuse_name(old_name,old_bytes,1,temporary,sizeof(temporary))!=1 || reuse_name(new_name,new_bytes,1,canonical,sizeof(canonical))!=1){record_loss();return 0;}
    if(dev!=cfg->reuse_directory_dev || ino!=cfg->reuse_directory_ino || objects[4]!=dev || objects[5]!=ino || objects[2]!=cfg->reuse_record_dev || objects[3]!=cfg->reuse_record_ino || (objects[0]==cfg->reuse_marker_dev && objects[1]==cfg->reuse_marker_ino)){record_loss();return 0;}
    reuse_metadata(cfg,MC_REUSE_VFS_OBJECTS,3,identity,dev,ino,0,objects);return 0;
}

// Explicit feature32. The four initial file identities are independently
// held by the observer. The loader performs actual reads before arm; kernel
// table/data identity then catches aliases opened via another procfs mount.
// Flavor names preserve optional CO-RE relocations for legacy captures.
struct ctl_table___mc_host { void *data; } __attribute__((preserve_access_index));
struct proc_inode___mc_host {
    struct inode vfs_inode;
    struct ctl_table___mc_host *sysctl_entry;
} __attribute__((preserve_access_index));
struct mc_host_slot_v1 {
    __u64 dev, ino, table, data, initialized_ns, netns_inode;
};
struct mc_host_pending_v1 {
    __u64 dev, ino, table, data, entry_ns;
    __u32 slot;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, struct mc_host_slot_v1);
} host_slots SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct mc_host_pending_v1);
} host_reads SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct mc_host_pending_v1);
} host_writes SEC(".maps");

static __always_inline int host_object(struct kiocb *iocb, struct mc_host_pending_v1 *object)
{
    if (!iocb || !bpf_core_field_exists(struct proc_inode___mc_host, sysctl_entry) ||
        !bpf_core_field_exists(struct ctl_table___mc_host, data)) return -1;
    struct inode *inode = 0;
    if (BPF_CORE_READ_INTO(&inode, iocb, ki_filp, f_inode) || !inode) return -1;
    struct proc_inode___mc_host *proc = (void *)inode -
        bpf_core_field_offset(struct proc_inode___mc_host, vfs_inode);
    struct ctl_table___mc_host *table = 0;
    __u32 device = 0;
    if (BPF_CORE_READ_INTO(&table, proc, sysctl_entry) || !table ||
        BPF_CORE_READ_INTO(&device, inode, i_sb, s_dev) ||
        BPF_CORE_READ_INTO(&object->ino, inode, i_ino) ||
        BPF_CORE_READ_INTO(&object->data, table, data)) return -1;
    object->dev = stat_device(device);
    object->table = (__u64)table;
    object->entry_ns = bpf_ktime_get_ns();
    // NULL data is valid for some unrelated custom sysctl handlers. It cannot
    // alias any of the four required non-NULL bootstrap identities.
    return object->dev && object->ino ? 0 : -1;
}

static __always_inline void host_emit(struct mc_config_v1 *cfg, __u32 kind, __u32 slot,
                                     struct mc_host_slot_v1 *pin,
                                     struct mc_host_pending_v1 *object, __s64 result)
{
    // Host writes deliberately remain armed across the product enable/disable
    // transitions. The loader excludes only completed pre-arm host writes.
    struct mc_event_v1 *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) { record_loss(); return; }
    __builtin_memset(event, 0, sizeof(*event));
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    event->monotonic_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->task_start_ns = BPF_CORE_READ(task, start_boottime);
    event->pid = (__u32)bpf_get_current_pid_tgid();
    event->tgid = bpf_get_current_pid_tgid() >> 32;
    event->time_ns_inode = BPF_CORE_READ(task, nsproxy, time_ns, ns.inum);
    event->other_pid = slot + 1;
    event->image_dev = object->dev;
    event->image_inode = object->ino;
    event->syscall_result = result;
    event->kind = kind;
    event->args[0] = object->table;
    event->args[1] = object->data;
    event->args[2] = pin->initialized_ns;
    event->args[3] = pin->netns_inode;
    event->args[4] = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    event->args[5] = object->entry_ns;
    __builtin_memcpy(event->request_key, cfg->request_key, sizeof(event->request_key));
    bpf_ringbuf_submit(event, 0);
}

SEC("fentry/proc_sys_read")
int BPF_PROG(mc_host_sysctl_read_enter, struct kiocb *iocb, struct iov_iter *iter)
{
    __u32 zero = 0, tid = (__u32)bpf_get_current_pid_tgid();
    struct mc_config_v1 *cfg = bpf_map_lookup_elem(&config, &zero);
    if (!cfg || !cfg->host_evidence_enabled ||
        bpf_get_current_pid_tgid() >> 32 != cfg->host_loader_tgid) return 0;
    struct mc_host_pending_v1 object = {0};
    if (host_object(iocb, &object)) { record_loss(); return 0; }
    for (__u32 slot = 0; slot < 4; slot++) {
        if (cfg->host_sysctl_dev[slot] != object.dev || cfg->host_sysctl_ino[slot] != object.ino) continue;
        object.slot = slot;
        if (bpf_map_update_elem(&host_reads, &tid, &object, BPF_NOEXIST)) record_loss();
        break;
    }
    return 0;
}

SEC("fexit/proc_sys_read")
int BPF_PROG(mc_host_sysctl_read_exit, struct kiocb *iocb, struct iov_iter *iter, long result)
{
    __u32 zero = 0, tid = (__u32)bpf_get_current_pid_tgid();
    struct mc_config_v1 *cfg = bpf_map_lookup_elem(&config, &zero);
    struct mc_host_pending_v1 *pending = bpf_map_lookup_elem(&host_reads, &tid);
    if (!cfg || !cfg->host_evidence_enabled || !pending) return 0;
    struct mc_host_pending_v1 object = *pending;
    bpf_map_delete_elem(&host_reads, &tid);
    if (result <= 0 || object.slot >= 4 || !object.data) { record_loss(); return 0; }
    struct mc_host_slot_v1 *existing = bpf_map_lookup_elem(&host_slots, &object.slot);
    if (!existing) { record_loss(); return 0; }
    if (!cfg->capture_enabled) {
        if (existing->initialized_ns) { record_loss(); return 0; }
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        struct mc_host_slot_v1 pin = { .dev=object.dev, .ino=object.ino,
            .table=object.table, .data=object.data, .initialized_ns=bpf_ktime_get_ns(),
            .netns_inode=BPF_CORE_READ(task, nsproxy, net_ns, ns.inum) };
        if (!pin.initialized_ns || !pin.netns_inode || bpf_map_update_elem(&host_slots, &object.slot, &pin, BPF_ANY)) record_loss();
    } else {
        if (existing->dev!=object.dev || existing->ino!=object.ino || existing->table!=object.table || existing->data!=object.data) { record_loss(); return 0; }
        host_emit(cfg, MC_HOST_SYSCTL_PIN, object.slot, existing, &object, result);
    }
    return 0;
}

SEC("fentry/proc_sys_write")
int BPF_PROG(mc_host_sysctl_write_enter, struct kiocb *iocb, struct iov_iter *iter)
{
    __u32 zero = 0, tid = (__u32)bpf_get_current_pid_tgid();
    struct mc_config_v1 *cfg = bpf_map_lookup_elem(&config, &zero);
    if (!cfg || !cfg->host_evidence_enabled) return 0;
    struct mc_host_pending_v1 object = {0};
    if (host_object(iocb, &object) || bpf_map_update_elem(&host_writes, &tid, &object, BPF_NOEXIST)) record_loss();
    return 0;
}

SEC("fexit/proc_sys_write")
int BPF_PROG(mc_host_sysctl_write_exit, struct kiocb *iocb, struct iov_iter *iter, long result)
{
    __u32 zero = 0, tid = (__u32)bpf_get_current_pid_tgid();
    struct mc_config_v1 *cfg = bpf_map_lookup_elem(&config, &zero);
    if (!cfg || !cfg->host_evidence_enabled) return 0;
    struct mc_host_pending_v1 *pending = bpf_map_lookup_elem(&host_writes, &tid);
    if (!pending) { record_loss(); return 0; }
    struct mc_host_pending_v1 object = *pending;
    bpf_map_delete_elem(&host_writes, &tid);
    if (result <= 0) return 0;
    for (__u32 slot=0; slot<4; slot++) {
        struct mc_host_slot_v1 *pin = bpf_map_lookup_elem(&host_slots, &slot);
        if (pin && pin->initialized_ns && pin->data==object.data) {
            host_emit(cfg, MC_HOST_SYSCTL_WRITE, slot, pin, &object, result);
            break;
        }
    }
    return 0;
}

// Feature16 is explicitly enabled by the protected qualification controller.
// Instructions come from the kernel's retained original program AFTER actual
// successful installation; a userspace pointer/buffer is never that proof.
// CO-RE flavors keep optional CHECKPOINT_RESTORE fields out of the required
// generated header. A legacy observer does not require orig_prog support;
// feature16 fails closed if the real kernel lacks the retained original.
struct sock_fprog_kern___mc { __u16 len; struct sock_filter *filter; } __attribute__((preserve_access_index));
struct bpf_prog___mc { struct sock_fprog_kern___mc *orig_prog; } __attribute__((preserve_access_index));
struct seccomp_filter___mc { struct seccomp_filter___mc *prev; struct bpf_prog___mc *prog; } __attribute__((preserve_access_index));
// Linux v6.12 include/linux/seccomp_types.h and kernel/seccomp.c define
// these fields. These are CO-RE type flavors, not substitute kernel headers:
// each required field is relocated against the authenticated target BTF and
// checked for existence. CONFIG_SECCOMP=n development headers may omit them;
// a target without them cannot supply mode/filter evidence and fails closed.
struct seccomp___mc {
    int mode;
    atomic_t filter_count;
    struct seccomp_filter___mc *filter;
} __attribute__((preserve_access_index));
struct task_struct___mc { struct seccomp___mc seccomp; } __attribute__((preserve_access_index));
struct seccomp_filter;
static __always_inline int checked_seccomp_mode(struct task_struct *task,int *mode)
{
    struct task_struct___mc *subject=(void *)task;
    if (!bpf_core_field_exists(subject->seccomp.mode)) return -1;
    return BPF_CORE_READ_INTO(mode,subject,seccomp.mode);
}
static __always_inline int checked_seccomp_head(struct task_struct *task,struct seccomp_filter___mc **head)
{
    struct task_struct___mc *subject=(void *)task;
    if (!bpf_core_field_exists(subject->seccomp.filter)) return -1;
    return BPF_CORE_READ_INTO(head,subject,seccomp.filter);
}
static __always_inline int checked_filter_count(struct task_struct *task,__u32 *count)
{
    struct task_struct___mc *subject=(void *)task;
    if (!bpf_core_field_exists(subject->seccomp.filter_count.counter)) return -1;
    return BPF_CORE_READ_INTO(count,subject,seccomp.filter_count.counter);
}
static __always_inline int is_filter_install(__u32 arch,__s64 nr,const __u64 args[6])
{
    return (((arch==0xc000003eU && nr==317)||(arch==0xc00000b7U && nr==277)) && args[0]==1 && !(args[1]&~1ULL) && args[2]) ||
        (((arch==0xc000003eU && nr==157)||(arch==0xc00000b7U && nr==167)) && args[0]==22 && args[1]==2 && args[2]);
}
static __always_inline void filter_identity(struct mc_config_v1 *cfg,struct task_struct *subject,__u32 child,__u32 arch,__s64 nr,__u32 role)
{
    if (!cfg || !cfg->filter_evidence_enabled) return;
    int mode=0; struct seccomp_filter___mc *head=0,*previous=0;
    if (checked_seccomp_mode(subject,&mode)) {record_loss();return;}
    if (mode!=2) return;
    if (checked_seccomp_head(subject,&head) || !head ||
        BPF_CORE_READ_INTO(&previous,head,prev)) {record_loss();return;}
    __u32 count=child;
    if (role==1 && (checked_filter_count(subject,&count) || !count)) {record_loss();return;}
    emit_scoped(cfg,MC_FILTER_IDENTITY,count,(__u64)head,(__u64)previous,arch,nr,role,mode);
}
static __always_inline void checked_filter_descriptor(struct mc_config_v1 *cfg,struct mc_syscall_identity_v1 *identity)
{
    if (!cfg || !cfg->filter_evidence_enabled || !is_filter_install(identity->arch,identity->nr,identity->args)) return;
    struct {__u16 length;__u8 padding[6];__u64 pointer;} descriptor={};
    __u64 address=identity->args[2];
    if (!address || bpf_probe_read_user(&descriptor,sizeof(descriptor),(const void *)address) ||
        !descriptor.length || descriptor.length>4096 || !descriptor.pointer) {record_loss();return;}
    struct task_struct *task=(struct task_struct *)bpf_get_current_task_btf();
    __u32 before=0;
    if (checked_filter_count(task,&before)) {record_loss();return;}
    emit_scoped(cfg,MC_FILTER_PROGRAM_DESCRIPTOR,before,descriptor.length,descriptor.pointer,identity->arch,identity->nr,0,0);
}
static __always_inline void installed_filter_program(struct mc_config_v1 *cfg,struct task_struct *task,struct mc_syscall_identity_v1 *identity)
{
    if (!cfg || !cfg->filter_evidence_enabled || !is_filter_install(identity->arch,identity->nr,identity->args)) return;
    struct seccomp_filter___mc *head=0; struct bpf_prog___mc *program=0; struct sock_fprog_kern___mc *original=0;struct sock_filter *instructions=0;
    __u16 count=0;
    if (checked_seccomp_head(task,&head) || !head ||
        BPF_CORE_READ_INTO(&program,head,prog) || !program ||
        !bpf_core_field_exists(program->orig_prog) ||
        BPF_CORE_READ_INTO(&original,program,orig_prog) || !original ||
        BPF_CORE_READ_INTO(&count,original,len) || !count || count>4096 ||
        BPF_CORE_READ_INTO(&instructions,original,filter) || !instructions) {record_loss();return;}
    for (__u32 index=0;index<4096;index++) {
        if (index>=count) break;
        struct sock_filter instruction={};
        if (bpf_probe_read_kernel(&instruction,sizeof(instruction),instructions+index)) {record_loss();return;}
        __u64 packed=(__u64)instruction.code|((__u64)instruction.jt<<16)|((__u64)instruction.jf<<24)|((__u64)instruction.k<<32);
        emit_scoped(cfg,MC_INSTALLED_FILTER_INSTRUCTION,count,(__u64)head,packed,identity->arch,identity->nr,0,index);
    }
    filter_identity(cfg,task,0,identity->arch,identity->nr,1);
}

SEC("uprobe/mc_request_enter")
int BPF_UPROBE(mc_request_enter)
{
    struct mc_config_v1 *cfg = active_config();
    if (cfg && (__u32)bpf_get_current_uid_gid() == 0) {
        __u32 tid = (__u32)bpf_get_current_pid_tgid();
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        __u64 start = 0;
        if (BPF_CORE_READ_INTO(&start,task,start_boottime) || !start ||
            bpf_map_update_elem(&tracked_descendants,&tid,&start,BPF_ANY) ||
            bpf_map_update_elem(&marker_lifecycle_owners,&tid,&start,BPF_ANY)) record_loss();
    }
    emit(MC_REQUEST_ENTER, 0, 0, 0, 0, 0, 0, 0);
    return 0;
}

SEC("uretprobe/mc_request_exit")
int BPF_URETPROBE(mc_request_exit)
{
    emit(MC_REQUEST_EXIT, 0, 0, 0, 0, 0, 0, 0);
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&marker_lifecycle_owners,&tid);
    return 0;
}

SEC("uprobe/mc_allocate")
int BPF_UPROBE(mc_allocate)
{
    struct mc_config_v1 *cfg = active_config();
    if (cfg && (__u32)bpf_get_current_uid_gid() == 0) {
        __u32 tid = (__u32)bpf_get_current_pid_tgid();
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        __u64 start = 0;
        if (BPF_CORE_READ_INTO(&start,task,start_boottime) || !start ||
            bpf_map_update_elem(&tracked_descendants,&tid,&start,BPF_ANY) ||
            bpf_map_update_elem(&marker_lifecycle_owners,&tid,&start,BPF_ANY)) record_loss();
    }
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
    if (!active_config())
        return 0;
    struct seccomp_data data = {};
    if (!sd || bpf_probe_read_kernel(&data, sizeof(data), sd)) {
        record_loss();
        return 0;
    }
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mc_syscall_identity_v1 identity = {
        .arch = data.arch,
        .nr = data.nr,
    };
    __u32 zero = 0;
    __u64 *next = bpf_map_lookup_elem(&next_sequence, &zero);
    if (!next) {
        record_loss();
        return 0;
    }
    identity.occurrence = __sync_fetch_and_add(next, 1) + 1;
    __builtin_memcpy(identity.args, data.args, sizeof(identity.args));
    if (bpf_map_update_elem(&pending_syscall, &tid, &identity, BPF_NOEXIST))
        record_loss();
    struct mc_config_v1 *cfg=active_config();
    filter_identity(cfg,(struct task_struct *)bpf_get_current_task_btf(),0,data.arch,data.nr,2);
    __u64 operand_dev=0,operand_ino=0;
    if ((data.arch==0xc000003eU && (data.nr==49 || data.nr==42)) ||
        (data.arch==0xc00000b7U && (data.nr==200 || data.nr==203))) {
        struct mc_sockaddr_in_v1 address={};
        if (data.args[2]!=sizeof(address) || !data.args[1] ||
            bpf_probe_read_user(&address,sizeof(address),(const void *)data.args[1]) || address.family!=2) {
            record_loss();
            return 0;
        }
        __u16 port=(address.port_be>>8)|(address.port_be<<8);
        operand_dev=((__u64)address.family<<32)|sizeof(address);
        operand_ino=((__u64)address.address<<32)|port;
    }
    emit(MC_SECCOMP, 0, operand_dev, operand_ino, data.arch, data.nr,
         ret & MC_SECCOMP_RET_ACTION_FULL, ret & MC_SECCOMP_RET_DATA);
    checked_filter_descriptor(cfg,&identity);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int mc_syscall_return(struct trace_event_raw_sys_exit *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mc_syscall_identity_v1 *identity = bpf_map_lookup_elem(&pending_syscall, &tid);
    if (!identity) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        // An explicitly unfiltered helper has no seccomp decision to pair.
        // It cannot satisfy a known-action control; retain filtered missing
        // pairs as loss rather than silently assigning ALLOW.
        int mode=-1;
        if (checked_seccomp_mode(task,&mode)) {record_loss();return 0;}
        if (mode == 0)
            return 0;
    }
    __u32 arch = identity && identity->nr == ctx->id ? identity->arch : 0;
    struct mc_config_v1 *cfg = active_config();
    if (identity && identity->unfiltered) {
        __u32 zero = 0;
        struct mc_config_v1 *observer = bpf_map_lookup_elem(&config, &zero);
        if (observer && observer->observer_tgid == bpf_get_current_pid_tgid() >> 32)
            cfg = observer;
    }
    emit_scoped(cfg, MC_SYSCALL_RETURN, 0, 0, 0, arch, ctx->id, 0, ctx->ret);
    if (identity && ctx->ret==0) installed_filter_program(cfg,(struct task_struct *)bpf_get_current_task_btf(),identity);
    bpf_map_delete_elem(&pending_syscall, &tid);
    return 0;
}

// Versioned auxiliary lifecycle entry: this is never a seccomp ALLOW claim.
// Only exact observer/owned-fork lineage and reviewed native durable/control
// syscall numbers are retained. Filtered tasks remain on the decision path.
SEC("tracepoint/raw_syscalls/sys_enter")
int mc_unfiltered_syscall_entry(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    __u32 zero = 0;
    struct mc_config_v1 *cfg = bpf_map_lookup_elem(&config, &zero);
    if (!cfg || !cfg->capture_enabled) return 0;
    int observer_direct = cfg->observer_tgid == bpf_get_current_pid_tgid() >> 32;
    if (!observer_direct) {
        __u32 tid = (__u32)bpf_get_current_pid_tgid();
        __u64 *forked = bpf_map_lookup_elem(&owned_fork_lifecycle,&tid);
        __u64 *owner = bpf_map_lookup_elem(&marker_lifecycle_owners,&tid);
        __u64 start = 0;
        if ((!forked && !owner) || !active_config()) return 0;
        if (BPF_CORE_READ_INTO(&start,task,start_boottime)) {record_loss();return 0;}
        if ((!forked || *forked!=start) && (!owner || *owner!=start)) return 0;
    }
    int mode = -1;
    if (checked_seccomp_mode(task,&mode)) { record_loss(); return 0; }
    if (mode != 0) return 0;
#if defined(__TARGET_ARCH_x86)
    __u32 arch = 0xc000003e;
    // Observer drain threads block until after detach. They are not product
    // lifecycle reads/writes; admitting them would create a cut capture.
    if (observer_direct && (ctx->id == 0 || ctx->id == 1 ||
        ((ctx->id == 62 || ctx->id == 424) && ctx->args[1] == 2) ||
        (ctx->id == 234 && ctx->args[2] == 2))) return 0;
    if (ctx->id != 0 && ctx->id != 1 && ctx->id != 3 && ctx->id != 44 &&
        ctx->id != 46 && ctx->id != 47 && ctx->id != 48 && ctx->id != 62 &&
        ctx->id != 74 && ctx->id != 75 && ctx->id != 234 && ctx->id != 424 &&
        !(cfg->filter_evidence_enabled && (ctx->id==317 || (ctx->id==157 && ctx->args[0]==22 && ctx->args[1]==2))) &&
        !(cfg->reuse_evidence_enabled && reuse_role(arch,ctx->id))) return 0;
#elif defined(__TARGET_ARCH_arm64)
    __u32 arch = 0xc00000b7;
    if (observer_direct && (ctx->id == 63 || ctx->id == 64 ||
        ((ctx->id == 129 || ctx->id == 424) && ctx->args[1] == 2) ||
        (ctx->id == 131 && ctx->args[2] == 2))) return 0;
    if (ctx->id != 57 && ctx->id != 63 && ctx->id != 64 && ctx->id != 82 &&
        ctx->id != 83 && ctx->id != 129 && ctx->id != 131 && ctx->id != 206 &&
        ctx->id != 210 && ctx->id != 211 && ctx->id != 212 && ctx->id != 424 &&
        !(cfg->filter_evidence_enabled && (ctx->id==277 || (ctx->id==167 && ctx->args[0]==22 && ctx->args[1]==2))) &&
        !(cfg->reuse_evidence_enabled && reuse_role(arch,ctx->id))) return 0;
#else
#error Unsupported native auxiliary syscall ABI
#endif
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mc_syscall_identity_v1 identity = { .arch = arch, .nr = ctx->id, .unfiltered = 1 };
    __u64 *next = bpf_map_lookup_elem(&next_sequence, &zero);
    if (!next || bpf_probe_read_kernel(identity.args, sizeof(identity.args), ctx->args)) {
        record_loss(); return 0;
    }
    __u64 dev = 0, ino = 0, names[6] = {0};
    int role=checked_reuse_entry(cfg,task,&identity,&dev,&ino,names);
    if (cfg->reuse_evidence_enabled && reuse_role(arch,ctx->id) && role<=0) return 0;
    identity.occurrence = __sync_fetch_and_add(next, 1) + 1;
    if (bpf_map_update_elem(&pending_syscall, &tid, &identity, BPF_NOEXIST)) {
        record_loss(); return 0;
    }
    // Capture the actual live file object for fsync/fdatasync. Do not turn a
    // userspace fd number into a path assertion or dereference it after close.
    if ((arch == 0xc000003e && (ctx->id == 74 || ctx->id == 75)) ||
        (arch == 0xc00000b7 && (ctx->id == 82 || ctx->id == 83))) {
        struct fdtable *table = 0;
        struct file **descriptors = 0;
        struct file *file = 0;
        struct inode *inode = 0;
        __u32 capacity = 0;
        if (BPF_CORE_READ_INTO(&table,task,files,fdt) || !table ||
            BPF_CORE_READ_INTO(&capacity,table,max_fds) ||
            BPF_CORE_READ_INTO(&descriptors,table,fd)) { record_loss(); return 0; }
        if (identity.args[0] < capacity) {
            if (bpf_probe_read_kernel(&file,sizeof(file),descriptors+identity.args[0])) { record_loss(); return 0; }
            if (file) {
                __u32 rawdev = 0;
                if (BPF_CORE_READ_INTO(&inode,file,f_inode) || !inode ||
                    BPF_CORE_READ_INTO(&ino,inode,i_ino) ||
                    BPF_CORE_READ_INTO(&rawdev,inode,i_sb,s_dev)) { record_loss(); return 0; }
                dev = stat_device(rawdev);
            }
        }
    }
    if (role>0) {
        emit_scoped(cfg,MC_REUSE_SYSCALL_ENTRY,role,dev,ino,arch,ctx->id,0,0);
        const char temporary[]="attempt.json.new",canonical[]="attempt.json";
        reuse_metadata(cfg,MC_REUSE_PATH_OPERANDS,role,&identity,dev,ino,
            (__s64)sizeof(temporary) | ((__s64)(role==3?sizeof(canonical):0)<<32),names);
    } else emit_scoped(cfg,MC_UNFILTERED_SYSCALL_ENTRY,0,dev,ino,arch,ctx->id,0,0);
    checked_filter_descriptor(cfg,&identity);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int mc_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct file *file = BPF_CORE_READ(task, mm, exe_file);
    struct inode *inode = file ? BPF_CORE_READ(file, f_inode) : 0;
    __u64 number = inode ? BPF_CORE_READ(inode, i_ino) : 0;
    __u64 dev = inode ? stat_device(BPF_CORE_READ(inode, i_sb, s_dev)) : 0;
    emit(MC_EXEC, 0, dev, number, 0, 0, 0, 0);
    filter_identity(active_config(),task,0,0,0,3);
    return 0;
}

SEC("fentry/wake_up_new_task")
int BPF_PROG(mc_fork, struct task_struct *child_task)
{
    struct mc_config_v1 *cfg = active_config();
    if (!cfg) {
        __u32 zero = 0;
        cfg = bpf_map_lookup_elem(&config, &zero);
        if (!cfg || !cfg->observer_tgid || (__u32)(bpf_get_current_pid_tgid() >> 32) != cfg->observer_tgid)
            return 0;
    }
    if (cfg && cfg->capture_enabled) {
        __u32 child = BPF_CORE_READ(child_task, pid);
        __u64 child_start = BPF_CORE_READ(child_task, start_boottime);
        if (!child || !child_start || bpf_map_update_elem(&tracked_descendants, &child, &child_start, BPF_ANY) ||
            bpf_map_update_elem(&owned_fork_lifecycle,&child,&child_start,BPF_ANY))
            record_loss();
        emit_scoped(cfg, MC_FORK, child, 0, 0, 0, 0, 0, child_start);
        filter_identity(cfg,child_task,child,0,0,4);
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
    // Keep the identity tombstone until release_task, including orphan reap.
    bpf_map_delete_elem(&pending_syscall, &tid);
    return 0;
}

// release_task is the kernel's final task reaping path, not merely an exit
// notification. The victim's raw start time is carried separately from the
// current reaper task and joined by the Rust parser to a prior exact exit.
SEC("fentry/release_task")
int BPF_PROG(mc_reap, struct task_struct *victim)
{
    __u32 pid = BPF_CORE_READ(victim, pid);
    __u64 start = BPF_CORE_READ(victim, start_boottime);
    __u64 *known = bpf_map_lookup_elem(&tracked_descendants, &pid);
    if (known && *known == start) {
        __u32 zero = 0;
        emit_scoped(bpf_map_lookup_elem(&config, &zero), MC_REAP, pid, 0, 0, 0, 0, 0, start);
        bpf_map_delete_elem(&tracked_descendants, &pid);
        bpf_map_delete_elem(&owned_fork_lifecycle,&pid);
        bpf_map_delete_elem(&marker_lifecycle_owners,&pid);
    }
    return 0;
}

// NSFS_MAGIC from linux/magic.h. This observes the kernel close operation,
// not a later scan of the process's mutable fd table.
#define MC_NSFS_MAGIC 0x6e736673U
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} pending_ns_close SEC(".maps");

SEC("fentry/filp_close")
int BPF_PROG(mc_nsfd_close_enter, struct file *file, void *owner)
{
    struct mc_config_v1 *cfg = active_config();
    if (!cfg) {
        __u32 zero = 0;
        cfg = bpf_map_lookup_elem(&config, &zero);
        if (!cfg || !cfg->capture_enabled || !cfg->observer_tgid || (__u32)(bpf_get_current_pid_tgid() >> 32) != cfg->observer_tgid)
            return 0;
    }
    struct inode *inode = file ? BPF_CORE_READ(file, f_inode) : 0;
    __u64 magic = inode ? BPF_CORE_READ(inode, i_sb, s_magic) : 0;
    if (magic == MC_NSFS_MAGIC) {
        __u32 tid = (__u32)bpf_get_current_pid_tgid();
        __u64 ino = BPF_CORE_READ(inode, i_ino);
        if (!ino || bpf_map_update_elem(&pending_ns_close, &tid, &ino, BPF_NOEXIST))
            record_loss();
    }
    return 0;
}

SEC("fexit/filp_close")
int BPF_PROG(mc_nsfd_close, struct file *file, void *owner, int ret)
{
    // file may have been freed by filp_close; only use the entry snapshot.
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *ino = bpf_map_lookup_elem(&pending_ns_close, &tid);
    if (ino) {
        __u32 zero = 0;
        struct mc_config_v1 *cfg = bpf_map_lookup_elem(&config, &zero);
        if (cfg)
            emit_scoped(cfg, MC_NSFD_CLOSE, 0, 0, *ino, 0, 0, 0, ret);
        else
            record_loss();
        bpf_map_delete_elem(&pending_ns_close, &tid);
    }
    return 0;
}
