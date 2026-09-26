// SPDX-License-Identifier: GPL-2.0
// Qualification-only loader for private_kernel_v1.bpf.o. The Rust collector
// verifies this executable, object, host BTF and target build-id/offset map
// before launch. A nonzero exit or any ring-buffer loss invalidates the run.
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MC_HEADER_BYTES 40U
#define MC_EVENT_BYTES 192U
// Candidate C3 has an 8-MiB member budget. Exhaustion fails, never truncates.
#define MC_CANDIDATE_MAX_EVENTS ((8U * 1024U * 1024U - MC_HEADER_BYTES) / MC_EVENT_BYTES)
#define MC_PUBLIC_MAX_EVENTS 100000U
#define MC_MAGIC 0x4d434b31U

enum mc_event_kind {
    MC_REQUEST_ENTER = 1, MC_REQUEST_EXIT = 2, MC_ALLOCATE = 3,
    MC_SECCOMP = 4, MC_SYSCALL_RETURN = 5, MC_EXEC = 6,
    MC_FORK = 7, MC_EXIT = 8, MC_REAP = 9, MC_NSFD_CLOSE = 10, MC_UNFILTERED_SYSCALL_ENTRY = 11,
    MC_INSTALLED_FILTER_INSTRUCTION = 12, MC_FILTER_IDENTITY = 13, MC_FILTER_PROGRAM_DESCRIPTOR = 14,
    MC_HOST_SYSCTL_PIN = 15, MC_HOST_SYSCTL_WRITE = 16,
    MC_REUSE_SYSCALL_ENTRY = 17, MC_REUSE_PATH_OPERANDS = 18, MC_REUSE_VFS_OBJECTS = 19
};
struct mc_config_v1 {
    uint64_t cgroup_id;
    uint64_t broker_cgroup_id;
    uint8_t request_key[32];
    uint32_t observer_tgid;
    uint32_t capture_enabled;
    uint32_t filter_evidence_enabled;
    uint32_t host_evidence_enabled;
    uint32_t host_loader_tgid;
    uint64_t host_sysctl_dev[4];
    uint64_t host_sysctl_ino[4];
    uint32_t reuse_evidence_enabled;
    uint64_t reuse_directory_dev, reuse_directory_ino;
    uint64_t reuse_marker_dev, reuse_marker_ino;
    uint64_t reuse_record_dev, reuse_record_ino;
};
struct mc_host_slot_v1 { uint64_t dev, ino, table, data, initialized_ns, netns_inode; };
struct mc_host_pending_v1 { uint64_t dev, ino, table, data, entry_ns; uint32_t slot; };
struct mc_event_v1 {
    uint64_t sequence, monotonic_ns, cgroup_id, task_start_ns;
    uint64_t image_dev, image_inode;
    int64_t syscall_nr, syscall_result;
    uint32_t pid, other_pid, syscall_arch, seccomp_action, kind;
    uint8_t request_key[32];
    uint64_t time_ns_inode;
    uint64_t syscall_occurrence, args[6];
    uint32_t tgid, reserved;
};
_Static_assert(sizeof(struct mc_event_v1) == MC_EVENT_BYTES, "private probe event wire size differs");
struct mc_capture_header_v1 {
    uint32_t magic, schema_version;
    uint64_t event_count, lost_count;
    uint32_t record_bytes, lifecycle_flags, attached_links, endian_tag;
};
_Static_assert(sizeof(struct mc_capture_header_v1) == MC_HEADER_BYTES, "capture header size differs");
struct capture {
    FILE *file;
    uint64_t count;
    int failed;
    uint64_t max_events;
    uint64_t armed_ns;
};
static volatile sig_atomic_t stopping;
static uint64_t monotonic_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 || now.tv_nsec < 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}
static void stop_handler(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}
static int sample(void *context, void *data, size_t size)
{
    struct capture *capture = context;
    struct mc_event_v1 *event = data;
    if (size != sizeof(*event)) {
        capture->failed = 1;
        return -1;
    }
    // Ring consumption is reservation ordered; kernel atomic allocation is not.
    event->sequence = capture->count + 1;
    if (event->kind < MC_REQUEST_ENTER ||
        event->kind > MC_REUSE_VFS_OBJECTS) {
        capture->failed = 1;
        return -1;
    }
    // The global host watch is already active before product arm. These
    // completed writes precede the admitted observation window, not its tail.
    if (event->kind == MC_HOST_SYSCTL_WRITE && event->monotonic_ns < capture->armed_ns)
        return 0;
    if (capture->count >= capture->max_events ||
        fwrite(event, sizeof(*event), 1, capture->file) != 1) {
        capture->failed = 1;
        return -1;
    }
    capture->count++;
    return 0;
}
static int hex_key(const char *hex, uint8_t *output, size_t output_bytes)
{
    if (strlen(hex) != output_bytes * 2) return -1;
    for (size_t index = 0; index < output_bytes; index++) {
        unsigned int value = 0;
        for (size_t nibble = 0; nibble < 2; nibble++) {
            unsigned char character = hex[index * 2 + nibble];
            unsigned int digit;
            if (character >= '0' && character <= '9') digit = character - '0';
            else if (character >= 'a' && character <= 'f') digit = character - 'a' + 10;
            else return -1;
            value = value * 16 + digit;
        }
        output[index] = (uint8_t)value;
    }
    return 0;
}
static struct bpf_link *attach_program(struct bpf_object *object,
                                        const char *name,
                                        const char *category,
                                        const char *event)
{
    struct bpf_program *program = bpf_object__find_program_by_name(object, name);
    if (!program) return NULL;
    if (category)
        return bpf_program__attach_tracepoint(program, category, event);
    return bpf_program__attach(program);
}
int main(int argc, char **argv)
{
    if (argc != 12 && argc != 13 && argc != 19 && argc != 20 && argc != 21 && argc != 22 && argc != 28 && argc != 29) {
        fprintf(stderr, "usage: loader OBJECT AGENT REQUEST_ENTER_OFFSET REQUEST_EXIT_OFFSET ALLOC_OFFSET SERVICE_CGROUP_ID BROKER_CGROUP_ID KEY_HEX OUTPUT candidate-v2|final-public-v2 OBSERVER_TGID [filter-install-v1] [host-sysctl-watch-v1 DEV INO DEV INO DEV INO DEV INO]\n");
        return 2;
    }
    uint64_t max_events;
    if (!strcmp(argv[10], "candidate-v2")) max_events = MC_CANDIDATE_MAX_EVENTS;
    else if (!strcmp(argv[10], "final-public-v2")) max_events = MC_PUBLIC_MAX_EVENTS;
    else return 2;
    char *end = NULL;
    errno = 0;
    unsigned long long request_offset = strtoull(argv[3], &end, 10);
    if (errno || !end || *end || !request_offset) return 2;
    errno = 0;
    unsigned long long request_exit_offset = strtoull(argv[4], &end, 10);
    if (errno || !end || *end || !request_exit_offset || request_exit_offset == request_offset) return 2;
    errno = 0;
    unsigned long long alloc_offset = strtoull(argv[5], &end, 10);
    if (errno || !end || *end || !alloc_offset) return 2;
    errno = 0;
    unsigned long long cgroup_id = strtoull(argv[6], &end, 10);
    if (errno || !end || *end || !cgroup_id) return 2;
    errno = 0;
    unsigned long long broker_cgroup_id = strtoull(argv[7], &end, 10);
    if (errno || !end || *end || !broker_cgroup_id || broker_cgroup_id == cgroup_id) return 2;
    struct mc_config_v1 config = { .cgroup_id = cgroup_id, .broker_cgroup_id = broker_cgroup_id };
    errno = 0;
    unsigned long long observer_tgid = strtoull(argv[11], &end, 10);
    if (errno || !end || *end || !observer_tgid || observer_tgid > UINT32_MAX) return 2;
    config.observer_tgid = (uint32_t)observer_tgid;
    if (argc==13 || argc==20 || argc==22 || argc==29) {
        if (strcmp(argv[12],"filter-install-v1")) return 2;
        config.filter_evidence_enabled=1;
    }
    int host_files[4] = {-1,-1,-1,-1};
    const char *host_paths[4] = {
        "/proc/sys/net/ipv4/ip_unprivileged_port_start",
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/sys/net/ipv4/ip_local_port_range",
        "/proc/sys/net/ipv4/ip_local_reserved_ports"
    };
    if (argc==21 || argc==22 || argc==28 || argc==29) {
        int cursor = 12 + (int)config.filter_evidence_enabled;
        if (geteuid()!=0 || strcmp(argv[cursor++],"host-sysctl-watch-v1")) return 2;
        config.host_evidence_enabled=1;
        config.host_loader_tgid=(uint32_t)getpid();
        for (size_t slot=0;slot<4;slot++) {
            errno=0;
            config.host_sysctl_dev[slot]=strtoull(argv[cursor++],&end,10);
            if (errno || !end || *end || !config.host_sysctl_dev[slot]) return 2;
            errno=0;
            config.host_sysctl_ino[slot]=strtoull(argv[cursor++],&end,10);
            if (errno || !end || *end || !config.host_sysctl_ino[slot]) return 2;
            host_files[slot]=open(host_paths[slot],O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
            struct stat metadata;
            if (host_files[slot]<0 || fstat(host_files[slot],&metadata) ||
                (uint64_t)metadata.st_dev!=config.host_sysctl_dev[slot] ||
                (uint64_t)metadata.st_ino!=config.host_sysctl_ino[slot]) return 2;
            for (size_t previous=0;previous<slot;previous++)
                if (config.host_sysctl_dev[slot]==config.host_sysctl_dev[previous] &&
                    config.host_sysctl_ino[slot]==config.host_sysctl_ino[previous]) return 2;
        }
    }
    if (argc==19 || argc==20 || argc==28 || argc==29) {
        int cursor=12+(int)config.filter_evidence_enabled+(config.host_evidence_enabled?9:0);
        if (geteuid()!=0 || strcmp(argv[cursor++],"reuse-journal-source-v1")) return 2;
        uint64_t *values[6]={&config.reuse_directory_dev,&config.reuse_directory_ino,&config.reuse_marker_dev,&config.reuse_marker_ino,&config.reuse_record_dev,&config.reuse_record_ino};
        for (size_t index=0;index<6;index++) {errno=0;*values[index]=strtoull(argv[cursor++],&end,10);if(errno || !end || *end || !*values[index])return 2;}
        if(config.reuse_marker_dev==config.reuse_record_dev && config.reuse_marker_ino==config.reuse_record_ino)return 2;
        config.reuse_evidence_enabled=1;
    }
    if (hex_key(argv[8], config.request_key, sizeof(config.request_key))) return 2;

    struct bpf_object *object = bpf_object__open_file(argv[1], NULL);
    if (!object || libbpf_get_error(object)) return 3;
    const char *host_programs[4] = {"mc_host_sysctl_read_enter","mc_host_sysctl_read_exit",
        "mc_host_sysctl_write_enter","mc_host_sysctl_write_exit"};
    for (size_t index=0;index<4;index++) {
        struct bpf_program *program=bpf_object__find_program_by_name(object,host_programs[index]);
        if (!program || bpf_program__set_autoload(program,config.host_evidence_enabled!=0)) return 3;
    }
    const char *reuse_programs[2]={"mc_reuse_unlink_objects","mc_reuse_rename_objects"};
    for(size_t index=0;index<2;index++){struct bpf_program *program=bpf_object__find_program_by_name(object,reuse_programs[index]);if(!program || bpf_program__set_autoload(program,config.reuse_evidence_enabled!=0))return 3;}
    if (bpf_object__load(object)) return 3;
    struct bpf_map *config_map = bpf_object__find_map_by_name(object, "config");
    struct bpf_map *event_map = bpf_object__find_map_by_name(object, "events");
    struct bpf_map *loss_map = bpf_object__find_map_by_name(object, "lost");
    if (!config_map || !event_map || !loss_map) return 3;
    uint32_t zero = 0;
    if (bpf_map_update_elem(bpf_map__fd(config_map), &zero, &config, BPF_ANY)) return 3;

    int output_fd = open(argv[9], O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (output_fd < 0) return 3;
    FILE *output = fdopen(output_fd, "w+b");
    if (!output) return 3;
    struct mc_capture_header_v1 header = {
        .magic = MC_MAGIC, .schema_version = 2,
        .record_bytes = MC_EVENT_BYTES, .endian_tag = 0x01020304U
    };
    if (fwrite(&header, sizeof(header), 1, output) != 1) return 3;
    struct capture capture = { .file = output, .max_events = max_events };
    struct ring_buffer *ring = ring_buffer__new(bpf_map__fd(event_map), sample, &capture, NULL);
    if (!ring) return 3;

    struct bpf_link *links[18] = {0};
    links[0] = attach_program(object, "mc_seccomp_decision", NULL, NULL);
    links[1] = attach_program(object, "mc_syscall_return", "raw_syscalls", "sys_exit");
    links[2] = attach_program(object, "mc_exec", "sched", "sched_process_exec");
    links[3] = attach_program(object, "mc_fork", NULL, NULL);
    links[4] = attach_program(object, "mc_exit", "sched", "sched_process_exit");
    struct bpf_program *request_enter = bpf_object__find_program_by_name(object, "mc_request_enter");
    struct bpf_program *request_exit = bpf_object__find_program_by_name(object, "mc_request_exit");
    struct bpf_program *allocation = bpf_object__find_program_by_name(object, "mc_allocate");
    if (!request_enter || !request_exit || !allocation) return 3;
    links[5] = bpf_program__attach_uprobe(request_enter, false, -1, argv[2], request_offset);
    links[6] = bpf_program__attach_uprobe(request_exit, true, -1, argv[2], request_exit_offset);
    links[7] = bpf_program__attach_uprobe(allocation, false, -1, argv[2], alloc_offset);
    links[8] = attach_program(object, "mc_reap", NULL, NULL);
    links[9] = attach_program(object, "mc_nsfd_close", NULL, NULL);
    links[10] = attach_program(object, "mc_nsfd_close_enter", NULL, NULL);
    links[11] = attach_program(object, "mc_unfiltered_syscall_entry", "raw_syscalls", "sys_enter");
    size_t link_count = config.host_evidence_enabled ? 16 : 12;
    if (config.host_evidence_enabled)
        for (size_t index=0;index<4;index++)
            links[12+index]=attach_program(object,host_programs[index],NULL,NULL);
    if(config.reuse_evidence_enabled){
        for(size_t index=0;index<2;index++)links[link_count+index]=attach_program(object,reuse_programs[index],NULL,NULL);
        link_count+=2;
    }
    for (size_t index = 0; index < link_count; index++)
        if (!links[index] || libbpf_get_error(links[index])) return 4;
    header.attached_links = (uint32_t)link_count;
    header.lifecycle_flags = 13; // armed + unfiltered lifecycle + checked native socket operands
    if (config.filter_evidence_enabled) header.lifecycle_flags |= 16;
    if (config.reuse_evidence_enabled) header.lifecycle_flags |= 64;
    struct mc_host_slot_v1 host_slots[4] = {0};
    struct bpf_map *host_slot_map=NULL;
    struct bpf_map *host_write_map=NULL;
    if (config.host_evidence_enabled) {
        header.lifecycle_flags |= 32;
        host_slot_map=bpf_object__find_map_by_name(object,"host_slots");
        host_write_map=bpf_object__find_map_by_name(object,"host_writes");
        if (!host_slot_map || !host_write_map) return 4;
        for (uint32_t slot=0;slot<4;slot++) {
            char bytes[4096];
            if (pread(host_files[slot],bytes,sizeof(bytes),0)<=0 ||
                bpf_map_lookup_elem(bpf_map__fd(host_slot_map),&slot,&host_slots[slot]) ||
                host_slots[slot].dev!=config.host_sysctl_dev[slot] ||
                host_slots[slot].ino!=config.host_sysctl_ino[slot] ||
                !host_slots[slot].table || !host_slots[slot].data ||
                !host_slots[slot].initialized_ns || !host_slots[slot].netns_inode) return 4;
            for (uint32_t previous=0;previous<slot;previous++)
                if (host_slots[slot].data==host_slots[previous].data ||
                    host_slots[slot].table==host_slots[previous].table ||
                    host_slots[slot].netns_inode!=host_slots[previous].netns_inode) return 4;
        }
    }

    struct sigaction action = { .sa_handler = stop_handler };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) return 4;
    uint64_t armed_ns = monotonic_ns();
    capture.armed_ns=armed_ns;
    config.capture_enabled = 1;
    if (!armed_ns || bpf_map_update_elem(bpf_map__fd(config_map), &zero, &config, BPF_ANY)) return 4;
    if (config.host_evidence_enabled)
        for (size_t slot=0;slot<4;slot++) {
            char bytes[4096];
            if (host_slots[slot].initialized_ns>armed_ns ||
                pread(host_files[slot],bytes,sizeof(bytes),0)<=0) return 4;
        }
    if (!armed_ns || write(STDOUT_FILENO, "READY\n", 6) != 6) return 4;
    while (!stopping && !capture.failed) {
        int polled = ring_buffer__poll(ring, 100);
        if (polled < 0 && polled != -EINTR) capture.failed = 1;
    }
    // Detach producers before the final drain. Keep maps/ring alive through
    // drain and loss readback so a completed capture cannot omit its tail.
    uint64_t detached_ns=0;
    if (config.host_evidence_enabled) {
        // The independent global host watch remains active across this
        // product stop and the measured endpoint; no host-tail gap is accepted.
        config.capture_enabled=0;
        if (bpf_map_update_elem(bpf_map__fd(config_map),&zero,&config,BPF_ANY)) capture.failed=1;
        detached_ns=monotonic_ns();
    }
    for (size_t index = 0; index < link_count; index++)
        if (bpf_link__destroy(links[index])) capture.failed = 1;
    if (!config.host_evidence_enabled) detached_ns=monotonic_ns();
    if (config.host_evidence_enabled) {
        uint32_t key, next_key;
        uint32_t *previous=NULL;
        size_t count=0;
        while (!bpf_map_get_next_key(bpf_map__fd(host_write_map),previous,&next_key)) {
            struct mc_host_pending_v1 pending;
            if (++count>4096 || bpf_map_lookup_elem(bpf_map__fd(host_write_map),&next_key,&pending)) {
                capture.failed=1;break;
            }
            for (size_t slot=0;slot<4;slot++)
                if (pending.data==host_slots[slot].data) capture.failed=1;
            key=next_key;previous=&key;
        }
        if (errno!=ENOENT) capture.failed=1;
        for (size_t slot=0;slot<4;slot++)
            if (close(host_files[slot])) capture.failed=1;
    }
    header.lifecycle_flags |= 2;
    while (!capture.failed) {
        int drained = ring_buffer__consume(ring);
        if (drained < 0) { capture.failed = 1; break; }
        if (drained == 0) break;
    }
    uint64_t drained_ns = monotonic_ns();
    if (!detached_ns || drained_ns < detached_ns) capture.failed = 1;

    int cpu_count = libbpf_num_possible_cpus();
    if (cpu_count <= 0) capture.failed = 1;
    uint64_t *cpu_loss = cpu_count > 0 ? calloc((size_t)cpu_count, sizeof(uint64_t)) : NULL;
    if (!cpu_loss || bpf_map_lookup_elem(bpf_map__fd(loss_map), &zero, cpu_loss))
        capture.failed = 1;
    if (cpu_loss)
        for (int cpu = 0; cpu < cpu_count; cpu++) header.lost_count += cpu_loss[cpu];
    free(cpu_loss);
    header.event_count = capture.count;
    if (fseek(output, 0, SEEK_SET) || fwrite(&header, sizeof(header), 1, output) != 1 ||
        fflush(output) || fsync(fileno(output))) capture.failed = 1;
    fclose(output);
    ring_buffer__free(ring);
    bpf_object__close(object);
    if (fprintf(stderr, "MC_TIMING_V1 {\"armed_monotonic_ns\":%llu,\"detached_monotonic_ns\":%llu,\"drained_monotonic_ns\":%llu}\n",
                (unsigned long long)armed_ns, (unsigned long long)detached_ns,
                (unsigned long long)drained_ns) < 0 || fflush(stderr)) return 5;
    return capture.failed || header.lost_count ? 5 : 0;
}
