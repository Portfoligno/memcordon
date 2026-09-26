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
#include <unistd.h>

#define MC_MAX_EVENTS 100000U
#define MC_MAGIC 0x4d434b31U

enum mc_event_kind {
    MC_REQUEST_ENTER = 1, MC_REQUEST_EXIT = 2, MC_ALLOCATE = 3,
    MC_SECCOMP = 4, MC_SYSCALL_RETURN = 5, MC_EXEC = 6,
    MC_FORK = 7, MC_EXIT = 8, MC_REAP = 9, MC_NSFD_CLOSE = 10
};
struct mc_config_v1 {
    uint64_t cgroup_id;
    uint64_t broker_cgroup_id;
    uint8_t request_key[32];
};
struct mc_event_v1 {
    uint64_t sequence, monotonic_ns, cgroup_id, task_start_ns;
    uint64_t image_dev, image_inode;
    int64_t syscall_nr, syscall_result;
    uint32_t pid, other_pid, syscall_arch, seccomp_action, kind;
    uint8_t request_key[32];
    uint64_t time_ns_inode;
};
_Static_assert(sizeof(struct mc_event_v1) == 128, "private probe event wire size differs");
struct mc_capture_header_v1 {
    uint32_t magic, schema_version;
    uint64_t event_count, lost_count;
};
struct capture {
    FILE *file;
    uint64_t count;
    int failed;
};
static volatile sig_atomic_t stopping;
static void stop_handler(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}
static int sample(void *context, void *data, size_t size)
{
    struct capture *capture = context;
    const struct mc_event_v1 *event = data;
    if (size != sizeof(*event) || event->kind < MC_REQUEST_ENTER ||
        event->kind > MC_NSFD_CLOSE || capture->count >= MC_MAX_EVENTS ||
        fwrite(event, sizeof(*event), 1, capture->file) != 1) {
        capture->failed = 1;
        return -1;
    }
    capture->count++;
    return 0;
}
static int hex_key(const char *hex, uint8_t output[32])
{
    if (strlen(hex) != 64) return -1;
    for (size_t index = 0; index < 32; index++) {
        unsigned int byte;
        if (sscanf(hex + index * 2, "%2x", &byte) != 1 || byte > 255)
            return -1;
        output[index] = (uint8_t)byte;
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
    if (argc != 10) {
        fprintf(stderr, "usage: loader OBJECT AGENT REQUEST_ENTER_OFFSET REQUEST_EXIT_OFFSET ALLOC_OFFSET SERVICE_CGROUP_ID BROKER_CGROUP_ID KEY_HEX OUTPUT\n");
        return 2;
    }
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
    if (hex_key(argv[8], config.request_key)) return 2;

    struct bpf_object *object = bpf_object__open_file(argv[1], NULL);
    if (!object || libbpf_get_error(object) || bpf_object__load(object)) return 3;
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
        .magic = MC_MAGIC, .schema_version = 1
    };
    if (fwrite(&header, sizeof(header), 1, output) != 1) return 3;
    struct capture capture = { .file = output };
    struct ring_buffer *ring = ring_buffer__new(bpf_map__fd(event_map), sample, &capture, NULL);
    if (!ring) return 3;

    struct bpf_link *links[10] = {0};
    links[0] = attach_program(object, "mc_seccomp_decision", NULL, NULL);
    links[1] = attach_program(object, "mc_syscall_return", "raw_syscalls", "sys_exit");
    links[2] = attach_program(object, "mc_exec", "sched", "sched_process_exec");
    links[3] = attach_program(object, "mc_fork", "sched", "sched_process_fork");
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
    for (size_t index = 0; index < 10; index++)
        if (!links[index] || libbpf_get_error(links[index])) return 4;

    struct sigaction action = { .sa_handler = stop_handler };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) return 4;
    if (write(STDOUT_FILENO, "READY\n", 6) != 6) return 4;
    while (!stopping && !capture.failed) {
        int polled = ring_buffer__poll(ring, 100);
        if (polled < 0 && polled != -EINTR) capture.failed = 1;
    }
    while (!capture.failed && ring_buffer__poll(ring, 0) > 0) {}
    for (size_t index = 0; index < 10; index++) bpf_link__destroy(links[index]);

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
    return capture.failed || header.lost_count ? 5 : 0;
}
