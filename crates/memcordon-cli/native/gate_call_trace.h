#pragma once
#include <stdint.h>
#include <stddef.h>
struct TraceEntry {
    uint64_t raw_root, raw_output;
    uint32_t sequence, operation, thread_id, desired_access;
    uint32_t attributes_length, attributes_flags, root_is_null;
    uint32_t arguments_readable, name_readable, reported_name_bytes;
    uint32_t copied_name_units, name_malformed, name_truncated;
    uint32_t entered, returned;
    int32_t native_status;
    uint32_t output_handle_readable, output_handle_returned;
    uint16_t name[256];
};
struct TracePacket {
    uint32_t version, setup_stage, setup_error, attached_directory, attached_event;
    uint32_t armed_call_count, count, overflow, incomplete, called;
    uint32_t outer_opened, outer_error, thread_count, thread_limit, clock_live, lifetime_policy;
    uint64_t started_qpc, finished_qpc, original_cutoff_qpc;
    TraceEntry entries[8];
};
static_assert(sizeof(TraceEntry) == 600 && offsetof(TraceEntry, name) == 88, "trace entry ABI");
static_assert(sizeof(TracePacket) == 4888 && offsetof(TracePacket, entries) == 88, "trace packet ABI");
extern "C" void memcordon_gate_trace_prepare(TracePacket*, uint64_t, uint64_t);
extern "C" void* memcordon_gate_trace_call(TracePacket*, const uint16_t*, uint32_t*, uint32_t*);
extern "C" uint32_t memcordon_gate_trace_mock();
