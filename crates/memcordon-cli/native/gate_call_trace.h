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
struct SnapshotEntry {
    uint64_t creation_time, exit_time, capture_time, raw_start_address;
    uint32_t process_id, thread_id, flags, exit_status;
};
struct SnapshotSummary {
    uint32_t attempted, captured, walk_completed, error;
    uint32_t entry_count, terminated_count, without_terminated_count, unknown_flags_count;
    uint32_t detail_count, detail_truncated;
    SnapshotEntry details[8];
};
struct IatRecord {
    uint64_t owner_base, original_open_event, normal_iat_start, normal_iat_end;
    uint64_t directory_slot, event_slot, directory_original, event_original;
    uint32_t strategy, owner_pinned, owner_size, owner_timestamp;
    uint32_t discovery_complete, descriptor_count, function_count, directory_matches, event_matches;
    uint32_t published_directory, published_event, protections_restored;
    uint32_t rollback_error, protection_error, callback_error, reserved;
};
struct RouteNode {
    uint64_t owner_base, entry, delegation_slot, delegation_target;
    uint32_t owner_size, owner_timestamp, module_name_units, module_name_truncated;
    uint32_t entry_bytes_read, entry_byte_count, decode_kind, decode_error, open_event_matches;
    uint32_t entry_revalidated, slot_revalidated, directory_name_matches, event_name_matches, reserved;
    uint16_t module_name[96];
    uint8_t entry_bytes[16];
};
struct RouteRecord {
    uint32_t node_count, node_limit, hop_count, route_reason;
    uint32_t callbacks_total_descriptors, callbacks_total_functions, original_owner_export_equal, route_revalidated;
    RouteNode nodes[2];
    uint64_t directory_descriptor_module, event_descriptor_module;
    uint8_t directory_descriptor[64], event_descriptor[64];
    uint32_t directory_descriptor_bytes, event_descriptor_bytes, directory_descriptor_truncated, event_descriptor_truncated;
};
struct TracePacket {
    uint32_t version, setup_stage, setup_error, attached_directory, attached_event;
    uint32_t armed_call_count, count, overflow, incomplete, called;
    uint32_t outer_opened, outer_error, thread_count, thread_limit, clock_live, lifetime_policy;
    uint32_t setup_reason, original_current_thread_id, snapshot_source, reserved;
    uint64_t started_qpc, finished_qpc, original_cutoff_qpc;
    SnapshotSummary first_snapshot, second_snapshot;
    IatRecord iat;
    RouteRecord route;
    TraceEntry entries[8];
};
static_assert(sizeof(TraceEntry) == 600 && offsetof(TraceEntry, name) == 88, "trace entry ABI");
static_assert(sizeof(SnapshotEntry) == 48 && offsetof(SnapshotEntry, process_id) == 32, "snapshot entry ABI");
static_assert(sizeof(SnapshotSummary) == 424 && offsetof(SnapshotSummary, details) == 40, "snapshot summary ABI");
static_assert(sizeof(IatRecord) == 128 && offsetof(IatRecord, strategy) == 64, "IAT record ABI");
static_assert(sizeof(RouteNode) == 296 && offsetof(RouteNode, module_name) == 88, "route node ABI");
static_assert(sizeof(RouteRecord) == 784 && offsetof(RouteRecord, nodes) == 32 && offsetof(RouteRecord, directory_descriptor_module) == 624, "route record ABI");
static_assert(sizeof(TracePacket) == 6664 && offsetof(TracePacket, entries) == 1864 && offsetof(TracePacket, route) == 1080 && offsetof(TracePacket, iat) == 952, "trace packet ABI v4");
extern "C" void memcordon_gate_trace_prepare(TracePacket*, uint64_t, uint64_t);
extern "C" void* memcordon_gate_trace_call(TracePacket*, const uint16_t*, uint32_t*, uint32_t*);
extern "C" uint32_t memcordon_gate_trace_mock();
extern "C" void memcordon_gate_trace_directories(TracePacket*, uint64_t*, uint32_t*);
extern "C" void memcordon_gate_trace_release_directories(TracePacket*);
extern "C" uint32_t memcordon_decode_import_entry(uint32_t, uint64_t, const uint8_t*, size_t, uint64_t*);
