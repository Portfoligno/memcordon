#pragma once
#include <stdint.h>
#include <stddef.h>
struct WsaEntry {
    uint64_t sequence,raw_root,raw_output,requested_size,secondary_size;
    uint32_t operation,thread_id,desired_access,flags,entered,returned;
    int32_t native_status;
    uint32_t incoming_error,outgoing_error,reported_name_bytes,copied_name_units,name_flags,output_flags,scalar_flags;
    uint16_t name[256];
};
struct WsaSlot {
    uint64_t slot,original,hook,descriptor_module;
    uint32_t operation,published,restored,reserved;
};
struct WsaNode {
    uint64_t owner_base,entry,slot,target;
    uint32_t owner_size,timestamp,machine,entry_len;
    uint8_t entry_bytes[16];
    uint16_t module_name[64];
};
struct WsaPacket {
    uint32_t version,setup_stage,setup_error,setup_reason,called;
    int32_t original_return;
    uint32_t requested_version,negotiated_version,incoming_error,outgoing_error,armed,record_count;
    uint32_t total_calls,total_failures,dropped,overflow,incomplete,first_failure_present,original_thread,scope_flags;
    uint32_t node_count,hop_count,descriptor_count,function_count,slot_count,callbacks_complete,protections_restored,rollback_error;
    uint32_t owner_pinned,clock_live,retention_error,reserved;
    uint64_t started_qpc,finished_qpc,cutoff_qpc,frequency;
    WsaNode nodes[2];
    WsaSlot slots[16];
    WsaEntry first_failure,entries[16];
};
static_assert(sizeof(WsaEntry)==608 && offsetof(WsaEntry,name)==96,"WSA entry ABI");
static_assert(sizeof(WsaSlot)==48 && sizeof(WsaNode)==192,"WSA route ABI");
static_assert(sizeof(WsaPacket)==11648 && offsetof(WsaPacket,nodes)==160 && offsetof(WsaPacket,slots)==544 && offsetof(WsaPacket,first_failure)==1312 && offsetof(WsaPacket,entries)==1920,"WSA packet ABI v1");
extern "C" void memcordon_wsa_trace_call(WsaPacket*,uintptr_t,uint16_t,uint64_t,uint64_t);
extern "C" uint32_t memcordon_wsa_trace_mock(uint64_t,uint64_t);
