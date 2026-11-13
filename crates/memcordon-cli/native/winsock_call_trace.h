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

struct ListenerOutcome {
    uint32_t kind,raw_error_present;
    int32_t raw_error;
    uint32_t reserved;
};
struct ListenerRequest {
    uint64_t cutoff_qpc,frequency;
    uint32_t incoming_win32;
    int32_t incoming_wsa;
    uint32_t experiment_flags,reserved;
};
struct ListenerEntry {
    uint64_t sequence,parent_sequence,arguments[6],result;
    uint32_t operation,thread_id,depth,flags,incoming_win32;
    int32_t incoming_wsa;
    uint32_t outgoing_win32;
    int32_t outgoing_wsa;
    uint32_t entered,returned,failed,error_domain,output_valid,output_u32;
    uint64_t completion_sequence;
    uint8_t input_prefix[32];
    uint32_t input_bytes,input_flags;
};
struct ListenerDependencyLink {
    uint64_t dependency_sequence,timeline_sequence,parent_listener_sequence;
};
struct ListenerReturnedModule {
    uint32_t version,setup_stage,setup_error,setup_reason;
    uint32_t selected,armed,scope_flags,incomplete;
    uint32_t link_count,links_dropped,selection_count,skipped_count;
    uint64_t parent_listener_sequence,loader_dependency_sequence;
    uint64_t loader_timeline_sequence,returned_module;
    WsaPacket dependencies;
    ListenerDependencyLink first_failure_link,links[16];
};
struct ListenerLoaderLink {
    uint64_t dependency_sequence,timeline_sequence,parent_listener_sequence;
    uint64_t loader_dependency_sequence,loader_timeline_sequence;
};
struct ListenerLoaderWindow {
    uint64_t dependency_sequence,loader_dependency_sequence;
    uint64_t parent_listener_sequence,started_qpc,finished_qpc;
};
struct ListenerLoaderOwner {
    uint32_t version,setup_stage,setup_error,setup_reason;
    uint32_t selected,armed,scope_flags,incomplete;
    uint32_t link_count,links_dropped,attempt_count,skipped_count;
    uint64_t loader_target,owner_base;
    WsaPacket dependencies;
    ListenerLoaderLink first_failure_link,links[16];
    uint32_t window_count,windows_dropped,first_failure_window_present,windows_invalid;
    ListenerLoaderWindow first_failure_window,windows[16];
};
struct ListenerPacket {
    uint32_t version,setup_stage,setup_error,setup_reason;
    uint32_t called,callback_outcome,callback_raw_error_present;
    int32_t callback_raw_error;
    uint32_t armed,original_thread,scope_flags,incomplete;
    uint32_t slot_count,descriptor_count,function_count,callbacks_complete;
    uint32_t owner_pinned,protections_restored,rollback_error,clock_live;
    uint32_t total_calls,total_failures,record_count,dropped;
    uint32_t overflow,first_failure_present,dependency_scope_armed,dependency_scope_error;
    uint32_t incoming_win32;
    int32_t incoming_wsa;
    uint32_t outgoing_win32;
    int32_t outgoing_wsa;
    uint32_t discovered_mask,verified_mask,published_mask,entered_mask;
    uint32_t returned_mask,failure_mask,dependency_link_count,dependency_links_dropped;
    uint64_t started_qpc,finished_qpc,cutoff_qpc,frequency,next_sequence,listener_owner_anchor;
    WsaNode owner;
    WsaSlot slots[16];
    ListenerEntry first_failure,entries[16];
    ListenerDependencyLink first_dependency_failure_link,dependency_links[16];
    WsaPacket dependencies;
    ListenerReturnedModule returned_module;
    ListenerLoaderOwner loader_owner;
    struct ImageReturn {
        uint64_t dependency_sequence,parent_listener_sequence,returned_base,allocation_base,started_qpc,finished_qpc;
        uint32_t original_thread,domain,memory_type,state,virtual_query_error,mapped_name_error,mapped_path_units,flags;
        uint16_t mapped_path[512];
    };
    struct ReturnedImages {
        uint32_t version,enabled,count,dropped,attempts,incomplete,reserved[2];
        ImageReturn rows[8];
    } returned_images;
};
using ListenerInvoke=void(*)(void*,ListenerOutcome*);
extern "C" void memcordon_listener_trace_call(ListenerPacket*,const ListenerRequest*,ListenerInvoke,void*);
extern "C" uint32_t memcordon_listener_trace_mock(uint64_t,uint64_t);
static_assert(sizeof(ListenerOutcome)==16 && sizeof(ListenerRequest)==32,"listener callback ABI v2");
static_assert(sizeof(ListenerEntry)==176 && offsetof(ListenerEntry,completion_sequence)==128 && offsetof(ListenerEntry,input_prefix)==136,"listener entry ABI v1");
static_assert(sizeof(ListenerDependencyLink)==24,"listener dependency link ABI v1");
static_assert(sizeof(ListenerReturnedModule)==12136 && offsetof(ListenerReturnedModule,dependencies)==80 && offsetof(ListenerReturnedModule,first_failure_link)==11728 && offsetof(ListenerReturnedModule,links)==11752,"listener returned module ABI v1");
static_assert(sizeof(ListenerLoaderLink)==40,"listener loader link ABI v1");
static_assert(sizeof(ListenerLoaderWindow)==40,"listener loader window ABI v1");
static_assert(sizeof(ListenerLoaderOwner)==13088 && offsetof(ListenerLoaderOwner,dependencies)==64 && offsetof(ListenerLoaderOwner,first_failure_link)==11712 && offsetof(ListenerLoaderOwner,links)==11752 && offsetof(ListenerLoaderOwner,window_count)==12392 && offsetof(ListenerLoaderOwner,first_failure_window)==12408 && offsetof(ListenerLoaderOwner,windows)==12448,"listener loader owner ABI v2");
static_assert(sizeof(ListenerPacket::ImageReturn)==1104 && sizeof(ListenerPacket::ReturnedImages)==8864,"returned image ABI v1");
static_assert(sizeof(ListenerPacket)==50304 && offsetof(ListenerPacket,owner)==208 && offsetof(ListenerPacket,slots)==400 && offsetof(ListenerPacket,first_failure)==1168 && offsetof(ListenerPacket,entries)==1344 && offsetof(ListenerPacket,first_dependency_failure_link)==4160 && offsetof(ListenerPacket,dependency_links)==4184 && offsetof(ListenerPacket,dependencies)==4568 && offsetof(ListenerPacket,returned_module)==16216 && offsetof(ListenerPacket,loader_owner)==28352 && offsetof(ListenerPacket,loader_owner)+offsetof(ListenerLoaderOwner,window_count)==40744 && offsetof(ListenerPacket,loader_owner)+offsetof(ListenerLoaderOwner,first_failure_window)==40760 && offsetof(ListenerPacket,loader_owner)+offsetof(ListenerLoaderOwner,windows)==40800 && offsetof(ListenerPacket,returned_images)==41440,"listener packet ABI v5");
