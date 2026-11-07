#pragma once
#include "winsock_call_trace.h"

constexpr uint32_t NativeFileVersion=1,NativeFileOwners=2,NativeFileRoutes=4,NativeFileRows=16,NativeFileNameUnits=128;
struct NativeFileOwner {
    WsaNode identity;
    uint32_t role,stage,error,complete,descriptor_count,function_count,flags,shared_owner;
};
struct NativeFileRoute {
    WsaSlot slot;
    WsaNode target;
    uint32_t owner_index,original_protection,postvalidated,stage,error,thunk_kind;
};
struct NativeFileRow {
    uint64_t sequence,ldr_dependency_sequence,parent_listener_sequence,started_qpc,finished_qpc,raw_root,raw_output,allocation_size;
    uint32_t operation,thread_id,desired_access,oa_length,oa_attributes,input_flags;
    uint32_t reported_name_bytes,copied_name_units,name_flags,share_access,create_disposition,create_options,file_attributes,ea_length;
    uint32_t entered,returned;
    int32_t native_status;
    uint32_t output_flags,incoming_win32;
    int32_t incoming_wsa;
    uint32_t outgoing_win32;
    int32_t outgoing_wsa;
    uint32_t flags,route_index,reserved[2];
    uint16_t name[NativeFileNameUnits];
};
struct NativeFilePacket {
    uint32_t version,packet_bytes,owner_count,route_count,record_count,total_calls,total_failures,dropped,overflow,incomplete,first_failure_present;
    uint32_t attempts,scopes,scope_reentry,late,clock_failures,input_failures,unmatched_scope,scope_unavailable,route_failures,original_thread,reserved;
    uint64_t cutoff_qpc,frequency;
    NativeFileOwner owners[NativeFileOwners];
    NativeFileRoute routes[NativeFileRoutes];
    NativeFileRow first_failure,rows[NativeFileRows];
};
static_assert(sizeof(NativeFileOwner)==224 && sizeof(NativeFileRoute)==264,"native file route ABI v1");
static_assert(sizeof(NativeFileRow)==424 && offsetof(NativeFileRow,name)==168,"native file row ABI v1");
static_assert(sizeof(NativeFilePacket)==8816 && offsetof(NativeFilePacket,owners)==104 && offsetof(NativeFilePacket,routes)==552 && offsetof(NativeFilePacket,first_failure)==1608 && offsetof(NativeFilePacket,rows)==2032,"native file packet ABI v1");
extern "C" void memcordon_listener_native_file_trace_call(ListenerPacket*,const ListenerRequest*,ListenerInvoke,void*,NativeFilePacket*);
extern "C" uint32_t memcordon_native_file_trace_mock(uint64_t,uint64_t);
