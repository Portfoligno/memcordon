#pragma once
#include "native_file_request_trace.h"

constexpr uint32_t SpawnVersion=1,SpawnOwners=1,SpawnRoutes=5,SpawnRows=16,SpawnNameUnits=128;
using SpawnOwner=NativeFileOwner;
using SpawnRoute=NativeFileRoute;
struct SpawnRow {
    uint64_t sequence,started_qpc,finished_qpc,raw_root,raw_output,secondary_output;
    uint64_t source_process,source_handle,target_process,default_timeout;
    uint32_t operation,thread_id,route_index,input_flags,desired_access,oa_length,oa_attributes;
    uint32_t reported_name_bytes,copied_name_units,name_flags,share_access,create_disposition,create_options,file_attributes;
    uint32_t pipe_type,read_mode,completion_mode,max_instances,inbound_quota,outbound_quota;
    uint32_t inherit_handle,duplicate_options,creation_flags,security_present,entered,returned;
    int32_t native_status;
    uint32_t win32_result,incoming_win32;
    int32_t incoming_wsa;
    uint32_t outgoing_win32;
    int32_t outgoing_wsa;
    uint32_t output_flags,flags,output_pid,output_tid;
    uint16_t name[SpawnNameUnits];
};
struct SpawnPacket {
    uint32_t version,packet_bytes,owner_count,route_count,record_count,total_calls,total_failures,dropped,overflow,incomplete,first_failure_present;
    uint32_t scope_attempted,scope_returned,scope_reentry,late,clock_failures,input_failures,unmatched_scope,scope_unavailable,route_failures,original_thread,reserved;
    uint64_t cutoff_qpc,frequency,started_qpc,finished_qpc;
    SpawnOwner owners[SpawnOwners];
    SpawnRoute routes[SpawnRoutes];
    SpawnRow first_failure,rows[SpawnRows];
};
static_assert(sizeof(SpawnOwner)==224 && sizeof(SpawnRoute)==264,"spawn route ABI v1");
static_assert(sizeof(SpawnRow)==480 && offsetof(SpawnRow,name)==224,"spawn row ABI v1");
static_assert(sizeof(SpawnPacket)==9824 && offsetof(SpawnPacket,owners)==120 && offsetof(SpawnPacket,routes)==344 && offsetof(SpawnPacket,first_failure)==1664 && offsetof(SpawnPacket,rows)==2144,"spawn packet ABI v1");
extern "C" void memcordon_spawn_trace_call(SpawnPacket*,const ListenerRequest*,ListenerInvoke,void*);
extern "C" uint32_t memcordon_spawn_trace_mock(uint64_t,uint64_t);
