#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <winreg.h>
#include <intrin.h>
#include <atomic>
#include <type_traits>
#include "detours.h"
#include "winsock_call_trace.h"

static_assert(sizeof(void*)==8 && sizeof(WCHAR)==2 && sizeof(NTSTATUS)==4,"WSA trace native ABI");
static_assert(sizeof(OBJECT_ATTRIBUTES)==48 && offsetof(OBJECT_ATTRIBUTES,ObjectName)==16,"WSA native object attributes ABI");
static_assert(sizeof(UNICODE_STRING)==16 && offsetof(UNICODE_STRING,Buffer)==8,"WSA native counted string ABI");
static std::atomic<void*> originals[16] = {};
static_assert(std::atomic<void*>::is_always_lock_free,"forwarding publication is lock-free");
static volatile LONG installed=0;
// Published once, before installed=2. No call/event/error-state data is retained.
struct DependencyRoute {
    WsaNode nodes[2];WsaSlot slots[16];
    uint32_t node_count,hop_count,slot_count,descriptor_count,function_count;
    uint32_t callbacks_complete,owner_pinned,protections_restored,scope_flags,incomplete;
};
static DependencyRoute dependency_route={};
static void save_dependency_route(const WsaPacket* packet){
    for(size_t index=0;index<2;++index)dependency_route.nodes[index]=packet->nodes[index];
    for(size_t index=0;index<16;++index)dependency_route.slots[index]=packet->slots[index];
    dependency_route.node_count=packet->node_count;dependency_route.hop_count=packet->hop_count;
    dependency_route.slot_count=packet->slot_count;dependency_route.descriptor_count=packet->descriptor_count;
    dependency_route.function_count=packet->function_count;dependency_route.callbacks_complete=packet->callbacks_complete;
    dependency_route.owner_pinned=packet->owner_pinned;dependency_route.protections_restored=packet->protections_restored;
    dependency_route.scope_flags=packet->scope_flags;dependency_route.incomplete=packet->incomplete;
}
static void copy_dependency_route(WsaPacket* packet){
    for(size_t index=0;index<2;++index)packet->nodes[index]=dependency_route.nodes[index];
    for(size_t index=0;index<16;++index)packet->slots[index]=dependency_route.slots[index];
    packet->node_count=dependency_route.node_count;packet->hop_count=dependency_route.hop_count;
    packet->slot_count=dependency_route.slot_count;packet->descriptor_count=dependency_route.descriptor_count;
    packet->function_count=dependency_route.function_count;packet->callbacks_complete=dependency_route.callbacks_complete;
    packet->owner_pinned=dependency_route.owner_pinned;packet->protections_restored=dependency_route.protections_restored;
    packet->scope_flags=dependency_route.scope_flags;packet->incomplete=dependency_route.incomplete;
}
struct ErrorPair {DWORD win32;int wsa;};
static ErrorPair errors(){const DWORD win32=GetLastError();const int wsa=WSAGetLastError();return {win32,wsa};}
static void errors_restore(ErrorPair saved){WSASetLastError(saved.wsa);SetLastError(saved.win32);}
struct ListenerCollector {ListenerPacket* packet;bool inside;uint32_t depth;uint64_t parents[16];};
static __declspec(thread) ListenerCollector listener_collector={};
struct Collector {
    WsaPacket* packet;bool inside;ListenerPacket* timeline;
    uint32_t pending_count;ListenerDependencyLink pending[16];
};
static __declspec(thread) Collector collector={};
struct DependencyErrors {
    bool dual;ErrorPair incoming,outgoing;
    DependencyErrors():dual(collector.timeline!=nullptr),incoming{},outgoing{}{
        incoming.win32=GetLastError();if(dual)incoming.wsa=WSAGetLastError();
    }
    void forward(bool active){if(active)collector.inside=false;if(dual)errors_restore(incoming);else SetLastError(incoming.win32);}
    DWORD returned(){outgoing.win32=GetLastError();if(dual)outgoing.wsa=WSAGetLastError();return outgoing.win32;}
    ~DependencyErrors(){if(dual)errors_restore(outgoing);}
};
static uint64_t timeline_next(ListenerPacket* packet){
    if(packet->next_sequence==UINT64_MAX){packet->overflow=1;packet->incomplete=1;return 0;}
    return ++packet->next_sequence;
}
static uint64_t listener_parent(){return listener_collector.depth?listener_collector.parents[listener_collector.depth-1]:0;}
static uint64_t timeline_enter(ListenerPacket* packet){
    const uint64_t listeners=listener_collector.packet==packet?listener_collector.depth:0;
    const uint64_t dependencies=collector.timeline==packet?collector.pending_count:0;
    // Leave a RETURN ordinal for every already-active frame and this entry.
    if(UINT64_MAX-packet->next_sequence<listeners+dependencies+2){packet->overflow=1;packet->incomplete=1;return 0;}
    return timeline_next(packet);
}
static void dependency_link_finish(const WsaEntry* entry,bool first){
    auto* packet=collector.timeline;if(!packet)return;
    ListenerDependencyLink link={};
    for(uint32_t index=0;index<collector.pending_count;++index){
        if(collector.pending[index].dependency_sequence!=entry->sequence)continue;
        link=collector.pending[index];
        for(uint32_t next=index+1;next<collector.pending_count;++next)collector.pending[next-1]=collector.pending[next];
        --collector.pending_count;break;
    }
    timeline_next(packet); // RETURN consumes the same clock as listener ENTER/RETURN.
    if(!link.timeline_sequence){packet->incomplete=1;return;}
    if(first)packet->first_dependency_failure_link=link;
    if(packet->dependency_link_count<16)packet->dependency_links[packet->dependency_link_count++]=link;
    else {
        for(size_t index=1;index<16;++index)packet->dependency_links[index-1]=packet->dependency_links[index];
        packet->dependency_links[15]=link;
        if(packet->dependency_links_dropped!=UINT32_MAX)++packet->dependency_links_dropped;
        packet->overflow=1;packet->incomplete=1;
    }
}
static uint32_t increment(uint32_t value) {return value==UINT32_MAX?value:value+1;}
static bool live(WsaPacket* packet) {
    LARGE_INTEGER now={},frequency={};
    if (!QueryPerformanceCounter(&now)) {
        const auto error=GetLastError();if(!packet->setup_error){packet->setup_error=error;packet->setup_stage=2;}packet->clock_live=0;return false;
    }
    if (!QueryPerformanceFrequency(&frequency)) {
        const auto error=GetLastError();if(!packet->setup_error){packet->setup_error=error;packet->setup_stage=2;}packet->clock_live=0;return false;
    }
    const bool valid=now.QuadPart>=0&&frequency.QuadPart>0&&static_cast<uint64_t>(frequency.QuadPart)==packet->frequency;
    packet->clock_live=valid&&static_cast<uint64_t>(now.QuadPart)<packet->cutoff_qpc;
    if (!packet->clock_live && !packet->setup_error) {packet->setup_error=valid?ERROR_TIMEOUT:ERROR_INVALID_DATA;packet->setup_stage=2;}
    return packet->clock_live!=0;
}
static bool begin(WsaEntry* entry,uint32_t operation,DWORD incoming) {
    auto* packet=collector.packet;
    if (!packet) return false;
    if (collector.inside||listener_collector.inside) {packet->incomplete=1;return false;}
    collector.inside=true;
    if (!live(packet)) {packet->incomplete=1;collector.packet=nullptr;collector.inside=false;return false;}
    if(packet->total_calls==UINT32_MAX){packet->overflow=1;packet->incomplete=1;collector.packet=nullptr;collector.inside=false;return false;}
    if(collector.timeline){
        auto* timeline=collector.timeline;
        if(collector.pending_count==16){timeline->overflow=1;timeline->incomplete=1;collector.inside=false;return false;}
        const auto sequence=timeline_enter(timeline);
        if(!sequence){collector.inside=false;return false;}
        collector.pending[collector.pending_count++]={static_cast<uint64_t>(packet->total_calls)+1,sequence,listener_parent()};
    }
    packet->total_calls=increment(packet->total_calls);
    entry->sequence=packet->total_calls;entry->operation=operation;entry->thread_id=GetCurrentThreadId();
    entry->incoming_error=incoming;entry->entered=1;
    return true;
}
static void name(WsaEntry* entry,const WCHAR* value,size_t units,bool terminated) {
    __try {
        if (!value) {entry->name_flags=units?2:0;return;}
        if (!terminated && units>UINT32_MAX/2) {entry->name_flags=2;return;}
        if (!terminated) entry->reported_name_bytes=static_cast<uint32_t>(units*2);
        const size_t limit=terminated?256:(units<256?units:256);
        size_t index=0;
        for (;index<limit;++index) {
            const auto unit=value[index];
            if (terminated && !unit) break;
            entry->name[index]=unit;
        }
        entry->copied_name_units=static_cast<uint32_t>(index);entry->name_flags=1;
        if ((terminated && index==256) || (!terminated && units>256)) entry->name_flags|=4;
        if (terminated) entry->reported_name_bytes=static_cast<uint32_t>(index*2);
    } __except(EXCEPTION_EXECUTE_HANDLER) {entry->name_flags|=2;}
}
static void unicode(WsaEntry* entry,PUNICODE_STRING value) {
    __try {
        if (!value) return;
        if (value->Length%2 || value->Length>value->MaximumLength) {entry->name_flags=2;return;}
        if (!value->Length) {entry->name_flags=1;return;}
        name(entry,value->Buffer,value->Length/2,false);
    } __except(EXCEPTION_EXECUTE_HANDLER) {entry->name_flags|=2;}
}
static void attributes(WsaEntry* entry,POBJECT_ATTRIBUTES value) {
    __try {
        if (!value) return;
        if (value->Length!=sizeof(OBJECT_ATTRIBUTES)) {entry->name_flags=2;return;}
        entry->raw_root=reinterpret_cast<uintptr_t>(value->RootDirectory);entry->flags=value->Attributes;entry->scalar_flags|=4;
        unicode(entry,value->ObjectName);
    } __except(EXCEPTION_EXECUTE_HANDLER) {entry->name_flags|=2;}
}
static void output(WsaEntry* entry,void** value) {
    const bool inside=collector.inside;collector.inside=true;
    __try {if(value){entry->raw_output=reinterpret_cast<uintptr_t>(*value);entry->output_flags=1|(*value?2:0);}}
    __except(EXCEPTION_EXECUTE_HANDLER) {entry->output_flags=0;}
    collector.inside=inside;
}
static uint64_t size_input(const SIZE_T* value,WsaEntry* entry,uint32_t bit) {
    const bool inside=collector.inside;collector.inside=true;uint64_t result=0;
    __try {if(value){result=*value;entry->scalar_flags|=bit;}} __except(EXCEPTION_EXECUTE_HANDLER) {}
    collector.inside=inside;return result;
}
static uint32_t dword_input(const DWORD* value,WsaEntry* entry,uint32_t bit) {
    const bool inside=collector.inside;collector.inside=true;uint32_t result=0;
    __try {if(value){result=*value;entry->scalar_flags|=bit;}} __except(EXCEPTION_EXECUTE_HANDLER) {}
    collector.inside=inside;return result;
}
static void finish(WsaEntry* entry,bool active,int32_t status,DWORD outgoing,bool failed) {
    auto* packet=collector.packet;
    if (!active || !packet) return;
    collector.inside=true;entry->returned=1;entry->native_status=status;entry->outgoing_error=outgoing;
    if(failed) {
        packet->total_failures=increment(packet->total_failures);
        if(packet->total_failures==UINT32_MAX){packet->overflow=1;packet->incomplete=1;}
    }
    const bool first=failed&&!packet->first_failure_present;
    if(first){packet->first_failure=*entry;packet->first_failure_present=1;}
    dependency_link_finish(entry,first);
    if(packet->record_count<16) packet->entries[packet->record_count++]=*entry;
    else {
        for(size_t index=1;index<16;++index) packet->entries[index-1]=packet->entries[index];
        packet->entries[15]=*entry;packet->overflow=1;packet->dropped=increment(packet->dropped);packet->incomplete=1;
    }
    collector.inside=false;
}
template<class T> static T original(size_t operation){return reinterpret_cast<T>(originals[operation-1].load(std::memory_order_acquire));}
using NtOpen=NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES);
static NTSTATUS NTAPI open_key(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attr){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,1,incoming);
    if(active){entry.desired_access=access;attributes(&entry,attr);}saved.forward(active);
    const auto result=original<NtOpen>(1)(out,access,attr);const DWORD error=saved.returned();
    if(active&&result>=0)output(&entry,reinterpret_cast<void**>(out));finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using NtOpenEx=NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,ULONG);
static NTSTATUS NTAPI open_key_ex(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attr,ULONG options){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,2,incoming);
    if(active){entry.desired_access=access;entry.secondary_size=options;entry.scalar_flags=2;attributes(&entry,attr);}saved.forward(active);
    const auto result=original<NtOpenEx>(2)(out,access,attr,options);const DWORD error=saved.returned();
    if(active&&result>=0)output(&entry,reinterpret_cast<void**>(out));finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using NtQuery=NTSTATUS(NTAPI*)(HANDLE,PUNICODE_STRING,ULONG,PVOID,ULONG,PULONG);
static NTSTATUS NTAPI query_value(HANDLE key,PUNICODE_STRING value,ULONG type,PVOID buffer,ULONG length,PULONG required){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,3,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(key);entry.requested_size=length;entry.secondary_size=type;entry.scalar_flags=3;unicode(&entry,value);}saved.forward(active);
    const auto result=original<NtQuery>(3)(key,value,type,buffer,length,required);const DWORD error=saved.returned();
    finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using Load=NTSTATUS(NTAPI*)(PWSTR,PULONG,PUNICODE_STRING,PHANDLE);
static NTSTATUS NTAPI load_dll(PWSTR search,PULONG flags,PUNICODE_STRING value,PHANDLE out){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,4,incoming);
    if(active){unicode(&entry,value);entry.flags=dword_input(flags,&entry,4);}saved.forward(active);
    const auto result=original<Load>(4)(search,flags,value,out);const DWORD error=saved.returned();
    if(active&&result>=0)output(&entry,reinterpret_cast<void**>(out));finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using NtCreate=NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,ULONG,BOOLEAN);
static NTSTATUS NTAPI create_event(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attr,ULONG type,BOOLEAN state){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,5,incoming);
    if(active){entry.desired_access=access;entry.requested_size=type;entry.secondary_size=state;entry.scalar_flags=3;attributes(&entry,attr);}saved.forward(active);
    const auto result=original<NtCreate>(5)(out,access,attr,type,state);const DWORD error=saved.returned();
    if(active&&result>=0)output(&entry,reinterpret_cast<void**>(out));finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
static NTSTATUS NTAPI open_event(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attr){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,6,incoming);
    if(active){entry.desired_access=access;attributes(&entry,attr);}saved.forward(active);
    const auto result=original<NtOpen>(6)(out,access,attr);const DWORD error=saved.returned();
    if(active&&result>=0)output(&entry,reinterpret_cast<void**>(out));finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
static NTSTATUS NTAPI open_directory(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attr){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,7,incoming);
    if(active){entry.desired_access=access;attributes(&entry,attr);}saved.forward(active);
    const auto result=original<NtOpen>(7)(out,access,attr);const DWORD error=saved.returned();
    if(active&&result>=0)output(&entry,reinterpret_cast<void**>(out));finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using NtAllocate=NTSTATUS(NTAPI*)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
static NTSTATUS NTAPI allocate(HANDLE process,PVOID* base,ULONG_PTR zero,PSIZE_T size,ULONG type,ULONG protection){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,8,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(process);entry.requested_size=size_input(size,&entry,1);entry.flags=type;entry.scalar_flags|=4;entry.desired_access=protection;}saved.forward(active);
    const auto result=original<NtAllocate>(8)(process,base,zero,size,type,protection);const DWORD error=saved.returned();
    if(active&&result>=0){output(&entry,base);entry.secondary_size=size_input(size,&entry,2);}finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using Heap=void*(NTAPI*)(void*,ULONG,SIZE_T);
static void* NTAPI heap(void* handle,ULONG flags,SIZE_T size){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,9,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(handle);entry.requested_size=size;entry.scalar_flags=5;entry.flags=flags;}saved.forward(active);
    void* result=original<Heap>(9)(handle,flags,size);const DWORD error=saved.returned();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
static LSTATUS WINAPI reg_open(HKEY key,LPCWSTR value,DWORD options,REGSAM access,PHKEY out){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,10,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(key);entry.desired_access=access;entry.flags=options;entry.scalar_flags=4;name(&entry,value,0,true);}saved.forward(active);
    const auto result=original<decltype(&RegOpenKeyExW)>(10)(key,value,options,access,out);const DWORD error=saved.returned();
    if(active&&result==ERROR_SUCCESS)output(&entry,reinterpret_cast<void**>(out));finish(&entry,active,result,error,result!=ERROR_SUCCESS);SetLastError(error);return result;
}
static LSTATUS WINAPI reg_query(HKEY key,LPCWSTR value,LPDWORD reserved,LPDWORD type,LPBYTE data,LPDWORD length){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,11,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(key);entry.requested_size=dword_input(length,&entry,1);name(&entry,value,0,true);}saved.forward(active);
    const auto result=original<decltype(&RegQueryValueExW)>(11)(key,value,reserved,type,data,length);const DWORD error=saved.returned();
    finish(&entry,active,result,error,result!=ERROR_SUCCESS);SetLastError(error);return result;
}
static HMODULE WINAPI load_library(LPCWSTR value,HANDLE file,DWORD flags){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,12,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(file);entry.flags=flags;entry.scalar_flags=4;name(&entry,value,0,true);}saved.forward(active);
    const auto result=original<decltype(&LoadLibraryExW)>(12)(value,file,flags);const DWORD error=saved.returned();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
static HANDLE WINAPI create_event_w(LPSECURITY_ATTRIBUTES security,BOOL reset,BOOL state,LPCWSTR value){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,13,incoming);
    if(active){entry.requested_size=reset;entry.secondary_size=state;entry.scalar_flags=3;name(&entry,value,0,true);}saved.forward(active);
    const auto result=original<decltype(&CreateEventW)>(13)(security,reset,state,value);const DWORD error=saved.returned();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
static HANDLE WINAPI open_event_w(DWORD access,BOOL inherit,LPCWSTR value){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,14,incoming);
    if(active){entry.desired_access=access;entry.flags=inherit;entry.scalar_flags=4;name(&entry,value,0,true);}saved.forward(active);
    const auto result=original<decltype(&OpenEventW)>(14)(access,inherit,value);const DWORD error=saved.returned();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
static void* WINAPI heap_alloc(HANDLE handle,DWORD flags,SIZE_T size){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,15,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(handle);entry.flags=flags;entry.requested_size=size;entry.scalar_flags=5;}saved.forward(active);
    const auto result=original<decltype(&HeapAlloc)>(15)(handle,flags,size);const DWORD error=saved.returned();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
static void* WINAPI virtual_alloc(LPVOID base,SIZE_T size,DWORD type,DWORD protection){
    DependencyErrors saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin(&entry,16,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(base);entry.flags=type;entry.desired_access=protection;entry.scalar_flags=5;}saved.forward(active);
    const auto result=original<decltype(&VirtualAlloc)>(16)(base,size,type,protection);const DWORD error=saved.returned();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
struct Hook {const char* name;void* target;};
static const Hook hooks[16]={
    {"NtOpenKey",reinterpret_cast<void*>(open_key)},{"NtOpenKeyEx",reinterpret_cast<void*>(open_key_ex)},
    {"NtQueryValueKey",reinterpret_cast<void*>(query_value)},{"LdrLoadDll",reinterpret_cast<void*>(load_dll)},
    {"NtCreateEvent",reinterpret_cast<void*>(create_event)},{"NtOpenEvent",reinterpret_cast<void*>(open_event)},
    {"NtOpenDirectoryObject",reinterpret_cast<void*>(open_directory)},{"NtAllocateVirtualMemory",reinterpret_cast<void*>(allocate)},
    {"RtlAllocateHeap",reinterpret_cast<void*>(heap)},{"RegOpenKeyExW",reinterpret_cast<void*>(reg_open)},
    {"RegQueryValueExW",reinterpret_cast<void*>(reg_query)},{"LoadLibraryExW",reinterpret_cast<void*>(load_library)},
    {"CreateEventW",reinterpret_cast<void*>(create_event_w)},{"OpenEventW",reinterpret_cast<void*>(open_event_w)},
    {"HeapAlloc",reinterpret_cast<void*>(heap_alloc)},{"VirtualAlloc",reinterpret_cast<void*>(virtual_alloc)}
};

struct Image {uintptr_t base,end,imports,imports_end,iat,iat_end;uint32_t size,timestamp,machine;};
static bool range(uintptr_t first,size_t bytes,uintptr_t begin,uintptr_t end){return first>=begin&&first<=end&&bytes<=end-first;}
static bool readable(uintptr_t first,size_t bytes,const Image& image){
    if(!range(first,bytes,image.base,image.end))return false;
    MEMORY_BASIC_INFORMATION memory={};
    if(VirtualQuery(reinterpret_cast<void*>(first),&memory,sizeof(memory))!=sizeof(memory))return false;
    const auto base=reinterpret_cast<uintptr_t>(memory.BaseAddress);
    return memory.RegionSize<=UINTPTR_MAX-base && memory.State==MEM_COMMIT && memory.Type==MEM_IMAGE &&
        memory.AllocationBase==reinterpret_cast<void*>(image.base) && !(memory.Protect&(PAGE_GUARD|PAGE_NOACCESS)) && range(first,bytes,base,base+memory.RegionSize);
}
static uint32_t machine(){
#if defined(_M_ARM64)
    return IMAGE_FILE_MACHINE_ARM64;
#elif defined(_M_X64)
    return IMAGE_FILE_MACHINE_AMD64;
#else
#error Unsupported WSA trace architecture
#endif
}
static bool image(HMODULE module,Image* result){
    __try {
        const auto base=reinterpret_cast<uintptr_t>(module);MEMORY_BASIC_INFORMATION memory={};
        if(VirtualQuery(module,&memory,sizeof(memory))!=sizeof(memory)||memory.State!=MEM_COMMIT||memory.Type!=MEM_IMAGE||memory.AllocationBase!=module||(memory.Protect&(PAGE_GUARD|PAGE_NOACCESS)))return false;
        auto* dos=reinterpret_cast<IMAGE_DOS_HEADER*>(module);
        if(dos->e_magic!=IMAGE_DOS_SIGNATURE||dos->e_lfanew<0||dos->e_lfanew>1024*1024)return false;
        auto* nt=reinterpret_cast<IMAGE_NT_HEADERS64*>(base+dos->e_lfanew);
        if(nt->Signature!=IMAGE_NT_SIGNATURE||nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC||nt->FileHeader.Machine!=machine()||
            nt->FileHeader.SizeOfOptionalHeader<sizeof(IMAGE_OPTIONAL_HEADER64)||nt->OptionalHeader.NumberOfRvaAndSizes<=IMAGE_DIRECTORY_ENTRY_IAT)return false;
        const auto size=nt->OptionalHeader.SizeOfImage;
        if(!size||base>UINTPTR_MAX-size)return false;
        Image value={base,base+size,0,0,0,0,size,nt->FileHeader.TimeDateStamp,nt->FileHeader.Machine};
        if(!readable(reinterpret_cast<uintptr_t>(nt),sizeof(*nt),value))return false;
        const auto imports=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        const auto iat=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
        if(!imports.VirtualAddress||!imports.Size||!iat.VirtualAddress||!iat.Size||imports.VirtualAddress>size||imports.Size>size-imports.VirtualAddress||iat.VirtualAddress>size||iat.Size>size-iat.VirtualAddress)return false;
        value.imports=base+imports.VirtualAddress;value.imports_end=value.imports+imports.Size;
        value.iat=base+iat.VirtualAddress;value.iat_end=value.iat+iat.Size;*result=value;return true;
    } __except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
static bool bounded_name(const char* value,const Image& image){
    for(size_t index=0;index<128;++index){if(!readable(reinterpret_cast<uintptr_t>(value)+index,1,image))return false;if(!value[index])return true;}return false;
}
static bool equals(const char* value,const char* expected,const Image& image){
    for(size_t index=0;index<128;++index){if(!readable(reinterpret_cast<uintptr_t>(value)+index,1,image)||value[index]!=expected[index])return false;if(!expected[index])return true;}return false;
}
static bool executable(void* entry,HMODULE owner){
    MEMORY_BASIC_INFORMATION memory={};
    return VirtualQuery(entry,&memory,sizeof(memory))==sizeof(memory)&&memory.State==MEM_COMMIT&&memory.Type==MEM_IMAGE&&memory.AllocationBase==owner&&
        (memory.Protect==PAGE_EXECUTE_READ||memory.Protect==PAGE_EXECUTE_READWRITE||memory.Protect==PAGE_EXECUTE_WRITECOPY);
}
static bool capture_node_data(HMODULE module,void* entry,WsaNode* node,Image* mapped,uint32_t* incomplete){
    if(!image(module,mapped)||!executable(entry,module))return false;
    node->owner_base=reinterpret_cast<uintptr_t>(module);node->entry=reinterpret_cast<uintptr_t>(entry);
    node->owner_size=mapped->size;node->timestamp=mapped->timestamp;node->machine=mapped->machine;
    const DWORD name_units=GetModuleFileNameW(module,reinterpret_cast<WCHAR*>(node->module_name),64);
    if(!name_units||name_units>=64)*incomplete=1;
    __try {
        const auto start=reinterpret_cast<uintptr_t>(entry);MEMORY_BASIC_INFORMATION memory={};
        if(VirtualQuery(entry,&memory,sizeof(memory))!=sizeof(memory))return false;
        const auto base=reinterpret_cast<uintptr_t>(memory.BaseAddress);
        if(memory.RegionSize>UINTPTR_MAX-base)return false;
        const auto end=base+memory.RegionSize<mapped->end?base+memory.RegionSize:mapped->end;
        if(start>=end)return false;
        const size_t available=end-start;node->entry_len=static_cast<uint32_t>(available<16?available:16);
        for(size_t index=0;index<node->entry_len;++index)node->entry_bytes[index]=reinterpret_cast<uint8_t*>(entry)[index];
        return node->entry_len>0;
    } __except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
static bool capture_node(HMODULE module,void* entry,WsaNode* node,Image* mapped,WsaPacket* packet){return capture_node_data(module,entry,node,mapped,&packet->incomplete);}
struct Discovery {Image image;WsaPacket* packet;HMODULE descriptor;DWORD error;void** wsa_slot;void* wsa_target;uint32_t wsa_matches;};
static bool bounded_imports(Discovery* state){
    __try {
        const auto& image=state->image;size_t functions=0;
        for(size_t index=0;index<256;++index){
            if(!live(state->packet))return false;
            const auto address=image.imports+index*sizeof(IMAGE_IMPORT_DESCRIPTOR);
            if(!range(address,sizeof(IMAGE_IMPORT_DESCRIPTOR),image.imports,image.imports_end)||!readable(address,sizeof(IMAGE_IMPORT_DESCRIPTOR),image))return false;
            auto* descriptor=reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(address);
            if(!descriptor->OriginalFirstThunk)return !descriptor->FirstThunk&&!descriptor->Name&&!descriptor->TimeDateStamp&&!descriptor->ForwarderChain;
            if(!descriptor->FirstThunk||!descriptor->Name||!bounded_name(reinterpret_cast<char*>(image.base+descriptor->Name),image))return false;
            for(size_t thunk=0;thunk<4096;++thunk){
                if(++functions>16384||!live(state->packet))return false;
                const auto address=image.base+descriptor->OriginalFirstThunk+thunk*sizeof(IMAGE_THUNK_DATA64);
                if(!readable(address,sizeof(IMAGE_THUNK_DATA64),image))return false;
                const auto value=reinterpret_cast<IMAGE_THUNK_DATA64*>(address)->u1.Ordinal;
                if(!value)break;
                const auto slot=image.base+descriptor->FirstThunk+thunk*sizeof(void*);
                if(!range(slot,sizeof(void*),image.iat,image.iat_end)||!readable(slot,sizeof(void*),image))return false;
                if(!IMAGE_SNAP_BY_ORDINAL64(value)&&(value>UINT32_MAX||!readable(image.base+static_cast<uint32_t>(value),sizeof(WORD)+1,image)||!bounded_name(reinterpret_cast<char*>(image.base+static_cast<uint32_t>(value)+sizeof(WORD)),image)))return false;
                if(thunk==4095)return false;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER){return false;}
    return false;
}
static BOOL CALLBACK import_file(void* context,HMODULE module,LPCSTR name){
    auto* state=static_cast<Discovery*>(context);
    if(!name){state->packet->callbacks_complete=state->error==ERROR_SUCCESS;return FALSE;}
    if(state->error)return FALSE;
    if(++state->packet->descriptor_count>512||!live(state->packet)){state->error=ERROR_BUFFER_OVERFLOW;return FALSE;}
    state->descriptor=module;return TRUE;
}
static BOOL CALLBACK import_function(void* context,DWORD,LPCSTR name,void** slot){
    auto* state=static_cast<Discovery*>(context);auto* packet=state->packet;
    if(!slot)return state->error==ERROR_SUCCESS;
    if(state->error)return FALSE;
    if(++packet->function_count>32768||!live(packet)){state->error=ERROR_BUFFER_OVERFLOW;return FALSE;}
    if(!name)return TRUE;
    if(!bounded_name(name,state->image)){state->error=ERROR_INVALID_DATA;return FALSE;}
    const auto address=reinterpret_cast<uintptr_t>(slot);
    if(equals(name,"WSAStartup",state->image)){
        ++state->wsa_matches;
        if(!range(address,sizeof(void*),state->image.iat,state->image.iat_end)||address%alignof(void*)||!readable(address,sizeof(void*),state->image)){state->error=ERROR_INVALID_ADDRESS;return FALSE;}
        state->wsa_slot=slot;state->wsa_target=*slot;
    }
    for(size_t operation=0;operation<16;++operation){
        if(!equals(name,hooks[operation].name,state->image))continue;
        for(size_t index=0;index<packet->slot_count;++index)if(packet->slots[index].operation==operation+1){state->error=ERROR_DUP_NAME;return FALSE;}
        if(packet->slot_count==16||!range(address,sizeof(void*),state->image.iat,state->image.iat_end)||address%alignof(void*)||!readable(address,sizeof(void*),state->image)){state->error=ERROR_INVALID_ADDRESS;return FALSE;}
        auto* selected=&packet->slots[packet->slot_count++];selected->slot=address;selected->original=reinterpret_cast<uintptr_t>(*slot);selected->operation=static_cast<uint32_t>(operation+1);selected->descriptor_module=reinterpret_cast<uintptr_t>(state->descriptor);
        HMODULE target=nullptr;
        if(!state->descriptor||GetProcAddress(state->descriptor,hooks[operation].name)!=reinterpret_cast<FARPROC>(*slot)||
            !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(*slot),&target)||!executable(*slot,target)){
            packet->scope_flags|=2;packet->incomplete=1;continue;
        }
        selected->hook=reinterpret_cast<uintptr_t>(hooks[operation].target);
    }
    return TRUE;
}
static bool discover(Discovery* state){
    state->packet->callbacks_complete=0;
    if(!bounded_imports(state)){state->error=state->packet->setup_error?state->packet->setup_error:ERROR_INVALID_DATA;return false;}
    SetLastError(ERROR_SUCCESS);
    const auto complete=DetourEnumerateImportsEx(reinterpret_cast<HMODULE>(state->image.base),state,import_file,import_function);
    const auto error=GetLastError();
    if(!complete&&!state->error)state->error=error?error:ERROR_INVALID_DATA;
    return complete&&state->packet->callbacks_complete&&!state->error;
}
static size_t verified(const WsaPacket* packet){size_t count=0;for(size_t index=0;index<packet->slot_count;++index)if(packet->slots[index].hook)++count;return count;}
extern "C" uint32_t memcordon_decode_import_entry(uint32_t,uint64_t,const uint8_t*,size_t,uint64_t*);
static bool route_live(const WsaPacket* packet){
    __try {
        if(!packet->node_count||packet->node_count>2)return false;
        for(size_t index=0;index<packet->node_count;++index){
            const auto& node=packet->nodes[index];Image mapped={};
            if(!image(reinterpret_cast<HMODULE>(node.owner_base),&mapped)||mapped.size!=node.owner_size||mapped.timestamp!=node.timestamp||!executable(reinterpret_cast<void*>(node.entry),reinterpret_cast<HMODULE>(node.owner_base)))return false;
            if(!node.entry_len||node.entry_len>16||!readable(node.entry,node.entry_len,mapped))return false;
            for(size_t byte=0;byte<node.entry_len;++byte)if(reinterpret_cast<uint8_t*>(node.entry)[byte]!=node.entry_bytes[byte])return false;
            if(index+1<packet->node_count){
                if(!node.slot||node.slot%alignof(void*)||!range(node.slot,sizeof(void*),mapped.iat,mapped.iat_end)||!readable(node.slot,sizeof(void*),mapped)||*reinterpret_cast<void**>(node.slot)!=reinterpret_cast<void*>(node.target)||node.target!=packet->nodes[index+1].entry)return false;
            }
        }
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
struct Page {void* base;SIZE_T size;DWORD original;bool writable;};
static bool data_page(void** slot,const Image& image,Page* page){
    MEMORY_BASIC_INFORMATION memory={};SYSTEM_INFO system={};GetSystemInfo(&system);
    const auto address=reinterpret_cast<uintptr_t>(slot),size=static_cast<uintptr_t>(system.dwPageSize);
    if(!size||address%alignof(void*)||!range(address,sizeof(void*),image.iat,image.iat_end)||address/size!=(address+sizeof(void*)-1)/size||VirtualQuery(slot,&memory,sizeof(memory))!=sizeof(memory)||memory.State!=MEM_COMMIT||memory.Type!=MEM_IMAGE||memory.AllocationBase!=reinterpret_cast<void*>(image.base)||
        (memory.Protect!=PAGE_READONLY&&memory.Protect!=PAGE_READWRITE&&memory.Protect!=PAGE_WRITECOPY))return false;
    const auto base=address-address%size;if(!range(base,size,image.base,image.end))return false;
    *page={reinterpret_cast<void*>(base),size,memory.Protect,false};return true;
}
static void failure(WsaPacket* packet,uint32_t stage,DWORD error){if(!packet->setup_error){packet->setup_stage=stage;packet->setup_error=error?error:ERROR_INVALID_DATA;}packet->incomplete=1;}
static void restore(Page* pages,size_t count,WsaPacket* packet){
    for(size_t index=0;index<count;++index){
        if(!pages[index].writable)continue;DWORD changed=0;
        if(!VirtualProtect(pages[index].base,pages[index].size,pages[index].original,&changed)){packet->rollback_error=GetLastError();failure(packet,7,packet->rollback_error);__fastfail(FAST_FAIL_FATAL_APP_EXIT);}
        if(changed!=PAGE_READWRITE){packet->rollback_error=ERROR_RETRY;failure(packet,7,ERROR_RETRY);__fastfail(FAST_FAIL_FATAL_APP_EXIT);}
        pages[index].writable=false;
    }
    packet->protections_restored=1;
}
static bool writable(Page* pages,size_t count,WsaPacket* packet){
    for(size_t index=0;index<count;++index){
        DWORD previous=0;
        if(!live(packet)){failure(packet,2,packet->setup_error);restore(pages,count,packet);return false;}
        if(!VirtualProtect(pages[index].base,pages[index].size,PAGE_READWRITE,&previous)){const auto error=GetLastError();failure(packet,6,error);restore(pages,count,packet);return false;}
        pages[index].writable=true;
        if(previous!=pages[index].original){pages[index].original=previous;failure(packet,6,ERROR_RETRY);restore(pages,count,packet);return false;}
    }
    return true;
}
static void* swap(void** slot,void* replacement,void* expected){return InterlockedCompareExchangePointer(slot,replacement,expected);}
static bool publish(WsaPacket* packet,const Image& image){
    Page pages[16]={};size_t count=0;
    for(size_t index=0;index<packet->slot_count;++index){
        auto& selected=packet->slots[index];if(!selected.hook)continue;Page page={};
        if(!data_page(reinterpret_cast<void**>(selected.slot),image,&page)){failure(packet,5,ERROR_INVALID_ADDRESS);return false;}
        bool present=false;for(size_t old=0;old<count;++old)if(pages[old].base==page.base)present=true;
        if(!present)pages[count++]=page;
        originals[selected.operation-1].store(reinterpret_cast<void*>(selected.original),std::memory_order_release);
    }
    if(!writable(pages,count,packet))return false;
    bool success=route_live(packet);
    if(!success)failure(packet,6,ERROR_RETRY);
    for(size_t index=0;success&&index<packet->slot_count;++index){
        auto& selected=packet->slots[index];if(!selected.hook)continue;
        if(!live(packet)||swap(reinterpret_cast<void**>(selected.slot),reinterpret_cast<void*>(selected.hook),reinterpret_cast<void*>(selected.original))!=reinterpret_cast<void*>(selected.original)){
            failure(packet,6,packet->setup_error?packet->setup_error:ERROR_RETRY);success=false;break;
        }
        selected.published=1;
    }
    if(!success){
        for(size_t index=packet->slot_count;index>0;--index){
            auto& selected=packet->slots[index-1];if(!selected.published)continue;
            if(swap(reinterpret_cast<void**>(selected.slot),reinterpret_cast<void*>(selected.original),reinterpret_cast<void*>(selected.hook))!=reinterpret_cast<void*>(selected.hook)){
                packet->rollback_error=ERROR_RETRY;__fastfail(FAST_FAIL_FATAL_APP_EXIT);
            }
            selected.published=0;selected.restored=1;
        }
    }
    restore(pages,count,packet);return success;
}
static bool install(WsaPacket* packet,void* entry){
    if(InterlockedCompareExchange(&installed,1,0)!=0){failure(packet,9,ERROR_BUSY);return false;}
    HMODULE owner=nullptr;Image mapped={};
    if(!live(packet)){failure(packet,2,packet->setup_error);InterlockedExchange(&installed,3);return false;}
    if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(entry),&owner)){
        const DWORD error=GetLastError();packet->setup_reason=1;failure(packet,3,error);InterlockedExchange(&installed,3);return false;
    }
    packet->owner_pinned=1;packet->nodes[0].owner_base=reinterpret_cast<uintptr_t>(owner);packet->nodes[0].entry=reinterpret_cast<uintptr_t>(entry);packet->node_count=1;
    const auto exported=GetProcAddress(owner,"WSAStartup");const DWORD export_error=exported?ERROR_SUCCESS:GetLastError();
    if(exported!=reinterpret_cast<FARPROC>(entry)){
        packet->setup_reason=2;failure(packet,3,exported?ERROR_INVALID_DATA:(export_error?export_error:ERROR_PROC_NOT_FOUND));InterlockedExchange(&installed,3);return false;
    }
    if(!capture_node(owner,entry,&packet->nodes[0],&mapped,packet)){
        packet->setup_reason=3;failure(packet,3,ERROR_INVALID_DATA);InterlockedExchange(&installed,3);return false;
    }
    Discovery state={mapped,packet,nullptr,0,nullptr,nullptr,0};
    bool complete=discover(&state);
    if(complete&&!verified(packet)){
        auto& node=packet->nodes[0];uint64_t decoded=0;
        if(state.wsa_matches!=1||!state.wsa_slot||!state.wsa_target||state.wsa_target==entry||
            memcordon_decode_import_entry(machine(),node.entry,node.entry_bytes,node.entry_len,&decoded)!=0||decoded!=reinterpret_cast<uintptr_t>(state.wsa_slot)){
            failure(packet,8,ERROR_NOT_SUPPORTED);InterlockedExchange(&installed,3);return false;
        }
        HMODULE next=nullptr;
        if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(state.wsa_target),&next)){
            const DWORD error=GetLastError();packet->setup_reason=4;failure(packet,8,error);InterlockedExchange(&installed,3);return false;
        }
        if(next==owner){packet->setup_reason=5;failure(packet,8,ERROR_INVALID_DATA);InterlockedExchange(&installed,3);return false;}
        const auto exported=GetProcAddress(next,"WSAStartup");const DWORD error=exported?ERROR_SUCCESS:GetLastError();
        if(exported!=reinterpret_cast<FARPROC>(state.wsa_target)||!capture_node(next,state.wsa_target,&packet->nodes[1],&mapped,packet)){
            packet->setup_reason=6;failure(packet,8,exported?ERROR_INVALID_DATA:(error?error:ERROR_PROC_NOT_FOUND));InterlockedExchange(&installed,3);return false;
        }
        node.slot=reinterpret_cast<uintptr_t>(state.wsa_slot);node.target=reinterpret_cast<uintptr_t>(state.wsa_target);packet->node_count=2;packet->hop_count=1;packet->scope_flags|=4;
        packet->slot_count=0;for(auto& slot:packet->slots)slot={};
        state={mapped,packet,nullptr,0,nullptr,nullptr,0};complete=discover(&state);
    }
    bool success=complete&&verified(packet)&&route_live(packet);
    if(!success)failure(packet,4,state.error?state.error:ERROR_PROC_NOT_FOUND);
    if(success)success=publish(packet,mapped);
    if(success){packet->setup_stage=1;packet->setup_error=0;save_dependency_route(packet);}
    InterlockedExchange(&installed,success?2:3);return success;
}
static void invoke(WsaPacket* packet,uintptr_t original_entry,uint16_t requested){
    const DWORD incoming=packet->incoming_error;
    if(!live(packet)){failure(packet,2,packet->setup_error);SetLastError(incoming);return;}
    if(packet->setup_stage==1){
        bool unchanged=route_live(packet);
        for(size_t index=0;index<packet->slot_count;++index){auto& slot=packet->slots[index];if(slot.published&&*reinterpret_cast<void**>(slot.slot)!=reinterpret_cast<void*>(slot.hook))unchanged=false;}
        if(!unchanged)failure(packet,6,ERROR_RETRY);
    }
    collector={};collector.packet=packet->setup_stage==1?packet:nullptr;packet->armed=collector.packet?1:0;
    WSADATA data={};using Startup=int(WSAAPI*)(WORD,LPWSADATA);const auto original_startup=reinterpret_cast<Startup>(original_entry);
    SetLastError(incoming);
    const int returned=original_startup(requested,&data);
    const DWORD outgoing=GetLastError(); // Before TLS disarm, clocks, SPI or retention.
    collector.packet=nullptr;collector.inside=false;
    packet->called=1;packet->original_return=returned;packet->negotiated_version=returned==0?data.wVersion:0;packet->outgoing_error=outgoing;
    LARGE_INTEGER finished={};
    if(QueryPerformanceCounter(&finished)&&finished.QuadPart>=0)packet->finished_qpc=static_cast<uint64_t>(finished.QuadPart);else packet->incomplete=1;
    if(!live(packet))packet->incomplete=1;
    SetLastError(outgoing);
}
extern "C" void memcordon_wsa_trace_call(WsaPacket* packet,uintptr_t original_entry,uint16_t requested,uint64_t cutoff,uint64_t frequency){
    const DWORD incoming=GetLastError();
    *packet={};packet->version=1;packet->requested_version=requested;packet->cutoff_qpc=cutoff;packet->frequency=frequency;packet->incoming_error=incoming;packet->scope_flags=1;
    LARGE_INTEGER started={};const BOOL initial_clock=QueryPerformanceCounter(&started);
    if(initial_clock&&started.QuadPart>=0)packet->started_qpc=static_cast<uint64_t>(started.QuadPart);
    else {const DWORD error=initial_clock?ERROR_INVALID_DATA:GetLastError();failure(packet,2,error);}
    packet->original_thread=GetCurrentThreadId();
    if(initial_clock&&started.QuadPart>=0)install(packet,reinterpret_cast<void*>(original_entry));
    invoke(packet,original_entry,requested);
}

static std::atomic<void*> listener_originals[7]={};
static volatile LONG listener_installed=0;
struct ListenerPrivateRoute {void* targets[7];};
// Only populated by the exclusive, pre-publication native mock. It never writes
// the permanent originals that live IAT forwarders may already be executing.
static std::atomic<const ListenerPrivateRoute*> listener_private_route{nullptr};
template<class T> static T listener_original(size_t operation){
    const auto* mock=listener_private_route.load(std::memory_order_acquire);
    void* target=mock?mock->targets[operation-1]:listener_originals[operation-1].load(std::memory_order_acquire);
    if(!target)__fastfail(FAST_FAIL_FATAL_APP_EXIT);
    return reinterpret_cast<T>(target);
}
static void listener_failure(ListenerPacket* packet,uint32_t stage,DWORD error){
    if(!packet->setup_error){packet->setup_stage=stage;packet->setup_error=error?error:ERROR_INVALID_DATA;}
    packet->incomplete=1;
}
static bool listener_live(ListenerPacket* packet,bool admission=false){
    LARGE_INTEGER now={},frequency={};
    if(!QueryPerformanceCounter(&now)||!QueryPerformanceFrequency(&frequency)){
        const DWORD error=GetLastError();
        if(admission){packet->setup_stage=2;packet->setup_error=error?error:ERROR_INVALID_DATA;packet->incomplete=1;}
        else listener_failure(packet,2,error);
        packet->clock_live=0;return false;
    }
    const bool valid=now.QuadPart>=0&&frequency.QuadPart>0&&static_cast<uint64_t>(frequency.QuadPart)==packet->frequency;
    packet->clock_live=valid&&static_cast<uint64_t>(now.QuadPart)<packet->cutoff_qpc;
    if(!packet->clock_live){
        const DWORD error=valid?ERROR_TIMEOUT:ERROR_INVALID_DATA;
        if(admission){packet->setup_stage=2;packet->setup_error=error;packet->incomplete=1;}
        else listener_failure(packet,2,error);
    }
    return packet->clock_live!=0;
}
static bool listener_capture(){
    auto* packet=listener_collector.packet;
    if(!packet)return false;
    if(listener_collector.inside||collector.inside){packet->incomplete=1;return false;}
    return true;
}
static bool listener_begin(ListenerEntry* entry,uint32_t operation,ErrorPair incoming){
    auto* packet=listener_collector.packet;listener_collector.inside=true;
    if(!listener_live(packet)||listener_collector.depth==16||packet->total_calls==UINT32_MAX){
        packet->incomplete=1;
        if(listener_collector.depth==16||packet->total_calls==UINT32_MAX)packet->overflow=1;
        listener_collector.inside=false;return false;
    }
    const auto sequence=timeline_enter(packet);if(!sequence){listener_collector.inside=false;return false;}
    entry->sequence=sequence;entry->parent_sequence=listener_parent();
    entry->operation=operation;entry->depth=listener_collector.depth;entry->thread_id=GetCurrentThreadId();
    entry->incoming_win32=incoming.win32;entry->incoming_wsa=incoming.wsa;entry->entered=1;
    entry->error_domain=operation==1?1:operation==3?3:2;
    listener_collector.parents[listener_collector.depth++]=sequence;
    ++packet->total_calls;packet->entered_mask|=1u<<(operation-1);return true;
}
static void listener_forward(ErrorPair incoming,bool active){if(active)listener_collector.inside=false;errors_restore(incoming);}
static void listener_finish(ListenerEntry* entry,bool active,uint64_t result,ErrorPair outgoing,bool failed){
    if(!active)return;
    auto* packet=listener_collector.packet;listener_collector.inside=true;
    entry->result=result;entry->outgoing_win32=outgoing.win32;entry->outgoing_wsa=outgoing.wsa;
    entry->returned=1;entry->failed=failed?1:0;entry->completion_sequence=timeline_next(packet);
    packet->returned_mask|=1u<<(entry->operation-1);
    if(failed){
        packet->failure_mask|=1u<<(entry->operation-1);
        packet->total_failures=increment(packet->total_failures);
        if(packet->total_failures==UINT32_MAX){packet->overflow=1;packet->incomplete=1;}
        if(!packet->first_failure_present){packet->first_failure=*entry;packet->first_failure_present=1;}
    }
    if(packet->record_count<16)packet->entries[packet->record_count++]=*entry;
    else {
        for(size_t index=1;index<16;++index)packet->entries[index-1]=packet->entries[index];
        packet->entries[15]=*entry;packet->dropped=increment(packet->dropped);packet->overflow=1;packet->incomplete=1;
    }
    if(!listener_collector.depth||listener_collector.parents[listener_collector.depth-1]!=entry->sequence)__fastfail(FAST_FAIL_FATAL_APP_EXIT);
    listener_collector.parents[--listener_collector.depth]=0;listener_collector.inside=false;
}
static void listener_input(ListenerEntry* entry,const sockaddr* address,int length){
    if(length<0){entry->input_flags=2;return;}
    const auto bytes=static_cast<uint32_t>(length);const auto limit=bytes<sizeof(entry->input_prefix)?bytes:sizeof(entry->input_prefix);
    if(bytes>sizeof(entry->input_prefix))entry->input_flags|=4;
    __try {
        for(size_t index=0;index<limit;++index){entry->input_prefix[index]=reinterpret_cast<const uint8_t*>(address)[index];++entry->input_bytes;}
        entry->input_flags|=1;
    } __except(EXCEPTION_EXECUTE_HANDLER){entry->input_flags|=2;}
}
static void listener_output(ListenerEntry* entry,LPWSADATA data){
    __try {if(data){entry->output_u32=data->wVersion;entry->output_valid=1;}}
    __except(EXCEPTION_EXECUTE_HANDLER){listener_collector.packet->incomplete=1;}
}
static int WSAAPI listener_startup(WORD requested,LPWSADATA data){
    const auto target=listener_original<decltype(&WSAStartup)>(1);if(!listener_capture())return target(requested,data);
    const auto incoming=errors();ListenerEntry entry={};const bool active=listener_begin(&entry,1,incoming);
    if(active){entry.arguments[0]=requested;entry.arguments[1]=reinterpret_cast<uintptr_t>(data);}listener_forward(incoming,active);
    const int result=target(requested,data);const auto outgoing=errors();
    if(active&&result==0){listener_collector.inside=true;listener_output(&entry,data);}
    listener_finish(&entry,active,static_cast<uint32_t>(result),outgoing,result!=0);errors_restore(outgoing);return result;
}
static SOCKET WSAAPI listener_socket(int af,int type,int protocol,LPWSAPROTOCOL_INFOW info,GROUP group,DWORD flags){
    const auto target=listener_original<decltype(&WSASocketW)>(2);if(!listener_capture())return target(af,type,protocol,info,group,flags);
    const auto incoming=errors();ListenerEntry entry={};const bool active=listener_begin(&entry,2,incoming);
    if(active){entry.arguments[0]=static_cast<uint32_t>(af);entry.arguments[1]=static_cast<uint32_t>(type);entry.arguments[2]=static_cast<uint32_t>(protocol);entry.arguments[3]=reinterpret_cast<uintptr_t>(info);entry.arguments[4]=group;entry.arguments[5]=flags;}
    listener_forward(incoming,active);const SOCKET result=target(af,type,protocol,info,group,flags);const auto outgoing=errors();
    listener_finish(&entry,active,static_cast<uint64_t>(result),outgoing,result==INVALID_SOCKET);errors_restore(outgoing);return result;
}
static BOOL WINAPI listener_handle(HANDLE handle,DWORD mask,DWORD flags){
    const auto target=listener_original<decltype(&SetHandleInformation)>(3);if(!listener_capture())return target(handle,mask,flags);
    const auto incoming=errors();ListenerEntry entry={};const bool active=listener_begin(&entry,3,incoming);
    if(active){entry.arguments[0]=reinterpret_cast<uintptr_t>(handle);entry.arguments[1]=mask;entry.arguments[2]=flags;}listener_forward(incoming,active);
    const BOOL result=target(handle,mask,flags);const auto outgoing=errors();
    listener_finish(&entry,active,static_cast<uint32_t>(result),outgoing,result==FALSE);errors_restore(outgoing);return result;
}
static int WSAAPI listener_bind(SOCKET socket,const sockaddr* address,int length){
    const auto target=listener_original<decltype(&bind)>(4);if(!listener_capture())return target(socket,address,length);
    const auto incoming=errors();ListenerEntry entry={};const bool active=listener_begin(&entry,4,incoming);
    if(active){entry.arguments[0]=static_cast<uint64_t>(socket);entry.arguments[1]=reinterpret_cast<uintptr_t>(address);entry.arguments[2]=static_cast<uint32_t>(length);listener_input(&entry,address,length);if(entry.input_flags&6)listener_collector.packet->incomplete=1;}
    listener_forward(incoming,active);const int result=target(socket,address,length);const auto outgoing=errors();
    listener_finish(&entry,active,static_cast<uint32_t>(result),outgoing,result==SOCKET_ERROR);errors_restore(outgoing);return result;
}
static int WSAAPI listener_listen(SOCKET socket,int backlog){
    const auto target=listener_original<decltype(&listen)>(5);if(!listener_capture())return target(socket,backlog);
    const auto incoming=errors();ListenerEntry entry={};const bool active=listener_begin(&entry,5,incoming);
    if(active){entry.arguments[0]=static_cast<uint64_t>(socket);entry.arguments[1]=static_cast<uint32_t>(backlog);}listener_forward(incoming,active);
    const int result=target(socket,backlog);const auto outgoing=errors();
    listener_finish(&entry,active,static_cast<uint32_t>(result),outgoing,result==SOCKET_ERROR);errors_restore(outgoing);return result;
}
static int WSAAPI listener_close(SOCKET socket){
    const auto target=listener_original<decltype(&closesocket)>(6);if(!listener_capture())return target(socket);
    const auto incoming=errors();ListenerEntry entry={};const bool active=listener_begin(&entry,6,incoming);
    if(active)entry.arguments[0]=static_cast<uint64_t>(socket);listener_forward(incoming,active);
    const int result=target(socket);const auto outgoing=errors();
    listener_finish(&entry,active,static_cast<uint32_t>(result),outgoing,result==SOCKET_ERROR);errors_restore(outgoing);return result;
}
static int WSAAPI listener_cleanup(){
    const auto target=listener_original<decltype(&WSACleanup)>(7);if(!listener_capture())return target();
    const auto incoming=errors();ListenerEntry entry={};const bool active=listener_begin(&entry,7,incoming);listener_forward(incoming,active);
    const int result=target();const auto outgoing=errors();
    listener_finish(&entry,active,static_cast<uint32_t>(result),outgoing,result==SOCKET_ERROR);errors_restore(outgoing);return result;
}
static_assert(std::is_same_v<decltype(&listener_startup),decltype(&WSAStartup)> &&
    std::is_same_v<decltype(&listener_socket),decltype(&WSASocketW)> &&
    std::is_same_v<decltype(&listener_handle),decltype(&SetHandleInformation)> &&
    std::is_same_v<decltype(&listener_bind),decltype(&bind)> &&
    std::is_same_v<decltype(&listener_listen),decltype(&listen)> &&
    std::is_same_v<decltype(&listener_close),decltype(&closesocket)> &&
    std::is_same_v<decltype(&listener_cleanup),decltype(&WSACleanup)>,"listener forwarders match SDK declarations");
static const Hook listener_hooks[7]={
    {"WSAStartup",reinterpret_cast<void*>(listener_startup)},{"WSASocketW",reinterpret_cast<void*>(listener_socket)},
    {"SetHandleInformation",reinterpret_cast<void*>(listener_handle)},{"bind",reinterpret_cast<void*>(listener_bind)},
    {"listen",reinterpret_cast<void*>(listener_listen)},{"closesocket",reinterpret_cast<void*>(listener_close)},
    {"WSACleanup",reinterpret_cast<void*>(listener_cleanup)}
};

struct ListenerRoute {
    WsaNode owner,targets[7];WsaSlot slots[16];
    uint32_t slot_count,descriptor_count,function_count,callbacks_complete;
    uint32_t owner_pinned,protections_restored,scope_flags,incomplete;
    uint32_t discovered_mask,verified_mask,published_mask;
};
static ListenerRoute listener_route={};
struct ListenerDiscovery {
    Image image;ListenerPacket* packet;HMODULE descriptor;DWORD error;
    WsaNode targets[7];uint32_t unsupported_mask;uintptr_t original_thunk,first_thunk;size_t thunk_index;
};
// An ordinal is only a representation of an already typed, uniquely identified
// SDK export. Neither the ordinal number nor a matching address alone admits it.
static size_t listener_ordinal_operation(void* resolved,void* target,void* const* exports){
    if(!resolved||resolved!=target)return 0;
    size_t selected=0;
    for(size_t operation=0;operation<7;++operation){
        if(!exports[operation]||exports[operation]!=resolved)continue;
        if(selected)return 8;
        selected=operation+1;
    }
    return selected;
}
static bool listener_bounded_imports(ListenerDiscovery* state){
    __try {
        const auto& mapped=state->image;size_t functions=0;
        for(size_t index=0;index<256;++index){
            if(!listener_live(state->packet))return false;
            const auto address=mapped.imports+index*sizeof(IMAGE_IMPORT_DESCRIPTOR);
            if(!range(address,sizeof(IMAGE_IMPORT_DESCRIPTOR),mapped.imports,mapped.imports_end)||!readable(address,sizeof(IMAGE_IMPORT_DESCRIPTOR),mapped))return false;
            const auto* descriptor=reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(address);
            if(!descriptor->OriginalFirstThunk)return !descriptor->FirstThunk&&!descriptor->Name&&!descriptor->TimeDateStamp&&!descriptor->ForwarderChain;
            if(!descriptor->FirstThunk||!descriptor->Name||!bounded_name(reinterpret_cast<const char*>(mapped.base+descriptor->Name),mapped))return false;
            for(size_t thunk=0;thunk<4096;++thunk){
                if(++functions>16384||!listener_live(state->packet))return false;
                const auto address=mapped.base+descriptor->OriginalFirstThunk+thunk*sizeof(IMAGE_THUNK_DATA64);
                if(!readable(address,sizeof(IMAGE_THUNK_DATA64),mapped))return false;
                const auto value=reinterpret_cast<const IMAGE_THUNK_DATA64*>(address)->u1.Ordinal;if(!value)break;
                const auto slot=mapped.base+descriptor->FirstThunk+thunk*sizeof(void*);
                if(!range(slot,sizeof(void*),mapped.iat,mapped.iat_end)||!readable(slot,sizeof(void*),mapped))return false;
                if(!IMAGE_SNAP_BY_ORDINAL64(value)&&(value>UINT32_MAX||!readable(mapped.base+static_cast<uint32_t>(value),sizeof(WORD)+1,mapped)||!bounded_name(reinterpret_cast<const char*>(mapped.base+static_cast<uint32_t>(value)+sizeof(WORD)),mapped)))return false;
                if(thunk==4095)return false;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER){return false;}
    return false;
}
static BOOL CALLBACK listener_import_file(void* context,HMODULE,LPCSTR name){
    auto* state=static_cast<ListenerDiscovery*>(context);
    if(!name){state->packet->callbacks_complete=state->error==ERROR_SUCCESS;return FALSE;}
    if(state->error)return FALSE;
    if(++state->packet->descriptor_count>256||!listener_live(state->packet)){state->error=state->packet->setup_error?state->packet->setup_error:ERROR_BUFFER_OVERFLOW;return FALSE;}
    __try {
        const auto address=state->image.imports+(state->packet->descriptor_count-1)*sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if(!range(address,sizeof(IMAGE_IMPORT_DESCRIPTOR),state->image.imports,state->image.imports_end)||!readable(address,sizeof(IMAGE_IMPORT_DESCRIPTOR),state->image)){state->error=ERROR_INVALID_DATA;return FALSE;}
        const auto* declared=reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(address);
        if(!declared->OriginalFirstThunk||!declared->FirstThunk||!declared->Name||reinterpret_cast<uintptr_t>(name)!=state->image.base+declared->Name||!bounded_name(name,state->image)){state->error=ERROR_INVALID_DATA;return FALSE;}
        // Detours supplies the owner of the first resolved target, which can
        // differ from the declared DLL when that first export is forwarded.
        // Resolve only this existing declared module; never load another DLL.
        state->descriptor=GetModuleHandleA(name);HMODULE pinned=nullptr;
        if(state->descriptor&&(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(state->descriptor),&pinned)||pinned!=state->descriptor))state->descriptor=nullptr;
        state->original_thunk=state->image.base+declared->OriginalFirstThunk;
        state->first_thunk=state->image.base+declared->FirstThunk;state->thunk_index=0;
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER){state->error=ERROR_INVALID_ADDRESS;state->packet->incomplete=1;return FALSE;}
}
static BOOL CALLBACK listener_import_function(void* context,DWORD ordinal,LPCSTR name,void** slot){
    auto* state=static_cast<ListenerDiscovery*>(context);auto* packet=state->packet;
    __try {
    if(state->error)return FALSE;
    if(state->thunk_index>=4096){state->error=ERROR_BUFFER_OVERFLOW;return FALSE;}
    const auto thunk_address=state->original_thunk+state->thunk_index*sizeof(IMAGE_THUNK_DATA64);
    if(!readable(thunk_address,sizeof(IMAGE_THUNK_DATA64),state->image)){state->error=ERROR_INVALID_DATA;return FALSE;}
    const auto thunk=reinterpret_cast<const IMAGE_THUNK_DATA64*>(thunk_address)->u1.Ordinal;
    if(!slot){if(thunk||ordinal||name)state->error=ERROR_INVALID_DATA;return state->error==ERROR_SUCCESS;}
    if(++packet->function_count>16384||!listener_live(packet)){state->error=packet->setup_error?packet->setup_error:ERROR_BUFFER_OVERFLOW;return FALSE;}
    const auto address=reinterpret_cast<uintptr_t>(slot);
    if(!thunk||address!=state->first_thunk+state->thunk_index*sizeof(void*)||!range(address,sizeof(void*),state->image.iat,state->image.iat_end)||!readable(address,sizeof(void*),state->image)){state->error=ERROR_INVALID_DATA;return FALSE;}
    ++state->thunk_index;
    size_t ordinal_operation=0;
    if(IMAGE_SNAP_BY_ORDINAL64(thunk)){
        if(name||!ordinal||ordinal>UINT16_MAX||IMAGE_ORDINAL64(thunk)!=ordinal||(thunk&~(IMAGE_ORDINAL_FLAG64|UINT64_C(0xffff)))){state->error=ERROR_INVALID_DATA;return FALSE;}
        if(state->descriptor){
            void* exports[7]={};for(size_t operation=0;operation<7;++operation)exports[operation]=reinterpret_cast<void*>(GetProcAddress(state->descriptor,listener_hooks[operation].name));
            void* resolved=reinterpret_cast<void*>(GetProcAddress(state->descriptor,MAKEINTRESOURCEA(static_cast<WORD>(ordinal))));
            ordinal_operation=listener_ordinal_operation(resolved,*slot,exports);
            if(!resolved||resolved!=*slot){packet->incomplete=1;packet->scope_flags|=2;}
        }else{packet->incomplete=1;packet->scope_flags|=2;}
        if(ordinal_operation>7){packet->incomplete=1;packet->scope_flags|=2;return TRUE;}
        if(!ordinal_operation)return TRUE;
    }else if(ordinal||!name||thunk>UINT32_MAX||reinterpret_cast<uintptr_t>(name)!=state->image.base+static_cast<uint32_t>(thunk)+sizeof(WORD)||!bounded_name(name,state->image)){state->error=ERROR_INVALID_DATA;return FALSE;}
    for(size_t operation=0;operation<7;++operation){
        if(ordinal_operation?ordinal_operation!=operation+1:!equals(name,listener_hooks[operation].name,state->image))continue;
        const uint32_t bit=1u<<operation;packet->discovered_mask|=bit;
        if(packet->slot_count==16){state->error=ERROR_BUFFER_OVERFLOW;return FALSE;}
        auto& selected=packet->slots[packet->slot_count++];selected.slot=address;selected.operation=static_cast<uint32_t>(operation+1);selected.descriptor_module=reinterpret_cast<uintptr_t>(state->descriptor);
        Page page={};
        if(address%alignof(void*)||!readable(address,sizeof(void*),state->image)||!data_page(slot,state->image,&page)){
            state->unsupported_mask|=bit;packet->incomplete=1;packet->scope_flags|=2;continue;
        }
        void* target=*slot;selected.original=reinterpret_cast<uintptr_t>(target);HMODULE owner=nullptr,descriptor=nullptr;Image mapped={};
        if(!state->descriptor||GetProcAddress(state->descriptor,listener_hooks[operation].name)!=reinterpret_cast<FARPROC>(target)||
            !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(state->descriptor),&descriptor)||descriptor!=state->descriptor||
            !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(target),&owner)||!executable(target,owner)){
            state->unsupported_mask|=bit;packet->incomplete=1;packet->scope_flags|=2;continue;
        }
        auto& proof=state->targets[operation];
        if((proof.entry&&proof.entry!=selected.original)||(!proof.entry&&!capture_node_data(owner,target,&proof,&mapped,&packet->incomplete))){
            state->unsupported_mask|=bit;packet->incomplete=1;packet->scope_flags|=2;continue;
        }
        selected.hook=reinterpret_cast<uintptr_t>(listener_hooks[operation].target);
    }
    return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER){state->error=ERROR_INVALID_ADDRESS;packet->incomplete=1;return FALSE;}
}
static bool listener_node_live(const WsaNode& node){
    __try {
        Image mapped={};const auto module=reinterpret_cast<HMODULE>(node.owner_base);
        if(!image(module,&mapped)||mapped.size!=node.owner_size||mapped.timestamp!=node.timestamp||mapped.machine!=node.machine||!executable(reinterpret_cast<void*>(node.entry),module)||!node.entry_len||node.entry_len>16||!readable(node.entry,node.entry_len,mapped))return false;
        for(size_t index=0;index<node.entry_len;++index)if(reinterpret_cast<const uint8_t*>(node.entry)[index]!=node.entry_bytes[index])return false;
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
static bool listener_route_live(const ListenerPacket* packet,const WsaNode* targets){
    __try {
        if(packet->slot_count>16||!listener_node_live(packet->owner))return false;
        Image mapped={};if(!image(reinterpret_cast<HMODULE>(packet->owner.owner_base),&mapped))return false;
        for(size_t operation=0;operation<7;++operation)if((packet->verified_mask&(1u<<operation))&&!listener_node_live(targets[operation]))return false;
        for(size_t index=0;index<packet->slot_count;++index){
            const auto& selected=packet->slots[index];if(!selected.hook)continue;Page page={};
            if(!selected.operation||selected.operation>7||!data_page(reinterpret_cast<void**>(selected.slot),mapped,&page)||!readable(selected.slot,sizeof(void*),mapped)||
                *reinterpret_cast<void**>(selected.slot)!=reinterpret_cast<void*>(selected.published?selected.hook:selected.original)||
                GetProcAddress(reinterpret_cast<HMODULE>(selected.descriptor_module),listener_hooks[selected.operation-1].name)!=reinterpret_cast<FARPROC>(selected.original)||
                selected.original!=targets[selected.operation-1].entry)return false;
        }
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
static void listener_restore(Page* pages,size_t count,ListenerPacket* packet){
    for(size_t index=0;index<count;++index){
        if(!pages[index].writable)continue;DWORD changed=0;
        if(!VirtualProtect(pages[index].base,pages[index].size,pages[index].original,&changed)||changed!=PAGE_READWRITE){
            packet->rollback_error=ERROR_RETRY;listener_failure(packet,7,ERROR_RETRY);__fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
        pages[index].writable=false;
    }
    packet->protections_restored=1;
}
static bool listener_writable(Page* pages,size_t count,ListenerPacket* packet){
    for(size_t index=0;index<count;++index){
        if(!listener_live(packet)){listener_restore(pages,count,packet);return false;}
        DWORD previous=0;
        if(!VirtualProtect(pages[index].base,pages[index].size,PAGE_READWRITE,&previous)){
            const auto error=GetLastError();listener_failure(packet,6,error);listener_restore(pages,count,packet);return false;
        }
        pages[index].writable=true;
        if(previous!=pages[index].original){pages[index].original=previous;listener_failure(packet,6,ERROR_RETRY);listener_restore(pages,count,packet);return false;}
    }
    return true;
}
static void listener_rollback(ListenerPacket* packet){
    for(size_t index=packet->slot_count;index>0;--index){
        auto& selected=packet->slots[index-1];if(!selected.published)continue;
        if(swap(reinterpret_cast<void**>(selected.slot),reinterpret_cast<void*>(selected.original),reinterpret_cast<void*>(selected.hook))!=reinterpret_cast<void*>(selected.hook)){
            packet->rollback_error=ERROR_RETRY;__fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
        selected.published=0;selected.restored=1;
    }
    packet->published_mask=0;
}
static bool listener_publish(ListenerPacket* packet,const Image& mapped,const WsaNode* targets){
    Page pages[16]={};size_t count=0;
    for(size_t index=0;index<packet->slot_count;++index){
        const auto& selected=packet->slots[index];if(!selected.hook)continue;Page page={};
        if(!data_page(reinterpret_cast<void**>(selected.slot),mapped,&page)){listener_failure(packet,5,ERROR_INVALID_ADDRESS);return false;}
        bool present=false;for(size_t old=0;old<count;++old)if(pages[old].base==page.base)present=true;
        if(!present)pages[count++]=page;
    }
    // Every original is immutable even if a racing thread enters a briefly
    // published slot before a later CAS forces rollback.
    for(size_t operation=0;operation<7;++operation){
        if(!(packet->verified_mask&(1u<<operation)))continue;
        void* expected=nullptr;void* target=reinterpret_cast<void*>(targets[operation].entry);
        if(!listener_originals[operation].compare_exchange_strong(expected,target,std::memory_order_acq_rel,std::memory_order_acquire)&&expected!=target){listener_failure(packet,6,ERROR_RETRY);return false;}
    }
    if(!listener_writable(pages,count,packet))return false;
    bool success=listener_route_live(packet,targets);if(!success)listener_failure(packet,6,ERROR_RETRY);
    for(size_t index=0;success&&index<packet->slot_count;++index){
        auto& selected=packet->slots[index];if(!selected.hook)continue;
        if(!listener_live(packet)||swap(reinterpret_cast<void**>(selected.slot),reinterpret_cast<void*>(selected.hook),reinterpret_cast<void*>(selected.original))!=reinterpret_cast<void*>(selected.original)){
            listener_failure(packet,6,packet->setup_error?packet->setup_error:ERROR_RETRY);success=false;break;
        }
        selected.published=1;packet->published_mask|=1u<<(selected.operation-1);
    }
    if(!success)listener_rollback(packet);
    listener_restore(pages,count,packet);return success;
}
static void listener_save_route(const ListenerPacket* packet,const WsaNode* targets){
    listener_route.owner=packet->owner;
    for(size_t index=0;index<7;++index)listener_route.targets[index]=targets[index];
    for(size_t index=0;index<16;++index)listener_route.slots[index]=packet->slots[index];
    listener_route.slot_count=packet->slot_count;listener_route.descriptor_count=packet->descriptor_count;listener_route.function_count=packet->function_count;
    listener_route.callbacks_complete=packet->callbacks_complete;listener_route.owner_pinned=packet->owner_pinned;listener_route.protections_restored=packet->protections_restored;
    listener_route.scope_flags=packet->scope_flags;listener_route.incomplete=packet->incomplete;
    listener_route.discovered_mask=packet->discovered_mask;listener_route.verified_mask=packet->verified_mask;listener_route.published_mask=packet->published_mask;
}
static void listener_copy_route(ListenerPacket* packet){
    packet->owner=listener_route.owner;for(size_t index=0;index<16;++index)packet->slots[index]=listener_route.slots[index];
    packet->slot_count=listener_route.slot_count;packet->descriptor_count=listener_route.descriptor_count;packet->function_count=listener_route.function_count;
    packet->callbacks_complete=listener_route.callbacks_complete;packet->owner_pinned=listener_route.owner_pinned;packet->protections_restored=listener_route.protections_restored;
    packet->scope_flags=listener_route.scope_flags;packet->incomplete|=listener_route.incomplete;
    packet->discovered_mask=listener_route.discovered_mask;packet->verified_mask=listener_route.verified_mask;packet->published_mask=listener_route.published_mask;
}
static bool listener_install(ListenerPacket* packet,void* anchor){
    const LONG state=InterlockedCompareExchange(&listener_installed,1,0);
    if(state==2){
        listener_copy_route(packet);
        if(packet->owner.entry!=reinterpret_cast<uintptr_t>(anchor)||!listener_route_live(packet,listener_route.targets)){listener_failure(packet,6,ERROR_RETRY);return false;}
        packet->setup_stage=1;return true;
    }
    if(state!=0){listener_failure(packet,9,state==1?ERROR_BUSY:ERROR_NOT_SUPPORTED);packet->scope_flags|=2;return false;}
    HMODULE owner=nullptr;Image mapped={};bool success=false;
    if(!listener_live(packet)){InterlockedExchange(&listener_installed,3);return false;}
    if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(anchor),&owner))listener_failure(packet,3,GetLastError());
    else {
        packet->owner_pinned=1;
        if(!capture_node_data(owner,anchor,&packet->owner,&mapped,&packet->incomplete))listener_failure(packet,3,ERROR_INVALID_DATA);
        else {
            ListenerDiscovery discovery={};discovery.image=mapped;discovery.packet=packet;
            bool complete=listener_bounded_imports(&discovery);
            if(complete){
                SetLastError(ERROR_SUCCESS);
                complete=DetourEnumerateImportsEx(owner,&discovery,listener_import_file,listener_import_function)!=FALSE;
                const DWORD error=GetLastError();if(!complete&&!discovery.error)discovery.error=error?error:ERROR_INVALID_DATA;
            }
            for(size_t index=0;index<packet->slot_count;++index){
                auto& selected=packet->slots[index];const uint32_t bit=1u<<(selected.operation-1);
                if(discovery.unsupported_mask&bit)selected.hook=0;
                if(selected.hook)packet->verified_mask|=bit;
            }
            if(!complete||!packet->callbacks_complete||discovery.error||!packet->verified_mask)listener_failure(packet,4,discovery.error?discovery.error:ERROR_PROC_NOT_FOUND);
            else if(listener_route_live(packet,discovery.targets)){
                success=listener_publish(packet,mapped,discovery.targets);
                if(success){
                    packet->setup_stage=1;packet->setup_error=0;
                    if(packet->discovered_mask!=0x7f||packet->verified_mask!=packet->discovered_mask){packet->scope_flags|=2;packet->incomplete=1;}
                    listener_save_route(packet,discovery.targets);
                }
            }else listener_failure(packet,4,ERROR_RETRY);
        }
    }
    if(packet->discovered_mask!=0x7f||packet->verified_mask!=packet->discovered_mask){packet->scope_flags|=2;packet->incomplete=1;}
    // Route cache and immutable originals precede this release publication.
    InterlockedExchange(&listener_installed,success?2:3);return success;
}
static bool dependency_route_live(const WsaPacket* packet){
    __try {
        if(packet->slot_count>16||!route_live(packet))return false;
        Image mapped={};if(!image(reinterpret_cast<HMODULE>(packet->nodes[packet->node_count-1].owner_base),&mapped))return false;
        for(size_t index=0;index<packet->slot_count;++index){
            const auto& selected=packet->slots[index];if(!selected.hook)continue;Page page={};
            if(!selected.published||!selected.operation||selected.operation>16||!data_page(reinterpret_cast<void**>(selected.slot),mapped,&page)||!readable(selected.slot,sizeof(void*),mapped)||
                *reinterpret_cast<void**>(selected.slot)!=reinterpret_cast<void*>(selected.hook)||
                originals[selected.operation-1].load(std::memory_order_acquire)!=reinterpret_cast<void*>(selected.original)||
                GetProcAddress(reinterpret_cast<HMODULE>(selected.descriptor_module),hooks[selected.operation-1].name)!=reinterpret_cast<FARPROC>(selected.original))return false;
        }
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
static void begin_listener_dependencies(ListenerPacket* packet){
    auto* dependencies=&packet->dependencies;*dependencies={};
    dependencies->version=1;dependencies->cutoff_qpc=packet->cutoff_qpc;dependencies->frequency=packet->frequency;
    dependencies->incoming_error=packet->incoming_win32;dependencies->original_thread=packet->original_thread;
    const LONG state=InterlockedCompareExchange(&installed,0,0);
    if(state!=2){packet->dependency_scope_error=state==1?ERROR_BUSY:ERROR_NOT_SUPPORTED;packet->incomplete=1;return;}
    copy_dependency_route(dependencies);
    if(!dependency_route_live(dependencies)){
        packet->dependency_scope_error=ERROR_RETRY;failure(dependencies,6,ERROR_RETRY);packet->incomplete=1;return;
    }
    dependencies->setup_stage=1;dependencies->armed=1;packet->dependency_scope_armed=1;
}
static void end_listener_dependencies(ListenerPacket* packet){
    if(collector.timeline==packet){
        if(collector.pending_count){packet->incomplete=1;packet->dependencies.incomplete=1;}
        collector={};
    }
    if(packet->dependencies.incomplete)packet->incomplete=1;
}
static void listener_invoke(ListenerPacket* packet,const ListenerRequest* request,ListenerInvoke callback,void* opaque,bool ready){
    // Admission is the same original-work QPC cutoff; observation unavailability
    // never supplies a second reason to suppress or retry the Rust aggregate.
    if(!listener_live(packet,true)){errors_restore({request->incoming_win32,request->incoming_wsa});return;}
    const ListenerCollector previous_listener=listener_collector;const Collector previous_dependencies=collector;
    const bool occupied=previous_listener.packet||previous_dependencies.packet;
    listener_collector={};collector={};
    if(occupied){
        if(previous_listener.packet)previous_listener.packet->incomplete=1;
        if(previous_dependencies.packet)previous_dependencies.packet->incomplete=1;
        if(previous_dependencies.timeline)previous_dependencies.timeline->incomplete=1;
        listener_failure(packet,9,ERROR_BUSY);ready=false;packet->dependency_scope_error=ERROR_BUSY;
    }
    else {
        begin_listener_dependencies(packet);
        if(ready&&!listener_route_live(packet,listener_route.targets)){listener_failure(packet,6,ERROR_RETRY);ready=false;}
    }
    LARGE_INTEGER started={};
    const BOOL clock=QueryPerformanceCounter(&started);
    if(!clock||started.QuadPart<0||static_cast<uint64_t>(started.QuadPart)>=packet->cutoff_qpc){
        const DWORD error=!clock?GetLastError():started.QuadPart<0?ERROR_INVALID_DATA:ERROR_TIMEOUT;
        packet->setup_stage=2;packet->setup_error=error?error:ERROR_INVALID_DATA;packet->incomplete=1;
        packet->clock_live=0;packet->dependency_scope_armed=0;packet->dependencies.armed=0;
        listener_collector=previous_listener;collector=previous_dependencies;
        errors_restore({request->incoming_win32,request->incoming_wsa});return;
    }
    packet->started_qpc=static_cast<uint64_t>(started.QuadPart);
    packet->dependencies.started_qpc=packet->started_qpc;
    ListenerOutcome outcome={};packet->called=1;
    if(ready)listener_collector.packet=packet;
    if(packet->dependency_scope_armed){collector.packet=&packet->dependencies;collector.timeline=packet;}
    packet->armed=ready?1:0;
    errors_restore({request->incoming_win32,request->incoming_wsa});
    callback(opaque,&outcome);
    const auto outgoing=errors(); // Before disarm, clocks or scalar projection.
    listener_collector={};end_listener_dependencies(packet);
    listener_collector=previous_listener;collector=previous_dependencies;
    packet->outgoing_win32=outgoing.win32;packet->outgoing_wsa=outgoing.wsa;
    packet->dependencies.outgoing_error=outgoing.win32;
    LARGE_INTEGER finished={};
    if(QueryPerformanceCounter(&finished)&&finished.QuadPart>=0)packet->finished_qpc=static_cast<uint64_t>(finished.QuadPart);else packet->incomplete=1;
    packet->dependencies.finished_qpc=packet->finished_qpc;
    if(!outcome.kind||outcome.kind>3||outcome.raw_error_present>1||outcome.reserved)__fastfail(FAST_FAIL_FATAL_APP_EXIT);
    packet->callback_outcome=outcome.kind;packet->callback_raw_error_present=outcome.raw_error_present;packet->callback_raw_error=outcome.raw_error;
    if(outcome.kind==3)packet->incomplete=1;
    if(!listener_live(packet))packet->incomplete=1;
    errors_restore(outgoing);
}
extern "C" void memcordon_listener_trace_call(ListenerPacket* packet,const ListenerRequest* request,ListenerInvoke callback,void* opaque){
    if(!packet||!request||!callback)__fastfail(FAST_FAIL_FATAL_APP_EXIT);
    *packet={};packet->version=1;packet->scope_flags=1;
    packet->cutoff_qpc=request->cutoff_qpc;packet->frequency=request->frequency;
    packet->incoming_win32=request->incoming_win32;packet->incoming_wsa=request->incoming_wsa;
    packet->original_thread=GetCurrentThreadId();packet->listener_owner_anchor=reinterpret_cast<uintptr_t>(callback);
    const bool ready=listener_install(packet,reinterpret_cast<void*>(callback));
    listener_invoke(packet,request,callback,opaque,ready);
}

struct Mock {std::atomic<uint32_t> calls,heaps;DWORD expected_error;PHANDLE output;POBJECT_ATTRIBUTES attributes;std::atomic<bool> same;};
static std::atomic<Mock*> fixture_mock{nullptr};
struct MockScope {
    void* key_original;void* heap_original;
    ~MockScope(){collector.packet=nullptr;collector.inside=false;fixture_mock.store(nullptr,std::memory_order_release);originals[0].store(key_original,std::memory_order_release);originals[8].store(heap_original,std::memory_order_release);}
};
static NTSTATUS NTAPI mock_open(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attributes){
    auto* state=fixture_mock.load(std::memory_order_acquire);++state->calls;
    state->same=state->same&&out==state->output&&access==0xF&&attributes==state->attributes&&GetLastError()==state->expected_error;
    SetLastError(0x12345678);return static_cast<NTSTATUS>(0xC0000022u);
}
static void* NTAPI mock_heap(void* handle,ULONG flags,SIZE_T size){
    auto* state=fixture_mock.load(std::memory_order_acquire);++state->heaps;
    state->same=state->same&&handle==reinterpret_cast<void*>(0x3210)&&flags==0x1234&&size==(UINT64_C(1)<<40)&&GetLastError()==state->expected_error;
    SetLastError(0x87654321);return nullptr;
}
static DWORD WINAPI mock_thread(void*){
    SetLastError(0xCAFE);
    const auto result=heap(reinterpret_cast<void*>(0x3210),0x1234,UINT64_C(1)<<40);
    return !result&&GetLastError()==0x87654321?0:1;
}
static int WSAAPI mock_startup(WORD requested,LPWSADATA data){
    auto* state=fixture_mock.load(std::memory_order_acquire);++state->calls;
    state->same=state->same&&requested==0x0202&&data&&GetLastError()==state->expected_error;
    if(data)data->wVersion=0xBEEF;SetLastError(0x33445566);return 10107;
}
extern "C" uint32_t memcordon_wsa_trace_mock(uint64_t cutoff,uint64_t frequency){
    if(InterlockedCompareExchange(&installed,0,0)!=0)return 1;
    MockScope scope={originals[0].load(std::memory_order_acquire),originals[8].load(std::memory_order_acquire)};
    WsaPacket packet={};packet.cutoff_qpc=cutoff;packet.frequency=frequency;packet.original_thread=GetCurrentThreadId();
    if(!live(&packet))return 2;
    WCHAR raw[]={0xD800,0,0xDC00};UNICODE_STRING value={sizeof(raw),sizeof(raw),raw};
    OBJECT_ATTRIBUTES attributes={sizeof(OBJECT_ATTRIBUTES),reinterpret_cast<HANDLE>(0x8888),&value,0x40,nullptr,nullptr};
    HANDLE output_handle=reinterpret_cast<HANDLE>(0x7777);
    Mock state={};state.expected_error=0xCAFE;state.output=&output_handle;state.attributes=&attributes;state.same=true;fixture_mock.store(&state,std::memory_order_release);
    originals[0].store(reinterpret_cast<void*>(mock_open),std::memory_order_release);originals[8].store(reinterpret_cast<void*>(mock_heap),std::memory_order_release);
    collector.packet=&packet;
    SetLastError(0xCAFE);const auto denied=open_key(&output_handle,0xF,&attributes);const auto error=GetLastError();
    if(denied!=static_cast<NTSTATUS>(0xC0000022u)||error!=0x12345678||output_handle!=reinterpret_cast<HANDLE>(0x7777)||packet.first_failure.output_flags!=0)return 3;
    for(size_t index=0;index<20;++index){
        SetLastError(0xCAFE);if(heap(reinterpret_cast<void*>(0x3210),0x1234,UINT64_C(1)<<40)||GetLastError()!=0x87654321)return 4;
    }
    if(!state.same||state.calls!=1||state.heaps!=20||packet.total_calls!=21||packet.total_failures!=21||packet.record_count!=16||packet.dropped!=5||packet.first_failure.sequence!=1||packet.first_failure.raw_root!=0x8888||packet.first_failure.copied_name_units!=3||packet.first_failure.name[0]!=0xD800||packet.first_failure.name[2]!=0xDC00||packet.entries[15].requested_size!=(UINT64_C(1)<<40)||packet.entries[15].scalar_flags!=5)return 5;
    // Instrumentation-internal reentry forwards but must not recursively record.
    collector.inside=true;SetLastError(0xCAFE);
    const auto recursive=heap(reinterpret_cast<void*>(0x3210),0x1234,UINT64_C(1)<<40);
    const DWORD recursive_error=GetLastError();collector.inside=false;
    if(recursive||recursive_error!=0x87654321||state.heaps!=21||packet.total_calls!=21)return 14;
    // A different caller thread forwards but cannot write the original caller's TLS packet.
    HANDLE thread=CreateThread(nullptr,0,mock_thread,nullptr,0,nullptr);if(!thread)return 6;
    LARGE_INTEGER now={};if(!QueryPerformanceCounter(&now)||now.QuadPart<0||static_cast<uint64_t>(now.QuadPart)>=cutoff){CloseHandle(thread);__fastfail(FAST_FAIL_FATAL_APP_EXIT);}
    const uint64_t ticks=cutoff-static_cast<uint64_t>(now.QuadPart);
    if(ticks>UINT64_MAX/1000){CloseHandle(thread);__fastfail(FAST_FAIL_FATAL_APP_EXIT);}
    const uint64_t remaining=ticks*1000/frequency;
    const DWORD waited=WaitForSingleObject(thread,remaining>MAXDWORD-1?MAXDWORD-1:static_cast<DWORD>(remaining));
    if(waited!=WAIT_OBJECT_0){CloseHandle(thread);__fastfail(FAST_FAIL_FATAL_APP_EXIT);}
    DWORD status=1;const BOOL queried=GetExitCodeThread(thread,&status);CloseHandle(thread);
    collector.packet=nullptr;
    if(!queried||status||!state.same||state.heaps!=22||packet.total_calls!=21)return 7;
    // Exercise the same protected data-page CAS/restore primitives on owned
    // private storage; this is not a claim of a valid real module/IAT route.
    SYSTEM_INFO system={};GetSystemInfo(&system);
    void* memory=VirtualAlloc(nullptr,system.dwPageSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!memory)return 8;
    auto** slot=static_cast<void**>(memory);*slot=reinterpret_cast<void*>(mock_open);DWORD previous=0;
    if(!VirtualProtect(memory,system.dwPageSize,PAGE_READONLY,&previous)){VirtualFree(memory,0,MEM_RELEASE);return 9;}
    Page page={memory,system.dwPageSize,PAGE_READONLY,false};Image invalid={reinterpret_cast<uintptr_t>(memory),reinterpret_cast<uintptr_t>(memory)+system.dwPageSize,0,0,reinterpret_cast<uintptr_t>(memory),reinterpret_cast<uintptr_t>(memory)+sizeof(void*),system.dwPageSize,0,machine()};Page refused={};
    if(data_page(slot,invalid,&refused)){VirtualFree(memory,0,MEM_RELEASE);return 10;}
    if(!writable(&page,1,&packet)){VirtualFree(memory,0,MEM_RELEASE);return 11;}
    bool good=swap(slot,reinterpret_cast<void*>(open_key),reinterpret_cast<void*>(mock_open))==reinterpret_cast<void*>(mock_open)&&*slot==reinterpret_cast<void*>(open_key);
    good=good&&swap(slot,reinterpret_cast<void*>(mock_open),reinterpret_cast<void*>(open_key))==reinterpret_cast<void*>(open_key);
    good=good&&swap(slot,reinterpret_cast<void*>(open_key),reinterpret_cast<void*>(mock_heap))==reinterpret_cast<void*>(mock_open)&&*slot==reinterpret_cast<void*>(mock_open);
    restore(&page,1,&packet);MEMORY_BASIC_INFORMATION restored={};
    good=good&&VirtualQuery(memory,&restored,sizeof(restored))==sizeof(restored)&&restored.Protect==PAGE_READONLY;
    const BOOL freed=VirtualFree(memory,0,MEM_RELEASE);if(!good||!freed)return 12;
    originals[0].store(nullptr,std::memory_order_release);originals[8].store(nullptr,std::memory_order_release);
    // Unsupported setup must still forward the one original immutable call.
    state.expected_error=0xABCD;SetLastError(0xABCD);WsaPacket call={};
    call.version=1;call.setup_stage=8;call.setup_error=ERROR_NOT_SUPPORTED;call.incomplete=1;call.cutoff_qpc=cutoff;call.frequency=frequency;call.incoming_error=0xABCD;
    invoke(&call,reinterpret_cast<uintptr_t>(mock_startup),0x0202);
    const DWORD outgoing=GetLastError();
    if(!state.same||state.calls!=2||call.called!=1||call.original_return!=10107||call.negotiated_version||call.armed||call.setup_stage==1||outgoing!=0x33445566||call.incoming_error!=0xABCD||call.outgoing_error!=0x33445566||!live(&packet))return 13;
    return 0;
}

struct ListenerMock {
    std::atomic<uint32_t> calls[7];std::atomic<bool> same;
    ErrorPair incoming,outgoing;LPWSADATA data;LPWSAPROTOCOL_INFOW info;
    const sockaddr* address;int length;bool fail[7];bool nested,dependency;
};
static std::atomic<ListenerMock*> listener_mock{nullptr};
static constexpr SOCKET listener_mock_socket=static_cast<SOCKET>(UINT64_C(0xfedcba9876543210));
static HANDLE listener_mock_handle(){return reinterpret_cast<HANDLE>(UINT64_C(0x8877665544332211));}
static bool same_errors(ErrorPair left,ErrorPair right){return left.win32==right.win32&&left.wsa==right.wsa;}
static ErrorPair seed_listener_error(DWORD value){WSASetLastError(static_cast<int>(value));SetLastError(value);return errors();}
static ListenerMock* listener_mock_enter(size_t operation){
    const auto incoming=errors();auto* state=listener_mock.load(std::memory_order_acquire);
    if(!state)__fastfail(FAST_FAIL_FATAL_APP_EXIT);
    ++state->calls[operation-1];if(!same_errors(incoming,state->incoming))state->same=false;return state;
}
static void listener_mock_return(ListenerMock* state){errors_restore(state->outgoing);}
static int WSAAPI listener_mock_startup(WORD version,LPWSADATA data){
    auto* state=listener_mock_enter(1);if(version!=0x202||data!=state->data)state->same=false;
    // Write on both return paths to prove failed-call output is never valid.
    if(data)data->wVersion=0xbeef;
    listener_mock_return(state);return state->fail[0]?10107:0;
}
static SOCKET WSAAPI listener_mock_socket_call(int af,int type,int protocol,LPWSAPROTOCOL_INFOW info,GROUP group,DWORD flags){
    auto* state=listener_mock_enter(2);
    if(af!=-2||type!=3||protocol!=-4||info!=state->info||group!=0xfedcba98||flags!=0x80000001)state->same=false;
    listener_mock_return(state);return state->fail[1]?INVALID_SOCKET:listener_mock_socket;
}
static BOOL WINAPI listener_mock_handle_call(HANDLE handle,DWORD mask,DWORD flags){
    auto* state=listener_mock_enter(3);if(handle!=listener_mock_handle()||mask!=0x87654321||flags!=0x12345678)state->same=false;
    listener_mock_return(state);return state->fail[2]?FALSE:static_cast<BOOL>(0x23456789);
}
static int WSAAPI listener_mock_bind_call(SOCKET socket,const sockaddr* address,int length){
    auto* state=listener_mock_enter(4);
    if(socket!=listener_mock_socket||address!=state->address||length!=state->length)state->same=false;
    if(state->nested&&listener_listen(socket,-128)!=(state->fail[4]?SOCKET_ERROR:0))state->same=false;
    listener_mock_return(state);return state->fail[3]?SOCKET_ERROR:0;
}
static int WSAAPI listener_mock_listen_call(SOCKET socket,int backlog){
    auto* state=listener_mock_enter(5);if(socket!=listener_mock_socket||backlog!=-128)state->same=false;
    if(state->dependency){
        WsaEntry entry={};const bool active=begin(&entry,3,state->incoming.win32);
        if(active)collector.inside=false;
        finish(&entry,active,static_cast<int32_t>(0xc0000022u),state->outgoing.win32,true);
    }
    listener_mock_return(state);return state->fail[4]?SOCKET_ERROR:0;
}
static int WSAAPI listener_mock_close_call(SOCKET socket){
    auto* state=listener_mock_enter(6);if(socket!=listener_mock_socket)state->same=false;
    listener_mock_return(state);return state->fail[5]?SOCKET_ERROR:0;
}
static int WSAAPI listener_mock_cleanup_call(){
    auto* state=listener_mock_enter(7);listener_mock_return(state);return state->fail[6]?SOCKET_ERROR:0;
}
struct ListenerMockScope {
    ListenerCollector previous_listener;Collector previous_dependencies;
    ~ListenerMockScope(){
        listener_collector=previous_listener;collector=previous_dependencies;
        listener_private_route.store(nullptr,std::memory_order_release);listener_mock.store(nullptr,std::memory_order_release);
        // No real route was published, and permanent originals were never set.
        InterlockedExchange(&listener_installed,0);
    }
};
static void listener_mock_packet(ListenerPacket* packet,uint64_t cutoff,uint64_t frequency){
    *packet={};packet->version=1;packet->cutoff_qpc=cutoff;packet->frequency=frequency;packet->original_thread=GetCurrentThreadId();
    listener_collector={};listener_collector.packet=packet;collector={};
}
static void listener_mock_dependencies(ListenerPacket* packet){
    packet->dependencies={};packet->dependencies.version=1;
    packet->dependencies.cutoff_qpc=packet->cutoff_qpc;packet->dependencies.frequency=packet->frequency;
    collector={};collector.packet=&packet->dependencies;collector.timeline=packet;
}
static DWORD WINAPI listener_mock_thread(void*){
    auto* state=listener_mock.load(std::memory_order_acquire);errors_restore(state->incoming);
    const int result=listener_close(listener_mock_socket);const auto outgoing=errors();
    return result==(state->fail[5]?SOCKET_ERROR:0)&&same_errors(outgoing,state->outgoing)&&!listener_collector.packet&&!collector.packet?0:1;
}
static void listener_mock_callback(void* opaque,ListenerOutcome* outcome){
    auto* state=static_cast<ListenerMock*>(opaque);
    if(listener_close(listener_mock_socket)!=(state->fail[5]?SOCKET_ERROR:0))state->same=false;
    *outcome={2,1,2,0};
}
extern "C" uint32_t memcordon_listener_trace_mock(uint64_t cutoff,uint64_t frequency){
    if(InterlockedCompareExchange(&listener_installed,1,0)!=0)return 1;
    ListenerMockScope scope={listener_collector,collector};
    for(const auto& original:listener_originals)if(original.load(std::memory_order_acquire))return 1;
    ListenerPacket packet={};listener_mock_packet(&packet,cutoff,frequency);if(!listener_live(&packet))return 2;
    ListenerMock state={};state.same=true;WSADATA data={};uint8_t address[40]={};
    for(size_t index=0;index<sizeof(address);++index)address[index]=static_cast<uint8_t>(index+1);
    state.data=&data;state.info=reinterpret_cast<LPWSAPROTOCOL_INFOW>(0x1234);state.address=reinterpret_cast<const sockaddr*>(address);state.length=sizeof(address);
    state.incoming=seed_listener_error(0x4321);state.outgoing=seed_listener_error(0x5678);
    const ListenerPrivateRoute private_route={{reinterpret_cast<void*>(listener_mock_startup),reinterpret_cast<void*>(listener_mock_socket_call),reinterpret_cast<void*>(listener_mock_handle_call),reinterpret_cast<void*>(listener_mock_bind_call),reinterpret_cast<void*>(listener_mock_listen_call),reinterpret_cast<void*>(listener_mock_close_call),reinterpret_cast<void*>(listener_mock_cleanup_call)}};
    // Exercise the production ordinal-to-typed-export join without publishing
    // any slot. A wrong resolution/slot/module export set or ambiguous alias
    // must never select a forwarder, even when one address happens to match.
    void* exports[7]={};for(size_t operation=0;operation<7;++operation)exports[operation]=private_route.targets[operation];
    for(size_t operation=0;operation<7;++operation){
        if(listener_ordinal_operation(exports[operation],exports[operation],exports)!=operation+1)return 17;
        if(listener_ordinal_operation(exports[operation],exports[(operation+1)%7],exports))return 17;
    }
    if(listener_ordinal_operation(nullptr,exports[0],exports))return 17;
    void* foreign[7]={};if(listener_ordinal_operation(exports[0],exports[0],foreign))return 17;
    exports[1]=exports[0];if(listener_ordinal_operation(exports[0],exports[0],exports)!=8)return 17;
    listener_mock.store(&state,std::memory_order_release);listener_private_route.store(&private_route,std::memory_order_release);
    errors_restore(state.incoming);const int startup=listener_startup(0x202,&data);const auto startup_errors=errors();
    errors_restore(state.incoming);const SOCKET socket=listener_socket(-2,3,-4,state.info,0xfedcba98,0x80000001);const auto socket_errors=errors();
    errors_restore(state.incoming);const BOOL handle=listener_handle(listener_mock_handle(),0x87654321,0x12345678);const auto handle_errors=errors();
    errors_restore(state.incoming);const int bound=listener_bind(listener_mock_socket,state.address,state.length);const auto bind_errors=errors();
    errors_restore(state.incoming);const int listened=listener_listen(listener_mock_socket,-128);const auto listen_errors=errors();
    errors_restore(state.incoming);const int closed=listener_close(listener_mock_socket);const auto close_errors=errors();
    errors_restore(state.incoming);const int cleanup=listener_cleanup();const auto cleanup_errors=errors();
    if(startup||socket!=listener_mock_socket||handle!=static_cast<BOOL>(0x23456789)||bound||listened||closed||cleanup||!state.same||data.wVersion!=0xbeef)return 3;
    if(!same_errors(startup_errors,state.outgoing)||!same_errors(socket_errors,state.outgoing)||!same_errors(handle_errors,state.outgoing)||!same_errors(bind_errors,state.outgoing)||!same_errors(listen_errors,state.outgoing)||!same_errors(close_errors,state.outgoing)||!same_errors(cleanup_errors,state.outgoing))return 4;
    if(packet.total_calls!=7||packet.total_failures||packet.first_failure_present||packet.entered_mask!=0x7f||packet.returned_mask!=0x7f||packet.failure_mask||packet.next_sequence!=14||packet.record_count!=7)return 5;
    for(size_t index=0;index<7;++index){
        const auto& entry=packet.entries[index];
        if(state.calls[index]!=1||entry.operation!=index+1||entry.flags||entry.depth||entry.parent_sequence||entry.sequence!=index*2+1||entry.completion_sequence!=index*2+2||entry.error_domain!=(index==0?1:index==2?3:2)||entry.failed||!same_errors({entry.incoming_win32,entry.incoming_wsa},state.incoming)||!same_errors({entry.outgoing_win32,entry.outgoing_wsa},state.outgoing))return 5;
    }
    if(packet.entries[0].arguments[1]!=reinterpret_cast<uintptr_t>(&data)||!packet.entries[0].output_valid||packet.entries[0].output_u32!=0xbeef||packet.entries[1].result!=static_cast<uint64_t>(listener_mock_socket)||packet.entries[1].arguments[0]!=static_cast<uint32_t>(-2)||packet.entries[1].arguments[2]!=static_cast<uint32_t>(-4)||packet.entries[1].arguments[3]!=reinterpret_cast<uintptr_t>(state.info)||packet.entries[2].arguments[0]!=reinterpret_cast<uintptr_t>(listener_mock_handle())||packet.entries[3].input_bytes!=32||packet.entries[3].input_flags!=5)return 6;
    for(size_t index=0;index<32;++index)if(packet.entries[3].input_prefix[index]!=address[index])return 6;
    // Each API's failure predicate is independent of either stale error value.
    listener_mock_packet(&packet,cutoff,frequency);for(auto& fail:state.fail)fail=true;
    errors_restore(state.incoming);if(listener_startup(0x202,&data)!=10107)return 7;
    errors_restore(state.incoming);if(listener_socket(-2,3,-4,state.info,0xfedcba98,0x80000001)!=INVALID_SOCKET)return 7;
    errors_restore(state.incoming);if(listener_handle(listener_mock_handle(),0x87654321,0x12345678)!=FALSE)return 7;
    errors_restore(state.incoming);if(listener_bind(listener_mock_socket,state.address,state.length)!=SOCKET_ERROR)return 7;
    errors_restore(state.incoming);if(listener_listen(listener_mock_socket,-128)!=SOCKET_ERROR)return 7;
    errors_restore(state.incoming);if(listener_close(listener_mock_socket)!=SOCKET_ERROR)return 7;
    errors_restore(state.incoming);if(listener_cleanup()!=SOCKET_ERROR)return 7;
    if(!state.same||packet.total_failures!=7||packet.failure_mask!=0x7f||packet.first_failure.operation!=1||packet.first_failure.result!=10107||packet.first_failure.output_valid||packet.entries[1].result!=UINT64_MAX||packet.entries[3].result!=UINT32_MAX)return 7;
    // Faulted and negative input lengths cannot change the original arguments.
    listener_mock_packet(&packet,cutoff,frequency);state.address=reinterpret_cast<const sockaddr*>(1);state.length=16;
    errors_restore(state.incoming);if(listener_bind(listener_mock_socket,state.address,state.length)!=SOCKET_ERROR||!(packet.entries[0].input_flags&2)||packet.entries[0].input_bytes)return 8;
    state.length=-1;errors_restore(state.incoming);if(listener_bind(listener_mock_socket,state.address,state.length)!=SOCKET_ERROR||packet.entries[1].arguments[2]!=UINT32_MAX||packet.entries[1].input_flags!=2)return 8;
    // A failing nested RETURN pins first_failure before its enclosing RETURN.
    listener_mock_packet(&packet,cutoff,frequency);state.address=reinterpret_cast<const sockaddr*>(address);state.length=16;state.nested=true;
    errors_restore(state.incoming);if(listener_bind(listener_mock_socket,state.address,state.length)!=SOCKET_ERROR)return 9;
    if(packet.total_calls!=2||packet.record_count!=2||packet.entries[0].operation!=5||packet.entries[0].sequence!=2||packet.entries[0].parent_sequence!=1||packet.entries[0].depth!=1||packet.entries[0].completion_sequence!=3||packet.entries[1].operation!=4||packet.entries[1].sequence!=1||packet.entries[1].completion_sequence!=4||packet.first_failure.operation!=5||listener_collector.depth)return 9;
    state.nested=false;
    // Dependency ENTER ordinals share the listener clock, while dependency
    // local sequence and completion-ring retention remain their existing ABI.
    listener_mock_packet(&packet,cutoff,frequency);listener_mock_dependencies(&packet);state.nested=true;state.dependency=true;
    errors_restore(state.incoming);if(listener_bind(listener_mock_socket,state.address,state.length)!=SOCKET_ERROR)return 15;
    if(packet.next_sequence!=6||packet.entries[0].completion_sequence!=5||packet.entries[1].completion_sequence!=6||packet.dependencies.called||packet.dependencies.record_count!=1||packet.dependency_link_count!=1||packet.dependency_links[0].dependency_sequence!=1||packet.dependency_links[0].timeline_sequence!=3||packet.dependency_links[0].parent_listener_sequence!=2||packet.first_dependency_failure_link.timeline_sequence!=3)return 15;
    state.nested=false;listener_mock_packet(&packet,cutoff,frequency);listener_mock_dependencies(&packet);
    for(size_t index=0;index<20;++index){errors_restore(state.incoming);if(listener_listen(listener_mock_socket,-128)!=SOCKET_ERROR)return 15;}
    if(packet.dependency_link_count!=16||packet.dependency_links_dropped!=4||packet.dependencies.record_count!=16||packet.dependencies.dropped!=4||packet.first_dependency_failure_link.dependency_sequence!=1||packet.first_dependency_failure_link.timeline_sequence!=2||packet.next_sequence!=80)return 15;
    for(size_t index=0;index<16;++index){
        if(packet.dependency_links[index].dependency_sequence!=packet.dependencies.entries[index].sequence||packet.dependency_links[index].dependency_sequence!=index+5||packet.dependency_links[index].timeline_sequence!=index*4+18||packet.dependency_links[index].parent_listener_sequence!=index*4+17)return 15;
    }
    state.dependency=false;collector={};listener_mock_packet(&packet,cutoff,frequency);
    // Instrumentation reentry and foreign threads only forward.
    const auto calls=packet.total_calls;const auto native_calls=state.calls[5].load();listener_collector.inside=true;errors_restore(state.incoming);
    const int reentered=listener_close(listener_mock_socket);const auto reentry_errors=errors();listener_collector.inside=false;
    if(reentered!=SOCKET_ERROR||!same_errors(reentry_errors,state.outgoing)||packet.total_calls!=calls||state.calls[5]!=native_calls+1||!packet.incomplete)return 10;
    // Either collector's instrumentation must suppress the other namespace.
    // These are private typed originals and collector state, never real APIs.
    listener_mock_dependencies(&packet);packet.incomplete=0;collector.inside=true;errors_restore(state.incoming);
    const int cross_reentered=listener_close(listener_mock_socket);const auto cross_errors=errors();collector.inside=false;
    if(cross_reentered!=SOCKET_ERROR||!same_errors(cross_errors,state.outgoing)||packet.total_calls!=calls||packet.next_sequence||packet.dependencies.total_calls||packet.dependency_link_count||state.calls[5]!=native_calls+2||!packet.incomplete)return 10;
    listener_collector.inside=true;WsaEntry suppressed={};const bool cross_active=begin(&suppressed,3,state.incoming.win32);listener_collector.inside=false;
    if(cross_active||packet.dependencies.total_calls||packet.dependency_link_count||collector.pending_count||!packet.dependencies.incomplete)return 10;
    collector={};
    HANDLE thread=CreateThread(nullptr,0,listener_mock_thread,nullptr,0,nullptr);if(!thread)return 11;
    LARGE_INTEGER now={};
    if(!QueryPerformanceCounter(&now)||now.QuadPart<0||static_cast<uint64_t>(now.QuadPart)>=cutoff||!frequency){CloseHandle(thread);__fastfail(FAST_FAIL_FATAL_APP_EXIT);}
    const auto ticks=cutoff-static_cast<uint64_t>(now.QuadPart);
    if(ticks>UINT64_MAX/1000){CloseHandle(thread);__fastfail(FAST_FAIL_FATAL_APP_EXIT);}
    const auto remaining=ticks*1000/frequency;
    if(WaitForSingleObject(thread,remaining>MAXDWORD-1?MAXDWORD-1:static_cast<DWORD>(remaining))!=WAIT_OBJECT_0){CloseHandle(thread);__fastfail(FAST_FAIL_FATAL_APP_EXIT);}
    DWORD thread_status=1;const BOOL queried=GetExitCodeThread(thread,&thread_status);CloseHandle(thread);
    if(!queried||thread_status||packet.total_calls!=calls||state.calls[5]!=native_calls+3||!state.same)return 11;
    // Recent completions and a pinned first failure survive ring eviction.
    listener_mock_packet(&packet,cutoff,frequency);
    for(size_t index=0;index<20;++index){errors_restore(state.incoming);if(listener_close(listener_mock_socket)!=SOCKET_ERROR)return 12;}
    if(packet.total_calls!=20||packet.total_failures!=20||packet.record_count!=16||packet.dropped!=4||packet.first_failure.sequence!=1||packet.entries[0].sequence!=9||packet.entries[15].sequence!=39||!packet.overflow||!packet.incomplete)return 12;
    packet.total_calls=UINT32_MAX;const auto recorded=packet.record_count;errors_restore(state.incoming);
    if(listener_close(listener_mock_socket)!=SOCKET_ERROR||packet.record_count!=recorded||packet.total_calls!=UINT32_MAX)return 12;
    listener_mock_packet(&packet,cutoff,frequency);packet.next_sequence=UINT64_MAX;errors_restore(state.incoming);
    if(listener_close(listener_mock_socket)!=SOCKET_ERROR||packet.total_calls||!packet.overflow)return 12;
    listener_mock_packet(&packet,cutoff,frequency);packet.next_sequence=UINT64_MAX-1;errors_restore(state.incoming);
    if(listener_close(listener_mock_socket)!=SOCKET_ERROR||packet.total_calls||!packet.overflow)return 12;
    // Test the exact publication rollback primitives against a private data
    // page. MEM_PRIVATE must never pass the real image/IAT validation.
    listener_collector={};SYSTEM_INFO system={};GetSystemInfo(&system);
    void* memory=VirtualAlloc(nullptr,system.dwPageSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!memory)return 13;
    auto** slots=static_cast<void**>(memory);slots[0]=private_route.targets[0];slots[1]=private_route.targets[1];DWORD previous=0;
    if(!VirtualProtect(memory,system.dwPageSize,PAGE_READONLY,&previous)){VirtualFree(memory,0,MEM_RELEASE);return 13;}
    Page page={memory,system.dwPageSize,PAGE_READONLY,false},refused={};
    const auto base=reinterpret_cast<uintptr_t>(memory);Image invalid={base,base+system.dwPageSize,0,0,base,base+sizeof(void*)*2,system.dwPageSize,0,machine()};
    if(data_page(slots,invalid,&refused)){VirtualFree(memory,0,MEM_RELEASE);return 13;}
    if(!listener_writable(&page,1,&packet)){VirtualFree(memory,0,MEM_RELEASE);return 13;}
    bool good=swap(&slots[0],listener_hooks[0].target,private_route.targets[0])==private_route.targets[0];
    packet.slot_count=2;packet.slots[0]={reinterpret_cast<uintptr_t>(&slots[0]),reinterpret_cast<uintptr_t>(private_route.targets[0]),reinterpret_cast<uintptr_t>(listener_hooks[0].target),0,1,1,0,0};
    packet.slots[1]={reinterpret_cast<uintptr_t>(&slots[1]),reinterpret_cast<uintptr_t>(private_route.targets[1]),reinterpret_cast<uintptr_t>(listener_hooks[1].target),0,2,0,0,0};packet.published_mask=1;
    // Inject a foreign slot identity: a failed CAS must leave it untouched.
    good=good&&swap(&slots[1],listener_hooks[1].target,private_route.targets[2])==private_route.targets[1]&&slots[1]==private_route.targets[1];
    listener_rollback(&packet);
    good=good&&slots[0]==private_route.targets[0]&&slots[1]==private_route.targets[1]&&packet.slots[0].restored==1&&!packet.slots[0].published&&!packet.slots[1].restored&&!packet.published_mask;
    listener_restore(&page,1,&packet);MEMORY_BASIC_INFORMATION restored={};
    good=good&&VirtualQuery(memory,&restored,sizeof(restored))==sizeof(restored)&&restored.Protect==PAGE_READONLY;
    const BOOL freed=VirtualFree(memory,0,MEM_RELEASE);if(!good||!freed||!packet.protections_restored)return 13;
    // Unsupported observer setup must preserve one opaque original callback,
    // scalar outcome, outgoing errors, and permanent original lifetime.
    ListenerPacket call={};call.version=1;call.setup_stage=4;call.setup_error=ERROR_NOT_SUPPORTED;call.incomplete=1;call.cutoff_qpc=cutoff;call.frequency=frequency;
    call.incoming_win32=state.incoming.win32;call.incoming_wsa=state.incoming.wsa;
    const ListenerRequest request={cutoff,frequency,state.incoming.win32,state.incoming.wsa};const auto before=state.calls[5].load();
    listener_invoke(&call,&request,listener_mock_callback,&state,false);const auto returned=errors();
    if(!state.same||state.calls[5]!=before+1||call.called!=1||call.callback_outcome!=2||call.callback_raw_error_present!=1||call.callback_raw_error!=2||call.armed||!same_errors(returned,state.outgoing)||!same_errors({call.outgoing_win32,call.outgoing_wsa},state.outgoing))return 14;
    ListenerPacket stopped={};stopped.setup_stage=4;stopped.setup_error=ERROR_NOT_SUPPORTED;stopped.frequency=frequency;
    const ListenerRequest expired={0,frequency,state.incoming.win32,state.incoming.wsa};
    listener_invoke(&stopped,&expired,listener_mock_callback,&state,false);const auto stopped_errors=errors();
    if(stopped.called||stopped.callback_outcome||stopped.callback_raw_error_present||stopped.setup_stage!=2||stopped.setup_error!=ERROR_TIMEOUT||state.calls[5]!=before+1||!same_errors(stopped_errors,state.incoming))return 16;
    for(const auto& original:listener_originals)if(original.load(std::memory_order_acquire))return 14;
    return 0;
}
