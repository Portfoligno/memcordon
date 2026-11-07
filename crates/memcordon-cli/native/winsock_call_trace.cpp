#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <winreg.h>
#include <intrin.h>
#include <psapi.h>
#include <atomic>
#include <type_traits>
#include "detours.h"
#include "winsock_call_trace.h"
#include "native_file_request_trace.h"

static_assert(sizeof(void*)==8 && sizeof(WCHAR)==2 && sizeof(NTSTATUS)==4,"WSA trace native ABI");
static_assert(sizeof(OBJECT_ATTRIBUTES)==48 && offsetof(OBJECT_ATTRIBUTES,ObjectName)==16,"WSA native object attributes ABI");
static_assert(sizeof(UNICODE_STRING)==16 && offsetof(UNICODE_STRING,Buffer)==8,"WSA native counted string ABI");
static std::atomic<void*> originals[16] = {};
static std::atomic<void*> returned_originals[16]={};
static std::atomic<void*> loader_originals[16]={};
struct DependencyPrivateRoute {void* targets[16];};
static std::atomic<const DependencyPrivateRoute*> dependency_private_routes[3]={};
using LoaderPrivatePrepare=bool(*)(ListenerPacket*,void*);
static std::atomic<LoaderPrivatePrepare> loader_private_prepare{nullptr};
static_assert(std::atomic<void*>::is_always_lock_free,"forwarding publication is lock-free");
static volatile LONG installed=0;
// Published once, before installed=2. No call/event/error-state data is retained.
struct DependencyRoute {
    WsaNode nodes[2];WsaSlot slots[16];
    uint32_t node_count,hop_count,slot_count,descriptor_count,function_count;
    uint32_t callbacks_complete,owner_pinned,protections_restored,scope_flags,incomplete;
};
static DependencyRoute dependency_route={};
static void save_dependency_route(const WsaPacket* packet,DependencyRoute* destination=&dependency_route){
    auto& dependency_route=*destination;
    for(size_t index=0;index<2;++index)dependency_route.nodes[index]=packet->nodes[index];
    for(size_t index=0;index<16;++index)dependency_route.slots[index]=packet->slots[index];
    dependency_route.node_count=packet->node_count;dependency_route.hop_count=packet->hop_count;
    dependency_route.slot_count=packet->slot_count;dependency_route.descriptor_count=packet->descriptor_count;
    dependency_route.function_count=packet->function_count;dependency_route.callbacks_complete=packet->callbacks_complete;
    dependency_route.owner_pinned=packet->owner_pinned;dependency_route.protections_restored=packet->protections_restored;
    dependency_route.scope_flags=packet->scope_flags;dependency_route.incomplete=packet->incomplete;
}
static void copy_dependency_route(WsaPacket* packet,const DependencyRoute* source=&dependency_route){
    const auto& dependency_route=*source;
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
struct ListenerCollector {ListenerPacket* packet;bool inside;uint32_t depth;uint64_t parents[16];uint32_t operations[16];};
static __declspec(thread) ListenerCollector listener_collector={};
static __declspec(thread) bool observer_setup_active=false;
struct ObserverSetup {
    bool previous;
    ObserverSetup():previous(observer_setup_active){observer_setup_active=true;}
    ~ObserverSetup(){observer_setup_active=previous;}
};
struct Collector {
    WsaPacket* packet;bool inside;ListenerPacket* timeline;
    uint32_t pending_count;ListenerDependencyLink pending[16];
    uint64_t loader_dependency_sequence,loader_timeline_sequence,parent_listener_sequence;
};
static __declspec(thread) Collector collector={};
static __declspec(thread) Collector returned_collector={};
static __declspec(thread) Collector loader_collector={};
// Domain 0 is startup, 1 the returned provider, 2 the original loader owner.
template<unsigned Returned> static Collector& dependency_collector(){static_assert(Returned<3);if constexpr(Returned==2)return loader_collector;else if constexpr(Returned==1)return returned_collector;else return collector;}
template<unsigned Returned=0> struct DependencyErrors {
    Collector& scope;
    bool dual;ErrorPair incoming,outgoing;
    DependencyErrors():scope(dependency_collector<Returned>()),dual(Returned||scope.timeline!=nullptr),incoming{},outgoing{}{
        incoming.win32=GetLastError();if(dual)incoming.wsa=WSAGetLastError();
    }
    void forward(bool active){if(active)scope.inside=false;if(dual)errors_restore(incoming);else SetLastError(incoming.win32);}
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
    const uint64_t returned=returned_collector.timeline==packet?returned_collector.pending_count:0;
    const uint64_t loader=loader_collector.timeline==packet?loader_collector.pending_count:0;
    // Leave a RETURN ordinal for every already-active frame and this entry.
    if(UINT64_MAX-packet->next_sequence<listeners+dependencies+returned+loader+2){packet->overflow=1;packet->incomplete=1;return 0;}
    return timeline_next(packet);
}
template<unsigned Returned=0> static void dependency_link_finish(const WsaEntry* entry,bool first){
    auto& collector=dependency_collector<Returned>();
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
    if constexpr(Returned==2){
        auto& scope=packet->loader_owner;
        const ListenerLoaderLink linked={link.dependency_sequence,link.timeline_sequence,collector.parent_listener_sequence,collector.loader_dependency_sequence,collector.loader_timeline_sequence};
        if(first)scope.first_failure_link=linked;
        if(scope.link_count<16)scope.links[scope.link_count++]=linked;
        else{for(size_t index=1;index<16;++index)scope.links[index-1]=scope.links[index];scope.links[15]=linked;if(scope.links_dropped!=UINT32_MAX)++scope.links_dropped;scope.incomplete=1;packet->overflow=1;packet->incomplete=1;}
        return;
    }
    auto* first_link=Returned?&packet->returned_module.first_failure_link:&packet->first_dependency_failure_link;
    auto* links=Returned?packet->returned_module.links:packet->dependency_links;
    auto* count=Returned?&packet->returned_module.link_count:&packet->dependency_link_count;
    auto* dropped=Returned?&packet->returned_module.links_dropped:&packet->dependency_links_dropped;
    if(first)*first_link=link;
    if(*count<16)links[(*count)++]=link;
    else {
        for(size_t index=1;index<16;++index)links[index-1]=links[index];
        links[15]=link;
        if(*dropped!=UINT32_MAX)++*dropped;
        if constexpr(Returned)packet->returned_module.incomplete=1;
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
template<unsigned Returned=0> static bool begin(WsaEntry* entry,uint32_t operation,DWORD incoming) {
    auto& collector=dependency_collector<Returned>();
    auto* packet=collector.packet;
    if (!packet) return false;
    if (observer_setup_active||collector.inside||::collector.inside||returned_collector.inside||loader_collector.inside||listener_collector.inside) {packet->incomplete=1;return false;}
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
template<unsigned Returned=0> static void output(WsaEntry* entry,void** value) {
    auto& collector=dependency_collector<Returned>();
    const bool inside=collector.inside;collector.inside=true;
    __try {if(value){entry->raw_output=reinterpret_cast<uintptr_t>(*value);entry->output_flags=1|(*value?2:0);}}
    __except(EXCEPTION_EXECUTE_HANDLER) {entry->output_flags=0;}
    collector.inside=inside;
}
template<unsigned Returned=0> static uint64_t size_input(const SIZE_T* value,WsaEntry* entry,uint32_t bit) {
    auto& collector=dependency_collector<Returned>();
    const bool inside=collector.inside;collector.inside=true;uint64_t result=0;
    __try {if(value){result=*value;entry->scalar_flags|=bit;}} __except(EXCEPTION_EXECUTE_HANDLER) {}
    collector.inside=inside;return result;
}
template<unsigned Returned=0> static uint32_t dword_input(const DWORD* value,WsaEntry* entry,uint32_t bit) {
    auto& collector=dependency_collector<Returned>();
    const bool inside=collector.inside;collector.inside=true;uint32_t result=0;
    __try {if(value){result=*value;entry->scalar_flags|=bit;}} __except(EXCEPTION_EXECUTE_HANDLER) {}
    collector.inside=inside;return result;
}
template<unsigned Returned=0> static void finish(WsaEntry* entry,bool active,int32_t status,DWORD outgoing,bool failed) {
    auto& collector=dependency_collector<Returned>();
    auto* packet=collector.packet;
    if (!active || !packet) return;
    collector.inside=true;entry->returned=1;entry->native_status=status;entry->outgoing_error=outgoing;
    if(failed) {
        packet->total_failures=increment(packet->total_failures);
        if(packet->total_failures==UINT32_MAX){packet->overflow=1;packet->incomplete=1;}
    }
    const bool first=failed&&!packet->first_failure_present;
    if(first){packet->first_failure=*entry;packet->first_failure_present=1;}
    dependency_link_finish<Returned>(entry,first);
    if(packet->record_count<16) packet->entries[packet->record_count++]=*entry;
    else {
        for(size_t index=1;index<16;++index) packet->entries[index-1]=packet->entries[index];
        packet->entries[15]=*entry;packet->overflow=1;packet->dropped=increment(packet->dropped);packet->incomplete=1;
    }
    collector.inside=false;
}
template<class T,unsigned Returned=0> static T original(size_t operation){
    static_assert(Returned<3);
    const auto* mock=dependency_private_routes[Returned].load(std::memory_order_acquire);
    auto* targets=Returned==2?loader_originals:Returned==1?returned_originals:originals;
    return reinterpret_cast<T>(mock?mock->targets[operation-1]:targets[operation-1].load(std::memory_order_acquire));
}
static void returned_module_loaded(const WsaEntry*,bool,HMODULE,HANDLE,DWORD);
struct LoaderCallScope {Collector previous;ListenerPacket* packet;bool managed;};
static LoaderCallScope loader_owner_begin(const WsaEntry*,bool,void*);
static void loader_owner_end(const LoaderCallScope&);
struct ReturnedImageApis {
    decltype(&VirtualQuery) query;
    decltype(&K32GetMappedFileNameW) mapped_name;
};
static void returned_image(const WsaEntry* entry,bool active,HMODULE module,const ReturnedImageApis& api={&VirtualQuery,&K32GetMappedFileNameW}){
    auto* packet=collector.timeline;
    if(!active||!module||!packet||!packet->returned_images.enabled)return;
    auto& output=packet->returned_images;
    output.attempts=increment(output.attempts);
    if(output.count>=8){output.dropped=increment(output.dropped);output.incomplete=1;return;}
    const auto saved=errors();
    auto& row=output.rows[output.count++];
    row.dependency_sequence=entry->sequence;row.parent_listener_sequence=listener_parent();row.returned_base=reinterpret_cast<uintptr_t>(module);row.original_thread=GetCurrentThreadId();row.domain=0;row.state=7;
    if(observer_setup_active||!row.parent_listener_sequence||!listener_collector.depth||listener_collector.operations[listener_collector.depth-1]!=2){output.incomplete=1;errors_restore(saved);return;}
    {ObserverSetup suppress;
        LARGE_INTEGER started={},finished={};
        const BOOL clock=QueryPerformanceCounter(&started);
        if(!clock||started.QuadPart<=0||static_cast<uint64_t>(started.QuadPart)>=packet->cutoff_qpc){row.state=2;output.incomplete=1;}
        else {
            row.started_qpc=static_cast<uint64_t>(started.QuadPart);
            MEMORY_BASIC_INFORMATION info={};
            const SIZE_T queried=api.query(module,&info,sizeof(info));
            const DWORD query_error=queried?0:GetLastError();
            row.allocation_base=reinterpret_cast<uintptr_t>(info.AllocationBase);row.memory_type=info.Type;
            if(queried!=sizeof(info)){row.state=3;row.virtual_query_error=query_error;output.incomplete=1;}
            else if(info.Type!=MEM_IMAGE||info.State!=MEM_COMMIT||info.AllocationBase!=module){row.state=4;output.incomplete=1;}
            else {
                row.flags=1;
                LARGE_INTEGER before_name={};
                if(!QueryPerformanceCounter(&before_name)||before_name.QuadPart<=0||static_cast<uint64_t>(before_name.QuadPart)>=packet->cutoff_qpc){row.state=2;output.incomplete=1;}
                else {
                const DWORD count=api.mapped_name(GetCurrentProcess(),module,reinterpret_cast<WCHAR*>(row.mapped_path),512);
                const DWORD path_error=count?0:GetLastError();
                if(!count){row.state=5;row.mapped_name_error=path_error;output.incomplete=1;}
                else if(count>=512){row.state=6;row.mapped_path_units=512;output.incomplete=1;}
                else {row.mapped_path_units=count;row.flags|=2;row.state=1;}
                }
            }
        }
        const BOOL ended=QueryPerformanceCounter(&finished);
        if(ended&&finished.QuadPart>0)row.finished_qpc=static_cast<uint64_t>(finished.QuadPart);
        if(!ended||!row.started_qpc||row.finished_qpc<row.started_qpc||row.finished_qpc>=packet->cutoff_qpc){row.state=2;output.incomplete=1;}
        else row.flags|=4;
    }
    errors_restore(saved);
}
using NtOpen=NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES);
template<unsigned Returned=0> static NTSTATUS NTAPI open_key(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attr){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<NtOpen,Returned>(1)(out,access,attr);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,1,incoming);
    if(active){entry.desired_access=access;attributes(&entry,attr);}saved.forward(active);
    const auto result=original<NtOpen,Returned>(1)(out,access,attr);const DWORD error=saved.returned();
    if(active&&result>=0)output<Returned>(&entry,reinterpret_cast<void**>(out));finish<Returned>(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using NtOpenEx=NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,ULONG);
template<unsigned Returned=0> static NTSTATUS NTAPI open_key_ex(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attr,ULONG options){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<NtOpenEx,Returned>(2)(out,access,attr,options);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,2,incoming);
    if(active){entry.desired_access=access;entry.secondary_size=options;entry.scalar_flags=2;attributes(&entry,attr);}saved.forward(active);
    const auto result=original<NtOpenEx,Returned>(2)(out,access,attr,options);const DWORD error=saved.returned();
    if(active&&result>=0)output<Returned>(&entry,reinterpret_cast<void**>(out));finish<Returned>(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using NtQuery=NTSTATUS(NTAPI*)(HANDLE,PUNICODE_STRING,ULONG,PVOID,ULONG,PULONG);
template<unsigned Returned=0> static NTSTATUS NTAPI query_value(HANDLE key,PUNICODE_STRING value,ULONG type,PVOID buffer,ULONG length,PULONG required){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<NtQuery,Returned>(3)(key,value,type,buffer,length,required);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,3,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(key);entry.requested_size=length;entry.secondary_size=type;entry.scalar_flags=3;unicode(&entry,value);}saved.forward(active);
    const auto result=original<NtQuery,Returned>(3)(key,value,type,buffer,length,required);const DWORD error=saved.returned();
    finish<Returned>(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using Load=NTSTATUS(NTAPI*)(PWSTR,PULONG,PUNICODE_STRING,PHANDLE);
using LoaderWindowClock=BOOL(*)(LARGE_INTEGER*);
static std::atomic<LoaderWindowClock> loader_private_clock{nullptr};
static BOOL loader_window_clock(LARGE_INTEGER* value){const auto mock=loader_private_clock.load(std::memory_order_acquire);return mock?mock(value):QueryPerformanceCounter(value);}
struct LoaderWindowCapture {ListenerPacket* packet;ListenerLoaderWindow window;bool start_valid;};
struct NativeFileCollector {NativeFilePacket* packet;uint64_t ldr,parent,started;uint32_t thread;bool inside,disarmed;};
struct NativeFileScope {NativeFileCollector previous;NativeFilePacket* packet;bool managed,armed;};
static __declspec(thread) NativeFilePacket* native_file_output=nullptr;
static __declspec(thread) NativeFileCollector native_file_collector={};
static NativeFileScope native_file_scope_begin(const LoaderWindowCapture*,bool);
static void native_file_scope_end(const NativeFileScope&);
static void native_file_prepare(ListenerPacket*,void*,void*);
static NTSTATUS native_file_ldr_forward(Load,PWSTR,PULONG,PUNICODE_STRING,PHANDLE,const LoaderWindowCapture*,bool);
static LoaderWindowCapture loader_window_begin(const WsaEntry* entry,bool active){
    LoaderWindowCapture capture={};if(!active||!loader_collector.timeline)return capture;
    capture.packet=loader_collector.timeline;
    capture.window={entry->sequence,loader_collector.loader_dependency_sequence,loader_collector.parent_listener_sequence,0,0};
    bool linked=false;
    for(size_t index=0;index<loader_collector.pending_count;++index){
        const auto& pending=loader_collector.pending[index];
        if(pending.dependency_sequence==entry->sequence&&pending.parent_listener_sequence==capture.window.parent_listener_sequence)linked=true;
    }
    LARGE_INTEGER started={};const BOOL clock=loader_window_clock(&started);
    capture.start_valid=linked&&capture.window.loader_dependency_sequence&&capture.window.parent_listener_sequence&&clock&&started.QuadPart>0;
    if(capture.start_valid)capture.window.started_qpc=static_cast<uint64_t>(started.QuadPart);
    return capture;
}
static void loader_window_end(LoaderWindowCapture* capture,bool failed){
    if(!capture->packet)return;
    loader_collector.inside=true;
    LARGE_INTEGER finished={};const BOOL clock=loader_window_clock(&finished);
    auto* packet=capture->packet;auto& scope=packet->loader_owner;auto& window=capture->window;
    const bool valid=loader_collector.packet==&scope.dependencies&&capture->start_valid&&clock&&finished.QuadPart>0&&window.started_qpc>=packet->started_qpc&&
        static_cast<uint64_t>(finished.QuadPart)>=window.started_qpc&&static_cast<uint64_t>(finished.QuadPart)<=packet->cutoff_qpc;
    if(!valid){scope.windows_invalid=increment(scope.windows_invalid);if(scope.windows_invalid==UINT32_MAX)packet->overflow=1;scope.incomplete=1;packet->incomplete=1;return;}
    window.finished_qpc=static_cast<uint64_t>(finished.QuadPart);
    if(failed&&!scope.first_failure_window_present){scope.first_failure_window=window;scope.first_failure_window_present=1;}
    if(scope.window_count<16)scope.windows[scope.window_count++]=window;
    else {
        for(size_t index=1;index<16;++index)scope.windows[index-1]=scope.windows[index];
        scope.windows[15]=window;scope.windows_dropped=increment(scope.windows_dropped);scope.incomplete=1;packet->incomplete=1;packet->overflow=1;
    }
}
template<unsigned Returned=0> static NTSTATUS NTAPI load_dll(PWSTR search,PULONG flags,PUNICODE_STRING value,PHANDLE out){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<Load,Returned>(4)(search,flags,value,out);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,4,incoming);
    if(active){unicode(&entry,value);entry.flags=dword_input<Returned>(flags,&entry,4);}
    LoaderWindowCapture window={};if constexpr(Returned==2)window=loader_window_begin(&entry,active);
    saved.forward(active);
    NTSTATUS result=0;
    if constexpr(Returned==2)result=native_file_ldr_forward(original<Load,Returned>(4),search,flags,value,out,&window,active);
    else result=original<Load,Returned>(4)(search,flags,value,out);
    const DWORD error=saved.returned();
    if constexpr(Returned==2)loader_window_end(&window,result<0);
    if(active&&result>=0)output<Returned>(&entry,reinterpret_cast<void**>(out));finish<Returned>(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using NtCreate=NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,ULONG,BOOLEAN);
template<unsigned Returned=0> static NTSTATUS NTAPI create_event(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attr,ULONG type,BOOLEAN state){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<NtCreate,Returned>(5)(out,access,attr,type,state);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,5,incoming);
    if(active){entry.desired_access=access;entry.requested_size=type;entry.secondary_size=state;entry.scalar_flags=3;attributes(&entry,attr);}saved.forward(active);
    const auto result=original<NtCreate,Returned>(5)(out,access,attr,type,state);const DWORD error=saved.returned();
    if(active&&result>=0)output<Returned>(&entry,reinterpret_cast<void**>(out));finish<Returned>(&entry,active,result,error,result<0);SetLastError(error);return result;
}
template<unsigned Returned=0> static NTSTATUS NTAPI open_event(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attr){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<NtOpen,Returned>(6)(out,access,attr);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,6,incoming);
    if(active){entry.desired_access=access;attributes(&entry,attr);}saved.forward(active);
    const auto result=original<NtOpen,Returned>(6)(out,access,attr);const DWORD error=saved.returned();
    if(active&&result>=0)output<Returned>(&entry,reinterpret_cast<void**>(out));finish<Returned>(&entry,active,result,error,result<0);SetLastError(error);return result;
}
template<unsigned Returned=0> static NTSTATUS NTAPI open_directory(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attr){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<NtOpen,Returned>(7)(out,access,attr);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,7,incoming);
    if(active){entry.desired_access=access;attributes(&entry,attr);}saved.forward(active);
    const auto result=original<NtOpen,Returned>(7)(out,access,attr);const DWORD error=saved.returned();
    if(active&&result>=0)output<Returned>(&entry,reinterpret_cast<void**>(out));finish<Returned>(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using NtAllocate=NTSTATUS(NTAPI*)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
template<unsigned Returned=0> static NTSTATUS NTAPI allocate(HANDLE process,PVOID* base,ULONG_PTR zero,PSIZE_T size,ULONG type,ULONG protection){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<NtAllocate,Returned>(8)(process,base,zero,size,type,protection);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,8,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(process);entry.requested_size=size_input<Returned>(size,&entry,1);entry.flags=type;entry.scalar_flags|=4;entry.desired_access=protection;}saved.forward(active);
    const auto result=original<NtAllocate,Returned>(8)(process,base,zero,size,type,protection);const DWORD error=saved.returned();
    if(active&&result>=0){output<Returned>(&entry,base);entry.secondary_size=size_input<Returned>(size,&entry,2);}finish<Returned>(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using Heap=void*(NTAPI*)(void*,ULONG,SIZE_T);
template<unsigned Returned=0> static void* NTAPI heap(void* handle,ULONG flags,SIZE_T size){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<Heap,Returned>(9)(handle,flags,size);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,9,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(handle);entry.requested_size=size;entry.scalar_flags=5;entry.flags=flags;}saved.forward(active);
    void* result=original<Heap,Returned>(9)(handle,flags,size);const DWORD error=saved.returned();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish<Returned>(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
template<unsigned Returned=0> static LSTATUS WINAPI reg_open(HKEY key,LPCWSTR value,DWORD options,REGSAM access,PHKEY out){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<decltype(&RegOpenKeyExW),Returned>(10)(key,value,options,access,out);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,10,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(key);entry.desired_access=access;entry.flags=options;entry.scalar_flags=4;name(&entry,value,0,true);}saved.forward(active);
    const auto result=original<decltype(&RegOpenKeyExW),Returned>(10)(key,value,options,access,out);const DWORD error=saved.returned();
    if(active&&result==ERROR_SUCCESS)output<Returned>(&entry,reinterpret_cast<void**>(out));finish<Returned>(&entry,active,result,error,result!=ERROR_SUCCESS);SetLastError(error);return result;
}
template<unsigned Returned=0> static LSTATUS WINAPI reg_query(HKEY key,LPCWSTR value,LPDWORD reserved,LPDWORD type,LPBYTE data,LPDWORD length){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<decltype(&RegQueryValueExW),Returned>(11)(key,value,reserved,type,data,length);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,11,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(key);entry.requested_size=dword_input<Returned>(length,&entry,1);name(&entry,value,0,true);}saved.forward(active);
    const auto result=original<decltype(&RegQueryValueExW),Returned>(11)(key,value,reserved,type,data,length);const DWORD error=saved.returned();
    finish<Returned>(&entry,active,result,error,result!=ERROR_SUCCESS);SetLastError(error);return result;
}
template<unsigned Returned=0> static HMODULE WINAPI load_library(LPCWSTR value,HANDLE file,DWORD flags){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<decltype(&LoadLibraryExW),Returned>(12)(value,file,flags);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,12,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(file);entry.flags=flags;entry.scalar_flags=4;name(&entry,value,0,true);}
    LoaderCallScope loader={};
    if constexpr(Returned==0)loader=loader_owner_begin(&entry,active,reinterpret_cast<void*>(original<decltype(&LoadLibraryExW),0>(12)));
    saved.forward(active);
    const auto result=original<decltype(&LoadLibraryExW),Returned>(12)(value,file,flags);const DWORD error=saved.returned();
    if constexpr(Returned==0)returned_image(&entry,active,result);
    if constexpr(Returned==0)loader_owner_end(loader);
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish<Returned>(&entry,active,result?0:1,error,!result);if constexpr(!Returned)returned_module_loaded(&entry,active,result,file,flags);SetLastError(error);return result;
}
template<unsigned Returned=0> static HANDLE WINAPI create_event_w(LPSECURITY_ATTRIBUTES security,BOOL reset,BOOL state,LPCWSTR value){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<decltype(&CreateEventW),Returned>(13)(security,reset,state,value);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,13,incoming);
    if(active){entry.requested_size=reset;entry.secondary_size=state;entry.scalar_flags=3;name(&entry,value,0,true);}saved.forward(active);
    const auto result=original<decltype(&CreateEventW),Returned>(13)(security,reset,state,value);const DWORD error=saved.returned();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish<Returned>(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
template<unsigned Returned=0> static HANDLE WINAPI open_event_w(DWORD access,BOOL inherit,LPCWSTR value){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<decltype(&OpenEventW),Returned>(14)(access,inherit,value);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,14,incoming);
    if(active){entry.desired_access=access;entry.flags=inherit;entry.scalar_flags=4;name(&entry,value,0,true);}saved.forward(active);
    const auto result=original<decltype(&OpenEventW),Returned>(14)(access,inherit,value);const DWORD error=saved.returned();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish<Returned>(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
template<unsigned Returned=0> static void* WINAPI heap_alloc(HANDLE handle,DWORD flags,SIZE_T size){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<decltype(&HeapAlloc),Returned>(15)(handle,flags,size);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,15,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(handle);entry.flags=flags;entry.requested_size=size;entry.scalar_flags=5;}saved.forward(active);
    const auto result=original<decltype(&HeapAlloc),Returned>(15)(handle,flags,size);const DWORD error=saved.returned();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish<Returned>(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
template<unsigned Returned=0> static void* WINAPI virtual_alloc(LPVOID base,SIZE_T size,DWORD type,DWORD protection){
    if constexpr(Returned){if(!dependency_collector<Returned>().packet)return original<decltype(&VirtualAlloc),Returned>(16)(base,size,type,protection);}
    DependencyErrors<Returned> saved;const DWORD incoming=saved.incoming.win32;WsaEntry entry={};bool active=begin<Returned>(&entry,16,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(base);entry.flags=type;entry.desired_access=protection;entry.scalar_flags=5;}saved.forward(active);
    const auto result=original<decltype(&VirtualAlloc),Returned>(16)(base,size,type,protection);const DWORD error=saved.returned();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish<Returned>(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
struct Hook {const char* name;void* target;};
static const Hook hooks[16]={
    {"NtOpenKey",reinterpret_cast<void*>(open_key<false>)},{"NtOpenKeyEx",reinterpret_cast<void*>(open_key_ex<false>)},
    {"NtQueryValueKey",reinterpret_cast<void*>(query_value<false>)},{"LdrLoadDll",reinterpret_cast<void*>(load_dll<false>)},
    {"NtCreateEvent",reinterpret_cast<void*>(create_event<false>)},{"NtOpenEvent",reinterpret_cast<void*>(open_event<false>)},
    {"NtOpenDirectoryObject",reinterpret_cast<void*>(open_directory<false>)},{"NtAllocateVirtualMemory",reinterpret_cast<void*>(allocate<false>)},
    {"RtlAllocateHeap",reinterpret_cast<void*>(heap<false>)},{"RegOpenKeyExW",reinterpret_cast<void*>(reg_open<false>)},
    {"RegQueryValueExW",reinterpret_cast<void*>(reg_query<false>)},{"LoadLibraryExW",reinterpret_cast<void*>(load_library<false>)},
    {"CreateEventW",reinterpret_cast<void*>(create_event_w<false>)},{"OpenEventW",reinterpret_cast<void*>(open_event_w<false>)},
    {"HeapAlloc",reinterpret_cast<void*>(heap_alloc<false>)},{"VirtualAlloc",reinterpret_cast<void*>(virtual_alloc<false>)}
};

static const Hook returned_hooks[16]={
    {"NtOpenKey",reinterpret_cast<void*>(open_key<true>)},{"NtOpenKeyEx",reinterpret_cast<void*>(open_key_ex<true>)},
    {"NtQueryValueKey",reinterpret_cast<void*>(query_value<true>)},{"LdrLoadDll",reinterpret_cast<void*>(load_dll<true>)},
    {"NtCreateEvent",reinterpret_cast<void*>(create_event<true>)},{"NtOpenEvent",reinterpret_cast<void*>(open_event<true>)},
    {"NtOpenDirectoryObject",reinterpret_cast<void*>(open_directory<true>)},{"NtAllocateVirtualMemory",reinterpret_cast<void*>(allocate<true>)},
    {"RtlAllocateHeap",reinterpret_cast<void*>(heap<true>)},{"RegOpenKeyExW",reinterpret_cast<void*>(reg_open<true>)},
    {"RegQueryValueExW",reinterpret_cast<void*>(reg_query<true>)},{"LoadLibraryExW",reinterpret_cast<void*>(load_library<true>)},
    {"CreateEventW",reinterpret_cast<void*>(create_event_w<true>)},{"OpenEventW",reinterpret_cast<void*>(open_event_w<true>)},
    {"HeapAlloc",reinterpret_cast<void*>(heap_alloc<true>)},{"VirtualAlloc",reinterpret_cast<void*>(virtual_alloc<true>)}
};
static const Hook loader_hooks[16]={
    {"NtOpenKey",reinterpret_cast<void*>(open_key<2>)},{"NtOpenKeyEx",reinterpret_cast<void*>(open_key_ex<2>)},
    {"NtQueryValueKey",reinterpret_cast<void*>(query_value<2>)},{"LdrLoadDll",reinterpret_cast<void*>(load_dll<2>)},
    {"NtCreateEvent",reinterpret_cast<void*>(create_event<2>)},{"NtOpenEvent",reinterpret_cast<void*>(open_event<2>)},
    {"NtOpenDirectoryObject",reinterpret_cast<void*>(open_directory<2>)},{"NtAllocateVirtualMemory",reinterpret_cast<void*>(allocate<2>)},
    {"RtlAllocateHeap",reinterpret_cast<void*>(heap<2>)},{"RegOpenKeyExW",reinterpret_cast<void*>(reg_open<2>)},
    {"RegQueryValueExW",reinterpret_cast<void*>(reg_query<2>)},{"LoadLibraryExW",reinterpret_cast<void*>(load_library<2>)},
    {"CreateEventW",reinterpret_cast<void*>(create_event_w<2>)},{"OpenEventW",reinterpret_cast<void*>(open_event_w<2>)},
    {"HeapAlloc",reinterpret_cast<void*>(heap_alloc<2>)},{"VirtualAlloc",reinterpret_cast<void*>(virtual_alloc<2>)}
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
static bool image(HMODULE module,Image* result,bool imports_required=true){
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
        if(!imports_required&&!imports.VirtualAddress&&!imports.Size&&!iat.VirtualAddress&&!iat.Size){*result=value;return true;}
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
static bool capture_node_data(HMODULE module,void* entry,WsaNode* node,Image* mapped,uint32_t* incomplete,bool imports_required=true){
    if(!image(module,mapped,imports_required)||!executable(entry,module))return false;
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
    if(observer_setup_active||listener_collector.inside||collector.inside||returned_collector.inside||loader_collector.inside){packet->incomplete=1;return false;}
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
    listener_collector.operations[listener_collector.depth]=operation;
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
    listener_collector.parents[--listener_collector.depth]=0;listener_collector.operations[listener_collector.depth]=0;listener_collector.inside=false;
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
static size_t typed_ordinal_operation(void* resolved,void* target,void* const* exports,size_t count){
    if(!resolved||resolved!=target)return 0;
    size_t selected=0;
    for(size_t operation=0;operation<count;++operation){
        if(!exports[operation]||exports[operation]!=resolved)continue;
        if(selected)return count+1;
        selected=operation+1;
    }
    return selected;
}
static size_t listener_ordinal_operation(void* resolved,void* target,void* const* exports){return typed_ordinal_operation(resolved,target,exports,7);}
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

static volatile LONG returned_installed=0;
static DependencyRoute returned_route={};
static WsaNode returned_target_proofs[16]={};
struct ReturnedDiscovery {
    Image image;WsaPacket* packet;HMODULE descriptor;DWORD error;
    uintptr_t original_thunk,first_thunk;size_t thunk_index;
    uint32_t unsupported_mask;WsaNode targets[16];
    const Hook* route_hooks=returned_hooks;
};
static bool returned_bounded_imports(ReturnedDiscovery* state){
    __try {
        const auto& mapped=state->image;size_t functions=0;
        for(size_t index=0;index<256;++index){
            if(!live(state->packet))return false;
            const auto address=mapped.imports+index*sizeof(IMAGE_IMPORT_DESCRIPTOR);
            if(!range(address,sizeof(IMAGE_IMPORT_DESCRIPTOR),mapped.imports,mapped.imports_end)||!readable(address,sizeof(IMAGE_IMPORT_DESCRIPTOR),mapped))return false;
            const auto* declared=reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(address);
            if(!declared->OriginalFirstThunk)return !declared->FirstThunk&&!declared->Name&&!declared->TimeDateStamp&&!declared->ForwarderChain;
            if(!declared->FirstThunk||!declared->Name||!bounded_name(reinterpret_cast<const char*>(mapped.base+declared->Name),mapped))return false;
            for(size_t thunk=0;thunk<4096;++thunk){
                if(++functions>16384||!live(state->packet))return false;
                const auto address=mapped.base+declared->OriginalFirstThunk+thunk*sizeof(IMAGE_THUNK_DATA64);
                if(!readable(address,sizeof(IMAGE_THUNK_DATA64),mapped))return false;
                const auto value=reinterpret_cast<const IMAGE_THUNK_DATA64*>(address)->u1.Ordinal;if(!value)break;
                const auto slot=mapped.base+declared->FirstThunk+thunk*sizeof(void*);
                if(!range(slot,sizeof(void*),mapped.iat,mapped.iat_end)||!readable(slot,sizeof(void*),mapped))return false;
                if(!IMAGE_SNAP_BY_ORDINAL64(value)&&(value>UINT32_MAX||!readable(mapped.base+static_cast<uint32_t>(value),sizeof(WORD)+1,mapped)||!bounded_name(reinterpret_cast<const char*>(mapped.base+static_cast<uint32_t>(value)+sizeof(WORD)),mapped)))return false;
                if(thunk==4095)return false;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER){return false;}
    return false;
}
static BOOL CALLBACK returned_import_file(void* context,HMODULE,LPCSTR name){
    auto* state=static_cast<ReturnedDiscovery*>(context);auto* packet=state->packet;
    if(!name){packet->callbacks_complete=state->error==ERROR_SUCCESS;return FALSE;}
    if(state->error)return FALSE;
    if(++packet->descriptor_count>256||!live(packet)){state->error=packet->setup_error?packet->setup_error:ERROR_BUFFER_OVERFLOW;return FALSE;}
    __try {
        const auto address=state->image.imports+(packet->descriptor_count-1)*sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if(!range(address,sizeof(IMAGE_IMPORT_DESCRIPTOR),state->image.imports,state->image.imports_end)||!readable(address,sizeof(IMAGE_IMPORT_DESCRIPTOR),state->image)){state->error=ERROR_INVALID_DATA;return FALSE;}
        const auto* declared=reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(address);
        if(!declared->OriginalFirstThunk||!declared->FirstThunk||!declared->Name||reinterpret_cast<uintptr_t>(name)!=state->image.base+declared->Name||!bounded_name(name,state->image)){state->error=ERROR_INVALID_DATA;return FALSE;}
        state->descriptor=GetModuleHandleA(name);HMODULE pinned=nullptr;
        if(state->descriptor&&(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(state->descriptor),&pinned)||pinned!=state->descriptor))state->descriptor=nullptr;
        state->original_thunk=state->image.base+declared->OriginalFirstThunk;
        state->first_thunk=state->image.base+declared->FirstThunk;state->thunk_index=0;return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER){state->error=ERROR_INVALID_ADDRESS;packet->incomplete=1;return FALSE;}
}
static BOOL CALLBACK returned_import_function(void* context,DWORD ordinal,LPCSTR name,void** slot){
    auto* state=static_cast<ReturnedDiscovery*>(context);auto* packet=state->packet;
    __try {
        if(state->error)return FALSE;
        if(state->thunk_index>=4096){state->error=ERROR_BUFFER_OVERFLOW;return FALSE;}
        const auto address=state->original_thunk+state->thunk_index*sizeof(IMAGE_THUNK_DATA64);
        if(!readable(address,sizeof(IMAGE_THUNK_DATA64),state->image)){state->error=ERROR_INVALID_DATA;return FALSE;}
        const auto thunk=reinterpret_cast<const IMAGE_THUNK_DATA64*>(address)->u1.Ordinal;
        if(!slot){if(thunk||ordinal||name)state->error=ERROR_INVALID_DATA;return state->error==ERROR_SUCCESS;}
        if(++packet->function_count>16384||!live(packet)){state->error=packet->setup_error?packet->setup_error:ERROR_BUFFER_OVERFLOW;return FALSE;}
        const auto slot_address=reinterpret_cast<uintptr_t>(slot);
        if(!thunk||slot_address!=state->first_thunk+state->thunk_index*sizeof(void*)||!range(slot_address,sizeof(void*),state->image.iat,state->image.iat_end)||!readable(slot_address,sizeof(void*),state->image)){state->error=ERROR_INVALID_DATA;return FALSE;}
        ++state->thunk_index;size_t ordinal_operation=0;
        if(IMAGE_SNAP_BY_ORDINAL64(thunk)){
            if(name||!ordinal||ordinal>UINT16_MAX||IMAGE_ORDINAL64(thunk)!=ordinal||(thunk&~(IMAGE_ORDINAL_FLAG64|UINT64_C(0xffff)))){state->error=ERROR_INVALID_DATA;return FALSE;}
            if(state->descriptor){
                void* exports[16]={};for(size_t operation=0;operation<16;++operation)exports[operation]=reinterpret_cast<void*>(GetProcAddress(state->descriptor,state->route_hooks[operation].name));
                void* resolved=reinterpret_cast<void*>(GetProcAddress(state->descriptor,MAKEINTRESOURCEA(static_cast<WORD>(ordinal))));
                ordinal_operation=typed_ordinal_operation(resolved,*slot,exports,16);
                if(!resolved||resolved!=*slot){packet->incomplete=1;packet->scope_flags|=2;}
            }else{packet->incomplete=1;packet->scope_flags|=2;}
            if(ordinal_operation>16){state->error=ERROR_DUP_NAME;return FALSE;}
            if(!ordinal_operation)return TRUE;
        }else if(ordinal||!name||thunk>UINT32_MAX||reinterpret_cast<uintptr_t>(name)!=state->image.base+static_cast<uint32_t>(thunk)+sizeof(WORD)||!bounded_name(name,state->image)){state->error=ERROR_INVALID_DATA;return FALSE;}
        for(size_t operation=0;operation<16;++operation){
            if(ordinal_operation?ordinal_operation!=operation+1:!equals(name,state->route_hooks[operation].name,state->image))continue;
            if(packet->slot_count==16){state->error=ERROR_BUFFER_OVERFLOW;return FALSE;}
            for(size_t index=0;index<packet->slot_count;++index)if(packet->slots[index].slot==slot_address){state->error=ERROR_DUP_NAME;return FALSE;}
            auto& selected=packet->slots[packet->slot_count++];selected.slot=slot_address;selected.operation=static_cast<uint32_t>(operation+1);selected.descriptor_module=reinterpret_cast<uintptr_t>(state->descriptor);
            selected.original=reinterpret_cast<uintptr_t>(*slot);Page page={};HMODULE owner=nullptr;Image target_image={};const uint32_t bit=1u<<operation;
            if(!data_page(slot,state->image,&page)||!state->descriptor||GetProcAddress(state->descriptor,state->route_hooks[operation].name)!=reinterpret_cast<FARPROC>(*slot)||
                !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(*slot),&owner)||!executable(*slot,owner)){
                state->unsupported_mask|=bit;packet->scope_flags|=2;packet->incomplete=1;continue;
            }
            auto& proof=state->targets[operation];
            if((proof.entry&&proof.entry!=selected.original)||(!proof.entry&&!capture_node_data(owner,*slot,&proof,&target_image,&packet->incomplete,false))){state->unsupported_mask|=bit;packet->scope_flags|=2;packet->incomplete=1;continue;}
            selected.hook=reinterpret_cast<uintptr_t>(state->route_hooks[operation].target);
        }
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER){state->error=ERROR_INVALID_ADDRESS;packet->incomplete=1;return FALSE;}
}
static bool returned_owner(HMODULE module,WsaNode* owner,Image* mapped,uint32_t* incomplete){
    __try {
        if(!image(module,mapped))return false;
        const auto* dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
        const auto* nt=reinterpret_cast<const IMAGE_NT_HEADERS64*>(mapped->base+dos->e_lfanew);
        if((nt->FileHeader.Characteristics&(IMAGE_FILE_DLL|IMAGE_FILE_EXECUTABLE_IMAGE))!=(IMAGE_FILE_DLL|IMAGE_FILE_EXECUTABLE_IMAGE))return false;
        owner->owner_base=mapped->base;owner->owner_size=mapped->size;owner->timestamp=mapped->timestamp;owner->machine=mapped->machine;
        const DWORD length=GetModuleFileNameW(module,reinterpret_cast<WCHAR*>(owner->module_name),64);
        if(!length||length>=64)*incomplete=1;
        // No provider entrypoint was observed; entry and entry_len stay zero.
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
static bool returned_route_live(const WsaPacket* packet,const WsaNode* targets,const Hook* route_hooks=returned_hooks){
    __try {
        if(packet->node_count!=1||packet->hop_count||packet->slot_count>16)return false;
        const auto& owner=packet->nodes[0];Image mapped={};WsaNode checked={};uint32_t incomplete=0;
        if(!returned_owner(reinterpret_cast<HMODULE>(owner.owner_base),&checked,&mapped,&incomplete)||checked.owner_size!=owner.owner_size||checked.timestamp!=owner.timestamp||checked.machine!=owner.machine||owner.entry||owner.entry_len)return false;
        for(size_t index=0;index<packet->slot_count;++index){
            const auto& selected=packet->slots[index];if(!selected.hook)continue;
            if(!selected.operation||selected.operation>16)return false;
            const auto& proof=targets[selected.operation-1];Image target_image={};Page page={};
            if(!proof.entry||!image(reinterpret_cast<HMODULE>(proof.owner_base),&target_image,false)||target_image.size!=proof.owner_size||target_image.timestamp!=proof.timestamp||target_image.machine!=proof.machine||!executable(reinterpret_cast<void*>(proof.entry),reinterpret_cast<HMODULE>(proof.owner_base))||!proof.entry_len||proof.entry_len>16||!readable(proof.entry,proof.entry_len,target_image))return false;
            for(size_t byte=0;byte<proof.entry_len;++byte)if(reinterpret_cast<const uint8_t*>(proof.entry)[byte]!=proof.entry_bytes[byte])return false;
            if(selected.hook!=reinterpret_cast<uintptr_t>(route_hooks[selected.operation-1].target)||!data_page(reinterpret_cast<void**>(selected.slot),mapped,&page)||!readable(selected.slot,sizeof(void*),mapped)||*reinterpret_cast<void**>(selected.slot)!=reinterpret_cast<void*>(selected.published?selected.hook:selected.original)||selected.original!=proof.entry||GetProcAddress(reinterpret_cast<HMODULE>(selected.descriptor_module),route_hooks[selected.operation-1].name)!=reinterpret_cast<FARPROC>(selected.original))return false;
        }
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
static void returned_rollback(WsaPacket* packet){
    for(size_t index=packet->slot_count;index>0;--index){
        auto& selected=packet->slots[index-1];if(!selected.published)continue;
        if(swap(reinterpret_cast<void**>(selected.slot),reinterpret_cast<void*>(selected.original),reinterpret_cast<void*>(selected.hook))!=reinterpret_cast<void*>(selected.hook)){packet->rollback_error=ERROR_RETRY;__fastfail(FAST_FAIL_FATAL_APP_EXIT);}
        selected.published=0;selected.restored=1;
    }
}
static bool returned_publish(WsaPacket* packet,const Image& mapped,const WsaNode* targets,std::atomic<void*>* published_originals=returned_originals,const Hook* route_hooks=returned_hooks){
    Page pages[16]={};size_t count=0;
    for(size_t index=0;index<packet->slot_count;++index){
        const auto& selected=packet->slots[index];if(!selected.hook)continue;Page page={};
        if(!data_page(reinterpret_cast<void**>(selected.slot),mapped,&page)){failure(packet,5,ERROR_INVALID_ADDRESS);return false;}
        bool present=false;for(size_t previous=0;previous<count;++previous)if(pages[previous].base==page.base)present=true;if(!present)pages[count++]=page;
        void* expected=nullptr;void* target=reinterpret_cast<void*>(selected.original);
        if(!published_originals[selected.operation-1].compare_exchange_strong(expected,target,std::memory_order_acq_rel,std::memory_order_acquire)&&expected!=target){failure(packet,6,ERROR_RETRY);return false;}
    }
    if(!writable(pages,count,packet))return false;
    bool success=returned_route_live(packet,targets,route_hooks);if(!success)failure(packet,6,ERROR_RETRY);
    for(size_t index=0;success&&index<packet->slot_count;++index){
        auto& selected=packet->slots[index];if(!selected.hook)continue;
        if(!live(packet)||swap(reinterpret_cast<void**>(selected.slot),reinterpret_cast<void*>(selected.hook),reinterpret_cast<void*>(selected.original))!=reinterpret_cast<void*>(selected.original)){failure(packet,6,packet->setup_error?packet->setup_error:ERROR_RETRY);success=false;break;}
        selected.published=1;
    }
    if(!success)returned_rollback(packet);
    restore(pages,count,packet);return success;
}
#include "native_file_request_trace.inc"
static void returned_failure(ListenerReturnedModule* section,uint32_t stage,DWORD error,uint32_t reason){
    section->setup_stage=stage;section->setup_error=error?error:ERROR_INVALID_DATA;section->setup_reason=reason;
    section->scope_flags|=2;section->incomplete=1;
}
static void returned_skipped(ListenerReturnedModule* section){section->skipped_count=increment(section->skipped_count);if(section->skipped_count==UINT32_MAX)section->incomplete=1;}
static bool returned_prepare(ListenerPacket* listener,HMODULE module){
    auto* section=&listener->returned_module;auto* packet=&section->dependencies;
    packet->version=1;packet->cutoff_qpc=listener->cutoff_qpc;packet->frequency=listener->frequency;packet->original_thread=listener->original_thread;packet->scope_flags=1;
    if(!live(packet)){returned_failure(section,2,packet->setup_error,7);return false;}
    LARGE_INTEGER started={};const BOOL started_clock=QueryPerformanceCounter(&started);
    if(!started_clock){const DWORD error=GetLastError();returned_failure(section,2,error,7);return false;}
    if(started.QuadPart<0){returned_failure(section,2,ERROR_INVALID_DATA,7);return false;}
    if(static_cast<uint64_t>(started.QuadPart)>=packet->cutoff_qpc){returned_failure(section,2,ERROR_TIMEOUT,7);return false;}
    packet->started_qpc=static_cast<uint64_t>(started.QuadPart);
    const LONG state=InterlockedCompareExchange(&returned_installed,1,0);
    if(state==2){
        if(returned_route.nodes[0].owner_base!=reinterpret_cast<uintptr_t>(module)){returned_failure(section,9,ERROR_NOT_SUPPORTED,4);return false;}
        copy_dependency_route(packet,&returned_route);
        if(!returned_route_live(packet,returned_target_proofs)){returned_failure(section,6,ERROR_RETRY,8);return false;}
        packet->setup_stage=1;section->setup_stage=1;section->setup_error=0;section->setup_reason=0;
        if(!live(packet)){returned_failure(section,2,packet->setup_error,7);return false;}
        return true;
    }
    if(state!=0){returned_failure(section,9,state==1?ERROR_BUSY:ERROR_NOT_SUPPORTED,5);return false;}
    HMODULE pinned=nullptr;Image mapped={};bool success=false;
    if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(module),&pinned)||pinned!=module||!returned_owner(module,&packet->nodes[0],&mapped,&packet->incomplete))returned_failure(section,3,ERROR_INVALID_DATA,6);
    else {
        packet->owner_pinned=1;packet->node_count=1;
        ReturnedDiscovery discovery={};discovery.image=mapped;discovery.packet=packet;
        bool complete=returned_bounded_imports(&discovery);
        if(complete){SetLastError(ERROR_SUCCESS);complete=DetourEnumerateImportsEx(module,&discovery,returned_import_file,returned_import_function)!=FALSE;const auto error=GetLastError();if(!complete&&!discovery.error)discovery.error=error?error:ERROR_INVALID_DATA;}
        for(size_t index=0;index<packet->slot_count;++index)if(discovery.unsupported_mask&(1u<<(packet->slots[index].operation-1)))packet->slots[index].hook=0;
        if(!complete||!packet->callbacks_complete||discovery.error||!verified(packet))returned_failure(section,4,packet->setup_error?packet->setup_error:discovery.error?discovery.error:ERROR_PROC_NOT_FOUND,7);
        else if(returned_route_live(packet,discovery.targets)){
            success=returned_publish(packet,mapped,discovery.targets);
            if(success){
                packet->setup_stage=1;packet->setup_error=0;save_dependency_route(packet,&returned_route);
                for(size_t index=0;index<16;++index)returned_target_proofs[index]=discovery.targets[index];
                section->setup_stage=1;section->setup_error=0;section->setup_reason=0;
            }else returned_failure(section,packet->setup_stage,packet->setup_error,7);
        }else returned_failure(section,6,ERROR_RETRY,8);
    }
    InterlockedExchange(&returned_installed,success?2:3);
    if(success&&!live(packet)){returned_failure(section,2,packet->setup_error,7);return false;}
    return success;
}
static volatile LONG loader_installed=0;
static DependencyRoute loader_route={};
static WsaNode loader_target_proofs[16]={};
static WsaNode loader_entry_proof={};
static bool loader_entry_live(void* target,HMODULE owner){
    WsaNode current={};Image mapped={};uint32_t incomplete=0;
    if(!capture_node_data(owner,target,&current,&mapped,&incomplete,false)||
       current.owner_base!=loader_entry_proof.owner_base||current.owner_size!=loader_entry_proof.owner_size||
       current.timestamp!=loader_entry_proof.timestamp||current.machine!=loader_entry_proof.machine||
       current.entry!=loader_entry_proof.entry||current.entry_len!=loader_entry_proof.entry_len)return false;
    for(size_t index=0;index<current.entry_len;++index)if(current.entry_bytes[index]!=loader_entry_proof.entry_bytes[index])return false;
    return true;
}
static void loader_failure(ListenerLoaderOwner* scope,uint32_t stage,DWORD error,uint32_t reason){
    scope->setup_stage=stage;scope->setup_error=error?error:ERROR_INVALID_DATA;scope->setup_reason=reason;
    scope->scope_flags|=2;scope->incomplete=1;
}
static bool loader_prepare(ListenerPacket* listener,void* target){
    auto* scope=&listener->loader_owner;auto* packet=&scope->dependencies;
    packet->version=1;packet->cutoff_qpc=listener->cutoff_qpc;packet->frequency=listener->frequency;
    packet->original_thread=listener->original_thread;packet->scope_flags|=1;
    if(!live(packet)){loader_failure(scope,2,packet->setup_error,7);return false;}
    HMODULE owner=nullptr;
    const BOOL resolved=GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(target),&owner);
    const DWORD resolution_error=resolved?ERROR_SUCCESS:GetLastError();
    if(!resolved||!owner||!executable(target,owner)){
        loader_failure(scope,3,!resolved?resolution_error:ERROR_INVALID_ADDRESS,6);return false;
    }
    if(!live(packet)){loader_failure(scope,2,packet->setup_error,7);return false;}
    if(scope->selected&&(scope->loader_target!=reinterpret_cast<uintptr_t>(target)||scope->owner_base!=reinterpret_cast<uintptr_t>(owner))){loader_failure(scope,9,ERROR_NOT_SUPPORTED,4);return false;}
    scope->selected=1;scope->loader_target=reinterpret_cast<uintptr_t>(target);scope->owner_base=reinterpret_cast<uintptr_t>(owner);scope->scope_flags|=1;
    const LONG state=InterlockedCompareExchange(&loader_installed,1,0);
    if(state==2){
        if(loader_route.nodes[0].owner_base!=reinterpret_cast<uintptr_t>(owner)||!loader_entry_live(target,owner)){loader_failure(scope,9,ERROR_NOT_SUPPORTED,4);return false;}
        copy_dependency_route(packet,&loader_route);
        if(!returned_route_live(packet,loader_target_proofs,loader_hooks)){loader_failure(scope,6,ERROR_RETRY,8);return false;}
        packet->setup_stage=1;scope->setup_stage=1;scope->setup_error=0;scope->setup_reason=0;
        if(!live(packet)){loader_failure(scope,2,packet->setup_error,7);return false;}
        return true;
    }
    if(state!=0){loader_failure(scope,9,state==1?ERROR_BUSY:ERROR_NOT_SUPPORTED,5);return false;}
    Image mapped={};WsaNode entry_proof={};bool success=false;
    if(!capture_node_data(owner,target,&entry_proof,&mapped,&packet->incomplete,false)||!returned_owner(owner,&packet->nodes[0],&mapped,&packet->incomplete))loader_failure(scope,3,ERROR_INVALID_DATA,6);
    else{
        packet->owner_pinned=1;packet->node_count=1;
        ReturnedDiscovery discovery={};discovery.image=mapped;discovery.packet=packet;discovery.route_hooks=loader_hooks;
        bool complete=returned_bounded_imports(&discovery);
        if(complete){SetLastError(ERROR_SUCCESS);complete=DetourEnumerateImportsEx(owner,&discovery,returned_import_file,returned_import_function)!=FALSE;const auto error=GetLastError();if(!complete&&!discovery.error)discovery.error=error?error:ERROR_INVALID_DATA;}
        for(size_t index=0;index<packet->slot_count;++index)if(discovery.unsupported_mask&(1u<<(packet->slots[index].operation-1)))packet->slots[index].hook=0;
        if(!complete||!packet->callbacks_complete||discovery.error||!verified(packet))loader_failure(scope,4,packet->setup_error?packet->setup_error:discovery.error?discovery.error:ERROR_PROC_NOT_FOUND,7);
        else if(returned_route_live(packet,discovery.targets,loader_hooks)){
            success=returned_publish(packet,mapped,discovery.targets,loader_originals,loader_hooks);
            if(success){
                bool ldr_route=false;
                for(size_t index=0;index<packet->slot_count;++index)if(packet->slots[index].operation==4&&packet->slots[index].hook&&packet->slots[index].published)ldr_route=true;
                if(!ldr_route){packet->scope_flags|=2;packet->incomplete=1;}
                packet->setup_stage=1;packet->setup_error=0;save_dependency_route(packet,&loader_route);
                for(size_t index=0;index<16;++index)loader_target_proofs[index]=discovery.targets[index];
                loader_entry_proof=entry_proof;scope->setup_stage=1;scope->setup_error=0;scope->setup_reason=0;
            }else loader_failure(scope,packet->setup_stage,packet->setup_error,7);
        }else loader_failure(scope,6,ERROR_RETRY,8);
    }
    InterlockedExchange(&loader_installed,success?2:3);
    if(success&&!live(packet)){loader_failure(scope,2,packet->setup_error,7);return false;}
    return success;
}
static LoaderCallScope loader_owner_begin(const WsaEntry* entry,bool active,void* target){
    LoaderCallScope result={};auto* listener=collector.timeline;
    if(!listener||observer_setup_active||!listener_collector.depth||listener_collector.operations[listener_collector.depth-1]!=2)return result;
    result.previous=loader_collector;result.packet=listener;result.managed=true;
    auto* scope=&listener->loader_owner;scope->attempt_count=increment(scope->attempt_count);
    if(scope->attempt_count==UINT32_MAX)scope->incomplete=1;
    if(loader_collector.packet){loader_collector.packet->incomplete=1;if(loader_collector.timeline)loader_collector.timeline->incomplete=1;loader_collector={};loader_failure(scope,9,ERROR_BUSY,5);scope->skipped_count=increment(scope->skipped_count);return result;}
    ListenerDependencyLink link={};
    if(active)for(uint32_t index=0;index<collector.pending_count;++index)if(collector.pending[index].dependency_sequence==entry->sequence)link=collector.pending[index];
    if(!active||!link.timeline_sequence||link.parent_listener_sequence!=listener_parent()){
        loader_failure(scope,4,ERROR_NOT_SUPPORTED,3);scope->skipped_count=increment(scope->skipped_count);return result;
    }
    ObserverSetup setup;
    bool prepared=false;
    if(dependency_private_routes[2].load(std::memory_order_acquire)){
        // Only the isolated native selfcheck publishes private forwarding
        // targets. Its prepare callback never installs or changes a real IAT.
        const auto prepare=loader_private_prepare.load(std::memory_order_acquire);
        if(prepare)prepared=prepare(listener,target);else loader_failure(scope,9,ERROR_BUSY,5);
    }else {
        prepared=loader_prepare(listener,target);
        native_file_prepare(listener,target,loader_originals[3].load(std::memory_order_acquire));
    }
    scope->scope_flags|=scope->dependencies.scope_flags;scope->incomplete|=scope->dependencies.incomplete;
    if(!prepared){scope->skipped_count=increment(scope->skipped_count);return result;}
    scope->armed=1;scope->dependencies.armed=1;scope->dependencies.incoming_error=entry->incoming_error;
    if(!scope->dependencies.started_qpc)scope->dependencies.started_qpc=listener->started_qpc;
    loader_collector={};loader_collector.packet=&scope->dependencies;loader_collector.timeline=listener;
    loader_collector.parent_listener_sequence=link.parent_listener_sequence;loader_collector.loader_dependency_sequence=link.dependency_sequence;loader_collector.loader_timeline_sequence=link.timeline_sequence;
    return result;
}
static void loader_owner_end(const LoaderCallScope& call){
    if(!call.managed)return;
    auto& scope=call.packet->loader_owner;
    if(loader_collector.timeline==call.packet&&loader_collector.pending_count){scope.incomplete=1;scope.dependencies.incomplete=1;}
    scope.incomplete|=scope.dependencies.incomplete;
    loader_collector=call.previous;
}
static void returned_module_loaded(const WsaEntry* entry,bool active,HMODULE module,HANDLE file,DWORD flags){
    auto* listener=collector.timeline;
    if(!listener||observer_setup_active||!listener_collector.depth||listener_collector.operations[listener_collector.depth-1]!=2)return;
    auto* section=&listener->returned_module;section->selection_count=increment(section->selection_count);
    if(section->selection_count==UINT32_MAX)section->incomplete=1;
    if(!module||file||flags){
        returned_skipped(section);
        if(!section->selected)returned_failure(section,4,!module?ERROR_MOD_NOT_FOUND:ERROR_NOT_SUPPORTED,!module?1:2);
        return;
    }
    if(section->selected){
        returned_skipped(section);
        if(section->returned_module!=reinterpret_cast<uintptr_t>(module))returned_failure(section,9,ERROR_NOT_SUPPORTED,4);
        return;
    }
    ListenerDependencyLink link={};
    if(active)for(size_t index=0;index<listener->dependency_link_count;++index)if(listener->dependency_links[index].dependency_sequence==entry->sequence)link=listener->dependency_links[index];
    if(!active||!link.timeline_sequence||link.parent_listener_sequence!=listener_parent()){
        returned_skipped(section);returned_failure(section,4,ERROR_NOT_SUPPORTED,3);return;
    }
    section->selected=1;section->returned_module=reinterpret_cast<uintptr_t>(module);section->scope_flags=1;
    section->parent_listener_sequence=link.parent_listener_sequence;section->loader_dependency_sequence=link.dependency_sequence;section->loader_timeline_sequence=link.timeline_sequence;
    section->dependencies.incoming_error=entry->outgoing_error;
    ObserverSetup setup;
    if(returned_prepare(listener,module)){
        section->armed=1;section->dependencies.armed=1;
        returned_collector={};returned_collector.packet=&section->dependencies;returned_collector.timeline=listener;
    }else returned_skipped(section);
    section->scope_flags|=section->dependencies.scope_flags;section->incomplete|=section->dependencies.incomplete;
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
    if(returned_collector.timeline==packet){
        if(returned_collector.pending_count){packet->returned_module.incomplete=1;packet->returned_module.dependencies.incomplete=1;}
        returned_collector={};
    }
    if(loader_collector.timeline==packet){
        if(loader_collector.pending_count){packet->loader_owner.incomplete=1;packet->loader_owner.dependencies.incomplete=1;}
        loader_collector={};
    }
    packet->loader_owner.incomplete|=packet->loader_owner.dependencies.incomplete;
    if(packet->loader_owner.incomplete)packet->incomplete=1;
    packet->returned_module.incomplete|=packet->returned_module.dependencies.incomplete;
    if(packet->returned_module.incomplete)packet->incomplete=1;
    if(packet->dependencies.incomplete)packet->incomplete=1;
}
static void listener_invoke(ListenerPacket* packet,const ListenerRequest* request,ListenerInvoke callback,void* opaque,bool ready){
    // Admission is the same original-work QPC cutoff; observation unavailability
    // never supplies a second reason to suppress or retry the Rust aggregate.
    if(!listener_live(packet,true)){errors_restore({request->incoming_win32,request->incoming_wsa});return;}
    const ListenerCollector previous_listener=listener_collector;const Collector previous_dependencies=collector,previous_returned=returned_collector,previous_loader=loader_collector;
    const bool occupied=previous_listener.packet||previous_dependencies.packet||previous_returned.packet||previous_loader.packet;
    listener_collector={};collector={};returned_collector={};loader_collector={};
    if(occupied){
        if(previous_listener.packet)previous_listener.packet->incomplete=1;
        if(previous_dependencies.packet)previous_dependencies.packet->incomplete=1;
        if(previous_dependencies.timeline)previous_dependencies.timeline->incomplete=1;
        if(previous_returned.packet)previous_returned.packet->incomplete=1;
        if(previous_returned.timeline)previous_returned.timeline->incomplete=1;
        if(previous_loader.packet)previous_loader.packet->incomplete=1;
        if(previous_loader.timeline)previous_loader.timeline->incomplete=1;
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
        listener_collector=previous_listener;collector=previous_dependencies;returned_collector=previous_returned;loader_collector=previous_loader;
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
    listener_collector=previous_listener;collector=previous_dependencies;returned_collector=previous_returned;loader_collector=previous_loader;
    packet->outgoing_win32=outgoing.win32;packet->outgoing_wsa=outgoing.wsa;
    packet->dependencies.outgoing_error=outgoing.win32;
    if(packet->returned_module.armed)packet->returned_module.dependencies.outgoing_error=outgoing.win32;
    if(packet->loader_owner.armed)packet->loader_owner.dependencies.outgoing_error=outgoing.win32;
    LARGE_INTEGER finished={};
    if(QueryPerformanceCounter(&finished)&&finished.QuadPart>=0)packet->finished_qpc=static_cast<uint64_t>(finished.QuadPart);else packet->incomplete=1;
    packet->dependencies.finished_qpc=packet->finished_qpc;
    if(packet->returned_module.armed)packet->returned_module.dependencies.finished_qpc=packet->finished_qpc;
    if(packet->loader_owner.armed)packet->loader_owner.dependencies.finished_qpc=packet->finished_qpc;
    if(!outcome.kind||outcome.kind>3||outcome.raw_error_present>1||outcome.reserved)__fastfail(FAST_FAIL_FATAL_APP_EXIT);
    packet->callback_outcome=outcome.kind;packet->callback_raw_error_present=outcome.raw_error_present;packet->callback_raw_error=outcome.raw_error;
    if(outcome.kind==3)packet->incomplete=1;
    if(!listener_live(packet))packet->incomplete=1;
    errors_restore(outgoing);
}
extern "C" void memcordon_listener_trace_call(ListenerPacket* packet,const ListenerRequest* request,ListenerInvoke callback,void* opaque){
    if(!packet||!request||!callback)__fastfail(FAST_FAIL_FATAL_APP_EXIT);
    *packet={};packet->version=5;packet->returned_module.version=1;packet->loader_owner.version=2;packet->scope_flags=1;
    packet->returned_images.version=1;packet->returned_images.enabled=(request->experiment_flags==1&&request->reserved==0)?1:0;
    packet->cutoff_qpc=request->cutoff_qpc;packet->frequency=request->frequency;
    packet->incoming_win32=request->incoming_win32;packet->incoming_wsa=request->incoming_wsa;
    packet->original_thread=GetCurrentThreadId();packet->listener_owner_anchor=reinterpret_cast<uintptr_t>(callback);
    packet->returned_module.dependencies.version=1;packet->returned_module.dependencies.cutoff_qpc=packet->cutoff_qpc;
    packet->returned_module.dependencies.frequency=packet->frequency;packet->returned_module.dependencies.original_thread=packet->original_thread;
    packet->loader_owner.dependencies.version=1;packet->loader_owner.dependencies.cutoff_qpc=packet->cutoff_qpc;
    packet->loader_owner.dependencies.frequency=packet->frequency;packet->loader_owner.dependencies.original_thread=packet->original_thread;
    bool ready=false;{ObserverSetup setup;ready=listener_install(packet,reinterpret_cast<void*>(callback));}
    listener_invoke(packet,request,callback,opaque,ready);
}
extern "C" void memcordon_listener_native_file_trace_call(ListenerPacket* packet,const ListenerRequest* request,ListenerInvoke callback,void* opaque,NativeFilePacket* native){
    if(!native||!request){memcordon_listener_trace_call(packet,request,callback,opaque);return;}
    const auto previous=native_file_output;const auto previous_scope=native_file_collector;
    *native={};native->version=NativeFileVersion;native->packet_bytes=sizeof(*native);
    native->cutoff_qpc=request->cutoff_qpc;native->frequency=request->frequency;native->original_thread=GetCurrentThreadId();
    for(auto& owner:native->owners)owner.shared_owner=UINT32_MAX;
    if(previous||previous_scope.packet){native->incomplete=1;native->unmatched_scope=1;if(previous)previous->incomplete=1;}
    native_file_output=native;native_file_collector={};
    __try {memcordon_listener_trace_call(packet,request,callback,opaque);}
    __finally {
        const auto outgoing=errors();
        if(AbnormalTermination())native->incomplete=1;
        if(native_file_collector.packet){native->incomplete=1;native->unmatched_scope=increment(native->unmatched_scope);}
        native_file_output=previous;native_file_collector=previous_scope;errors_restore(outgoing);
    }
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
    bool good=swap(slot,reinterpret_cast<void*>(open_key<false>),reinterpret_cast<void*>(mock_open))==reinterpret_cast<void*>(mock_open)&&*slot==reinterpret_cast<void*>(open_key<false>);
    good=good&&swap(slot,reinterpret_cast<void*>(mock_open),reinterpret_cast<void*>(open_key<false>))==reinterpret_cast<void*>(open_key<false>);
    good=good&&swap(slot,reinterpret_cast<void*>(open_key<false>),reinterpret_cast<void*>(mock_heap))==reinterpret_cast<void*>(mock_open)&&*slot==reinterpret_cast<void*>(mock_open);
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
    const sockaddr* address;int length;bool fail[7];bool nested,dependency,route_dependencies;
};
static void returned_mock_nested_work();
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
    if(state->route_dependencies)returned_mock_nested_work();
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
    ListenerCollector previous_listener;Collector previous_dependencies,previous_returned,previous_loader;
    ~ListenerMockScope(){
        listener_collector=previous_listener;collector=previous_dependencies;returned_collector=previous_returned;loader_collector=previous_loader;
        listener_private_route.store(nullptr,std::memory_order_release);listener_mock.store(nullptr,std::memory_order_release);
        // No real route was published, and permanent originals were never set.
        InterlockedExchange(&listener_installed,0);
    }
};
static void listener_mock_packet(ListenerPacket* packet,uint64_t cutoff,uint64_t frequency){
    *packet={};packet->version=4;packet->returned_module.version=1;packet->loader_owner.version=2;packet->cutoff_qpc=cutoff;packet->frequency=frequency;packet->original_thread=GetCurrentThreadId();
    packet->returned_module.dependencies.version=1;packet->returned_module.dependencies.cutoff_qpc=cutoff;packet->returned_module.dependencies.frequency=frequency;packet->returned_module.dependencies.original_thread=packet->original_thread;
    packet->loader_owner.dependencies.version=1;packet->loader_owner.dependencies.cutoff_qpc=cutoff;packet->loader_owner.dependencies.frequency=frequency;packet->loader_owner.dependencies.original_thread=packet->original_thread;
    listener_collector={};listener_collector.packet=packet;collector={};returned_collector={};loader_collector={};
}
static void listener_mock_dependencies(ListenerPacket* packet){
    packet->dependencies={};packet->dependencies.version=1;
    packet->dependencies.cutoff_qpc=packet->cutoff_qpc;packet->dependencies.frequency=packet->frequency;
    collector={};collector.packet=&packet->dependencies;collector.timeline=packet;
}
struct ImageMock {uint32_t queries,names,mode;};
static thread_local ImageMock image_mock={};
static SIZE_T WINAPI image_mock_query(LPCVOID address,PMEMORY_BASIC_INFORMATION info,SIZE_T size){
    ++image_mock.queries;SetLastError(87);WSASetLastError(10022);
    if(image_mock.mode==1){SetLastError(5);return 0;}
    if(size!=sizeof(*info))return 0;
    *info={};info->AllocationBase=const_cast<void*>(address);info->Type=MEM_IMAGE;info->State=MEM_COMMIT;
    if(image_mock.mode==2)info->Type=MEM_PRIVATE;
    return sizeof(*info);
}
static DWORD WINAPI image_mock_name(HANDLE process,LPVOID,LPWSTR path,DWORD capacity){
    ++image_mock.names;SetLastError(31);WSASetLastError(10013);
    if(process!=GetCurrentProcess()||capacity!=512)return 0;
    if(image_mock.mode==3){SetLastError(5);return 0;}
    if(image_mock.mode==4)return capacity;
    const WCHAR name[]=L"\\Device\\HarddiskVolume3\\private\\mswsock.dll";
    const DWORD units=static_cast<DWORD>(sizeof(name)/sizeof(name[0])-1);
    memcpy(path,name,units*sizeof(WCHAR));return units;
}
static uint32_t image_native_mock(ListenerPacket* packet,uint64_t cutoff,uint64_t frequency){
    const ReturnedImageApis api={image_mock_query,image_mock_name};
    errors_restore({0x12345678,10035});const auto incoming=errors();
    WsaEntry entry={};entry.sequence=91;
    for(uint32_t mode=0;mode!=5;++mode){
        listener_mock_packet(packet,cutoff,frequency);listener_mock_dependencies(packet);
        listener_collector.depth=1;listener_collector.parents[0]=42;listener_collector.operations[0]=2;
        packet->returned_images.version=1;image_mock={0,0,mode};
        errors_restore(incoming);returned_image(&entry,true,reinterpret_cast<HMODULE>(0x10000),api);
        if(image_mock.queries||image_mock.names||packet->returned_images.count||!same_errors(errors(),incoming))return 35;
        packet->returned_images.enabled=1;
        returned_image(&entry,true,reinterpret_cast<HMODULE>(0x10000),api);
        const auto& row=packet->returned_images.rows[0];
        if(image_mock.queries!=1||image_mock.names!=(mode==1||mode==2?0u:1u)||packet->returned_images.count!=1||row.dependency_sequence!=91||row.parent_listener_sequence!=42||!same_errors(errors(),incoming))return 35;
        const uint32_t expected[]={1,3,4,5,6};
        if(row.state!=expected[mode]||(mode==0&&(row.flags!=7||row.mapped_path_units==0)))return 35;
        packet->returned_images.count=8;const auto queried=image_mock.queries,named=image_mock.names;
        returned_image(&entry,true,reinterpret_cast<HMODULE>(0x10000),api);
        if(image_mock.queries!=queried||image_mock.names!=named||packet->returned_images.dropped!=1||!packet->returned_images.incomplete||!same_errors(errors(),incoming))return 35;
    }
    return 0;
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
struct ReturnedMock {
    std::atomic<uint32_t> ws2_calls,provider_calls,loader_calls;
    std::atomic<bool> same;ErrorPair incoming,outgoing;bool nested,fail;
    LPCWSTR path;HMODULE module;
    std::atomic<uint32_t> loader_native_calls,loader_heap_calls,prepare_calls;
    bool loader_nested,prepare_failed;
    uint32_t window_clock_mode,window_clock_calls;
    uint64_t window_clock_start,window_clock_cutoff;
    PWSTR search;PULONG flags;PUNICODE_STRING name;PHANDLE output;
};
static std::atomic<ReturnedMock*> returned_mock{nullptr};
static ReturnedMock* returned_mock_enter(void* handle,ULONG flags,SIZE_T size){
    const auto incoming=errors();auto* state=returned_mock.load(std::memory_order_acquire);
    if(!state)__fastfail(FAST_FAIL_FATAL_APP_EXIT);
    if(handle!=reinterpret_cast<void*>(0x3210)||flags!=0x1234||size!=(UINT64_C(1)<<40)||!same_errors(incoming,state->incoming))state->same=false;
    return state;
}
static void* NTAPI returned_mock_provider_heap(void* handle,ULONG flags,SIZE_T size){
    auto* state=returned_mock_enter(handle,flags,size);++state->provider_calls;
    errors_restore(state->outgoing);return state->fail?nullptr:reinterpret_cast<void*>(0x2222);
}
static void* NTAPI returned_mock_ws2_heap(void* handle,ULONG flags,SIZE_T size){
    auto* state=returned_mock_enter(handle,flags,size);++state->ws2_calls;
    if(state->nested&&heap<true>(handle,flags,size)!=reinterpret_cast<void*>(0x2222))state->same=false;
    errors_restore(state->outgoing);return reinterpret_cast<void*>(0x1111);
}
static HMODULE WINAPI returned_mock_loader(LPCWSTR path,HANDLE file,DWORD flags){
    const auto incoming=errors();auto* state=returned_mock.load(std::memory_order_acquire);++state->loader_calls;
    if(path!=state->path||file||flags||!same_errors(incoming,state->incoming))state->same=false;
    if(state->loader_nested){
        if(load_dll<2>(state->search,state->flags,state->name,state->output)!=static_cast<NTSTATUS>(0xC0000022u))state->same=false;
    }
    errors_restore(state->outgoing);return state->module;
}
static NTSTATUS NTAPI loader_mock_native(PWSTR search,PULONG flags,PUNICODE_STRING name,PHANDLE output){
    const auto incoming=errors();auto* state=returned_mock.load(std::memory_order_acquire);++state->loader_native_calls;
    if(search!=state->search||flags!=state->flags||name!=state->name||output!=state->output||!same_errors(incoming,state->incoming))state->same=false;
    errors_restore(state->outgoing);return static_cast<NTSTATUS>(0xC0000022u);
}
static BOOL loader_mock_clock(LARGE_INTEGER* value){
    auto* state=returned_mock.load(std::memory_order_acquire);const bool finish=(state->window_clock_calls++%2)!=0;
    // Deliberately clobber both reachable channels: forwarding must restore the
    // original incoming/outgoing pair around either optional QPC read.
    seed_listener_error(0xabc1);
    value->QuadPart=static_cast<LONGLONG>(state->window_clock_start+(finish?1:0));
    if(state->window_clock_mode==1&&!finish)return FALSE;
    if(state->window_clock_mode==2&&!finish)value->QuadPart=-1;
    if(state->window_clock_mode==3&&finish)return FALSE;
    if(state->window_clock_mode==4&&finish)value->QuadPart=static_cast<LONGLONG>(state->window_clock_start-1);
    if(state->window_clock_mode==5&&finish)value->QuadPart=static_cast<LONGLONG>(state->window_clock_cutoff+1);
    if(state->window_clock_mode==6&&!finish)value->QuadPart=0;
    return TRUE;
}
static void* NTAPI loader_mock_heap(void* handle,ULONG flags,SIZE_T size){
    auto* state=returned_mock_enter(handle,flags,size);++state->loader_heap_calls;
    errors_restore(state->outgoing);return reinterpret_cast<void*>(0x3333);
}
static bool loader_mock_prepare(ListenerPacket* listener,void* target){
    auto* state=returned_mock.load(std::memory_order_acquire);++state->prepare_calls;
    auto* scope=&listener->loader_owner;
    if(target!=reinterpret_cast<void*>(returned_mock_loader)||InterlockedCompareExchange(&loader_installed,0,0)!=0)state->same=false;
    for(const auto& original:loader_originals)if(original.load(std::memory_order_acquire))state->same=false;
    if(!live(&scope->dependencies)){loader_failure(scope,2,scope->dependencies.setup_error,7);return false;}
    if(state->prepare_failed){loader_failure(scope,4,ERROR_NOT_SUPPORTED,7);return false;}
    scope->selected=1;scope->loader_target=reinterpret_cast<uintptr_t>(target);scope->owner_base=0x55550000;
    scope->scope_flags=1;scope->setup_stage=1;scope->setup_error=0;scope->setup_reason=0;
    return true;
}
static void returned_mock_nested_work(){
    auto* state=returned_mock.load(std::memory_order_acquire);
    if(heap<false>(reinterpret_cast<void*>(0x3210),0x1234,UINT64_C(1)<<40)!=reinterpret_cast<void*>(0x1111))state->same=false;
}
struct ReturnedMockScope {
    ListenerCollector previous_listener;Collector previous_ws2,previous_returned;bool previous_setup;
    bool owns_ws2,owns_returned;
    Collector previous_loader;
    ~ReturnedMockScope(){
        dependency_private_routes[0].store(nullptr,std::memory_order_release);dependency_private_routes[1].store(nullptr,std::memory_order_release);dependency_private_routes[2].store(nullptr,std::memory_order_release);loader_private_prepare.store(nullptr,std::memory_order_release);loader_private_clock.store(nullptr,std::memory_order_release);returned_mock.store(nullptr,std::memory_order_release);
        listener_collector=previous_listener;collector=previous_ws2;returned_collector=previous_returned;loader_collector=previous_loader;observer_setup_active=previous_setup;
        // These states protected private mocks only; no live route was installed
        // and neither permanent original table was written or cleared.
        if(owns_returned)InterlockedExchange(&returned_installed,0);
        if(owns_ws2)InterlockedExchange(&installed,0);
    }
};
static void returned_mock_packets(ListenerPacket* packet,uint64_t cutoff,uint64_t frequency){
    listener_mock_packet(packet,cutoff,frequency);listener_mock_dependencies(packet);
    auto* section=&packet->returned_module;section->dependencies.version=1;
    section->dependencies.cutoff_qpc=cutoff;section->dependencies.frequency=frequency;section->dependencies.original_thread=packet->original_thread;
    returned_collector={};returned_collector.packet=&section->dependencies;returned_collector.timeline=packet;
}
static DWORD WINAPI returned_mock_thread(void*){
    auto* state=returned_mock.load(std::memory_order_acquire);errors_restore(state->incoming);
    const auto result=heap<true>(reinterpret_cast<void*>(0x3210),0x1234,UINT64_C(1)<<40);const auto outgoing=errors();
    if(result!=reinterpret_cast<void*>(0x2222)||!same_errors(outgoing,state->outgoing))return 1;
    errors_restore(state->incoming);const auto loader=heap<2>(reinterpret_cast<void*>(0x3210),0x1234,UINT64_C(1)<<40);const auto loader_errors=errors();
    return loader==reinterpret_cast<void*>(0x3333)&&same_errors(loader_errors,state->outgoing)&&!loader_collector.packet&&!returned_collector.packet&&!collector.packet&&!listener_collector.packet?0:1;
}
struct ReturnedMockCallback {ListenerPacket* packet;ReturnedMock* state;uint32_t kind,calls;};
static void returned_mock_callback(void* opaque,ListenerOutcome* outcome){
    auto* invocation=static_cast<ReturnedMockCallback*>(opaque);++invocation->calls;
    // Private collector injection verifies the real callback exit/disarm path;
    // it neither installs a route nor invokes a Rust constructor or startup.
    collector={};collector.packet=&invocation->packet->dependencies;collector.timeline=invocation->packet;
    returned_collector={};returned_collector.packet=&invocation->packet->returned_module.dependencies;returned_collector.timeline=invocation->packet;
    loader_collector={};loader_collector.packet=&invocation->packet->loader_owner.dependencies;loader_collector.timeline=invocation->packet;
    if(heap<true>(reinterpret_cast<void*>(0x3210),0x1234,UINT64_C(1)<<40)!=reinterpret_cast<void*>(0x2222))invocation->state->same=false;
    *outcome={invocation->kind,invocation->kind==2?1u:0u,invocation->kind==2?2:0,0};
    errors_restore(invocation->state->outgoing);
}
static uint32_t returned_native_mock(ListenerPacket* packet,ListenerMock* listener,uint64_t cutoff,uint64_t frequency){
    ReturnedMockScope scope={listener_collector,collector,returned_collector,observer_setup_active,false,false,loader_collector};
    if(InterlockedCompareExchange(&installed,1,0)!=0)return 17;scope.owns_ws2=true;
    if(InterlockedCompareExchange(&returned_installed,1,0)!=0)return 17;scope.owns_returned=true;
    for(const auto& target:returned_originals)if(target.load(std::memory_order_acquire))return 17;
    ReturnedMock state={};state.same=true;state.incoming=listener->incoming;state.outgoing=listener->outgoing;
    const WCHAR path[]={L'p',L'r',L'i',L'v',L'a',L't',L'e',0};state.path=path;state.module=reinterpret_cast<HMODULE>(UINT64_C(0x1234567887650000));
    DependencyPrivateRoute ws2={},provider={},loader_targets={};ws2.targets[8]=reinterpret_cast<void*>(returned_mock_ws2_heap);provider.targets[8]=reinterpret_cast<void*>(returned_mock_provider_heap);
    loader_targets.targets[3]=reinterpret_cast<void*>(loader_mock_native);loader_targets.targets[8]=reinterpret_cast<void*>(loader_mock_heap);
    ws2.targets[11]=reinterpret_cast<void*>(returned_mock_loader);provider.targets[11]=reinterpret_cast<void*>(returned_mock_loader);
    returned_mock.store(&state,std::memory_order_release);dependency_private_routes[0].store(&ws2,std::memory_order_release);dependency_private_routes[1].store(&provider,std::memory_order_release);
    dependency_private_routes[2].store(&loader_targets,std::memory_order_release);loader_private_prepare.store(loader_mock_prepare,std::memory_order_release);
    returned_mock_packets(packet,cutoff,frequency);state.nested=true;listener->route_dependencies=true;
    errors_restore(state.incoming);const auto socket=listener_socket(-2,3,-4,listener->info,0xfedcba98,0x80000001);const auto outgoing=errors();listener->route_dependencies=false;
    if(socket!=INVALID_SOCKET||!same_errors(outgoing,state.outgoing)||!state.same||state.ws2_calls!=1||state.provider_calls!=1||packet->next_sequence!=6||packet->dependencies.total_calls!=1||packet->returned_module.dependencies.total_calls!=1||packet->dependency_links[0].dependency_sequence!=1||packet->dependency_links[0].timeline_sequence!=2||packet->returned_module.links[0].dependency_sequence!=1||packet->returned_module.links[0].timeline_sequence!=3||packet->dependency_links[0].parent_listener_sequence!=1||packet->returned_module.links[0].parent_listener_sequence!=1||packet->entries[0].completion_sequence!=6)return 18;
    if(packet->dependencies.entries[0].raw_output!=0x1111||packet->returned_module.dependencies.entries[0].raw_output!=0x2222)return 18;
    state.nested=false;
    // All three namespaces suppress setup-caused reentry without suppressing
    // the exact typed originals or changing either reachable error channel.
    returned_mock_packets(packet,cutoff,frequency);const auto before_ws2=state.ws2_calls.load(),before_provider=state.provider_calls.load(),before_listener=listener->calls[5].load();
    observer_setup_active=true;
    errors_restore(state.incoming);const auto ws2_value=heap<false>(reinterpret_cast<void*>(0x3210),0x1234,UINT64_C(1)<<40);const auto ws2_errors=errors();
    errors_restore(state.incoming);const auto provider_value=heap<true>(reinterpret_cast<void*>(0x3210),0x1234,UINT64_C(1)<<40);const auto provider_errors=errors();
    errors_restore(state.incoming);const auto closed=listener_close(listener_mock_socket);const auto close_errors=errors();
    errors_restore(state.incoming);const auto loaded=load_library<false>(state.path,nullptr,0);const auto loader_errors=errors();observer_setup_active=false;
    if(ws2_value!=reinterpret_cast<void*>(0x1111)||provider_value!=reinterpret_cast<void*>(0x2222)||closed!=SOCKET_ERROR||loaded!=state.module||!same_errors(ws2_errors,state.outgoing)||!same_errors(provider_errors,state.outgoing)||!same_errors(close_errors,state.outgoing)||!same_errors(loader_errors,state.outgoing)||state.ws2_calls!=before_ws2+1||state.provider_calls!=before_provider+1||listener->calls[5]!=before_listener+1||state.loader_calls!=1||packet->total_calls||packet->dependencies.total_calls||packet->returned_module.dependencies.total_calls||packet->returned_module.selection_count||packet->next_sequence)return 19;
    // A provider loader is recorded in its own namespace but never nominates
    // another returned module, even while the active parent is WSASocketW.
    listener_collector.depth=1;listener_collector.operations[0]=2;listener_collector.parents[0]=1;packet->next_sequence=1;
    errors_restore(state.incoming);if(load_library<true>(state.path,nullptr,0)!=state.module||packet->returned_module.selection_count||packet->returned_module.dependencies.entries[0].raw_output!=reinterpret_cast<uintptr_t>(state.module))return 20;
    // Unsupported/missing-link/capacity cases use the same selection helper.
    returned_mock_packets(packet,cutoff,frequency);listener_collector.depth=1;listener_collector.operations[0]=2;listener_collector.parents[0]=1;
    WsaEntry loader={};loader.sequence=1;
    returned_module_loaded(&loader,false,nullptr,nullptr,0);
    if(packet->returned_module.selected||packet->returned_module.setup_reason!=1||packet->returned_module.selection_count!=1||packet->returned_module.skipped_count!=1)return 20;
    returned_module_loaded(&loader,false,state.module,reinterpret_cast<HANDLE>(1),0);
    if(packet->returned_module.selected||packet->returned_module.setup_reason!=2)return 20;
    returned_module_loaded(&loader,false,state.module,nullptr,0);
    if(packet->returned_module.selected||packet->returned_module.setup_reason!=3||packet->returned_module.returned_module)return 20;
    packet->returned_module.selected=1;packet->returned_module.returned_module=reinterpret_cast<uintptr_t>(state.module);
    returned_module_loaded(&loader,true,reinterpret_cast<HMODULE>(0x9999),nullptr,0);
    if(packet->returned_module.setup_reason!=4||packet->returned_module.returned_module!=reinterpret_cast<uintptr_t>(state.module))return 20;
    // A captured successful original loader remains unchanged when its optional
    // observer preparation has no time. No module pin/load is attempted here.
    returned_mock_packets(packet,0,frequency);listener_collector.depth=1;listener_collector.operations[0]=2;listener_collector.parents[0]=1;
    packet->next_sequence=3;packet->dependency_link_count=1;packet->dependency_links[0]={1,2,1};
    loader.operation=12;loader.entered=1;loader.returned=1;loader.thread_id=packet->original_thread;loader.raw_output=reinterpret_cast<uintptr_t>(state.module);loader.output_flags=3;loader.scalar_flags=4;
    returned_module_loaded(&loader,true,state.module,nullptr,0);
    if(packet->returned_module.selected!=1||packet->returned_module.armed||packet->returned_module.setup_stage!=2||packet->returned_module.setup_error!=ERROR_TIMEOUT||packet->returned_module.loader_dependency_sequence!=1||packet->returned_module.loader_timeline_sequence!=2||packet->returned_module.parent_listener_sequence!=1||packet->returned_module.dependencies.called)return 21;
    // Expired recording and foreign-thread cold forwarding still use this
    // route's own immutable-typed mock target once, without a record.
    errors_restore(state.incoming);const auto expired=heap<true>(reinterpret_cast<void*>(0x3210),0x1234,UINT64_C(1)<<40);const auto expired_errors=errors();
    if(expired!=reinterpret_cast<void*>(0x2222)||!same_errors(expired_errors,state.outgoing)||packet->returned_module.dependencies.total_calls)return 21;
    // Keep the original thread armed: the new thread must have independent
    // empty TLS, rather than merely inherit a process-wide disabled observer.
    returned_mock_packets(packet,cutoff,frequency);
    loader_collector={};loader_collector.packet=&packet->loader_owner.dependencies;loader_collector.timeline=packet;
    HANDLE thread=CreateThread(nullptr,0,returned_mock_thread,nullptr,0,nullptr);if(!thread)return 22;
    LARGE_INTEGER now={};if(!QueryPerformanceCounter(&now)||now.QuadPart<0||static_cast<uint64_t>(now.QuadPart)>=cutoff||!frequency){CloseHandle(thread);__fastfail(FAST_FAIL_FATAL_APP_EXIT);}
    const auto ticks=cutoff-static_cast<uint64_t>(now.QuadPart);if(ticks>UINT64_MAX/1000){CloseHandle(thread);__fastfail(FAST_FAIL_FATAL_APP_EXIT);}
    const auto remaining=ticks*1000/frequency;
    if(WaitForSingleObject(thread,remaining>MAXDWORD-1?MAXDWORD-1:static_cast<DWORD>(remaining))!=WAIT_OBJECT_0){CloseHandle(thread);__fastfail(FAST_FAIL_FATAL_APP_EXIT);}
    DWORD status=1;const BOOL queried=GetExitCodeThread(thread,&status);CloseHandle(thread);if(!queried||status||!state.same||returned_collector.packet!=&packet->returned_module.dependencies||loader_collector.packet!=&packet->loader_owner.dependencies||packet->loader_owner.dependencies.total_calls||packet->returned_module.dependencies.total_calls||packet->dependencies.total_calls||packet->next_sequence)return 22;
    // Ordinal resolution requires unique typed identity, not fixed ordinals or
    // merely a non-null current target. All16 candidate exports are bounded.
    void* exports[16]={};exports[8]=provider.targets[8];
    if(typed_ordinal_operation(nullptr,provider.targets[8],exports,16)||typed_ordinal_operation(provider.targets[8],ws2.targets[8],exports,16)||typed_ordinal_operation(provider.targets[8],provider.targets[8],exports,16)!=9)return 23;
    exports[9]=exports[8];if(typed_ordinal_operation(provider.targets[8],provider.targets[8],exports,16)!=17)return 23;
    // Link eviction remains aligned with the returned packet's local ring.
    returned_mock_packets(packet,cutoff,frequency);state.fail=true;
    for(size_t index=0;index<20;++index){errors_restore(state.incoming);if(heap<true>(reinterpret_cast<void*>(0x3210),0x1234,UINT64_C(1)<<40))return 24;}
    if(packet->returned_module.link_count!=16||packet->returned_module.links_dropped!=4||packet->returned_module.dependencies.record_count!=16||packet->returned_module.dependencies.dropped!=4||packet->returned_module.dependencies.total_failures!=20||packet->returned_module.first_failure_link.dependency_sequence!=1||packet->returned_module.first_failure_link.timeline_sequence!=1||packet->returned_module.dependencies.first_failure.sequence!=1)return 24;
    for(size_t index=0;index<16;++index)if(packet->returned_module.links[index].dependency_sequence!=packet->returned_module.dependencies.entries[index].sequence||packet->returned_module.links[index].timeline_sequence!=index*2+9)return 24;
    end_listener_dependencies(packet);if(collector.packet||returned_collector.packet||collector.timeline||returned_collector.timeline)return 24;
    state.fail=false;listener_collector={};
    // Exercise the actual returned-route owned-slot rollback and page restore
    // helpers on a private data page, including an untouched foreign conflict.
    SYSTEM_INFO system={};GetSystemInfo(&system);void* memory=VirtualAlloc(nullptr,system.dwPageSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!memory)return 25;
    auto** slots=static_cast<void**>(memory);slots[0]=provider.targets[8];slots[1]=ws2.targets[8];DWORD previous=0;
    if(!VirtualProtect(memory,system.dwPageSize,PAGE_READONLY,&previous)){VirtualFree(memory,0,MEM_RELEASE);return 25;}
    WsaPacket rollback={};rollback.cutoff_qpc=cutoff;rollback.frequency=frequency;Page page={memory,system.dwPageSize,PAGE_READONLY,false};
    if(!writable(&page,1,&rollback)){VirtualFree(memory,0,MEM_RELEASE);return 25;}
    bool good=swap(&slots[0],returned_hooks[8].target,provider.targets[8])==provider.targets[8];
    rollback.slot_count=2;rollback.slots[0]={reinterpret_cast<uintptr_t>(&slots[0]),reinterpret_cast<uintptr_t>(provider.targets[8]),reinterpret_cast<uintptr_t>(returned_hooks[8].target),0,9,1,0,0};
    rollback.slots[1]={reinterpret_cast<uintptr_t>(&slots[1]),reinterpret_cast<uintptr_t>(provider.targets[8]),reinterpret_cast<uintptr_t>(returned_hooks[8].target),0,9,0,0,0};
    good=good&&swap(&slots[1],returned_hooks[8].target,provider.targets[8])==ws2.targets[8]&&slots[1]==ws2.targets[8];returned_rollback(&rollback);
    good=good&&slots[0]==provider.targets[8]&&slots[1]==ws2.targets[8]&&!rollback.slots[0].published&&rollback.slots[0].restored&&!rollback.slots[1].restored;
    restore(&page,1,&rollback);MEMORY_BASIC_INFORMATION restored={};good=good&&VirtualQuery(memory,&restored,sizeof(restored))==sizeof(restored)&&restored.Protect==PAGE_READONLY;
    const BOOL freed=VirtualFree(memory,0,MEM_RELEASE);if(!good||!freed||!rollback.protections_restored)return 25;
    // Scalar caught-panic and ordinary-error exits both detach the independent
    // collectors and invoke their original opaque callback once.
    for(uint32_t kind=2;kind<=3;++kind){
        listener_mock_packet(packet,cutoff,frequency);listener_collector={};
        packet->dependencies.version=1;packet->dependencies.cutoff_qpc=cutoff;packet->dependencies.frequency=frequency;
        const ListenerRequest request={cutoff,frequency,state.incoming.win32,state.incoming.wsa};ReturnedMockCallback callback={packet,&state,kind,0};
        listener_invoke(packet,&request,returned_mock_callback,&callback,false);const auto returned=errors();
        if(callback.calls!=1||packet->called!=1||packet->callback_outcome!=kind||!same_errors(returned,state.outgoing)||collector.packet||returned_collector.packet||loader_collector.packet||listener_collector.packet||!state.same)return 26;
    }
    // The exact failed original wrapper forwards once while its independent
    // loader route records the nested typed NTSTATUS with both parent links.
    // Private preparation never publishes a real slot or original target.
    const auto saved_outgoing=state.outgoing;state.outgoing=seed_listener_error(5);
    WCHAR search[]={L'p',0},dll[]={L'm',0};ULONG flags=0;
    UNICODE_STRING counted={sizeof(WCHAR),sizeof(dll),dll};HANDLE output=reinterpret_cast<HANDLE>(0xc0de);
    state.search=search;state.flags=&flags;state.name=&counted;state.output=&output;
    state.module=nullptr;state.loader_nested=true;
    listener_mock_packet(packet,cutoff,frequency);listener_mock_dependencies(packet);
    listener_collector.depth=1;listener_collector.operations[0]=2;listener_collector.parents[0]=1;packet->next_sequence=1;
    const auto outer_before=state.loader_calls.load(),inner_before=state.loader_native_calls.load(),prepare_before=state.prepare_calls.load();
    errors_restore(state.incoming);const auto failed_load=load_library<false>(path,nullptr,0);const auto failed_errors=errors();
    const auto& linked=packet->loader_owner.first_failure_link;
    if(failed_load||!same_errors(failed_errors,state.outgoing)||!state.same||state.loader_calls!=outer_before+1||state.loader_native_calls!=inner_before+1||state.prepare_calls!=prepare_before+1||output!=reinterpret_cast<HANDLE>(0xc0de)||packet->next_sequence!=5||packet->dependencies.total_calls!=1||packet->loader_owner.dependencies.total_calls!=1||packet->loader_owner.dependencies.first_failure.native_status!=static_cast<NTSTATUS>(0xC0000022u)||packet->dependencies.entries[0].outgoing_error!=5||packet->returned_module.setup_error!=ERROR_MOD_NOT_FOUND||linked.dependency_sequence!=1||linked.timeline_sequence!=3||linked.parent_listener_sequence!=1||linked.loader_dependency_sequence!=1||linked.loader_timeline_sequence!=2||loader_collector.packet)return 27;
    const auto pinned_window=packet->loader_owner.first_failure_window;
    if(packet->loader_owner.window_count!=1||packet->loader_owner.first_failure_window_present!=1||packet->loader_owner.windows_invalid||pinned_window.dependency_sequence!=1||pinned_window.loader_dependency_sequence!=1||pinned_window.parent_listener_sequence!=1||!pinned_window.started_qpc||pinned_window.finished_qpc<pinned_window.started_qpc||pinned_window.finished_qpc>cutoff)return 32;
    errors_restore(state.incoming);if(load_library<false>(path,nullptr,0)||!same_errors(errors(),state.outgoing)||state.loader_calls!=outer_before+2||state.loader_native_calls!=inner_before+2||state.prepare_calls!=prepare_before+2||packet->loader_owner.link_count!=2||packet->loader_owner.links[1].loader_dependency_sequence!=2||packet->loader_owner.links[1].loader_timeline_sequence!=6||packet->loader_owner.links[1].timeline_sequence!=7||packet->next_sequence!=9||loader_collector.packet)return 28;
    if(packet->loader_owner.window_count!=2||packet->loader_owner.windows[1].dependency_sequence!=2||packet->loader_owner.windows[1].loader_dependency_sequence!=2||packet->loader_owner.first_failure_window.dependency_sequence!=pinned_window.dependency_sequence||packet->loader_owner.first_failure_window.started_qpc!=pinned_window.started_qpc)return 32;
    for(size_t index=0;index<20;++index){errors_restore(state.incoming);if(load_library<false>(path,nullptr,0)||!same_errors(errors(),state.outgoing))return 33;}
    if(packet->loader_owner.window_count!=16||packet->loader_owner.windows_dropped!=6||packet->loader_owner.windows_invalid||packet->loader_owner.first_failure_window.dependency_sequence!=1||packet->loader_owner.windows[0].dependency_sequence!=7||packet->loader_owner.windows[15].dependency_sequence!=22||!state.same)return 33;
    // Script only private optional QPC reads under the same existing cutoff;
    // failed, negative, reversed and late timing never suppresses original work.
    for(uint32_t mode=0;mode<=6;++mode){
        LARGE_INTEGER now={};if(!QueryPerformanceCounter(&now)||now.QuadPart<=1||static_cast<uint64_t>(now.QuadPart)+1>=cutoff)return 34;
        listener_mock_packet(packet,cutoff,frequency);listener_mock_dependencies(packet);
        listener_collector.depth=1;listener_collector.operations[0]=2;listener_collector.parents[0]=1;packet->next_sequence=1;
        state.window_clock_mode=mode;state.window_clock_calls=0;state.window_clock_start=static_cast<uint64_t>(now.QuadPart);state.window_clock_cutoff=cutoff;
        const auto native_before=state.loader_native_calls.load(),load_before=state.loader_calls.load();loader_private_clock.store(loader_mock_clock,std::memory_order_release);
        errors_restore(state.incoming);const auto result=load_library<false>(path,nullptr,0);const auto outgoing=errors();loader_private_clock.store(nullptr,std::memory_order_release);
        if(result||!same_errors(outgoing,state.outgoing)||state.loader_native_calls!=native_before+1||state.loader_calls!=load_before+1||state.window_clock_calls!=2||!state.same||output!=reinterpret_cast<HANDLE>(0xc0de)||flags||packet->loader_owner.dependencies.first_failure.native_status!=static_cast<NTSTATUS>(0xC0000022u))return 34;
        if(mode==0){if(packet->loader_owner.window_count!=1||packet->loader_owner.windows_invalid||packet->loader_owner.windows[0].started_qpc!=state.window_clock_start||packet->loader_owner.windows[0].finished_qpc!=state.window_clock_start+1)return 34;}
        else if(packet->loader_owner.window_count||packet->loader_owner.first_failure_window_present||packet->loader_owner.windows_invalid!=1||!packet->loader_owner.incomplete)return 34;
    }
    // Unavailable observer setup must neither suppress the original load nor
    // change its error. Nested cold forwarding records no invented event.
    listener_mock_packet(packet,cutoff,frequency);listener_mock_dependencies(packet);
    listener_collector.depth=1;listener_collector.operations[0]=2;listener_collector.parents[0]=1;packet->next_sequence=1;state.prepare_failed=true;
    const auto before_unavailable=state.loader_native_calls.load();
    errors_restore(state.incoming);if(load_library<false>(path,nullptr,0)||!same_errors(errors(),state.outgoing)||state.loader_native_calls!=before_unavailable+1||packet->loader_owner.dependencies.total_calls||packet->loader_owner.armed||packet->loader_owner.setup_error!=ERROR_NOT_SUPPORTED||loader_collector.packet)return 29;
    state.prepare_failed=false;state.loader_nested=false;
    // Expired and instrumentation-reentrant third-domain forwarders preserve
    // exact arguments/errors without consuming an event or common ordinal.
    listener_mock_packet(packet,0,frequency);loader_collector.packet=&packet->loader_owner.dependencies;loader_collector.timeline=packet;
    const auto before_expired=state.loader_native_calls.load();errors_restore(state.incoming);
    if(load_dll<2>(search,&flags,&counted,&output)!=static_cast<NTSTATUS>(0xC0000022u)||!same_errors(errors(),state.outgoing)||state.loader_native_calls!=before_expired+1||packet->loader_owner.dependencies.total_calls||packet->loader_owner.dependencies.setup_error!=ERROR_TIMEOUT||packet->next_sequence)return 30;
    listener_mock_packet(packet,cutoff,frequency);listener_mock_dependencies(packet);
    loader_collector.packet=&packet->loader_owner.dependencies;loader_collector.timeline=packet;collector.inside=true;
    errors_restore(state.incoming);if(heap<2>(reinterpret_cast<void*>(0x3210),0x1234,UINT64_C(1)<<40)!=reinterpret_cast<void*>(0x3333)||!same_errors(errors(),state.outgoing)||packet->loader_owner.dependencies.total_calls||packet->next_sequence)return 30;
    collector.inside=false;loader_collector.inside=true;errors_restore(state.incoming);
    if(heap<false>(reinterpret_cast<void*>(0x3210),0x1234,UINT64_C(1)<<40)!=reinterpret_cast<void*>(0x1111)||!same_errors(errors(),state.outgoing)||packet->dependencies.total_calls||packet->next_sequence)return 30;
    loader_collector.inside=false;end_listener_dependencies(packet);
    if(loader_collector.packet||collector.packet||returned_collector.packet||!state.same)return 30;
    state.outgoing=saved_outgoing;
    if(InterlockedCompareExchange(&loader_installed,0,0)!=0)return 31;
    for(const auto& target:loader_originals)if(target.load(std::memory_order_acquire))return 31;
    for(const auto& target:returned_originals)if(target.load(std::memory_order_acquire))return 24;
    return 0;
}
extern "C" uint32_t memcordon_listener_trace_mock(uint64_t cutoff,uint64_t frequency){
    if(InterlockedCompareExchange(&listener_installed,1,0)!=0)return 1;
    ListenerMockScope scope={listener_collector,collector,returned_collector,loader_collector};
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
    const auto returned_failed=returned_native_mock(&packet,&state,cutoff,frequency);if(returned_failed)return returned_failed;
    const auto image_failed=image_native_mock(&packet,cutoff,frequency);if(image_failed)return image_failed;
    return 0;
}
