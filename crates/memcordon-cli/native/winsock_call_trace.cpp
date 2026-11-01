#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <winreg.h>
#include <intrin.h>
#include <atomic>
#include "detours.h"
#include "winsock_call_trace.h"

static_assert(sizeof(void*)==8 && sizeof(WCHAR)==2 && sizeof(NTSTATUS)==4,"WSA trace native ABI");
static_assert(sizeof(OBJECT_ATTRIBUTES)==48 && offsetof(OBJECT_ATTRIBUTES,ObjectName)==16,"WSA native object attributes ABI");
static_assert(sizeof(UNICODE_STRING)==16 && offsetof(UNICODE_STRING,Buffer)==8,"WSA native counted string ABI");
static std::atomic<void*> originals[16] = {};
static_assert(std::atomic<void*>::is_always_lock_free,"forwarding publication is lock-free");
static volatile LONG installed=0;
struct Collector { WsaPacket* packet; bool inside; };
static __declspec(thread) Collector collector={nullptr,false};
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
    if (collector.inside) {packet->incomplete=1;return false;}
    collector.inside=true;
    if (!live(packet)) {packet->incomplete=1;collector.packet=nullptr;collector.inside=false;return false;}
    if(packet->total_calls==UINT32_MAX){packet->overflow=1;packet->incomplete=1;collector.packet=nullptr;collector.inside=false;return false;}
    packet->total_calls=increment(packet->total_calls);
    entry->sequence=packet->total_calls;entry->operation=operation;entry->thread_id=GetCurrentThreadId();
    entry->incoming_error=incoming;entry->entered=1;
    return true;
}
static void forwarding(DWORD incoming,bool active){if(active)collector.inside=false;SetLastError(incoming);}
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
        if(!packet->first_failure_present){packet->first_failure=*entry;packet->first_failure_present=1;}
    }
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
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,1,incoming);
    if(active){entry.desired_access=access;attributes(&entry,attr);}forwarding(incoming,active);
    const auto result=original<NtOpen>(1)(out,access,attr);const DWORD error=GetLastError();
    if(active&&result>=0)output(&entry,reinterpret_cast<void**>(out));finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using NtOpenEx=NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,ULONG);
static NTSTATUS NTAPI open_key_ex(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attr,ULONG options){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,2,incoming);
    if(active){entry.desired_access=access;entry.secondary_size=options;entry.scalar_flags=2;attributes(&entry,attr);}forwarding(incoming,active);
    const auto result=original<NtOpenEx>(2)(out,access,attr,options);const DWORD error=GetLastError();
    if(active&&result>=0)output(&entry,reinterpret_cast<void**>(out));finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using NtQuery=NTSTATUS(NTAPI*)(HANDLE,PUNICODE_STRING,ULONG,PVOID,ULONG,PULONG);
static NTSTATUS NTAPI query_value(HANDLE key,PUNICODE_STRING value,ULONG type,PVOID buffer,ULONG length,PULONG required){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,3,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(key);entry.requested_size=length;entry.secondary_size=type;entry.scalar_flags=3;unicode(&entry,value);}forwarding(incoming,active);
    const auto result=original<NtQuery>(3)(key,value,type,buffer,length,required);const DWORD error=GetLastError();
    finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using Load=NTSTATUS(NTAPI*)(PWSTR,PULONG,PUNICODE_STRING,PHANDLE);
static NTSTATUS NTAPI load_dll(PWSTR search,PULONG flags,PUNICODE_STRING value,PHANDLE out){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,4,incoming);
    if(active){unicode(&entry,value);entry.flags=dword_input(flags,&entry,4);}forwarding(incoming,active);
    const auto result=original<Load>(4)(search,flags,value,out);const DWORD error=GetLastError();
    if(active&&result>=0)output(&entry,reinterpret_cast<void**>(out));finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using NtCreate=NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,ULONG,BOOLEAN);
static NTSTATUS NTAPI create_event(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attr,ULONG type,BOOLEAN state){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,5,incoming);
    if(active){entry.desired_access=access;entry.requested_size=type;entry.secondary_size=state;entry.scalar_flags=3;attributes(&entry,attr);}forwarding(incoming,active);
    const auto result=original<NtCreate>(5)(out,access,attr,type,state);const DWORD error=GetLastError();
    if(active&&result>=0)output(&entry,reinterpret_cast<void**>(out));finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
static NTSTATUS NTAPI open_event(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attr){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,6,incoming);
    if(active){entry.desired_access=access;attributes(&entry,attr);}forwarding(incoming,active);
    const auto result=original<NtOpen>(6)(out,access,attr);const DWORD error=GetLastError();
    if(active&&result>=0)output(&entry,reinterpret_cast<void**>(out));finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
static NTSTATUS NTAPI open_directory(PHANDLE out,ACCESS_MASK access,POBJECT_ATTRIBUTES attr){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,7,incoming);
    if(active){entry.desired_access=access;attributes(&entry,attr);}forwarding(incoming,active);
    const auto result=original<NtOpen>(7)(out,access,attr);const DWORD error=GetLastError();
    if(active&&result>=0)output(&entry,reinterpret_cast<void**>(out));finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using NtAllocate=NTSTATUS(NTAPI*)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
static NTSTATUS NTAPI allocate(HANDLE process,PVOID* base,ULONG_PTR zero,PSIZE_T size,ULONG type,ULONG protection){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,8,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(process);entry.requested_size=size_input(size,&entry,1);entry.flags=type;entry.scalar_flags|=4;entry.desired_access=protection;}forwarding(incoming,active);
    const auto result=original<NtAllocate>(8)(process,base,zero,size,type,protection);const DWORD error=GetLastError();
    if(active&&result>=0){output(&entry,base);entry.secondary_size=size_input(size,&entry,2);}finish(&entry,active,result,error,result<0);SetLastError(error);return result;
}
using Heap=void*(NTAPI*)(void*,ULONG,SIZE_T);
static void* NTAPI heap(void* handle,ULONG flags,SIZE_T size){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,9,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(handle);entry.requested_size=size;entry.scalar_flags=5;entry.flags=flags;}forwarding(incoming,active);
    void* result=original<Heap>(9)(handle,flags,size);const DWORD error=GetLastError();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
static LSTATUS WINAPI reg_open(HKEY key,LPCWSTR value,DWORD options,REGSAM access,PHKEY out){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,10,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(key);entry.desired_access=access;entry.flags=options;entry.scalar_flags=4;name(&entry,value,0,true);}forwarding(incoming,active);
    const auto result=original<decltype(&RegOpenKeyExW)>(10)(key,value,options,access,out);const DWORD error=GetLastError();
    if(active&&result==ERROR_SUCCESS)output(&entry,reinterpret_cast<void**>(out));finish(&entry,active,result,error,result!=ERROR_SUCCESS);SetLastError(error);return result;
}
static LSTATUS WINAPI reg_query(HKEY key,LPCWSTR value,LPDWORD reserved,LPDWORD type,LPBYTE data,LPDWORD length){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,11,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(key);entry.requested_size=dword_input(length,&entry,1);name(&entry,value,0,true);}forwarding(incoming,active);
    const auto result=original<decltype(&RegQueryValueExW)>(11)(key,value,reserved,type,data,length);const DWORD error=GetLastError();
    finish(&entry,active,result,error,result!=ERROR_SUCCESS);SetLastError(error);return result;
}
static HMODULE WINAPI load_library(LPCWSTR value,HANDLE file,DWORD flags){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,12,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(file);entry.flags=flags;entry.scalar_flags=4;name(&entry,value,0,true);}forwarding(incoming,active);
    const auto result=original<decltype(&LoadLibraryExW)>(12)(value,file,flags);const DWORD error=GetLastError();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
static HANDLE WINAPI create_event_w(LPSECURITY_ATTRIBUTES security,BOOL reset,BOOL state,LPCWSTR value){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,13,incoming);
    if(active){entry.requested_size=reset;entry.secondary_size=state;entry.scalar_flags=3;name(&entry,value,0,true);}forwarding(incoming,active);
    const auto result=original<decltype(&CreateEventW)>(13)(security,reset,state,value);const DWORD error=GetLastError();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
static HANDLE WINAPI open_event_w(DWORD access,BOOL inherit,LPCWSTR value){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,14,incoming);
    if(active){entry.desired_access=access;entry.flags=inherit;entry.scalar_flags=4;name(&entry,value,0,true);}forwarding(incoming,active);
    const auto result=original<decltype(&OpenEventW)>(14)(access,inherit,value);const DWORD error=GetLastError();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
static void* WINAPI heap_alloc(HANDLE handle,DWORD flags,SIZE_T size){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,15,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(handle);entry.flags=flags;entry.requested_size=size;entry.scalar_flags=5;}forwarding(incoming,active);
    const auto result=original<decltype(&HeapAlloc)>(15)(handle,flags,size);const DWORD error=GetLastError();
    entry.raw_output=reinterpret_cast<uintptr_t>(result);entry.output_flags=1|(result?2:0);finish(&entry,active,result?0:1,error,!result);SetLastError(error);return result;
}
static void* WINAPI virtual_alloc(LPVOID base,SIZE_T size,DWORD type,DWORD protection){
    const DWORD incoming=GetLastError();WsaEntry entry={};bool active=begin(&entry,16,incoming);
    if(active){entry.raw_root=reinterpret_cast<uintptr_t>(base);entry.flags=type;entry.desired_access=protection;entry.requested_size=size;entry.scalar_flags=5;}forwarding(incoming,active);
    const auto result=original<decltype(&VirtualAlloc)>(16)(base,size,type,protection);const DWORD error=GetLastError();
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
static bool capture_node(HMODULE module,void* entry,WsaNode* node,Image* mapped,WsaPacket* packet){
    if(!image(module,mapped)||!executable(entry,module))return false;
    node->owner_base=reinterpret_cast<uintptr_t>(module);node->entry=reinterpret_cast<uintptr_t>(entry);
    node->owner_size=mapped->size;node->timestamp=mapped->timestamp;node->machine=mapped->machine;
    const DWORD name_units=GetModuleFileNameW(module,reinterpret_cast<WCHAR*>(node->module_name),64);
    if(!name_units||name_units>=64)packet->incomplete=1;
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
    if(success){packet->setup_stage=1;packet->setup_error=0;}
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
    collector.packet=packet->setup_stage==1?packet:nullptr;packet->armed=collector.packet?1:0;collector.inside=false;
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
