// Only normal imports in the actual fixture image. Permanent forwarding
// references remain valid outside the diagnostic TLS scope; no entry patching.
using SpawnOpen=NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,ULONG,ULONG);
using SpawnPipe=NTSTATUS(NTAPI*)(PHANDLE,ULONG,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,ULONG,ULONG,ULONG,ULONG,ULONG,ULONG,ULONG,ULONG,ULONG,PLARGE_INTEGER);
using SpawnFile=decltype(&CreateFileW);
using SpawnDuplicate=decltype(&DuplicateHandle);
using SpawnProcess=decltype(&CreateProcessW);
static_assert(std::is_same_v<SpawnOpen,decltype(&NtOpenFile)>,"SDK NtOpenFile ABI");
static std::atomic<void*> spawn_originals[SpawnRoutes]={};
struct SpawnPrivateTargets {void* targets[SpawnRoutes];};
static std::atomic<const SpawnPrivateTargets*> spawn_private_targets{nullptr};
static std::atomic<LoaderWindowClock> spawn_private_clock{nullptr};
using SpawnPrivatePrepare=void(*)(SpawnPacket*,ListenerInvoke);
static std::atomic<SpawnPrivatePrepare> spawn_private_prepare{nullptr};
static BOOL spawn_clock(LARGE_INTEGER* value){const auto mock=spawn_private_clock.load(std::memory_order_acquire);return mock?mock(value):QueryPerformanceCounter(value);}
struct SpawnCollector {SpawnPacket* packet;uint64_t started;uint32_t thread;bool inside,disarmed;};
static __declspec(thread) SpawnCollector spawn_collector={};
template<class T,unsigned Operation> static T spawn_original(){
    static_assert(Operation<SpawnRoutes);const auto mock=spawn_private_targets.load(std::memory_order_acquire);
    return reinterpret_cast<T>(mock?mock->targets[Operation]:spawn_originals[Operation].load(std::memory_order_acquire));
}
static bool spawn_begin(SpawnRow* row,uint32_t operation,ErrorPair incoming){
    auto& scope=spawn_collector;auto* packet=scope.packet;if(!packet)return false;
    if(observer_setup_active||scope.inside){packet->scope_reentry=increment(packet->scope_reentry);return false;}
    const auto thread=GetCurrentThreadId();if(thread!=scope.thread){packet->scope_unavailable=increment(packet->scope_unavailable);return false;}
    scope.inside=true;LARGE_INTEGER now={};const BOOL clock=spawn_clock(&now);
    if(!clock||now.QuadPart<=0||static_cast<uint64_t>(now.QuadPart)<scope.started){packet->clock_failures=increment(packet->clock_failures);scope.inside=false;scope.packet=nullptr;scope.disarmed=true;return false;}
    if(static_cast<uint64_t>(now.QuadPart)>=packet->cutoff_qpc){packet->late=increment(packet->late);scope.inside=false;scope.packet=nullptr;scope.disarmed=true;return false;}
    if(packet->total_calls==UINT32_MAX){packet->overflow=1;scope.inside=false;scope.packet=nullptr;scope.disarmed=true;return false;}
    uint32_t route=UINT32_MAX;
    for(uint32_t index=0;index<packet->route_count&&index<SpawnRoutes;++index){const auto& candidate=packet->routes[index];
        if(candidate.owner_index==0&&candidate.slot.operation==operation&&candidate.slot.published&&candidate.postvalidated){if(route!=UINT32_MAX){route=UINT32_MAX;break;}route=index;}}
    if(route==UINT32_MAX){packet->scope_unavailable=increment(packet->scope_unavailable);scope.inside=false;return false;}
    row->sequence=++packet->total_calls;row->operation=operation;row->route_index=route;row->thread_id=thread;
    row->started_qpc=static_cast<uint64_t>(now.QuadPart);row->incoming_win32=incoming.win32;row->incoming_wsa=incoming.wsa;row->entered=1;row->flags=1|8;
    if(row->thread_id==scope.thread)row->flags|=4;
    return true;
}
static void spawn_counted_name(SpawnRow* row,POBJECT_ATTRIBUTES attributes,PLARGE_INTEGER timeout){
    if(timeout){row->input_flags|=8;__try {row->default_timeout=static_cast<uint64_t>(timeout->QuadPart);row->input_flags|=16;}__except(EXCEPTION_EXECUTE_HANDLER){row->input_flags|=128;}}
    __try {
        if(!attributes)return;row->input_flags|=1;const auto object=*attributes;row->oa_length=object.Length;
        if(object.Length!=sizeof(OBJECT_ATTRIBUTES)){row->input_flags|=64;return;}
        row->input_flags|=2;row->oa_attributes=object.Attributes;row->raw_root=reinterpret_cast<uintptr_t>(object.RootDirectory);
        if(!object.ObjectName)return;row->input_flags|=4;const auto counted=*object.ObjectName;row->reported_name_bytes=counted.Length;
        if(counted.Length%2||counted.Length>counted.MaximumLength||(!counted.Buffer&&counted.Length)){row->input_flags|=256;return;}
        row->name_flags|=32;const size_t units=counted.Length/sizeof(WCHAR),count=units<SpawnNameUnits?units:SpawnNameUnits;
        for(size_t index=0;index<count;++index){const auto unit=counted.Buffer[index];row->name[index]=unit;row->copied_name_units=static_cast<uint32_t>(index+1);if(!unit)row->name_flags|=8;}
        row->name_flags|=1;if(units>count)row->name_flags|=4;
    }__except(EXCEPTION_EXECUTE_HANDLER){row->input_flags|=128;row->name_flags|=2;}
}
static void spawn_win32_name(SpawnRow* row,LPCWSTR name){
    if(!name)return;row->input_flags|=512;row->name_flags|=16;
    __try {for(size_t index=0;index<SpawnNameUnits;++index){const auto unit=name[index];if(!unit){row->reported_name_bytes=static_cast<uint32_t>(index*sizeof(WCHAR));row->name_flags|=1|32;return;}row->name[index]=unit;row->copied_name_units=static_cast<uint32_t>(index+1);}row->name_flags|=4;}
    __except(EXCEPTION_EXECUTE_HANDLER){row->input_flags|=128;row->name_flags|=2;}
}
static bool spawn_returned(SpawnRow* row,SpawnPacket* packet,ErrorPair outgoing){
    row->returned=1;row->outgoing_win32=outgoing.win32;row->outgoing_wsa=outgoing.wsa;
    LARGE_INTEGER ended={};const BOOL clock=spawn_clock(&ended);const bool valid=clock&&ended.QuadPart>0&&static_cast<uint64_t>(ended.QuadPart)>=row->started_qpc;
    if(valid){row->finished_qpc=static_cast<uint64_t>(ended.QuadPart);row->flags|=2;}else packet->clock_failures=increment(packet->clock_failures);
    const bool within=valid&&row->finished_qpc<packet->cutoff_qpc;
    if(valid&&!within){row->flags|=32;packet->late=increment(packet->late);}
    if(spawn_collector.packet!=packet){row->flags&=~8u;packet->unmatched_scope=increment(packet->unmatched_scope);}
    return within;
}
static void spawn_handle_output(SpawnRow* row,bool within,PHANDLE output){
    if(output)row->output_flags|=1;if(!within){row->output_flags|=32;return;}
    __try {if(output){row->raw_output=reinterpret_cast<uintptr_t>(*output);if(row->raw_output)row->output_flags|=2;}}
    __except(EXCEPTION_EXECUTE_HANDLER){row->output_flags|=4;}
}
static void spawn_commit(SpawnRow* row,SpawnPacket* packet,bool failed,bool within){
    if(within&&(row->flags&(1|2|4|8))==(1|2|4|8)&&!(row->flags&64)&&!(row->input_flags&(64|128|256))&&!(row->name_flags&(2|4))&&!(row->output_flags&4))row->flags|=16;
    if(row->input_flags&(64|128|256)||row->name_flags&(2|4))packet->input_failures=increment(packet->input_failures);
    if(failed){packet->total_failures=increment(packet->total_failures);if(!packet->first_failure_present){packet->first_failure=*row;packet->first_failure_present=1;}}
    if(packet->record_count<SpawnRows)packet->rows[packet->record_count++]=*row;
    else{for(size_t index=1;index<SpawnRows;++index)packet->rows[index-1]=packet->rows[index];packet->rows[SpawnRows-1]=*row;packet->dropped=increment(packet->dropped);packet->overflow=1;}
    spawn_collector.inside=false;if(!within){spawn_collector.packet=nullptr;spawn_collector.disarmed=true;}
}
static NTSTATUS NTAPI spawn_open(PHANDLE output,ACCESS_MASK access,POBJECT_ATTRIBUTES attributes,PIO_STATUS_BLOCK io,ULONG share,ULONG options){
    const auto target=spawn_original<SpawnOpen,0>();if(!spawn_collector.packet)return target(output,access,attributes,io,share,options);
    const auto incoming=errors();SpawnRow row={};const bool active=spawn_begin(&row,1,incoming);auto* packet=spawn_collector.packet;
    if(active){row.desired_access=access;row.share_access=share;row.create_options=options;spawn_counted_name(&row,attributes,nullptr);}
    errors_restore(incoming);const auto result=target(output,access,attributes,io,share,options);const auto outgoing=errors();
    if(active){row.native_status=result;row.flags|=128;row.output_flags|=16;const bool within=spawn_returned(&row,packet,outgoing);if(result==static_cast<NTSTATUS>(0x103)){row.flags|=64;row.output_flags|=8;}else if(result>=0)spawn_handle_output(&row,within,output);spawn_commit(&row,packet,result<0,within);}errors_restore(outgoing);return result;
}
static NTSTATUS NTAPI spawn_pipe(PHANDLE output,ULONG access,POBJECT_ATTRIBUTES attributes,PIO_STATUS_BLOCK io,ULONG share,ULONG disposition,ULONG options,ULONG type,ULONG read_mode,ULONG completion,ULONG instances,ULONG inbound,ULONG outbound,PLARGE_INTEGER timeout){
    const auto target=spawn_original<SpawnPipe,1>();if(!spawn_collector.packet)return target(output,access,attributes,io,share,disposition,options,type,read_mode,completion,instances,inbound,outbound,timeout);
    const auto incoming=errors();SpawnRow row={};const bool active=spawn_begin(&row,2,incoming);auto* packet=spawn_collector.packet;
    if(active){row.desired_access=access;row.share_access=share;row.create_disposition=disposition;row.create_options=options;row.pipe_type=type;row.read_mode=read_mode;row.completion_mode=completion;row.max_instances=instances;row.inbound_quota=inbound;row.outbound_quota=outbound;spawn_counted_name(&row,attributes,timeout);}
    errors_restore(incoming);const auto result=target(output,access,attributes,io,share,disposition,options,type,read_mode,completion,instances,inbound,outbound,timeout);const auto outgoing=errors();
    if(active){row.native_status=result;row.flags|=128;row.output_flags|=16;const bool within=spawn_returned(&row,packet,outgoing);if(result==static_cast<NTSTATUS>(0x103)){row.flags|=64;row.output_flags|=8;}else if(result>=0)spawn_handle_output(&row,within,output);spawn_commit(&row,packet,result<0,within);}errors_restore(outgoing);return result;
}
static HANDLE WINAPI spawn_file(LPCWSTR name,DWORD access,DWORD share,LPSECURITY_ATTRIBUTES security,DWORD disposition,DWORD attributes,HANDLE template_file){
    const auto target=spawn_original<SpawnFile,2>();if(!spawn_collector.packet)return target(name,access,share,security,disposition,attributes,template_file);
    const auto incoming=errors();SpawnRow row={};const bool active=spawn_begin(&row,3,incoming);auto* packet=spawn_collector.packet;
    if(active){row.desired_access=access;row.share_access=share;row.create_disposition=disposition;row.file_attributes=attributes;row.security_present=security?1:0;spawn_win32_name(&row,name);}
    errors_restore(incoming);const auto result=target(name,access,share,security,disposition,attributes,template_file);const auto outgoing=errors();
    if(active){row.win32_result=result!=INVALID_HANDLE_VALUE;row.flags|=256;row.raw_output=reinterpret_cast<uintptr_t>(result);row.output_flags=1;if(result&&result!=INVALID_HANDLE_VALUE)row.output_flags|=2;const bool within=spawn_returned(&row,packet,outgoing);spawn_commit(&row,packet,result==INVALID_HANDLE_VALUE,within);}errors_restore(outgoing);return result;
}
static BOOL WINAPI spawn_duplicate(HANDLE source_process,HANDLE source,HANDLE target_process,LPHANDLE output,DWORD access,BOOL inherit,DWORD options){
    const auto target=spawn_original<SpawnDuplicate,3>();if(!spawn_collector.packet)return target(source_process,source,target_process,output,access,inherit,options);
    const auto incoming=errors();SpawnRow row={};const bool active=spawn_begin(&row,4,incoming);auto* packet=spawn_collector.packet;
    if(active){row.source_process=reinterpret_cast<uintptr_t>(source_process);row.source_handle=reinterpret_cast<uintptr_t>(source);row.target_process=reinterpret_cast<uintptr_t>(target_process);row.desired_access=access;row.inherit_handle=static_cast<uint32_t>(inherit);row.duplicate_options=options;}
    errors_restore(incoming);const auto result=target(source_process,source,target_process,output,access,inherit,options);const auto outgoing=errors();
    if(active){row.win32_result=static_cast<uint32_t>(result);row.flags|=256;const bool within=spawn_returned(&row,packet,outgoing);if(result)spawn_handle_output(&row,within,output);spawn_commit(&row,packet,!result,within);}errors_restore(outgoing);return result;
}
static BOOL WINAPI spawn_process(LPCWSTR application,LPWSTR command,LPSECURITY_ATTRIBUTES process_security,LPSECURITY_ATTRIBUTES thread_security,BOOL inherit,DWORD flags,LPVOID environment,LPCWSTR directory,LPSTARTUPINFOW startup,LPPROCESS_INFORMATION output){
    const auto target=spawn_original<SpawnProcess,4>();if(!spawn_collector.packet)return target(application,command,process_security,thread_security,inherit,flags,environment,directory,startup,output);
    const auto incoming=errors();SpawnRow row={};const bool active=spawn_begin(&row,5,incoming);auto* packet=spawn_collector.packet;
    if(active){row.inherit_handle=static_cast<uint32_t>(inherit);row.creation_flags=flags;row.security_present=(process_security?1:0)|(thread_security?2:0);spawn_win32_name(&row,application);}
    errors_restore(incoming);const auto result=target(application,command,process_security,thread_security,inherit,flags,environment,directory,startup,output);const auto outgoing=errors();
    if(active){row.win32_result=static_cast<uint32_t>(result);row.flags|=256;const bool within=spawn_returned(&row,packet,outgoing);if(output)row.output_flags|=1;
        if(result&&within){__try {if(output){const auto info=*output;row.raw_output=reinterpret_cast<uintptr_t>(info.hProcess);row.secondary_output=reinterpret_cast<uintptr_t>(info.hThread);row.output_pid=info.dwProcessId;row.output_tid=info.dwThreadId;row.output_flags|=64;if(row.raw_output)row.output_flags|=2;}}__except(EXCEPTION_EXECUTE_HANDLER){row.output_flags|=4;}}
        else if(result)row.output_flags|=32;spawn_commit(&row,packet,!result,within);}errors_restore(outgoing);return result;
}
static_assert(std::is_same_v<decltype(&spawn_open),SpawnOpen> && std::is_same_v<decltype(&spawn_pipe),SpawnPipe>,"native spawn wrapper ABI");
static_assert(std::is_same_v<decltype(&spawn_file),SpawnFile> && std::is_same_v<decltype(&spawn_duplicate),SpawnDuplicate> && std::is_same_v<decltype(&spawn_process),SpawnProcess>,"Win32 spawn wrapper ABI");
static const Hook spawn_hooks[SpawnRoutes]={{"NtOpenFile",reinterpret_cast<void*>(spawn_open)},{"NtCreateNamedPipeFile",reinterpret_cast<void*>(spawn_pipe)},{"CreateFileW",reinterpret_cast<void*>(spawn_file)},{"DuplicateHandle",reinterpret_cast<void*>(spawn_duplicate)},{"CreateProcessW",reinterpret_cast<void*>(spawn_process)}};

enum SpawnRefusalReason : uint32_t {SpawnDescriptor=1,SpawnThunkLimit,SpawnThunkRead,SpawnEndMarker,SpawnFunctionLimit,SpawnClock,SpawnSlotShape,SpawnOrdinalShape,SpawnOrdinalMissing,SpawnOrdinalAmbiguous,SpawnSelectedMismatch,SpawnNamedShape,SpawnDuplicateCandidate,SpawnCapacity,SpawnTargetIdentity,SpawnPointerFault,SpawnBoundedImports,SpawnEnumeration,SpawnCallbackEnd,SpawnOwnerClock,SpawnOwnerIdentity,SpawnCacheUnavailable,SpawnCacheValidation,SpawnPublication};
// Availability bits name values already read; zero without a bit is unknown.
enum SpawnAvailability : uint32_t {SpawnDescriptorKnown=1,SpawnSlotKnown=2,SpawnCurrentKnown=4,SpawnResolvedKnown=8,SpawnCandidateKnown=16,SpawnOrdinalKnown=32,SpawnDescriptorIndexKnown=64,SpawnThunkIndexKnown=128,SpawnKindKnown=256};
static void spawn_first_refusal(SpawnRefusal* destination,uint32_t reason,const SpawnRefusal& observed){if(destination&&!destination->present){*destination=observed;destination->reason=reason;destination->present=1;}}
static bool spawn_ordinal_selected(void* resolved,void* current,void* const* exports,size_t* typed,uint32_t* reason){
    *typed=0;*reason=0;
    if(!resolved){*reason=SpawnOrdinalMissing;return false;}
    // Declared identity is classified independently of the live IAT. The
    // shared helper intentionally conflates mismatch with unselected otherwise.
    *typed=typed_ordinal_operation(resolved,resolved,exports,SpawnRoutes);
    if(*typed>SpawnRoutes){*reason=SpawnOrdinalAmbiguous;return false;}
    if(*typed&&resolved!=current){*reason=SpawnSelectedMismatch;return false;}
    return true;
}
static bool spawn_ordinal_shape(uint64_t thunk,DWORD ordinal,LPCSTR name,HMODULE descriptor){return IMAGE_SNAP_BY_ORDINAL64(thunk)&&!name&&ordinal&&ordinal<=UINT16_MAX&&IMAGE_ORDINAL64(thunk)==ordinal&&!(thunk&~(IMAGE_ORDINAL_FLAG64|UINT64_C(0xffff)))&&descriptor;}
static bool spawn_slot_shape(uint64_t thunk,uintptr_t slot,uintptr_t first,size_t index,const Image& mapped){return thunk&&index<4096&&first<=UINTPTR_MAX-index*sizeof(void*)&&slot==first+index*sizeof(void*)&&range(slot,sizeof(void*),mapped.iat,mapped.iat_end);}
struct SpawnCache {volatile LONG state;Image mapped;SpawnOwner owner;WsaPacket proof;WsaNode targets[SpawnRoutes];SpawnRoute routes[SpawnRoutes];uint32_t route_count;SpawnRefusal refusal;};
static SpawnCache spawn_cache={};
struct SpawnDiscovery {ReturnedDiscovery base;uint32_t kinds[SpawnRoutes];SpawnRefusal* refusal;};
static std::atomic<NativeFileWritable> spawn_private_writable{nullptr};
static BOOL CALLBACK spawn_import_file(void* context,HMODULE module,LPCSTR name){
    auto* discovery=static_cast<SpawnDiscovery*>(context);auto* state=&discovery->base;
    const auto result=returned_import_file(state,module,name);
    if(state->error){SpawnRefusal observed={};observed.kind=name?4:3;observed.availability=SpawnKindKnown;
        if(state->packet->descriptor_count){observed.descriptor_index=state->packet->descriptor_count-1;observed.availability|=SpawnDescriptorIndexKnown;}
        spawn_first_refusal(discovery->refusal,name?SpawnDescriptor:SpawnCallbackEnd,observed);}
    return result;
}
static BOOL spawn_discovery_failure(SpawnDiscovery* discovery,SpawnRefusal* observed,uint32_t reason,DWORD error){
    discovery->base.error=error;spawn_first_refusal(discovery->refusal,reason,*observed);return FALSE;
}
static BOOL CALLBACK spawn_import_function(void* context,DWORD ordinal,LPCSTR name,void** slot){
    auto* discovery=static_cast<SpawnDiscovery*>(context);auto* state=&discovery->base;auto* proof=state->packet;
    SpawnRefusal observed={};observed.descriptor_module=reinterpret_cast<uintptr_t>(state->descriptor);observed.slot=reinterpret_cast<uintptr_t>(slot);observed.ordinal=ordinal;
    observed.thunk_index=static_cast<uint32_t>(state->thunk_index);observed.availability=SpawnDescriptorKnown|SpawnSlotKnown|SpawnOrdinalKnown|SpawnThunkIndexKnown;
    if(proof->descriptor_count){observed.descriptor_index=proof->descriptor_count-1;observed.availability|=SpawnDescriptorIndexKnown;}
    __try {
        if(state->error)return FALSE;
        if(state->thunk_index>=4096)return spawn_discovery_failure(discovery,&observed,SpawnThunkLimit,ERROR_BUFFER_OVERFLOW);
        const auto address=state->original_thunk+state->thunk_index*sizeof(IMAGE_THUNK_DATA64);
        if(!readable(address,sizeof(IMAGE_THUNK_DATA64),state->image))return spawn_discovery_failure(discovery,&observed,SpawnThunkRead,ERROR_INVALID_DATA);
        const auto thunk=reinterpret_cast<const IMAGE_THUNK_DATA64*>(address)->u1.Ordinal;
        if(!slot){observed.kind=3;observed.availability|=SpawnKindKnown;if(thunk||ordinal||name)return spawn_discovery_failure(discovery,&observed,SpawnEndMarker,ERROR_INVALID_DATA);return TRUE;}
        if(++proof->function_count>16384)return spawn_discovery_failure(discovery,&observed,SpawnFunctionLimit,proof->setup_error?proof->setup_error:ERROR_BUFFER_OVERFLOW);
        if(!live(proof))return spawn_discovery_failure(discovery,&observed,SpawnClock,proof->setup_error?proof->setup_error:ERROR_BUFFER_OVERFLOW);
        const auto slot_address=reinterpret_cast<uintptr_t>(slot);
        if(!spawn_slot_shape(thunk,slot_address,state->first_thunk,state->thunk_index,state->image)||!readable(slot_address,sizeof(void*),state->image))return spawn_discovery_failure(discovery,&observed,SpawnSlotShape,ERROR_INVALID_DATA);
        ++state->thunk_index;size_t typed=0;uint32_t kind=1;
        if(IMAGE_SNAP_BY_ORDINAL64(thunk)){
            kind=2;observed.kind=2;observed.availability|=SpawnKindKnown;
            if(!spawn_ordinal_shape(thunk,ordinal,name,state->descriptor))return spawn_discovery_failure(discovery,&observed,SpawnOrdinalShape,ERROR_INVALID_DATA);
            void* exports[SpawnRoutes]={};for(size_t op=0;op<SpawnRoutes;++op)exports[op]=reinterpret_cast<void*>(GetProcAddress(state->descriptor,spawn_hooks[op].name));
            void* resolved=reinterpret_cast<void*>(GetProcAddress(state->descriptor,MAKEINTRESOURCEA(static_cast<WORD>(ordinal))));
            observed.resolved=reinterpret_cast<uintptr_t>(resolved);observed.availability|=SpawnResolvedKnown;
            uint32_t reason=0;
            // First classify without consulting the slot, then compare only a
            // selected candidate. Never skip a candidate because it was changed.
            if(!spawn_ordinal_selected(resolved,resolved,exports,&typed,&reason)){observed.candidate=static_cast<uint32_t>(typed);if(resolved)observed.availability|=SpawnCandidateKnown;return spawn_discovery_failure(discovery,&observed,reason,ERROR_INVALID_DATA);}
            observed.candidate=static_cast<uint32_t>(typed);observed.availability|=SpawnCandidateKnown;
            if(!typed)return TRUE;
            void* current=*slot;observed.current=reinterpret_cast<uintptr_t>(current);observed.availability|=SpawnCurrentKnown;
            if(!spawn_ordinal_selected(resolved,current,exports,&typed,&reason))return spawn_discovery_failure(discovery,&observed,reason,ERROR_INVALID_DATA);
        }else {
            observed.kind=1;observed.availability|=SpawnKindKnown;
            if(ordinal||!name||thunk>UINT32_MAX||reinterpret_cast<uintptr_t>(name)!=state->image.base+static_cast<uint32_t>(thunk)+sizeof(WORD)||!bounded_name(name,state->image))return spawn_discovery_failure(discovery,&observed,SpawnNamedShape,ERROR_INVALID_DATA);
        }
        for(size_t op=0;op<SpawnRoutes;++op){
            if(typed?typed!=op+1:!equals(name,spawn_hooks[op].name,state->image))continue;
            observed.candidate=static_cast<uint32_t>(op+1);observed.availability|=SpawnCandidateKnown;
            for(size_t previous=0;previous<proof->slot_count;++previous)if(proof->slots[previous].operation==op+1||proof->slots[previous].slot==slot_address)return spawn_discovery_failure(discovery,&observed,SpawnDuplicateCandidate,ERROR_DUP_NAME);
            if(proof->slot_count>=SpawnRoutes)return spawn_discovery_failure(discovery,&observed,SpawnCapacity,ERROR_BUFFER_OVERFLOW);
            if(!(observed.availability&SpawnCurrentKnown)){observed.current=reinterpret_cast<uintptr_t>(*slot);observed.availability|=SpawnCurrentKnown;}
            void* current=reinterpret_cast<void*>(static_cast<uintptr_t>(observed.current));
            auto& selected=proof->slots[proof->slot_count++];selected.slot=slot_address;selected.operation=static_cast<uint32_t>(op+1);selected.descriptor_module=reinterpret_cast<uintptr_t>(state->descriptor);selected.original=observed.current;selected.hook=reinterpret_cast<uintptr_t>(spawn_hooks[op].target);discovery->kinds[op]=kind;
            Page page={};HMODULE target_owner=nullptr;Image target={};
            if(!data_page(slot,state->image,&page)||!state->descriptor)return spawn_discovery_failure(discovery,&observed,SpawnTargetIdentity,ERROR_NOT_SUPPORTED);
            void* resolved=reinterpret_cast<void*>(GetProcAddress(state->descriptor,spawn_hooks[op].name));observed.resolved=reinterpret_cast<uintptr_t>(resolved);observed.availability|=SpawnResolvedKnown;
            if(resolved!=current)return spawn_discovery_failure(discovery,&observed,SpawnSelectedMismatch,ERROR_NOT_SUPPORTED);
            if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(current),&target_owner)||!capture_node_data(target_owner,current,&state->targets[op],&target,&proof->incomplete,false))return spawn_discovery_failure(discovery,&observed,SpawnTargetIdentity,ERROR_NOT_SUPPORTED);
        }
        return TRUE;
    }__except(EXCEPTION_EXECUTE_HANDLER){proof->incomplete=1;return spawn_discovery_failure(discovery,&observed,SpawnPointerFault,ERROR_INVALID_ADDRESS);}
}
static bool spawn_routes_live(const SpawnCache* cache){
    __try {
        Image mapped={};if(!native_file_node_live(cache->owner.identity)||!image(reinterpret_cast<HMODULE>(cache->mapped.base),&mapped,false)||
            mapped.base!=cache->mapped.base||mapped.size!=cache->mapped.size||mapped.timestamp!=cache->mapped.timestamp||mapped.machine!=cache->mapped.machine||
            mapped.imports!=cache->mapped.imports||mapped.imports_end!=cache->mapped.imports_end||mapped.iat!=cache->mapped.iat||mapped.iat_end!=cache->mapped.iat_end||cache->proof.slot_count>SpawnRoutes)return false;
        for(uint32_t index=0;index<cache->proof.slot_count;++index){const auto& slot=cache->proof.slots[index];if(!slot.operation||slot.operation>SpawnRoutes)return false;
            const auto op=slot.operation-1;Page page={};if(!native_file_node_live(cache->targets[op])||slot.original!=cache->targets[op].entry||slot.hook!=reinterpret_cast<uintptr_t>(spawn_hooks[op].target)||
                !data_page(reinterpret_cast<void**>(slot.slot),mapped,&page)||*reinterpret_cast<void**>(slot.slot)!=reinterpret_cast<void*>(slot.published?slot.hook:slot.original)||
                GetProcAddress(reinterpret_cast<HMODULE>(slot.descriptor_module),spawn_hooks[op].name)!=reinterpret_cast<FARPROC>(slot.original)||
                (slot.published&&spawn_originals[op].load(std::memory_order_acquire)!=reinterpret_cast<void*>(slot.original)))return false;
        }
        return true;
    }__except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
static bool spawn_publish(SpawnCache* cache){
    auto* proof=&cache->proof;Page pages[SpawnRoutes]={};size_t count=0;
    for(size_t index=0;index<proof->slot_count;++index){const auto& slot=proof->slots[index];Page page={};
        if(!slot.operation||slot.operation>SpawnRoutes||!slot.hook||!data_page(reinterpret_cast<void**>(slot.slot),cache->mapped,&page)){failure(proof,5,ERROR_INVALID_ADDRESS);return false;}
        cache->routes[index].original_protection=page.original;bool present=false;for(size_t previous=0;previous<count;++previous)if(pages[previous].base==page.base)present=true;if(!present)pages[count++]=page;
        void* expected=nullptr;auto* original=reinterpret_cast<void*>(slot.original);
        if(!spawn_originals[slot.operation-1].compare_exchange_strong(expected,original,std::memory_order_acq_rel,std::memory_order_acquire)&&expected!=original){failure(proof,5,ERROR_RETRY);return false;}
    }
    const auto private_writable=spawn_private_writable.load(std::memory_order_acquire);if(!(private_writable?private_writable(pages,count,proof):writable(pages,count,proof)))return false;
    bool success=spawn_routes_live(cache);if(!success)failure(proof,6,ERROR_RETRY);
    for(size_t index=0;success&&index<proof->slot_count;++index){auto& slot=proof->slots[index];if(!live(proof)||swap(reinterpret_cast<void**>(slot.slot),reinterpret_cast<void*>(slot.hook),reinterpret_cast<void*>(slot.original))!=reinterpret_cast<void*>(slot.original)){failure(proof,5,proof->setup_error?proof->setup_error:ERROR_RETRY);success=false;break;}slot.published=1;}
    if(!success)returned_rollback(proof);restore(pages,count,proof);
    if(success&&!spawn_routes_live(cache)){failure(proof,6,ERROR_RETRY);return false;}return success;
}
static void spawn_prepare(SpawnPacket* output,ListenerInvoke callback){
    ObserverSetup setup;auto& record=output->owners[0];record.role=1;record.shared_owner=UINT32_MAX;output->owner_count=1;
    auto* cache=&spawn_cache;const LONG state=InterlockedCompareExchange(&cache->state,1,0);
    if(state==2){record=cache->owner;HMODULE current=nullptr;
        if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(callback),&current)||reinterpret_cast<uintptr_t>(current)!=cache->mapped.base||!executable(reinterpret_cast<void*>(callback),current)||!spawn_routes_live(cache)){record.stage=6;record.error=ERROR_RETRY;record.complete=0;output->route_failures=1;spawn_first_refusal(&output->refusal,SpawnCacheValidation,SpawnRefusal{});return;}
        for(uint32_t index=0;index<cache->route_count;++index)output->routes[output->route_count++]=cache->routes[index];return;}
    if(state!=0){record.stage=9;record.error=state==1?ERROR_BUSY:ERROR_NOT_SUPPORTED;output->route_failures=1;if(state==3)output->refusal=cache->refusal;spawn_first_refusal(&output->refusal,SpawnCacheUnavailable,SpawnRefusal{});return;}
    auto* proof=&cache->proof;proof->version=1;proof->cutoff_qpc=output->cutoff_qpc;proof->frequency=output->frequency;
    HMODULE owner=nullptr;Image mapped={};bool success=false;
    do {
        if(!live(proof)){record.stage=2;record.error=proof->setup_error;spawn_first_refusal(&cache->refusal,SpawnOwnerClock,SpawnRefusal{});break;}
        const BOOL resolved=GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(callback),&owner);const auto error=resolved?ERROR_SUCCESS:GetLastError();
        if(!resolved||owner!=GetModuleHandleW(nullptr)||!capture_node_data(owner,reinterpret_cast<void*>(callback),&record.identity,&mapped,&proof->incomplete,false)){record.stage=3;record.error=resolved?ERROR_INVALID_ADDRESS:error;spawn_first_refusal(&cache->refusal,SpawnOwnerIdentity,SpawnRefusal{});break;}
        cache->mapped=mapped;cache->owner=record;
        if(!mapped.imports&&!mapped.iat){record.flags|=2;record.complete=1;record.stage=1;success=true;break;}
        SpawnDiscovery discovery={};discovery.base.image=mapped;discovery.base.packet=proof;discovery.refusal=&cache->refusal;
        bool complete=returned_bounded_imports(&discovery.base);
        if(!complete)spawn_first_refusal(&cache->refusal,SpawnBoundedImports,SpawnRefusal{});
        if(complete){SetLastError(ERROR_SUCCESS);complete=DetourEnumerateImportsEx(owner,&discovery,spawn_import_file,spawn_import_function)!=FALSE;const auto enumeration_error=GetLastError();if(!complete&&!discovery.base.error){discovery.base.error=enumeration_error?enumeration_error:ERROR_INVALID_DATA;spawn_first_refusal(&cache->refusal,SpawnEnumeration,SpawnRefusal{});}}
        record.descriptor_count=proof->descriptor_count;record.function_count=proof->function_count;cache->route_count=proof->slot_count;
        for(uint32_t index=0;index<proof->slot_count&&index<SpawnRoutes;++index){auto& route=cache->routes[index];route.slot=proof->slots[index];route.owner_index=0;route.thunk_kind=discovery.kinds[route.slot.operation-1];route.target=discovery.base.targets[route.slot.operation-1];cache->targets[route.slot.operation-1]=route.target;}
        if(!complete||!proof->callbacks_complete||discovery.base.error){record.stage=4;record.error=proof->setup_error?proof->setup_error:discovery.base.error?discovery.base.error:ERROR_INVALID_DATA;spawn_first_refusal(&cache->refusal,proof->callbacks_complete?SpawnEnumeration:SpawnCallbackEnd,SpawnRefusal{});break;}
        if(!spawn_publish(cache)){record.stage=proof->setup_stage?proof->setup_stage:5;record.error=proof->setup_error?proof->setup_error:ERROR_RETRY;spawn_first_refusal(&cache->refusal,SpawnPublication,SpawnRefusal{});break;}
        record.complete=1;record.stage=1;success=true;
    }while(false);
    if(proof->incomplete)record.flags|=4;if(!success)output->route_failures=increment(output->route_failures);
    for(uint32_t index=0;index<cache->route_count&&index<SpawnRoutes;++index){auto& route=cache->routes[index];route.slot=proof->slots[index];route.stage=success?1:record.stage;route.error=success?0:record.error;route.postvalidated=success?1:0;output->routes[output->route_count++]=route;}
    cache->owner=record;output->refusal=cache->refusal;InterlockedExchange(&cache->state,success?2:3);
}

// POD-only SEH boundary; no exception translation or synthetic callback result.
extern "C" void memcordon_spawn_trace_call(SpawnPacket* packet,const ListenerRequest* request,ListenerInvoke callback,void* opaque){
    if(!packet||!request){if(packet){*packet={};packet->version=SpawnVersion;packet->packet_bytes=sizeof(*packet);packet->incomplete=1;packet->scope_unavailable=1;}if(callback){ListenerOutcome outcome={};callback(opaque,&outcome);}return;}
    const auto previous=spawn_collector;const ErrorPair incoming={request->incoming_win32,request->incoming_wsa};
    *packet={};packet->version=SpawnVersion;packet->packet_bytes=sizeof(*packet);packet->incomplete=1;
    packet->cutoff_qpc=request->cutoff_qpc;packet->frequency=request->frequency;packet->original_thread=GetCurrentThreadId();
    if(callback&&!previous.packet){const auto prepare=spawn_private_prepare.load(std::memory_order_acquire);if(prepare)prepare(packet,callback);else spawn_prepare(packet,callback);}else{packet->scope_unavailable=1;if(previous.packet){packet->scope_reentry=1;previous.packet->scope_reentry=increment(previous.packet->scope_reentry);}}
    spawn_collector={};LARGE_INTEGER start={};const BOOL clock=spawn_clock(&start);
    if(clock&&start.QuadPart>0){packet->started_qpc=static_cast<uint64_t>(start.QuadPart);if(packet->started_qpc<packet->cutoff_qpc&&callback&&!previous.packet)spawn_collector={packet,packet->started_qpc,packet->original_thread,false,false};else packet->late=increment(packet->late);}else packet->clock_failures=increment(packet->clock_failures);
    errors_restore(incoming);ListenerOutcome outcome={};
    __try {if(callback){packet->scope_attempted=1;callback(opaque,&outcome);packet->scope_returned=1;}else packet->scope_unavailable=increment(packet->scope_unavailable);}
    __finally {
        const auto outgoing=errors();if(AbnormalTermination())packet->unmatched_scope=increment(packet->unmatched_scope);
        if(spawn_collector.inside)packet->unmatched_scope=increment(packet->unmatched_scope);
        LARGE_INTEGER finish={};if(spawn_clock(&finish)&&finish.QuadPart>0&&static_cast<uint64_t>(finish.QuadPart)>=packet->started_qpc){packet->finished_qpc=static_cast<uint64_t>(finish.QuadPart);if(packet->finished_qpc>=packet->cutoff_qpc)packet->late=increment(packet->late);}else packet->clock_failures=increment(packet->clock_failures);
        spawn_collector=previous;errors_restore(outgoing);
    }
}

struct SpawnMock {
    std::atomic<uint32_t> calls[SpawnRoutes];std::atomic<bool> same;
    PHANDLE output;POBJECT_ATTRIBUTES attributes;PIO_STATUS_BLOCK io;PLARGE_INTEGER timeout;
    LPCWSTR name;LPWSTR command;LPPROCESS_INFORMATION process_output;
    ErrorPair incoming,outgoing;NTSTATUS status;BOOL win32;HANDLE file;
    bool write_output,recurse,late;uint32_t mode;uint64_t cutoff;
    std::atomic<uint32_t> clock_mode;
};
static std::atomic<SpawnMock*> spawn_mock{nullptr};
static void spawn_mock_check(SpawnMock* state,unsigned operation,bool args){
    ++state->calls[operation];if(!args||!native_file_same_errors(errors(),state->incoming))state->same=false;
}
static NTSTATUS NTAPI spawn_mock_open(PHANDLE output,ACCESS_MASK access,POBJECT_ATTRIBUTES attributes,PIO_STATUS_BLOCK io,ULONG share,ULONG options){
    auto* state=spawn_mock.load(std::memory_order_acquire);spawn_mock_check(state,0,output==state->output&&access==0x101&&attributes==state->attributes&&io==state->io&&share==3&&options==0x102);
    if(state->recurse){state->recurse=false;errors_restore(state->incoming);spawn_open(output,access,attributes,io,share,options);}
    if(state->mode==9)RaiseException(0xE04D4302u,0,0,nullptr);
    if(state->status>=0&&state->status!=static_cast<NTSTATUS>(0x103)&&state->write_output)*output=reinterpret_cast<HANDLE>(0xABCD);
    if(state->late)state->clock_mode=2;errors_restore(state->outgoing);return state->status;
}
static NTSTATUS NTAPI spawn_mock_pipe(PHANDLE output,ULONG access,POBJECT_ATTRIBUTES attributes,PIO_STATUS_BLOCK io,ULONG share,ULONG disposition,ULONG options,ULONG type,ULONG read_mode,ULONG completion,ULONG instances,ULONG inbound,ULONG outbound,PLARGE_INTEGER timeout){
    auto* state=spawn_mock.load(std::memory_order_acquire);spawn_mock_check(state,1,output==state->output&&access==0x201&&attributes==state->attributes&&io==state->io&&share==7&&disposition==4&&options==0x202&&type==1&&read_mode==2&&completion==3&&instances==4&&inbound==4096&&outbound==8192&&timeout==state->timeout);
    if(state->status>=0&&state->status!=static_cast<NTSTATUS>(0x103)&&state->write_output)*output=reinterpret_cast<HANDLE>(0xABCD);
    errors_restore(state->outgoing);return state->status;
}
static HANDLE WINAPI spawn_mock_file(LPCWSTR name,DWORD access,DWORD share,LPSECURITY_ATTRIBUTES security,DWORD disposition,DWORD attributes,HANDLE template_file){
    auto* state=spawn_mock.load(std::memory_order_acquire);spawn_mock_check(state,2,name==state->name&&access==0x301&&share==5&&!security&&disposition==3&&attributes==0x302&&template_file==reinterpret_cast<HANDLE>(0xABC));errors_restore(state->outgoing);return state->file;
}
static BOOL WINAPI spawn_mock_duplicate(HANDLE source_process,HANDLE source,HANDLE target_process,LPHANDLE output,DWORD access,BOOL inherit,DWORD options){
    auto* state=spawn_mock.load(std::memory_order_acquire);spawn_mock_check(state,3,source_process==reinterpret_cast<HANDLE>(static_cast<intptr_t>(-1))&&source==reinterpret_cast<HANDLE>(0x123)&&target_process==source_process&&output==state->output&&access==0x401&&inherit==TRUE&&options==2);
    if(state->win32&&state->write_output)*output=reinterpret_cast<HANDLE>(0xABCD);errors_restore(state->outgoing);return state->win32;
}
static BOOL WINAPI spawn_mock_process(LPCWSTR application,LPWSTR command,LPSECURITY_ATTRIBUTES process_security,LPSECURITY_ATTRIBUTES thread_security,BOOL inherit,DWORD flags,LPVOID environment,LPCWSTR directory,LPSTARTUPINFOW startup,LPPROCESS_INFORMATION output){
    auto* state=spawn_mock.load(std::memory_order_acquire);spawn_mock_check(state,4,application==state->name&&command==state->command&&process_security==reinterpret_cast<LPSECURITY_ATTRIBUTES>(0x11)&&thread_security==reinterpret_cast<LPSECURITY_ATTRIBUTES>(0x22)&&inherit==TRUE&&flags==0x501&&environment==reinterpret_cast<void*>(0x33)&&directory==reinterpret_cast<LPCWSTR>(0x44)&&startup==reinterpret_cast<LPSTARTUPINFOW>(0x55)&&output==state->process_output);
    if(state->win32&&state->write_output)*output={reinterpret_cast<HANDLE>(0xABCD),reinterpret_cast<HANDLE>(0xEF),123,456};errors_restore(state->outgoing);return state->win32;
}
static void spawn_mock_call(SpawnMock* state,unsigned operation){
    errors_restore(state->incoming);
    if(operation==0){const auto result=spawn_open(state->output,0x101,state->attributes,state->io,3,0x102);if(result!=state->status)state->same=false;}
    else if(operation==1){const auto result=spawn_pipe(state->output,0x201,state->attributes,state->io,7,4,0x202,1,2,3,4,4096,8192,state->timeout);if(result!=state->status)state->same=false;}
    else if(operation==2){const auto result=spawn_file(state->name,0x301,5,nullptr,3,0x302,reinterpret_cast<HANDLE>(0xABC));if(result!=state->file)state->same=false;}
    else if(operation==3){const auto self=reinterpret_cast<HANDLE>(static_cast<intptr_t>(-1));const auto result=spawn_duplicate(self,reinterpret_cast<HANDLE>(0x123),self,state->output,0x401,TRUE,2);if(result!=state->win32)state->same=false;}
    else {const auto result=spawn_process(state->name,state->command,reinterpret_cast<LPSECURITY_ATTRIBUTES>(0x11),reinterpret_cast<LPSECURITY_ATTRIBUTES>(0x22),TRUE,0x501,reinterpret_cast<void*>(0x33),reinterpret_cast<LPCWSTR>(0x44),reinterpret_cast<LPSTARTUPINFOW>(0x55),state->process_output);if(result!=state->win32)state->same=false;}
    if(!native_file_same_errors(errors(),state->outgoing))state->same=false;
}
static BOOL spawn_mock_clock(LARGE_INTEGER* now){
    auto* state=spawn_mock.load(std::memory_order_acquire);const auto mode=state->clock_mode.load();
    if(mode==1){SetLastError(ERROR_INVALID_DATA);return FALSE;}if(mode==2){now->QuadPart=static_cast<LONGLONG>(state->cutoff);return TRUE;}if(mode==3){now->QuadPart=1;return TRUE;}return QueryPerformanceCounter(now);
}
static void spawn_mock_packet(SpawnPacket* packet,ListenerInvoke){
    if(spawn_mock.load(std::memory_order_acquire)->mode==10){packet->scope_unavailable=1;return;}
    packet->owner_count=1;packet->owners[0].complete=1;packet->route_count=SpawnRoutes;
    for(uint32_t index=0;index<SpawnRoutes;++index){packet->routes[index].slot.operation=index+1;packet->routes[index].slot.published=1;packet->routes[index].postvalidated=1;}
}
static void spawn_mock_callback(void* context,ListenerOutcome*){
    auto* state=static_cast<SpawnMock*>(context);if(state->mode==12&&spawn_collector.packet)spawn_collector.packet->total_calls=UINT32_MAX;
    if(state->mode==0){for(unsigned index=0;index<SpawnRoutes;++index)spawn_mock_call(state,index);}else if(state->mode==2){for(unsigned index=0;index<SpawnRows+2;++index)spawn_mock_call(state,0);}else spawn_mock_call(state,0);
}
static bool spawn_mock_unwind(SpawnPacket* packet,const ListenerRequest* request,SpawnMock* state){
    const auto previous=spawn_collector;bool caught=false;
    __try {memcordon_spawn_trace_call(packet,request,spawn_mock_callback,state);}
    __except(GetExceptionCode()==0xE04D4302u?EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH){caught=true;}
    const auto restored=spawn_collector;return caught&&restored.packet==previous.packet&&restored.started==previous.started&&restored.thread==previous.thread&&restored.inside==previous.inside&&restored.disarmed==previous.disarmed;
}
static DWORD WINAPI spawn_mock_foreign(void* context){spawn_mock_call(static_cast<SpawnMock*>(context),0);return 0;}
struct SpawnMockRestore {
    SpawnCollector collector;const SpawnPrivateTargets* targets;LoaderWindowClock clock;SpawnPrivatePrepare prepare;SpawnMock* mock;NativeFileWritable writable;ErrorPair errors;
    ~SpawnMockRestore(){spawn_collector=collector;spawn_private_targets.store(targets,std::memory_order_release);spawn_private_clock.store(clock,std::memory_order_release);spawn_private_prepare.store(prepare,std::memory_order_release);spawn_mock.store(mock,std::memory_order_release);spawn_private_writable.store(writable,std::memory_order_release);errors_restore(errors);}
};
static bool spawn_mock_protection_failure(Page*,size_t,WsaPacket* packet){failure(packet,5,ERROR_ACCESS_DENIED);return false;}
static uint32_t spawn_preflight_selfcheck(uint64_t cutoff,uint64_t frequency){
    void* exports[SpawnRoutes]={};for(size_t index=0;index<SpawnRoutes;++index)exports[index]=reinterpret_cast<void*>(0x1000+index*8);
    void* unrelated=reinterpret_cast<void*>(0x2000);void* changed=reinterpret_cast<void*>(0x3000);size_t typed=0;uint32_t reason=0;
    void* unselected_slots[]={unrelated,changed,exports[0],nullptr};for(void* current:unselected_slots)if(!spawn_ordinal_selected(unrelated,current,exports,&typed,&reason)||typed||reason)return 1;
    for(size_t index=0;index<SpawnRoutes;++index){
        if(!spawn_ordinal_selected(exports[index],exports[index],exports,&typed,&reason)||typed!=index+1||reason)return 2;
        if(spawn_ordinal_selected(exports[index],changed,exports,&typed,&reason)||typed!=index+1||reason!=SpawnSelectedMismatch)return 3;
        if(spawn_ordinal_selected(exports[index],spawn_hooks[index].target,exports,&typed,&reason)||typed!=index+1||reason!=SpawnSelectedMismatch)return 4;
    }
    if(spawn_ordinal_selected(nullptr,changed,exports,&typed,&reason)||typed||reason!=SpawnOrdinalMissing)return 5;
    void* aliases[SpawnRoutes]={exports[0],exports[0],nullptr,nullptr,nullptr};
    if(spawn_ordinal_selected(exports[0],exports[0],aliases,&typed,&reason)||typed!=SpawnRoutes+1||reason!=SpawnOrdinalAmbiguous)return 6;
    const uint64_t ordinal=IMAGE_ORDINAL_FLAG64|17;const auto descriptor=reinterpret_cast<HMODULE>(1);
    if(!spawn_ordinal_shape(ordinal,17,nullptr,descriptor)||spawn_ordinal_shape(17,17,nullptr,descriptor)||spawn_ordinal_shape(ordinal|UINT64_C(0x10000),17,nullptr,descriptor)||spawn_ordinal_shape(ordinal,18,nullptr,descriptor)||spawn_ordinal_shape(ordinal,17,reinterpret_cast<LPCSTR>(1),descriptor)||spawn_ordinal_shape(ordinal,17,nullptr,nullptr)||spawn_ordinal_shape(IMAGE_ORDINAL_FLAG64|65535,65536,nullptr,descriptor))return 7;
    Image mapped={};mapped.iat=0x1000;mapped.iat_end=0x1028;
    if(!spawn_slot_shape(ordinal,0x1020,0x1000,4,mapped)||spawn_slot_shape(ordinal,0x1021,0x1000,4,mapped)||spawn_slot_shape(ordinal,0x1028,0x1000,5,mapped)||spawn_slot_shape(ordinal,0x1000,0x1000,4096,mapped)||spawn_slot_shape(0,0x1000,0x1000,0,mapped))return 8;
    WsaPacket proof={};proof.cutoff_qpc=cutoff;proof.frequency=frequency;SpawnRefusal refusal={};SpawnDiscovery bad={};bad.base.packet=&proof;bad.refusal=&refusal;bad.base.thunk_index=4096;
    if(spawn_import_function(&bad,0,nullptr,nullptr)||refusal.reason!=SpawnThunkLimit||refusal.thunk_index!=4096||refusal.availability&SpawnCurrentKnown)return 9;
    bad.base.error=0;bad.base.thunk_index=0;refusal={};
    if(spawn_import_function(&bad,0,nullptr,nullptr)||refusal.reason!=SpawnThunkRead||refusal.availability&(SpawnCurrentKnown|SpawnResolvedKnown))return 10;
    SpawnRefusal measured={};measured.current=0;measured.availability=SpawnCurrentKnown;SpawnRefusal first={};spawn_first_refusal(&first,SpawnSelectedMismatch,measured);measured.current=0x9876;spawn_first_refusal(&first,SpawnTargetIdentity,measured);
    if(first.reason!=SpawnSelectedMismatch||first.current||first.availability!=SpawnCurrentKnown)return 11;
    return 0;
}
extern "C" uint32_t memcordon_spawn_trace_mock(uint64_t cutoff,uint64_t frequency){
    const auto saved=errors();SpawnMockRestore restore={spawn_collector,spawn_private_targets.load(),spawn_private_clock.load(),spawn_private_prepare.load(),spawn_mock.load(),spawn_private_writable.load(),saved};
    const auto preflight=spawn_preflight_selfcheck(cutoff,frequency);if(preflight)return 32+preflight;
    SpawnMock state={};state.same=true;state.incoming={131,131};state.outgoing={5,5};state.status=static_cast<NTSTATUS>(0xC0000022u);state.file=INVALID_HANDLE_VALUE;state.cutoff=cutoff;state.write_output=true;
    HANDLE output=nullptr;PROCESS_INFORMATION process={};LARGE_INTEGER timeout={};timeout.QuadPart=-500000;
    WCHAR text[]={L'p',L'i',L'p',L'e',0};UNICODE_STRING name={8,10,text};OBJECT_ATTRIBUTES attributes={sizeof(OBJECT_ATTRIBUTES),reinterpret_cast<HANDLE>(0x7788),&name,0x40,nullptr,nullptr};
    state.output=&output;state.attributes=&attributes;state.io=reinterpret_cast<PIO_STATUS_BLOCK>(1);state.timeout=&timeout;state.name=text;state.command=reinterpret_cast<LPWSTR>(0x99);state.process_output=&process;
    const SpawnPrivateTargets targets={{reinterpret_cast<void*>(spawn_mock_open),reinterpret_cast<void*>(spawn_mock_pipe),reinterpret_cast<void*>(spawn_mock_file),reinterpret_cast<void*>(spawn_mock_duplicate),reinterpret_cast<void*>(spawn_mock_process)}};
    spawn_mock.store(&state,std::memory_order_release);spawn_private_targets.store(&targets,std::memory_order_release);spawn_private_clock.store(spawn_mock_clock,std::memory_order_release);spawn_private_prepare.store(spawn_mock_packet,std::memory_order_release);spawn_collector={};
    SpawnPacket packet={};ListenerRequest request={cutoff,frequency,state.incoming.win32,state.incoming.wsa,0,0};
    memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);
    if(!state.same||packet.record_count!=SpawnRoutes||packet.total_calls!=SpawnRoutes||packet.total_failures!=SpawnRoutes||!packet.first_failure_present||packet.first_failure.sequence!=1||!packet.scope_attempted||!packet.scope_returned)return 1;
    for(uint32_t index=0;index<SpawnRoutes;++index)if(state.calls[index]!=1||packet.rows[index].operation!=index+1||!(packet.rows[index].flags&16))return 2;
    if(packet.rows[0].raw_root!=0x7788||packet.rows[1].default_timeout!=static_cast<uint64_t>(timeout.QuadPart)||packet.rows[1].inbound_quota!=4096||packet.rows[2].reported_name_bytes!=8||packet.rows[3].duplicate_options!=2||packet.rows[4].creation_flags!=0x501)return 3;
    const auto old=state.calls[0].load();spawn_mock_call(&state,0);if(state.calls[0]!=old+1||packet.total_calls!=SpawnRoutes||!state.same)return 4;
    SpawnPacket foreign={};spawn_mock_packet(&foreign,nullptr);foreign.cutoff_qpc=cutoff;foreign.original_thread=GetCurrentThreadId();LARGE_INTEGER started={};QueryPerformanceCounter(&started);spawn_collector={&foreign,static_cast<uint64_t>(started.QuadPart),foreign.original_thread,false,false};
    HANDLE thread=CreateThread(nullptr,0,spawn_mock_foreign,&state,0,nullptr);if(!thread)return 5;
    DWORD settled=WAIT_TIMEOUT;while(settled==WAIT_TIMEOUT){LARGE_INTEGER now={};if(!QueryPerformanceCounter(&now)||now.QuadPart<=0||static_cast<uint64_t>(now.QuadPart)>=cutoff)__fastfail(FAST_FAIL_FATAL_APP_EXIT);settled=WaitForSingleObject(thread,0);}
    LARGE_INTEGER after={};if(settled!=WAIT_OBJECT_0||!QueryPerformanceCounter(&after)||after.QuadPart<=0||static_cast<uint64_t>(after.QuadPart)>=cutoff)__fastfail(FAST_FAIL_FATAL_APP_EXIT);CloseHandle(thread);
    if(foreign.total_calls||!state.same)return 6;spawn_collector={};
    state.mode=1;state.recurse=true;memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(packet.total_calls!=1||!packet.scope_reentry||!state.same)return 7;
    state.mode=2;memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(packet.record_count!=SpawnRows||packet.dropped!=2||packet.first_failure.sequence!=1||packet.total_calls!=SpawnRows+2)return 8;
    state.mode=1;state.status=static_cast<NTSTATUS>(0x103);state.output=reinterpret_cast<PHANDLE>(1);memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(packet.rows[0].output_flags!=(16|8)||!(packet.rows[0].flags&64))return 9;
    state.status=0;state.write_output=false;memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(!(packet.rows[0].output_flags&4))return 10;
    state.output=&output;state.write_output=true;state.win32=TRUE;state.file=reinterpret_cast<HANDLE>(0xABCD);state.mode=0;memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(packet.total_failures||packet.rows[0].raw_output!=0xABCD||packet.rows[4].output_pid!=123||packet.rows[4].output_tid!=456||packet.rows[4].secondary_output!=0xEF||!(packet.rows[4].output_flags&64)||!state.same)return 11;
    WCHAR long_name[SpawnNameUnits+1]={};for(auto& unit:long_name)unit=L'x';state.name=long_name;memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(packet.rows[2].reported_name_bytes||packet.rows[2].copied_name_units!=SpawnNameUnits||!(packet.rows[2].name_flags&4)||(packet.rows[2].name_flags&32))return 12;
    state.name=text;state.attributes=reinterpret_cast<POBJECT_ATTRIBUTES>(1);state.mode=1;memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(!(packet.rows[0].input_flags&128))return 13;
    state.attributes=&attributes;UNICODE_STRING odd={3,3,text};attributes.ObjectName=&odd;memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(!(packet.rows[0].input_flags&256))return 14;attributes.ObjectName=&name;
    state.clock_mode=1;const auto before=state.calls[0].load();memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(packet.total_calls||!packet.clock_failures||state.calls[0]!=before+1||!state.same)return 15;
    state.clock_mode=2;memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(packet.total_calls||!packet.late||!state.same)return 16;
    state.clock_mode=0;state.late=true;memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(!(packet.rows[0].flags&32)||(packet.rows[0].flags&16)||!packet.late||!state.same)return 17;state.late=false;state.clock_mode=0;
    state.mode=9;state.status=static_cast<NTSTATUS>(0xC0000022u);if(!spawn_mock_unwind(&packet,&request,&state)||packet.scope_returned||!packet.scope_attempted||!packet.unmatched_scope||packet.record_count||packet.total_calls!=1)return 18;state.mode=1;
    state.mode=10;const auto unobserved=state.calls[0].load();memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(packet.total_calls||!packet.scope_unavailable||state.calls[0]!=unobserved+1||!state.same)return 21;
    state.mode=12;memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(packet.total_calls!=UINT32_MAX||!packet.overflow||packet.record_count||!state.same)return 22;
    state.mode=0;state.timeout=reinterpret_cast<PLARGE_INTEGER>(1);memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(!(packet.rows[1].input_flags&128)||(packet.rows[1].input_flags&16))return 23;state.timeout=&timeout;
    state.name=reinterpret_cast<LPCWSTR>(1);memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(!(packet.rows[2].name_flags&2)||!state.same)return 24;state.name=text;
    state.process_output=reinterpret_cast<LPPROCESS_INFORMATION>(1);state.write_output=false;memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(!(packet.rows[4].output_flags&4)||!state.same)return 31;state.process_output=&process;state.write_output=true;
    UNICODE_STRING long_counted={sizeof(long_name),sizeof(long_name),long_name};attributes.ObjectName=&long_counted;memcordon_spawn_trace_call(&packet,&request,spawn_mock_callback,&state);if(packet.rows[0].reported_name_bytes!=sizeof(long_name)||packet.rows[0].copied_name_units!=SpawnNameUnits||(packet.rows[0].name_flags&(4|32))!=(4|32))return 25;attributes.ObjectName=&name;
    spawn_private_targets.store(nullptr,std::memory_order_release);spawn_private_prepare.store(nullptr,std::memory_order_release);spawn_private_clock.store(nullptr,std::memory_order_release);
    // Independent physical import inventory/publication proof. No callback is
    // invoked: this does not force a syscall or another spawn.
    SpawnPacket real={};real.cutoff_qpc=cutoff;real.frequency=frequency;spawn_prepare(&real,spawn_mock_callback);
    if(real.owner_count!=1||!real.owners[0].complete||real.owners[0].identity.owner_base!=reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr))||!spawn_routes_live(&spawn_cache))return 19;
    bool native_open_present=false;for(uint32_t index=0;index<real.route_count;++index)if(real.routes[index].slot.operation==1)native_open_present=true;
    // The existing noinline native-file selfcheck already owns a normal
    // SDK NtOpenFile import in this same translation unit; no call is added.
    if(!native_open_present)return 30;
    for(uint32_t index=0;index<real.route_count;++index)if(!real.routes[index].slot.published||!real.routes[index].postvalidated||!real.routes[index].original_protection||real.routes[index].slot.restored)return 20;
    if(real.route_count){auto changed=spawn_cache;changed.proof.slots[0].hook^=1;if(spawn_routes_live(&changed))return 26;
        changed=spawn_cache;changed.owner.identity.owner_size^=1;if(spawn_routes_live(&changed))return 27;
        changed=spawn_cache;changed.targets[changed.proof.slots[0].operation-1].entry^=1;if(spawn_routes_live(&changed))return 28;
        changed=spawn_cache;const auto before=*reinterpret_cast<void**>(changed.proof.slots[0].slot);spawn_private_writable.store(spawn_mock_protection_failure,std::memory_order_release);const bool published=spawn_publish(&changed);spawn_private_writable.store(nullptr,std::memory_order_release);
        if(published||changed.proof.setup_error!=ERROR_ACCESS_DENIED||*reinterpret_cast<void**>(changed.proof.slots[0].slot)!=before)return 29;
    }
    errors_restore(saved);return 0;
}

static void spawn_composition_callback(void* opaque,ListenerOutcome* outcome){++*static_cast<uint32_t*>(opaque);outcome->kind=1;}
static uint32_t spawn_composition_inner(uint64_t cutoff,uint64_t frequency,SpawnPacket* output){
    if(!output)return 8;
    *output={};output->version=SpawnVersion;output->packet_bytes=sizeof(*output);output->cutoff_qpc=cutoff;output->frequency=frequency;output->incomplete=1;output->scope_unavailable=1;
    WsaPacket budget={};budget.cutoff_qpc=cutoff;budget.frequency=frequency;
    if(!live(&budget)||InterlockedCompareExchange(&listener_installed,0,0)!=2||InterlockedCompareExchange(&spawn_cache.state,0,0)!=0)return 1;
    ListenerPacket before={};before.cutoff_qpc=cutoff;before.frequency=frequency;listener_copy_route(&before);
    if(!before.slot_count||before.slot_count>16||(before.published_mask&0x1A)!=0x1A||!listener_route_live(&before,listener_route.targets)||!live(&budget))return 2;
    const auto incoming=errors();ListenerRequest request={cutoff,frequency,incoming.win32,incoming.wsa,0,0};auto& packet=*output;uint32_t calls=0;
    memcordon_spawn_trace_call(&packet,&request,spawn_composition_callback,&calls);
    if(calls!=1||packet.scope_attempted!=1||packet.scope_returned!=1||packet.owner_count!=1||packet.owners[0].complete!=1||packet.route_count!=SpawnRoutes||packet.refusal.present||!spawn_routes_live(&spawn_cache)||!live(&budget))return 3;
    uint32_t operations=0;for(uint32_t index=0;index<packet.route_count;++index){const auto& route=packet.routes[index];
        if(!route.slot.operation||route.slot.operation>SpawnRoutes||!route.slot.published||route.slot.restored||!route.postvalidated||!route.original_protection)return 4;
        operations|=1u<<(route.slot.operation-1);
    }
    if(operations!=(1u<<SpawnRoutes)-1)return 5;
    ListenerPacket after={};after.cutoff_qpc=cutoff;after.frequency=frequency;listener_copy_route(&after);
    if(after.slot_count!=before.slot_count||after.published_mask!=before.published_mask||!listener_route_live(&after,listener_route.targets)||!live(&budget))return 6;
    for(uint32_t index=0;index<before.slot_count;++index){const auto& original=before.slots[index];const auto& observed=after.slots[index];
        if(original.slot!=observed.slot||original.original!=observed.original||original.hook!=observed.hook||original.published!=observed.published||original.restored!=observed.restored)return 7;
    }
    return 0;
}
extern "C" uint32_t memcordon_spawn_trace_composition_check(uint64_t cutoff,uint64_t frequency,SpawnPacket* output){
    const auto saved=errors();const auto result=spawn_composition_inner(cutoff,frequency,output);errors_restore(saved);return result;
}
