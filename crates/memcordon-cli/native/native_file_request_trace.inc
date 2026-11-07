// Included after the existing bounded PE/IAT helpers. These routes never
// replace function prologues, detach live forwarding code or load a DLL.
using NativeCreateFile=NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
using NativeOpenFile=NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,ULONG,ULONG);
static std::atomic<void*> native_file_originals[NativeFileRoutes]={};
struct NativeFilePrivateTargets {void* targets[NativeFileRoutes];};
static std::atomic<const NativeFilePrivateTargets*> native_file_private_targets{nullptr};
static std::atomic<LoaderWindowClock> native_file_private_clock{nullptr};
static BOOL native_file_clock(LARGE_INTEGER* value){const auto mock=native_file_private_clock.load(std::memory_order_acquire);return mock?mock(value):QueryPerformanceCounter(value);}
template<class T,unsigned Route> static T native_file_original(){
    static_assert(Route<NativeFileRoutes);
    const auto mock=native_file_private_targets.load(std::memory_order_acquire);
    return reinterpret_cast<T>(mock?mock->targets[Route]:native_file_originals[Route].load(std::memory_order_acquire));
}
static NativeFileScope native_file_scope_begin(const LoaderWindowCapture* window,bool active){
    NativeFileScope scope={};auto* packet=native_file_output;if(!packet)return scope;
    scope={native_file_collector,packet,true,false};native_file_collector={};
    packet->scopes=increment(packet->scopes);
    if(scope.previous.packet){packet->scope_reentry=increment(packet->scope_reentry);packet->incomplete=1;return scope;}
    if(!active||!window->packet||!window->start_valid||!window->window.dependency_sequence||!window->window.parent_listener_sequence||
       !window->window.started_qpc||window->window.started_qpc>=packet->cutoff_qpc||GetCurrentThreadId()!=packet->original_thread){
        packet->scope_unavailable=increment(packet->scope_unavailable);packet->incomplete=1;return scope;
    }
    native_file_collector={packet,window->window.dependency_sequence,window->window.parent_listener_sequence,window->window.started_qpc,packet->original_thread,false};
    scope.armed=true;return scope;
}
static void native_file_scope_end(const NativeFileScope& scope){
    if(!scope.managed)return;
    if(scope.armed&&((native_file_collector.packet!=scope.packet&&!native_file_collector.disarmed)||native_file_collector.inside)){
        scope.packet->unmatched_scope=increment(scope.packet->unmatched_scope);scope.packet->incomplete=1;
    }
    native_file_collector=scope.previous;
}
// POD-only SEH boundary: an original Ldr exception may be caught inside its
// caller. Restore only the new TLS scope, without catching/translating it or
// adding another invocation. Keeping this outside DependencyErrors avoids the
// MSVC restriction on SEH in a function with C++ unwind destructors.
static NTSTATUS native_file_ldr_forward(Load target,PWSTR search,PULONG flags,PUNICODE_STRING name,PHANDLE output,const LoaderWindowCapture* window,bool active){
    const auto incoming=errors();const auto scope=native_file_scope_begin(window,active);errors_restore(incoming);
    __try {return target(search,flags,name,output);}
    __finally {const auto outgoing=errors();if(AbnormalTermination()&&scope.packet)scope.packet->incomplete=1;native_file_scope_end(scope);errors_restore(outgoing);}
}
static bool native_file_begin(NativeFileRow* row,uint32_t operation,uint32_t route,ErrorPair incoming){
    auto& scope=native_file_collector;auto* packet=scope.packet;if(!packet)return false;
    if(observer_setup_active||scope.inside){packet->scope_reentry=increment(packet->scope_reentry);packet->incomplete=1;return false;}
    scope.inside=true;LARGE_INTEGER now={};const BOOL clock=native_file_clock(&now);
    if(!clock||now.QuadPart<=0||static_cast<uint64_t>(now.QuadPart)<scope.started){packet->clock_failures=increment(packet->clock_failures);packet->incomplete=1;scope.inside=false;scope.packet=nullptr;scope.disarmed=true;return false;}
    if(static_cast<uint64_t>(now.QuadPart)>=packet->cutoff_qpc){packet->late=increment(packet->late);packet->incomplete=1;scope.inside=false;scope.packet=nullptr;scope.disarmed=true;return false;}
    if(packet->total_calls==UINT32_MAX){packet->overflow=1;packet->incomplete=1;scope.inside=false;scope.packet=nullptr;scope.disarmed=true;return false;}
    uint32_t matched=UINT32_MAX;
    for(uint32_t index=0;index<packet->route_count&&index<NativeFileRoutes;++index){const auto& candidate=packet->routes[index];
        if(candidate.owner_index==route/2&&candidate.slot.operation==operation&&candidate.slot.published&&candidate.postvalidated){if(matched!=UINT32_MAX){matched=UINT32_MAX;break;}matched=index;}}
    if(matched==UINT32_MAX){packet->scope_unavailable=increment(packet->scope_unavailable);packet->incomplete=1;scope.inside=false;return false;}
    row->sequence=++packet->total_calls;row->operation=operation;row->route_index=matched;row->thread_id=GetCurrentThreadId();
    row->ldr_dependency_sequence=scope.ldr;row->parent_listener_sequence=scope.parent;row->started_qpc=static_cast<uint64_t>(now.QuadPart);
    row->incoming_win32=incoming.win32;row->incoming_wsa=incoming.wsa;row->entered=1;row->flags=1|8;
    if(row->thread_id==scope.thread)row->flags|=4;else packet->incomplete=1;
    return true;
}
static void native_file_input(NativeFileRow* row,POBJECT_ATTRIBUTES attributes,PLARGE_INTEGER allocation,PVOID ea){
    if(allocation){row->input_flags|=8;__try {row->allocation_size=static_cast<uint64_t>(allocation->QuadPart);row->input_flags|=16;}__except(EXCEPTION_EXECUTE_HANDLER){row->input_flags|=128;}}
    if(ea)row->input_flags|=32;
    __try {
        if(!attributes)return;row->input_flags|=1;const auto object=*attributes;row->oa_length=object.Length;
        if(row->oa_length!=sizeof(OBJECT_ATTRIBUTES)){row->input_flags|=64;return;}
        row->input_flags|=2;row->oa_attributes=object.Attributes;row->raw_root=reinterpret_cast<uintptr_t>(object.RootDirectory);
        if(!object.ObjectName)return;row->input_flags|=4;
        const auto counted=*object.ObjectName;row->reported_name_bytes=counted.Length;
        if(counted.Length%2||counted.Length>counted.MaximumLength||(!counted.Buffer&&counted.Length)){row->input_flags|=256;return;}
        const size_t units=counted.Length/sizeof(WCHAR),count=units<NativeFileNameUnits?units:NativeFileNameUnits;
        for(size_t index=0;index<count;++index){const auto unit=counted.Buffer[index];row->name[index]=unit;row->copied_name_units=static_cast<uint32_t>(index+1);if(!unit)row->name_flags|=8;}
        row->name_flags|=1;if(units>count)row->name_flags|=4;
    }__except(EXCEPTION_EXECUTE_HANDLER){row->input_flags|=128;row->name_flags|=2;}
}
static void native_file_finish(NativeFileRow* row,NativeFilePacket* packet,NTSTATUS status,ErrorPair outgoing,PHANDLE output){
    row->returned=1;row->native_status=status;row->outgoing_win32=outgoing.win32;row->outgoing_wsa=outgoing.wsa;
    row->output_flags=16; // IO_STATUS_BLOCK is deliberately never inspected.
    LARGE_INTEGER ended={};const BOOL clock=native_file_clock(&ended);
    const bool valid=clock&&ended.QuadPart>0&&static_cast<uint64_t>(ended.QuadPart)>=row->started_qpc;
    if(valid){row->finished_qpc=static_cast<uint64_t>(ended.QuadPart);row->flags|=2;}
    else{packet->clock_failures=increment(packet->clock_failures);packet->incomplete=1;}
    const bool within=valid&&row->finished_qpc<packet->cutoff_qpc;
    if(valid&&!within){row->flags|=32;packet->late=increment(packet->late);packet->incomplete=1;}
    if(native_file_collector.packet!=packet||native_file_collector.ldr!=row->ldr_dependency_sequence||native_file_collector.parent!=row->parent_listener_sequence){row->flags&=~8u;packet->unmatched_scope=increment(packet->unmatched_scope);packet->incomplete=1;}
    if(status==static_cast<NTSTATUS>(0x103)){row->flags|=64;row->output_flags|=8;}
    else if(status>=0&&within){__try {if(output){const auto returned=*output;row->raw_output=reinterpret_cast<uintptr_t>(returned);row->output_flags|=1;if(returned)row->output_flags|=2;}}__except(EXCEPTION_EXECUTE_HANDLER){row->output_flags|=4;}}
    else if(status>=0)row->output_flags|=32;
    const bool complete=within&&status!=static_cast<NTSTATUS>(0x103)&&(row->flags&(1|2|4|8))==(1|2|4|8)&&!(row->input_flags&(64|128|256))&&!(row->name_flags&(2|4))&&!(row->output_flags&4);
    if(complete)row->flags|=16;else packet->incomplete=1;
    if(row->input_flags&(64|128|256)||row->name_flags&(2|4))packet->input_failures=increment(packet->input_failures);
    if(status<0){packet->total_failures=increment(packet->total_failures);if(!packet->first_failure_present){packet->first_failure=*row;packet->first_failure_present=1;}}
    if(packet->record_count<NativeFileRows)packet->rows[packet->record_count++]=*row;
    else{for(size_t index=1;index<NativeFileRows;++index)packet->rows[index-1]=packet->rows[index];packet->rows[NativeFileRows-1]=*row;packet->dropped=increment(packet->dropped);packet->overflow=1;packet->incomplete=1;}
    native_file_collector.inside=false;if(!within){native_file_collector.packet=nullptr;native_file_collector.disarmed=true;}
}
template<unsigned Route> static NTSTATUS NTAPI native_create_file(PHANDLE output,ACCESS_MASK access,POBJECT_ATTRIBUTES attributes,PIO_STATUS_BLOCK io,PLARGE_INTEGER allocation,ULONG file_attributes,ULONG share,ULONG disposition,ULONG options,PVOID ea,ULONG ea_length){
    auto target=native_file_original<NativeCreateFile,Route>();if(!native_file_collector.packet)return target(output,access,attributes,io,allocation,file_attributes,share,disposition,options,ea,ea_length);
    const auto incoming=errors();NativeFileRow row={};const bool active=native_file_begin(&row,1,Route,incoming);auto* packet=native_file_collector.packet;
    if(active){row.desired_access=access;row.file_attributes=file_attributes;row.share_access=share;row.create_disposition=disposition;row.create_options=options;row.ea_length=ea_length;native_file_input(&row,attributes,allocation,ea);}
    errors_restore(incoming);const auto result=target(output,access,attributes,io,allocation,file_attributes,share,disposition,options,ea,ea_length);const auto outgoing=errors();
    if(active)native_file_finish(&row,packet,result,outgoing,output);errors_restore(outgoing);return result;
}
template<unsigned Route> static NTSTATUS NTAPI native_open_file(PHANDLE output,ACCESS_MASK access,POBJECT_ATTRIBUTES attributes,PIO_STATUS_BLOCK io,ULONG share,ULONG options){
    auto target=native_file_original<NativeOpenFile,Route>();if(!native_file_collector.packet)return target(output,access,attributes,io,share,options);
    const auto incoming=errors();NativeFileRow row={};const bool active=native_file_begin(&row,2,Route,incoming);auto* packet=native_file_collector.packet;
    if(active){row.desired_access=access;row.share_access=share;row.create_options=options;native_file_input(&row,attributes,nullptr,nullptr);}
    errors_restore(incoming);const auto result=target(output,access,attributes,io,share,options);const auto outgoing=errors();
    if(active)native_file_finish(&row,packet,result,outgoing,output);errors_restore(outgoing);return result;
}
static const Hook native_file_hooks[NativeFileOwners][2]={
    {{"NtCreateFile",reinterpret_cast<void*>(native_create_file<0>)},{"NtOpenFile",reinterpret_cast<void*>(native_open_file<1>)}},
    {{"NtCreateFile",reinterpret_cast<void*>(native_create_file<2>)},{"NtOpenFile",reinterpret_cast<void*>(native_open_file<3>)}}};

struct NativeFileCache {
    volatile LONG state;Image mapped;NativeFileOwner owner;WsaPacket proof;WsaNode targets[2];
    NativeFileRoute routes[2];uint32_t route_count;
};
static NativeFileCache native_file_cache[NativeFileOwners]={};
struct NativeFileDiscovery {ReturnedDiscovery base;uint32_t owner;uint32_t kinds[2];};
using NativeFileWritable=bool(*)(Page*,size_t,WsaPacket*);
static std::atomic<NativeFileWritable> native_file_private_writable{nullptr};
static BOOL CALLBACK native_file_import_file(void* context,HMODULE module,LPCSTR name){
    auto* state=static_cast<NativeFileDiscovery*>(context);
    return returned_import_file(&state->base,module,name);
}
static BOOL CALLBACK native_file_import_function(void* context,DWORD ordinal,LPCSTR name,void** slot){
    auto* native=static_cast<NativeFileDiscovery*>(context);auto* state=&native->base;auto* packet=state->packet;
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
        ++state->thunk_index;size_t typed=0;uint32_t kind=1;
        if(IMAGE_SNAP_BY_ORDINAL64(thunk)){
            kind=2;
            if(name||!ordinal||ordinal>UINT16_MAX||IMAGE_ORDINAL64(thunk)!=ordinal||(thunk&~(IMAGE_ORDINAL_FLAG64|UINT64_C(0xffff)))){state->error=ERROR_INVALID_DATA;return FALSE;}
            if(!state->descriptor){state->error=ERROR_MOD_NOT_FOUND;return FALSE;}
            void* exports[2]={};for(size_t operation=0;operation<2;++operation)exports[operation]=reinterpret_cast<void*>(GetProcAddress(state->descriptor,native_file_hooks[native->owner][operation].name));
            void* resolved=reinterpret_cast<void*>(GetProcAddress(state->descriptor,MAKEINTRESOURCEA(static_cast<WORD>(ordinal))));
            typed=typed_ordinal_operation(resolved,*slot,exports,2);
            if(!resolved||resolved!=*slot||typed>2){state->error=ERROR_INVALID_DATA;return FALSE;}
            if(!typed)return TRUE;
        }else if(ordinal||!name||thunk>UINT32_MAX||reinterpret_cast<uintptr_t>(name)!=state->image.base+static_cast<uint32_t>(thunk)+sizeof(WORD)||!bounded_name(name,state->image)){state->error=ERROR_INVALID_DATA;return FALSE;}
        for(size_t operation=0;operation<2;++operation){
            if(typed?typed!=operation+1:!equals(name,native_file_hooks[native->owner][operation].name,state->image))continue;
            for(size_t index=0;index<packet->slot_count;++index)if(packet->slots[index].operation==operation+1||packet->slots[index].slot==slot_address){state->error=ERROR_DUP_NAME;return FALSE;}
            if(packet->slot_count>=2){state->error=ERROR_BUFFER_OVERFLOW;return FALSE;}
            auto& selected=packet->slots[packet->slot_count++];selected.slot=slot_address;selected.operation=static_cast<uint32_t>(operation+1);selected.descriptor_module=reinterpret_cast<uintptr_t>(state->descriptor);selected.original=reinterpret_cast<uintptr_t>(*slot);
            native->kinds[operation]=kind;Page page={};HMODULE owner=nullptr;Image target_image={};
            if(!data_page(slot,state->image,&page)||!state->descriptor||GetProcAddress(state->descriptor,native_file_hooks[native->owner][operation].name)!=reinterpret_cast<FARPROC>(*slot)||
               !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(*slot),&owner)||!capture_node_data(owner,*slot,&state->targets[operation],&target_image,&packet->incomplete,false)){
                state->error=ERROR_NOT_SUPPORTED;return FALSE;
            }
            selected.hook=reinterpret_cast<uintptr_t>(native_file_hooks[native->owner][operation].target);
        }
        return TRUE;
    }__except(EXCEPTION_EXECUTE_HANDLER){state->error=ERROR_INVALID_ADDRESS;packet->incomplete=1;return FALSE;}
}
static bool native_file_node_live(const WsaNode& proof){
    WsaNode actual={};Image mapped={};uint32_t incomplete=0;
    if(!proof.entry||!capture_node_data(reinterpret_cast<HMODULE>(proof.owner_base),reinterpret_cast<void*>(proof.entry),&actual,&mapped,&incomplete,false)||
       actual.owner_size!=proof.owner_size||actual.timestamp!=proof.timestamp||actual.machine!=proof.machine||actual.entry_len!=proof.entry_len)return false;
    for(size_t index=0;index<proof.entry_len;++index)if(actual.entry_bytes[index]!=proof.entry_bytes[index])return false;
    return true;
}
static bool native_file_route_live(const NativeFileCache* cache,uint32_t owner_index){
    __try {
        Image mapped={};if(!native_file_node_live(cache->owner.identity)||!image(reinterpret_cast<HMODULE>(cache->mapped.base),&mapped,false)||
            mapped.base!=cache->mapped.base||mapped.size!=cache->mapped.size||mapped.timestamp!=cache->mapped.timestamp||mapped.machine!=cache->mapped.machine||
            mapped.imports!=cache->mapped.imports||mapped.imports_end!=cache->mapped.imports_end||mapped.iat!=cache->mapped.iat||mapped.iat_end!=cache->mapped.iat_end||cache->proof.slot_count>2)return false;
        for(size_t index=0;index<cache->proof.slot_count;++index){
            const auto& slot=cache->proof.slots[index];if(!slot.operation||slot.operation>2||!slot.hook)return false;
            const auto operation=slot.operation-1;Page page={};
            if(!native_file_node_live(cache->targets[operation])||slot.original!=cache->targets[operation].entry||slot.hook!=reinterpret_cast<uintptr_t>(native_file_hooks[owner_index][operation].target)||
               !data_page(reinterpret_cast<void**>(slot.slot),mapped,&page)||*reinterpret_cast<void**>(slot.slot)!=reinterpret_cast<void*>(slot.published?slot.hook:slot.original)||
               GetProcAddress(reinterpret_cast<HMODULE>(slot.descriptor_module),native_file_hooks[owner_index][operation].name)!=reinterpret_cast<FARPROC>(slot.original))return false;
            if(slot.published&&native_file_originals[owner_index*2+operation].load(std::memory_order_acquire)!=reinterpret_cast<void*>(slot.original))return false;
        }
        return true;
    }__except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
static bool native_file_publish(NativeFileCache* cache,uint32_t owner_index){
    auto* packet=&cache->proof;Page pages[2]={};size_t count=0;
    for(size_t index=0;index<packet->slot_count;++index){
        const auto& selected=packet->slots[index];Page page={};
        if(!selected.operation||selected.operation>2||!selected.hook||!data_page(reinterpret_cast<void**>(selected.slot),cache->mapped,&page)){failure(packet,5,ERROR_INVALID_ADDRESS);return false;}
        cache->routes[index].original_protection=page.original;
        bool present=false;for(size_t previous=0;previous<count;++previous)if(pages[previous].base==page.base)present=true;if(!present)pages[count++]=page;
        void* expected=nullptr;auto* original=reinterpret_cast<void*>(selected.original);
        if(!native_file_originals[owner_index*2+selected.operation-1].compare_exchange_strong(expected,original,std::memory_order_acq_rel,std::memory_order_acquire)&&expected!=original){failure(packet,5,ERROR_RETRY);return false;}
    }
    const auto private_writable=native_file_private_writable.load(std::memory_order_acquire);
    if(!(private_writable?private_writable(pages,count,packet):writable(pages,count,packet)))return false;
    bool success=native_file_route_live(cache,owner_index);if(!success)failure(packet,6,ERROR_RETRY);
    for(size_t index=0;success&&index<packet->slot_count;++index){
        auto& selected=packet->slots[index];
        if(!live(packet)||swap(reinterpret_cast<void**>(selected.slot),reinterpret_cast<void*>(selected.hook),reinterpret_cast<void*>(selected.original))!=reinterpret_cast<void*>(selected.original)){failure(packet,5,packet->setup_error?packet->setup_error:ERROR_RETRY);success=false;break;}
        selected.published=1;
    }
    if(!success)returned_rollback(packet);
    restore(pages,count,packet);
    if(success&&!native_file_route_live(cache,owner_index)){failure(packet,6,ERROR_RETRY);return false;}
    return success;
}
static void native_file_owner_prepare(NativeFilePacket* output,uint32_t index,void* anchor){
    auto& record=output->owners[index];record.role=index+1;record.shared_owner=UINT32_MAX;output->owner_count=index+1;
    if(!anchor){record.stage=3;record.error=ERROR_PROC_NOT_FOUND;output->incomplete=1;return;}
    auto* cache=&native_file_cache[index];const LONG state=InterlockedCompareExchange(&cache->state,1,0);
    if(state==2){
        record=cache->owner;
        if(record.flags&4)output->incomplete=1;
        if(record.identity.entry!=reinterpret_cast<uintptr_t>(anchor)||!native_file_route_live(cache,index)){record.stage=6;record.error=ERROR_RETRY;record.complete=0;output->incomplete=1;return;}
        for(uint32_t route=0;route<cache->route_count;++route)if(output->route_count<NativeFileRoutes)output->routes[output->route_count++]=cache->routes[route];
        return;
    }
    if(state!=0){record.stage=9;record.error=state==1?ERROR_BUSY:ERROR_NOT_SUPPORTED;output->incomplete=1;return;}
    auto* proof=&cache->proof;proof->version=1;proof->cutoff_qpc=output->cutoff_qpc;proof->frequency=output->frequency;
    bool success=false;HMODULE owner=nullptr;Image mapped={};
    do {
        if(!live(proof)){record.stage=2;record.error=proof->setup_error;break;}
        const auto resolved=GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(anchor),&owner);const auto error=resolved?ERROR_SUCCESS:GetLastError();
        if(!resolved||!capture_node_data(owner,anchor,&record.identity,&mapped,&proof->incomplete,false)){record.stage=3;record.error=resolved?ERROR_INVALID_ADDRESS:error;break;}
        cache->mapped=mapped;cache->owner=record;
        if(index&&output->owners[0].identity.owner_base==mapped.base&&output->owners[0].complete){
            if(!native_file_route_live(&native_file_cache[0],0)){record.stage=6;record.error=ERROR_RETRY;break;}
            record.flags|=1;record.shared_owner=0;record.complete=1;record.stage=1;success=true;break;
        }
        if(!mapped.imports&&!mapped.iat){record.flags|=2;record.complete=1;record.stage=1;success=true;break;}
        NativeFileDiscovery discovery={};discovery.owner=index;discovery.base.image=mapped;discovery.base.packet=proof;
        bool complete=returned_bounded_imports(&discovery.base);
        if(complete){SetLastError(ERROR_SUCCESS);complete=DetourEnumerateImportsEx(owner,&discovery,native_file_import_file,native_file_import_function)!=FALSE;const auto enumeration_error=GetLastError();if(!complete&&!discovery.base.error)discovery.base.error=enumeration_error?enumeration_error:ERROR_INVALID_DATA;}
        record.descriptor_count=proof->descriptor_count;record.function_count=proof->function_count;
        cache->route_count=proof->slot_count;
        for(uint32_t route=0;route<proof->slot_count&&route<2;++route){auto& item=cache->routes[route];item.slot=proof->slots[route];item.owner_index=index;item.thunk_kind=discovery.kinds[item.slot.operation-1];item.target=discovery.base.targets[item.slot.operation-1];cache->targets[item.slot.operation-1]=item.target;}
        if(!complete||!proof->callbacks_complete||discovery.base.error){record.stage=4;record.error=proof->setup_error?proof->setup_error:discovery.base.error?discovery.base.error:ERROR_INVALID_DATA;break;}
        if(!native_file_publish(cache,index)){record.stage=proof->setup_stage?proof->setup_stage:5;record.error=proof->setup_error?proof->setup_error:ERROR_RETRY;break;}
        record.complete=1;record.stage=1;success=true;
    }while(false);
    if(proof->incomplete){record.flags|=4;output->incomplete=1;}
    if(!success){output->incomplete=1;output->route_failures=increment(output->route_failures);}
    for(uint32_t route=0;route<cache->route_count&&route<2;++route){auto& item=cache->routes[route];item.slot=proof->slots[route];item.stage=success?1:record.stage;item.error=success?0:record.error;item.postvalidated=success?1:0;
        if(output->route_count<NativeFileRoutes)output->routes[output->route_count++]=item;else{output->overflow=1;output->incomplete=1;}}
    cache->owner=record;InterlockedExchange(&cache->state,success?2:3);
}
static void native_file_prepare(ListenerPacket* listener,void* owner,void* ldr){
    auto* output=native_file_output;if(!output)return;const auto saved=errors();
    output->attempts=increment(output->attempts);
    if(output->attempts!=1){output->incomplete=1;output->scope_unavailable=increment(output->scope_unavailable);errors_restore(saved);return;}
    if(listener->cutoff_qpc!=output->cutoff_qpc||listener->frequency!=output->frequency||listener->original_thread!=output->original_thread){output->incomplete=1;output->unmatched_scope=increment(output->unmatched_scope);errors_restore(saved);return;}
    native_file_owner_prepare(output,0,owner);native_file_owner_prepare(output,1,ldr);errors_restore(saved);
}

struct NativeFileMock {
    std::atomic<uint32_t> create_calls,open_calls,ldr_calls;std::atomic<bool> same;
    PHANDLE output;POBJECT_ATTRIBUTES attributes;PIO_STATUS_BLOCK io;PLARGE_INTEGER allocation;PVOID ea;
    ErrorPair incoming,outgoing;NTSTATUS status;bool recurse,late;
    uint64_t cutoff;std::atomic<uint32_t> clock_mode;
};
static std::atomic<NativeFileMock*> native_file_mock{nullptr};
static NTSTATUS NTAPI native_file_mock_ldr_fault(PWSTR,PULONG,PUNICODE_STRING,PHANDLE){
    ++native_file_mock.load(std::memory_order_acquire)->ldr_calls;
    RaiseException(0xE04D4301u,0,0,nullptr);return 0;
}
static bool native_file_mock_unwind(const LoaderWindowCapture* window){
    const auto previous=native_file_collector;bool caught=false;
    __try {native_file_ldr_forward(native_file_mock_ldr_fault,nullptr,nullptr,nullptr,nullptr,window,true);}
    __except(GetExceptionCode()==0xE04D4301u?EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH){caught=true;}
    const auto current=native_file_collector;
    return caught&&current.packet==previous.packet&&current.ldr==previous.ldr&&current.parent==previous.parent&&current.started==previous.started&&current.thread==previous.thread&&current.inside==previous.inside&&current.disarmed==previous.disarmed;
}
static BOOL native_file_mock_clock(LARGE_INTEGER* now){
    auto* state=native_file_mock.load(std::memory_order_acquire);const auto mode=state->clock_mode.load();
    if(mode==1){SetLastError(ERROR_INVALID_DATA);return FALSE;}
    if(mode==2){now->QuadPart=static_cast<LONGLONG>(state->cutoff);return TRUE;}
    return QueryPerformanceCounter(now);
}
static bool native_file_same_errors(ErrorPair left,ErrorPair right){return left.win32==right.win32&&left.wsa==right.wsa;}
static NTSTATUS NTAPI native_file_mock_open(PHANDLE output,ACCESS_MASK access,POBJECT_ATTRIBUTES attributes,PIO_STATUS_BLOCK io,ULONG share,ULONG options){
    auto* state=native_file_mock.load(std::memory_order_acquire);++state->open_calls;
    if(output!=state->output||access!=0x123||attributes!=state->attributes||io!=state->io||share!=7||options!=0x456||!native_file_same_errors(errors(),state->incoming))state->same=false;
    if(state->status>=0&&state->status!=static_cast<NTSTATUS>(0x103)&&output)*output=reinterpret_cast<HANDLE>(0xABCD);
    if(state->late)state->clock_mode=2;errors_restore(state->outgoing);return state->status;
}
static NTSTATUS NTAPI native_file_mock_create(PHANDLE output,ACCESS_MASK access,POBJECT_ATTRIBUTES attributes,PIO_STATUS_BLOCK io,PLARGE_INTEGER allocation,ULONG file_attributes,ULONG share,ULONG disposition,ULONG options,PVOID ea,ULONG ea_length){
    auto* state=native_file_mock.load(std::memory_order_acquire);++state->create_calls;
    if(output!=state->output||access!=0x123||attributes!=state->attributes||io!=state->io||allocation!=state->allocation||file_attributes!=0x20||share!=7||disposition!=1||options!=0x456||ea!=state->ea||ea_length!=13||!native_file_same_errors(errors(),state->incoming))state->same=false;
    if(state->recurse){const auto saved=errors();native_open_file<1>(output,access,attributes,io,share,options);errors_restore(saved);}
    if(state->status>=0&&state->status!=static_cast<NTSTATUS>(0x103)&&output)*output=reinterpret_cast<HANDLE>(0xABCD);
    if(state->late)state->clock_mode=2;errors_restore(state->outgoing);return state->status;
}
static DWORD WINAPI native_file_mock_foreign(void* context){
    auto* state=static_cast<NativeFileMock*>(context);errors_restore(state->incoming);
    if(native_open_file<1>(state->output,0x123,state->attributes,state->io,7,0x456)!=state->status||!native_file_same_errors(errors(),state->outgoing))state->same=false;
    return 0;
}
static void native_file_mock_packet(NativeFilePacket* packet,uint64_t cutoff,uint64_t frequency){
    *packet={};packet->version=1;packet->packet_bytes=sizeof(*packet);packet->cutoff_qpc=cutoff;packet->frequency=frequency;packet->original_thread=GetCurrentThreadId();
    packet->owner_count=1;packet->route_count=2;
    for(uint32_t operation=0;operation<2;++operation){auto& route=packet->routes[operation];route.owner_index=0;route.slot.operation=operation+1;route.slot.published=1;route.postvalidated=1;}
}
static LoaderWindowCapture native_file_mock_window(ListenerPacket* listener){
    LARGE_INTEGER now={};QueryPerformanceCounter(&now);LoaderWindowCapture window={};window.packet=listener;window.start_valid=true;
    window.window={11,22,33,static_cast<uint64_t>(now.QuadPart),0};return window;
}
struct NativeFileMockGuard {
    NativeFilePacket* output;NativeFileCollector collector;ErrorPair errors;
    const NativeFilePrivateTargets* targets;LoaderWindowClock clock;NativeFileWritable writable;
    ~NativeFileMockGuard(){native_file_private_targets.store(targets,std::memory_order_release);native_file_private_clock.store(clock,std::memory_order_release);native_file_private_writable.store(writable,std::memory_order_release);native_file_mock.store(nullptr,std::memory_order_release);native_file_output=output;native_file_collector=collector;errors_restore(errors);}
};
static bool native_file_mock_not_writable(Page*,size_t,WsaPacket* packet){failure(packet,5,ERROR_ACCESS_DENIED);return false;}
static bool native_file_system_inventory(void* anchor,uint64_t cutoff,uint64_t frequency){
    if(!anchor)return false;HMODULE owner=nullptr;WsaNode node={};Image mapped={};WsaPacket packet={};
    packet.cutoff_qpc=cutoff;packet.frequency=frequency;
    if(!live(&packet))return false;
    if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(anchor),&owner)||!capture_node_data(owner,anchor,&node,&mapped,&packet.incomplete,false))return false;
    if(!mapped.imports&&!mapped.iat)return true; // Verified empty normal route inventory.
    NativeFileDiscovery discovery={};discovery.owner=1;discovery.base.image=mapped;discovery.base.packet=&packet;
    bool complete=returned_bounded_imports(&discovery.base);
    if(complete){SetLastError(0);complete=DetourEnumerateImportsEx(owner,&discovery,native_file_import_file,native_file_import_function)!=FALSE;const auto error=GetLastError();if(!complete&&!discovery.base.error)discovery.base.error=error?error:ERROR_INVALID_DATA;}
    // A system's malformed/unsupported inventory is explicitly unavailable,
    // never a failed original workload or proof that native opens were absent.
    if(!complete||discovery.base.error)return discovery.base.error!=0||packet.setup_error!=0;
    if(!packet.callbacks_complete||packet.slot_count>2)return false;
    for(uint32_t index=0;index<packet.slot_count;++index){const auto& slot=packet.slots[index];
        if(!slot.operation||slot.operation>2||!slot.hook||slot.published||!native_file_node_live(discovery.base.targets[slot.operation-1]))return false;}
    return true;
}
// These normal imports exist solely for the selected native selfcheck. Their
// two read-only invalid-name calls never run in the original workload path.
static_assert(std::is_same_v<decltype(&NtCreateFile),NativeCreateFile>,"NtCreateFile exact forwarding ABI");
static_assert(std::is_same_v<decltype(&NtOpenFile),NativeOpenFile>,"NtOpenFile exact forwarding ABI");
static __declspec(noinline) NTSTATUS native_file_direct_open(PHANDLE output,POBJECT_ATTRIBUTES attributes,PIO_STATUS_BLOCK io){return NtOpenFile(output,FILE_READ_ATTRIBUTES,attributes,io,7,0);}
static __declspec(noinline) NTSTATUS native_file_direct_create(PHANDLE output,POBJECT_ATTRIBUTES attributes,PIO_STATUS_BLOCK io){return NtCreateFile(output,FILE_READ_ATTRIBUTES,attributes,io,nullptr,0,7,1,0,nullptr,0);}
extern "C" uint32_t memcordon_native_file_trace_mock(uint64_t cutoff,uint64_t frequency){
    NativeFileMock state={};state.create_calls=0;state.open_calls=0;state.ldr_calls=0;state.clock_mode=0;state.same=true;state.incoming={0x1234,0x1234};state.outgoing={0x5678,0x5678};state.status=static_cast<NTSTATUS>(0xC0000022u);state.cutoff=cutoff;
    NativeFileMock* expected=nullptr;if(!native_file_mock.compare_exchange_strong(expected,&state,std::memory_order_acq_rel))return 1;
    NativeFileMockGuard guard={native_file_output,native_file_collector,errors(),native_file_private_targets.load(),native_file_private_clock.load(),native_file_private_writable.load()};
    const NativeFilePrivateTargets targets={{reinterpret_cast<void*>(native_file_mock_create),reinterpret_cast<void*>(native_file_mock_open),reinterpret_cast<void*>(native_file_mock_create),reinterpret_cast<void*>(native_file_mock_open)}};
    native_file_private_targets.store(&targets,std::memory_order_release);native_file_private_clock.store(native_file_mock_clock,std::memory_order_release);
    HANDLE output=nullptr;LARGE_INTEGER allocation={};allocation.QuadPart=4096;WCHAR text[]={L'a',0,L'b'};UNICODE_STRING name={sizeof(text),sizeof(text),text};
    OBJECT_ATTRIBUTES attributes={sizeof(OBJECT_ATTRIBUTES),reinterpret_cast<HANDLE>(0x7788),&name,0x40,nullptr,nullptr};
    state.output=&output;state.attributes=&attributes;state.io=reinterpret_cast<PIO_STATUS_BLOCK>(1);state.allocation=&allocation;state.ea=reinterpret_cast<void*>(2);
    NativeFilePacket packet={};ListenerPacket listener={};native_file_mock_packet(&packet,cutoff,frequency);native_file_output=&packet;native_file_collector={};
    auto window=native_file_mock_window(&listener);auto scope=native_file_scope_begin(&window,true);
    errors_restore(state.incoming);if(native_create_file<0>(&output,0x123,&attributes,state.io,&allocation,0x20,7,1,0x456,state.ea,13)!=state.status||!native_file_same_errors(errors(),state.outgoing))return 2;
    if(!state.same||state.create_calls!=1||packet.record_count!=1||!packet.first_failure_present||packet.rows[0].copied_name_units!=3||packet.rows[0].name_flags!=9||packet.rows[0].raw_root!=0x7788||packet.rows[0].desired_access!=0x123||packet.rows[0].output_flags!=16||packet.rows[0].allocation_size!=4096)return 3;
    errors_restore(state.incoming);if(native_open_file<1>(&output,0x123,&attributes,state.io,7,0x456)!=state.status||state.open_calls!=1||!state.same||packet.rows[1].operation!=2||packet.rows[1].ea_length||packet.rows[1].input_flags&(8|16|32))return 4;
    const auto calls=packet.total_calls;HANDLE thread=CreateThread(nullptr,0,native_file_mock_foreign,&state,0,nullptr);if(!thread)return 5;
    LARGE_INTEGER now={};QueryPerformanceCounter(&now);const uint64_t remaining=now.QuadPart>0&&static_cast<uint64_t>(now.QuadPart)<cutoff?cutoff-static_cast<uint64_t>(now.QuadPart):0;
    const DWORD wait=frequency&&remaining<UINT64_MAX/1000?static_cast<DWORD>((remaining*1000/frequency)<MAXDWORD?(remaining*1000/frequency):MAXDWORD-1):0;
    const DWORD joined=WaitForSingleObject(thread,wait);CloseHandle(thread);if(joined!=WAIT_OBJECT_0)__fastfail(FAST_FAIL_FATAL_APP_EXIT);
    if(!state.same||packet.total_calls!=calls)return 6;
    auto nested=native_file_scope_begin(&window,true);errors_restore(state.incoming);native_open_file<1>(&output,0x123,&attributes,state.io,7,0x456);native_file_scope_end(nested);
    if(native_file_collector.packet!=&packet||packet.total_calls!=calls||!packet.scope_reentry)return 7;
    const auto enclosing=native_file_collector;native_file_collector={};packet.incomplete=0;
    const bool unwound=native_file_mock_unwind(&window);const bool partial=packet.incomplete!=0;native_file_collector=enclosing;
    if(!unwound||!partial||state.ldr_calls!=1)return 33;
    state.recurse=true;errors_restore(state.incoming);native_create_file<0>(&output,0x123,&attributes,state.io,&allocation,0x20,7,1,0x456,state.ea,13);state.recurse=false;
    if(packet.total_calls!=calls+1||!state.same)return 8;
    WCHAR long_name[NativeFileNameUnits+1]={};for(auto& unit:long_name)unit=L'x';UNICODE_STRING long_counted={sizeof(long_name),sizeof(long_name),long_name};attributes.ObjectName=&long_counted;
    errors_restore(state.incoming);native_open_file<1>(&output,0x123,&attributes,state.io,7,0x456);
    if(packet.rows[packet.record_count-1].copied_name_units!=NativeFileNameUnits||!(packet.rows[packet.record_count-1].name_flags&4))return 9;
    UNICODE_STRING odd_name={3,3,text};attributes.ObjectName=&odd_name;
    errors_restore(state.incoming);native_open_file<1>(&output,0x123,&attributes,state.io,7,0x456);
    if(!(packet.rows[packet.record_count-1].input_flags&256))return 29;
    attributes.ObjectName=&name;state.allocation=reinterpret_cast<PLARGE_INTEGER>(1);
    errors_restore(state.incoming);native_create_file<0>(&output,0x123,&attributes,state.io,state.allocation,0x20,7,1,0x456,state.ea,13);
    if(!(packet.rows[packet.record_count-1].input_flags&128)||(packet.rows[packet.record_count-1].input_flags&16))return 30;
    state.allocation=&allocation;
    state.attributes=reinterpret_cast<POBJECT_ATTRIBUTES>(1);errors_restore(state.incoming);native_open_file<1>(&output,0x123,state.attributes,state.io,7,0x456);
    if(!(packet.rows[packet.record_count-1].input_flags&128))return 10;state.attributes=&attributes;attributes.ObjectName=&name;
    state.output=reinterpret_cast<PHANDLE>(1);errors_restore(state.incoming);native_open_file<1>(state.output,0x123,&attributes,state.io,7,0x456);
    if(packet.rows[packet.record_count-1].output_flags!=16)return 11;
    state.status=static_cast<NTSTATUS>(0x103);errors_restore(state.incoming);native_open_file<1>(state.output,0x123,&attributes,state.io,7,0x456);
    if(packet.rows[packet.record_count-1].output_flags!=(16|8)||!(packet.rows[packet.record_count-1].flags&64))return 12;
    state.status=0;state.output=&output;errors_restore(state.incoming);native_open_file<1>(&output,0x123,&attributes,state.io,7,0x456);
    if(packet.rows[packet.record_count-1].raw_output!=0xABCD||packet.rows[packet.record_count-1].output_flags!=(16|1|2))return 13;
    state.status=static_cast<NTSTATUS>(0xC0000022u);
    for(size_t index=0;index<NativeFileRows+1;++index){errors_restore(state.incoming);native_open_file<1>(&output,0x123,&attributes,state.io,7,0x456);}
    if(packet.record_count!=NativeFileRows||!packet.dropped||packet.first_failure.sequence!=1||packet.first_failure.name[2]!=L'b')return 14;
    packet.routes[1].postvalidated=0;const auto covered=packet.total_calls;const auto forwarded=state.open_calls.load();
    errors_restore(state.incoming);native_open_file<1>(&output,0x123,&attributes,state.io,7,0x456);
    if(packet.total_calls!=covered||state.open_calls!=forwarded+1||!packet.scope_unavailable||!native_file_same_errors(errors(),state.outgoing))return 31;
    packet.routes[1].postvalidated=1;
    native_file_scope_end(scope);native_file_mock_packet(&packet,cutoff,frequency);native_file_output=&packet;scope=native_file_scope_begin(&window,true);
    state.late=true;state.status=0;errors_restore(state.incoming);native_open_file<1>(&output,0x123,&attributes,state.io,7,0x456);
    if(packet.record_count!=1||!(packet.rows[0].flags&32)||packet.rows[0].output_flags!=(16|32)||!native_file_same_errors(errors(),state.outgoing))return 15;
    native_file_scope_end(scope);state.late=false;state.clock_mode=2;native_file_mock_packet(&packet,cutoff,frequency);scope=native_file_scope_begin(&window,true);
    const auto before=state.open_calls.load();errors_restore(state.incoming);native_open_file<1>(&output,0x123,&attributes,state.io,7,0x456);
    if(packet.record_count||packet.total_calls||state.open_calls!=before+1||!packet.late||!native_file_same_errors(errors(),state.outgoing))return 16;
    native_file_scope_end(scope);state.clock_mode=1;native_file_mock_packet(&packet,cutoff,frequency);scope=native_file_scope_begin(&window,true);errors_restore(state.incoming);native_open_file<1>(&output,0x123,&attributes,state.io,7,0x456);
    if(packet.record_count||!packet.clock_failures||!native_file_same_errors(errors(),state.outgoing))return 17;
    native_file_scope_end(scope);native_file_private_targets.store(nullptr,std::memory_order_release);native_file_private_clock.store(nullptr,std::memory_order_release);native_file_collector={};
    // Real admitted normal IAT routes in this owned fixture image. This is a
    // separate test of publication; it makes no claim about system-loader use.
    native_file_mock_packet(&packet,cutoff,frequency);packet.route_count=0;packet.owner_count=0;
    {ObserverSetup setup;native_file_owner_prepare(&packet,0,reinterpret_cast<void*>(&memcordon_native_file_trace_mock));}
    if(!packet.owners[0].complete||packet.route_count!=2||!native_file_route_live(&native_file_cache[0],0))return 18;
    native_file_output=&packet;window=native_file_mock_window(&listener);scope=native_file_scope_begin(&window,true);
    IO_STATUS_BLOCK io={};UNICODE_STRING empty={};OBJECT_ATTRIBUTES empty_attributes={sizeof(OBJECT_ATTRIBUTES),nullptr,&empty,0,nullptr,nullptr};HANDLE real_output=nullptr;
    const auto opened=native_file_direct_open(&real_output,&empty_attributes,&io);
    if(opened>=0){if(real_output)CloseHandle(real_output);return 19;}
    const auto created=native_file_direct_create(&real_output,&empty_attributes,&io);
    if(created>=0){if(real_output)CloseHandle(real_output);return 20;}
    native_file_scope_end(scope);
    if(packet.total_calls!=2||packet.record_count!=2||packet.total_failures!=2||!packet.first_failure_present)return 21;
    // Mutated slots/target bytes are refused by the same pre-publication proof.
    auto altered=native_file_cache[0].targets[0];native_file_cache[0].targets[0].entry_bytes[0]^=1;
    const bool accepted=native_file_route_live(&native_file_cache[0],0);native_file_cache[0].targets[0]=altered;
    if(accepted||!native_file_route_live(&native_file_cache[0],0))return 22;
    NativeFileCache denied=native_file_cache[0];denied.proof.setup_error=0;
    native_file_private_writable.store(native_file_mock_not_writable,std::memory_order_release);
    const bool published=native_file_publish(&denied,0);native_file_private_writable.store(nullptr,std::memory_order_release);
    if(published||denied.proof.setup_error!=ERROR_ACCESS_DENIED||!native_file_route_live(&native_file_cache[0],0))return 23;
    auto& selected=native_file_cache[0].proof.slots[0];Page page={};
    if(!data_page(reinterpret_cast<void**>(selected.slot),native_file_cache[0].mapped,&page))return 24;
    DWORD previous=0;if(!VirtualProtect(page.base,page.size,PAGE_READWRITE,&previous))return 25;
    if(swap(reinterpret_cast<void**>(selected.slot),reinterpret_cast<void*>(selected.original),reinterpret_cast<void*>(selected.hook))!=reinterpret_cast<void*>(selected.hook))__fastfail(FAST_FAIL_FATAL_APP_EXIT);
    const bool stale_accepted=native_file_route_live(&native_file_cache[0],0);
    if(swap(reinterpret_cast<void**>(selected.slot),reinterpret_cast<void*>(selected.hook),reinterpret_cast<void*>(selected.original))!=reinterpret_cast<void*>(selected.original))__fastfail(FAST_FAIL_FATAL_APP_EXIT);
    DWORD restored=0;if(!VirtualProtect(page.base,page.size,previous,&restored)||restored!=PAGE_READWRITE)__fastfail(FAST_FAIL_FATAL_APP_EXIT);
    if(stale_accepted||!native_file_route_live(&native_file_cache[0],0))return 26;
    WsaPacket duplicate={};duplicate.cutoff_qpc=cutoff;duplicate.frequency=frequency;duplicate.slot_count=1;duplicate.slots[0]=selected;
    NativeFileDiscovery duplicated={};duplicated.owner=0;duplicated.base.image=native_file_cache[0].mapped;duplicated.base.packet=&duplicate;
    if(!returned_bounded_imports(&duplicated.base))return 32;
    DetourEnumerateImportsEx(reinterpret_cast<HMODULE>(duplicated.base.image.base),&duplicated,native_file_import_file,native_file_import_function);
    if(duplicated.base.error!=ERROR_DUP_NAME||!native_file_route_live(&native_file_cache[0],0))return 32;
    const auto ntdll=GetModuleHandleW(L"ntdll.dll");
    const auto ldr=ntdll?GetProcAddress(ntdll,"LdrLoadDll"):nullptr;
    if(!native_file_system_inventory(reinterpret_cast<void*>(&LoadLibraryExW),cutoff,frequency)||!native_file_system_inventory(reinterpret_cast<void*>(ldr),cutoff,frequency))return 27;
    return state.same?0:28;
}
