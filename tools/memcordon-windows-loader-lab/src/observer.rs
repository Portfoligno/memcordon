use memcordon_windows_loader_lab::scenario::{DiagnosticObserverV1, ObserverEvidenceV1};
use std::{
    ffi::c_void,
    mem::offset_of,
    ptr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread::JoinHandle,
};
use windows_sys::{
    Win32::{
        Foundation::{DBG_CONTINUE, ERROR_SEM_TIMEOUT, HANDLE},
        System::Diagnostics::{
            Debug::{
                ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcess, DebugActiveProcessStop,
                DebugSetProcessKillOnExit, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
                LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, ReadProcessMemory,
                UNLOAD_DLL_DEBUG_EVENT, WaitForDebugEventEx, WriteProcessMemory,
            },
            Etw::{
                CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
                EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
                PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
                ProcessTrace, StartTraceW, TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
            },
        },
    },
    core::GUID,
};

const DEBUG_WAIT_MILLIS: u32 = 20;
const SESSION_NAME_CAPACITY: usize = 128;
const FULL_DEBUG_EVENT_CAPACITY: usize = 256;
static KERNEL_PROCESS_PROVIDER: GUID = GUID {
    data1: 0x22fb2cd6,
    data2: 0x0e7b,
    data3: 0x422b,
    data4: [0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16],
};

pub(crate) enum ObserverLease {
    Debug(DebugObserver),
    Etw(Box<EtwObserver>),
}

impl ObserverLease {
    pub(crate) fn start(
        observer: &DiagnosticObserverV1,
        process: HANDLE,
        process_id: u32,
        namespace: &str,
    ) -> Result<Option<Self>, &'static str> {
        match observer {
            DiagnosticObserverV1::None => Ok(None),
            DiagnosticObserverV1::DebugEventPump | DiagnosticObserverV1::FullDebugger => {
                DebugObserver::start(observer.clone(), process_id)
                    .map(|value| Some(Self::Debug(value)))
            }
            DiagnosticObserverV1::LoaderSnaps => {
                enable_loader_snaps(process)?;
                DebugObserver::start(observer.clone(), process_id)
                    .map(|value| Some(Self::Debug(value)))
            }
            DiagnosticObserverV1::PassiveEtw => EtwObserver::start(namespace, process_id)
                .map(|value| Some(Self::Etw(Box::new(value)))),
            DiagnosticObserverV1::ExternalProcmon | DiagnosticObserverV1::ExternalWpr => {
                Err("external-observer-cannot-run-in-process")
            }
        }
    }

    pub(crate) fn finish(self) -> Result<ObserverEvidenceV1, &'static str> {
        match self {
            Self::Debug(value) => value.finish(),
            Self::Etw(value) => (*value).finish(),
        }
    }
}

pub(crate) struct DebugObserver {
    kind: DiagnosticObserverV1,
    worker: JoinHandle<Result<DebugEvidence, &'static str>>,
}

struct DebugEvidence {
    event_count: u64,
    output_debug_string_count: u64,
    module_event_count: u64,
    exception_event_count: u64,
    event_codes: Vec<u32>,
}

impl DebugObserver {
    fn start(kind: DiagnosticObserverV1, process_id: u32) -> Result<Self, &'static str> {
        if unsafe { DebugActiveProcess(process_id) } == 0 {
            return Err("debug-attach-failed");
        }
        if unsafe { DebugSetProcessKillOnExit(0) } == 0 {
            unsafe { DebugActiveProcessStop(process_id) };
            return Err("debug-kill-on-exit-policy-failed");
        }
        let worker_kind = kind.clone();
        let worker = std::thread::Builder::new()
            .name(String::from("memcordon-loader-lab-debug-pump"))
            .spawn(move || {
                let mut events = 0_u64;
                let mut output_strings = 0_u64;
                let mut modules = 0_u64;
                let mut exceptions = 0_u64;
                let mut event_codes = Vec::new();
                loop {
                    let mut event = DEBUG_EVENT::default();
                    if unsafe { WaitForDebugEventEx(&raw mut event, DEBUG_WAIT_MILLIS) } == 0 {
                        if std::io::Error::last_os_error().raw_os_error()
                            == Some(ERROR_SEM_TIMEOUT as i32)
                        {
                            continue;
                        }
                        unsafe { DebugActiveProcessStop(process_id) };
                        return Err("debug-event-wait-failed");
                    }
                    events = events.checked_add(1).ok_or("debug-event-count-overflow")?;
                    if event.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT {
                        output_strings = output_strings
                            .checked_add(1)
                            .ok_or("debug-output-count-overflow")?;
                    }
                    if matches!(
                        event.dwDebugEventCode,
                        LOAD_DLL_DEBUG_EVENT | UNLOAD_DLL_DEBUG_EVENT
                    ) {
                        modules = modules
                            .checked_add(1)
                            .ok_or("debug-module-count-overflow")?;
                    }
                    if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                        exceptions = exceptions
                            .checked_add(1)
                            .ok_or("debug-exception-count-overflow")?;
                    }
                    if worker_kind == DiagnosticObserverV1::FullDebugger
                        && event_codes.len() < FULL_DEBUG_EVENT_CAPACITY
                    {
                        event_codes.push(event.dwDebugEventCode);
                    }
                    let exited = event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT
                        && event.dwProcessId == process_id;
                    if unsafe {
                        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE)
                    } == 0
                    {
                        unsafe { DebugActiveProcessStop(process_id) };
                        return Err("debug-event-continue-failed");
                    }
                    if exited {
                        break;
                    }
                }
                Ok(DebugEvidence {
                    event_count: events,
                    output_debug_string_count: output_strings,
                    module_event_count: modules,
                    exception_event_count: exceptions,
                    event_codes,
                })
            });
        let worker = match worker {
            Ok(worker) => worker,
            Err(_) => {
                unsafe { DebugActiveProcessStop(process_id) };
                return Err("debug-pump-thread-start-failed");
            }
        };
        Ok(Self { kind, worker })
    }

    fn finish(self) -> Result<ObserverEvidenceV1, &'static str> {
        let evidence = self
            .worker
            .join()
            .map_err(|_| "debug-pump-thread-panicked")??;
        Ok(ObserverEvidenceV1 {
            kind: self.kind,
            completed: true,
            stable_code: None,
            event_count: evidence.event_count,
            output_debug_string_count: evidence.output_debug_string_count,
            module_event_count: evidence.module_event_count,
            exception_event_count: evidence.exception_event_count,
            event_codes: evidence.event_codes,
            session_started: false,
            provider_enabled: false,
            cleanup_complete: true,
        })
    }
}

#[repr(C)]
struct TracePropertiesBuffer {
    properties: EVENT_TRACE_PROPERTIES,
    logger_name: [u16; SESSION_NAME_CAPACITY],
}

pub(crate) struct EtwObserver {
    handle: CONTROLTRACE_HANDLE,
    properties: TracePropertiesBuffer,
    processing: PROCESSTRACE_HANDLE,
    worker: JoinHandle<u32>,
    context: Arc<EtwContext>,
}

struct EtwContext {
    process_id: u32,
    events: AtomicU64,
}

unsafe extern "system" fn etw_event(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let context = unsafe { (*record).UserContext.cast::<EtwContext>().as_ref() };
    if let Some(context) = context {
        if unsafe { (*record).EventHeader.ProcessId } == context.process_id {
            context.events.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl EtwObserver {
    fn start(namespace: &str, process_id: u32) -> Result<Self, &'static str> {
        let mut name = namespace.encode_utf16().collect::<Vec<_>>();
        if name.is_empty() || name.len() >= SESSION_NAME_CAPACITY {
            return Err("etw-session-name-invalid");
        }
        name.push(0);
        let mut properties = TracePropertiesBuffer {
            properties: EVENT_TRACE_PROPERTIES::default(),
            logger_name: [0; SESSION_NAME_CAPACITY],
        };
        properties.logger_name[..name.len()].copy_from_slice(&name);
        properties.properties.Wnode.BufferSize =
            std::mem::size_of::<TracePropertiesBuffer>() as u32;
        properties.properties.Wnode.ClientContext = 1;
        properties.properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties.properties.BufferSize = 64;
        properties.properties.MinimumBuffers = 2;
        properties.properties.MaximumBuffers = 16;
        properties.properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        properties.properties.FlushTimer = 1;
        properties.properties.LoggerNameOffset =
            offset_of!(TracePropertiesBuffer, logger_name) as u32;
        let mut handle = CONTROLTRACE_HANDLE::default();
        if unsafe {
            StartTraceW(
                &raw mut handle,
                name.as_ptr(),
                &raw mut properties.properties,
            )
        } != 0
        {
            return Err("etw-session-start-failed");
        }
        if unsafe {
            EnableTraceEx2(
                handle,
                &raw const KERNEL_PROCESS_PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_VERBOSE as u8,
                u64::MAX,
                0,
                0,
                ptr::null(),
            )
        } != 0
        {
            unsafe {
                ControlTraceW(
                    handle,
                    ptr::null(),
                    &raw mut properties.properties,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            return Err("etw-provider-enable-failed");
        }
        let context = Arc::new(EtwContext {
            process_id,
            events: AtomicU64::new(0),
        });
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: name.as_mut_ptr(),
            Context: Arc::as_ptr(&context).cast_mut().cast::<c_void>(),
            ..EVENT_TRACE_LOGFILEW::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
        logfile.Anonymous2.EventRecordCallback = Some(etw_event);
        let processing = unsafe { OpenTraceW(&raw mut logfile) };
        if processing.Value == u64::MAX {
            unsafe {
                EnableTraceEx2(
                    handle,
                    &raw const KERNEL_PROCESS_PROVIDER,
                    EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                    0,
                    0,
                    0,
                    0,
                    ptr::null(),
                );
                ControlTraceW(
                    handle,
                    ptr::null(),
                    &raw mut properties.properties,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            return Err("etw-consumer-open-failed");
        }
        let worker = std::thread::Builder::new()
            .name(String::from("memcordon-loader-lab-etw-consumer"))
            .spawn(move || unsafe {
                ProcessTrace(&raw const processing, 1, ptr::null(), ptr::null())
            });
        let worker = match worker {
            Ok(worker) => worker,
            Err(_) => {
                unsafe {
                    CloseTrace(processing);
                    EnableTraceEx2(
                        handle,
                        &raw const KERNEL_PROCESS_PROVIDER,
                        EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                        0,
                        0,
                        0,
                        0,
                        ptr::null(),
                    );
                    ControlTraceW(
                        handle,
                        ptr::null(),
                        &raw mut properties.properties,
                        EVENT_TRACE_CONTROL_STOP,
                    );
                }
                return Err("etw-consumer-thread-start-failed");
            }
        };
        Ok(Self {
            handle,
            properties,
            processing,
            worker,
            context,
        })
    }

    fn finish(mut self) -> Result<ObserverEvidenceV1, &'static str> {
        let disable = unsafe {
            EnableTraceEx2(
                self.handle,
                &raw const KERNEL_PROCESS_PROVIDER,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                0,
                0,
                0,
                0,
                ptr::null(),
            )
        };
        let stop = unsafe {
            ControlTraceW(
                self.handle,
                ptr::null(),
                &raw mut self.properties.properties,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        let process = self
            .worker
            .join()
            .map_err(|_| "etw-consumer-thread-panicked")?;
        let close = unsafe { CloseTrace(self.processing) };
        if disable != 0 || stop != 0 || process != 0 || close != 0 {
            return Err("etw-cleanup-failed");
        }
        Ok(ObserverEvidenceV1 {
            kind: DiagnosticObserverV1::PassiveEtw,
            completed: true,
            stable_code: None,
            event_count: self.context.events.load(Ordering::Relaxed),
            output_debug_string_count: 0,
            module_event_count: 0,
            exception_event_count: 0,
            event_codes: Vec::new(),
            session_started: true,
            provider_enabled: true,
            cleanup_complete: true,
        })
    }
}

#[repr(C)]
struct ProcessBasicInformation {
    reserved1: *mut core::ffi::c_void,
    peb_base_address: *mut u8,
    reserved2: [*mut core::ffi::c_void; 2],
    unique_process_id: usize,
    reserved3: *mut core::ffi::c_void,
}

fn enable_loader_snaps(process: HANDLE) -> Result<(), &'static str> {
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryInformationProcess(
            process: HANDLE,
            information_class: u32,
            information: *mut core::ffi::c_void,
            information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }
    let mut basic = ProcessBasicInformation {
        reserved1: ptr::null_mut(),
        peb_base_address: ptr::null_mut(),
        reserved2: [ptr::null_mut(); 2],
        unique_process_id: 0,
        reserved3: ptr::null_mut(),
    };
    if unsafe {
        NtQueryInformationProcess(
            process,
            0,
            (&raw mut basic).cast(),
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            ptr::null_mut(),
        )
    } < 0
        || basic.peb_base_address.is_null()
    {
        return Err("loader-snaps-peb-query-failed");
    }
    #[cfg(target_pointer_width = "64")]
    let offset = 0xbc_usize;
    #[cfg(target_pointer_width = "32")]
    let offset = 0x68_usize;
    let address = unsafe { basic.peb_base_address.add(offset) };
    let mut flags = 0_u32;
    let mut transferred = 0_usize;
    if unsafe {
        ReadProcessMemory(
            process,
            address.cast(),
            (&raw mut flags).cast(),
            std::mem::size_of::<u32>(),
            &raw mut transferred,
        )
    } == 0
        || transferred != std::mem::size_of::<u32>()
    {
        return Err("loader-snaps-flag-read-failed");
    }
    flags |= 0x2;
    transferred = 0;
    if unsafe {
        WriteProcessMemory(
            process,
            address.cast(),
            (&raw const flags).cast(),
            std::mem::size_of::<u32>(),
            &raw mut transferred,
        )
    } == 0
        || transferred != std::mem::size_of::<u32>()
    {
        return Err("loader-snaps-flag-write-failed");
    }
    Ok(())
}
