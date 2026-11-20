//! Controller-owned, diagnostic-only trace of the original compiler process.
#![allow(unsafe_code)]

#[path = "windows_toolchain_file_trace_model.rs"]
mod model;

use memcordon_platform::{
    test_support::windows_fileio::EventFields,
    windows_fileio_record::{DecodeRejection, FieldId, RejectStage},
};
pub use model::Target;
use model::{
    EventClass, FileEvent, Generation, Location, Operation, Process, StopDisposition, Thread,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fmt, fs, io,
    mem::{offset_of, size_of},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::{
    Win32::{
        Foundation::{
            ERROR_ALREADY_EXISTS, ERROR_WMI_INSTANCE_NOT_FOUND, FILETIME, GetLastError, LocalFree,
        },
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::CreateDirectoryW,
        System::{
            Diagnostics::Etw::*,
            Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
            SystemInformation::GetSystemTimePreciseAsFileTime,
        },
    },
    core::GUID,
};

const PROCESS: GUID = GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);
const THREAD: GUID = GUID::from_u128(0x3d6fa8d1_fe05_11d0_9dda_00c04fd7ba7c);
const IMAGE: GUID = GUID::from_u128(0x2cb15d1d_5fc1_11d2_abe1_00a0c911f518);
const FILE: GUID = GUID::from_u128(0x90cbdc39_4a3e_11d1_84f4_0000f80464e3);
const MAX_FILE_MIB: u32 = 64;
const BUFFER_KIB: u32 = 64;
const MAX_EVENTS: usize = 300_000;
const MAX_PROBES: usize = 96;
const MAX_IMAGES: usize = 32;
const DECODE_BUDGET: Duration = Duration::from_secs(8);
// Process creation FILETIME can use the ordinary system clock granularity.
// Enclose two 15.625 ms clock ticks and require a unique generation.
const BIRTH_TOLERANCE_100NS: i128 = 320_000;
const FILETIME_TICKS_PER_SECOND: i128 = 10_000_000;

#[derive(Debug, Serialize)]
pub struct TraceError {
    api: &'static str,
    native_status: Option<u32>,
}

impl TraceError {
    fn new(api: &'static str, native_status: u32) -> Self {
        Self {
            api,
            native_status: Some(native_status),
        }
    }

    fn io(api: &'static str, error: io::Error) -> Self {
        Self {
            api,
            native_status: error.raw_os_error().map(|status| status as u32),
        }
    }
}

impl fmt::Display for TraceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} status {:?}", self.api, self.native_status)
    }
}

impl std::error::Error for TraceError {}

#[repr(C)]
struct Properties {
    native: EVENT_TRACE_PROPERTIES,
    logger: [u16; 128],
    file: [u16; 1024],
}

impl Properties {
    fn buffer(guid: GUID) -> Self {
        let mut properties = Self {
            native: EVENT_TRACE_PROPERTIES::default(),
            logger: [0; 128],
            file: [0; 1024],
        };
        let native = &mut properties.native;
        native.Wnode.BufferSize = size_of::<Self>() as u32;
        native.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        native.Wnode.Guid = guid;
        native.LoggerNameOffset = offset_of!(Self, logger) as u32;
        native.LogFileNameOffset = offset_of!(Self, file) as u32;
        properties
    }

    fn new(name: &str, path: &Path, guid: GUID) -> Result<Self, TraceError> {
        let mut properties = Self::buffer(guid);
        let logger = wide(OsStr::new(name));
        let file = wide(path.as_os_str());
        if logger.len() > properties.logger.len() || file.len() > properties.file.len() {
            return Err(TraceError {
                api: "EVENT_TRACE_PROPERTIES path extent",
                native_status: None,
            });
        }
        properties.logger[..logger.len()].copy_from_slice(&logger);
        properties.file[..file.len()].copy_from_slice(&file);
        let native = &mut properties.native;
        native.Wnode.ClientContext = 1; // QPC
        native.BufferSize = BUFFER_KIB;
        native.MinimumBuffers = 2;
        native.MaximumBuffers = 16;
        native.MaximumFileSize = MAX_FILE_MIB;
        native.LogFileMode = EVENT_TRACE_SYSTEM_LOGGER_MODE
            | EVENT_TRACE_FILE_MODE_SEQUENTIAL
            | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
        native.FlushTimer = 1;
        native.EnableFlags = EVENT_TRACE_FLAG_PROCESS
            | EVENT_TRACE_FLAG_THREAD
            | EVENT_TRACE_FLAG_IMAGE_LOAD
            | EVENT_TRACE_FLAG_DISK_FILE_IO
            | EVENT_TRACE_FLAG_FILE_IO
            | EVENT_TRACE_FLAG_FILE_IO_INIT;
        Ok(properties)
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

struct PrivateTrace {
    directory: PathBuf,
    file: PathBuf,
}

impl PrivateTrace {
    fn new(suffix: &str) -> Result<Self, TraceError> {
        let directory = std::env::temp_dir().join(format!("memcordon-etw-{suffix}"));
        let name = wide(directory.as_os_str());
        let sddl = wide(OsStr::new("D:P(A;OICI;GA;;;OW)(A;OICI;GA;;;SY)"));
        let mut descriptor = ptr::null_mut();
        // SAFETY: terminated SDDL and valid writable descriptor output.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(TraceError::new(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                unsafe { GetLastError() },
            ));
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        // SAFETY: both the terminated name and security descriptor outlive this call.
        let created = unsafe { CreateDirectoryW(name.as_ptr(), &attributes) };
        let status = if created == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        unsafe { LocalFree(descriptor) };
        if status != 0 {
            return Err(TraceError::new("CreateDirectoryW", status));
        }
        Ok(Self {
            file: directory.join("lookup.etl"),
            directory,
        })
    }

    fn remove(&self) -> Result<(), TraceError> {
        match fs::remove_file(&self.file) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(TraceError::io("DeleteFileW", error)),
        }
        match fs::remove_dir(&self.directory) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(TraceError::io("RemoveDirectoryW", error)),
        }
    }
}

impl Drop for PrivateTrace {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

#[derive(Clone, Copy)]
struct Anchor {
    before: i64,
    after: i64,
    filetime: u64,
}

impl Anchor {
    fn measure() -> Result<Self, TraceError> {
        let before = qpc()?;
        let mut time = FILETIME::default();
        unsafe { GetSystemTimePreciseAsFileTime(&mut time) };
        let after = qpc()?;
        let filetime = (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
        Ok(Self {
            before,
            after,
            filetime,
        })
    }

    fn bounds(self, tick: u64, frequency: i64) -> (i128, i128) {
        let convert = |reference| {
            i128::from(self.filetime)
                + (i128::from(tick) - i128::from(reference)) * FILETIME_TICKS_PER_SECOND
                    / i128::from(frequency)
        };
        (convert(self.after) - 1, convert(self.before) + 1)
    }
}

fn qpc() -> Result<i64, TraceError> {
    let mut counter = 0;
    if unsafe { QueryPerformanceCounter(&mut counter) } == 0 {
        return Err(TraceError::new("QueryPerformanceCounter", unsafe {
            GetLastError()
        }));
    }
    Ok(counter)
}

#[derive(Default, Serialize)]
struct Stop {
    status: Option<u32>,
    disposition: StopDisposition,
    events_lost: Option<u32>,
    buffers_lost: Option<u32>,
    buffers_written: Option<u32>,
}

pub struct Capture {
    file: PrivateTrace,
    session_guid: GUID,
    handle: Option<CONTROLTRACE_HANDLE>,
    frequency: i64,
    start_anchor: Anchor,
    stop_anchor: Option<Result<Anchor, TraceError>>,
    stop: Stop,
}

impl Capture {
    pub fn start() -> Result<Self, TraceError> {
        let mut identifier = [0; 16];
        getrandom::fill(&mut identifier).map_err(|error| TraceError {
            api: "getrandom",
            native_status: error.raw_os_error().map(|status| status as u32),
        })?;
        let suffix = hex::encode(identifier);
        let name = format!("MemCordon-OriginalCompiler-{suffix}");
        let file = PrivateTrace::new(&suffix)?;
        let session_guid = GUID::from_u128(u128::from_be_bytes(identifier));
        let mut properties = Properties::new(&name, &file.file, session_guid)?;
        let name = wide(OsStr::new(&name));
        let mut frequency = 0;
        if unsafe { QueryPerformanceFrequency(&mut frequency) } == 0 || frequency <= 0 {
            return Err(TraceError::new("QueryPerformanceFrequency", unsafe {
                GetLastError()
            }));
        }
        let start_anchor = Anchor::measure()?;
        let mut handle = CONTROLTRACE_HANDLE::default();
        // SAFETY: the aligned native properties and their offset buffers are one object.
        let status = unsafe { StartTraceW(&mut handle, name.as_ptr(), &mut properties.native) };
        if status != 0 {
            let api = if status == ERROR_ALREADY_EXISTS {
                "StartTraceW (session already exists)"
            } else {
                "StartTraceW"
            };
            return Err(TraceError::new(api, status));
        }
        Ok(Self {
            file,
            session_guid,
            handle: Some(handle),
            frequency,
            start_anchor,
            stop_anchor: None,
            stop: Stop::default(),
        })
    }

    pub fn stop(&mut self) {
        if self.stop.status.is_some() {
            return;
        }
        self.stop_anchor = Some(Anchor::measure());
        self.stop.status = self.stop_native();
    }

    pub fn is_stopped(&self) -> bool {
        self.handle.is_none()
    }

    fn stop_native(&mut self) -> Option<u32> {
        let handle = self.handle?;
        let mut properties = Properties::buffer(self.session_guid);
        let native = &mut properties.native;
        // Only the returned handle can stop this session. The supplied name is null.
        let status =
            unsafe { ControlTraceW(handle, ptr::null(), native, EVENT_TRACE_CONTROL_STOP) };
        match status {
            0 => {
                self.handle = None;
                self.stop.disposition = StopDisposition::Controlled;
                self.stop.events_lost = Some(native.EventsLost);
                self.stop.buffers_lost = Some(native.LogBuffersLost);
                self.stop.buffers_written = Some(native.BuffersWritten);
            }
            // Sequential tracing can stop at the file limit. Windows reports
            // this status when the owned session is already absent.
            ERROR_WMI_INSTANCE_NOT_FOUND => {
                self.handle = None;
                self.stop.disposition = StopDisposition::SessionAbsent;
            }
            _ => {}
        }
        Some(status)
    }

    pub fn finish(mut self, target: Option<Target>, deadline: Instant) -> Value {
        self.stop();
        let mut evidence = json!({
            "schema_version": 1,
            "diagnostic_only": true,
            "facility": "controller-owned-system-etw",
            "clock": {"unit": "qpc", "frequency_hz": self.frequency},
            "projection_scope": "attributed compiler file creates and image loads with module-like basenames",
            "start": {"api": "StartTraceW", "native_status": 0},
            "stop": {"api": "ControlTraceW", "result": self.stop},
            "target": target,
        });
        let size = fs::metadata(&self.file.file).map(|metadata| metadata.len());
        let limit_reached = size.as_ref().is_ok_and(|&bytes| {
            bytes.saturating_add(u64::from(BUFFER_KIB) * 1024)
                >= u64::from(MAX_FILE_MIB) * 1024 * 1024
        });
        evidence["etl_bytes"] = json!(size.as_ref().ok());
        let availability = if !self.stop.disposition.can_open() {
            "stop-failed"
        } else if let Some(target) = target {
            match size {
                Ok(_) => self.decode(target, &mut evidence, limit_reached, deadline),
                Err(error) => {
                    evidence["file_error"] = json!(TraceError::io("ETL metadata", error));
                    "etl-unavailable"
                }
            }
        } else {
            "original-compiler-identity-unavailable"
        };
        evidence["file_limit_reached"] = json!(limit_reached);
        if self.handle.is_some() {
            evidence["stop_retry_status"] = json!(self.stop_native());
        }
        evidence["private_etl_cleanup_error"] = json!(self.file.remove().err());
        evidence["availability"] = json!(availability);
        evidence
    }

    fn decode(
        &self,
        target: Target,
        evidence: &mut Value,
        limit_reached: bool,
        deadline: Instant,
    ) -> &'static str {
        let Some(Ok(stop_anchor)) = self.stop_anchor.as_ref() else {
            evidence["clock_error"] = json!(
                self.stop_anchor
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
            );
            return "clock-unavailable";
        };
        let min_qpc = self.start_anchor.before.max(0) as u64;
        let max_qpc = stop_anchor.after.max(0) as u64;
        let birth_matches = |at, birth| {
            if !(min_qpc..=max_qpc).contains(&at) {
                return false;
            }
            let (start_lo, start_hi) = self.start_anchor.bounds(at, self.frequency);
            let (stop_lo, stop_hi) = stop_anchor.bounds(at, self.frequency);
            let time = i128::from(birth);
            // Refuse a clock step/sample stall that consumes the uncertainty budget.
            let lo = start_lo.min(stop_lo);
            let hi = start_hi.max(stop_hi);
            hi - lo <= BIRTH_TOLERANCE_100NS
                && (lo - BIRTH_TOLERANCE_100NS..=hi + BIRTH_TOLERANCE_100NS).contains(&time)
        };
        let deadline = deadline.min(Instant::now() + DECODE_BUDGET);
        let mut lifetimes = Pass::new(Selection::Lifetime(target), deadline);
        let lifetime_status = lifetimes.read(&self.file.file);
        evidence["lifetime_scan"] = json!({"status": lifetime_status, "details": lifetimes.report});
        if lifetime_status.open_error.is_some() {
            return "etl-open-failed";
        }
        if lifetime_status.finalized == Some(false) {
            return "etl-unfinalized";
        }
        let generation = match model::attribute(
            target,
            &lifetimes.processes,
            &mut lifetimes.threads,
            birth_matches,
        ) {
            Ok(generation) => generation,
            Err(reason) => {
                evidence["attribution_error"] = json!(reason);
                return "attribution-incomplete";
            }
        };
        evidence["compiler_generation"] = json!({
            "start_qpc": generation.start,
            "end_qpc": generation.end,
            "ambiguous_threads": generation.ambiguous_threads,
            "parent_start_observed": generation.parent_start_observed,
            "birth_tolerance_100ns": BIRTH_TOLERANCE_100NS as u32,
        });
        let grace = (self.frequency / 10) as u64;
        let mut operations = Pass::new(
            Selection::Operations(target.pid, &generation, grace),
            deadline,
        );
        let operation_status = operations.read(&self.file.file);
        evidence["operation_scan"] =
            json!({"status": operation_status, "details": operations.report});
        let mut pairs = model::pair(operations.operations);
        let probe_limit = pairs.truncate(MAX_PROBES);
        operations.images.sort_unstable_by_key(|image| image.at_qpc);
        evidence["file_probes"] = json!(pairs);
        evidence["image_loads"] = json!(operations.images);
        evidence["projection_limit_reached"] = json!(probe_limit || operations.report.image_limit);
        if limit_reached
            || !self.stop.disposition.allows_complete_coverage()
            || self.stop.events_lost != Some(0)
            || self.stop.buffers_lost != Some(0)
            || !lifetime_status.complete()
            || !operation_status.complete()
            || !lifetimes.report.complete()
            || !operations.report.complete()
            || probe_limit
            || generation.ambiguous_threads != 0
            || pairs.unmatched != 0
            || pairs.ambiguous != 0
            || pairs.matched == 0
        {
            "attribution-incomplete"
        } else {
            "attributed"
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let _ = self.stop_native();
    }
}

fn same_guid(left: &GUID, right: &GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

#[derive(Clone, Copy)]
enum Selection<'a> {
    Lifetime(Target),
    Operations(u32, &'a Generation, u64),
}

#[derive(Default, Serialize)]
struct ScanStatus {
    open_error: Option<u32>,
    finalized: Option<bool>,
    process_status: Option<u32>,
    close_status: Option<u32>,
    events_lost: u32,
    buffers_lost: u32,
    buffers_written: u32,
}

impl ScanStatus {
    fn complete(&self) -> bool {
        self.open_error.is_none()
            && self.finalized == Some(true)
            && self.process_status == Some(0)
            && self.close_status == Some(0)
            && self.events_lost == 0
            && self.buffers_lost == 0
    }
}

#[derive(Default, Serialize)]
struct Report {
    seen: usize,
    event_versions: BTreeMap<&'static str, BTreeSet<u8>>,
    native_rejections: usize,
    first_rejections: Vec<Rejection>,
    time_limit: bool,
    event_limit: bool,
    image_limit: bool,
    callback_failure: bool,
}

impl Report {
    fn complete(&self) -> bool {
        self.native_rejections == 0
            && !self.time_limit
            && !self.event_limit
            && !self.image_limit
            && !self.callback_failure
    }
}

#[derive(Serialize)]
struct Rejection {
    class: &'static str,
    version: u8,
    opcode: u8,
    details: DecodeRejection,
}

#[derive(Serialize)]
struct ImageLoad {
    at_qpc: u64,
    #[serde(flatten)]
    location: Location,
}

struct Pass<'a> {
    selection: Selection<'a>,
    deadline: Instant,
    report: Report,
    processes: Vec<Process>,
    threads: Vec<Thread>,
    operations: Vec<FileEvent>,
    images: Vec<ImageLoad>,
}

impl<'a> Pass<'a> {
    fn new(selection: Selection<'a>, deadline: Instant) -> Self {
        Self {
            selection,
            deadline,
            report: Report::default(),
            processes: Vec::new(),
            threads: Vec::new(),
            operations: Vec::new(),
            images: Vec::new(),
        }
    }

    fn read(&mut self, path: &Path) -> ScanStatus {
        let mut status = ScanStatus::default();
        if !self.within_limit() {
            return status;
        }
        let mut path = wide(path.as_os_str());
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LogFileName: path.as_mut_ptr(),
            BufferCallback: Some(next_buffer),
            Context: (self as *mut Self).cast(),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        logfile.Anonymous2.EventRecordCallback = Some(record);
        // SAFETY: the path, logfile and context stay live through synchronous ProcessTrace.
        let handle = unsafe { OpenTraceW(&mut logfile) };
        if handle.Value == u64::MAX {
            status.open_error = Some(unsafe { GetLastError() });
            return status;
        }
        let header = &logfile.LogfileHeader;
        status.buffers_lost = header.BuffersLost;
        status.buffers_written = header.BuffersWritten;
        // TRACE_LOGFILE_HEADER defines this union arm for ETL loss counters.
        status.events_lost = unsafe { header.Anonymous2.Anonymous.EventsLost };
        status.finalized = Some(header.EndTime > 0 && header.EndTime >= header.StartTime);
        if status.finalized != Some(true) {
            status.close_status = Some(unsafe { CloseTrace(handle) });
            return status;
        }
        status.process_status = Some(unsafe { ProcessTrace(&handle, 1, ptr::null(), ptr::null()) });
        status.close_status = Some(unsafe { CloseTrace(handle) });
        status
    }

    fn within_limit(&mut self) -> bool {
        self.report.time_limit |= Instant::now() >= self.deadline;
        !self.report.time_limit && !self.report.event_limit && !self.report.callback_failure
    }

    fn event(&mut self, record: &EVENT_RECORD) {
        if !self.within_limit() {
            return;
        }
        if self.report.seen == MAX_EVENTS {
            self.report.event_limit = true;
            return;
        }
        self.report.seen += 1;
        let header = &record.EventHeader;
        let provider = &header.ProviderId;
        let descriptor = header.EventDescriptor;
        let opcode = descriptor.Opcode;
        let version = descriptor.Version;
        let Ok(at) = u64::try_from(header.TimeStamp) else {
            return;
        };
        let (class, result) = match self.selection {
            Selection::Lifetime(target)
                if same_guid(provider, &PROCESS) && matches!(opcode, 1 | 2) =>
            {
                ("process", self.process(record, version, opcode, target, at))
            }
            Selection::Lifetime(_) if same_guid(provider, &THREAD) && matches!(opcode, 1 | 2) => {
                ("thread", self.thread(record, version, opcode, at))
            }
            Selection::Operations(_, generation, grace)
                if same_guid(provider, &FILE)
                    && matches!(opcode, 64 | 76)
                    && (generation.start.saturating_sub(grace)
                        ..=generation.end.saturating_add(grace))
                        .contains(&at) =>
            {
                (
                    "file-io",
                    self.operation(record, version, opcode, at, generation),
                )
            }
            Selection::Operations(pid, generation, _)
                if same_guid(provider, &IMAGE) && opcode == 10 && generation.contains(at) =>
            {
                ("image-load", self.image(record, version, at, pid))
            }
            _ => return,
        };
        self.report
            .event_versions
            .entry(class)
            .or_default()
            .insert(version);
        if let Err(details) = result {
            self.report.native_rejections += 1;
            if !self
                .report
                .first_rejections
                .iter()
                .any(|entry| entry.class == class && entry.opcode == opcode)
            {
                self.report.first_rejections.push(Rejection {
                    class,
                    version,
                    opcode,
                    details,
                });
            }
        }
    }

    fn process(
        &mut self,
        record: &EVENT_RECORD,
        version: u8,
        opcode: u8,
        target: Target,
        at: u64,
    ) -> Result<(), DecodeRejection> {
        check_version(version, EventClass::Process)?;
        let fields = event_fields(record)?;
        let pid = dword(&fields, FieldId::ProcessId)?;
        if pid == target.pid || pid == target.parent_pid {
            let key = fields.scalar(FieldId::UniqueProcessKey, true, false)?;
            self.processes.push(Process {
                pid,
                parent: dword(&fields, FieldId::ParentId)?,
                key,
                at,
                start: opcode == 1,
                status: dword(&fields, FieldId::ExitStatus)?,
            });
        }
        Ok(())
    }

    fn thread(
        &mut self,
        record: &EVENT_RECORD,
        version: u8,
        opcode: u8,
        at: u64,
    ) -> Result<(), DecodeRejection> {
        check_version(version, EventClass::Thread)?;
        let fields = event_fields(record)?;
        self.threads.push(Thread {
            pid: dword(&fields, FieldId::ProcessId)?,
            tid: dword(&fields, FieldId::TThreadId)?,
            at,
            start: opcode == 1,
        });
        Ok(())
    }

    fn operation(
        &mut self,
        record: &EVENT_RECORD,
        version: u8,
        opcode: u8,
        at: u64,
        generation: &Generation,
    ) -> Result<(), DecodeRejection> {
        check_version(version, EventClass::FileIo)?;
        let fields = event_fields(record)?;
        let irp = fields.scalar(FieldId::IrpPtr, true, false)?;
        if irp == 0 {
            return Err(reject_field(RejectStage::ScalarExtent, FieldId::IrpPtr));
        }
        let operation = if opcode == 64 {
            let raw_tid = fields.scalar(FieldId::Ttid, true, true)?;
            let tid = u32::try_from(raw_tid)
                .map_err(|_| reject_field(RejectStage::ThreadId, FieldId::Ttid))?;
            let location = if generation.issued(tid, at) {
                Location::from_path(&fields.unicode(FieldId::OpenPath)?)
            } else {
                None
            };
            Operation::Create(location)
        } else {
            Operation::End(dword(&fields, FieldId::NtStatus)?)
        };
        self.operations.push(FileEvent { at, irp, operation });
        Ok(())
    }

    fn image(
        &mut self,
        record: &EVENT_RECORD,
        version: u8,
        at: u64,
        pid: u32,
    ) -> Result<(), DecodeRejection> {
        check_version(version, EventClass::Image)?;
        let fields = event_fields(record)?;
        if dword(&fields, FieldId::ProcessId)? == pid
            && let Some(location) = Location::from_path(&fields.unicode(FieldId::FileName)?)
        {
            if self.images.len() == MAX_IMAGES {
                self.report.image_limit = true;
            } else {
                self.images.push(ImageLoad {
                    at_qpc: at,
                    location,
                });
            }
        }
        Ok(())
    }
}

fn dword(fields: &EventFields<'_>, field: FieldId) -> Result<u32, DecodeRejection> {
    fields.scalar(field, false, true).map(|value| value as u32)
}

fn reject_field(stage: RejectStage, field: FieldId) -> DecodeRejection {
    let mut rejection = DecodeRejection::new(stage);
    rejection.field = Some(field);
    rejection
}

fn event_fields(record: &EVENT_RECORD) -> Result<EventFields<'_>, DecodeRejection> {
    // SAFETY: this private adapter is only called while processing a live
    // record borrowed from the synchronous ProcessTrace callback.
    unsafe { EventFields::new(record) }
}

fn check_version(version: u8, class: EventClass) -> Result<(), DecodeRejection> {
    if class.supports(version) {
        Ok(())
    } else {
        Err(DecodeRejection::new(RejectStage::EventVersion))
    }
}

unsafe extern "system" fn record(raw: *mut EVENT_RECORD) {
    // SAFETY: only the synchronous consumer invokes callbacks with this live context.
    let Some(record) = (unsafe { raw.as_ref() }) else {
        return;
    };
    let Some(pass) = (unsafe { record.UserContext.cast::<Pass<'_>>().as_mut() }) else {
        return;
    };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pass.event(record))).is_err() {
        pass.report.callback_failure = true;
    }
}

unsafe extern "system" fn next_buffer(raw: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    // SAFETY: OpenTrace preserves the caller context for ProcessTrace callbacks.
    let Some(log) = (unsafe { raw.as_ref() }) else {
        return 0;
    };
    let Some(pass) = (unsafe { log.Context.cast::<Pass<'_>>().as_mut() }) else {
        return 0;
    };
    u32::from(pass.within_limit())
}
