//! Controller-owned diagnostic system session; consumer callbacks live only in
//! the separately supervised ordinary helper process.
use super::WindowsImageProcess;
use crate::windows_fileio_record::*;
use sha2::{Digest, Sha256};
use std::{
    ffi::c_void,
    io,
    mem::{offset_of, size_of},
    ptr,
    time::Instant,
};
use windows_sys::{
    Win32::{
        Foundation::*,
        System::{Diagnostics::Etw::*, Performance::QueryPerformanceCounter},
    },
    core::GUID,
};

const FILE_IO: GUID = GUID::from_u128(0x90cbdc39_4a3e_11d1_84f4_0000f80464e3);
const FLAGS: u32 = EVENT_TRACE_SYSTEM_LOGGER_MODE
    | EVENT_TRACE_REAL_TIME_MODE
    | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
const ENABLE_FLAGS: u32 =
    EVENT_TRACE_FLAG_DISK_FILE_IO | EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT;
fn live(deadline: Instant) -> io::Result<()> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original FileIo observation cutoff",
        ))
    }
}
fn status(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
fn guid(bytes: [u8; 16]) -> GUID {
    GUID::from_u128(u128::from_be_bytes(bytes))
}
fn same_guid(left: &GUID, right: &GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}
fn tick() -> io::Result<u64> {
    let mut value = 0;
    if unsafe { QueryPerformanceCounter(&mut value) } == 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(value).map_err(io::Error::other)
}
struct Properties {
    words: Vec<u64>,
}
impl Properties {
    fn new(spec: &ConsumerSpec) -> Self {
        let name = spec
            .session_name
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let length = size_of::<EVENT_TRACE_PROPERTIES>() + name.len() * 2;
        let mut value = Self {
            words: vec![0; length.div_ceil(8)],
        };
        let properties = value.get();
        properties.Wnode.BufferSize = length as u32;
        properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties.Wnode.Guid = guid(spec.session_guid);
        properties.Wnode.ClientContext = 1;
        properties.BufferSize = 64;
        properties.MinimumBuffers = 2;
        properties.MaximumBuffers = 8;
        properties.LogFileMode = FLAGS;
        properties.FlushTimer = 1;
        properties.EnableFlags = ENABLE_FLAGS;
        properties.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        unsafe {
            ptr::copy_nonoverlapping(
                name.as_ptr().cast::<u8>(),
                value
                    .words
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(size_of::<EVENT_TRACE_PROPERTIES>()),
                name.len() * 2,
            );
        }
        value
    }
    fn get(&mut self) -> &mut EVENT_TRACE_PROPERTIES {
        unsafe { &mut *self.words.as_mut_ptr().cast() }
    }
}
pub struct OwnedFileIoSession {
    handle: CONTROLTRACE_HANDLE,
    spec: ConsumerSpec,
    cleanup: Instant,
    active: bool,
    last: Option<StopRecord>,
}
pub struct PreparedFileIoSession {
    pid: u32,
    birth: u64,
    binding: Binding,
    work: Instant,
    cleanup: Instant,
}
#[derive(Debug)]
struct StopFailure {
    primary: io::Error,
    stop: StopRecord,
    session: String,
}
impl std::fmt::Display for StopFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; owned FileIo stop status={} session={} late={}",
            self.primary, self.stop.status, self.session, self.stop.late
        )
    }
}
impl std::error::Error for StopFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
#[derive(Debug)]
struct ReadyFailure {
    primary: io::Error,
    secondary: io::Error,
}
impl std::fmt::Display for ReadyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; FileIo readiness delivery: {}",
            self.primary, self.secondary
        )
    }
}
impl std::error::Error for ReadyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
impl OwnedFileIoSession {
    pub fn prepare(
        target: &WindowsImageProcess,
        binding: Binding,
        work: Instant,
        cleanup: Instant,
    ) -> io::Result<PreparedFileIoSession> {
        live(work)?;
        if cleanup < work || target.has_exited()? {
            return Err(io::Error::other(
                "original FileIo target/deadline unavailable",
            ));
        }
        let pid = target.identity.pid;
        let birth = u64::try_from(target.identity.birth).map_err(io::Error::other)?;
        if pid == 0 || birth == 0 || binding.cutoff_qpc == 0 || binding.frequency == 0 {
            return Err(io::Error::other("original FileIo binding invalid"));
        }
        Ok(PreparedFileIoSession {
            pid,
            birth,
            binding,
            work,
            cleanup,
        })
    }
    pub fn consumer_spec(&self) -> &ConsumerSpec {
        &self.spec
    }
    pub fn stop(&mut self) -> StopRecord {
        if let Some(record) = &self.last {
            return record.clone();
        }
        let started = Instant::now();
        let late = started >= self.cleanup;
        let mut properties = Properties::new(&self.spec);
        let result = unsafe {
            ControlTraceW(
                self.handle,
                ptr::null(),
                properties.get(),
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        let data = properties.get();
        let record = StopRecord {
            attempted: true,
            status: result,
            stopped: result == 0,
            late: late || Instant::now() >= self.cleanup,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            events_lost: data.EventsLost,
            log_buffers_lost: data.LogBuffersLost,
            realtime_buffers_lost: data.RealTimeBuffersLost,
            buffers: data.NumberOfBuffers,
            buffer_kib: data.BufferSize,
        };
        self.active = false;
        self.last = Some(record.clone());
        record
    }
}
impl PreparedFileIoSession {
    pub fn start(self) -> io::Result<OwnedFileIoSession> {
        let Self {
            pid,
            birth,
            binding,
            work,
            cleanup,
        } = self;
        live(work)?;
        let nonce = tempfile::Builder::new().prefix("mc-fileio-").tempdir()?;
        let digest =
            Sha256::digest(format!("{:?}-{pid}-{birth}-{}", nonce.path(), tick()?).as_bytes());
        let mut unique = [0; 16];
        unique.copy_from_slice(&digest[..16]);
        let name = format!("Memcordon-FileIo-{:032x}", u128::from_be_bytes(unique));
        let spec = ConsumerSpec {
            version: 1,
            session_name: name,
            session_guid: unique,
            pid,
            birth,
            binding,
        };
        spec.validate().map_err(io::Error::other)?;
        let mut properties = Properties::new(&spec);
        let mut handle = CONTROLTRACE_HANDLE::default();
        let name = spec
            .session_name
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        live(work)?;
        status(unsafe { StartTraceW(&mut handle, name.as_ptr(), properties.get()) })?;
        let mut owner = OwnedFileIoSession {
            handle,
            spec,
            cleanup,
            active: true,
            last: None,
        };
        let checked = (|| -> io::Result<()> {
            status(unsafe {
                ControlTraceW(
                    owner.handle,
                    ptr::null(),
                    properties.get(),
                    EVENT_TRACE_CONTROL_QUERY,
                )
            })?;
            let actual = properties.get();
            if actual.BufferSize != 64
                || actual.MaximumBuffers == 0
                || actual.MaximumBuffers > 8
                || actual.MinimumBuffers == 0
                || actual.MinimumBuffers > 8
                || actual.NumberOfBuffers == 0
                || actual.NumberOfBuffers > 8
                || actual.MinimumBuffers > actual.MaximumBuffers
                || actual.NumberOfBuffers > actual.MaximumBuffers
                || actual.EnableFlags & ENABLE_FLAGS != ENABLE_FLAGS
                || actual.LogFileMode & FLAGS != FLAGS
                || actual.Wnode.ClientContext != 1
            {
                return Err(io::Error::other(format!(
                    "owned FileIo session configuration differs: buffer_kib={} minimum={} maximum={} allocated={} enabled_flags=0x{:08x} mode=0x{:08x} clock={}",
                    actual.BufferSize,
                    actual.MinimumBuffers,
                    actual.MaximumBuffers,
                    actual.NumberOfBuffers,
                    actual.EnableFlags,
                    actual.LogFileMode,
                    actual.Wnode.ClientContext
                )));
            }
            live(work)
        })();
        if let Err(primary) = checked {
            let stopped = owner.stop();
            return if stopped.stopped {
                Err(primary)
            } else {
                Err(io::Error::new(
                    primary.kind(),
                    StopFailure {
                        primary,
                        stop: stopped,
                        session: owner.spec.session_name.clone(),
                    },
                ))
            };
        }
        Ok(owner)
    }
}
impl Drop for OwnedFileIoSession {
    fn drop(&mut self) {
        if self.active {
            let record = self.stop();
            if !record.stopped {
                use std::io::Write;
                let _ = writeln!(
                    io::stderr().lock(),
                    "owned diagnostic FileIo session stop failed; session={}; status={}; late={}",
                    self.spec.session_name,
                    record.status,
                    record.late
                );
            }
        }
    }
}

fn read_utf16(bytes: &[u8], offset: usize) -> io::Result<Vec<u16>> {
    if offset % 2 != 0 || offset >= bytes.len() {
        return Err(io::Error::other("TDH native string offset"));
    }
    let mut units = Vec::new();
    for pair in bytes[offset..].chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            return Ok(units);
        }
        if units.len() == 128 {
            return Err(io::Error::other("TDH property name bound"));
        }
        units.push(unit);
    }
    Err(io::Error::other("TDH native string terminator"))
}
struct Schema {
    fields: std::collections::BTreeMap<String, u16>,
}
fn schema(event: &EVENT_RECORD) -> io::Result<Schema> {
    let mut length = 0;
    let result =
        unsafe { TdhGetEventInformation(event, 0, ptr::null(), ptr::null_mut(), &mut length) };
    if result != ERROR_INSUFFICIENT_BUFFER
        || length as usize > 65536
        || (length as usize) < size_of::<TRACE_EVENT_INFO>()
    {
        return Err(io::Error::other("unsupported bounded TDH schema extent"));
    }
    let mut words = vec![0u64; (length as usize).div_ceil(8)];
    let capacity = length;
    status(unsafe {
        TdhGetEventInformation(
            event,
            0,
            ptr::null(),
            words.as_mut_ptr().cast(),
            &mut length,
        )
    })?;
    if length > capacity || (length as usize) < size_of::<TRACE_EVENT_INFO>() {
        return Err(io::Error::other("TDH returned schema extent"));
    }
    let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), length as usize) };
    let info = unsafe { &*words.as_ptr().cast::<TRACE_EVENT_INFO>() };
    // Classic TDH metadata identifies the MOF class through EventGuid; its
    // controlling provider GUID need not equal that class GUID.
    if (!same_guid(&info.ProviderGuid, &event.EventHeader.ProviderId)
        && !same_guid(&info.EventGuid, &event.EventHeader.ProviderId))
        || info.EventDescriptor.Version != event.EventHeader.EventDescriptor.Version
        || info.EventDescriptor.Opcode != event.EventHeader.EventDescriptor.Opcode
        || info.PropertyCount != info.TopLevelPropertyCount
        || info.PropertyCount > 32
    {
        return Err(io::Error::other(
            "unsupported TDH nested/property inventory",
        ));
    }
    let mut fields = std::collections::BTreeMap::new();
    for index in 0..info.PropertyCount as usize {
        let offset = offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray)
            + index * size_of::<EVENT_PROPERTY_INFO>();
        if offset + size_of::<EVENT_PROPERTY_INFO>() > bytes.len() {
            return Err(io::Error::other("TDH property extent"));
        }
        let property = unsafe {
            ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<EVENT_PROPERTY_INFO>())
        };
        if property.Flags != 0 {
            return Err(io::Error::other("unsupported TDH property flags"));
        }
        let name = String::from_utf16(&read_utf16(bytes, property.NameOffset as usize)?)
            .map_err(io::Error::other)?;
        if fields
            .insert(name, unsafe { property.Anonymous1.nonStructType.InType })
            .is_some()
        {
            return Err(io::Error::other("duplicate TDH property identity"));
        }
    }
    Ok(Schema { fields })
}
fn property(
    event: &EVENT_RECORD,
    schema: &Schema,
    name: &str,
    types: &[i32],
) -> io::Result<Vec<u8>> {
    if !schema
        .fields
        .get(name)
        .is_some_and(|kind| types.contains(&i32::from(*kind)))
    {
        return Err(io::Error::other("unsupported TDH property type"));
    }
    let name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let descriptor = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name.as_ptr() as usize as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let mut length = 0;
    status(unsafe { TdhGetPropertySize(event, 0, ptr::null(), 1, &descriptor, &mut length) })?;
    if length == 0 || length > 65536 {
        return Err(io::Error::other("TDH property byte bound"));
    }
    let mut data = vec![0; length as usize];
    status(unsafe {
        TdhGetProperty(
            event,
            0,
            ptr::null(),
            1,
            &descriptor,
            length,
            data.as_mut_ptr(),
        )
    })?;
    Ok(data)
}
fn scalar(event: &EVENT_RECORD, schema: &Schema, name: &str, pointer: bool) -> io::Result<u64> {
    let data = property(
        event,
        schema,
        name,
        if pointer {
            &[TDH_INTYPE_POINTER]
        } else {
            &[TDH_INTYPE_UINT32, TDH_INTYPE_HEXINT32]
        },
    )?;
    let width = if pointer {
        let flags = u32::from(event.EventHeader.Flags);
        if flags & EVENT_HEADER_FLAG_32_BIT_HEADER != 0
            && flags & EVENT_HEADER_FLAG_64_BIT_HEADER == 0
        {
            4
        } else if flags & EVENT_HEADER_FLAG_64_BIT_HEADER != 0
            && flags & EVENT_HEADER_FLAG_32_BIT_HEADER == 0
        {
            8
        } else {
            return Err(io::Error::other("unavailable ETW pointer width"));
        }
    } else {
        4
    };
    crate::windows_fileio_record::pointer(&data, width).map_err(io::Error::other)
}
struct Context {
    spec: ConsumerSpec,
    collector: Option<Collector>,
    cutoff_reached: bool,
    failed: bool,
}
unsafe extern "system" fn callback(raw: *mut EVENT_RECORD) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        callback_inner(raw)
    }))
    .is_err()
        && !raw.is_null()
    {
        // The consumer owns this context until ProcessTrace has returned. Never
        // permit a Rust panic to unwind into ETW or resume partially mutated capture.
        let context = unsafe { (*raw).UserContext.cast::<Context>() };
        if !context.is_null() {
            let context = unsafe { &mut *context };
            context.failed = true;
            if let Some(collector) = &mut context.collector {
                let counters = collector.counters();
                counters.malformed = counters.malformed.saturating_add(1);
            }
        }
    }
}
unsafe fn callback_inner(raw: *mut EVENT_RECORD) {
    if raw.is_null() {
        return;
    }
    // ETW owns this record only for the synchronous callback. Copy fields and
    // bounded payloads; never retain an EVENT_RECORD pointer.
    let event = unsafe { &*raw };
    if event.UserContext.is_null() {
        return;
    }
    let context = unsafe { &mut *event.UserContext.cast::<Context>() };
    if context.failed {
        return;
    }
    let Some(collector) = &mut context.collector else {
        return;
    };
    let header = &event.EventHeader;
    if !same_guid(&header.ProviderId, &FILE_IO) || !matches!(header.EventDescriptor.Opcode, 64 | 76)
    {
        return;
    }
    if header.TimeStamp < 0
        || header.TimeStamp as u64 > context.spec.binding.cutoff_qpc
        || tick().map_or(true, |now| now >= context.spec.binding.cutoff_qpc)
    {
        context.cutoff_reached = true;
        return;
    }
    if header.EventDescriptor.Opcode == 64 && header.ProcessId != context.spec.pid {
        let counters = collector.counters();
        counters.filtered = counters.filtered.saturating_add(1);
        return;
    }
    let decoded = (|| -> io::Result<()> {
        if header.EventDescriptor.Version != 2 {
            return Err(io::Error::other("unsupported FileIo schema version"));
        }
        let shape = schema(event)?;
        let irp = scalar(event, &shape, "IrpPtr", true)?;
        if header.EventDescriptor.Opcode == 76 {
            collector.completion(Completion {
                irp,
                qpc: header.TimeStamp as u64,
                extra_info: scalar(event, &shape, "ExtraInfo", true)?,
                ntstatus: scalar(event, &shape, "NtStatus", false)? as u32 as i32,
            });
            return Ok(());
        }
        let path = property(event, &shape, "OpenPath", &[TDH_INTYPE_UNICODESTRING])?;
        let units = path_units(&path).map_err(io::Error::other)?;
        let full = units.as_slice();
        let mut hash = Sha256::new();
        for unit in full {
            hash.update(unit.to_le_bytes());
        }
        let ttid_pointer = match shape.fields.get("TTID").copied().map(i32::from) {
            Some(TDH_INTYPE_POINTER) => true,
            Some(TDH_INTYPE_UINT32 | TDH_INTYPE_HEXINT32) => false,
            _ => return Err(io::Error::other("unsupported TDH thread identifier type")),
        };
        let ttid =
            thread_id(scalar(event, &shape, "TTID", ttid_pointer)?).map_err(io::Error::other)?;
        collector.create(Create {
            irp,
            qpc: header.TimeStamp as u64,
            header_pid: header.ProcessId,
            header_tid: header.ThreadId,
            ttid,
            file_object: scalar(event, &shape, "FileObject", true)?,
            create_options: scalar(event, &shape, "CreateOptions", false)? as u32,
            file_attributes: scalar(event, &shape, "FileAttributes", false)? as u32,
            share_access: scalar(event, &shape, "ShareAccess", false)? as u32,
            path_prefix: full[..full.len().min(128)].to_vec(),
            path_units: full.len() as u32,
            path_sha256: Some(hash.finalize().into()),
            path_truncated: full.len() > 128,
        });
        Ok(())
    })();
    if decoded.is_err() {
        let counters = collector.counters();
        counters.unsupported = counters.unsupported.saturating_add(1);
    }
}
/// Runs only in the separately owned consumer process. The caller supervises
/// process settlement; no Rust thread or callback state is detached.
pub fn consume(
    spec: &ConsumerSpec,
    ready: impl FnOnce(io::Result<()>) -> io::Result<()>,
) -> io::Result<Observation> {
    spec.validate().map_err(io::Error::other)?;
    let mut context = Box::new(Context {
        spec: spec.clone(),
        collector: Some(Collector::new(spec.clone()).map_err(io::Error::other)?),
        cutoff_reached: false,
        failed: false,
    });
    let mut name = spec
        .session_name
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut logfile = EVENT_TRACE_LOGFILEW {
        LoggerName: name.as_mut_ptr(),
        ..Default::default()
    };
    logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
        | PROCESS_TRACE_MODE_EVENT_RECORD
        | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    logfile.Anonymous2.EventRecordCallback = Some(callback);
    logfile.Context = (&mut *context as *mut Context).cast::<c_void>();
    let handle = unsafe { OpenTraceW(&mut logfile) };
    if handle.Value == u64::MAX {
        let error = io::Error::last_os_error();
        let code = error.raw_os_error();
        let primary = code
            .map(io::Error::from_raw_os_error)
            .unwrap_or_else(|| io::Error::other("OpenTrace unavailable without native status"));
        return match ready(Err(error)) {
            Ok(()) => Err(primary),
            Err(secondary) => Err(io::Error::new(
                primary.kind(),
                ReadyFailure { primary, secondary },
            )),
        };
    }
    if let Err(error) = ready(Ok(())) {
        unsafe { CloseTrace(handle) };
        return Err(error);
    }
    let result = unsafe { ProcessTrace(&handle, 1, ptr::null(), ptr::null()) };
    let closed = unsafe { CloseTrace(handle) };
    let mut observation = context
        .collector
        .take()
        .expect("owned consumer collector")
        .finish(result, context.cutoff_reached);
    observation.close_trace_status = closed;
    Ok(observation)
}
