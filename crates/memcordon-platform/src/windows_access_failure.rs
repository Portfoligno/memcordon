//! Gate-only manifest-provider session. Blocking consumers run in an owned helper process.
use super::WindowsImageProcess;
use crate::windows_access_failure_record::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
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

const PROVIDER_GUID: GUID = GUID::from_u128(PROVIDER);
const MODE: u32 = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
fn live(deadline: Instant) -> io::Result<()> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original access-failure probe cutoff",
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
fn tick() -> io::Result<u64> {
    let mut value = 0;
    if unsafe { QueryPerformanceCounter(&mut value) } == 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(value).map_err(io::Error::other)
}
fn same_guid(left: &GUID, right: &GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
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
        let bytes = size_of::<EVENT_TRACE_PROPERTIES>() + name.len() * 2;
        let mut value = Self {
            words: vec![0; bytes.div_ceil(8)],
        };
        let data = value.get();
        data.Wnode.BufferSize = bytes as u32;
        data.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        data.Wnode.Guid = GUID::from_u128(u128::from_be_bytes(spec.session_guid));
        data.Wnode.ClientContext = 1;
        data.BufferSize = 64;
        data.MinimumBuffers = 2;
        data.MaximumBuffers = 8;
        data.LogFileMode = MODE;
        data.FlushTimer = 1;
        data.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
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
pub struct PreparedAccessFailureSession {
    object_name: Vec<u16>,
    pid: u32,
    birth: u64,
    binding: Binding,
    work: Instant,
    cleanup: Instant,
}
pub struct OwnedAccessFailureSession {
    handle: CONTROLTRACE_HANDLE,
    spec: ConsumerSpec,
    cleanup: Instant,
    active: bool,
    last: Option<StopRecord>,
}
#[derive(Debug)]
struct Secondary {
    primary: io::Error,
    secondary: io::Error,
}
/// An owned session was created, but setup cleanup could not be established.
#[derive(Debug)]
pub struct StartupCleanupFailure {
    pub primary: io::Error,
    pub stop: StopRecord,
}
impl std::fmt::Display for StartupCleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; owned access-failure setup cleanup={:?}",
            self.primary, self.stop
        )
    }
}
impl std::error::Error for StartupCleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
impl std::fmt::Display for Secondary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; {}", self.primary, self.secondary)
    }
}
impl std::error::Error for Secondary {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
impl OwnedAccessFailureSession {
    pub fn prepare(
        target: &WindowsImageProcess,
        binding: Binding,
        object_name: Vec<u16>,
        work: Instant,
        cleanup: Instant,
    ) -> io::Result<PreparedAccessFailureSession> {
        live(work)?;
        if cleanup < work || target.has_exited()? {
            return Err(io::Error::other(
                "access-failure held target/deadlines unavailable",
            ));
        }
        let pid = target.identity.pid;
        let birth = u64::try_from(target.identity.birth).map_err(io::Error::other)?;
        if pid == 0 || birth == 0 || binding.cutoff_qpc == 0 || binding.frequency == 0 {
            return Err(io::Error::other("access-failure target binding invalid"));
        }
        live(work)?;
        Ok(PreparedAccessFailureSession {
            object_name,
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
        // Only this successfully created session is disabled/stopped, even after cleanup expiry.
        let disabled = unsafe {
            EnableTraceEx2(
                self.handle,
                &PROVIDER_GUID,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                2,
                KEYWORD,
                0,
                0,
                ptr::null(),
            )
        };
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
            status: result,
            disable_status: disabled,
            stopped: result == 0,
            late: Instant::now() >= self.cleanup,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            events_lost: data.EventsLost,
            log_buffers_lost: data.LogBuffersLost,
            realtime_buffers_lost: data.RealTimeBuffersLost,
        };
        self.active = false;
        self.last = Some(record.clone());
        record
    }
}
impl PreparedAccessFailureSession {
    pub fn start(self) -> io::Result<OwnedAccessFailureSession> {
        live(self.work)?;
        let nonce = tempfile::Builder::new()
            .prefix("mc-access-failure-")
            .tempdir()?;
        let hash = Sha256::digest(
            format!("{:?}-{}-{}-{}", nonce.path(), self.pid, self.birth, tick()?).as_bytes(),
        );
        let mut session_guid = [0; 16];
        session_guid.copy_from_slice(&hash[..16]);
        let spec = ConsumerSpec {
            object_name: self.object_name,
            version: 1,
            session_name: format!(
                "Memcordon-AccessFailure-{:032x}",
                u128::from_be_bytes(session_guid)
            ),
            session_guid,
            pid: self.pid,
            birth: self.birth,
            binding: self.binding,
        };
        spec.validate().map_err(io::Error::other)?;
        let mut properties = Properties::new(&spec);
        let name = spec
            .session_name
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut handle = CONTROLTRACE_HANDLE::default();
        live(self.work)?;
        status(unsafe { StartTraceW(&mut handle, name.as_ptr(), properties.get()) })?;
        let mut owner = OwnedAccessFailureSession {
            handle,
            spec,
            cleanup: self.cleanup,
            active: true,
            last: None,
        };
        let result = (|| {
            live(self.work)?;
            let milliseconds = u32::try_from(
                self.work
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            )
            .unwrap_or(u32::MAX - 1)
            .clamp(1, u32::MAX - 1);
            status(unsafe {
                EnableTraceEx2(
                    owner.handle,
                    &PROVIDER_GUID,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    2,
                    KEYWORD,
                    0,
                    milliseconds,
                    ptr::null(),
                )
            })?;
            live(self.work)?;
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
                || actual.MinimumBuffers == 0
                || actual.MaximumBuffers == 0
                || actual.MaximumBuffers > 8
                || actual.NumberOfBuffers == 0
                || actual.NumberOfBuffers > 8
                || actual.MinimumBuffers > actual.MaximumBuffers
                || actual.NumberOfBuffers > actual.MaximumBuffers
                || actual.LogFileMode & MODE != MODE
                || actual.Wnode.ClientContext != 1
            {
                return Err(io::Error::other(
                    "access-failure actual session configuration differs",
                ));
            }
            live(self.work)
        })();
        if let Err(primary) = result {
            let stopped = owner.stop();
            return if stopped.stopped && stopped.disable_status == 0 {
                Err(primary)
            } else {
                Err(io::Error::new(
                    primary.kind(),
                    StartupCleanupFailure {
                        primary,
                        stop: stopped,
                    },
                ))
            };
        }
        Ok(owner)
    }
}
impl Drop for OwnedAccessFailureSession {
    fn drop(&mut self) {
        if self.active {
            let record = self.stop();
            if !record.stopped {
                use std::io::Write;
                let _ = writeln!(
                    io::stderr().lock(),
                    "owned access-failure session stop unavailable: {record:?}"
                );
            }
        }
    }
}

struct Schema {
    words: Vec<u64>,
    length: usize,
    fields: BTreeMap<String, usize>,
}
impl Schema {
    fn info(&self) -> &TRACE_EVENT_INFO {
        unsafe { &*self.words.as_ptr().cast() }
    }
    fn property(&self, index: usize) -> io::Result<&EVENT_PROPERTY_INFO> {
        let offset = offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray)
            .checked_add(
                index
                    .checked_mul(size_of::<EVENT_PROPERTY_INFO>())
                    .ok_or_else(|| io::Error::other("property index overflow"))?,
            )
            .ok_or_else(|| io::Error::other("property extent overflow"))?;
        if offset
            .checked_add(size_of::<EVENT_PROPERTY_INFO>())
            .is_none_or(|end| end > self.length)
        {
            return Err(io::Error::other("property extent outside TDH metadata"));
        }
        Ok(unsafe { &*self.words.as_ptr().cast::<u8>().add(offset).cast() })
    }
    fn name(&self, offset: u32) -> io::Result<String> {
        let offset = offset as usize;
        if offset % 2 != 0 || offset >= self.length {
            return Err(io::Error::other("TDH name offset invalid"));
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.length) };
        let mut units = Vec::new();
        for pair in bytes[offset..].chunks_exact(2) {
            let unit = u16::from_le_bytes([pair[0], pair[1]]);
            if unit == 0 {
                return String::from_utf16(&units).map_err(io::Error::other);
            }
            if units.len() == 128 {
                return Err(io::Error::other("TDH field name too long"));
            }
            units.push(unit);
        }
        Err(io::Error::other("TDH field name unterminated"))
    }
    fn field(&self, name: &str) -> io::Result<&EVENT_PROPERTY_INFO> {
        self.property(
            *self
                .fields
                .get(name)
                .ok_or_else(|| io::Error::other("required TDH field absent"))?,
        )
    }
}
fn schema(event: &EVENT_RECORD) -> io::Result<Schema> {
    let mut length = 0;
    let result =
        unsafe { TdhGetEventInformation(event, 0, ptr::null(), ptr::null_mut(), &mut length) };
    if result != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    if length as usize > MAX_PROPERTY_BYTES || (length as usize) < size_of::<TRACE_EVENT_INFO>() {
        return Err(io::Error::other("TDH metadata extent unsupported"));
    }
    let capacity = length;
    let mut words = vec![0u64; (length as usize).div_ceil(8)];
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
        return Err(io::Error::other("TDH returned extent invalid"));
    }
    let mut shape = Schema {
        words,
        length: length as usize,
        fields: BTreeMap::new(),
    };
    let info = shape.info();
    if !same_guid(&info.ProviderGuid, &PROVIDER_GUID)
        || info.EventDescriptor.Id != 14
        || info.EventDescriptor.Version != 0
        || info.EventDescriptor.Keyword != event.EventHeader.EventDescriptor.Keyword
        || info.EventDescriptor.Level != event.EventHeader.EventDescriptor.Level
        || info.EventDescriptor.Opcode != event.EventHeader.EventDescriptor.Opcode
        || info.EventDescriptor.Task != event.EventHeader.EventDescriptor.Task
        || info.EventDescriptor.Channel != event.EventHeader.EventDescriptor.Channel
        || info.PropertyCount != info.TopLevelPropertyCount
        || info.PropertyCount > 64
    {
        return Err(io::Error::other(
            "access-failure TDH identity/struct inventory unsupported",
        ));
    }
    let count = info.PropertyCount;
    for index in 0..count as usize {
        let property = shape.property(index)?;
        if property.Flags & !PropertyParamCount != 0 {
            return Err(io::Error::other(
                "access-failure complex TDH field flags unsupported",
            ));
        }
        let name = shape.name(property.NameOffset)?;
        if shape.fields.insert(name, index).is_some() {
            return Err(io::Error::other("duplicate TDH field"));
        }
    }
    Ok(shape)
}
fn raw_property(event: &EVENT_RECORD, name: &str) -> io::Result<Vec<u8>> {
    let name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let descriptor = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name.as_ptr() as usize as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let mut length = 0;
    status(unsafe { TdhGetPropertySize(event, 0, ptr::null(), 1, &descriptor, &mut length) })?;
    if length as usize > MAX_PROPERTY_BYTES {
        return Err(io::Error::other("TDH field exceeds transient bound"));
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    let mut bytes = vec![0; length as usize];
    status(unsafe {
        TdhGetProperty(
            event,
            0,
            ptr::null(),
            1,
            &descriptor,
            length,
            bytes.as_mut_ptr(),
        )
    })?;
    Ok(bytes)
}
fn scalar(
    event: &EVENT_RECORD,
    shape: &Schema,
    name: &str,
    kind: i32,
    width: usize,
) -> io::Result<u32> {
    let field = shape.field(name)?;
    if field.Flags != 0 || unsafe { field.Anonymous1.nonStructType.InType } != kind as u16 {
        return Err(io::Error::other("TDH scalar type/flags differ"));
    }
    let bytes = raw_property(event, name)?;
    if bytes.len() != width {
        return Err(io::Error::other("TDH scalar extent differs"));
    }
    let mut output = [0; 4];
    output[..width].copy_from_slice(&bytes);
    Ok(u32::from_le_bytes(output))
}
fn text(event: &EVENT_RECORD, shape: &Schema, name: &str, max: usize) -> io::Result<Vec<u16>> {
    let field = shape.field(name)?;
    if field.Flags != 0
        || unsafe { field.Anonymous1.nonStructType.InType } != TDH_INTYPE_UNICODESTRING as u16
    {
        return Err(io::Error::other("TDH text type differs"));
    }
    let bytes = raw_property(event, name)?;
    if bytes.len() % 2 != 0 || bytes.len() < 2 || bytes.len() > 2 * (max + 1) {
        return Err(io::Error::other("TDH text extent differs"));
    }
    let mut units = bytes
        .chunks_exact(2)
        .map(|part| u16::from_le_bytes([part[0], part[1]]))
        .collect::<Vec<_>>();
    if units.pop() != Some(0) || units.contains(&0) || String::from_utf16(&units).is_err() {
        return Err(io::Error::other("TDH text malformed"));
    }
    Ok(units)
}
fn decode(
    event: &EVENT_RECORD,
    spec: &ConsumerSpec,
    stage: &mut DecodeStage,
) -> io::Result<Option<Row>> {
    *stage = DecodeStage::Schema;
    let shape = schema(event)?;
    *stage = DecodeStage::ObjectNames;
    let object_name = text(event, &shape, "ObjectName", 512)?;
    if object_name != spec.object_name {
        return Ok(None);
    }
    let object_type = text(event, &shape, "ObjectType", 64)?;
    let mut fields = Vec::new();
    *stage = DecodeStage::SensitiveFields;
    for field in SensitiveField::ALL {
        let property = shape.field(field.name())?;
        let count = if let Some(count_name) = field.count_name() {
            let count_kind = if matches!(field, SensitiveField::Dacl | SensitiveField::Sacl) {
                TDH_INTYPE_UINT16
            } else {
                TDH_INTYPE_UINT32
            };
            let count = scalar(
                event,
                &shape,
                count_name,
                count_kind,
                if count_kind == TDH_INTYPE_UINT16 {
                    2
                } else {
                    4
                },
            )?;
            if property.Flags != PropertyParamCount
                || unsafe { property.Anonymous2.countPropertyIndex } as usize
                    != *shape
                        .fields
                        .get(count_name)
                        .ok_or_else(|| io::Error::other("count property absent"))?
            {
                return Err(io::Error::other("TDH counted field reference differs"));
            }
            count
        } else {
            if property.Flags != 0
                || unsafe { property.Anonymous1.nonStructType.InType } != TDH_INTYPE_SID as u16
            {
                return Err(io::Error::other("TDH owner/group SID type differs"));
            }
            1
        };
        if count > 256 {
            return Err(io::Error::other("TDH sensitive field count exceeds bound"));
        }
        let bytes = raw_property(event, field.name())?;
        if matches!(field, SensitiveField::Owner | SensitiveField::Group) {
            validate_sid_extent(&bytes).map_err(io::Error::other)?;
        }
        if (count == 0 && !bytes.is_empty()) || (count > 0 && bytes.len() < count as usize) {
            return Err(io::Error::other("TDH counted field extent differs"));
        }
        fields.push(SanitizedField {
            field,
            in_type: unsafe { property.Anonymous1.nonStructType.InType },
            out_type: unsafe { property.Anonymous1.nonStructType.OutType },
            count,
            bytes: bytes.len() as u32,
            sha256: Sha256::digest(&bytes).into(),
        });
    }
    *stage = DecodeStage::Scalars;
    let row = Row {
        qpc: event.EventHeader.TimeStamp as u64,
        pid: event.EventHeader.ProcessId,
        tid: event.EventHeader.ThreadId,
        access_mask: scalar(event, &shape, "AccessMask", TDH_INTYPE_HEXINT32, 4)?,
        object_type,
        object_name,
        token_type: scalar(event, &shape, "TokenType", TDH_INTYPE_UINT32, 4)?,
        impersonation_level: scalar(event, &shape, "ImpersonationLevel", TDH_INTYPE_UINT32, 4)?,
        session_id: scalar(event, &shape, "SessionId", TDH_INTYPE_UINT32, 4)?,
        security_descriptor_revision: scalar(
            event,
            &shape,
            "SecurityDescriptorRevision",
            TDH_INTYPE_UINT8,
            1,
        )? as u8,
        security_descriptor_control: scalar(
            event,
            &shape,
            "SecurityDescriptorControl",
            TDH_INTYPE_UINT16,
            2,
        )? as u16,
        sensitive_fields: fields,
    };
    *stage = DecodeStage::RowValidation;
    row.validate(spec).map_err(io::Error::other)?;
    Ok(Some(row))
}
struct Context {
    observation: Observation,
    failed: bool,
}
unsafe extern "system" fn callback(event: *mut EVENT_RECORD) {
    if event.is_null() {
        return;
    }
    let event = unsafe { &*event };
    if event.UserContext.is_null() {
        return;
    }
    let context = unsafe { &mut *event.UserContext.cast::<Context>() };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let header = &event.EventHeader;
        // No payload or TDH inspection before the exact held PID/provider filter.
        if !same_guid(&header.ProviderId, &PROVIDER_GUID)
            || header.ProcessId != context.observation.spec.pid
            || header.EventDescriptor.Id != 14
        {
            return;
        }
        context.observation.matched_events = context.observation.matched_events.saturating_add(1);
        if header.TimeStamp <= 0
            || header.TimeStamp as u64 > context.observation.spec.binding.cutoff_qpc
        {
            context.observation.cutoff_reached = true;
            context.observation.unsupported_events =
                context.observation.unsupported_events.saturating_add(1);
            return;
        }
        if header.EventDescriptor.Version != 0
            || header.EventDescriptor.Keyword & KEYWORD != KEYWORD
            || header.EventDescriptor.Level != 2
            || event.UserDataLength == 0
            || event.UserData.is_null()
        {
            context.observation.last_decode_stage = Some(DecodeStage::EventIdentity);
            context.observation.unsupported_events =
                context.observation.unsupported_events.saturating_add(1);
            return;
        }
        let mut stage = DecodeStage::Schema;
        match decode(event, &context.observation.spec, &mut stage) {
            Ok(Some(row)) => {
                if context.observation.rows.len() == MAX_ROWS {
                    context.observation.overflow = context.observation.overflow.saturating_add(1);
                } else {
                    context.observation.rows.push(row);
                }
            }
            Ok(None) => {
                context.observation.filtered_objects =
                    context.observation.filtered_objects.saturating_add(1);
            }
            Err(error) => {
                context.observation.unsupported_events =
                    context.observation.unsupported_events.saturating_add(1);
                context.observation.last_native_error =
                    error.raw_os_error().map(|code| code as u32);
                context.observation.last_decode_stage = Some(stage);
            }
        }
    }));
    if result.is_err() {
        context.failed = true;
        context.observation.last_decode_stage = Some(DecodeStage::CallbackPanic);
        context.observation.unsupported_events =
            context.observation.unsupported_events.saturating_add(1);
    }
}
/// Only the separately supervised consumer process may block in this function.
pub fn consume(
    spec: &ConsumerSpec,
    ready: impl FnOnce(io::Result<()>) -> io::Result<()>,
) -> io::Result<Observation> {
    spec.validate().map_err(io::Error::other)?;
    let mut context = Box::new(Context {
        observation: Observation::new(spec.clone()),
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
        let primary = error
            .raw_os_error()
            .map(io::Error::from_raw_os_error)
            .unwrap_or_else(|| io::Error::other("OpenTrace unavailable without native status"));
        return match ready(Err(error)) {
            Ok(()) => Err(primary),
            Err(secondary) => Err(io::Error::new(
                primary.kind(),
                Secondary { primary, secondary },
            )),
        };
    }
    if let Err(error) = ready(Ok(())) {
        let closed = unsafe { CloseTrace(handle) };
        return if closed == 0 {
            Err(error)
        } else {
            Err(io::Error::new(
                error.kind(),
                Secondary {
                    primary: error,
                    secondary: io::Error::from_raw_os_error(closed as i32),
                },
            ))
        };
    }
    let result = unsafe { ProcessTrace(&handle, 1, ptr::null(), ptr::null()) };
    let closed = unsafe { CloseTrace(handle) };
    context.observation.consumer_completed = !context.failed;
    context.observation.process_trace_status = result;
    context.observation.close_trace_status = closed;
    context.observation.validate().map_err(io::Error::other)?;
    Ok(context.observation)
}
