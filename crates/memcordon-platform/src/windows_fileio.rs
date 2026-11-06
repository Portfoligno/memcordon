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
    retention: RetentionMode,
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
            retention: RetentionMode::Prefix,
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
    pub fn with_retention_mode(mut self, retention: RetentionMode) -> Self {
        self.retention = retention;
        self
    }
    pub fn start(self) -> io::Result<OwnedFileIoSession> {
        let Self {
            pid,
            birth,
            binding,
            work,
            cleanup,
            retention,
        } = self;
        live(work)?;
        let nonce = tempfile::Builder::new().prefix("mc-fileio-").tempdir()?;
        let digest =
            Sha256::digest(format!("{:?}-{pid}-{birth}-{}", nonce.path(), tick()?).as_bytes());
        let mut unique = [0; 16];
        unique.copy_from_slice(&digest[..16]);
        let name = format!("Memcordon-FileIo-{:032x}", u128::from_be_bytes(unique));
        let spec = ConsumerSpec {
            version: 2,
            retention,
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
    metadata: Metadata,
}
// This owns only the already-returned bounded TDH metadata, never event data.
struct Metadata {
    words: Vec<u64>,
    length: usize,
}
impl Metadata {
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.length) }
    }
    fn info(&self) -> &TRACE_EVENT_INFO {
        unsafe { &*self.words.as_ptr().cast() }
    }
    fn property(&self, index: usize) -> Option<EVENT_PROPERTY_INFO> {
        let offset = offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray)
            .checked_add(index.checked_mul(size_of::<EVENT_PROPERTY_INFO>())?)?;
        if offset.checked_add(size_of::<EVENT_PROPERTY_INFO>())? > self.length {
            return None;
        }
        Some(unsafe { ptr::read_unaligned(self.bytes().as_ptr().add(offset).cast()) })
    }
    fn preview(&self) -> SchemaPreview {
        let info = self.info();
        let mut properties = Vec::with_capacity(8);
        for index in 0..info.PropertyCount.min(8) {
            let Some(property) = self.property(index as usize) else {
                break;
            };
            let (name_prefix, name_units, name_truncated, name_unavailable) =
                metadata_name(self.bytes(), property.NameOffset as usize);
            // Unsupported unions remain opaque; flags alone explain their rejection.
            let (in_type, out_type) = if property.Flags == 0 {
                let scalar = unsafe { property.Anonymous1.nonStructType };
                (Some(scalar.InType), Some(scalar.OutType))
            } else {
                (None, None)
            };
            properties.push(PropertyPreview {
                index,
                flags: property.Flags as u32,
                in_type,
                out_type,
                name_prefix,
                name_units,
                name_truncated,
                name_unavailable,
            });
        }
        SchemaPreview {
            decoding_source: info.DecodingSource,
            provider_guid: guid_bytes(&info.ProviderGuid),
            event_guid: guid_bytes(&info.EventGuid),
            descriptor_id: info.EventDescriptor.Id,
            descriptor_version: info.EventDescriptor.Version,
            descriptor_opcode: info.EventDescriptor.Opcode,
            property_count: info.PropertyCount,
            top_level_property_count: info.TopLevelPropertyCount,
            properties_omitted: info.PropertyCount.saturating_sub(properties.len() as u32),
            properties,
        }
    }
}
fn guid_bytes(value: &GUID) -> [u8; 16] {
    ((u128::from(value.data1) << 96)
        | (u128::from(value.data2) << 80)
        | (u128::from(value.data3) << 64)
        | u128::from(u64::from_be_bytes(value.data4)))
    .to_be_bytes()
}
fn metadata_name(bytes: &[u8], offset: usize) -> (Vec<u16>, Option<u32>, bool, bool) {
    if offset % 2 != 0 || offset >= bytes.len() {
        return (vec![], None, false, true);
    }
    let units = bytes[offset..].chunks_exact(2);
    let Some(length) = units
        .clone()
        .position(|pair| u16::from_le_bytes([pair[0], pair[1]]) == 0)
    else {
        return (vec![], None, false, true);
    };
    (
        units
            .take(length.min(32))
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect(),
        Some(length as u32),
        length > 32,
        false,
    )
}
struct NativeRejection {
    detail: DecodeRejection,
    metadata: Option<Metadata>,
}
impl NativeRejection {
    fn new(stage: RejectStage, field: Option<FieldId>) -> Self {
        let mut detail = DecodeRejection::new(stage);
        detail.field = field;
        Self {
            detail,
            metadata: None,
        }
    }
    fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = Some(metadata);
        self
    }
    fn status(stage: RejectStage, field: Option<FieldId>, status: u32) -> Self {
        let mut value = Self::new(stage, field);
        value.detail.native_status = Some(status);
        value
    }
}
type Decoded<T> = Result<T, NativeRejection>;
fn schema(event: &EVENT_RECORD) -> Decoded<Schema> {
    let mut length = 0;
    let result =
        unsafe { TdhGetEventInformation(event, 0, ptr::null(), ptr::null_mut(), &mut length) };
    if result != ERROR_INSUFFICIENT_BUFFER {
        let mut failure = NativeRejection::status(RejectStage::SchemaSizeQuery, None, result);
        failure.detail.returned_bytes = Some(length);
        return Err(failure);
    }
    if length as usize > 65536 || (length as usize) < size_of::<TRACE_EVENT_INFO>() {
        let mut failure = NativeRejection::new(RejectStage::SchemaExtent, None);
        failure.detail.required_bytes = Some(size_of::<TRACE_EVENT_INFO>() as u32);
        failure.detail.returned_bytes = Some(length);
        return Err(failure);
    }
    let mut words = vec![0u64; (length as usize).div_ceil(8)];
    let capacity = length;
    let result = unsafe {
        TdhGetEventInformation(
            event,
            0,
            ptr::null(),
            words.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        let mut failure = NativeRejection::status(RejectStage::SchemaRead, None, result);
        failure.detail.required_bytes = Some(capacity);
        failure.detail.returned_bytes = Some(length);
        return Err(failure);
    }
    if length > capacity || (length as usize) < size_of::<TRACE_EVENT_INFO>() {
        let mut failure = NativeRejection::new(RejectStage::SchemaExtent, None);
        failure.detail.required_bytes = Some(capacity);
        failure.detail.returned_bytes = Some(length);
        return Err(failure);
    }
    let metadata = Metadata {
        words,
        length: length as usize,
    };
    let info = metadata.info();
    // Classic TDH metadata identifies the MOF class through EventGuid; its
    // controlling provider GUID need not equal that class GUID.
    if !same_guid(&info.ProviderGuid, &event.EventHeader.ProviderId)
        && !same_guid(&info.EventGuid, &event.EventHeader.ProviderId)
    {
        return Err(NativeRejection::new(RejectStage::SchemaIdentity, None).with_metadata(metadata));
    }
    if info.EventDescriptor.Version != event.EventHeader.EventDescriptor.Version
        || info.EventDescriptor.Opcode != event.EventHeader.EventDescriptor.Opcode
    {
        return Err(
            NativeRejection::new(RejectStage::SchemaDescriptor, None).with_metadata(metadata)
        );
    }
    if info.PropertyCount != info.TopLevelPropertyCount || info.PropertyCount > 32 {
        return Err(
            NativeRejection::new(RejectStage::SchemaInventory, None).with_metadata(metadata)
        );
    }
    let mut fields = std::collections::BTreeMap::new();
    for index in 0..info.PropertyCount as usize {
        let Some(property) = metadata.property(index) else {
            return Err(
                NativeRejection::new(RejectStage::PropertyExtent, None).with_metadata(metadata)
            );
        };
        if property.Flags != 0 {
            return Err(
                NativeRejection::new(RejectStage::PropertyFlags, None).with_metadata(metadata)
            );
        }
        let name = read_utf16(metadata.bytes(), property.NameOffset as usize)
            .ok()
            .and_then(|units| String::from_utf16(&units).ok());
        let Some(name) = name else {
            return Err(
                NativeRejection::new(RejectStage::PropertyName, None).with_metadata(metadata)
            );
        };
        if fields
            .insert(name, unsafe { property.Anonymous1.nonStructType.InType })
            .is_some()
        {
            return Err(
                NativeRejection::new(RejectStage::DuplicateProperty, None).with_metadata(metadata)
            );
        }
    }
    Ok(Schema { fields, metadata })
}
fn property(
    event: &EVENT_RECORD,
    schema: &Schema,
    field: FieldId,
    types: &[i32],
) -> Decoded<Vec<u8>> {
    let name = field.name();
    if !schema
        .fields
        .get(name)
        .is_some_and(|kind| types.contains(&i32::from(*kind)))
    {
        let mut failure = NativeRejection::new(RejectStage::PropertyType, Some(field));
        failure.detail.expected_type = (types.len() == 1).then_some(types[0] as u16);
        failure.detail.actual_type = schema.fields.get(name).copied();
        return Err(failure);
    }
    let name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let descriptor = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name.as_ptr() as usize as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let mut length = 0;
    let result = unsafe { TdhGetPropertySize(event, 0, ptr::null(), 1, &descriptor, &mut length) };
    if result != 0 {
        let mut failure = NativeRejection::status(RejectStage::PropertySize, Some(field), result);
        failure.detail.returned_bytes = Some(length);
        return Err(failure);
    }
    if length == 0 || length > 65536 {
        let mut failure = NativeRejection::new(RejectStage::PropertySize, Some(field));
        failure.detail.returned_bytes = Some(length);
        return Err(failure);
    }
    let mut data = vec![0; length as usize];
    let result = unsafe {
        TdhGetProperty(
            event,
            0,
            ptr::null(),
            1,
            &descriptor,
            length,
            data.as_mut_ptr(),
        )
    };
    if result != 0 {
        let mut failure = NativeRejection::status(RejectStage::PropertyRead, Some(field), result);
        failure.detail.required_bytes = Some(length);
        return Err(failure);
    }
    Ok(data)
}
fn scalar(event: &EVENT_RECORD, schema: &Schema, field: FieldId, pointer: bool) -> Decoded<u64> {
    let data = property(
        event,
        schema,
        field,
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
            return Err(NativeRejection::new(RejectStage::PointerWidth, Some(field)));
        }
    } else {
        4
    };
    crate::windows_fileio_record::pointer(&data, width).map_err(|_| {
        let mut failure = NativeRejection::new(RejectStage::ScalarExtent, Some(field));
        failure.detail.expected_width = Some(width as u8);
        failure.detail.actual_width = Some(data.len() as u32);
        failure
    })
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
    let opcode = header.EventDescriptor.Opcode;
    collector.received(opcode);
    let decoded = (|| -> Decoded<()> {
        if !matches!(header.EventDescriptor.Version, 2 | 3) {
            return Err(NativeRejection::new(RejectStage::EventVersion, None));
        }
        let shape = schema(event)?;
        let result = (|| -> Decoded<()> {
            let irp = scalar(event, &shape, FieldId::IrpPtr, true)?;
            if header.EventDescriptor.Opcode == 76 {
                collector.completion(Completion {
                    irp,
                    qpc: header.TimeStamp as u64,
                    extra_info: scalar(event, &shape, FieldId::ExtraInfo, true)?,
                    ntstatus: scalar(event, &shape, FieldId::NtStatus, false)? as u32 as i32,
                });
                return Ok(());
            }
            let path = property(
                event,
                &shape,
                FieldId::OpenPath,
                &[TDH_INTYPE_UNICODESTRING],
            )?;
            let units = path_units(&path).map_err(|_| {
                let mut failure =
                    NativeRejection::new(RejectStage::PathEncoding, Some(FieldId::OpenPath));
                failure.detail.returned_bytes = Some(path.len() as u32);
                failure
            })?;
            let full = units.as_slice();
            let mut hash = Sha256::new();
            for unit in full {
                hash.update(unit.to_le_bytes());
            }
            let ttid_pointer = match shape.fields.get("TTID").copied().map(i32::from) {
                Some(TDH_INTYPE_POINTER) => true,
                Some(TDH_INTYPE_UINT32 | TDH_INTYPE_HEXINT32) => false,
                actual => {
                    let mut failure =
                        NativeRejection::new(RejectStage::PropertyType, Some(FieldId::Ttid));
                    failure.detail.actual_type = actual.map(|value| value as u16);
                    return Err(failure);
                }
            };
            let ttid =
                thread_id(scalar(event, &shape, FieldId::Ttid, ttid_pointer)?).map_err(|_| {
                    let mut failure =
                        NativeRejection::new(RejectStage::ThreadId, Some(FieldId::Ttid));
                    failure.detail.expected_width = Some(4);
                    failure
                })?;
            collector.create(Create {
                irp,
                qpc: header.TimeStamp as u64,
                header_pid: header.ProcessId,
                header_tid: header.ThreadId,
                ttid,
                file_object: scalar(event, &shape, FieldId::FileObject, true)?,
                create_options: scalar(event, &shape, FieldId::CreateOptions, false)? as u32,
                file_attributes: scalar(event, &shape, FieldId::FileAttributes, false)? as u32,
                share_access: scalar(event, &shape, FieldId::ShareAccess, false)? as u32,
                path_prefix: full[..full.len().min(128)].to_vec(),
                path_units: full.len() as u32,
                path_sha256: Some(hash.finalize().into()),
                path_truncated: full.len() > 128,
            });
            Ok(())
        })();
        result.map_err(|failure| failure.with_metadata(shape.metadata))
    })();
    match decoded {
        Ok(()) => collector.decoded(opcode),
        Err(failure) => {
            let metadata = if collector.wants_sample(
                opcode,
                header.EventDescriptor.Version,
                failure.detail.stage,
                failure.detail.field,
            ) {
                failure.metadata.as_ref().map(Metadata::preview)
            } else {
                None
            };
            collector.rejected(RejectSample {
                opcode,
                event_version: header.EventDescriptor.Version,
                header_flags: header.Flags,
                user_data_length: event.UserDataLength,
                rejection: failure.detail,
                metadata,
            });
        }
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
