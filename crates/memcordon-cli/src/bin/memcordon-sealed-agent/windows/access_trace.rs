use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::ptr::null;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND, FILETIME, HANDLE,
};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_DISABLE_PROVIDER,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD, EVENT_TRACE_CONTROL_QUERY,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, FlushTraceW, OpenTraceW,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
    PROPERTY_DATA_DESCRIPTOR, ProcessTrace, StartTraceW, TRACE_LEVEL_VERBOSE, TdhGetProperty,
    TdhGetPropertySize, WNODE_FLAG_TRACED_GUID,
};
use windows_sys::Win32::System::Threading::{GetProcessId, GetProcessTimes};
use windows_sys::core::GUID;

const KERNEL_FILE_PROVIDER: GUID = GUID::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);
const FILE_CREATE_EVENT_ID: u16 = 12;
const FILE_OPERATION_END_EVENT_ID: u16 = 24;
const FILE_CREATE_EVENT_VERSIONS: [u8; 2] = [0, 1];
const FILE_OPERATION_END_EVENT_VERSION: u8 = 0;
const INFO_OPCODE: u8 = 0;
const KERNEL_FILE_KEYWORD_OPERATION_END: u64 = 0x40;
const KERNEL_FILE_KEYWORD_CREATE: u64 = 0x80;
const MAX_TRACE_EVENTS: usize = 4_096;
#[cfg(test)]
pub(crate) const MAX_TRACE_EVENTS_FOR_TEST: usize = MAX_TRACE_EVENTS;
const MAX_EVENT_PAYLOAD_BYTES: usize = 4_096;
const MAX_PENDING_OPERATIONS: usize = 1_024;
const MAX_FRONTIER_EVENTS: usize = 64;
const MAX_BROKER_DIAGNOSTIC_FRONTIER: usize = 2;
#[cfg(test)]
pub(crate) const MAX_FRONTIER_EVENTS_FOR_TEST: usize = MAX_FRONTIER_EVENTS;
const MAX_RENDERED_BYTES: usize = 32_768;
const MAX_SUBJECT_WINDOW: Duration = Duration::from_secs(45);
const MAX_TRACE_SESSION: Duration = Duration::from_secs(180);
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_NAME_CAPACITY: usize = 128;
const STATUS_ACCESS_DENIED: i32 = 0xc000_0022_u32 as i32;
const COVERAGE: &str = "kernel-file-create-operation-end/no-requested-access";

static SESSION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PassiveAccessLocalizationSetupStageV1 {
    SessionStart,
    ProviderEnable,
    ConsumerOpen,
    ConsumerReady,
}

impl PassiveAccessLocalizationSetupStageV1 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::SessionStart => "session-start",
            Self::ProviderEnable => "provider-enable",
            Self::ConsumerOpen => "consumer-open",
            Self::ConsumerReady => "consumer-ready",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PassiveAccessLocalizationCleanupStatusV1 {
    NotAttempted,
    Native(u32),
    WorkerPanicked,
}

impl PassiveAccessLocalizationCleanupStatusV1 {
    const fn successful_or_not_attempted(self) -> bool {
        matches!(self, Self::NotAttempted | Self::Native(ERROR_SUCCESS))
    }

    const fn not_attempted(self) -> bool {
        matches!(self, Self::NotAttempted)
    }

    fn diagnostic(self) -> String {
        match self {
            Self::NotAttempted => "not-attempted".to_owned(),
            Self::Native(status) => status.to_string(),
            Self::WorkerPanicked => "worker-panicked".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PassiveAccessLocalizationSetupErrorV1 {
    stage: PassiveAccessLocalizationSetupStageV1,
    win32_status: Option<i64>,
    session_created: bool,
    provider_enable_attempted: bool,
    consumer_opened: bool,
    consumer_ready: bool,
    session_name_sha256: String,
    cleanup_provider_disable_status: PassiveAccessLocalizationCleanupStatusV1,
    cleanup_stop_status: PassiveAccessLocalizationCleanupStatusV1,
    cleanup_close_status: PassiveAccessLocalizationCleanupStatusV1,
    cleanup_process_trace_status: PassiveAccessLocalizationCleanupStatusV1,
    cleanup_absence_query_status: PassiveAccessLocalizationCleanupStatusV1,
    session_absence_proven: bool,
    detail_sha256: String,
}

impl PassiveAccessLocalizationSetupErrorV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        stage: PassiveAccessLocalizationSetupStageV1,
        win32_status: Option<i64>,
        session_created: bool,
        provider_enable_attempted: bool,
        consumer_opened: bool,
        consumer_ready: bool,
        session_name_sha256: String,
        cleanup_provider_disable_status: PassiveAccessLocalizationCleanupStatusV1,
        cleanup_stop_status: PassiveAccessLocalizationCleanupStatusV1,
        cleanup_close_status: PassiveAccessLocalizationCleanupStatusV1,
        cleanup_process_trace_status: PassiveAccessLocalizationCleanupStatusV1,
        cleanup_absence_query_status: PassiveAccessLocalizationCleanupStatusV1,
        session_absence_proven: bool,
        detail: &[u8],
    ) -> Self {
        Self {
            stage,
            win32_status,
            session_created,
            provider_enable_attempted,
            consumer_opened,
            consumer_ready,
            session_name_sha256,
            cleanup_provider_disable_status,
            cleanup_stop_status,
            cleanup_close_status,
            cleanup_process_trace_status,
            cleanup_absence_query_status,
            session_absence_proven,
            detail_sha256: super::record::digest(detail),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PassiveAccessLocalizationCellV1 {
    CanonicalSameAccess,
    TargetUser,
}

impl PassiveAccessLocalizationCellV1 {
    fn diagnostic(self) -> &'static str {
        match self {
            Self::CanonicalSameAccess => "canonical-same-access",
            Self::TargetUser => "target-user-singleton",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SubjectIdentityV1 {
    cell: PassiveAccessLocalizationCellV1,
    process_id: u32,
    creation_time_100ns: u64,
    started: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingCreateV1 {
    cell: PassiveAccessLocalizationCellV1,
    object_name_sha256: String,
    ordinal: usize,
    event_version: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileOperationV1 {
    cell: PassiveAccessLocalizationCellV1,
    ordinal: usize,
    native_status: i32,
    object_name_sha256: String,
    create_event_version: u8,
    operation_end_event_version: u8,
}

fn file_object_name_digest(raw_name: &[u8]) -> String {
    let mut material = b"memcordon-passive-file-object-name-v1\0".to_vec();
    material.extend_from_slice(raw_name);
    super::record::digest(&material)
}

fn same_observed_file_operation(left: &FileOperationV1, right: &FileOperationV1) -> bool {
    left.object_name_sha256 == right.object_name_sha256
        && left.create_event_version == right.create_event_version
        && left.operation_end_event_version == right.operation_end_event_version
}

fn classify_completed_file_pairs(
    canonical: &[FileOperationV1],
    target_user: &[FileOperationV1],
) -> &'static str {
    let comparable = target_user.iter().any(|target| {
        canonical
            .iter()
            .any(|baseline| same_observed_file_operation(baseline, target))
    });
    let differential_denial = target_user.iter().any(|target| {
        target.native_status == STATUS_ACCESS_DENIED
            && canonical.iter().any(|baseline| {
                same_observed_file_operation(baseline, target)
                    && baseline.native_status != target.native_status
            })
    });
    if !comparable {
        "coverage-insufficient"
    } else if differential_denial {
        "candidate-file-denial-differential"
    } else {
        "file-domain-common"
    }
}

#[derive(Debug)]
struct TraceStateV1 {
    active: Option<SubjectIdentityV1>,
    total_events: usize,
    total_payload_bytes: usize,
    pending: HashMap<u64, PendingCreateV1>,
    frontier: Vec<FileOperationV1>,
    subject_bindings: Vec<(PassiveAccessLocalizationCellV1, String)>,
    unsupported_schema: Option<String>,
    overflow: Option<&'static str>,
    incomplete: bool,
    events_lost: u32,
    realtime_buffers_lost: u32,
    flush_failed: bool,
}

impl Default for TraceStateV1 {
    fn default() -> Self {
        Self {
            active: None,
            total_events: 0,
            total_payload_bytes: 0,
            pending: HashMap::new(),
            frontier: Vec::new(),
            subject_bindings: Vec::new(),
            unsupported_schema: None,
            overflow: None,
            incomplete: false,
            events_lost: 0,
            realtime_buffers_lost: 0,
            flush_failed: false,
        }
    }
}

fn push_completed_frontier_or_invalidate(state: &mut TraceStateV1, event: FileOperationV1) {
    if state.frontier.len() >= MAX_FRONTIER_EVENTS {
        state.overflow = Some("frontier-bound");
        state.incomplete = true;
        return;
    }
    state.frontier.push(event);
}

fn admit_subject_event_budget(state: &mut TraceStateV1, payload_bytes: usize) -> bool {
    state.total_events = state.total_events.saturating_add(1);
    state.total_payload_bytes = state.total_payload_bytes.saturating_add(payload_bytes);
    if state.total_events > MAX_TRACE_EVENTS
        || payload_bytes > MAX_EVENT_PAYLOAD_BYTES
        || state.total_payload_bytes > MAX_TRACE_EVENTS * MAX_EVENT_PAYLOAD_BYTES
    {
        state.overflow = Some("event-bound");
        state.incomplete = true;
        return false;
    }
    true
}

#[derive(Debug, Default)]
struct DrainBarrierStateV1 {
    processed_buffers: u64,
    requested_epoch: u64,
    acknowledged_epoch: u64,
    target_buffers: Option<u64>,
}

#[derive(Debug, Default)]
struct DrainBarrierV1 {
    state: Mutex<DrainBarrierStateV1>,
    changed: Condvar,
}

impl DrainBarrierV1 {
    fn request(&self) -> Option<u64> {
        let mut state = self.state.lock().ok()?;
        state.requested_epoch = state.requested_epoch.checked_add(1)?;
        state.target_buffers = None;
        Some(state.requested_epoch)
    }

    fn arm(&self, epoch: u64, target_buffers: u64) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if epoch != state.requested_epoch || epoch <= state.acknowledged_epoch {
            return false;
        }
        state.target_buffers = Some(target_buffers);
        if state.processed_buffers >= target_buffers {
            state.acknowledged_epoch = epoch;
            self.changed.notify_all();
        }
        true
    }

    fn buffer_completed(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.processed_buffers = state.processed_buffers.saturating_add(1);
        if let Some(target) = state.target_buffers {
            if state.processed_buffers >= target {
                state.acknowledged_epoch = state.requested_epoch;
                self.changed.notify_all();
            }
        }
    }

    fn acknowledged(&self, epoch: u64) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| state.acknowledged_epoch >= epoch)
    }

    fn wait(&self, epoch: u64, timeout: Duration) -> bool {
        let Ok(state) = self.state.lock() else {
            return false;
        };
        let Ok((state, _)) = self
            .changed
            .wait_timeout_while(state, timeout, |state| state.acknowledged_epoch < epoch)
        else {
            return false;
        };
        state.acknowledged_epoch >= epoch
    }
}

struct TraceCallbackContext {
    state: Arc<Mutex<TraceStateV1>>,
    drain: Arc<DrainBarrierV1>,
}

#[repr(C)]
struct TracePropertiesBuffer {
    properties: EVENT_TRACE_PROPERTIES,
    logger_name: [u16; SESSION_NAME_CAPACITY],
}

impl TracePropertiesBuffer {
    fn new(name: &[u16]) -> Result<Self, String> {
        if name.is_empty() || name.len() >= SESSION_NAME_CAPACITY || name.last() != Some(&0) {
            return Err("passive access-localization ETW session name is invalid".to_owned());
        }
        let mut buffer = Self {
            properties: EVENT_TRACE_PROPERTIES::default(),
            logger_name: [0; SESSION_NAME_CAPACITY],
        };
        buffer.logger_name[..name.len()].copy_from_slice(name);
        buffer.properties.Wnode.BufferSize = size_of::<Self>() as u32;
        buffer.properties.Wnode.ClientContext = 1;
        buffer.properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        buffer.properties.BufferSize = 64;
        buffer.properties.MinimumBuffers = 2;
        buffer.properties.MaximumBuffers = 16;
        buffer.properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        buffer.properties.FlushTimer = 1;
        buffer.properties.LoggerNameOffset = offset_of!(Self, logger_name) as u32;
        Ok(buffer)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TraceSessionCapabilityStageV1 {
    SessionStart,
    SessionStop,
}

impl TraceSessionCapabilityStageV1 {
    pub(super) const fn diagnostic(self) -> &'static str {
        match self {
            Self::SessionStart => "session-start",
            Self::SessionStop => "session-stop",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TraceSessionCapabilityNativeReceiptV1 {
    pub(super) stage: TraceSessionCapabilityStageV1,
    pub(super) session_name_sha256: String,
    pub(super) start_status: u32,
    pub(super) session_created: bool,
    pub(super) stop_attempted: bool,
    pub(super) stop_status: Option<u32>,
    pub(super) cleanup_count: u32,
    pub(super) session_absence_proven: bool,
}

struct StartedTraceSessionCapability {
    control_handle: CONTROLTRACE_HANDLE,
    properties: TracePropertiesBuffer,
    stop_status: Option<u32>,
    cleanup_count: u32,
}

impl StartedTraceSessionCapability {
    fn stop_once(&mut self) -> u32 {
        assert!(
            self.stop_status.is_none(),
            "trace-session capability STOP must be attempted exactly once"
        );
        let status = unsafe {
            ControlTraceW(
                self.control_handle,
                null(),
                &raw mut self.properties.properties,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        self.stop_status = Some(status);
        self.cleanup_count += 1;
        status
    }

    fn finish(mut self) -> (u32, u32) {
        let status = self.stop_once();
        (status, self.cleanup_count)
    }
}

impl Drop for StartedTraceSessionCapability {
    fn drop(&mut self) {
        if self.stop_status.is_none() {
            let status = self.stop_once();
            if status != ERROR_SUCCESS {
                eprintln!(
                    "MCSEALED-WINDOWS-SESSION-BROKER: trace-session capability emergency STOP failed: status={status}"
                );
            }
        }
    }
}

fn trace_session_capability_name(
    start_nonce: &str,
    transaction_nonce: &str,
    broker_process_id: u32,
    broker_creation_time_100ns: u64,
) -> (Vec<u16>, String) {
    let mut name_material = b"memcordon-session-broker-trace-capability-name-v1\0".to_vec();
    name_material.extend_from_slice(start_nonce.as_bytes());
    name_material.push(0);
    name_material.extend_from_slice(transaction_nonce.as_bytes());
    name_material.extend_from_slice(&broker_process_id.to_le_bytes());
    name_material.extend_from_slice(&broker_creation_time_100ns.to_le_bytes());
    let name_binding = super::record::digest(&name_material);
    let name = format!("MemCordon-Broker-Trace-Capability-{name_binding}");
    let mut session_name = name.encode_utf16().collect::<Vec<_>>();
    session_name.push(0);
    let mut session_name_bytes = Vec::with_capacity(session_name.len() * size_of::<u16>());
    for unit in &session_name {
        session_name_bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let mut digest_material =
        b"memcordon-session-broker-trace-capability-session-name-v1\0".to_vec();
    digest_material.extend_from_slice(&session_name_bytes);
    let session_name_sha256 = super::record::digest(&digest_material);
    (session_name, session_name_sha256)
}

pub(super) fn trace_session_capability_name_sha256(
    start_nonce: &str,
    transaction_nonce: &str,
    broker_process_id: u32,
    broker_creation_time_100ns: u64,
) -> String {
    trace_session_capability_name(
        start_nonce,
        transaction_nonce,
        broker_process_id,
        broker_creation_time_100ns,
    )
    .1
}

pub(super) fn run_trace_session_capability(
    start_nonce: &str,
    transaction_nonce: &str,
    broker_process_id: u32,
    broker_creation_time_100ns: u64,
) -> Result<TraceSessionCapabilityNativeReceiptV1, String> {
    let (session_name, session_name_sha256) = trace_session_capability_name(
        start_nonce,
        transaction_nonce,
        broker_process_id,
        broker_creation_time_100ns,
    );
    let mut properties = TracePropertiesBuffer::new(&session_name)?;
    let mut control_handle = CONTROLTRACE_HANDLE::default();
    let start_status = unsafe {
        StartTraceW(
            &raw mut control_handle,
            session_name.as_ptr(),
            &raw mut properties.properties,
        )
    };
    if start_status != ERROR_SUCCESS {
        return Ok(TraceSessionCapabilityNativeReceiptV1 {
            stage: TraceSessionCapabilityStageV1::SessionStart,
            session_name_sha256,
            start_status,
            session_created: false,
            stop_attempted: false,
            stop_status: None,
            cleanup_count: 0,
            session_absence_proven: start_status != ERROR_ALREADY_EXISTS,
        });
    }
    let guard = StartedTraceSessionCapability {
        control_handle,
        properties,
        stop_status: None,
        cleanup_count: 0,
    };
    let (stop_status, cleanup_count) = guard.finish();
    Ok(TraceSessionCapabilityNativeReceiptV1 {
        stage: TraceSessionCapabilityStageV1::SessionStop,
        session_name_sha256,
        start_status,
        session_created: true,
        stop_attempted: true,
        stop_status: Some(stop_status),
        cleanup_count,
        session_absence_proven: stop_status == ERROR_SUCCESS,
    })
}

pub(crate) struct PassiveAccessLocalizationObserverV1 {
    session_name: Vec<u16>,
    control_handle: CONTROLTRACE_HANDLE,
    processing_handle: PROCESSTRACE_HANDLE,
    callback_context: Box<TraceCallbackContext>,
    worker: Option<JoinHandle<u32>>,
    state: Arc<Mutex<TraceStateV1>>,
    drain: Arc<DrainBarrierV1>,
    cleanup_performed: bool,
    started: Instant,
}

pub(crate) struct PassiveAccessLocalizationSubjectGuardV1 {
    control_handle: CONTROLTRACE_HANDLE,
    state: Arc<Mutex<TraceStateV1>>,
    drain: Arc<DrainBarrierV1>,
    cell: PassiveAccessLocalizationCellV1,
    active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PassiveAccessLocalizationDrainReceiptV1 {
    pub(crate) flush_status: u32,
    pub(crate) barrier_requested: bool,
    pub(crate) barrier_armed: bool,
    pub(crate) barrier_acknowledged: bool,
    pub(crate) pending_empty: bool,
    pub(crate) detail_sha256: String,
}

impl PassiveAccessLocalizationDrainReceiptV1 {
    pub(crate) fn successful(&self) -> bool {
        self.flush_status == ERROR_SUCCESS
            && self.barrier_requested
            && self.barrier_armed
            && self.barrier_acknowledged
            && self.pending_empty
            && self.detail_sha256 == "none"
    }
}

#[derive(Clone, Debug)]
struct PassiveAccessLocalizationCleanupReceiptV1 {
    provider_disable: PassiveAccessLocalizationCleanupStatusV1,
    stop: PassiveAccessLocalizationCleanupStatusV1,
    process_trace: PassiveAccessLocalizationCleanupStatusV1,
    close: PassiveAccessLocalizationCleanupStatusV1,
    absence_query: PassiveAccessLocalizationCleanupStatusV1,
    session_absence_proven: bool,
    repeated: bool,
}

impl PassiveAccessLocalizationCleanupReceiptV1 {
    fn successful(&self) -> bool {
        !self.repeated
            && self.provider_disable
                == PassiveAccessLocalizationCleanupStatusV1::Native(ERROR_SUCCESS)
            && self.stop == PassiveAccessLocalizationCleanupStatusV1::Native(ERROR_SUCCESS)
            && self.process_trace == PassiveAccessLocalizationCleanupStatusV1::Native(ERROR_SUCCESS)
            && self.close == PassiveAccessLocalizationCleanupStatusV1::Native(ERROR_SUCCESS)
            && self.absence_query
                == PassiveAccessLocalizationCleanupStatusV1::Native(ERROR_WMI_INSTANCE_NOT_FOUND)
            && self.session_absence_proven
    }

    fn failure_detail(&self) -> Option<String> {
        (!self.successful()).then(|| {
            format!(
                "passive access-localization cleanup failed: repeated={} disable={} stop={} process_trace={} close={} absence_query={} absence_proven={}",
                self.repeated,
                self.provider_disable.diagnostic(),
                self.stop.diagnostic(),
                self.process_trace.diagnostic(),
                self.close.diagnostic(),
                self.absence_query.diagnostic(),
                self.session_absence_proven,
            )
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PassiveAccessLocalizationEvidenceV1 {
    pub(crate) classification: &'static str,
    pub(crate) cleanup_count: u32,
    pub(crate) detail_sha256: String,
    setup_stage: Option<PassiveAccessLocalizationSetupStageV1>,
    setup_win32_status: Option<i64>,
    session_created: bool,
    provider_enable_attempted: bool,
    consumer_opened: bool,
    consumer_ready: bool,
    schema_observed: bool,
    session_name_sha256: String,
    cleanup_provider_disable_status: PassiveAccessLocalizationCleanupStatusV1,
    cleanup_stop_status: PassiveAccessLocalizationCleanupStatusV1,
    cleanup_close_status: PassiveAccessLocalizationCleanupStatusV1,
    cleanup_process_trace_status: PassiveAccessLocalizationCleanupStatusV1,
    cleanup_absence_query_status: PassiveAccessLocalizationCleanupStatusV1,
    session_absence_proven: bool,
    subject_binding_sha256: String,
    canonical_events: usize,
    target_user_events: usize,
    frontier: Vec<FileOperationV1>,
    invalid: bool,
    unsupported_schema: bool,
    events_lost: u32,
    overflow: bool,
    incomplete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrokerPassiveFileOperationV1 {
    cell: String,
    ordinal: usize,
    native_status: i32,
    object_name_sha256: String,
    create_event_version: u8,
    operation_end_event_version: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrokerPassiveAccessEvidenceV1 {
    classification: String,
    cleanup_count: u32,
    detail_sha256: String,
    setup_stage: Option<String>,
    setup_win32_status: Option<i64>,
    session_created: bool,
    provider_enable_attempted: bool,
    consumer_opened: bool,
    consumer_ready: bool,
    schema_observed: bool,
    session_name_sha256: String,
    cleanup_provider_disable_status: String,
    cleanup_stop_status: String,
    cleanup_close_status: String,
    cleanup_process_trace_status: String,
    cleanup_absence_query_status: String,
    session_absence_proven: bool,
    subject_binding_sha256: String,
    canonical_events: usize,
    target_user_events: usize,
    frontier: Vec<BrokerPassiveFileOperationV1>,
    invalid: bool,
    unsupported_schema: bool,
    events_lost: u32,
    overflow: bool,
    incomplete: bool,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum BrokerPassiveAccessMutationForTest {
    MalformedObjectDigest,
    UnknownCell,
    UnsupportedVersion,
    CountMismatch,
    FalseDifferential,
    MissingSessionAbsence,
}

impl BrokerPassiveAccessEvidenceV1 {
    #[cfg(test)]
    pub(crate) fn for_test(classification: &str, invalid: bool) -> Self {
        let object_name_sha256 = file_object_name_digest(b"redacted-test-path");
        let mut frontier = Vec::new();
        if classification != "coverage-insufficient" {
            frontier.push(BrokerPassiveFileOperationV1 {
                cell: "canonical-same-access".to_owned(),
                ordinal: 1,
                native_status: 0,
                object_name_sha256: object_name_sha256.clone(),
                create_event_version: 1,
                operation_end_event_version: 0,
            });
        }
        frontier.push(BrokerPassiveFileOperationV1 {
            cell: "target-user-singleton".to_owned(),
            ordinal: 2,
            native_status: if classification == "candidate-file-denial-differential" {
                STATUS_ACCESS_DENIED
            } else {
                0
            },
            object_name_sha256,
            create_event_version: 1,
            operation_end_event_version: 0,
        });
        Self {
            classification: classification.to_owned(),
            cleanup_count: 1,
            detail_sha256: super::record::digest(b"broker-passive-trace-test-detail"),
            setup_stage: None,
            setup_win32_status: None,
            session_created: true,
            provider_enable_attempted: true,
            consumer_opened: true,
            consumer_ready: true,
            schema_observed: true,
            session_name_sha256: super::record::digest(b"broker-passive-trace-test-session"),
            cleanup_provider_disable_status: "0".to_owned(),
            cleanup_stop_status: "0".to_owned(),
            cleanup_close_status: "0".to_owned(),
            cleanup_process_trace_status: "0".to_owned(),
            cleanup_absence_query_status: ERROR_WMI_INSTANCE_NOT_FOUND.to_string(),
            session_absence_proven: true,
            subject_binding_sha256: super::record::digest(b"broker-passive-trace-test-subjects"),
            canonical_events: usize::from(classification != "coverage-insufficient"),
            target_user_events: 1,
            frontier,
            invalid,
            unsupported_schema: false,
            events_lost: 0,
            overflow: false,
            incomplete: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn max_frontier_for_test() -> Self {
        let mut evidence = Self::for_test("candidate-file-denial-differential", false);
        let pair_count = MAX_FRONTIER_EVENTS / 2;
        evidence.frontier.clear();
        for pair in 0..pair_count {
            let object_name_sha256 = file_object_name_digest(&pair.to_le_bytes());
            evidence.frontier.push(BrokerPassiveFileOperationV1 {
                cell: "canonical-same-access".to_owned(),
                ordinal: pair * 2 + 1,
                native_status: 0,
                object_name_sha256: object_name_sha256.clone(),
                create_event_version: 1,
                operation_end_event_version: 0,
            });
            evidence.frontier.push(BrokerPassiveFileOperationV1 {
                cell: "target-user-singleton".to_owned(),
                ordinal: pair * 2 + 2,
                native_status: if pair + 1 == pair_count {
                    STATUS_ACCESS_DENIED
                } else {
                    0
                },
                object_name_sha256,
                create_event_version: 1,
                operation_end_event_version: 0,
            });
        }
        evidence.canonical_events = pair_count;
        evidence.target_user_events = pair_count;
        evidence
    }

    #[cfg(test)]
    pub(crate) fn reordered_max_frontier_for_test() -> Self {
        let mut evidence = Self::max_frontier_for_test();
        evidence.frontier.reverse();
        evidence
    }

    #[cfg(test)]
    pub(crate) fn mutated_for_test(mutation: BrokerPassiveAccessMutationForTest) -> Self {
        let mut evidence = Self::for_test("candidate-file-denial-differential", false);
        match mutation {
            BrokerPassiveAccessMutationForTest::MalformedObjectDigest => {
                evidence.frontier[0].object_name_sha256 = "plaintext-path".to_owned();
            }
            BrokerPassiveAccessMutationForTest::UnknownCell => {
                evidence.frontier[0].cell = "unknown-cell".to_owned();
            }
            BrokerPassiveAccessMutationForTest::UnsupportedVersion => {
                evidence.frontier[0].create_event_version = 2;
            }
            BrokerPassiveAccessMutationForTest::CountMismatch => {
                evidence.canonical_events += 1;
            }
            BrokerPassiveAccessMutationForTest::FalseDifferential => {
                evidence.classification = "file-domain-common".to_owned();
            }
            BrokerPassiveAccessMutationForTest::MissingSessionAbsence => {
                evidence.session_absence_proven = false;
            }
        }
        evidence
    }

    #[cfg(test)]
    pub(crate) fn drained_subject_failure_for_test() -> Self {
        let mut evidence = Self::for_test("candidate-file-denial-differential", false);
        evidence.classification = "invalid-runtime".to_owned();
        evidence.detail_sha256 = super::record::digest(b"broker passive subject drain failed");
        evidence.frontier.clear();
        evidence.canonical_events = 0;
        evidence.target_user_events = 0;
        evidence.invalid = true;
        evidence.incomplete = true;
        evidence
    }

    pub(crate) fn classification(&self) -> &str {
        &self.classification
    }

    pub(crate) fn admissible(&self) -> bool {
        let Some((classification, _, _)) = self.validated_frontier_relation() else {
            return false;
        };
        !self.invalid
            && !self.unsupported_schema
            && self.cleanup_count == 1
            && self.cleanup_provider_disable_status == "0"
            && self.cleanup_stop_status == "0"
            && self.cleanup_close_status == "0"
            && self.cleanup_process_trace_status == "0"
            && self.cleanup_absence_query_status == ERROR_WMI_INSTANCE_NOT_FOUND.to_string()
            && self.session_absence_proven
            && self.session_created
            && self.provider_enable_attempted
            && self.consumer_opened
            && self.consumer_ready
            && self.schema_observed
            && self.setup_stage.is_none()
            && self.setup_win32_status.is_none()
            && self.events_lost == 0
            && !self.overflow
            && !self.incomplete
            && self.classification == classification
            && digest_or_none_valid(&self.detail_sha256)
            && super::record::validate_attempt_id(&self.subject_binding_sha256).is_ok()
            && super::record::validate_attempt_id(&self.session_name_sha256).is_ok()
    }

    pub(crate) fn diagnostic(&self) -> String {
        self.diagnostic_with_frontier(self.admissible())
    }

    pub(crate) fn diagnostic_without_frontier(&self) -> String {
        self.diagnostic_with_frontier(false)
    }

    fn diagnostic_with_frontier(&self, disclose_frontier: bool) -> String {
        let validated_frontier = self.validated_frontier_relation();
        let disclose_frontier =
            disclose_frontier && self.admissible() && validated_frontier.is_some();
        let witness = validated_frontier
            .as_ref()
            .and_then(|(_, _, witness)| *witness);
        let frontier = if disclose_frontier {
            witness
                .into_iter()
                .flat_map(|(canonical, target)| [canonical, target])
                .filter_map(|index| self.frontier.get(index))
                .map(|event| {
                    format!(
                        "{}:{}:file-create-id-12-v{}/operation-end-id-24-v{}:{:#010x}:{}:candidate-only",
                        event.ordinal,
                        event.cell,
                        event.create_event_version,
                        event.operation_end_event_version,
                        event.native_status as u32,
                        event.object_name_sha256,
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        } else {
            String::new()
        };
        let frontier_total = if disclose_frontier {
            self.frontier.len()
        } else {
            0
        };
        let frontier_retained = if disclose_frontier {
            usize::from(witness.is_some()) * MAX_BROKER_DIAGNOSTIC_FRONTIER
        } else {
            0
        };
        let frontier_render_overflow = frontier_total > frontier_retained;
        let frontier_sha256 = validated_frontier
            .as_ref()
            .map_or("unavailable", |(_, digest, _)| digest.as_str());
        let classification = if disclose_frontier {
            validated_frontier
                .as_ref()
                .map_or("invalid", |(value, _, _)| *value)
        } else {
            "invalid"
        };
        let detail_sha256 = if digest_or_none_valid(&self.detail_sha256) {
            self.detail_sha256.as_str()
        } else {
            "unavailable"
        };
        let subject_binding_sha256 = validated_digest_or_unavailable(&self.subject_binding_sha256);
        let session_name_sha256 = validated_digest_or_unavailable(&self.session_name_sha256);
        let cleanup_provider_disable_status =
            validated_cleanup_status_or_unavailable(&self.cleanup_provider_disable_status);
        let cleanup_stop_status =
            validated_cleanup_status_or_unavailable(&self.cleanup_stop_status);
        let cleanup_close_status =
            validated_cleanup_status_or_unavailable(&self.cleanup_close_status);
        let cleanup_process_trace_status =
            validated_cleanup_status_or_unavailable(&self.cleanup_process_trace_status);
        let cleanup_absence_query_status =
            validated_cleanup_status_or_unavailable(&self.cleanup_absence_query_status);
        let setup_stage = self
            .setup_stage
            .as_deref()
            .filter(|stage| {
                matches!(
                    *stage,
                    "session-start"
                        | "provider-enable"
                        | "consumer-open"
                        | "consumer-thread"
                        | "consumer-ready"
                )
            })
            .unwrap_or("none");
        let setup_win32_status = self
            .setup_win32_status
            .map_or_else(|| "none".to_owned(), |status| status.to_string());
        format!(
            "classification={} coverage={COVERAGE} requested_access_available=false unobserved_domains=registry,object-namespace-known-dll-section,alpc-csrss,other-providers setup_stage={} setup_win32_status={} session_created={} provider_enable_attempted={} consumer_opened={} consumer_ready={} schema_observed={} session_name_sha256={} cleanup_provider_disable_status={} cleanup_stop_status={} cleanup_close_status={} cleanup_process_trace_status={} cleanup_absence_query_status={} session_absence_proven={} cleanup_count={} subject_binding_sha256={} canonical_events={} target_user_events={} events_lost={} overflow={} incomplete={} frontier_total={} frontier_retained={} frontier_render_overflow={} frontier_sha256={} frontier=[{}] detail_sha256={} candidate_frontier_only=true exact_resource_identified=false acl_fix_identified=false object_values_redacted=true",
            classification,
            setup_stage,
            setup_win32_status,
            self.session_created,
            self.provider_enable_attempted,
            self.consumer_opened,
            self.consumer_ready,
            self.schema_observed,
            session_name_sha256,
            cleanup_provider_disable_status,
            cleanup_stop_status,
            cleanup_close_status,
            cleanup_process_trace_status,
            cleanup_absence_query_status,
            self.session_absence_proven,
            self.cleanup_count,
            subject_binding_sha256,
            self.canonical_events,
            self.target_user_events,
            self.events_lost,
            self.overflow,
            self.incomplete,
            frontier_total,
            frontier_retained,
            frontier_render_overflow,
            frontier_sha256,
            frontier,
            detail_sha256,
        )
    }

    fn validated_frontier_relation(
        &self,
    ) -> Option<(&'static str, String, Option<(usize, usize)>)> {
        if self.frontier.len() > MAX_FRONTIER_EVENTS
            || self.canonical_events
                != self
                    .frontier
                    .iter()
                    .filter(|event| event.cell == "canonical-same-access")
                    .count()
            || self.target_user_events
                != self
                    .frontier
                    .iter()
                    .filter(|event| event.cell == "target-user-singleton")
                    .count()
        {
            return None;
        }
        let mut ordinals = Vec::with_capacity(self.frontier.len());
        for event in &self.frontier {
            if !matches!(
                event.cell.as_str(),
                "canonical-same-access" | "target-user-singleton"
            ) || event.ordinal == 0
                || event.ordinal > MAX_TRACE_EVENTS
                || ordinals.contains(&event.ordinal)
                || !FILE_CREATE_EVENT_VERSIONS.contains(&event.create_event_version)
                || event.operation_end_event_version != FILE_OPERATION_END_EVENT_VERSION
                || super::record::validate_attempt_id(&event.object_name_sha256).is_err()
            {
                return None;
            }
            ordinals.push(event.ordinal);
        }
        let mut comparable_witness = None;
        let mut differential_witness = None;
        for (target_index, target) in self.frontier.iter().enumerate() {
            if target.cell != "target-user-singleton" {
                continue;
            }
            for (canonical_index, canonical) in self.frontier.iter().enumerate() {
                if canonical.cell != "canonical-same-access"
                    || !broker_file_operations_comparable(canonical, target)
                {
                    continue;
                }
                comparable_witness.get_or_insert((canonical_index, target_index));
                if target.native_status == STATUS_ACCESS_DENIED
                    && canonical.native_status != target.native_status
                {
                    differential_witness.get_or_insert((canonical_index, target_index));
                }
            }
        }
        let (classification, witness) = if comparable_witness.is_none() {
            ("coverage-insufficient", None)
        } else if let Some(witness) = differential_witness {
            ("candidate-file-denial-differential", Some(witness))
        } else {
            ("file-domain-common", comparable_witness)
        };
        let mut material = b"memcordon-broker-passive-frontier-v1\0".to_vec();
        material.extend_from_slice(&(self.frontier.len() as u64).to_le_bytes());
        for event in &self.frontier {
            material.extend_from_slice(event.cell.as_bytes());
            material.push(0);
            material.extend_from_slice(&(event.ordinal as u64).to_le_bytes());
            material.extend_from_slice(&event.native_status.to_le_bytes());
            material.extend_from_slice(event.object_name_sha256.as_bytes());
            material.push(event.create_event_version);
            material.push(event.operation_end_event_version);
        }
        Some((classification, super::record::digest(&material), witness))
    }
}

fn broker_file_operations_comparable(
    left: &BrokerPassiveFileOperationV1,
    right: &BrokerPassiveFileOperationV1,
) -> bool {
    left.object_name_sha256 == right.object_name_sha256
        && left.create_event_version == right.create_event_version
        && left.operation_end_event_version == right.operation_end_event_version
}

fn validated_digest_or_unavailable(value: &str) -> &str {
    if super::record::validate_attempt_id(value).is_ok() {
        value
    } else {
        "unavailable"
    }
}

fn validated_cleanup_status_or_unavailable(value: &str) -> &str {
    if value == "not-attempted"
        || value
            .parse::<u32>()
            .is_ok_and(|status| status.to_string() == value)
    {
        value
    } else {
        "unavailable"
    }
}

fn digest_or_none_valid(value: &str) -> bool {
    value == "none" || super::record::validate_attempt_id(value).is_ok()
}

impl PassiveAccessLocalizationEvidenceV1 {
    pub(crate) fn into_broker_evidence(self) -> BrokerPassiveAccessEvidenceV1 {
        BrokerPassiveAccessEvidenceV1 {
            classification: self.classification.to_owned(),
            cleanup_count: self.cleanup_count,
            detail_sha256: self.detail_sha256,
            setup_stage: self.setup_stage.map(|stage| stage.diagnostic().to_owned()),
            setup_win32_status: self.setup_win32_status,
            session_created: self.session_created,
            provider_enable_attempted: self.provider_enable_attempted,
            consumer_opened: self.consumer_opened,
            consumer_ready: self.consumer_ready,
            schema_observed: self.schema_observed,
            session_name_sha256: self.session_name_sha256,
            cleanup_provider_disable_status: self.cleanup_provider_disable_status.diagnostic(),
            cleanup_stop_status: self.cleanup_stop_status.diagnostic(),
            cleanup_close_status: self.cleanup_close_status.diagnostic(),
            cleanup_process_trace_status: self.cleanup_process_trace_status.diagnostic(),
            cleanup_absence_query_status: self.cleanup_absence_query_status.diagnostic(),
            session_absence_proven: self.session_absence_proven,
            subject_binding_sha256: self.subject_binding_sha256,
            canonical_events: self.canonical_events,
            target_user_events: self.target_user_events,
            frontier: self
                .frontier
                .into_iter()
                .map(|event| BrokerPassiveFileOperationV1 {
                    cell: event.cell.diagnostic().to_owned(),
                    ordinal: event.ordinal,
                    native_status: event.native_status,
                    object_name_sha256: event.object_name_sha256,
                    create_event_version: event.create_event_version,
                    operation_end_event_version: event.operation_end_event_version,
                })
                .collect(),
            invalid: self.invalid,
            unsupported_schema: self.unsupported_schema,
            events_lost: self.events_lost,
            overflow: self.overflow,
            incomplete: self.incomplete,
        }
    }

    pub(crate) fn observer_unavailable(error: &PassiveAccessLocalizationSetupErrorV1) -> Self {
        let cleanup_valid = error
            .cleanup_provider_disable_status
            .successful_or_not_attempted()
            && error.cleanup_stop_status.successful_or_not_attempted()
            && error.cleanup_close_status.successful_or_not_attempted()
            && error
                .cleanup_process_trace_status
                .successful_or_not_attempted()
            && if error.session_created {
                error.session_absence_proven
                    && error.cleanup_absence_query_status
                        == PassiveAccessLocalizationCleanupStatusV1::Native(
                            ERROR_WMI_INSTANCE_NOT_FOUND,
                        )
            } else {
                error.cleanup_absence_query_status.not_attempted()
            };
        Self {
            classification: if cleanup_valid {
                "observer-unavailable"
            } else {
                "invalid-setup-cleanup"
            },
            cleanup_count: u32::from(error.session_created),
            detail_sha256: error.detail_sha256.clone(),
            setup_stage: Some(error.stage),
            setup_win32_status: error.win32_status,
            session_created: error.session_created,
            provider_enable_attempted: error.provider_enable_attempted,
            consumer_opened: error.consumer_opened,
            consumer_ready: error.consumer_ready,
            schema_observed: false,
            session_name_sha256: error.session_name_sha256.clone(),
            cleanup_provider_disable_status: error.cleanup_provider_disable_status,
            cleanup_stop_status: error.cleanup_stop_status,
            cleanup_close_status: error.cleanup_close_status,
            cleanup_process_trace_status: error.cleanup_process_trace_status,
            cleanup_absence_query_status: error.cleanup_absence_query_status,
            session_absence_proven: error.session_absence_proven,
            subject_binding_sha256: "none".to_owned(),
            canonical_events: 0,
            target_user_events: 0,
            frontier: Vec::new(),
            invalid: !cleanup_valid,
            unsupported_schema: false,
            events_lost: 0,
            overflow: false,
            incomplete: true,
        }
    }

    pub(crate) fn diagnostic(&self) -> String {
        let frontier = self
            .frontier
            .iter()
            .map(|event| {
                format!(
                    "{}:{}:file-create-id-12-v{}/operation-end-id-24-v{}:{:#010x}:{}:requested-access-unavailable",
                    event.ordinal,
                    event.cell.diagnostic(),
                    event.create_event_version,
                    event.operation_end_event_version,
                    event.native_status as u32,
                    event.object_name_sha256,
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let events_lost = self.setup_stage.map_or_else(
            || self.events_lost.to_string(),
            |_| "unavailable".to_owned(),
        );
        let overflow = self
            .setup_stage
            .map_or_else(|| self.overflow.to_string(), |_| "unavailable".to_owned());
        let rendered = format!(
            "passive_access_localization=v2 coverage={COVERAGE} state={} setup_stage={} win32_status={} operation_status={} session_created={} provider_enable_attempted={} consumer_opened={} consumer_ready={} schema_observed={} session_name_sha256={} cleanup_provider_disable_status={} cleanup_stop_status={} cleanup_close_status={} cleanup_process_trace_status={} cleanup_absence_query_status={} session_absence_proven={} requested_access_available=false scope=child-pid-plus-creation-identity provider_sha256={} subject_binding_sha256={} canonical_events={} target_user_events={} frontier=[{frontier}] events_lost={} overflow={} incomplete={} cleanup_count={} detail_sha256={} object_values_redacted=true debugger_attached=false ifeo_changed=false sacl_changed=false acl_changed=false grant_created=false workload_executed=false qualification_promoted=false",
            self.classification,
            self.setup_stage.map_or("none", |stage| stage.diagnostic()),
            self.setup_win32_status
                .map_or_else(|| "none".to_owned(), |status| status.to_string()),
            self.setup_win32_status
                .map_or_else(|| "none".to_owned(), |status| status.to_string()),
            self.session_created,
            self.provider_enable_attempted,
            self.consumer_opened,
            self.consumer_ready,
            self.schema_observed,
            self.session_name_sha256,
            self.cleanup_provider_disable_status.diagnostic(),
            self.cleanup_stop_status.diagnostic(),
            self.cleanup_close_status.diagnostic(),
            self.cleanup_process_trace_status.diagnostic(),
            self.cleanup_absence_query_status.diagnostic(),
            self.session_absence_proven,
            super::record::digest(
                b"Microsoft-Windows-Kernel-File/edd08927-9cc4-4e65-b970-c2560fb5c289"
            ),
            self.subject_binding_sha256,
            self.canonical_events,
            self.target_user_events,
            events_lost,
            overflow,
            self.incomplete,
            self.cleanup_count,
            self.detail_sha256,
        );
        if rendered.len() <= MAX_RENDERED_BYTES {
            rendered
        } else {
            format!(
                "passive_access_localization=v2 coverage={COVERAGE} state=invalid setup_stage={} win32_status={} requested_access_available=false scope=child-pid-plus-creation-identity frontier=[] cleanup_count={} detail_sha256={} object_values_redacted=true workload_executed=false qualification_promoted=false",
                self.setup_stage.map_or("none", |stage| stage.diagnostic()),
                self.setup_win32_status
                    .map_or_else(|| "none".to_owned(), |status| status.to_string()),
                self.cleanup_count,
                super::record::digest(
                    b"passive access-localization rendered evidence exceeded bound"
                ),
            )
        }
    }

    pub(crate) fn admissible(&self) -> bool {
        !self.invalid
            && !self.unsupported_schema
            && self.cleanup_count == 1
            && matches!(
                self.classification,
                "candidate-file-denial-differential"
                    | "file-domain-common"
                    | "coverage-insufficient"
            )
    }

    pub(crate) fn exact_session_start_access_denied(&self) -> bool {
        self.classification == "observer-unavailable"
            && self.setup_stage == Some(PassiveAccessLocalizationSetupStageV1::SessionStart)
            && self.setup_win32_status == Some(5)
            && !self.session_created
            && !self.provider_enable_attempted
            && !self.consumer_opened
            && !self.consumer_ready
            && !self.schema_observed
            && super::record::validate_attempt_id(&self.session_name_sha256).is_ok()
            && self.cleanup_provider_disable_status.not_attempted()
            && self.cleanup_stop_status.not_attempted()
            && self.cleanup_close_status.not_attempted()
            && self.cleanup_process_trace_status.not_attempted()
            && self.cleanup_absence_query_status.not_attempted()
            && !self.session_absence_proven
            && self.subject_binding_sha256 == "none"
            && self.frontier.is_empty()
            && self.cleanup_count == 0
            && self.canonical_events == 0
            && self.target_user_events == 0
            && self.events_lost == 0
            && !self.overflow
            && self.incomplete
            && !self.invalid
            && !self.unsupported_schema
    }

    pub(crate) fn exact_session_start_access_denied_sha256(&self) -> Option<String> {
        self.exact_session_start_access_denied().then(|| {
            let mut material =
                b"memcordon-passive-access-session-start-denied-trigger-v1\0".to_vec();
            material.extend_from_slice(self.classification.as_bytes());
            material.extend_from_slice(&self.setup_win32_status.unwrap_or_default().to_le_bytes());
            material.extend_from_slice(self.detail_sha256.as_bytes());
            material.extend_from_slice(&self.cleanup_count.to_le_bytes());
            super::record::digest(&material)
        })
    }
}

fn passive_session_name_sha256(session_name: &[u16]) -> String {
    let mut material = b"memcordon-passive-access-session-name-v1\0".to_vec();
    for unit in session_name.iter().copied().take_while(|unit| *unit != 0) {
        material.extend_from_slice(&unit.to_le_bytes());
    }
    super::record::digest(&material)
}

pub(crate) fn broker_passive_trace_limits_sha256() -> String {
    let mut material = b"memcordon-broker-passive-trace-limits-v1\0".to_vec();
    for value in [
        MAX_TRACE_EVENTS as u64,
        MAX_EVENT_PAYLOAD_BYTES as u64,
        MAX_PENDING_OPERATIONS as u64,
        MAX_FRONTIER_EVENTS as u64,
        MAX_BROKER_DIAGNOSTIC_FRONTIER as u64,
        MAX_RENDERED_BYTES as u64,
        memcordon_core::PROVIDER_REJECTION_MAX_DETAIL_BYTES as u64,
        MAX_SUBJECT_WINDOW.as_millis() as u64,
        MAX_TRACE_SESSION.as_millis() as u64,
        READY_TIMEOUT.as_millis() as u64,
        DRAIN_TIMEOUT.as_millis() as u64,
    ] {
        material.extend_from_slice(&value.to_le_bytes());
    }
    super::record::digest(&material)
}

fn passive_session_absence(
    session_name: &[u16],
) -> (PassiveAccessLocalizationCleanupStatusV1, bool) {
    let Ok(mut properties) = TracePropertiesBuffer::new(session_name) else {
        return (
            PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
            false,
        );
    };
    let status = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            session_name.as_ptr(),
            &raw mut properties.properties,
            EVENT_TRACE_CONTROL_QUERY,
        )
    };
    (
        PassiveAccessLocalizationCleanupStatusV1::Native(status),
        status == ERROR_WMI_INSTANCE_NOT_FOUND,
    )
}

impl PassiveAccessLocalizationObserverV1 {
    pub(crate) fn session_name_sha256(&self) -> String {
        passive_session_name_sha256(&self.session_name)
    }

    pub(crate) fn start_ready_before_child_creation()
    -> Result<Self, PassiveAccessLocalizationSetupErrorV1> {
        let sequence = SESSION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            "Memcordon-Certification-FileAccess-{}-{sequence}",
            std::process::id()
        );
        let mut session_name = name.encode_utf16().collect::<Vec<_>>();
        session_name.push(0);
        let session_name_sha256 = passive_session_name_sha256(&session_name);
        let mut properties = TracePropertiesBuffer::new(&session_name).map_err(|error| {
            PassiveAccessLocalizationSetupErrorV1::new(
                PassiveAccessLocalizationSetupStageV1::SessionStart,
                None,
                false,
                false,
                false,
                false,
                session_name_sha256.clone(),
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                false,
                error.as_bytes(),
            )
        })?;
        let mut control_handle = CONTROLTRACE_HANDLE::default();
        let status = unsafe {
            StartTraceW(
                &raw mut control_handle,
                session_name.as_ptr(),
                &raw mut properties.properties,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(PassiveAccessLocalizationSetupErrorV1::new(
                PassiveAccessLocalizationSetupStageV1::SessionStart,
                Some(i64::from(status)),
                false,
                false,
                false,
                false,
                session_name_sha256.clone(),
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                false,
                b"StartTraceW",
            ));
        }

        let state = Arc::new(Mutex::new(TraceStateV1::default()));
        let drain = Arc::new(DrainBarrierV1::default());
        let mut callback_context = Box::new(TraceCallbackContext {
            state: Arc::clone(&state),
            drain: Arc::clone(&drain),
        });
        let provider = KERNEL_FILE_PROVIDER;
        let enable_status = unsafe {
            EnableTraceEx2(
                control_handle,
                &raw const provider,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_VERBOSE as u8,
                KERNEL_FILE_KEYWORD_CREATE | KERNEL_FILE_KEYWORD_OPERATION_END,
                0,
                0,
                null(),
            )
        };
        if enable_status != ERROR_SUCCESS {
            let cleanup_stop = unsafe {
                ControlTraceW(
                    control_handle,
                    null(),
                    &raw mut properties.properties,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            let (cleanup_absence_query, session_absence_proven) =
                passive_session_absence(&session_name);
            return Err(PassiveAccessLocalizationSetupErrorV1::new(
                PassiveAccessLocalizationSetupStageV1::ProviderEnable,
                Some(i64::from(enable_status)),
                true,
                true,
                false,
                false,
                session_name_sha256.clone(),
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                PassiveAccessLocalizationCleanupStatusV1::Native(cleanup_stop),
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                cleanup_absence_query,
                session_absence_proven,
                b"EnableTraceEx2",
            ));
        }

        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: session_name.as_mut_ptr(),
            Context: (&raw mut *callback_context).cast::<c_void>(),
            ..EVENT_TRACE_LOGFILEW::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
        logfile.Anonymous2.EventRecordCallback = Some(passive_file_event_callback);
        logfile.BufferCallback = Some(passive_file_buffer_callback);
        let processing_handle = unsafe { OpenTraceW(&raw mut logfile) };
        if processing_handle.Value == u64::MAX {
            let operation_status = std::io::Error::last_os_error()
                .raw_os_error()
                .map(i64::from);
            let disable = unsafe {
                EnableTraceEx2(
                    control_handle,
                    &raw const provider,
                    EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                    0,
                    0,
                    0,
                    0,
                    null(),
                )
            };
            let cleanup_stop = unsafe {
                ControlTraceW(
                    control_handle,
                    null(),
                    &raw mut properties.properties,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            let (cleanup_absence_query, session_absence_proven) =
                passive_session_absence(&session_name);
            return Err(PassiveAccessLocalizationSetupErrorV1::new(
                PassiveAccessLocalizationSetupStageV1::ConsumerOpen,
                operation_status,
                true,
                true,
                false,
                false,
                session_name_sha256.clone(),
                PassiveAccessLocalizationCleanupStatusV1::Native(disable),
                PassiveAccessLocalizationCleanupStatusV1::Native(cleanup_stop),
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                cleanup_absence_query,
                session_absence_proven,
                b"OpenTraceW",
            ));
        }
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let worker_handle = processing_handle;
        let worker = match thread::Builder::new()
            .name("memcordon-file-access-observer".to_owned())
            .spawn(move || {
                let _ = ready_sender.send(());
                unsafe { ProcessTrace(&raw const worker_handle, 1, null(), null()) }
            }) {
            Ok(worker) => worker,
            Err(error) => {
                let disable = unsafe {
                    EnableTraceEx2(
                        control_handle,
                        &raw const provider,
                        EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                        0,
                        0,
                        0,
                        0,
                        null(),
                    )
                };
                let stop = unsafe {
                    ControlTraceW(
                        control_handle,
                        null(),
                        &raw mut properties.properties,
                        EVENT_TRACE_CONTROL_STOP,
                    )
                };
                let close = unsafe { CloseTrace(processing_handle) };
                let (cleanup_absence_query, session_absence_proven) =
                    passive_session_absence(&session_name);
                return Err(PassiveAccessLocalizationSetupErrorV1::new(
                    PassiveAccessLocalizationSetupStageV1::ConsumerReady,
                    error.raw_os_error().map(i64::from),
                    true,
                    true,
                    true,
                    false,
                    session_name_sha256.clone(),
                    PassiveAccessLocalizationCleanupStatusV1::Native(disable),
                    PassiveAccessLocalizationCleanupStatusV1::Native(stop),
                    PassiveAccessLocalizationCleanupStatusV1::Native(close),
                    PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                    cleanup_absence_query,
                    session_absence_proven,
                    b"ProcessTrace worker spawn",
                ));
            }
        };
        if let Err(error) = ready_receiver.recv_timeout(READY_TIMEOUT) {
            let disable = unsafe {
                EnableTraceEx2(
                    control_handle,
                    &raw const provider,
                    EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                    0,
                    0,
                    0,
                    0,
                    null(),
                )
            };
            let stop = unsafe {
                ControlTraceW(
                    control_handle,
                    null(),
                    &raw mut properties.properties,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            let process_trace = worker.join();
            let close = unsafe { CloseTrace(processing_handle) };
            let process_trace_status = match process_trace {
                Ok(status) => PassiveAccessLocalizationCleanupStatusV1::Native(status),
                Err(_) => PassiveAccessLocalizationCleanupStatusV1::WorkerPanicked,
            };
            let (cleanup_absence_query, session_absence_proven) =
                passive_session_absence(&session_name);
            let detail = format!("consumer readiness: {error}");
            return Err(PassiveAccessLocalizationSetupErrorV1::new(
                PassiveAccessLocalizationSetupStageV1::ConsumerReady,
                None,
                true,
                true,
                true,
                false,
                session_name_sha256.clone(),
                PassiveAccessLocalizationCleanupStatusV1::Native(disable),
                PassiveAccessLocalizationCleanupStatusV1::Native(stop),
                PassiveAccessLocalizationCleanupStatusV1::Native(close),
                process_trace_status,
                cleanup_absence_query,
                session_absence_proven,
                detail.as_bytes(),
            ));
        }
        Ok(Self {
            session_name,
            control_handle,
            processing_handle,
            callback_context,
            worker: Some(worker),
            state,
            drain,
            cleanup_performed: false,
            started: Instant::now(),
        })
    }

    pub(crate) fn bind_suspended_child(
        &self,
        cell: PassiveAccessLocalizationCellV1,
        process: HANDLE,
        expected_process_id: u32,
        expected_creation_time_100ns: u64,
    ) -> Result<PassiveAccessLocalizationSubjectGuardV1, String> {
        if self.started.elapsed() > MAX_TRACE_SESSION {
            return Err("passive access-localization session exceeded its time bound".to_owned());
        }
        let process_id = unsafe { GetProcessId(process) };
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if process_id == 0
            || unsafe {
                GetProcessTimes(
                    process,
                    &raw mut creation,
                    &raw mut exit,
                    &raw mut kernel,
                    &raw mut user,
                )
            } == 0
        {
            return Err("passive access-localization child identity query failed".to_owned());
        }
        let creation_time_100ns =
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        if process_id != expected_process_id || creation_time_100ns != expected_creation_time_100ns
        {
            return Err("passive access-localization child identity binding changed".to_owned());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "passive access-localization state poisoned".to_owned())?;
        if state.active.is_some() || !state.pending.is_empty() {
            return Err("passive access-localization subject overlap is invalid".to_owned());
        }
        if state
            .subject_bindings
            .iter()
            .any(|(observed, _)| *observed == cell)
        {
            return Err("passive access-localization subject was bound more than once".to_owned());
        }
        let mut binding = b"memcordon-passive-access-subject-v1\0".to_vec();
        binding.extend_from_slice(cell.diagnostic().as_bytes());
        binding.extend_from_slice(&process_id.to_le_bytes());
        binding.extend_from_slice(&creation_time_100ns.to_le_bytes());
        state
            .subject_bindings
            .push((cell, super::record::digest(&binding)));
        state.active = Some(SubjectIdentityV1 {
            cell,
            process_id,
            creation_time_100ns,
            started: Instant::now(),
        });
        Ok(PassiveAccessLocalizationSubjectGuardV1 {
            control_handle: self.control_handle,
            state: Arc::clone(&self.state),
            drain: Arc::clone(&self.drain),
            cell,
            active: true,
        })
    }

    pub(crate) fn finish(
        mut self,
        reproduction_valid: bool,
    ) -> PassiveAccessLocalizationEvidenceV1 {
        let cleanup_receipt = self.cleanup();
        let cleanup_detail = cleanup_receipt.failure_detail();
        if self.started.elapsed() > MAX_TRACE_SESSION {
            if let Ok(mut state) = self.state.lock() {
                state.overflow = Some("session-window");
                state.incomplete = true;
            }
        }
        let state = self.state.lock();
        let Ok(state) = state else {
            return PassiveAccessLocalizationEvidenceV1 {
                classification: "invalid",
                cleanup_count: 1,
                detail_sha256: super::record::digest(b"passive access-localization state poisoned"),
                setup_stage: None,
                setup_win32_status: None,
                session_created: true,
                provider_enable_attempted: true,
                consumer_opened: true,
                consumer_ready: true,
                schema_observed: false,
                session_name_sha256: self.session_name_sha256(),
                cleanup_provider_disable_status: cleanup_receipt.provider_disable,
                cleanup_stop_status: cleanup_receipt.stop,
                cleanup_close_status: cleanup_receipt.close,
                cleanup_process_trace_status: cleanup_receipt.process_trace,
                cleanup_absence_query_status: cleanup_receipt.absence_query,
                session_absence_proven: cleanup_receipt.session_absence_proven,
                subject_binding_sha256: "none".to_owned(),
                canonical_events: 0,
                target_user_events: 0,
                frontier: Vec::new(),
                invalid: true,
                unsupported_schema: false,
                events_lost: 0,
                overflow: false,
                incomplete: true,
            };
        };
        let canonical = state
            .frontier
            .iter()
            .filter(|event| event.cell == PassiveAccessLocalizationCellV1::CanonicalSameAccess)
            .cloned()
            .collect::<Vec<_>>();
        let target_user = state
            .frontier
            .iter()
            .filter(|event| event.cell == PassiveAccessLocalizationCellV1::TargetUser)
            .cloned()
            .collect::<Vec<_>>();
        let invalid = !reproduction_valid
            || cleanup_detail.is_some()
            || state.active.is_some()
            || state.overflow.is_some()
            || state.incomplete
            || state.flush_failed
            || state.events_lost != 0
            || state.realtime_buffers_lost != 0;
        let subjects_bound = state.subject_bindings.len() == 2
            && state.subject_bindings[0].0 == PassiveAccessLocalizationCellV1::CanonicalSameAccess
            && state.subject_bindings[1].0 == PassiveAccessLocalizationCellV1::TargetUser;
        let invalid = invalid || !subjects_bound;
        let unsupported_schema = state.unsupported_schema.is_some();
        let subject_binding_sha256 = if subjects_bound {
            let mut binding = b"memcordon-passive-access-subject-pair-v1\0".to_vec();
            for (cell, digest) in &state.subject_bindings {
                binding.extend_from_slice(cell.diagnostic().as_bytes());
                binding.extend_from_slice(digest.as_bytes());
            }
            super::record::digest(&binding)
        } else {
            "none".to_owned()
        };
        let classification = if invalid {
            "invalid"
        } else if unsupported_schema {
            "unsupported-provider-schema"
        } else {
            classify_completed_file_pairs(&canonical, &target_user)
        };
        let detail = cleanup_detail
            .as_deref()
            .or(state.unsupported_schema.as_deref())
            .or(state.overflow)
            .unwrap_or("none");
        let frontier = if invalid || unsupported_schema {
            Vec::new()
        } else {
            state.frontier.clone()
        };
        PassiveAccessLocalizationEvidenceV1 {
            classification,
            cleanup_count: 1,
            detail_sha256: if detail == "none" {
                "none".to_owned()
            } else {
                super::record::digest(detail.as_bytes())
            },
            setup_stage: None,
            setup_win32_status: None,
            session_created: true,
            provider_enable_attempted: true,
            consumer_opened: true,
            consumer_ready: true,
            schema_observed: state.total_events != 0 || unsupported_schema,
            session_name_sha256: self.session_name_sha256(),
            cleanup_provider_disable_status: cleanup_receipt.provider_disable,
            cleanup_stop_status: cleanup_receipt.stop,
            cleanup_close_status: cleanup_receipt.close,
            cleanup_process_trace_status: cleanup_receipt.process_trace,
            cleanup_absence_query_status: cleanup_receipt.absence_query,
            session_absence_proven: cleanup_receipt.session_absence_proven,
            subject_binding_sha256,
            canonical_events: if invalid || unsupported_schema {
                0
            } else {
                canonical.len()
            },
            target_user_events: if invalid || unsupported_schema {
                0
            } else {
                target_user.len()
            },
            frontier,
            invalid,
            unsupported_schema,
            events_lost: state
                .events_lost
                .saturating_add(state.realtime_buffers_lost),
            overflow: state.overflow.is_some(),
            incomplete: state.incomplete || state.active.is_some(),
        }
    }

    fn cleanup(&mut self) -> PassiveAccessLocalizationCleanupReceiptV1 {
        if self.cleanup_performed {
            return PassiveAccessLocalizationCleanupReceiptV1 {
                provider_disable: PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                stop: PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                process_trace: PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                close: PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                absence_query: PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
                session_absence_proven: false,
                repeated: true,
            };
        }
        self.cleanup_performed = true;
        let provider = KERNEL_FILE_PROVIDER;
        let disable = unsafe {
            EnableTraceEx2(
                self.control_handle,
                &raw const provider,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                0,
                0,
                0,
                0,
                null(),
            )
        };
        let mut properties = TracePropertiesBuffer::new(&[b'm' as u16, 0])
            .expect("fixed ETW cleanup buffer name is valid");
        let stop = unsafe {
            ControlTraceW(
                self.control_handle,
                null(),
                &raw mut properties.properties,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        if let Ok(mut state) = self.state.lock() {
            state.events_lost = state.events_lost.max(properties.properties.EventsLost);
            state.realtime_buffers_lost = state
                .realtime_buffers_lost
                .max(properties.properties.RealTimeBuffersLost);
        }
        let process_trace = match self.worker.take() {
            Some(worker) => match worker.join() {
                Ok(status) => PassiveAccessLocalizationCleanupStatusV1::Native(status),
                Err(_) => PassiveAccessLocalizationCleanupStatusV1::WorkerPanicked,
            },
            None => PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
        };
        let close = unsafe { CloseTrace(self.processing_handle) };
        let (absence_query, session_absence_proven) = passive_session_absence(&self.session_name);
        let _keep_callback_context_live = &self.callback_context;
        PassiveAccessLocalizationCleanupReceiptV1 {
            provider_disable: PassiveAccessLocalizationCleanupStatusV1::Native(disable),
            stop: PassiveAccessLocalizationCleanupStatusV1::Native(stop),
            process_trace,
            close: PassiveAccessLocalizationCleanupStatusV1::Native(close),
            absence_query,
            session_absence_proven,
            repeated: false,
        }
    }
}

impl Drop for PassiveAccessLocalizationObserverV1 {
    fn drop(&mut self) {
        if !self.cleanup_performed {
            let _ = self.cleanup();
        }
    }
}

impl PassiveAccessLocalizationSubjectGuardV1 {
    pub(crate) fn finish(mut self) -> PassiveAccessLocalizationDrainReceiptV1 {
        self.finish_once()
    }

    fn finish_once(&mut self) -> PassiveAccessLocalizationDrainReceiptV1 {
        if !self.active {
            return PassiveAccessLocalizationDrainReceiptV1 {
                flush_status: ERROR_SUCCESS,
                barrier_requested: false,
                barrier_armed: false,
                barrier_acknowledged: false,
                pending_empty: false,
                detail_sha256: super::record::digest(b"subject drain repeated"),
            };
        }
        let drain_epoch = self.drain.request();
        let mut properties = TracePropertiesBuffer::new(&[b'm' as u16, 0])
            .expect("fixed ETW flush buffer name is valid");
        let flush_status =
            unsafe { FlushTraceW(self.control_handle, null(), &raw mut properties.properties) };
        let barrier_requested = drain_epoch.is_some();
        let barrier_armed = flush_status == ERROR_SUCCESS
            && drain_epoch.is_some_and(|epoch| {
                self.drain
                    .arm(epoch, u64::from(properties.properties.BuffersWritten))
            });
        let barrier_acknowledged =
            barrier_armed && drain_epoch.is_some_and(|epoch| self.drain.wait(epoch, DRAIN_TIMEOUT));
        let mut error = if flush_status != ERROR_SUCCESS {
            Some("flush-failed")
        } else if !barrier_requested || !barrier_armed {
            Some("flush-drain-barrier")
        } else if !barrier_acknowledged {
            Some("flush-drain-timeout")
        } else {
            None
        };
        let mut pending_empty = false;
        if let Ok(mut state) = self.state.lock() {
            if let Some(error) = error {
                state.flush_failed = true;
                state.overflow = Some(error);
                state.incomplete = true;
            }
            if state.active.as_ref().map(|active| active.cell) != Some(self.cell) {
                error.get_or_insert("subject-binding-changed");
                state.incomplete = true;
            }
            if state
                .active
                .as_ref()
                .is_some_and(|active| active.started.elapsed() > MAX_SUBJECT_WINDOW)
            {
                error.get_or_insert("subject-window");
                state.overflow = Some("subject-window");
                state.incomplete = true;
            }
            pending_empty = state.pending.is_empty();
            if !pending_empty {
                error.get_or_insert("pending-operation");
                state.incomplete = true;
                state.pending.clear();
            }
            state.active = None;
        } else {
            error.get_or_insert("state-poisoned");
        }
        self.active = false;
        PassiveAccessLocalizationDrainReceiptV1 {
            flush_status,
            barrier_requested,
            barrier_armed,
            barrier_acknowledged,
            pending_empty,
            detail_sha256: error.map_or_else(
                || "none".to_owned(),
                |detail| super::record::digest(detail.as_bytes()),
            ),
        }
    }
}

impl Drop for PassiveAccessLocalizationSubjectGuardV1 {
    fn drop(&mut self) {
        if self.active {
            let _ = self.finish_once();
        }
    }
}

unsafe extern "system" fn passive_file_buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    let Some(logfile) = (unsafe { logfile.as_ref() }) else {
        return 0;
    };
    let Some(context) = (unsafe { (logfile.Context as *const TraceCallbackContext).as_ref() })
    else {
        return 0;
    };
    if let Ok(mut state) = context.state.lock() {
        state.events_lost = state.events_lost.max(logfile.EventsLost);
    }
    context.drain.buffer_completed();
    1
}

unsafe extern "system" fn passive_file_event_callback(event: *mut EVENT_RECORD) {
    let Some(event) = (unsafe { event.as_ref() }) else {
        return;
    };
    let Some(context) = (unsafe { (event.UserContext as *const TraceCallbackContext).as_ref() })
    else {
        return;
    };
    let Ok(mut state) = context.state.lock() else {
        return;
    };
    let Some(active) = state.active.clone() else {
        return;
    };
    if !guid_equal(&event.EventHeader.ProviderId, &KERNEL_FILE_PROVIDER) {
        return;
    }
    if active.started.elapsed() > MAX_SUBJECT_WINDOW {
        state.overflow = Some("subject-window");
        state.incomplete = true;
        return;
    }
    let descriptor = event.EventHeader.EventDescriptor;
    match descriptor.Id {
        FILE_CREATE_EVENT_ID
            if FILE_CREATE_EVENT_VERSIONS.contains(&descriptor.Version)
                && descriptor.Opcode == INFO_OPCODE =>
        {
            if event.EventHeader.ProcessId != active.process_id {
                return;
            }
            let initiator_property = if descriptor.Version == 0 {
                "ThreadId"
            } else {
                "IssuingThreadId"
            };
            let initiator_thread_id = match tdh_property_bytes(event, initiator_property)
                .and_then(|bytes| decode_create_initiator(descriptor.Version, &bytes))
            {
                Ok(thread_id) => thread_id,
                Err(error) => {
                    state.unsupported_schema = Some(error);
                    return;
                }
            };
            if initiator_thread_id == 0 || initiator_thread_id != event.EventHeader.ThreadId {
                state.incomplete = true;
                return;
            }
            if !admit_subject_event_budget(&mut state, usize::from(event.UserDataLength)) {
                return;
            }
            let irp = match tdh_pointer_property(event, "Irp") {
                Ok(irp) => irp,
                Err(error) => {
                    state.unsupported_schema = Some(error);
                    return;
                }
            };
            let path = match tdh_property_bytes(event, "FileName") {
                Ok(path) => path,
                Err(error) => {
                    state.unsupported_schema = Some(error);
                    return;
                }
            };
            if state.pending.len() >= MAX_PENDING_OPERATIONS || state.pending.contains_key(&irp) {
                state.overflow = Some("operation-join-bound");
                return;
            }
            let ordinal = state.total_events;
            state.pending.insert(
                irp,
                PendingCreateV1 {
                    cell: active.cell,
                    object_name_sha256: file_object_name_digest(&path),
                    ordinal,
                    event_version: descriptor.Version,
                },
            );
        }
        FILE_OPERATION_END_EVENT_ID
            if descriptor.Version == FILE_OPERATION_END_EVENT_VERSION
                && descriptor.Opcode == INFO_OPCODE =>
        {
            let irp = match tdh_pointer_property(event, "Irp") {
                Ok(irp) => irp,
                Err(error) => {
                    state.unsupported_schema = Some(error);
                    return;
                }
            };
            let Some(pending) = state.pending.get(&irp).cloned() else {
                return;
            };
            if !admit_subject_event_budget(&mut state, usize::from(event.UserDataLength)) {
                return;
            }
            let _extra_information = match tdh_pointer_property(event, "ExtraInformation") {
                Ok(extra) => extra,
                Err(error) => {
                    state.unsupported_schema = Some(error);
                    return;
                }
            };
            let native_status = match tdh_i32_property(event, "Status") {
                Ok(status) => status,
                Err(error) => {
                    state.unsupported_schema = Some(error);
                    return;
                }
            };
            state.pending.remove(&irp);
            if pending.cell != active.cell {
                state.incomplete = true;
                return;
            }
            push_completed_frontier_or_invalidate(
                &mut state,
                FileOperationV1 {
                    cell: active.cell,
                    ordinal: pending.ordinal,
                    native_status,
                    object_name_sha256: pending.object_name_sha256,
                    create_event_version: pending.event_version,
                    operation_end_event_version: descriptor.Version,
                },
            );
        }
        FILE_CREATE_EVENT_ID | FILE_OPERATION_END_EVENT_ID => {
            state.unsupported_schema = Some(format!(
                "unsupported Kernel-File descriptor id={} version={} opcode={}",
                descriptor.Id, descriptor.Version, descriptor.Opcode
            ));
        }
        _ => {}
    }
}

fn guid_equal(left: &GUID, right: &GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

fn tdh_property_bytes(event: &EVENT_RECORD, name: &str) -> Result<Vec<u8>, String> {
    let mut property_name = name.encode_utf16().collect::<Vec<_>>();
    property_name.push(0);
    let descriptor = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: property_name.as_ptr() as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let mut size = 0_u32;
    let size_status =
        unsafe { TdhGetPropertySize(event, 0, null(), 1, &raw const descriptor, &raw mut size) };
    if size_status != ERROR_SUCCESS || size == 0 || size as usize > MAX_EVENT_PAYLOAD_BYTES {
        return Err(format!(
            "TDH property schema rejected field={name} status={size_status} size={size}"
        ));
    }
    let mut bytes = vec![0_u8; size as usize];
    let value_status = unsafe {
        TdhGetProperty(
            event,
            0,
            null(),
            1,
            &raw const descriptor,
            size,
            bytes.as_mut_ptr(),
        )
    };
    if value_status != ERROR_SUCCESS {
        return Err(format!(
            "TDH property read rejected field={name} status={value_status}"
        ));
    }
    Ok(bytes)
}

fn tdh_pointer_property(event: &EVENT_RECORD, name: &str) -> Result<u64, String> {
    let bytes = tdh_property_bytes(event, name)?;
    decode_pointer_property_bytes(&bytes, name)
}

fn decode_pointer_property_bytes(bytes: &[u8], name: &str) -> Result<u64, String> {
    match bytes.len() {
        4 => Ok(u64::from(u32::from_ne_bytes(bytes.try_into().map_err(
            |_| format!("TDH pointer field {name} width changed"),
        )?))),
        8 => Ok(u64::from_ne_bytes(bytes.try_into().map_err(|_| {
            format!("TDH pointer field {name} width changed")
        })?)),
        _ => Err(format!("TDH pointer field {name} width changed")),
    }
}

fn decode_create_initiator(version: u8, bytes: &[u8]) -> Result<u32, String> {
    match version {
        0 => u32::try_from(decode_pointer_property_bytes(bytes, "ThreadId")?)
            .map_err(|_| "TDH v0 ThreadId exceeds u32".to_owned()),
        1 if bytes.len() == size_of::<u32>() => {
            Ok(u32::from_ne_bytes(bytes.try_into().map_err(|_| {
                "TDH v1 IssuingThreadId width changed".to_owned()
            })?))
        }
        1 => Err("TDH v1 IssuingThreadId width changed".to_owned()),
        _ => Err("TDH Create initiator version changed".to_owned()),
    }
}

fn tdh_i32_property(event: &EVENT_RECORD, name: &str) -> Result<i32, String> {
    let bytes = tdh_property_bytes(event, name)?;
    if bytes.len() != size_of::<i32>() {
        return Err(format!("TDH status field {name} width changed"));
    }
    Ok(i32::from_ne_bytes(bytes.as_slice().try_into().map_err(
        |_| format!("TDH status field {name} width changed"),
    )?))
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PassiveAccessLocalizationEventForTest {
    Create {
        cell: PassiveAccessLocalizationCellV1,
        process_matches: bool,
        initiator_matches: bool,
        schema_matches: bool,
        irp: u64,
        name_sha256: &'static str,
        event_version: u8,
    },
    OperationEnd {
        cell: PassiveAccessLocalizationCellV1,
        header_process_matches: bool,
        schema_matches: bool,
        irp: u64,
        native_status: i32,
        event_version: u8,
    },
    Loss,
    Overflow,
    SubjectTimeout,
    SessionTimeout,
}

#[cfg(test)]
pub(crate) fn passive_file_object_name_digest_for_test(raw_name: &[u8]) -> String {
    file_object_name_digest(raw_name)
}

#[cfg(test)]
pub(crate) fn passive_access_setup_cleanup_failure_for_test(
    operation_status: Option<i64>,
    cleanup_stop: u32,
) -> String {
    PassiveAccessLocalizationEvidenceV1::observer_unavailable(
        &PassiveAccessLocalizationSetupErrorV1::new(
            PassiveAccessLocalizationSetupStageV1::ProviderEnable,
            operation_status,
            true,
            true,
            false,
            false,
            super::record::digest(b"test-provider-enable"),
            PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
            PassiveAccessLocalizationCleanupStatusV1::Native(cleanup_stop),
            PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
            PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
            PassiveAccessLocalizationCleanupStatusV1::Native(ERROR_WMI_INSTANCE_NOT_FOUND),
            true,
            b"test provider enable",
        ),
    )
    .diagnostic()
}

#[cfg(test)]
pub(crate) fn passive_access_consumer_open_failure_for_test(
    operation_status: Option<i64>,
    cleanup_stop: u32,
) -> PassiveAccessLocalizationEvidenceV1 {
    PassiveAccessLocalizationEvidenceV1::observer_unavailable(
        &PassiveAccessLocalizationSetupErrorV1::new(
            PassiveAccessLocalizationSetupStageV1::ConsumerOpen,
            operation_status,
            true,
            true,
            false,
            false,
            super::record::digest(b"test-consumer-open"),
            PassiveAccessLocalizationCleanupStatusV1::Native(ERROR_SUCCESS),
            PassiveAccessLocalizationCleanupStatusV1::Native(cleanup_stop),
            PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
            PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
            PassiveAccessLocalizationCleanupStatusV1::Native(ERROR_WMI_INSTANCE_NOT_FOUND),
            true,
            b"OpenTraceW",
        ),
    )
}

#[cfg(test)]
pub(crate) fn passive_access_runtime_cleanup_for_test(
    provider_disable: u32,
    stop: u32,
    process_trace: u32,
    close: u32,
) -> PassiveAccessLocalizationEvidenceV1 {
    let receipt = PassiveAccessLocalizationCleanupReceiptV1 {
        provider_disable: PassiveAccessLocalizationCleanupStatusV1::Native(provider_disable),
        stop: PassiveAccessLocalizationCleanupStatusV1::Native(stop),
        process_trace: PassiveAccessLocalizationCleanupStatusV1::Native(process_trace),
        close: PassiveAccessLocalizationCleanupStatusV1::Native(close),
        absence_query: PassiveAccessLocalizationCleanupStatusV1::Native(
            ERROR_WMI_INSTANCE_NOT_FOUND,
        ),
        session_absence_proven: true,
        repeated: false,
    };
    let successful = receipt.successful();
    PassiveAccessLocalizationEvidenceV1 {
        classification: if successful {
            "coverage-insufficient"
        } else {
            "invalid"
        },
        cleanup_count: 1,
        detail_sha256: receipt.failure_detail().map_or_else(
            || "none".to_owned(),
            |detail| super::record::digest(detail.as_bytes()),
        ),
        setup_stage: None,
        setup_win32_status: None,
        session_created: true,
        provider_enable_attempted: true,
        consumer_opened: true,
        consumer_ready: true,
        schema_observed: true,
        session_name_sha256: super::record::digest(b"test-runtime-cleanup"),
        cleanup_provider_disable_status: receipt.provider_disable,
        cleanup_stop_status: receipt.stop,
        cleanup_close_status: receipt.close,
        cleanup_process_trace_status: receipt.process_trace,
        cleanup_absence_query_status: receipt.absence_query,
        session_absence_proven: receipt.session_absence_proven,
        subject_binding_sha256: "test-binding".to_owned(),
        canonical_events: 0,
        target_user_events: 0,
        frontier: Vec::new(),
        invalid: !successful,
        unsupported_schema: false,
        events_lost: 0,
        overflow: false,
        incomplete: false,
    }
}

#[cfg(test)]
pub(crate) fn passive_access_session_start_unavailable_for_test(
    win32_status: u32,
) -> PassiveAccessLocalizationEvidenceV1 {
    PassiveAccessLocalizationEvidenceV1::observer_unavailable(
        &PassiveAccessLocalizationSetupErrorV1::new(
            PassiveAccessLocalizationSetupStageV1::SessionStart,
            Some(i64::from(win32_status)),
            false,
            false,
            false,
            false,
            super::record::digest(b"test-session-start"),
            PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
            PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
            PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
            PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
            PassiveAccessLocalizationCleanupStatusV1::NotAttempted,
            false,
            b"StartTraceW",
        ),
    )
}

#[cfg(test)]
pub(crate) fn passive_create_initiator_for_test(
    version: u8,
    raw_value: &[u8],
) -> Result<u32, String> {
    decode_create_initiator(version, raw_value)
}

#[cfg(test)]
pub(crate) fn passive_access_localization_drain_barrier_for_test(
    processed_before_flush: u64,
    target_after_flush: u64,
    callback_after_flush: bool,
) -> (bool, bool) {
    let barrier = DrainBarrierV1::default();
    for _ in 0..processed_before_flush {
        barrier.buffer_completed();
    }
    let epoch = barrier.request().expect("test drain epoch must fit");
    assert!(barrier.arm(epoch, target_after_flush));
    let before = barrier.acknowledged(epoch);
    if callback_after_flush {
        barrier.buffer_completed();
    }
    (before, barrier.acknowledged(epoch))
}

#[cfg(test)]
pub(crate) fn passive_access_localization_for_test(
    events: &[PassiveAccessLocalizationEventForTest],
    reproduction_valid: bool,
    cleanup_count: u32,
) -> PassiveAccessLocalizationEvidenceV1 {
    let mut state = TraceStateV1::default();
    for event in events {
        match *event {
            PassiveAccessLocalizationEventForTest::Create {
                cell,
                process_matches,
                initiator_matches,
                schema_matches,
                irp,
                name_sha256,
                event_version,
            } => {
                if !process_matches {
                    continue;
                }
                if !initiator_matches {
                    state.incomplete = true;
                    continue;
                }
                if !schema_matches {
                    state.unsupported_schema = Some("schema".to_owned());
                    continue;
                }
                if !admit_subject_event_budget(&mut state, 1) {
                    continue;
                }
                if state
                    .pending
                    .insert(
                        irp,
                        PendingCreateV1 {
                            cell,
                            object_name_sha256: name_sha256.to_owned(),
                            ordinal: state.total_events,
                            event_version,
                        },
                    )
                    .is_some()
                {
                    state.overflow = Some("duplicate-irp");
                }
            }
            PassiveAccessLocalizationEventForTest::OperationEnd {
                cell,
                header_process_matches: _,
                schema_matches,
                irp,
                native_status,
                event_version,
            } => {
                if !schema_matches {
                    state.unsupported_schema = Some("schema".to_owned());
                    continue;
                }
                let Some(pending) = state.pending.get(&irp).cloned() else {
                    continue;
                };
                if !admit_subject_event_budget(&mut state, 1) {
                    continue;
                }
                state.pending.remove(&irp);
                if pending.cell == cell {
                    push_completed_frontier_or_invalidate(
                        &mut state,
                        FileOperationV1 {
                            cell,
                            ordinal: pending.ordinal,
                            native_status,
                            object_name_sha256: pending.object_name_sha256,
                            create_event_version: pending.event_version,
                            operation_end_event_version: event_version,
                        },
                    );
                } else {
                    state.incomplete = true;
                }
            }
            PassiveAccessLocalizationEventForTest::Loss => state.events_lost += 1,
            PassiveAccessLocalizationEventForTest::Overflow => {
                state.overflow = Some("test-overflow")
            }
            PassiveAccessLocalizationEventForTest::SubjectTimeout => {
                state.overflow = Some("subject-window");
                state.incomplete = true;
            }
            PassiveAccessLocalizationEventForTest::SessionTimeout => {
                state.overflow = Some("session-window");
                state.incomplete = true;
            }
        }
    }
    if !state.pending.is_empty() {
        state.incomplete = true;
    }
    let canonical = state
        .frontier
        .iter()
        .filter(|event| event.cell == PassiveAccessLocalizationCellV1::CanonicalSameAccess)
        .count();
    let target_user = state
        .frontier
        .iter()
        .filter(|event| event.cell == PassiveAccessLocalizationCellV1::TargetUser)
        .count();
    let invalid = !reproduction_valid
        || cleanup_count != 1
        || state.incomplete
        || state.overflow.is_some()
        || state.events_lost != 0;
    let unsupported_schema = state.unsupported_schema.is_some();
    let classification = if invalid {
        "invalid"
    } else if unsupported_schema {
        "unsupported-provider-schema"
    } else {
        let canonical = state
            .frontier
            .iter()
            .filter(|event| event.cell == PassiveAccessLocalizationCellV1::CanonicalSameAccess)
            .cloned()
            .collect::<Vec<_>>();
        let target_user = state
            .frontier
            .iter()
            .filter(|event| event.cell == PassiveAccessLocalizationCellV1::TargetUser)
            .cloned()
            .collect::<Vec<_>>();
        classify_completed_file_pairs(&canonical, &target_user)
    };
    let frontier = if invalid || unsupported_schema {
        Vec::new()
    } else {
        state.frontier
    };
    PassiveAccessLocalizationEvidenceV1 {
        classification,
        cleanup_count,
        detail_sha256: "none".to_owned(),
        setup_stage: None,
        setup_win32_status: None,
        session_created: true,
        provider_enable_attempted: true,
        consumer_opened: true,
        consumer_ready: true,
        schema_observed: state.total_events != 0 || unsupported_schema,
        session_name_sha256: super::record::digest(b"test-localization"),
        cleanup_provider_disable_status: PassiveAccessLocalizationCleanupStatusV1::Native(
            ERROR_SUCCESS,
        ),
        cleanup_stop_status: PassiveAccessLocalizationCleanupStatusV1::Native(ERROR_SUCCESS),
        cleanup_close_status: PassiveAccessLocalizationCleanupStatusV1::Native(ERROR_SUCCESS),
        cleanup_process_trace_status: PassiveAccessLocalizationCleanupStatusV1::Native(
            ERROR_SUCCESS,
        ),
        cleanup_absence_query_status: PassiveAccessLocalizationCleanupStatusV1::Native(
            ERROR_WMI_INSTANCE_NOT_FOUND,
        ),
        session_absence_proven: true,
        subject_binding_sha256: "test-binding".to_owned(),
        canonical_events: if invalid || unsupported_schema {
            0
        } else {
            canonical
        },
        target_user_events: if invalid || unsupported_schema {
            0
        } else {
            target_user
        },
        frontier,
        invalid,
        unsupported_schema,
        events_lost: state.events_lost,
        overflow: state.overflow.is_some(),
        incomplete: state.incomplete,
    }
}
