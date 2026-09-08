//! Bounded failure observations. These facts never confer terminal or cleanup authority.
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256 as Sha256Hasher};
use std::fmt;

pub const CAUSAL_DIAGNOSTIC_SCHEMA: u32 = 1;
pub const MAX_DIAGNOSTIC_DETAIL_BYTES: usize = 512;
pub const MAX_DIAGNOSTIC_SECONDARY_EVENTS: usize = 8;
pub const MAX_DIAGNOSTIC_PROJECTION_BYTES: usize = 16 * 1024;
pub const MAX_DIAGNOSTIC_JOURNAL_BYTES: usize = 64 * 1024;
pub const MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_RETAINED_DIAGNOSTIC_PAYLOADS: usize = 128;
pub const MAX_RETAINED_DIAGNOSTIC_PAYLOAD_BYTES: usize =
    MAX_RETAINED_DIAGNOSTIC_PAYLOADS * MAX_DIAGNOSTIC_JOURNAL_BYTES;
pub const DIAGNOSTIC_PAYLOAD_RETENTION_SECS: u64 = 24 * 60 * 60;
pub const WINDOWS_RESPONSE_PREFIX_BYTES: usize = 256;
pub const MAX_RECORD_JSON_NODES: usize = 16 * 1024;
pub const MAX_RECORD_METADATA_TEXT_BYTES: usize = 256 * 1024;
pub const WINDOWS_MAX_TERMINAL_FRAME_BYTES: usize = 4 * 1024 * 1024;

pub fn deserialize_bounded_record_text<'de, D: Deserializer<'de>, const N: usize>(
    decoder: D,
) -> Result<String, D::Error> {
    BoundedText::<N>::deserialize(decoder).map(|text| text.0)
}

pub fn deserialize_record_outbox<'de, D: Deserializer<'de>>(
    decoder: D,
) -> Result<Option<String>, D::Error> {
    Option::<BoundedText<{ crate::WINDOWS_MAX_FRAME_BYTES / 2 }>>::deserialize(decoder)
        .map(|text| text.map(|text| text.0))
}

/// Bound container expansion before Serde's internally tagged enum buffering.
/// Strings are visited by reference; this pass never constructs a JSON tree.
pub fn validate_record_json_structure(bytes: &[u8]) -> Result<(), serde_json::Error> {
    use serde::de::{DeserializeSeed, MapAccess};
    struct Budget<'a> {
        remaining: &'a mut usize,
        text_remaining: &'a mut usize,
        depth: usize,
        outbox: bool,
    }
    impl<'de> DeserializeSeed<'de> for Budget<'_> {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
            if *self.remaining == 0 || self.depth > 32 {
                return Err(de::Error::custom("record JSON structural budget exceeded"));
            }
            *self.remaining -= 1;
            decoder.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Budget<'_> {
        type Value = ();
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("bounded record JSON")
        }
        fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
            Ok(())
        }
        fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
            Ok(())
        }
        fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
            Ok(())
        }
        fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
            Ok(())
        }
        fn visit_str<E: de::Error>(self, text: &str) -> Result<(), E> {
            if !self.outbox {
                if text.len() > *self.text_remaining {
                    return Err(de::Error::custom("record metadata text budget exceeded"));
                }
                *self.text_remaining -= text.len();
            }
            Ok(())
        }
        fn visit_unit<E: de::Error>(self) -> Result<(), E> {
            Ok(())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
            while sequence
                .next_element_seed(Budget {
                    remaining: self.remaining,
                    text_remaining: self.text_remaining,
                    depth: self.depth + 1,
                    outbox: false,
                })?
                .is_some()
            {}
            Ok(())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            while let Some(key) = map.next_key::<BoundedText<64>>()? {
                map.next_value_seed(Budget {
                    remaining: self.remaining,
                    text_remaining: self.text_remaining,
                    depth: self.depth + 1,
                    outbox: self.depth == 0 && key.as_str() == "terminal_response_json",
                })?;
            }
            Ok(())
        }
    }
    let mut remaining = MAX_RECORD_JSON_NODES;
    let mut text_remaining = MAX_RECORD_METADATA_TEXT_BYTES;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    Budget {
        remaining: &mut remaining,
        text_remaining: &mut text_remaining,
        depth: 0,
        outbox: false,
    }
    .deserialize(&mut decoder)?;
    decoder.end()
}

/// Version-two response framing requires the compact message discriminator
/// first, allowing diagnostic limits to be checked before allocating payload.
pub fn windows_response_frame_limit(prefix: &[u8]) -> Result<usize, &'static str> {
    let remainder = prefix
        .strip_prefix(b"{\"message\":\"")
        .ok_or("response message discriminator must be first")?;
    let end = remainder
        .iter()
        .position(|byte| *byte == b'"')
        .ok_or("response discriminator exceeds prefix bound")?;
    let kind = &remainder[..end];
    if !kind
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || *byte == b'-')
    {
        return Err("response discriminator is not canonical");
    }
    Ok(match kind {
        b"attempt-retained" | b"replay-pending" => MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES,
        b"workload-plan" | b"workload-discovery" => crate::workload_limits::PUBLIC_OBJECT_BYTES,
        b"terminal" | b"reject" => WINDOWS_MAX_TERMINAL_FRAME_BYTES,
        _ => crate::WINDOWS_MAX_FRAME_BYTES,
    })
}

/// Serialize into one fixed reservation, including the final newline.
pub fn bounded_json_bytes<T: Serialize>(
    value: &T,
    maximum: usize,
    pretty: bool,
) -> Result<Vec<u8>, serde_json::Error> {
    struct Output {
        bytes: Vec<u8>,
        maximum: usize,
    }
    impl std::io::Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
                return Err(std::io::Error::other(
                    "serialized JSON exceeds reserved capacity",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(maximum)
        .map_err(|error| serde_json::Error::io(std::io::Error::other(error)))?;
    let mut output = Output {
        bytes,
        maximum: maximum.saturating_sub(1),
    };
    if pretty {
        serde_json::to_writer_pretty(&mut output, value)?;
    } else {
        serde_json::to_writer(&mut output, value)?;
    }
    if maximum == 0 {
        return Err(serde_json::Error::io(std::io::Error::other(
            "JSON reservation is empty",
        )));
    }
    output.bytes.push(b'\n');
    Ok(output.bytes)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticRetentionV1 {
    pub admitted_monotonic_millis: u64,
    pub expires_monotonic_millis: u64,
    pub tombstone: Option<OriginalUnavailableReasonV1>,
}
impl DiagnosticRetentionV1 {
    pub fn admitted_at(now: u64) -> Result<Self, &'static str> {
        Ok(Self {
            admitted_monotonic_millis: now,
            expires_monotonic_millis: now
                .checked_add(DIAGNOSTIC_PAYLOAD_RETENTION_SECS * 1000)
                .ok_or("diagnostic retention clock exhausted")?,
            tombstone: None,
        })
    }
    pub fn is_consistent(&self) -> bool {
        self.admitted_monotonic_millis
            .checked_add(DIAGNOSTIC_PAYLOAD_RETENTION_SECS * 1000)
            == Some(self.expires_monotonic_millis)
            && self.tombstone.is_none_or(|reason| {
                matches!(
                    reason,
                    OriginalUnavailableReasonV1::RetentionExpired
                        | OriginalUnavailableReasonV1::ObservationNotDurableBeforeServiceLoss
                )
            })
    }
    pub fn export_eligible(&self, same_boot: bool, now: u64) -> bool {
        self.is_consistent()
            && self.tombstone.is_none()
            && same_boot
            && now >= self.admitted_monotonic_millis
            && now < self.expires_monotonic_millis
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum DiagnosticProjectionAvailabilityV1 {
    Available,
    RecordUnavailable,
    ProviderBindingUnavailable,
    InvalidProjection,
    RetentionExpired,
}

impl FailureCodeV1 {
    pub const fn display_code(self) -> &'static str {
        match self {
            Self::ProcessInventoryObservation => "MCSEALED-WINDOWS-PROCESS-INVENTORY",
            Self::ProcessInventoryCapacity => "MCSEALED-WINDOWS-PROCESS-INVENTORY-CAPACITY",
            Self::JobQuery => "MCSEALED-WINDOWS-JOB-QUERY",
            Self::GuardianLoss => "MCSEALED-WINDOWS-GUARDIAN-LOSS",
            Self::TargetCreate => "MCSPAWN-FAILED",
            Self::TargetResume => "MCSEALED-WINDOWS-TARGET-RESUME",
            Self::TargetQuery => "MCSEALED-WINDOWS-TARGET-QUERY",
            Self::ControlTransport => "MCSEALED-WINDOWS-CONTROL-TRANSPORT",
            Self::PolicyAdmission => "MCSEALED-POLICY-ADMISSION",
            Self::PolicyReadback => "MCSEALED-POLICY-READBACK",
            Self::TerminalBinding => "MCSEALED-WINDOWS-TERMINAL-RESPONSE",
            Self::RecordIo => "MCSEALED-WINDOWS-RECORD-IO",
            Self::RecordAuthentication => "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH",
            Self::UnexpectedProviderFailure => "MCSEALED-WINDOWS-LAUNCH",
        }
    }
}

impl SafeDiagnosticDetailV1 {
    pub fn render(&self) -> String {
        match self {
            Self::NoAdditionalDetail => "no additional detail".to_owned(),
            Self::CountAndLimit { observed, limit } => format!("observed={observed} limit={limit}"),
            Self::ProviderMessage { id } => match id {
                SafeMessageIdV1::OriginalFailureCaptured => "original failure captured",
                SafeMessageIdV1::ReceiptRequiredForPosttarget => {
                    "posttarget rejection requires a terminal receipt"
                }
                SafeMessageIdV1::PeerDisconnected => "authenticated peer disconnected",
                SafeMessageIdV1::CommitNotConfirmed => "diagnostic commit not confirmed",
                SafeMessageIdV1::ObservationUnavailableAfterOwnerLoss => {
                    "earlier native observation unavailable after owner loss"
                }
            }
            .to_owned(),
        }
    }
}

impl CausalEventV1 {
    pub fn safe_summary(&self) -> String {
        format!(
            "sequence={} code={} operation={:?} native={:?} phase={:?}: {}",
            self.sequence,
            self.code.display_code(),
            self.operation,
            self.native_code,
            self.observed_phase,
            self.safe_detail.render()
        )
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BoundedVec<T, const N: usize>(Vec<T>);
impl<T: Clone, const N: usize> Clone for BoundedVec<T, N> {
    fn clone(&self) -> Self {
        let mut result = Self::default();
        result.0.extend_from_slice(&self.0);
        result
    }
    fn clone_from(&mut self, source: &Self) {
        self.0.clear();
        self.0.extend_from_slice(&source.0);
    }
}
impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self(Vec::with_capacity(N))
    }
}
impl<T, const N: usize> BoundedVec<T, N> {
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
    pub fn try_push(&mut self, value: T) -> Result<(), T> {
        if self.0.len() == N {
            Err(value)
        } else {
            self.0.push(value);
            Ok(())
        }
    }
}
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for BoundedVec<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedVisitor<T, const N: usize>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for BoundedVisitor<T, N> {
            type Value = BoundedVec<T, N>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "at most {N} elements")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::with_capacity(N);
                while values.len() < N {
                    match seq.next_element()? {
                        Some(value) => values.push(value),
                        None => return Ok(BoundedVec(values)),
                    }
                }
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("diagnostic event bound exceeded"));
                }
                Ok(BoundedVec(values))
            }
        }
        deserializer.deserialize_seq(BoundedVisitor::<T, N>(std::marker::PhantomData))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BoundedText<const N: usize>(String);
impl<const N: usize> BoundedText<N> {
    pub fn new(value: &str) -> Result<Self, &'static str> {
        if value.len() > N || value.contains('\0') {
            Err("invalid diagnostic text")
        } else {
            Ok(Self(value.to_owned()))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de, const N: usize> Deserialize<'de> for BoundedText<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor<const N: usize>;
        impl<const N: usize> Visitor<'_> for TextVisitor<N> {
            type Value = BoundedText<N>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "text no longer than {N} bytes")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                BoundedText::new(value).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(TextVisitor::<N>)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "BoundedText<64>", into = "String")]
pub struct DiagnosticSha256([u8; 32]);
impl DiagnosticSha256 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl TryFrom<BoundedText<64>> for DiagnosticSha256 {
    type Error = &'static str;
    fn try_from(value: BoundedText<64>) -> Result<Self, Self::Error> {
        let mut output = [0; 32];
        if value.0.len() != output.len() * 2 {
            return Err("invalid SHA-256 length");
        }
        for (pair, byte) in value.0.as_bytes().chunks_exact(2).zip(&mut output) {
            let nibble = |n| match n {
                b'0'..=b'9' => Ok(n - b'0'),
                b'a'..=b'f' => Ok(n - b'a' + 10),
                _ => Err("invalid SHA-256 encoding"),
            };
            *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(output))
    }
}
impl From<DiagnosticSha256> for String {
    fn from(value: DiagnosticSha256) -> Self {
        value.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

macro_rules! vocabulary {
    ($name:ident { $($variant:ident = $tag:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
        #[repr(u16)]
        #[serde(rename_all = "kebab-case", deny_unknown_fields)]
        pub enum $name { $($variant = $tag),+ }
    };
}
vocabulary!(DiagnosticOriginV1 { Launcher = 0, ControlRelay = 1, GuardianRecovery = 2, StartupRecovery = 3, RecordWriter = 4, ClientTransport = 5 });
vocabulary!(FailureCategoryV1 { Admission = 0, Launch = 1, Monitor = 2, Cleanup = 3, Terminalization = 4, Transport = 5, Persistence = 6, Recovery = 7 });
vocabulary!(FailureOperationV1 { AuthenticateCaller = 0, ResolveAdmission = 1, InstallPolicy = 2, VerifyPolicy = 3, StartGuardian = 4, CreateTarget = 5, VerifySuspendedTarget = 6, AuthorizeTarget = 7, ResumeTarget = 8, QueryJobProcessIds = 9, ObserveProcessIdentity = 10, AccumulateProcessInventory = 11, ReadJobNotification = 12, QueryPeakMemory = 13, PollTarget = 14, ReadTargetExit = 15, CheckGuardian = 16, CheckDesktopAuthority = 17, ReadControlFrame = 18, TerminateJob = 19, WaitJobEmpty = 20, RetireGuardian = 21, CloseFinalHandles = 22, BuildRejection = 23, ValidateTerminalResponse = 24, SerializeTerminalResponse = 25, StoreRecord = 26, DeliverResponse = 27, AcknowledgeTerminal = 28, RetireOutbox = 29, InspectRecoveryRecord = 30, UnexpectedUnwind = 31, UnclassifiedProviderOperation = 32, QueryJobAccounting = 33 });
vocabulary!(FailureCodeV1 { ProcessInventoryObservation = 0, ProcessInventoryCapacity = 1, JobQuery = 2, GuardianLoss = 3, TargetCreate = 4, TargetResume = 5, TargetQuery = 6, ControlTransport = 7, PolicyAdmission = 8, PolicyReadback = 9, TerminalBinding = 10, RecordIo = 11, RecordAuthentication = 12, UnexpectedProviderFailure = 13 });
vocabulary!(SafeMessageIdV1 { OriginalFailureCaptured = 0, ReceiptRequiredForPosttarget = 1, PeerDisconnected = 2, CommitNotConfirmed = 3, ObservationUnavailableAfterOwnerLoss = 4 });
vocabulary!(AttemptObservationPhaseV1 { BeforeAuthorization = 0, AuthorizedBeforeResume = 1, ResumeAttempted = 2, Monitoring = 3, TargetExitObserved = 4, Cleaning = 5, Terminalizing = 6, Recovery = 7 });
vocabulary!(OriginalUnavailableReasonV1 { NoEarlierErrorObserved = 0, WorkerLostBeforeObservation = 1, ObservationNotDurableBeforeServiceLoss = 2, RecordUnavailable = 3, RecordAuthenticationFailed = 4, LegacyProvider = 5, RetentionExpired = 6 });

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum NativeFailureCodeV1 {
    Win32(u32),
    NtStatus(u32),
    HResult(u32),
    Winsock(i32),
    Errno(i32),
    LegacyUntyped(i32),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum SafeDiagnosticDetailV1 {
    NoAdditionalDetail,
    CountAndLimit { observed: u32, limit: u32 },
    ProviderMessage { id: SafeMessageIdV1 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum TerminalizationReferenceV1 {
    FirstError,
    SecondaryError { index: u8 },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalEventV1 {
    pub sequence: u64,
    pub origin: DiagnosticOriginV1,
    pub category: FailureCategoryV1,
    pub operation: FailureOperationV1,
    pub code: FailureCodeV1,
    pub native_code: Option<NativeFailureCodeV1>,
    pub observed_phase: AttemptObservationPhaseV1,
    pub safe_detail: SafeDiagnosticDetailV1,
    pub detail_redacted: bool,
    pub detail_truncated: bool,
    pub terminalization_reference: Option<TerminalizationReferenceV1>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum OriginalFailureV1 {
    Observed { event: CausalEventV1 },
    Unavailable { reason: OriginalUnavailableReasonV1 },
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticLossV1 {
    pub secondary_events_omitted: u32,
    pub secondary_count_saturated: bool,
    pub persistence_failure_observed: bool,
    pub writer_unavailable: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCausalDiagnosticsV1 {
    pub schema_version: u32,
    pub original: OriginalFailureV1,
    pub secondary: BoundedVec<CausalEventV1, MAX_DIAGNOSTIC_SECONDARY_EVENTS>,
    pub sequence: u64,
    pub durable_through_sequence: Option<u64>,
    pub loss: DiagnosticLossV1,
}
impl Default for WindowsCausalDiagnosticsV1 {
    fn default() -> Self {
        Self {
            schema_version: CAUSAL_DIAGNOSTIC_SCHEMA,
            original: OriginalFailureV1::Unavailable {
                reason: OriginalUnavailableReasonV1::NoEarlierErrorObserved,
            },
            secondary: BoundedVec::default(),
            sequence: 0,
            durable_through_sequence: None,
            loss: DiagnosticLossV1::default(),
        }
    }
}
impl WindowsCausalDiagnosticsV1 {
    /// Copy into the storage reserved at attempt admission. Events contain only
    /// closed enums and scalar fields, so this operation does not allocate.
    pub fn copy_into_reserved(&self, target: &mut Self) {
        target.schema_version = self.schema_version;
        target.original.clone_from(&self.original);
        target.secondary.clone_from(&self.secondary);
        target.sequence = self.sequence;
        target.durable_through_sequence = self.durable_through_sequence;
        target.loss.clone_from(&self.loss);
    }
    pub fn observe_secondary(&mut self, mut event: CausalEventV1) -> Result<(), &'static str> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("diagnostic sequence exhausted")?;
        event.sequence = self.sequence;
        if self.secondary.try_push(event).is_err() {
            let (count, overflow) = self.loss.secondary_events_omitted.overflowing_add(1);
            self.loss.secondary_events_omitted = if overflow { u32::MAX } else { count };
            self.loss.secondary_count_saturated |= overflow;
        }
        Ok(())
    }
    /// The first observation is immutable; later observations retain causal order.
    pub fn observe(&mut self, mut event: CausalEventV1) -> Result<(), &'static str> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("diagnostic sequence exhausted")?;
        event.sequence = self.sequence;
        if matches!(
            self.original,
            OriginalFailureV1::Unavailable {
                reason: OriginalUnavailableReasonV1::NoEarlierErrorObserved
            }
        ) {
            self.original = OriginalFailureV1::Observed { event };
        } else if self.secondary.try_push(event).is_err() {
            let (count, overflow) = self.loss.secondary_events_omitted.overflowing_add(1);
            self.loss.secondary_events_omitted = if overflow { u32::MAX } else { count };
            self.loss.secondary_count_saturated |= overflow;
        }
        Ok(())
    }
    pub fn is_consistent(&self) -> bool {
        if self.schema_version != CAUSAL_DIAGNOSTIC_SCHEMA
            || self
                .durable_through_sequence
                .is_some_and(|v| v > self.sequence)
        {
            return false;
        }
        let mut previous = 0;
        let original = match &self.original {
            OriginalFailureV1::Observed { event } => Some(event),
            _ => None,
        };
        for event in original.into_iter().chain(self.secondary.as_slice()) {
            if event.sequence != previous + 1
                || event.sequence > self.sequence
                || matches!(event.terminalization_reference, Some(TerminalizationReferenceV1::SecondaryError { index }) if usize::from(index) >= crate::WINDOWS_MAX_TERMINALIZATION_SECONDARY_ERRORS)
            {
                return false;
            }
            previous = event.sequence;
        }
        if self.loss.secondary_events_omitted > 0
            && self.secondary.as_slice().len() != MAX_DIAGNOSTIC_SECONDARY_EVENTS
        {
            return false;
        }
        if self.loss.secondary_count_saturated {
            self.loss.secondary_events_omitted == u32::MAX
                && self.sequence > previous + u64::from(u32::MAX)
        } else {
            self.sequence == previous + u64::from(self.loss.secondary_events_omitted)
        }
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_DIAGNOSTIC_JOURNAL_BYTES {
            return Err("diagnostic journal byte bound exceeded");
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| "malformed diagnostic journal")?;
        if !value.is_consistent() {
            return Err("inconsistent diagnostic journal");
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicProviderBindingV1 {
    pub generation: BoundedText<256>,
    pub source_commit: BoundedText<64>,
    pub runtime_manifest_sha256: DiagnosticSha256,
}
impl PublicProviderBindingV1 {
    pub fn is_consistent(&self) -> bool {
        let generation = self.generation.as_str();
        let commit = self.source_commit.as_str();
        const SHA1_BYTES: usize = std::mem::size_of::<[u8; 20]>();
        const SHA256_BYTES: usize = std::mem::size_of::<[u8; 32]>();
        !generation.is_empty()
            && generation.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
            })
            && [SHA1_BYTES * 2, SHA256_BYTES * 2].contains(&commit.len())
            && commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

/// A projection checked against the provider and attempt authenticated by the caller.
#[derive(Clone, Debug)]
pub struct ValidatedProviderFailureDiagnosticV1(ProviderFailureDiagnosticV1);
impl ValidatedProviderFailureDiagnosticV1 {
    pub fn into_projection(self) -> ProviderFailureDiagnosticV1 {
        self.0
    }
    pub fn projection(&self) -> &ProviderFailureDiagnosticV1 {
        &self.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderFailureDiagnosticV1 {
    pub schema_version: u32,
    pub provider_binding: PublicProviderBindingV1,
    pub attempt_id: DiagnosticSha256,
    pub request_sha256: DiagnosticSha256,
    pub diagnostic_sequence: u64,
    pub durable_through_sequence: Option<u64>,
    pub original: OriginalFailureV1,
    pub secondary: BoundedVec<CausalEventV1, MAX_DIAGNOSTIC_SECONDARY_EVENTS>,
    pub loss: DiagnosticLossV1,
    pub projection_sha256: DiagnosticSha256,
}
impl ProviderFailureDiagnosticV1 {
    pub fn safe_summary(&self) -> String {
        let mut summary = match &self.original {
            OriginalFailureV1::Observed { event } => format!("original: {}", event.safe_summary()),
            OriginalFailureV1::Unavailable { reason } => {
                format!("original-unavailable: {reason:?}")
            }
        };
        for event in self.secondary.as_slice() {
            summary.push_str("; secondary: ");
            summary.push_str(&event.safe_summary());
        }
        summary
    }
    pub fn from_journal(
        provider_binding: PublicProviderBindingV1,
        attempt_id: &str,
        request_sha256: &str,
        journal: &WindowsCausalDiagnosticsV1,
    ) -> Result<Self, &'static str> {
        let mut projection = Self {
            schema_version: CAUSAL_DIAGNOSTIC_SCHEMA,
            provider_binding,
            attempt_id: DiagnosticSha256::try_from(BoundedText::new(attempt_id)?)?,
            request_sha256: DiagnosticSha256::try_from(BoundedText::new(request_sha256)?)?,
            diagnostic_sequence: journal.sequence,
            durable_through_sequence: journal.durable_through_sequence,
            original: journal.original.clone(),
            secondary: journal.secondary.clone(),
            loss: journal.loss.clone(),
            projection_sha256: DiagnosticSha256::from_bytes([0; 32]),
        };
        if !projection.is_consistent() {
            return Err("invalid diagnostic projection binding or journal");
        }
        projection.projection_sha256 = projection.canonical_digest();
        if serde_json::to_vec(&projection)
            .map_err(|_| "diagnostic serialization failed")?
            .len()
            > MAX_DIAGNOSTIC_PROJECTION_BYTES
        {
            return Err("diagnostic projection byte bound exceeded");
        }
        Ok(projection)
    }
    pub fn matches_journal(
        &self,
        attempt_id: &str,
        request_sha256: &str,
        journal: &WindowsCausalDiagnosticsV1,
    ) -> bool {
        String::from(self.attempt_id.clone()) == attempt_id
            && String::from(self.request_sha256.clone()) == request_sha256
            && self.diagnostic_sequence == journal.sequence
            && self.durable_through_sequence == journal.durable_through_sequence
            && self.original == journal.original
            && self.secondary == journal.secondary
            && self.loss == journal.loss
    }
    /// Structural validation is independent from authenticating the enclosing transport.
    pub fn is_consistent(&self) -> bool {
        self.schema_version == CAUSAL_DIAGNOSTIC_SCHEMA
            && self.provider_binding.is_consistent()
            && WindowsCausalDiagnosticsV1 {
                schema_version: self.schema_version,
                original: self.original.clone(),
                secondary: self.secondary.clone(),
                sequence: self.diagnostic_sequence,
                durable_through_sequence: self.durable_through_sequence,
                loss: self.loss.clone(),
            }
            .is_consistent()
    }
    pub fn canonical_digest(&self) -> DiagnosticSha256 {
        let mut hash = Sha256Hasher::new();
        hash.update(b"memcordon:causal-diagnostic:v1\0");
        hash.update(self.schema_version.to_be_bytes());
        for text in [
            self.provider_binding.generation.as_str(),
            self.provider_binding.source_commit.as_str(),
        ] {
            hash.update(
                u64::try_from(text.len())
                    .expect("bounded text length")
                    .to_be_bytes(),
            );
            hash.update(text.as_bytes());
        }
        hash.update(self.provider_binding.runtime_manifest_sha256.bytes());
        hash.update(self.attempt_id.bytes());
        hash.update(self.request_sha256.bytes());
        hash.update(self.diagnostic_sequence.to_be_bytes());
        match self.durable_through_sequence {
            None => hash.update([0]),
            Some(value) => {
                hash.update([1]);
                hash.update(value.to_be_bytes());
            }
        }
        match &self.original {
            OriginalFailureV1::Observed { event } => {
                hash.update([0]);
                hash_event(&mut hash, event);
            }
            OriginalFailureV1::Unavailable { reason } => {
                hash.update([1]);
                hash.update((*reason as u16).to_be_bytes());
            }
        }
        hash.update(
            u64::try_from(self.secondary.as_slice().len())
                .expect("bounded event length")
                .to_be_bytes(),
        );
        for event in self.secondary.as_slice() {
            hash_event(&mut hash, event);
        }
        hash.update(self.loss.secondary_events_omitted.to_be_bytes());
        hash.update([
            u8::from(self.loss.secondary_count_saturated),
            u8::from(self.loss.persistence_failure_observed),
            u8::from(self.loss.writer_unavailable),
        ]);
        DiagnosticSha256::from_bytes(hash.finalize().into())
    }
    pub fn parse_bound(
        bytes: &[u8],
        provider: &PublicProviderBindingV1,
        attempt: &DiagnosticSha256,
        request: &DiagnosticSha256,
    ) -> Result<ValidatedProviderFailureDiagnosticV1, &'static str> {
        if bytes.len() > MAX_DIAGNOSTIC_PROJECTION_BYTES {
            return Err("diagnostic projection byte bound exceeded");
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| "malformed diagnostic projection")?;
        if !value.is_consistent()
            || &value.provider_binding != provider
            || &value.attempt_id != attempt
            || &value.request_sha256 != request
            || value.projection_sha256 != value.canonical_digest()
        {
            return Err("unbound or invalid diagnostic projection");
        }
        Ok(ValidatedProviderFailureDiagnosticV1(value))
    }
}

fn hash_event(hash: &mut Sha256Hasher, event: &CausalEventV1) {
    hash.update(event.sequence.to_be_bytes());
    for value in [
        event.origin as u16,
        event.category as u16,
        event.operation as u16,
        event.code as u16,
    ] {
        hash.update(value.to_be_bytes());
    }
    match event.native_code {
        None => hash.update([0]),
        Some(code) => {
            let (domain, value) = match code {
                NativeFailureCodeV1::Win32(v) => (1, v.to_be_bytes()),
                NativeFailureCodeV1::NtStatus(v) => (2, v.to_be_bytes()),
                NativeFailureCodeV1::HResult(v) => (3, v.to_be_bytes()),
                NativeFailureCodeV1::Winsock(v) => (4, v.to_be_bytes()),
                NativeFailureCodeV1::Errno(v) => (5, v.to_be_bytes()),
                NativeFailureCodeV1::LegacyUntyped(v) => (6, v.to_be_bytes()),
            };
            hash.update([domain]);
            hash.update(value);
        }
    }
    hash.update((event.observed_phase as u16).to_be_bytes());
    match event.safe_detail {
        SafeDiagnosticDetailV1::NoAdditionalDetail => hash.update([0]),
        SafeDiagnosticDetailV1::CountAndLimit { observed, limit } => {
            hash.update([1]);
            hash.update(observed.to_be_bytes());
            hash.update(limit.to_be_bytes());
        }
        SafeDiagnosticDetailV1::ProviderMessage { id } => {
            hash.update([2]);
            hash.update((id as u16).to_be_bytes());
        }
    }
    hash.update([
        u8::from(event.detail_redacted),
        u8::from(event.detail_truncated),
    ]);
    match event.terminalization_reference {
        None => hash.update([0]),
        Some(TerminalizationReferenceV1::FirstError) => hash.update([1]),
        Some(TerminalizationReferenceV1::SecondaryError { index }) => hash.update([2, index]),
    }
}
