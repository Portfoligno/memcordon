use memcordon_core::{
    BoundaryMechanismEvidence, ChildTermination, NativeWindowsCommandV1, RestartSafetyProof,
    RunOutcome, WINDOWS_CONTROL_PIPE, WINDOWS_PUBLIC_PROTOCOL_VERSION, WindowsLaunchPolicyV1,
    WindowsLaunchRequestV1, WindowsLifetimeV1, WindowsProviderRequestV3, WindowsProviderResponseV3,
    WindowsPublicFrameFailureV1, WindowsPublicFramePhaseV1, WindowsPublicTerminalRecoveryV1,
    WindowsRelayEventV1, WindowsRelayPhaseV1, WindowsSealedEvidenceV2, WindowsStreamRoleV1,
    WindowsTerminalReplayDecisionV1, WindowsTokenMatrixEvidenceV1, WindowsTokenScenarioEvidenceV1,
};

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct NestedChildReceiptV1 {
    schema_version: u32,
    attempt_binding: String,
    target_mode: TargetResultModeV1,
    child_identity: memcordon_core::WindowsProcessIdentityV1,
    initial_thread_token_id: u64,
    initial_thread_token_envelope: memcordon_core::WindowsCallerTokenEnvelopeV1,
    initial_token_behavior_attested: bool,
    initial_token_reverted: bool,
    thread_token_absent_after_revert: bool,
    token_envelope: memcordon_core::WindowsCallerTokenEnvelopeV1,
    process_token_id: u64,
    restricted_sid_count: u32,
    restricting_sids: Vec<String>,
    write_restricted_code_present: bool,
    restricted_code_absent: bool,
    write_restricted: bool,
    token_is_restricted: bool,
    enabled_sensitive_privilege_count: u32,
    in_any_job: bool,
    standard_streams: [u64; 3],
    standard_streams_verified: bool,
    window_station_name: String,
    desktop_name: String,
    desktop_policy_verified: bool,
    private_desktop_binding_verified: bool,
    success: bool,
    detail: String,
}

pub(super) const CLEANUP_PROCESS_CREATION_RESULT_SCHEMA_VERSION: u32 = 1;
pub(super) const CLEANUP_PROCESS_CREATION_STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) enum CleanupProcessCreationOutcomeV1 {
    Created {
        child_pid: u32,
    },
    Failed {
        phase: CleanupProcessCreationFailurePhaseV1,
        code: String,
        os_code: Option<i32>,
        detail: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum CleanupProcessCreationFailurePhaseV1 {
    ChildSpawn,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CleanupProcessCreationResultV1 {
    pub(super) schema_version: u32,
    pub(super) attempt_binding: String,
    pub(super) producer_pid: u32,
    pub(super) producer_identity: memcordon_core::WindowsProcessIdentityV1,
    pub(super) completed_phases: Vec<CleanupProcessCreationProducerPhaseV1>,
    pub(super) outcome: CleanupProcessCreationOutcomeV1,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CleanupProcessCreationProducerFailureV1 {
    pub(super) code: String,
    pub(super) last_completed_phase: Option<CleanupProcessCreationProducerPhaseV1>,
    pub(super) attempted_phase: Option<CleanupProcessCreationProducerPhaseV1>,
    pub(super) operation: CleanupProcessCreationOperationV1,
    pub(super) path_role: Option<CleanupProcessCreationPathRoleV1>,
    pub(super) io_error_kind: Option<String>,
    pub(super) os_code: Option<i32>,
    pub(super) detail: String,
    pub(super) secondary_publication_failure: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum CleanupProcessCreationOperationV1 {
    StartObservation,
    StateSerialize,
    StateStageOpen,
    StateStageWrite,
    StateStageSync,
    StatePublishRename,
    TerminalSerialize,
    TerminalStageOpen,
    TerminalStageWrite,
    TerminalStageSync,
    TerminalPublishRename,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum CleanupProcessCreationPathRoleV1 {
    StartSignal,
    PhaseStaging,
    PhaseReceipt,
    SuccessStaging,
    SuccessReceipt,
    FailureStaging,
    FailureReceipt,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "terminal", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum CleanupProcessCreationTerminalV1 {
    Success(CleanupProcessCreationResultV1),
    Failed {
        schema_version: u32,
        attempt_binding: String,
        producer_pid: u32,
        producer_identity: memcordon_core::WindowsProcessIdentityV1,
        completed_phases: Vec<CleanupProcessCreationProducerPhaseV1>,
        failure: CleanupProcessCreationProducerFailureV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum CleanupProcessCreationProducerPhaseV1 {
    Ready,
    StartObserved,
    SpawnEntered,
    SpawnReturned,
    ResultStaged,
    ResultSynced,
    ResultPublished,
}

impl CleanupProcessCreationProducerPhaseV1 {
    const fn receipt_extension(self) -> &'static str {
        match self {
            Self::Ready => "state.00-ready.json",
            Self::StartObserved => "state.01-start-observed.json",
            Self::SpawnEntered => "state.02-spawn-entered.json",
            Self::SpawnReturned => "state.03-spawn-returned.json",
            Self::ResultStaged => "state.04-result-staged.json",
            Self::ResultSynced => "state.05-result-synced.json",
            Self::ResultPublished => "state.06-result-published.json",
        }
    }
}

pub(super) const CLEANUP_PROCESS_CREATION_PRODUCER_PHASES: [CleanupProcessCreationProducerPhaseV1;
    7] = [
    CleanupProcessCreationProducerPhaseV1::Ready,
    CleanupProcessCreationProducerPhaseV1::StartObserved,
    CleanupProcessCreationProducerPhaseV1::SpawnEntered,
    CleanupProcessCreationProducerPhaseV1::SpawnReturned,
    CleanupProcessCreationProducerPhaseV1::ResultStaged,
    CleanupProcessCreationProducerPhaseV1::ResultSynced,
    CleanupProcessCreationProducerPhaseV1::ResultPublished,
];

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CleanupProcessCreationStateV1 {
    pub(super) schema_version: u32,
    pub(super) attempt_binding: String,
    pub(super) producer_pid: u32,
    pub(super) producer_identity: memcordon_core::WindowsProcessIdentityV1,
    pub(super) sequence: u32,
    pub(super) completed_phases: Vec<CleanupProcessCreationProducerPhaseV1>,
    pub(super) phase: CleanupProcessCreationProducerPhaseV1,
    pub(super) outcome: Option<CleanupProcessCreationOutcomeV1>,
}

pub(super) const TARGET_RESULT_SCHEMA_VERSION: u32 = 1;
const QUALIFICATION_JOB_TOTAL_PROCESSES_MINIMUM: u32 = 18;
const TARGET_RESULT_DETAIL_MAX_BYTES: usize = memcordon_core::WINDOWS_MAX_FRAME_BYTES / 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum TargetResultModeV1 {
    Standard,
    NestedAlternateToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TargetResultPhaseV1 {
    ArgumentBinding,
    HandleInheritance,
    StandardStreams,
    ProcessTree,
    OuterJobMembership,
    RestrictedPrimaryConstruction,
    InnerJobCreation,
    StreamSetup,
    LoaderContext,
    SuspendedChildCreation,
    TokenMembershipReadback,
    MarkerPublication,
    Resume,
    ChildExit,
    InnerJobEmpty,
    Complete,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetResultReceiptV1 {
    pub(super) schema_version: u32,
    pub(super) attempt_binding: String,
    pub(super) target_mode: TargetResultModeV1,
    pub(super) phase: TargetResultPhaseV1,
    pub(super) success: bool,
    pub(super) detail: String,
}

struct TargetCanaryError {
    phase: TargetResultPhaseV1,
    detail: String,
}

impl TargetCanaryError {
    fn at(phase: TargetResultPhaseV1, detail: impl Into<String>) -> Self {
        Self {
            phase,
            detail: detail.into(),
        }
    }
}

fn target_phase<T>(
    phase: TargetResultPhaseV1,
    result: Result<T, String>,
) -> Result<T, TargetCanaryError> {
    result.map_err(|detail| TargetCanaryError::at(phase, detail))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QualificationPublicationProducerV1 {
    TargetResult,
    NestedChild,
}

impl QualificationPublicationProducerV1 {
    const fn name(self) -> &'static str {
        match self {
            Self::TargetResult => "target-result",
            Self::NestedChild => "nested-child",
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::TargetResult => "MCSEALED-WINDOWS-TARGET-RESULT-PUBLICATION",
            Self::NestedChild => "MCSEALED-WINDOWS-NESTED-CHILD",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QualificationPublicationStageV1 {
    ReceiptSerialize,
    ReceiptStageOpen,
    ReceiptStageWrite,
    ReceiptStageSync,
    ReceiptPublishRename,
}

impl QualificationPublicationStageV1 {
    const fn name(self) -> &'static str {
        match self {
            Self::ReceiptSerialize => "receipt-serialize",
            Self::ReceiptStageOpen => "receipt-stage-open",
            Self::ReceiptStageWrite => "receipt-stage-write",
            Self::ReceiptStageSync => "receipt-stage-sync",
            Self::ReceiptPublishRename => "receipt-publish-rename",
        }
    }

    const fn api(self) -> &'static str {
        match self {
            Self::ReceiptSerialize => "serde_json::to_vec_pretty",
            Self::ReceiptStageOpen => "CreateFileW(CREATE_NEW)",
            Self::ReceiptStageWrite => "WriteFile",
            Self::ReceiptStageSync => "FlushFileBuffers",
            Self::ReceiptPublishRename => "SetFileInformationByHandle(FileRenameInfo)",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QualificationPublicationPathRoleV1 {
    Staging,
    Destination,
}

impl QualificationPublicationPathRoleV1 {
    const fn name(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Destination => "destination",
        }
    }
}

#[derive(Debug)]
struct QualificationPublicationFailure {
    producer: QualificationPublicationProducerV1,
    stage: QualificationPublicationStageV1,
    api: &'static str,
    path_role: QualificationPublicationPathRoleV1,
    path: std::path::PathBuf,
    requested_access: Option<u32>,
    io_error_kind: Option<std::io::ErrorKind>,
    native_code: Option<i32>,
    detail: String,
}

impl QualificationPublicationFailure {
    const CREATE_ONCE_STAGING_ACCESS: u32 = 0x4001_0000;

    fn protocol(
        producer: QualificationPublicationProducerV1,
        stage: QualificationPublicationStageV1,
        path_role: QualificationPublicationPathRoleV1,
        path: &std::path::Path,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            producer,
            stage,
            api: stage.api(),
            path_role,
            path: path.to_owned(),
            requested_access: None,
            io_error_kind: None,
            native_code: None,
            detail: bounded_qualification_publication_detail(detail.into()),
        }
    }

    fn io(
        producer: QualificationPublicationProducerV1,
        stage: QualificationPublicationStageV1,
        path_role: QualificationPublicationPathRoleV1,
        path: &std::path::Path,
        requested_access: Option<u32>,
        error: std::io::Error,
    ) -> Self {
        Self {
            producer,
            stage,
            api: stage.api(),
            path_role,
            path: path.to_owned(),
            requested_access,
            io_error_kind: Some(error.kind()),
            native_code: error.raw_os_error(),
            detail: bounded_qualification_publication_detail(error.to_string()),
        }
    }

    fn publication(
        producer: QualificationPublicationProducerV1,
        stage: QualificationPublicationStageV1,
        path_role: QualificationPublicationPathRoleV1,
        path: &std::path::Path,
        requested_access: Option<u32>,
        error: super::record::CreateOncePublicationFailure,
    ) -> Self {
        Self {
            producer,
            stage,
            api: error.stage().api(),
            path_role,
            path: path.to_owned(),
            requested_access,
            io_error_kind: Some(error.kind()),
            native_code: error.raw_os_error(),
            detail: bounded_qualification_publication_detail(error.to_string()),
        }
    }
}

impl std::fmt::Display for QualificationPublicationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: producer={} stage={} api={} object_role=qualification-receipt path_role={} path={} requested_access={} io_kind={} native_code={} detail={}",
            self.producer.code(),
            self.producer.name(),
            self.stage.name(),
            self.api,
            self.path_role.name(),
            self.path.display(),
            self.requested_access
                .map_or_else(|| "none".to_owned(), |access| format!("0x{access:08x}")),
            self.io_error_kind
                .map_or_else(|| "none".to_owned(), |kind| format!("{kind:?}")),
            self.native_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.detail,
        )
    }
}

fn bounded_qualification_publication_detail(mut detail: String) -> String {
    while detail.len() > TARGET_RESULT_DETAIL_MAX_BYTES {
        detail.pop();
    }
    detail
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QualificationTerminalAcknowledgmentStageV1 {
    BoundReceiptWrite,
}

impl QualificationTerminalAcknowledgmentStageV1 {
    const fn name(self) -> &'static str {
        match self {
            Self::BoundReceiptWrite => "bound-receipt-write",
        }
    }

    const fn api(self) -> &'static str {
        match self {
            Self::BoundReceiptWrite => "WriteFile(named-pipe-frame)",
        }
    }
}

#[derive(Debug)]
struct QualificationTerminalAcknowledgmentFailure {
    stage: QualificationTerminalAcknowledgmentStageV1,
    attempt_id: String,
    nonce_sha256: String,
    request_sha256: String,
    detail: String,
}

impl QualificationTerminalAcknowledgmentFailure {
    fn bound_receipt_write(
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
        detail: String,
    ) -> Self {
        Self {
            stage: QualificationTerminalAcknowledgmentStageV1::BoundReceiptWrite,
            attempt_id: attempt_id.to_owned(),
            nonce_sha256: super::record::digest(nonce.as_bytes()),
            request_sha256: request_sha256.to_owned(),
            detail: bounded_qualification_publication_detail(detail),
        }
    }
}

impl std::fmt::Display for QualificationTerminalAcknowledgmentFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-TERMINAL-ACKNOWLEDGMENT: stage={} api={} object_role=bound-terminal-delivery attempt_id={} nonce_sha256={} request_sha256={} detail={}",
            self.stage.name(),
            self.stage.api(),
            self.attempt_id,
            self.nonce_sha256,
            self.request_sha256,
            self.detail,
        )
    }
}

fn acknowledge_latched_qualification_terminal<T>(
    semantic_result: Result<T, String>,
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    acknowledge: impl FnOnce() -> Result<(), String>,
) -> Result<T, String> {
    let acknowledgment_result = acknowledge().map_err(|detail| {
        QualificationTerminalAcknowledgmentFailure::bound_receipt_write(
            attempt_id,
            nonce,
            request_sha256,
            detail,
        )
    });
    match (semantic_result, acknowledgment_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(acknowledgment)) => Err(acknowledgment.to_string()),
        (Err(primary), Err(acknowledgment)) => Err(format!(
            "{primary}; terminal acknowledgment failed after bound receipt was latched: {acknowledgment}"
        )),
    }
}

fn acknowledge_and_confirm_terminal_retirement(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    terminal_response_sha256: &str,
) -> Result<(), String> {
    super::pipe::write_frame(
        pipe,
        &WindowsProviderRequestV3::TerminalAcknowledged {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            attempt_id: attempt_id.to_owned(),
            nonce: nonce.to_owned(),
            request_sha256: request_sha256.to_owned(),
            terminal_response_sha256: terminal_response_sha256.to_owned(),
        },
    )?;
    confirm_terminal_retirement_response(
        super::pipe::read_response_frame::<WindowsProviderResponseV3>(pipe)?,
        attempt_id,
        nonce,
        request_sha256,
        terminal_response_sha256,
    )
}

pub(crate) fn confirm_terminal_retirement_response(
    response: WindowsProviderResponseV3,
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    terminal_response_sha256: &str,
) -> Result<(), String> {
    match response {
        WindowsProviderResponseV3::TerminalRetiredV2(retired)
            if retired.is_consistent_for(
                attempt_id,
                nonce,
                request_sha256,
                terminal_response_sha256,
            ) =>
        {
            Ok(())
        }
        WindowsProviderResponseV3::AttemptRetainedV2(retained)
            if retained.is_consistent_for(
                attempt_id,
                nonce,
                request_sha256,
                WindowsRelayPhaseV1::Terminal,
            ) =>
        {
            Err(format!(
                "terminal ACK was forwarded but attempt authority remains: primary={} secondary={}",
                retained.primary_detail,
                retained.secondary_failures.join(" | ")
            ))
        }
        _ => Err("provider did not confirm exact terminal retirement".to_owned()),
    }
}

#[cfg(test)]
pub(crate) fn acknowledge_latched_qualification_terminal_for_test<T>(
    semantic_result: Result<T, String>,
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    acknowledge: impl FnOnce() -> Result<(), String>,
) -> Result<T, String> {
    acknowledge_latched_qualification_terminal(
        semantic_result,
        attempt_id,
        nonce,
        request_sha256,
        acknowledge,
    )
}

fn publish_native_fixture_result<T: serde::Serialize + ?Sized>(
    destination: &std::path::Path,
    producer: QualificationPublicationProducerV1,
    receipt: &T,
) -> Result<(), QualificationPublicationFailure> {
    let staged = staged_receipt_path(destination);
    let mut bytes = serde_json::to_vec_pretty(receipt).map_err(|error| {
        QualificationPublicationFailure::protocol(
            producer,
            QualificationPublicationStageV1::ReceiptSerialize,
            QualificationPublicationPathRoleV1::Destination,
            destination,
            error.to_string(),
        )
    })?;
    bytes.push(b'\n');
    let mut file = super::record::CreateOnceStagingFile::create(&staged).map_err(|error| {
        QualificationPublicationFailure::io(
            producer,
            QualificationPublicationStageV1::ReceiptStageOpen,
            QualificationPublicationPathRoleV1::Staging,
            &staged,
            Some(QualificationPublicationFailure::CREATE_ONCE_STAGING_ACCESS),
            error,
        )
    })?;
    std::io::Write::write_all(file.file_mut(), &bytes).map_err(|error| {
        QualificationPublicationFailure::io(
            producer,
            QualificationPublicationStageV1::ReceiptStageWrite,
            QualificationPublicationPathRoleV1::Staging,
            &staged,
            None,
            error,
        )
    })?;
    file.sync_all().map_err(|error| {
        QualificationPublicationFailure::io(
            producer,
            QualificationPublicationStageV1::ReceiptStageSync,
            QualificationPublicationPathRoleV1::Staging,
            &staged,
            None,
            error,
        )
    })?;
    super::record::publish_create_once_atomically(file, destination).map_err(|error| {
        QualificationPublicationFailure::publication(
            producer,
            QualificationPublicationStageV1::ReceiptPublishRename,
            QualificationPublicationPathRoleV1::Destination,
            destination,
            Some(QualificationPublicationFailure::CREATE_ONCE_STAGING_ACCESS),
            error,
        )
    })
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QualificationPublicationProducerForTest {
    TargetResult,
    NestedChild,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct QualificationPublicationFailureForTest {
    pub(crate) producer: String,
    pub(crate) stage: String,
    pub(crate) api: String,
    pub(crate) path_role: String,
    pub(crate) requested_access: Option<u32>,
    pub(crate) io_error_kind: Option<std::io::ErrorKind>,
    pub(crate) native_code: Option<i32>,
    pub(crate) detail: String,
}

#[cfg(test)]
pub(crate) fn publish_native_fixture_result_for_test(
    destination: &std::path::Path,
    producer: QualificationPublicationProducerForTest,
) -> Result<(), QualificationPublicationFailureForTest> {
    #[derive(serde::Serialize)]
    struct QualificationPublicationProbeV1 {
        schema_version: u32,
        producer: &'static str,
    }

    let producer = match producer {
        QualificationPublicationProducerForTest::TargetResult => {
            QualificationPublicationProducerV1::TargetResult
        }
        QualificationPublicationProducerForTest::NestedChild => {
            QualificationPublicationProducerV1::NestedChild
        }
    };
    let receipt = QualificationPublicationProbeV1 {
        schema_version: 1,
        producer: producer.name(),
    };
    publish_native_fixture_result(destination, producer, &receipt).map_err(|failure| {
        QualificationPublicationFailureForTest {
            producer: failure.producer.name().to_owned(),
            stage: failure.stage.name().to_owned(),
            api: failure.api.to_owned(),
            path_role: failure.path_role.name().to_owned(),
            requested_access: failure.requested_access,
            io_error_kind: failure.io_error_kind,
            native_code: failure.native_code,
            detail: failure.detail,
        }
    })
}

struct TokenFixtureObservation {
    envelope: memcordon_core::WindowsCallerTokenEnvelopeV1,
    restricted_sid_count: u32,
    restricting_sids: Vec<String>,
    token_is_restricted: bool,
    write_restricted: bool,
    enabled_sensitive_privilege_count: u32,
    administrator_deny_only: bool,
}

impl TokenFixtureObservation {
    fn current() -> Result<Self, String> {
        Ok(Self::from_snapshot(
            super::token::current_thread_fixture_snapshot().map_err(|detail| {
                token_fixture_failure(
                    "elevated-admin",
                    "token-snapshot",
                    "GetTokenInformation",
                    detail,
                )
            })?,
        ))
    }

    fn retained(guard: &super::token::RestrictedImpersonationGuard) -> Self {
        Self::from_snapshot(guard.fixture_snapshot())
    }

    fn from_snapshot(snapshot: super::token::TokenFixtureSnapshot) -> Self {
        Self {
            envelope: snapshot.envelope,
            restricted_sid_count: snapshot.restricted_sid_count,
            restricting_sids: snapshot.restricting_sids,
            token_is_restricted: snapshot.token_is_restricted,
            write_restricted: snapshot.write_restricted,
            enabled_sensitive_privilege_count: snapshot.enabled_sensitive_privilege_count,
            administrator_deny_only: snapshot.administrator_deny_only,
        }
    }

    fn scenario(
        self,
        name: &str,
        initial_target_token_matches_caller: bool,
    ) -> WindowsTokenScenarioEvidenceV1 {
        WindowsTokenScenarioEvidenceV1 {
            name: name.to_owned(),
            caller_envelope: self.envelope,
            restricted_sid_count: self.restricted_sid_count,
            restricting_sids: self.restricting_sids,
            token_is_restricted: self.token_is_restricted,
            write_restricted: self.write_restricted,
            enabled_sensitive_privilege_count: self.enabled_sensitive_privilege_count,
            administrator_deny_only: self.administrator_deny_only,
            initial_target_token_matches_caller,
        }
    }
}

fn token_fixture_failure(
    scenario: &'static str,
    stage: &'static str,
    api: &'static str,
    detail: String,
) -> String {
    format!(
        "MCSEALED-WINDOWS-QUALIFICATION: stage={stage} scenario={scenario} api={api} role=qualification-token-fixture native_code=none detail={detail}"
    )
}

struct RemoveFileGuard(std::path::PathBuf);

impl Drop for RemoveFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct CleanupCreationMarkerGuard(Option<std::path::PathBuf>);

impl CleanupCreationMarkerGuard {
    fn remove_after_success(&mut self) {
        let Some(marker) = self.0.take() else {
            return;
        };
        for path in cleanup_process_creation_owned_paths(&marker) {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl Drop for CleanupCreationMarkerGuard {
    fn drop(&mut self) {
        // Failure artifacts remain in the nonce-bound certification workspace
        // for CI collection. Successful certification calls remove_after_success.
    }
}

struct TargetResultGuard(std::path::PathBuf);

impl Drop for TargetResultGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("result.new"));
    }
}

struct CertificationWorkspaceGuard(std::path::PathBuf);

impl Drop for CertificationWorkspaceGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn signal_relay_retirement(event: &mut Option<super::pipe::OwnedHandle>) -> Result<(), String> {
    let event = event
        .take()
        .ok_or_else(|| "relay-retirement event was not transferred".to_owned())?;
    // SAFETY: event is the launcher-created handle adopted from the complete
    // StreamsPrepared frame and remains live through this signal.
    if unsafe { windows_sys::Win32::System::Threading::SetEvent(event.raw()) } == 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

pub fn probe() -> Result<memcordon_core::WindowsProviderProbeV1, String> {
    let pipe = super::pipe::connect(memcordon_core::WINDOWS_CONTROL_PIPE)?;
    let peer = qualification_control_peer_identity(pipe.raw())?;
    let manager = super::service_manager::manager()?;
    if super::service_manager::running_process_id(
        &manager,
        memcordon_core::WINDOWS_CONTROL_SERVICE_NAME,
    )? != peer.process_id
    {
        return Err("live provider probe peer differs from SCM control service".into());
    }
    let expected = super::package::installed_public_provider_binding()?;
    super::pipe::write_frame(
        pipe.raw(),
        &memcordon_core::WindowsProviderRequestV3::Probe {
            schema_version: memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION,
        },
    )?;
    match super::pipe::read_response_frame::<memcordon_core::WindowsProviderResponseV3>(pipe.raw())?
    {
        memcordon_core::WindowsProviderResponseV3::Probe {
            schema_version,
            observation,
        } if schema_version == memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION
            && observation.validate().is_ok()
            && observation.provider_binding == expected =>
        {
            Ok(observation)
        }
        memcordon_core::WindowsProviderResponseV3::Reject { rejection, .. } => {
            Err(format!("{}: {}", rejection.code, rejection.detail))
        }
        _ => Err("Windows sealed control service returned an invalid probe receipt".to_owned()),
    }
}

fn service_process_identity(
    process_id: u32,
    stage: &'static str,
    role: &'static str,
) -> Result<memcordon_core::WindowsProcessIdentityV1, String> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // SAFETY: the PID is obtained from the SCM and the handle requests only
    // process identity/query authority, never token authority.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if raw.is_null() {
        let error = std::io::Error::last_os_error();
        return Err(format!(
            "MCSEALED-WINDOWS-SERVICE-ATTESTATION: component=qualification-frontend stage={stage} api=OpenProcess role={role} native_code={} detail={error}",
            error
                .raw_os_error()
                .map_or_else(|| "none".to_owned(), |code| code.to_string())
        ));
    }
    let process = super::pipe::OwnedHandle::new(raw).map_err(|detail| {
        format!(
            "MCSEALED-WINDOWS-SERVICE-ATTESTATION: component=qualification-frontend stage={stage} api=OwnedHandle::new role={role} native_code=none detail={detail}"
        )
    })?;
    super::process::process_identity(process.raw()).map_err(|detail| {
        format!(
            "MCSEALED-WINDOWS-SERVICE-ATTESTATION: component=qualification-frontend stage={stage} api=GetProcessTimes role={role} native_code=none detail={detail}"
        )
    })
}

#[cfg(test)]
pub(crate) fn terminal_frame_truncation_canary() -> Result<bool, String> {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    let mut reader = std::ptr::null_mut();
    let mut writer = std::ptr::null_mut();
    // SAFETY: both outputs are writable and null attributes create a private,
    // synchronous anonymous pipe.
    if unsafe { CreatePipe(&raw mut reader, &raw mut writer, std::ptr::null(), 0) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let reader = super::pipe::OwnedHandle::new(reader)?;
    let writer = super::pipe::OwnedHandle::new(writer)?;
    let payload = br#"{"kind":"terminal"}"#;
    let declared = u32::try_from(payload.len()).map_err(|error| error.to_string())?;
    let mut frame = declared.to_le_bytes().to_vec();
    frame.extend_from_slice(
        payload
            .strip_suffix(b"}")
            .ok_or_else(|| "terminal-frame canary payload has no suffix".to_owned())?,
    );
    let writer_thread = std::thread::spawn(move || -> Result<(), String> {
        let mut written = 0_u32;
        // SAFETY: frame and output storage remain live for the synchronous write.
        if unsafe {
            WriteFile(
                writer.raw(),
                frame.as_ptr(),
                u32::try_from(frame.len()).map_err(|error| error.to_string())?,
                &raw mut written,
                std::ptr::null_mut(),
            )
        } == 0
            || usize::try_from(written).ok() != Some(frame.len())
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    });
    let rejected =
        super::pipe::read_response_frame::<WindowsProviderResponseV3>(reader.raw()).is_err();
    writer_thread
        .join()
        .map_err(|_| "terminal-frame writer panicked".to_owned())??;
    Ok(rejected)
}

pub fn leaked_handle_mutant_target(
    marker: &std::ffi::OsStr,
    kind: &std::ffi::OsStr,
    raw_handle: &std::ffi::OsStr,
) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let raw_handle = String::from_utf16(&raw_handle.encode_wide().collect::<Vec<_>>())
        .map_err(|error| error.to_string())?
        .parse::<u64>()
        .map_err(|error| format!("invalid leaked-handle value: {error}"))?
        as usize as windows_sys::Win32::Foundation::HANDLE;
    let kind = String::from_utf16(&kind.encode_wide().collect::<Vec<_>>())
        .map_err(|error| error.to_string())?;
    let observed = match kind.as_str() {
        "job" => {
            let mut inside = 0_i32;
            (unsafe { IsProcessInJob(GetCurrentProcess(), raw_handle, &raw mut inside) }) != 0
                && inside != 0
        }
        "pipe" => (unsafe { GetFileType(raw_handle) }) == FILE_TYPE_PIPE,
        _ => return Err("unknown leaked-handle mutant kind".to_owned()),
    };
    if !observed {
        return Err(format!(
            "target did not observe the inherited {kind} handle mutant"
        ));
    }
    std::fs::write(marker, format!("leaked-{kind}-handle-observed\n"))
        .map_err(|error| error.to_string())?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5 * 60);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Ok(())
}

#[derive(Default)]
struct QualificationRelayRetirement {
    streams: Vec<super::pipe::OwnedHandle>,
    event: Option<super::pipe::OwnedHandle>,
    retired: bool,
}

impl QualificationRelayRetirement {
    fn retire(&mut self) -> Result<(), String> {
        if self.retired {
            return Ok(());
        }
        self.streams.clear();
        signal_relay_retirement(&mut self.event)?;
        self.retired = true;
        Ok(())
    }
}

impl Drop for QualificationRelayRetirement {
    fn drop(&mut self) {
        let _ = self.retire();
    }
}

fn qualification_control_peer_identity(
    pipe: windows_sys::Win32::Foundation::HANDLE,
) -> Result<memcordon_core::WindowsProcessIdentityV1, String> {
    super::security::SecurityDescriptor::from_sddl(&super::security::public_pipe_sddl()?)?
        .verify_named_pipe(pipe)
        .map_err(|error| error.to_string())?;
    let mut server_pid = 0_u32;
    // SAFETY: pipe is a connected client endpoint and output storage is live.
    if unsafe {
        windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId(pipe, &raw mut server_pid)
    } == 0
        || server_pid == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    super::process::process_identity_for_pid(server_pid)?
        .ok_or_else(|| "qualification control-service process identity is unavailable".to_owned())
}

pub(crate) fn render_replay_pending(pending: &memcordon_core::WindowsReplayPendingV2) -> String {
    let last_error_stage = pending
        .terminalization
        .last_error
        .as_ref()
        .map(|error| format!("{:?}", error.stage))
        .unwrap_or_else(|| "None".to_owned());
    let last_error_code = pending
        .terminalization
        .last_error
        .as_ref()
        .map(|error| error.error_code.as_str())
        .unwrap_or("None");
    let last_error_detail = pending
        .terminalization
        .last_error
        .as_ref()
        .map(|error| error.detail.lines().collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|| "None".to_owned());
    let last_error_native_code = pending
        .terminalization
        .last_error
        .as_ref()
        .map(|error| format!("{:?}", error.native_code))
        .unwrap_or_else(|| "None".to_owned());
    let last_error_observed_unix_millis = pending
        .terminalization
        .last_error
        .as_ref()
        .map(|error| format!("{:?}", error.observed_unix_millis))
        .unwrap_or_else(|| "None".to_owned());
    format!(
        "attempt_id={} relay_phase={:?} durable_state={:?} terminal_disposition={:?} checkpoint={:?} missing_proofs={:?} authorization_present={} resume_attempted={} target_released={} termination_requested={} active_processes_zero={} guardian_reaped={} final_handles_closed={} outbox_stage={:?} terminalization_owner={:?} terminalization_sequence={} terminalization_checkpoint={:?} last_error_stage={} last_error_code={} last_error_detail={} last_error_native_code={} last_error_observed_unix_millis={}",
        pending.attempt_id,
        pending.relay_phase,
        pending.durable_state,
        pending.terminal_disposition,
        pending.checkpoint,
        pending.missing_proofs,
        pending.authorization_present,
        pending.resume_attempted,
        pending.target_released,
        pending.cleanup_state.termination_requested,
        pending.cleanup_state.active_processes_zero,
        pending.cleanup_state.guardian_reaped,
        pending.cleanup_state.final_handles_closed,
        pending.outbox_stage,
        pending.terminalization.owner,
        pending.terminalization.sequence,
        pending.terminalization.checkpoint,
        last_error_stage,
        last_error_code,
        last_error_detail,
        last_error_native_code,
        last_error_observed_unix_millis,
    )
}

fn qualification_public_frame_failure(
    error: &super::pipe::FrameReadError,
) -> WindowsPublicFrameFailureV1 {
    let phase = match error.phase {
        super::pipe::FrameReadPhase::Length => WindowsPublicFramePhaseV1::Length,
        super::pipe::FrameReadPhase::Payload => WindowsPublicFramePhaseV1::Payload,
        super::pipe::FrameReadPhase::Decode => WindowsPublicFramePhaseV1::Decode,
    };
    if error.peer_closed {
        WindowsPublicFrameFailureV1::PeerClosed(phase)
    } else {
        WindowsPublicFrameFailureV1::Protocol(phase)
    }
}

fn read_qualification_replay_response(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    deadline: std::time::Instant,
    primary: &str,
) -> Result<WindowsProviderResponseV3, String> {
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "{primary}; secondary qualification terminal replay response deadline expired"
            ));
        }
        match super::pipe::frame_available_detailed(pipe) {
            Ok(true) => {
                return super::pipe::read_response_frame_detailed(pipe).map_err(|secondary| {
                    format!(
                        "{primary}; secondary qualification terminal replay read failure: {secondary}"
                    )
                });
            }
            Ok(false) => super::pipe::wait_poll_interval(),
            Err(secondary) => {
                return Err(format!(
                    "{primary}; secondary qualification terminal replay availability failure: {secondary}"
                ));
            }
        }
    }
}

fn write_qualification_terminal_replay(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    relay_phase: WindowsRelayPhaseV1,
) -> Result<(), String> {
    super::pipe::write_frame(
        pipe,
        &WindowsProviderRequestV3::ReplayTerminal {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            attempt_id: attempt_id.to_owned(),
            nonce: nonce.to_owned(),
            request_sha256: request_sha256.to_owned(),
            relay_phase,
        },
    )
}

pub(crate) fn qualification_process_attempt_id(
    nonce: &str,
    request_sha256: &str,
    caller: &memcordon_core::WindowsProcessIdentityV1,
) -> String {
    let mut identity = nonce.as_bytes().to_vec();
    identity.extend_from_slice(&caller.process_id.to_le_bytes());
    identity.extend_from_slice(&caller.creation_time_100ns.to_le_bytes());
    identity.extend_from_slice(request_sha256.as_bytes());
    super::record::digest(&identity)
}

pub(crate) fn qualification_pretarget_attempt_id(nonce: &str, request_sha256: &str) -> String {
    let mut identity = nonce.as_bytes().to_vec();
    identity.extend_from_slice(request_sha256.as_bytes());
    identity.extend_from_slice(b"pretarget-rejection-v1");
    super::record::digest(&identity)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_native_reject(
    schema_version: u32,
    returned_attempt: &str,
    returned_nonce: &str,
    returned_digest: &str,
    rejection: &memcordon_core::WindowsProviderRejectionV2,
    active_attempt: Option<&str>,
    expected_process_attempt: &str,
    expected_pretarget_attempt: &str,
    expected_nonce: &str,
    expected_digest: &str,
    relay_phase: WindowsRelayPhaseV1,
) -> Result<(), String> {
    if schema_version != WINDOWS_PUBLIC_PROTOCOL_VERSION {
        return Err(invalid_native_response("reject", relay_phase, "schema"));
    }
    let attempt_matches = active_attempt.map_or_else(
        || {
            returned_attempt == expected_process_attempt
                || returned_attempt == expected_pretarget_attempt
        },
        |active| returned_attempt == active,
    );
    if !attempt_matches {
        return Err(invalid_native_response("reject", relay_phase, "attempt-id"));
    }
    if returned_nonce != expected_nonce {
        return Err(invalid_native_response("reject", relay_phase, "nonce"));
    }
    if returned_digest != expected_digest {
        return Err(invalid_native_response(
            "reject",
            relay_phase,
            "request-digest",
        ));
    }
    if !rejection.is_consistent() {
        return Err(invalid_native_response(
            "reject",
            relay_phase,
            "rejection-consistency",
        ));
    }
    if !rejection.terminal_receipt().is_none_or(|terminal| {
        terminal.attempt_id == returned_attempt
            && terminal.nonce == returned_nonce
            && terminal.request_sha256 == returned_digest
    }) {
        return Err(invalid_native_response(
            "reject",
            relay_phase,
            "terminal-binding",
        ));
    }
    Ok(())
}

fn invalid_native_response(
    variant: &str,
    relay_phase: WindowsRelayPhaseV1,
    predicate: &str,
) -> String {
    format!(
        "qualification canary received an invalid response: variant={variant} relay_phase={relay_phase:?} predicate={predicate}"
    )
}

fn provider_response_variant(response: &WindowsProviderResponseV3) -> &'static str {
    match response {
        WindowsProviderResponseV3::Probe { .. } => "probe",
        WindowsProviderResponseV3::WorkloadPlan { .. } => "workload-plan",
        WindowsProviderResponseV3::WorkloadDiscovery { .. } => "workload-discovery",
        WindowsProviderResponseV3::StreamsPrepared { .. } => "streams-prepared",
        WindowsProviderResponseV3::RecoveryStatus { .. } => "recovery-status",
        WindowsProviderResponseV3::RecoveryInventory(_) => "recovery-inventory",
        WindowsProviderResponseV3::RecoveryAttemptUnavailable { .. } => {
            "recovery-attempt-unavailable"
        }
        WindowsProviderResponseV3::PackageCleanupResult { .. } => "package-cleanup-result",
        WindowsProviderResponseV3::CertificationMachineRestart { .. } => {
            "certification-machine-restart"
        }
        WindowsProviderResponseV3::TargetAuthorized { .. } => "target-authorized",
        WindowsProviderResponseV3::TargetRetired { .. } => "target-retired",
        WindowsProviderResponseV3::RelaysAbort { .. } => "relays-abort",
        WindowsProviderResponseV3::CertificationMutantHookObserved(_) => {
            "certification-mutant-hook-observed"
        }
        WindowsProviderResponseV3::CertificationMutantObserved(_) => {
            "certification-mutant-observed"
        }
        WindowsProviderResponseV3::Terminal(_) => "terminal",
        WindowsProviderResponseV3::Reject { .. } => "reject",
        WindowsProviderResponseV3::AttemptRetained(_) => "attempt-retained",
        WindowsProviderResponseV3::AttemptRetainedV2(_) => "attempt-retained-v2",
        WindowsProviderResponseV3::ReplayPending(_) => "replay-pending",
        WindowsProviderResponseV3::ReplayPendingV2(_) => "replay-pending-v2",
        WindowsProviderResponseV3::TerminalRetired(_) => "terminal-retired",
        WindowsProviderResponseV3::TerminalRetiredV2(_) => "terminal-retired-v2",
    }
}

fn advance_qualification_relay_phase(
    phase: &mut WindowsRelayPhaseV1,
    event: WindowsRelayEventV1,
) -> Result<(), String> {
    let before = *phase;
    phase
        .advance(event)
        .map_err(|detail| format!("qualification {detail}: phase={before:?} event={event:?}"))
}

pub(super) fn read_bound_target_result(
    path: &std::path::Path,
    nonce: &str,
    target_mode: &str,
) -> Result<TargetResultReceiptV1, String> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        format!(
            "qualification target-result receipt is absent: path={} error={error}",
            path.display()
        )
    })?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_file() {
        return Err("qualification target-result receipt is not a regular file".to_owned());
    }
    let receipt: TargetResultReceiptV1 = serde_json::from_slice(
        &std::fs::read(path).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("qualification target-result receipt is malformed: {error}"))?;
    let expected_binding = format!("attempt-{}", super::record::digest(nonce.as_bytes()));
    let expected_mode = target_result_mode(target_mode)?;
    if receipt.schema_version != TARGET_RESULT_SCHEMA_VERSION
        || receipt.attempt_binding != expected_binding
        || receipt.target_mode != expected_mode
        || receipt.detail.is_empty()
        || receipt.detail.len() > TARGET_RESULT_DETAIL_MAX_BYTES
        || (receipt.success && receipt.phase != TargetResultPhaseV1::Complete)
        || (!receipt.success && receipt.phase == TargetResultPhaseV1::Complete)
    {
        return Err(format!(
            "qualification target-result receipt is inconsistent: schema_version={} binding_matches={} mode_matches={} phase={:?} success={} detail_present={}",
            receipt.schema_version,
            receipt.attempt_binding == expected_binding,
            receipt.target_mode == expected_mode,
            receipt.phase,
            receipt.success,
            !receipt.detail.is_empty(),
        ));
    }
    Ok(receipt)
}

fn validate_qualification_terminal<'a>(
    terminal: &'a memcordon_core::WindowsTerminalReceiptV2,
    target_result: &TargetResultReceiptV1,
) -> Result<&'a WindowsSealedEvidenceV2, String> {
    if terminal.schema_version != 2 {
        return Err(format!(
            "qualification terminal schema-version invariant failed: observed={}",
            terminal.schema_version
        ));
    }
    if !terminal
        .restart_safety
        .is_safe_for(memcordon_core::BoundaryRequirement::Sealed)
    {
        return Err("qualification terminal restart-safety invariant failed".to_owned());
    }
    let Some((_, outcome, BoundaryMechanismEvidence::WindowsJobObjectV2(evidence))) =
        terminal.execution()
    else {
        return Err("qualification terminal boundary-evidence variant invariant failed".to_owned());
    };
    if !evidence.active_processes_zero
        || !evidence.relays_retired
        || !evidence.guardian_reaped
        || !evidence.final_job_handles_closed
    {
        return Err(format!(
            "qualification terminal boundary-evidence cleanup invariant failed: active_zero={} relays_retired={} guardian_reaped={} final_handles_closed={}",
            evidence.active_processes_zero,
            evidence.relays_retired,
            evidence.guardian_reaped,
            evidence.final_job_handles_closed,
        ));
    }
    if !target_result.success {
        return Err(format!(
            "qualification target failed: phase={:?} detail={}",
            target_result.phase, target_result.detail
        ));
    }
    let cleanup = terminal.cleanup_process_creation.as_ref().ok_or_else(|| {
        "qualification terminal cleanup-process-creation presence invariant failed".to_owned()
    })?;
    validate_cleanup_process_creation_evidence(cleanup)?;
    let accounting = terminal
        .process_observation
        .final_accounting
        .as_ref()
        .ok_or_else(|| {
            "qualification terminal final native accounting is unavailable".to_owned()
        })?;
    if accounting.total_processes_native_u32 < QUALIFICATION_JOB_TOTAL_PROCESSES_MINIMUM {
        return Err(format!(
            "qualification terminal cumulative-job-accounting invariant failed: observed={} required_minimum={QUALIFICATION_JOB_TOTAL_PROCESSES_MINIMUM}",
            accounting.total_processes_native_u32
        ));
    }
    if accounting.total_processes_native_u32 < cleanup.total_processes_after {
        return Err(format!(
            "qualification terminal cumulative-job-accounting contradicted cleanup evidence: observed={} cleanup_total={}",
            accounting.total_processes_native_u32, cleanup.total_processes_after
        ));
    }
    let validated = terminal
        .validate_for_certification(
            &target_result.attempt_binding,
            QUALIFICATION_JOB_TOTAL_PROCESSES_MINIMUM,
        )
        .map_err(|field| {
            format!("qualification terminal complete-evidence invariant failed: field={field}")
        })?;
    match outcome {
        RunOutcome::Exited {
            child: ChildTermination::ExitCode { code: 0 },
            ..
        } => Ok(validated.native),
        ref outcome => Err(format!(
            "qualification terminal target-outcome invariant failed: outcome={outcome:?} target_phase={:?} target_detail={}",
            target_result.phase, target_result.detail
        )),
    }
}

fn validate_cleanup_process_creation_evidence(
    evidence: &memcordon_core::WindowsCleanupProcessCreationEvidenceV1,
) -> Result<(), String> {
    if evidence.schema_version != 1 {
        return Err("qualification cleanup schema-version invariant failed".to_owned());
    }
    if !evidence.attempt_binding.starts_with("attempt-") {
        return Err("qualification cleanup attempt-binding invariant failed".to_owned());
    }
    if !evidence.attempted_after_terminating_transition {
        return Err("qualification cleanup terminating-transition invariant failed".to_owned());
    }
    if !evidence.child_created {
        return Err("qualification cleanup child-created invariant failed".to_owned());
    }
    if !evidence.child_job_membership_verified {
        return Err("qualification cleanup child-membership invariant failed".to_owned());
    }
    if evidence.child_identity.process_id == 0 {
        return Err("qualification cleanup child-identity invariant failed".to_owned());
    }
    if evidence.total_processes_after <= evidence.total_processes_before {
        return Err("qualification cleanup cumulative-accounting invariant failed".to_owned());
    }
    if !evidence.final_active_processes_zero {
        return Err("qualification cleanup final-active-zero invariant failed".to_owned());
    }
    Ok(())
}

pub fn certification_target_canary(canary_handles: &[std::ffi::OsString]) -> Result<(), String> {
    let (target_result, canary_handles) = canary_handles
        .split_first()
        .ok_or_else(|| "target-result path is absent".to_owned())?;
    let (cleanup_marker, canary_handles) = canary_handles
        .split_first()
        .ok_or_else(|| "cleanup-creation marker path is absent".to_owned())?;
    let result = (|| {
        let (expected_streams, unexpected_arguments) = split_stream_identity(canary_handles)
            .map_err(|detail| {
                TargetCanaryError::at(TargetResultPhaseV1::ArgumentBinding, detail)
            })?;
        if !unexpected_arguments.is_empty() {
            return Err(TargetCanaryError::at(
                TargetResultPhaseV1::ArgumentBinding,
                "qualification target received unexpected trailing arguments",
            ));
        }
        verify_standard_streams(expected_streams).map_err(|detail| {
            TargetCanaryError::at(TargetResultPhaseV1::StandardStreams, detail)
        })?;
        process_tree_canary(std::path::Path::new(cleanup_marker))
            .map_err(|detail| TargetCanaryError::at(TargetResultPhaseV1::ProcessTree, detail))
    })();
    publish_target_result(
        std::path::Path::new(target_result),
        TargetResultModeV1::Standard,
        &result,
    )?;
    result.map_err(|error| error.detail)
}

pub fn certification_nested_target_canary(
    canary_handles: &[std::ffi::OsString],
) -> Result<(), String> {
    let (target_result, canary_handles) = canary_handles
        .split_first()
        .ok_or_else(|| "target-result path is absent".to_owned())?;
    let (marker, canary_handles) = canary_handles
        .split_first()
        .ok_or_else(|| "nested certification marker path is absent".to_owned())?;
    let (cleanup_marker, canary_handles) = canary_handles
        .split_first()
        .ok_or_else(|| "cleanup-creation marker path is absent".to_owned())?;
    let result = (|| {
        let (expected_streams, unexpected_arguments) = split_stream_identity(canary_handles)
            .map_err(|detail| {
                TargetCanaryError::at(TargetResultPhaseV1::ArgumentBinding, detail)
            })?;
        if !unexpected_arguments.is_empty() {
            return Err(TargetCanaryError::at(
                TargetResultPhaseV1::ArgumentBinding,
                "qualification target received unexpected trailing arguments",
            ));
        }
        verify_standard_streams(expected_streams).map_err(|detail| {
            TargetCanaryError::at(TargetResultPhaseV1::StandardStreams, detail)
        })?;
        process_tree_canary(std::path::Path::new(cleanup_marker))
            .map_err(|detail| TargetCanaryError::at(TargetResultPhaseV1::ProcessTree, detail))?;
        nested_alternate_token_target_canary(std::path::Path::new(marker))
    })();
    publish_target_result(
        std::path::Path::new(target_result),
        TargetResultModeV1::NestedAlternateToken,
        &result,
    )?;
    result.map_err(|error| error.detail)
}

fn target_result_mode(target_mode: &str) -> Result<TargetResultModeV1, String> {
    match target_mode {
        "windows-certification-target" => Ok(TargetResultModeV1::Standard),
        "windows-certification-nested-target" => Ok(TargetResultModeV1::NestedAlternateToken),
        _ => Err(format!(
            "unsupported qualification target mode: {target_mode}"
        )),
    }
}

fn publish_target_result(
    path: &std::path::Path,
    target_mode: TargetResultModeV1,
    result: &Result<(), TargetCanaryError>,
) -> Result<(), String> {
    let attempt_binding = path
        .parent()
        .and_then(std::path::Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| "target-result path has no UTF-8 attempt binding".to_owned())?
        .to_owned();
    if path.file_name() != Some(std::ffi::OsStr::new("target.result"))
        || !attempt_binding.starts_with("attempt-")
    {
        return Err("target-result path is not a bound certification leaf".to_owned());
    }
    let (phase, success, mut detail) = match result {
        Ok(()) => (TargetResultPhaseV1::Complete, true, "complete".to_owned()),
        Err(error) => (error.phase, false, error.detail.clone()),
    };
    if detail.len() > TARGET_RESULT_DETAIL_MAX_BYTES {
        detail = "target diagnostic exceeded the bounded receipt detail".to_owned();
    }
    let receipt = TargetResultReceiptV1 {
        schema_version: TARGET_RESULT_SCHEMA_VERSION,
        attempt_binding,
        target_mode,
        phase,
        success,
        detail,
    };
    publish_native_fixture_result(
        path,
        QualificationPublicationProducerV1::TargetResult,
        &receipt,
    )
    .map_err(|error| error.to_string())
}

fn split_stream_identity(
    arguments: &[std::ffi::OsString],
) -> Result<(&[std::ffi::OsString], &[std::ffi::OsString]), String> {
    let expected_count = [
        windows_sys::Win32::System::Console::STD_INPUT_HANDLE,
        windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE,
        windows_sys::Win32::System::Console::STD_ERROR_HANDLE,
    ]
    .len();
    if arguments.len() < expected_count {
        return Err("configured standard-stream identity is absent".to_owned());
    }
    Ok(arguments.split_at(expected_count))
}

fn verify_standard_streams(expected_streams: &[std::ffi::OsString]) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    let handles = [
        unsafe { GetStdHandle(STD_INPUT_HANDLE) },
        unsafe { GetStdHandle(STD_OUTPUT_HANDLE) },
        unsafe { GetStdHandle(STD_ERROR_HANDLE) },
    ];
    let expected = expected_streams
        .iter()
        .map(|value| {
            String::from_utf16(&value.encode_wide().collect::<Vec<_>>())
                .map_err(|error| error.to_string())?
                .parse::<u64>()
                .map(|handle| handle as usize as windows_sys::Win32::Foundation::HANDLE)
                .map_err(|error| format!("invalid configured stream identity: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if handles.as_slice() != expected {
        return Err("target standard handles differ from the configured provider pipes".to_owned());
    }
    for (index, handle) in handles.iter().copied().enumerate() {
        if handle.is_null()
            || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
            || unsafe { GetFileType(handle) } != FILE_TYPE_PIPE
            || handles[..index].contains(&handle)
        {
            return Err(
                "target standard handles are not three distinct provider pipe objects".to_owned(),
            );
        }
    }
    Ok(())
}

fn process_tree_canary(cleanup_marker: &std::path::Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use windows_sys::Win32::System::Threading::{
        CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
    };

    let executable = crate::windows::package::installed_binary();
    let status = Command::new(&executable)
        .arg("windows-certification-grandchild")
        .status()
        .map_err(|error| {
            qualification_native_failure(
                "qualification-target-spawn",
                "CreateProcessW",
                "child-grandchild",
                Some(&executable),
                &error,
            )
        })?;
    if !status.success() {
        return Err("child/grandchild containment canary failed".to_owned());
    }
    let status = Command::new(&executable)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS)
        .status()
        .map_err(|error| {
            qualification_native_failure(
                "qualification-target-spawn",
                "CreateProcessW",
                "detached-process-group",
                Some(&executable),
                &error,
            )
        })?;
    if !status.success() {
        return Err("detached new-process-group descendant canary failed".to_owned());
    }
    match Command::new(&executable)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
        .spawn()
    {
        Err(_) => {}
        Ok(mut child) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("descendant escaped with CREATE_BREAKAWAY_FROM_JOB".to_owned());
        }
    }
    for ordinal in 0..16 {
        let status = Command::new(&executable)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| {
                let role = format!("rapid-descendant-{ordinal}");
                qualification_native_failure(
                    "qualification-target-spawn",
                    "CreateProcessW",
                    &role,
                    Some(&executable),
                    &error,
                )
            })?;
        if !status.success() {
            return Err("rapid descendant churn canary failed".to_owned());
        }
    }
    let state = cleanup_process_creation_phase_path(
        cleanup_marker,
        CleanupProcessCreationProducerPhaseV1::Ready,
    );
    let stderr_path = cleanup_marker.with_extension("stderr");
    let stderr = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stderr_path)
        .map_err(|error| {
            format!(
                "cleanup producer fallback stderr could not be created: path={} detail={error}",
                stderr_path.display()
            )
        })?;
    let mut producer = Command::new(&executable)
        .arg("windows-certification-cleanup-churn")
        .arg(cleanup_marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| {
            format!(
                "cleanup producer spawn failed: executable={} marker={} os_code={:?} detail={error}",
                executable.display(),
                cleanup_marker.display(),
                error.raw_os_error(),
            )
        })?;
    let producer_pid = producer.id();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match std::fs::read(&state) {
            Ok(bytes) => {
                let ready: CleanupProcessCreationStateV1 = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("cleanup producer state is malformed: {error}"))?;
                let attempt_binding = cleanup_marker
                    .parent()
                    .and_then(std::path::Path::file_name)
                    .and_then(std::ffi::OsStr::to_str)
                    .ok_or_else(|| {
                        "cleanup producer state has no UTF-8 attempt binding".to_owned()
                    })?;
                if ready.schema_version != CLEANUP_PROCESS_CREATION_STATE_SCHEMA_VERSION
                    || ready.attempt_binding != attempt_binding
                    || ready.producer_pid != producer_pid
                    || ready.producer_identity.process_id != producer_pid
                    || ready.sequence != 1
                    || ready.completed_phases != [CleanupProcessCreationProducerPhaseV1::Ready]
                    || ready.phase != CleanupProcessCreationProducerPhaseV1::Ready
                    || ready.outcome.is_some()
                {
                    return Err("cleanup producer ready state is inconsistent".to_owned());
                }
                if let Some(status) = producer.try_wait().map_err(|error| {
                    format!(
                        "cleanup producer post-ready wait failed: os_code={:?} detail={error}",
                        error.raw_os_error()
                    )
                })? {
                    return Err(format!(
                        "cleanup producer exited after ready publication: status={status}"
                    ));
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cleanup producer ready read failed: path={} os_code={:?} detail={error}",
                    state.display(),
                    error.raw_os_error(),
                ));
            }
        }
        if let Some(status) = producer.try_wait().map_err(|error| {
            format!(
                "cleanup producer pre-ready wait failed: os_code={:?} detail={error}",
                error.raw_os_error()
            )
        })? {
            let failure = cleanup_marker.with_extension("failure");
            let staged_failure = staged_receipt_path(&failure);
            return Err(format!(
                "cleanup producer exited before ready publication: status={status} failure_receipt={} staged_failure={} fallback_stderr={}",
                cleanup_producer_fallback_diagnostic(&failure),
                cleanup_producer_fallback_diagnostic(&staged_failure),
                cleanup_producer_fallback_diagnostic(&stderr_path),
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err("cleanup-time process-creation canary did not become active".to_owned());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok(())
}

pub fn grandchild_parent_canary() -> Result<(), String> {
    let executable = crate::windows::package::installed_binary();
    let status = std::process::Command::new(&executable)
        .arg("--version")
        .status()
        .map_err(|error| {
            qualification_native_failure(
                "qualification-target-spawn",
                "CreateProcessW",
                "grandchild-version",
                Some(&executable),
                &error,
            )
        })?;
    if status.success() {
        Ok(())
    } else {
        Err("grandchild containment canary failed".to_owned())
    }
}

pub fn cleanup_churn_canary(marker: &std::ffi::OsStr) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let executable = crate::windows::package::installed_binary();
    let marker = std::path::Path::new(marker);
    let attempt_binding = cleanup_process_creation_attempt_binding(marker)?;
    let producer_identity = super::process::process_identity(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })?;
    let mut completed_phases = Vec::new();
    let run = (|| -> Result<bool, CleanupProducerFailure> {
        publish_cleanup_process_creation_state(
            marker,
            &attempt_binding,
            &producer_identity,
            &completed_phases,
            CleanupProcessCreationProducerPhaseV1::Ready,
            None,
        )?;
        completed_phases.push(CleanupProcessCreationProducerPhaseV1::Ready);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5 * 60);
        while !cleanup_process_creation_start_observed(marker, completed_phases.last().copied())? {
            if std::time::Instant::now() >= deadline {
                return Err(CleanupProducerFailure::protocol(
                    completed_phases.last().copied(),
                    Some(CleanupProcessCreationProducerPhaseV1::StartObserved),
                    CleanupProcessCreationOperationV1::StartObservation,
                    "cleanup-creation start signal was not observed",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        publish_cleanup_process_creation_state(
            marker,
            &attempt_binding,
            &producer_identity,
            &completed_phases,
            CleanupProcessCreationProducerPhaseV1::StartObserved,
            None,
        )?;
        completed_phases.push(CleanupProcessCreationProducerPhaseV1::StartObserved);
        publish_cleanup_process_creation_state(
            marker,
            &attempt_binding,
            &producer_identity,
            &completed_phases,
            CleanupProcessCreationProducerPhaseV1::SpawnEntered,
            None,
        )?;
        completed_phases.push(CleanupProcessCreationProducerPhaseV1::SpawnEntered);
        let outcome = match Command::new(&executable)
            .arg("windows-certification-hold")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => CleanupProcessCreationOutcomeV1::Created {
                child_pid: child.id(),
            },
            Err(error) => CleanupProcessCreationOutcomeV1::Failed {
                phase: CleanupProcessCreationFailurePhaseV1::ChildSpawn,
                code: "MCSEALED-WINDOWS-CLEANUP-CHILD-SPAWN".to_owned(),
                os_code: error.raw_os_error(),
                detail: bounded_cleanup_producer_detail(error.to_string()),
            },
        };
        publish_cleanup_process_creation_state(
            marker,
            &attempt_binding,
            &producer_identity,
            &completed_phases,
            CleanupProcessCreationProducerPhaseV1::SpawnReturned,
            Some(&outcome),
        )?;
        completed_phases.push(CleanupProcessCreationProducerPhaseV1::SpawnReturned);
        let child_created = matches!(outcome, CleanupProcessCreationOutcomeV1::Created { .. });
        publish_cleanup_process_creation_success_terminal(
            marker,
            &attempt_binding,
            &producer_identity,
            &mut completed_phases,
            outcome,
        )?;
        Ok(child_created)
    })();

    match run {
        Ok(child_created) => {
            if child_created {
                std::thread::sleep(std::time::Duration::from_secs(5 * 60));
            }
            Ok(())
        }
        Err(primary) => {
            let mut failure = primary.receipt;
            let terminal = CleanupProcessCreationTerminalV1::Failed {
                schema_version: CLEANUP_PROCESS_CREATION_RESULT_SCHEMA_VERSION,
                attempt_binding,
                producer_pid: producer_identity.process_id,
                producer_identity,
                completed_phases,
                failure: failure.clone(),
            };
            if let Err(secondary) = publish_cleanup_process_creation_terminal(
                marker,
                &terminal,
                failure.last_completed_phase,
            ) {
                failure.secondary_publication_failure =
                    Some(bounded_cleanup_producer_detail(secondary.receipt.detail));
            }
            Err(format!(
                "{}: last_completed_phase={:?} attempted_phase={:?} operation={:?} os_code={:?} detail={} secondary_publication_failure={:?}",
                failure.code,
                failure.last_completed_phase,
                failure.attempted_phase,
                failure.operation,
                failure.os_code,
                failure.detail,
                failure.secondary_publication_failure,
            ))
        }
    }
}

fn cleanup_process_creation_start_observed(
    marker: &std::path::Path,
    last_completed_phase: Option<CleanupProcessCreationProducerPhaseV1>,
) -> Result<bool, CleanupProducerFailure> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let start = marker.with_extension("start");
    let file = match std::fs::File::open(&start) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(CleanupProducerFailure::io(
                last_completed_phase,
                Some(CleanupProcessCreationProducerPhaseV1::StartObserved),
                CleanupProcessCreationOperationV1::StartObservation,
                CleanupProcessCreationPathRoleV1::StartSignal,
                &start,
                error,
            ));
        }
    };
    let metadata = file.metadata().map_err(|error| {
        CleanupProducerFailure::io(
            last_completed_phase,
            Some(CleanupProcessCreationProducerPhaseV1::StartObserved),
            CleanupProcessCreationOperationV1::StartObservation,
            CleanupProcessCreationPathRoleV1::StartSignal,
            &start,
            error,
        )
    })?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(CleanupProducerFailure::io(
            last_completed_phase,
            Some(CleanupProcessCreationProducerPhaseV1::StartObserved),
            CleanupProcessCreationOperationV1::StartObservation,
            CleanupProcessCreationPathRoleV1::StartSignal,
            &start,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "start signal is not a regular non-reparse file",
            ),
        ));
    }
    Ok(true)
}

#[derive(Clone, Debug)]
struct CleanupProducerFailure {
    receipt: CleanupProcessCreationProducerFailureV1,
}

impl CleanupProducerFailure {
    fn protocol(
        last_completed_phase: Option<CleanupProcessCreationProducerPhaseV1>,
        attempted_phase: Option<CleanupProcessCreationProducerPhaseV1>,
        operation: CleanupProcessCreationOperationV1,
        detail: &str,
    ) -> Self {
        Self {
            receipt: CleanupProcessCreationProducerFailureV1 {
                code: "MCSEALED-WINDOWS-CLEANUP-PRODUCER".to_owned(),
                last_completed_phase,
                attempted_phase,
                operation,
                path_role: None,
                io_error_kind: None,
                os_code: None,
                detail: bounded_cleanup_producer_detail(detail.to_owned()),
                secondary_publication_failure: None,
            },
        }
    }

    fn io(
        last_completed_phase: Option<CleanupProcessCreationProducerPhaseV1>,
        attempted_phase: Option<CleanupProcessCreationProducerPhaseV1>,
        operation: CleanupProcessCreationOperationV1,
        path_role: CleanupProcessCreationPathRoleV1,
        path: &std::path::Path,
        error: std::io::Error,
    ) -> Self {
        Self {
            receipt: CleanupProcessCreationProducerFailureV1 {
                code: "MCSEALED-WINDOWS-CLEANUP-PRODUCER-IO".to_owned(),
                last_completed_phase,
                attempted_phase,
                operation,
                path_role: Some(path_role),
                io_error_kind: Some(format!("{:?}", error.kind())),
                os_code: error.raw_os_error(),
                detail: bounded_cleanup_producer_detail(format!(
                    "path={} detail={error}",
                    path.display()
                )),
                secondary_publication_failure: None,
            },
        }
    }

    fn publication(
        last_completed_phase: Option<CleanupProcessCreationProducerPhaseV1>,
        attempted_phase: Option<CleanupProcessCreationProducerPhaseV1>,
        operation: CleanupProcessCreationOperationV1,
        path_role: CleanupProcessCreationPathRoleV1,
        path: &std::path::Path,
        error: super::record::CreateOncePublicationFailure,
    ) -> Self {
        let io_error_kind = format!("{:?}", error.kind());
        let os_code = error.raw_os_error();
        Self {
            receipt: CleanupProcessCreationProducerFailureV1 {
                code: "MCSEALED-WINDOWS-CLEANUP-PRODUCER-IO".to_owned(),
                last_completed_phase,
                attempted_phase,
                operation,
                path_role: Some(path_role),
                io_error_kind: Some(io_error_kind),
                os_code,
                detail: bounded_cleanup_producer_detail(format!(
                    "path={} detail={error}",
                    path.display()
                )),
                secondary_publication_failure: None,
            },
        }
    }
}

fn bounded_cleanup_producer_detail(mut detail: String) -> String {
    let maximum_bytes = memcordon_core::WINDOWS_MAX_FRAME_BYTES / 1024;
    while detail.len() > maximum_bytes {
        detail.pop();
    }
    detail
}

fn cleanup_process_creation_attempt_binding(marker: &std::path::Path) -> Result<String, String> {
    marker
        .parent()
        .and_then(std::path::Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
        .filter(|value| value.starts_with("attempt-"))
        .map(str::to_owned)
        .ok_or_else(|| "cleanup-creation marker has no bound UTF-8 attempt directory".to_owned())
}

fn publish_cleanup_process_creation_state(
    marker: &std::path::Path,
    attempt_binding: &str,
    producer_identity: &memcordon_core::WindowsProcessIdentityV1,
    completed_phases: &[CleanupProcessCreationProducerPhaseV1],
    phase: CleanupProcessCreationProducerPhaseV1,
    outcome: Option<&CleanupProcessCreationOutcomeV1>,
) -> Result<(), CleanupProducerFailure> {
    let state = cleanup_process_creation_phase_path(marker, phase);
    let staged = staged_receipt_path(&state);
    let mut published_phases = completed_phases.to_vec();
    published_phases.push(phase);
    let receipt = CleanupProcessCreationStateV1 {
        schema_version: CLEANUP_PROCESS_CREATION_STATE_SCHEMA_VERSION,
        attempt_binding: attempt_binding.to_owned(),
        producer_pid: producer_identity.process_id,
        producer_identity: producer_identity.clone(),
        sequence: u32::try_from(published_phases.len()).unwrap_or(u32::MAX),
        completed_phases: published_phases,
        phase,
        outcome: outcome.cloned(),
    };
    let mut bytes = serde_json::to_vec_pretty(&receipt).map_err(|error| {
        CleanupProducerFailure::protocol(
            completed_phases.last().copied(),
            Some(phase),
            CleanupProcessCreationOperationV1::StateSerialize,
            &error.to_string(),
        )
    })?;
    bytes.push(b'\n');
    let mut file = super::record::CreateOnceStagingFile::create(&staged).map_err(|error| {
        CleanupProducerFailure::io(
            completed_phases.last().copied(),
            Some(phase),
            CleanupProcessCreationOperationV1::StateStageOpen,
            CleanupProcessCreationPathRoleV1::PhaseStaging,
            &staged,
            error,
        )
    })?;
    std::io::Write::write_all(file.file_mut(), &bytes).map_err(|error| {
        CleanupProducerFailure::io(
            completed_phases.last().copied(),
            Some(phase),
            CleanupProcessCreationOperationV1::StateStageWrite,
            CleanupProcessCreationPathRoleV1::PhaseStaging,
            &staged,
            error,
        )
    })?;
    file.sync_all().map_err(|error| {
        CleanupProducerFailure::io(
            completed_phases.last().copied(),
            Some(phase),
            CleanupProcessCreationOperationV1::StateStageSync,
            CleanupProcessCreationPathRoleV1::PhaseStaging,
            &staged,
            error,
        )
    })?;
    super::record::publish_create_once_atomically(file, &state).map_err(|error| {
        CleanupProducerFailure::publication(
            completed_phases.last().copied(),
            Some(phase),
            CleanupProcessCreationOperationV1::StatePublishRename,
            CleanupProcessCreationPathRoleV1::PhaseReceipt,
            &state,
            error,
        )
    })
}

pub(super) fn cleanup_process_creation_phase_path(
    marker: &std::path::Path,
    phase: CleanupProcessCreationProducerPhaseV1,
) -> std::path::PathBuf {
    marker.with_extension(phase.receipt_extension())
}

pub(super) fn staged_receipt_path(destination: &std::path::Path) -> std::path::PathBuf {
    let mut path = destination.as_os_str().to_os_string();
    path.push(".new");
    std::path::PathBuf::from(path)
}

pub(super) fn cleanup_process_creation_owned_paths(
    marker: &std::path::Path,
) -> Vec<std::path::PathBuf> {
    let mut paths = [
        "start",
        "result",
        "result.new",
        "failure",
        "failure.new",
        "stderr",
    ]
    .into_iter()
    .map(|extension| marker.with_extension(extension))
    .collect::<Vec<_>>();
    for phase in CLEANUP_PROCESS_CREATION_PRODUCER_PHASES {
        let receipt = cleanup_process_creation_phase_path(marker, phase);
        paths.push(staged_receipt_path(&receipt));
        paths.push(receipt);
    }
    paths
}

pub(super) fn cleanup_producer_fallback_diagnostic(path: &std::path::Path) -> String {
    use std::io::Read;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => file,
        Err(error) => {
            return format!(
                "unavailable(kind={:?} os_code={:?} detail={error})",
                error.kind(),
                error.raw_os_error()
            );
        }
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            return format!(
                "metadata-error(kind={:?} os_code={:?} detail={error})",
                error.kind(),
                error.raw_os_error()
            );
        }
    };
    let maximum = memcordon_core::WINDOWS_MAX_FRAME_BYTES / 1024;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.is_file()
        || metadata.len() > u64::try_from(maximum).unwrap_or(u64::MAX)
    {
        return "invalid-node".to_owned();
    }
    let mut bytes = Vec::new();
    if let Err(error) = file
        .by_ref()
        .take(u64::try_from(maximum).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
    {
        return format!(
            "read-error(kind={:?} os_code={:?} detail={error})",
            error.kind(),
            error.raw_os_error()
        );
    }
    String::from_utf8(bytes).unwrap_or_else(|_| "invalid-utf8".to_owned())
}

#[derive(Debug)]
pub(crate) struct CleanupPublicationFailureForTest {
    pub(crate) attempted_phase: Option<String>,
    pub(crate) operation: String,
    pub(crate) path_role: Option<String>,
    pub(crate) os_code: Option<i32>,
    pub(crate) detail: String,
    pub(crate) receipt: std::path::PathBuf,
    pub(crate) staged: std::path::PathBuf,
}

pub(crate) fn publish_cleanup_process_creation_state_for_test(
    marker: &std::path::Path,
    attempt_binding: &str,
    producer_identity: &memcordon_core::WindowsProcessIdentityV1,
) -> Result<(std::path::PathBuf, std::path::PathBuf), CleanupPublicationFailureForTest> {
    let phase = CleanupProcessCreationProducerPhaseV1::Ready;
    let receipt = cleanup_process_creation_phase_path(marker, phase);
    let staged = staged_receipt_path(&receipt);
    publish_cleanup_process_creation_state(
        marker,
        attempt_binding,
        producer_identity,
        &[],
        phase,
        None,
    )
    .map_err(|failure| CleanupPublicationFailureForTest {
        attempted_phase: failure
            .receipt
            .attempted_phase
            .map(|phase| format!("{phase:?}")),
        operation: format!("{:?}", failure.receipt.operation),
        path_role: failure
            .receipt
            .path_role
            .map(|path_role| format!("{path_role:?}")),
        os_code: failure.receipt.os_code,
        detail: failure.receipt.detail,
        receipt: receipt.clone(),
        staged: staged.clone(),
    })?;
    Ok((receipt, staged))
}

fn publish_cleanup_process_creation_success_terminal(
    marker: &std::path::Path,
    attempt_binding: &str,
    producer_identity: &memcordon_core::WindowsProcessIdentityV1,
    completed_phases: &mut Vec<CleanupProcessCreationProducerPhaseV1>,
    outcome: CleanupProcessCreationOutcomeV1,
) -> Result<(), CleanupProducerFailure> {
    let mut terminal_phases = completed_phases.clone();
    terminal_phases.extend([
        CleanupProcessCreationProducerPhaseV1::ResultStaged,
        CleanupProcessCreationProducerPhaseV1::ResultSynced,
        CleanupProcessCreationProducerPhaseV1::ResultPublished,
    ]);
    let terminal = CleanupProcessCreationTerminalV1::Success(CleanupProcessCreationResultV1 {
        schema_version: CLEANUP_PROCESS_CREATION_RESULT_SCHEMA_VERSION,
        attempt_binding: attempt_binding.to_owned(),
        producer_pid: producer_identity.process_id,
        producer_identity: producer_identity.clone(),
        completed_phases: terminal_phases,
        outcome: outcome.clone(),
    });
    let destination = marker.with_extension("result");
    let staged = staged_receipt_path(&destination);
    let mut bytes = serde_json::to_vec_pretty(&terminal).map_err(|error| {
        CleanupProducerFailure::protocol(
            completed_phases.last().copied(),
            Some(CleanupProcessCreationProducerPhaseV1::ResultStaged),
            CleanupProcessCreationOperationV1::TerminalSerialize,
            &error.to_string(),
        )
    })?;
    bytes.push(b'\n');
    let mut file = super::record::CreateOnceStagingFile::create(&staged).map_err(|error| {
        CleanupProducerFailure::io(
            completed_phases.last().copied(),
            Some(CleanupProcessCreationProducerPhaseV1::ResultStaged),
            CleanupProcessCreationOperationV1::TerminalStageOpen,
            CleanupProcessCreationPathRoleV1::SuccessStaging,
            &staged,
            error,
        )
    })?;
    std::io::Write::write_all(file.file_mut(), &bytes).map_err(|error| {
        CleanupProducerFailure::io(
            completed_phases.last().copied(),
            Some(CleanupProcessCreationProducerPhaseV1::ResultStaged),
            CleanupProcessCreationOperationV1::TerminalStageWrite,
            CleanupProcessCreationPathRoleV1::SuccessStaging,
            &staged,
            error,
        )
    })?;
    publish_cleanup_process_creation_state(
        marker,
        attempt_binding,
        producer_identity,
        completed_phases,
        CleanupProcessCreationProducerPhaseV1::ResultStaged,
        Some(&outcome),
    )?;
    completed_phases.push(CleanupProcessCreationProducerPhaseV1::ResultStaged);
    file.sync_all().map_err(|error| {
        CleanupProducerFailure::io(
            completed_phases.last().copied(),
            Some(CleanupProcessCreationProducerPhaseV1::ResultSynced),
            CleanupProcessCreationOperationV1::TerminalStageSync,
            CleanupProcessCreationPathRoleV1::SuccessStaging,
            &staged,
            error,
        )
    })?;
    publish_cleanup_process_creation_state(
        marker,
        attempt_binding,
        producer_identity,
        completed_phases,
        CleanupProcessCreationProducerPhaseV1::ResultSynced,
        Some(&outcome),
    )?;
    completed_phases.push(CleanupProcessCreationProducerPhaseV1::ResultSynced);
    super::record::publish_create_once_atomically(file, &destination).map_err(|error| {
        CleanupProducerFailure::publication(
            completed_phases.last().copied(),
            Some(CleanupProcessCreationProducerPhaseV1::ResultPublished),
            CleanupProcessCreationOperationV1::TerminalPublishRename,
            CleanupProcessCreationPathRoleV1::SuccessReceipt,
            &destination,
            error,
        )
    })?;
    publish_cleanup_process_creation_state(
        marker,
        attempt_binding,
        producer_identity,
        completed_phases,
        CleanupProcessCreationProducerPhaseV1::ResultPublished,
        Some(&outcome),
    )?;
    completed_phases.push(CleanupProcessCreationProducerPhaseV1::ResultPublished);
    Ok(())
}

fn publish_cleanup_process_creation_terminal(
    marker: &std::path::Path,
    terminal: &CleanupProcessCreationTerminalV1,
    last_completed_phase: Option<CleanupProcessCreationProducerPhaseV1>,
) -> Result<(), CleanupProducerFailure> {
    let (destination, staging_role, receipt_role) = match terminal {
        CleanupProcessCreationTerminalV1::Success(_) => (
            marker.with_extension("result"),
            CleanupProcessCreationPathRoleV1::SuccessStaging,
            CleanupProcessCreationPathRoleV1::SuccessReceipt,
        ),
        CleanupProcessCreationTerminalV1::Failed { .. } => (
            marker.with_extension("failure"),
            CleanupProcessCreationPathRoleV1::FailureStaging,
            CleanupProcessCreationPathRoleV1::FailureReceipt,
        ),
    };
    let staged = staged_receipt_path(&destination);
    let mut bytes = serde_json::to_vec_pretty(terminal).map_err(|error| {
        CleanupProducerFailure::protocol(
            last_completed_phase,
            None,
            CleanupProcessCreationOperationV1::TerminalSerialize,
            &error.to_string(),
        )
    })?;
    bytes.push(b'\n');
    let mut file = super::record::CreateOnceStagingFile::create(&staged).map_err(|error| {
        CleanupProducerFailure::io(
            last_completed_phase,
            None,
            CleanupProcessCreationOperationV1::TerminalStageOpen,
            staging_role,
            &staged,
            error,
        )
    })?;
    std::io::Write::write_all(file.file_mut(), &bytes).map_err(|error| {
        CleanupProducerFailure::io(
            last_completed_phase,
            None,
            CleanupProcessCreationOperationV1::TerminalStageWrite,
            staging_role,
            &staged,
            error,
        )
    })?;
    file.sync_all().map_err(|error| {
        CleanupProducerFailure::io(
            last_completed_phase,
            None,
            CleanupProcessCreationOperationV1::TerminalStageSync,
            staging_role,
            &staged,
            error,
        )
    })?;
    super::record::publish_create_once_atomically(file, &destination).map_err(|error| {
        CleanupProducerFailure::publication(
            last_completed_phase,
            None,
            CleanupProcessCreationOperationV1::TerminalPublishRename,
            receipt_role,
            &destination,
            error,
        )
    })
}

pub fn orphan_descendant_canary() -> Result<(), String> {
    std::process::Command::new(crate::windows::package::installed_binary())
        .arg("windows-certification-hold")
        .spawn()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

pub(crate) const FRONTEND_CANARY_HANDLE_ROLES: [&str;
    memcordon_core::WINDOWS_CERTIFICATION_FRONTEND_CANARY_COUNT] = [
    "installed-binary-file-canary",
    "event-canary",
    "anonymous-pipe-canary",
    "frontend-process-canary",
    "section-canary",
    "registry-key-canary",
];

pub(crate) struct PreparedFrontendCanaries {
    installed_image: super::pipe::OwnedHandle,
    event: super::pipe::OwnedHandle,
    pipe_read: super::pipe::OwnedHandle,
    pipe_write: super::pipe::OwnedHandle,
    frontend_process: super::pipe::OwnedHandle,
    section: super::pipe::OwnedHandle,
    registry: OwnedRegistryKey,
}

impl PreparedFrontendCanaries {
    pub(crate) fn raw_values(
        &self,
    ) -> [windows_sys::Win32::Foundation::HANDLE;
        memcordon_core::WINDOWS_CERTIFICATION_FRONTEND_CANARY_COUNT] {
        [
            self.installed_image.raw(),
            self.event.raw(),
            self.pipe_read.raw(),
            self.frontend_process.raw(),
            self.section.raw(),
            self.registry.raw() as windows_sys::Win32::Foundation::HANDLE,
        ]
    }

    fn validate(&self) -> Result<(), String> {
        use windows_sys::Win32::Foundation::{
            GetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
        };

        let advertised = self.raw_values();
        for (index, handle) in advertised.iter().copied().enumerate() {
            let role = FRONTEND_CANARY_HANDLE_ROLES[index];
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(qualification_frontend_handle_validation_failure(
                    "inventory",
                    role,
                    None,
                    "advertised handle is null or invalid",
                ));
            }
            if advertised[..index].contains(&handle) {
                return Err(qualification_frontend_handle_validation_failure(
                    "inventory",
                    role,
                    None,
                    "advertised handle duplicates an earlier role",
                ));
            }
            validate_inheritable_frontend_handle(handle, role)?;
        }

        let pipe_write = self.pipe_write.raw();
        if pipe_write.is_null()
            || pipe_write == INVALID_HANDLE_VALUE
            || advertised.contains(&pipe_write)
        {
            return Err(qualification_frontend_handle_validation_failure(
                "inventory",
                "pipe-write-retained",
                None,
                "retained pipe writer is invalid or advertised",
            ));
        }
        let mut flags = 0_u32;
        // SAFETY: pipe_write is owned by this bundle and flags is writable.
        if unsafe { GetHandleInformation(pipe_write, &raw mut flags) } == 0 {
            let error = std::io::Error::last_os_error();
            return Err(qualification_frontend_handle_validation_failure(
                "GetHandleInformation",
                "pipe-write-retained",
                Some(&error),
                "retained pipe writer is not live",
            ));
        }
        if flags & HANDLE_FLAG_INHERIT == 0 {
            return Err(qualification_frontend_handle_validation_failure(
                "GetHandleInformation",
                "pipe-write-retained",
                None,
                "retained pipe writer is not inheritable",
            ));
        }
        Ok(())
    }
}

struct OwnedRegistryKey(windows_sys::Win32::System::Registry::HKEY);

impl OwnedRegistryKey {
    fn raw(&self) -> windows_sys::Win32::System::Registry::HKEY {
        self.0
    }
}

impl Drop for OwnedRegistryKey {
    fn drop(&mut self) {
        // SAFETY: this wrapper exclusively owns the successfully opened HKEY.
        unsafe { windows_sys::Win32::System::Registry::RegCloseKey(self.0) };
    }
}

fn qualification_frontend_handle_validation_failure(
    api: &str,
    role: &str,
    error: Option<&std::io::Error>,
    detail: &str,
) -> String {
    let native_code = error
        .and_then(std::io::Error::raw_os_error)
        .map_or_else(|| "none".to_owned(), |code| code.to_string());
    let native_detail = error.map_or_else(String::new, |error| format!(" native_detail={error}"));
    format!(
        "MCSEALED-WINDOWS-QUALIFICATION: stage=qualification-frontend-handle-prepare api={api} role={role} path=none native_code={native_code} detail={detail}{native_detail}"
    )
}

#[cfg(test)]
pub(crate) fn qualification_frontend_handle_validation_failure_for_test(
    api: &str,
    role: &str,
    native_code: Option<i32>,
    detail: &str,
) -> String {
    let error = native_code.map(std::io::Error::from_raw_os_error);
    qualification_frontend_handle_validation_failure(api, role, error.as_ref(), detail)
}

fn validate_inheritable_frontend_handle(
    handle: windows_sys::Win32::Foundation::HANDLE,
    role: &str,
) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};

    let mut flags = 0_u32;
    // SAFETY: handle is retained by the prepared bundle and flags is writable.
    if unsafe { GetHandleInformation(handle, &raw mut flags) } == 0 {
        let error = std::io::Error::last_os_error();
        return Err(qualification_frontend_handle_validation_failure(
            "GetHandleInformation",
            role,
            Some(&error),
            "advertised handle is not live",
        ));
    }
    if flags & HANDLE_FLAG_INHERIT == 0 {
        return Err(qualification_frontend_handle_validation_failure(
            "GetHandleInformation",
            role,
            None,
            "advertised handle is not inheritable",
        ));
    }
    Ok(())
}

fn qualification_native_failure(
    stage: &str,
    api: &str,
    role: &str,
    path: Option<&std::path::Path>,
    error: &std::io::Error,
) -> String {
    let native_code = error
        .raw_os_error()
        .map_or_else(|| "unavailable".to_owned(), |code| code.to_string());
    let path = path.map_or_else(|| "none".to_owned(), |path| path.display().to_string());
    format!(
        "MCSEALED-WINDOWS-QUALIFICATION: stage={stage} api={api} role={role} path={path} native_code={native_code} detail={error}"
    )
}

fn qualification_owned_handle(
    handle: windows_sys::Win32::Foundation::HANDLE,
    api: &str,
    role: &str,
    path: Option<&std::path::Path>,
) -> Result<super::pipe::OwnedHandle, String> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;

    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        Err(qualification_native_failure(
            "qualification-frontend-handle-create",
            api,
            role,
            path,
            &error,
        ))
    } else {
        super::pipe::OwnedHandle::new(handle)
    }
}

#[cfg(test)]
pub(crate) fn qualification_native_failure_for_test(
    stage: &str,
    api: &str,
    role: &str,
    path: Option<&std::path::Path>,
    native_code: i32,
) -> String {
    qualification_native_failure(
        stage,
        api,
        role,
        path,
        &std::io::Error::from_raw_os_error(native_code),
    )
}

fn create_prepared_frontend_canaries(
    installed_binary: &std::path::Path,
) -> Result<PreparedFrontendCanaries, String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, GENERIC_READ, INVALID_HANDLE_VALUE, SetHandleInformation,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, KEY_READ, RegOpenKeyExW};
    use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess};

    let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let file_path = installed_binary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: path is NUL-terminated and attributes requests inheritance.
    let file = qualification_owned_handle(
        unsafe {
            CreateFileW(
                file_path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &raw const attributes,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        },
        "CreateFileW",
        "installed-image",
        Some(installed_binary),
    )?;

    // SAFETY: attributes remains live and requests an unnamed private event.
    let event = qualification_owned_handle(
        unsafe { CreateEventW(&raw const attributes, 1, 0, std::ptr::null()) },
        "CreateEventW",
        "event",
        None,
    )?;

    let mut pipe_read = std::ptr::null_mut();
    let mut pipe_write = std::ptr::null_mut();
    // SAFETY: both outputs and the inheritable attributes remain live.
    if unsafe {
        CreatePipe(
            &raw mut pipe_read,
            &raw mut pipe_write,
            &raw const attributes,
            0,
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        return Err(qualification_native_failure(
            "qualification-frontend-handle-create",
            "CreatePipe",
            "pipe-pair",
            None,
            &error,
        ));
    }
    let pipe_read = qualification_owned_handle(pipe_read, "CreatePipe", "pipe-read", None)?;
    let pipe_write = qualification_owned_handle(pipe_write, "CreatePipe", "pipe-write", None)?;

    let mut process = std::ptr::null_mut();
    // SAFETY: both pseudo handles are live; output receives an inheritable real
    // handle to the current frontend process.
    if unsafe {
        windows_sys::Win32::Foundation::DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentProcess(),
            GetCurrentProcess(),
            &raw mut process,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        return Err(qualification_native_failure(
            "qualification-frontend-handle-create",
            "DuplicateHandle",
            "process-duplicate",
            None,
            &error,
        ));
    }
    let process =
        qualification_owned_handle(process, "DuplicateHandle", "process-duplicate", None)?;

    // SAFETY: INVALID_HANDLE_VALUE requests a pagefile-backed unnamed section.
    let section = qualification_owned_handle(
        unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                &raw const attributes,
                PAGE_READWRITE,
                0,
                4_096,
                std::ptr::null(),
            )
        },
        "CreateFileMappingW",
        "section",
        None,
    )?;

    let software = super::pipe::wide_null("Software");
    let mut registry = std::ptr::null_mut();
    // SAFETY: subkey is NUL-terminated and output receives one owned HKEY.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            software.as_ptr(),
            0,
            KEY_READ,
            &raw mut registry,
        )
    };
    if status != 0 {
        let error = std::io::Error::from_raw_os_error(status as i32);
        return Err(qualification_native_failure(
            "qualification-frontend-handle-create",
            "RegOpenKeyExW",
            "registry",
            None,
            &error,
        ));
    }
    let registry = OwnedRegistryKey(registry);
    // SAFETY: registry is a live kernel handle and only its inherit flag changes.
    if unsafe {
        SetHandleInformation(
            registry.raw() as windows_sys::Win32::Foundation::HANDLE,
            windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT,
            windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT,
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        return Err(qualification_native_failure(
            "qualification-frontend-handle-create",
            "SetHandleInformation",
            "registry",
            None,
            &error,
        ));
    }
    let prepared = PreparedFrontendCanaries {
        installed_image: file,
        event,
        pipe_read,
        pipe_write,
        frontend_process: process,
        section,
        registry,
    };
    prepared.validate()?;
    Ok(prepared)
}

fn prepare_frontend_canaries(token_scenario: &str) -> Result<PreparedFrontendCanaries, String> {
    create_prepared_frontend_canaries(&crate::windows::package::installed_binary()).map_err(
        |detail| {
            format!("MCSEALED-WINDOWS-QUALIFICATION: scenario={token_scenario} detail={detail}")
        },
    )
}

#[cfg(test)]
pub(crate) fn prepare_frontend_canaries_for_test(
    installed_binary: &std::path::Path,
    token_scenario: &str,
) -> Result<PreparedFrontendCanaries, String> {
    create_prepared_frontend_canaries(installed_binary).map_err(|detail| {
        format!("MCSEALED-WINDOWS-QUALIFICATION: scenario={token_scenario} detail={detail}")
    })
}

#[cfg(test)]
impl PreparedFrontendCanaries {
    pub(crate) fn validate_for_test(&self) -> Result<(), String> {
        self.validate()
    }

    pub(crate) fn retained_pipe_writer_for_test(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.pipe_write.raw()
    }
}

fn recursive_provider_canary() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    let pipe = super::pipe::connect(WINDOWS_CONTROL_PIPE)?;
    let executable = crate::windows::package::installed_binary();
    let request = WindowsLaunchRequestV1 {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        expected_provider_binding: super::package::installed_public_provider_binding()?,
        workload_contract: None,
        restart_attempt: 0,
        nonce: format!("recursive-{}", std::process::id()),
        command: NativeWindowsCommandV1 {
            program: executable.as_os_str().encode_wide().collect(),
            arguments: vec!["--version".encode_utf16().collect()],
        },
        environment: Vec::new(),
        current_directory: crate::windows::package::install_root()
            .as_os_str()
            .encode_wide()
            .collect(),
        policy: WindowsLaunchPolicyV1 {
            memory_limit_bytes: None,
            absolute_deadline_millis: None,
            lifetime: WindowsLifetimeV1::Command,
            poll_interval_millis: 10,
            signal_grace_millis: 1_000,
            command_exit_grace_millis: 0,
            limit_grace_millis: 0,
        },
    };
    let nonce = request.nonce.clone();
    let request_sha256 =
        super::record::digest(&serde_json::to_vec(&request).map_err(|error| error.to_string())?);
    super::pipe::write_frame(pipe.raw(), &WindowsProviderRequestV3::Launch(request))?;
    match super::pipe::read_response_frame::<WindowsProviderResponseV3>(pipe.raw())? {
        WindowsProviderResponseV3::Reject {
            schema_version,
            attempt_id,
            nonce: returned_nonce,
            request_sha256: returned_digest,
            rejection,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
            && !attempt_id.is_empty()
            && returned_nonce == nonce
            && returned_digest == request_sha256
            && rejection.code == "MCSEALED-WINDOWS-RECURSIVE-PROVIDER"
            && !rejection.target_created
            && !rejection.target_released =>
        {
            Ok(())
        }
        _ => Err("recursive provider qualification request was not denied".to_owned()),
    }
}

fn nested_alternate_token_target_canary(marker: &std::path::Path) -> Result<(), TargetCanaryError> {
    use std::os::windows::ffi::OsStrExt;
    use std::time::{Duration, Instant};

    // SAFETY: the pseudo-handle denotes this live sealed target. This check is
    // performed before the inner Job exists, so the observed membership can
    // only be the outer MemCordon Job.
    if !target_phase(
        TargetResultPhaseV1::OuterJobMembership,
        super::job::Job::process_is_in_any_job(unsafe {
            windows_sys::Win32::System::Threading::GetCurrentProcess()
        }),
    )? {
        return Err(TargetCanaryError::at(
            TargetResultPhaseV1::OuterJobMembership,
            "nested fixture target is not in the outer sealed Job",
        ));
    }
    let parent_envelope = target_phase(
        TargetResultPhaseV1::RestrictedPrimaryConstruction,
        super::token::current_thread_envelope(),
    )?;
    let nested_tokens = target_phase(
        TargetResultPhaseV1::RestrictedPrimaryConstruction,
        super::token::nested_target_tokens(),
    )?;
    let token = nested_tokens.permanent;
    let expected_envelope = target_phase(
        TargetResultPhaseV1::RestrictedPrimaryConstruction,
        super::token::envelope(token.raw()),
    )?;
    let initial_thread_token = nested_tokens.initial;
    if parent_envelope.session_id != expected_envelope.session_id {
        return Err(TargetCanaryError::at(
            TargetResultPhaseV1::RestrictedPrimaryConstruction,
            format!(
                "nested alternate-token parent/alternate session mismatch: parent={} alternate={}",
                parent_envelope.session_id, expected_envelope.session_id
            ),
        ));
    }
    let job = target_phase(
        TargetResultPhaseV1::InnerJobCreation,
        super::job::Job::create_nested_canary(None),
    )?;
    let mut streams = target_phase(
        TargetResultPhaseV1::StreamSetup,
        super::process::StreamSet::create(
            unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() },
            None,
        ),
    )?;
    let expected_stream_handles = streams.certification_target_handle_values();
    let executable = crate::windows::package::installed_binary();
    let attempt_binding = marker
        .parent()
        .and_then(std::path::Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
        .filter(|value| value.starts_with("attempt-"))
        .ok_or_else(|| {
            TargetCanaryError::at(
                TargetResultPhaseV1::ArgumentBinding,
                "nested child receipt path has no bound attempt directory",
            )
        })?
        .to_owned();
    let current_directory = crate::windows::package::install_root()
        .as_os_str()
        .encode_wide()
        .collect::<Vec<_>>();
    let nested_target = super::process::SuspendedTarget::create_nested_canary(
        token.raw(),
        initial_thread_token.raw(),
        &job,
        &NativeWindowsCommandV1 {
            program: executable.as_os_str().encode_wide().collect(),
            arguments: vec![
                "windows-certification-nested-child"
                    .encode_utf16()
                    .collect(),
                marker.as_os_str().encode_wide().collect(),
                attempt_binding.encode_utf16().collect(),
                expected_stream_handles[0]
                    .to_string()
                    .encode_utf16()
                    .collect(),
                expected_stream_handles[1]
                    .to_string()
                    .encode_utf16()
                    .collect(),
                expected_stream_handles[2]
                    .to_string()
                    .encode_utf16()
                    .collect(),
                parent_envelope
                    .session_id
                    .to_string()
                    .encode_utf16()
                    .collect(),
            ],
        },
        &[],
        &current_directory,
        &streams,
    )
    .map_err(|error| {
        TargetCanaryError::at(
            if error.loader_context {
                TargetResultPhaseV1::LoaderContext
            } else {
                TargetResultPhaseV1::SuspendedChildCreation
            },
            error.detail,
        )
    })?;
    let expected_initial_thread_token_id = nested_target.initial.observed_thread.instance.token_id;
    let expected_initial_thread_envelope = nested_target
        .initial
        .observed_thread
        .behavior
        .envelope
        .clone();
    let target = nested_target.target;
    drop(initial_thread_token);
    let suspended_process_token = target_phase(
        TargetResultPhaseV1::TokenMembershipReadback,
        super::token::process_token_query_attestation(target.handle()),
    )?;
    let suspended_process_token_id = suspended_process_token.instance.token_id;
    if !target_phase(
        TargetResultPhaseV1::TokenMembershipReadback,
        job.contains(target.handle()),
    )? || suspended_process_token.behavior.envelope != expected_envelope
    {
        return Err(TargetCanaryError::at(
            TargetResultPhaseV1::TokenMembershipReadback,
            "nested alternate-token child failed preauthorization readback",
        ));
    }
    let expected_child_identity = target_phase(
        TargetResultPhaseV1::TokenMembershipReadback,
        super::process::process_identity(target.handle()),
    )?;
    let output = target_phase(
        TargetResultPhaseV1::StreamSetup,
        NestedChildOutputCollectors::start(&mut streams),
    )?;
    drop(streams);
    target_phase(TargetResultPhaseV1::Resume, target.resume(None))?;
    let completed = target_phase(
        TargetResultPhaseV1::ChildExit,
        target.wait(Duration::from_secs(30)),
    )?;
    let completion = if completed {
        NestedChildCompletion::Exited(target_phase(
            TargetResultPhaseV1::ChildExit,
            target.exit_status(),
        )?)
    } else {
        NestedChildCompletion::TimedOut
    };
    let captured = if matches!(completion, NestedChildCompletion::Exited(_)) {
        Some(output.finish())
    } else {
        None
    };
    validate_nested_child_completion(completion).map_err(|detail| {
        TargetCanaryError::at(
            TargetResultPhaseV1::ChildExit,
            append_nested_child_output(detail, captured.as_ref()),
        )
    })?;
    let receipt = read_bound_nested_child_receipt(marker, &attempt_binding).map_err(|detail| {
        TargetCanaryError::at(
            TargetResultPhaseV1::MarkerPublication,
            append_nested_child_output(detail, captured.as_ref()),
        )
    })?;
    let expected_desktop_binding = target.desktop_binding();
    if format!("{}\\{}", receipt.window_station_name, receipt.desktop_name)
        != expected_desktop_binding
    {
        return Err(TargetCanaryError::at(
            TargetResultPhaseV1::TokenMembershipReadback,
            append_nested_child_output(
                "nested alternate-token desktop binding differs from pre-resume attestation"
                    .to_owned(),
                captured.as_ref(),
            ),
        ));
    }
    if receipt.token_envelope.session_id != expected_envelope.session_id {
        return Err(TargetCanaryError::at(
            TargetResultPhaseV1::TokenMembershipReadback,
            append_nested_child_output(
                format!(
                    "nested alternate-token session mismatch: parent={} alternate={} child={}",
                    parent_envelope.session_id,
                    expected_envelope.session_id,
                    receipt.token_envelope.session_id
                ),
                captured.as_ref(),
            ),
        ));
    }
    if receipt.child_identity != expected_child_identity
        || receipt.initial_thread_token_id != expected_initial_thread_token_id
        || receipt.initial_thread_token_envelope != expected_initial_thread_envelope
        || !receipt.initial_token_behavior_attested
        || !receipt.initial_token_reverted
        || !receipt.thread_token_absent_after_revert
        || receipt.token_envelope != expected_envelope
        || receipt.process_token_id != suspended_process_token_id
        || receipt.standard_streams != expected_stream_handles
    {
        return Err(TargetCanaryError::at(
            TargetResultPhaseV1::TokenMembershipReadback,
            append_nested_child_output(
                "nested child post-start identity, token envelope, or standard streams did not match pre-resume readback".to_owned(),
                captured.as_ref(),
            ),
        ));
    }
    if !target_phase(
        TargetResultPhaseV1::InnerJobEmpty,
        job.wait_empty(Instant::now() + Duration::from_secs(30)),
    )? {
        return Err(TargetCanaryError::at(
            TargetResultPhaseV1::InnerJobEmpty,
            "nested alternate-token child Job did not become empty",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NestedChildCompletion {
    TimedOut,
    Exited(u32),
}

pub(crate) fn validate_nested_child_completion(
    completion: NestedChildCompletion,
) -> Result<(), String> {
    match completion {
        NestedChildCompletion::TimedOut => {
            Err("nested alternate-token child timed out after 30000 ms".to_owned())
        }
        NestedChildCompletion::Exited(0) => Ok(()),
        NestedChildCompletion::Exited(0xC000_0142) => Err(
            "nested alternate-token child exited with status 3221225794 (0xc0000142 STATUS_DLL_INIT_FAILED; entry not instrumented)"
                .to_owned(),
        ),
        NestedChildCompletion::Exited(status) => Err(format!(
            "nested alternate-token child exited with status {status} (0x{status:08x})"
        )),
    }
}

const NESTED_CHILD_OUTPUT_MAX_BYTES: usize = 8 * 1024;
const NESTED_CHILD_RECEIPT_MAX_BYTES: u64 = 32 * 1024;

struct BoundedNestedChildOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

struct NestedChildOutput {
    stdout: Result<BoundedNestedChildOutput, String>,
    stderr: Result<BoundedNestedChildOutput, String>,
}

struct NestedChildOutputCollectors {
    stdout: std::thread::JoinHandle<Result<BoundedNestedChildOutput, String>>,
    stderr: std::thread::JoinHandle<Result<BoundedNestedChildOutput, String>>,
}

impl NestedChildOutputCollectors {
    fn start(streams: &mut super::process::StreamSet) -> Result<Self, String> {
        let invalid = windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE as usize as u64;
        if streams.remote.len() != 3
            || streams.remote_relay_retired_event == 0
            || streams.remote_relay_retired_event == invalid
            || streams
                .remote
                .iter()
                .any(|stream| stream.remote_handle == 0 || stream.remote_handle == invalid)
        {
            return Err("nested child relay stream inventory is invalid".to_owned());
        }
        let mut roles = streams
            .remote
            .iter()
            .map(|stream| stream.role)
            .collect::<Vec<_>>();
        roles.sort_by_key(|role| match role {
            WindowsStreamRoleV1::Stdin => 0,
            WindowsStreamRoleV1::Stdout => 1,
            WindowsStreamRoleV1::Stderr => 2,
        });
        if roles
            != [
                WindowsStreamRoleV1::Stdin,
                WindowsStreamRoleV1::Stdout,
                WindowsStreamRoleV1::Stderr,
            ]
        {
            return Err("nested child relay stream roles are not exact".to_owned());
        }

        let transferred = std::mem::take(&mut streams.remote);
        let retired_event = std::mem::replace(&mut streams.remote_relay_retired_event, 0);
        streams.accept_remote_handles();
        let mut stdin = None;
        let mut stdout = None;
        let mut stderr = None;
        for stream in transferred {
            let handle = super::pipe::OwnedHandle::new(
                stream.remote_handle as usize as windows_sys::Win32::Foundation::HANDLE,
            )?;
            match stream.role {
                WindowsStreamRoleV1::Stdin => stdin = Some(handle),
                WindowsStreamRoleV1::Stdout => stdout = Some(handle),
                WindowsStreamRoleV1::Stderr => stderr = Some(handle),
            }
        }
        drop(stdin.take());
        drop(super::pipe::OwnedHandle::new(
            retired_event as usize as windows_sys::Win32::Foundation::HANDLE,
        )?);
        let stdout = stdout.ok_or_else(|| "nested child stdout relay is absent".to_owned())?;
        let stderr = stderr.ok_or_else(|| "nested child stderr relay is absent".to_owned())?;
        Ok(Self {
            stdout: std::thread::spawn(move || read_bounded_nested_child_output(stdout)),
            stderr: std::thread::spawn(move || read_bounded_nested_child_output(stderr)),
        })
    }

    fn finish(self) -> NestedChildOutput {
        let stdout = self
            .stdout
            .join()
            .unwrap_or_else(|_| Err("nested child stdout collector panicked".to_owned()));
        let stderr = self
            .stderr
            .join()
            .unwrap_or_else(|_| Err("nested child stderr collector panicked".to_owned()));
        NestedChildOutput { stdout, stderr }
    }
}

fn read_bounded_nested_child_output(
    handle: super::pipe::OwnedHandle,
) -> Result<BoundedNestedChildOutput, String> {
    use windows_sys::Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_NO_DATA};
    use windows_sys::Win32::Storage::FileSystem::ReadFile;

    let mut bytes = Vec::new();
    let mut truncated = false;
    loop {
        let mut buffer = [0_u8; 4096];
        let mut read = 0_u32;
        // SAFETY: the relay handle is the live read end of an anonymous pipe;
        // the fixed buffer and byte-count output remain writable for the call.
        if unsafe {
            ReadFile(
                handle.raw(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &raw mut read,
                std::ptr::null_mut(),
            )
        } == 0
        {
            let error = std::io::Error::last_os_error();
            let code = error
                .raw_os_error()
                .and_then(|value| u32::try_from(value).ok());
            if matches!(code, Some(ERROR_BROKEN_PIPE) | Some(ERROR_NO_DATA)) {
                break;
            }
            return Err(format!("nested child output drain failed: {error}"));
        }
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read as usize];
        let remaining = NESTED_CHILD_OUTPUT_MAX_BYTES.saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        truncated |= chunk.len() > remaining;
    }
    Ok(BoundedNestedChildOutput { bytes, truncated })
}

fn append_nested_child_output(mut detail: String, output: Option<&NestedChildOutput>) -> String {
    let Some(output) = output else {
        return detail;
    };
    for (name, captured) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        match captured {
            Ok(captured) => {
                let text = String::from_utf8_lossy(&captured.bytes);
                detail.push_str(&format!(
                    " child_{name}={text:?} child_{name}_truncated={}",
                    captured.truncated
                ));
            }
            Err(error) => detail.push_str(&format!(" child_{name}_capture_error={error:?}")),
        }
    }
    if detail.len() > TARGET_RESULT_DETAIL_MAX_BYTES {
        let mut boundary = TARGET_RESULT_DETAIL_MAX_BYTES;
        while !detail.is_char_boundary(boundary) {
            boundary -= 1;
        }
        detail.truncate(boundary);
    }
    detail
}

pub fn certification_nested_child(
    entry_thread_token_transition: &super::token::EntryThreadTokenTransition,
    receipt: &std::ffi::OsStr,
    attempt_binding: &std::ffi::OsStr,
    expected_streams: [&std::ffi::OsStr; 3],
    expected_session: &std::ffi::OsStr,
) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let initial_thread_token_envelope = entry_thread_token_transition
        .initial_token_envelope
        .clone()
        .ok_or_else(|| "nested child did not enter with its bounded initial token".to_owned())?;
    let initial_thread_token_id = entry_thread_token_transition
        .initial_token_id
        .ok_or_else(|| "nested child entry token had no object identity".to_owned())?;
    if !entry_thread_token_transition.initial_token_behavior_attested
        || !entry_thread_token_transition.initial_token_reverted
        || !entry_thread_token_transition.thread_token_absent_after_revert
    {
        return Err("nested child entry token transition was incomplete".to_owned());
    }

    let receipt = std::path::Path::new(receipt);
    let attempt_binding = attempt_binding
        .to_str()
        .filter(|value| value.starts_with("attempt-"))
        .ok_or_else(|| "nested child attempt binding is invalid".to_owned())?;
    let expected_streams = expected_streams
        .map(parse_nested_child_numeric_argument)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let expected_streams: [u64; 3] = expected_streams
        .try_into()
        .map_err(|_| "nested child expected-stream inventory is not exact".to_owned())?;
    validate_nested_child_stream_values(expected_streams)?;
    let expected_session = parse_nested_child_numeric_argument(expected_session)?;
    let expected_session = u32::try_from(expected_session)
        .map_err(|_| "nested child expected session is out of range".to_owned())?;
    let parent = receipt
        .parent()
        .ok_or_else(|| "nested child receipt has no parent".to_owned())?;
    if receipt.file_name() != Some(std::ffi::OsStr::new("nested-child.json"))
        || parent.file_name() != Some(std::ffi::OsStr::new(attempt_binding))
    {
        return Err("nested child receipt path is not exactly attempt-bound".to_owned());
    }
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
    if parent_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !parent_metadata.is_dir()
    {
        return Err("nested child receipt parent is not a regular directory".to_owned());
    }
    for path in [receipt.to_owned(), nested_child_staged_receipt(receipt)] {
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(format!(
                    "nested child receipt leaf already exists: {}",
                    path.display()
                ));
            }
            Err(error) => return Err(error.to_string()),
        }
    }

    std::thread::sleep(std::time::Duration::from_millis(500));
    let in_any_job = super::job::Job::process_is_in_any_job(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })?;
    verify_nested_child_standard_streams(expected_streams)?;
    let process_token = super::token::current_process_token_for_attestation_and_access_check()?;
    let process_token_attestation = super::token::token_attestation_snapshot(process_token.raw())?;
    let process_token_id = process_token_attestation.instance.token_id;
    let token_envelope = process_token_attestation.behavior.envelope.clone();
    let token_is_restricted = process_token_attestation.behavior.token_is_restricted;
    let restricted_sid_count = super::token::restricted_sid_count(process_token.raw())?;
    let restricting_sids = super::token::token_restricting_sids(process_token.raw())?;
    let write_restricted_code_present =
        super::token::token_has_restricting_sid(process_token.raw(), "S-1-5-33")?;
    let restricted_code_absent =
        !super::token::token_has_restricting_sid(process_token.raw(), "S-1-5-12")?;
    let write_restricted =
        super::security::write_restricted_behavior_attested(process_token.raw())?;
    let enabled_sensitive_privilege_count = process_token_attestation
        .behavior
        .enabled_sensitive_privilege_count;
    if !in_any_job
        || !token_is_restricted
        || restricted_sid_count != 1
        || restricting_sids != ["S-1-5-33"]
        || !write_restricted_code_present
        || !restricted_code_absent
        || !write_restricted
        || enabled_sensitive_privilege_count != 0
        || token_envelope.session_id != expected_session
    {
        return Err("nested child post-start token or Job observation is incomplete".to_owned());
    }
    let (window_station_name, desktop_name) = super::process::attest_current_target_desktop()?;
    let receipt_value = NestedChildReceiptV1 {
        schema_version: 4,
        attempt_binding: attempt_binding.to_owned(),
        target_mode: TargetResultModeV1::NestedAlternateToken,
        child_identity: super::process::process_identity(unsafe {
            windows_sys::Win32::System::Threading::GetCurrentProcess()
        })?,
        initial_thread_token_id,
        initial_thread_token_envelope,
        initial_token_behavior_attested: entry_thread_token_transition
            .initial_token_behavior_attested,
        initial_token_reverted: entry_thread_token_transition.initial_token_reverted,
        thread_token_absent_after_revert: entry_thread_token_transition
            .thread_token_absent_after_revert,
        token_envelope,
        process_token_id,
        restricted_sid_count,
        restricting_sids,
        write_restricted_code_present,
        restricted_code_absent,
        write_restricted,
        token_is_restricted,
        enabled_sensitive_privilege_count,
        in_any_job,
        standard_streams: expected_streams,
        standard_streams_verified: true,
        window_station_name,
        desktop_name,
        desktop_policy_verified: true,
        private_desktop_binding_verified: true,
        success: true,
        detail: "complete".to_owned(),
    };
    publish_native_fixture_result(
        receipt,
        QualificationPublicationProducerV1::NestedChild,
        &receipt_value,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn nested_child_staged_receipt(receipt: &std::path::Path) -> std::path::PathBuf {
    receipt.with_file_name("nested-child.json.new")
}

fn parse_nested_child_numeric_argument(value: &std::ffi::OsStr) -> Result<u64, String> {
    value
        .to_str()
        .ok_or_else(|| "nested child numeric argument is not UTF-8".to_owned())?
        .parse::<u64>()
        .map_err(|error| format!("nested child numeric argument is invalid: {error}"))
}

pub(crate) fn validate_nested_child_stream_values(values: [u64; 3]) -> Result<(), String> {
    let invalid = windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE as usize as u64;
    if values.iter().any(|value| *value == 0 || *value == invalid)
        || values[0] == values[1]
        || values[0] == values[2]
        || values[1] == values[2]
    {
        return Err("nested child standard-stream values are invalid or duplicated".to_owned());
    }
    Ok(())
}

fn verify_nested_child_standard_streams(expected: [u64; 3]) -> Result<(), String> {
    use windows_sys::Win32::Foundation::GetHandleInformation;
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
    use windows_sys::Win32::System::Console::GetStdHandle;
    use windows_sys::Win32::System::Console::{
        STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    validate_nested_child_stream_values(expected)?;
    for (role, selector, expected) in [
        ("stdin", STD_INPUT_HANDLE, expected[0]),
        ("stdout", STD_OUTPUT_HANDLE, expected[1]),
        ("stderr", STD_ERROR_HANDLE, expected[2]),
    ] {
        // SAFETY: selector is one of the three documented standard-handle
        // constants and the returned borrowed handle is inspected only.
        let observed = unsafe { GetStdHandle(selector) };
        if observed as usize as u64 != expected {
            return Err(format!(
                "nested child {role} handle mismatch: expected={expected} observed={}",
                observed as usize as u64
            ));
        }
        let mut flags = 0_u32;
        // SAFETY: observed must equal the validated inherited handle; the
        // flags output is writable and no handle state is changed.
        if unsafe { GetHandleInformation(observed, &raw mut flags) } == 0 {
            return Err(format!(
                "nested child {role} handle query failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: observed is a live standard handle and this query is read-only.
        if unsafe { GetFileType(observed) } != FILE_TYPE_PIPE {
            return Err(format!("nested child {role} is not an anonymous pipe"));
        }
    }
    Ok(())
}

fn read_bound_nested_child_receipt(
    path: &std::path::Path,
    expected_binding: &str,
) -> Result<NestedChildReceiptV1, String> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let parent = path
        .parent()
        .ok_or_else(|| "nested child receipt has no parent".to_owned())?;
    if path.file_name() != Some(std::ffi::OsStr::new("nested-child.json"))
        || parent.file_name() != Some(std::ffi::OsStr::new(expected_binding))
    {
        return Err("nested child receipt path is not exactly attempt-bound".to_owned());
    }
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
    if parent_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !parent_metadata.is_dir()
    {
        return Err("nested child receipt parent is not a regular directory".to_owned());
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        format!(
            "nested child receipt is absent: path={} error={error}",
            path.display()
        )
    })?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.is_file()
        || metadata.len() > NESTED_CHILD_RECEIPT_MAX_BYTES
    {
        return Err("nested child receipt is not a bounded regular file".to_owned());
    }
    let receipt: NestedChildReceiptV1 =
        serde_json::from_slice(&std::fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|error| format!("nested child receipt is malformed: {error}"))?;
    if receipt.schema_version != 4
        || receipt.attempt_binding != expected_binding
        || receipt.target_mode != TargetResultModeV1::NestedAlternateToken
        || receipt.child_identity.process_id == 0
        || receipt.initial_thread_token_id == 0
        || receipt.initial_thread_token_envelope.token_type
            != windows_sys::Win32::Security::TokenImpersonation as u32
        || receipt.initial_thread_token_envelope.impersonation_level
            != windows_sys::Win32::Security::SecurityImpersonation as u32
        || receipt.initial_thread_token_envelope.elevated
        || !receipt.initial_token_behavior_attested
        || !receipt.initial_token_reverted
        || !receipt.thread_token_absent_after_revert
        || receipt.process_token_id == 0
        || receipt.restricted_sid_count != 1
        || receipt.restricting_sids != ["S-1-5-33"]
        || !receipt.write_restricted_code_present
        || !receipt.restricted_code_absent
        || !receipt.write_restricted
        || !receipt.token_is_restricted
        || receipt.enabled_sensitive_privilege_count != 0
        || !receipt.in_any_job
        || !receipt.standard_streams_verified
        || super::process::validate_target_desktop_binding(
            &receipt.window_station_name,
            &receipt.desktop_name,
        )
        .is_err()
        || !receipt.desktop_policy_verified
        || !receipt.private_desktop_binding_verified
        || validate_nested_child_stream_values(receipt.standard_streams).is_err()
        || !receipt.success
        || receipt.detail != "complete"
    {
        return Err("nested child receipt invariants are incomplete".to_owned());
    }
    Ok(receipt)
}

fn control_request_challenge(operation: &str) -> String {
    let mut challenge = b"memcordon-windows-control-request-v1".to_vec();
    challenge.extend_from_slice(operation.as_bytes());
    challenge.extend_from_slice(&std::process::id().to_le_bytes());
    challenge.extend_from_slice(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0_u128, |duration| duration.as_nanos())
            .to_le_bytes(),
    );
    super::record::digest(&challenge)
}

pub fn recovery_status() -> Result<bool, String> {
    let pipe = super::pipe::connect(WINDOWS_CONTROL_PIPE)?;
    let challenge = control_request_challenge("recovery-status");
    super::pipe::write_frame(
        pipe.raw(),
        &WindowsProviderRequestV3::RecoveryStatus {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            challenge: challenge.clone(),
        },
    )?;
    match super::pipe::read_response_frame::<WindowsProviderResponseV3>(pipe.raw())? {
        WindowsProviderResponseV3::RecoveryStatus {
            schema_version,
            challenge: returned_challenge,
            status,
            attempts_empty,
            detail,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
            && returned_challenge == challenge =>
        {
            match (status, attempts_empty) {
                (memcordon_core::WindowsControlRequestStatusV1::Ready, Some(true)) => Ok(true),
                (memcordon_core::WindowsControlRequestStatusV1::Active, Some(false)) => Ok(false),
                (memcordon_core::WindowsControlRequestStatusV1::Failed, _) => Err(detail),
                _ => Err("control service returned contradictory recovery status".to_owned()),
            }
        }
        _ => Err("control service returned an invalid recovery status".to_owned()),
    }
}

pub fn prepare_package_cleanup(
    deadline_millis: u64,
) -> Result<(), super::record::PackageCleanupError> {
    if deadline_millis == 0 {
        return Err(super::record::PackageCleanupError::Failed(
            "package cleanup deadline must be nonzero".to_owned(),
        ));
    }
    let pipe = super::pipe::connect(WINDOWS_CONTROL_PIPE)?;
    let challenge = control_request_challenge("package-cleanup");
    super::pipe::write_frame(
        pipe.raw(),
        &WindowsProviderRequestV3::PackageCleanup {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            challenge: challenge.clone(),
            deadline_millis,
        },
    )?;
    match super::pipe::read_response_frame::<WindowsProviderResponseV3>(pipe.raw())? {
        WindowsProviderResponseV3::PackageCleanupResult {
            schema_version,
            challenge: returned_challenge,
            status,
            attempts_empty,
            terminal_outboxes,
            detail,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
            && returned_challenge == challenge =>
        {
            let outcome = memcordon_core::WindowsPackageCleanupOutcomeV1 {
                status,
                attempts_empty,
                terminal_outboxes,
                detail,
            };
            outcome
                .validate()
                .map_err(|error| super::record::PackageCleanupError::Failed(error.to_owned()))?;
            let detail = outcome.detail;
            match (status, attempts_empty) {
                (memcordon_core::WindowsControlRequestStatusV1::Ready, Some(true)) => Ok(()),
                (memcordon_core::WindowsControlRequestStatusV1::Active, Some(false)) => {
                    Err(super::record::PackageCleanupError::Active(format!(
                        "{detail}; authenticated_terminal_outboxes={}",
                        terminal_outboxes
                            .map_or_else(|| "unavailable".to_owned(), |count| count.to_string())
                    )))
                }
                (memcordon_core::WindowsControlRequestStatusV1::Failed, _) => {
                    Err(super::record::PackageCleanupError::Failed(detail))
                }
                _ => Err(super::record::PackageCleanupError::Failed(
                    "control service returned contradictory package cleanup state".to_owned(),
                )),
            }
        }
        _ => Err(super::record::PackageCleanupError::Failed(
            "control service returned an invalid package cleanup response".to_owned(),
        )),
    }
}
