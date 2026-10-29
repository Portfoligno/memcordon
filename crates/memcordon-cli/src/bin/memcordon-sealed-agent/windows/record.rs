use std::ffi::c_void;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub use memcordon_core::{WindowsAttemptStateV1, WindowsAttemptTerminalDispositionV1};
use memcordon_core::{
    WindowsProcessIdentityV1, WindowsTerminalizationCheckpointV1,
    WindowsTerminalizationErrorStageV1, WindowsTerminalizationErrorV1,
    WindowsTerminalizationOwnerV1, WindowsTerminalizationStatusV1, WindowsWorkerThreadIdentityV1,
    windows_attempt_transition_allowed,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, FILETIME, HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_RENAME_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileIdInfo,
    FileRenameInfo, FileStandardInfo, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, SetFileInformationByHandle,
    VOLUME_NAME_NT,
};
use windows_sys::Win32::System::Threading::{
    GetThreadTimes, OpenProcess, OpenThread, PROCESS_QUERY_LIMITED_INFORMATION,
    THREAD_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};

use super::package;
use super::pipe::OwnedHandle;

const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const DELETE_ACCESS: u32 = 0x0001_0000;
const GENERIC_WRITE_ACCESS: u32 = 0x4000_0000;
const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
const MAX_TERMINALIZATION_CODE_BYTES: usize = 128;
const MAX_TERMINALIZATION_DETAIL_BYTES: usize = 2 * 1024;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCleanupStateV1 {
    pub termination_requested: bool,
    pub active_processes_zero: bool,
    pub guardian_reaped: bool,
    pub final_handles_closed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAttemptRecordV1 {
    pub schema_version: u32,
    #[serde(deserialize_with = "memcordon_core::deserialize_bounded_record_text::<_, 256>")]
    pub attempt_id: String,
    #[serde(deserialize_with = "memcordon_core::deserialize_bounded_record_text::<_, 256>")]
    pub provider_generation: String,
    #[serde(deserialize_with = "memcordon_core::deserialize_bounded_record_text::<_, 256>")]
    pub boot_identity: String,
    pub launch_incarnation: String,
    pub nonce: String,
    #[serde(deserialize_with = "memcordon_core::deserialize_bounded_record_text::<_, 256>")]
    pub request_sha256: String,
    pub caller_process_identity: WindowsProcessIdentityV1,
    #[serde(deserialize_with = "memcordon_core::deserialize_bounded_record_text::<_, 256>")]
    pub caller_token_sha256: String,
    #[serde(deserialize_with = "memcordon_core::deserialize_bounded_record_text::<_, 256>")]
    pub job_identity_sha256: String,
    pub guardian_identity: Option<WindowsProcessIdentityV1>,
    pub worker_identity: Option<WindowsProcessIdentityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_thread_identity: Option<WindowsWorkerThreadIdentityV1>,
    pub target_identity: Option<WindowsProcessIdentityV1>,
    pub state: WindowsAttemptStateV1,
    pub lifecycle: memcordon_core::WindowsTerminalLifecycleV1,
    pub authorization_unix_millis: Option<u64>,
    pub resume_attempted: bool,
    pub target_released: bool,
    pub cleanup_state: WindowsCleanupStateV1,
    pub owner_manifest: Option<memcordon_core::WindowsCapabilityOwnerManifestV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_closure_contract: Option<memcordon_core::WindowsJobClosureContractV2>,
    pub recovery_authorization: Option<memcordon_core::WindowsRecoveryAuthorizationV1>,
    pub terminal_publication_reserved: bool,
    pub terminal_seed: Option<memcordon_core::WindowsTerminalSeedV2>,
    pub retirement_proof: Option<memcordon_core::WindowsRetirementProofV3>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_shared_outbox"
    )]
    pub terminal_response_json: Option<std::sync::Arc<str>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_disposition: Option<WindowsAttemptTerminalDispositionV1>,
    pub terminalization: WindowsTerminalizationStatusV1,
    pub causal_diagnostics: memcordon_core::WindowsCausalDiagnosticsV1,
    pub diagnostic_retention: memcordon_core::DiagnosticRetentionV1,
    pub record_revision: u64,
    #[serde(deserialize_with = "memcordon_core::deserialize_bounded_record_text::<_, 256>")]
    pub provider_incarnation: String,
    #[serde(deserialize_with = "memcordon_core::deserialize_bounded_record_text::<_, 256>")]
    pub integrity_sha256: String,
}

pub fn current_worker_thread_identity() -> Result<WindowsWorkerThreadIdentityV1, String> {
    // SAFETY: the pseudo handle names the calling worker thread.
    let thread = unsafe { windows_sys::Win32::System::Threading::GetCurrentThread() };
    // SAFETY: a live thread handle has a stable kernel thread id.
    let thread_id = unsafe { windows_sys::Win32::System::Threading::GetThreadId(thread) };
    let creation_time_100ns = thread_creation_time(thread)?;
    if thread_id == 0 || creation_time_100ns == 0 {
        return Err("worker thread identity is invalid".to_owned());
    }
    Ok(WindowsWorkerThreadIdentityV1 {
        thread_id,
        creation_time_100ns,
    })
}

fn thread_creation_time(thread: windows_sys::Win32::Foundation::HANDLE) -> Result<u64, String> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all four FILETIME outputs are writable; the handle has query access.
    if unsafe {
        GetThreadTimes(
            thread,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn deserialize_shared_outbox<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<std::sync::Arc<str>>, D::Error> {
    memcordon_core::deserialize_record_outbox(decoder)
        .map(|outbox| outbox.map(std::sync::Arc::from))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationPhase {
    ReadPrevious,
    Serialize,
    CreateStaging,
    WritePrefix,
    WriteRemainder,
    Flush,
    Rename,
    AfterRename,
    Readback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotInvariant {
    ExpectedRevision,
    FrozenWorkloadCheckpoint,
    AuthorizedWorkloadCheckpoint,
    FrozenWorkloadAdmission,
    AuthorizedWorkloadAdmission,
    RetentionAdmittedTime,
    RetentionExpiresTime,
    RetentionTombstone,
    ProviderIncarnation,
    LaunchIncarnation,
    Nonce,
    OwnerManifest,
    RecoveryAuthorization,
    PublicationReservation,
    TerminalSeed,
    RetirementProof,
    RequestDigest,
    CallerProcess,
    CallerToken,
    JobIdentity,
    WorkerProcess,
    WorkerThread,
    BootIdentity,
    AuthorizationTime,
    ResumeRegression,
    ReleaseRegression,
    TerminationRegression,
    ActiveZeroRegression,
    GuardianReapedRegression,
    FinalHandlesRegression,
    CausalSecondaryPrefix,
    StateTransition,
    CausalSequenceRegression,
    OriginalFailureReplacement,
    TerminalOutbox,
}

fn publication_io_error(error: io::Error) -> String {
    super::diagnostics::capture(memcordon_core::CausalEventV1 {
        sequence: 0,
        origin: memcordon_core::DiagnosticOriginV1::RecordWriter,
        category: memcordon_core::FailureCategoryV1::Persistence,
        operation: memcordon_core::FailureOperationV1::StoreRecord,
        code: memcordon_core::FailureCodeV1::RecordIo,
        native_code: error.raw_os_error().map(|code| {
            memcordon_core::NativeFailureCodeV1::Win32(u32::from_ne_bytes(code.to_ne_bytes()))
        }),
        observed_phase: memcordon_core::AttemptObservationPhaseV1::Terminalizing,
        safe_detail: memcordon_core::SafeDiagnosticDetailV1::NoAdditionalDetail,
        detail_redacted: true,
        detail_truncated: false,
        terminalization_reference: None,
    });
    error.to_string()
}

#[cfg(test)]
#[path = "../../../../tests/sealed_agent/windows_record_faults.rs"]
mod record_fault_tests;

#[cfg(test)]
#[path = "../../../../tests/sealed_agent/windows_guardian_liveness.rs"]
mod guardian_liveness_tests;

/// Native component tests use the real publication boundary at an owned path;
/// this hook changes neither installed storage paths nor production authority.
#[cfg(test)]
pub(crate) fn publish_owned_component_record_for_test(
    record: &mut WindowsAttemptRecordV1,
    path: &Path,
) -> Result<(), String> {
    let expected = record.record_revision;
    let mut candidate = record.clone();
    candidate.record_revision = expected
        .checked_add(1)
        .ok_or("component record revision exhausted")?;
    candidate.publish_at(path, expected, |_| Ok(()))?;
    *record = candidate;
    Ok(())
}

impl WindowsAttemptRecordV1 {
    pub fn new(
        attempt_id: String,
        request_sha256: String,
        caller_process_identity: WindowsProcessIdentityV1,
        caller_token_sha256: String,
        job_identity_sha256: String,
    ) -> Result<Self, String> {
        Ok(Self {
            schema_version: 5,
            attempt_id,
            provider_generation: provider_generation(),
            boot_identity: boot_identity()?,
            launch_incarnation: digest(&super::random::random_nonce()?.0),
            nonce: digest(&super::random::random_nonce()?.0),
            request_sha256,
            caller_process_identity,
            caller_token_sha256,
            job_identity_sha256,
            guardian_identity: None,
            worker_identity: None,
            worker_thread_identity: None,
            target_identity: None,
            state: WindowsAttemptStateV1::BoundaryCreated,
            lifecycle: memcordon_core::WindowsTerminalLifecycleV1::Executing,
            authorization_unix_millis: None,
            resume_attempted: false,
            target_released: false,
            cleanup_state: WindowsCleanupStateV1::default(),
            owner_manifest: None,
            job_closure_contract: None,
            recovery_authorization: None,
            terminal_publication_reserved: false,
            terminal_seed: None,
            retirement_proof: None,
            terminal_response_json: None,
            terminal_disposition: None,
            terminalization: WindowsTerminalizationStatusV1 {
                schema_version: 1,
                owner: WindowsTerminalizationOwnerV1::LauncherWorker,
                sequence: 1,
                checkpoint: WindowsTerminalizationCheckpointV1::Executing,
                last_error: None,
                secondary_errors: Vec::new(),
            },
            integrity_sha256: String::new(),
            causal_diagnostics: memcordon_core::WindowsCausalDiagnosticsV1::default(),
            diagnostic_retention: memcordon_core::DiagnosticRetentionV1::admitted_at(unsafe {
                windows_sys::Win32::System::SystemInformation::GetTickCount64()
            })
            .map_err(str::to_owned)?,
            record_revision: 0,
            provider_incarnation: provider_incarnation()?.to_owned(),
        })
    }

    pub fn store(&mut self) -> Result<(), String> {
        super::attempt_store::commit(self)
    }

    fn snapshot_violation(
        &self,
        previous: &Self,
        expected_revision: u64,
    ) -> Option<SnapshotInvariant> {
        let expiry = previous.diagnostic_retention.tombstone.is_none()
            && self.diagnostic_retention.tombstone
                == Some(memcordon_core::OriginalUnavailableReasonV1::RetentionExpired)
            && !diagnostic_export_eligible(previous)
            && self.causal_diagnostics.sequence == 0
            && self.causal_diagnostics.secondary.as_slice().is_empty()
            && self.causal_diagnostics.original
                == memcordon_core::OriginalFailureV1::Unavailable {
                    reason: memcordon_core::OriginalUnavailableReasonV1::RetentionExpired,
                };
        macro_rules! refuse {
            ($condition:expr, $kind:ident) => {
                if $condition {
                    return Some(SnapshotInvariant::$kind);
                }
            };
        }
        refuse!(
            previous.record_revision != expected_revision,
            ExpectedRevision
        );
        refuse!(
            previous.diagnostic_retention.admitted_monotonic_millis
                != self.diagnostic_retention.admitted_monotonic_millis,
            RetentionAdmittedTime
        );
        refuse!(
            previous.diagnostic_retention.expires_monotonic_millis
                != self.diagnostic_retention.expires_monotonic_millis,
            RetentionExpiresTime
        );
        refuse!(
            previous.diagnostic_retention.tombstone != self.diagnostic_retention.tombstone
                && !expiry,
            RetentionTombstone
        );
        refuse!(
            previous.provider_incarnation != self.provider_incarnation,
            ProviderIncarnation
        );
        refuse!(
            previous.launch_incarnation != self.launch_incarnation,
            LaunchIncarnation
        );
        refuse!(previous.nonce != self.nonce, Nonce);
        refuse!(
            previous
                .owner_manifest
                .as_ref()
                .is_some_and(|manifest| self.owner_manifest.as_ref() != Some(manifest)),
            OwnerManifest
        );
        refuse!(
            previous
                .recovery_authorization
                .as_ref()
                .is_some_and(
                    |authorization| self.recovery_authorization.as_ref() != Some(authorization)
                ),
            RecoveryAuthorization
        );
        refuse!(
            previous.terminal_publication_reserved && !self.terminal_publication_reserved,
            PublicationReservation
        );
        refuse!(
            previous
                .terminal_seed
                .as_ref()
                .is_some_and(|seed| self.terminal_seed.as_ref() != Some(seed)),
            TerminalSeed
        );
        refuse!(
            previous
                .retirement_proof
                .as_ref()
                .is_some_and(|proof| self.retirement_proof.as_ref() != Some(proof)),
            RetirementProof
        );
        refuse!(
            previous.request_sha256 != self.request_sha256,
            RequestDigest
        );
        refuse!(
            previous.caller_process_identity != self.caller_process_identity,
            CallerProcess
        );
        refuse!(
            previous.caller_token_sha256 != self.caller_token_sha256,
            CallerToken
        );
        refuse!(
            previous.job_identity_sha256 != self.job_identity_sha256,
            JobIdentity
        );
        refuse!(
            previous
                .worker_identity
                .as_ref()
                .is_some_and(|identity| self.worker_identity.as_ref() != Some(identity)),
            WorkerProcess
        );
        refuse!(
            previous
                .worker_thread_identity
                .is_some_and(|identity| self.worker_thread_identity != Some(identity)),
            WorkerThread
        );
        refuse!(previous.boot_identity != self.boot_identity, BootIdentity);
        refuse!(
            previous
                .authorization_unix_millis
                .is_some_and(|authorization| self.authorization_unix_millis != Some(authorization)),
            AuthorizationTime
        );
        refuse!(
            previous.resume_attempted && !self.resume_attempted,
            ResumeRegression
        );
        refuse!(
            previous.target_released && !self.target_released,
            ReleaseRegression
        );
        refuse!(
            previous.cleanup_state.termination_requested
                && !self.cleanup_state.termination_requested,
            TerminationRegression
        );
        refuse!(
            previous.cleanup_state.active_processes_zero
                && !self.cleanup_state.active_processes_zero,
            ActiveZeroRegression
        );
        refuse!(
            previous.cleanup_state.guardian_reaped && !self.cleanup_state.guardian_reaped,
            GuardianReapedRegression
        );
        refuse!(
            previous.cleanup_state.final_handles_closed && !self.cleanup_state.final_handles_closed,
            FinalHandlesRegression
        );
        refuse!(
            !expiry
                && !self
                    .causal_diagnostics
                    .secondary
                    .as_slice()
                    .starts_with(previous.causal_diagnostics.secondary.as_slice()),
            CausalSecondaryPrefix
        );
        refuse!(
            previous.state != self.state
                && !windows_attempt_transition_allowed(previous.state, self.state),
            StateTransition
        );
        refuse!(
            !expiry && previous.causal_diagnostics.sequence > self.causal_diagnostics.sequence,
            CausalSequenceRegression
        );
        refuse!(
            !expiry
                && matches!(
                    previous.causal_diagnostics.original,
                    memcordon_core::OriginalFailureV1::Observed { .. }
                )
                && previous.causal_diagnostics.original != self.causal_diagnostics.original,
            OriginalFailureReplacement
        );
        refuse!(
            previous
                .terminal_response_json
                .as_ref()
                .is_some_and(|outbox| self.terminal_response_json.as_ref() != Some(outbox)),
            TerminalOutbox
        );
        None
    }

    pub(super) fn publish_exclusive(&mut self, expected_revision: u64) -> Result<(), String> {
        let _owner = super::attempt_store::PublicationGuard::acquire(&self.attempt_id)
            .map_err(|error| format!("publication guard acquisition: {error}"))?;
        let path = record_path(&self.attempt_id)
            .map_err(|error| format!("publication record path: {error}"))?;
        let mut phase = PublicationPhase::ReadPrevious;
        self.publish_at(&path, expected_revision, |next| {
            phase = next;
            Ok(())
        })
        .map_err(|error| {
            format!("publication phase={phase:?}; attempt={}; expected-revision={expected_revision}; candidate-revision={}: {error}", self.attempt_id, self.record_revision)
        })
    }

    fn publish_at(
        &mut self,
        path: &Path,
        expected_revision: u64,
        mut checkpoint: impl FnMut(PublicationPhase) -> Result<(), String>,
    ) -> Result<(), String> {
        checkpoint(PublicationPhase::ReadPrevious)?;
        match read_record_bounded(path) {
            Ok(bytes) => {
                let previous: Self =
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                drop(bytes);
                authenticate(&previous, &self.attempt_id)?;
                if let Some(invariant) = self.snapshot_violation(&previous, expected_revision) {
                    return Err(format!(
                        "attempt snapshot violates exclusive revision or immutable evidence; invariant={invariant:?}; previous-revision={}; expected-revision={expected_revision}; candidate-revision={}; previous-state={:?}; candidate-state={:?}; previous-sequence={}; candidate-sequence={}; previous-secondary={}; candidate-secondary={}",
                        previous.record_revision,
                        self.record_revision,
                        previous.state,
                        self.state,
                        previous.causal_diagnostics.sequence,
                        self.causal_diagnostics.sequence,
                        previous.causal_diagnostics.secondary.as_slice().len(),
                        self.causal_diagnostics.secondary.as_slice().len()
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && expected_revision == 0 => {}
            Err(error) => return Err(publication_io_error(error)),
        }
        if self.record_revision
            != expected_revision
                .checked_add(1)
                .ok_or_else(|| "attempt revision exhausted".to_owned())?
        {
            return Err(format!(
                "attempt revision is not contiguous; expected-revision={expected_revision}; candidate-revision={}",
                self.record_revision
            ));
        }
        // The durable image establishes this watermark only when publication
        // succeeds; the caller receives it exclusively through completion.
        self.causal_diagnostics.durable_through_sequence = Some(self.causal_diagnostics.sequence);
        checkpoint(PublicationPhase::Serialize)?;
        let bytes = self.authenticated_store_bytes()?;
        let staged = path.with_extension("json.new");
        use std::io::Write;
        use std::os::windows::fs::OpenOptionsExt;
        checkpoint(PublicationPhase::CreateStaging)?;
        let mut staged_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&staged)
            .map_err(publication_io_error)?;
        let split = bytes.len() / 2;
        checkpoint(PublicationPhase::WritePrefix)?;
        staged_file
            .write_all(&bytes[..split])
            .map_err(publication_io_error)?;
        checkpoint(PublicationPhase::WriteRemainder)?;
        staged_file
            .write_all(&bytes[split..])
            .map_err(publication_io_error)?;
        checkpoint(PublicationPhase::Flush)?;
        staged_file.sync_all().map_err(publication_io_error)?;
        drop(staged_file);
        checkpoint(PublicationPhase::Rename)?;
        replace_atomically(&staged, path)?;
        checkpoint(PublicationPhase::AfterRename)?;
        checkpoint(PublicationPhase::Readback)?;
        let committed = read_record_bounded(path).map_err(publication_io_error)?;
        if committed != bytes {
            return Err("attempt publication readback differs".to_owned());
        }
        Ok(())
    }

    fn authenticated_store_bytes(&mut self) -> Result<Vec<u8>, String> {
        self.integrity_sha256.clear();
        self.integrity_sha256 = digest(&canonical_record_bytes(self)?);
        authenticate(self, &self.attempt_id).map_err(|detail| {
            format!("MCSEALED-WINDOWS-ATTEMPT-RECORD-STORE: phase=validate-before-publish {detail}")
        })?;
        memcordon_core::bounded_json_bytes(self, memcordon_core::WINDOWS_MAX_FRAME_BYTES, true)
            .map_err(|error| error.to_string())
    }

    #[cfg(test)]
    pub fn validate_for_store_for_test(&mut self) -> Result<(), String> {
        self.record_revision = self.record_revision.max(1);
        self.authenticated_store_bytes().map(|_| ())
    }

    pub fn authorize(&mut self) -> Result<(), String> {
        if !self
            .worker_thread_identity
            .is_some_and(|identity| identity.thread_id != 0 && identity.creation_time_100ns != 0)
        {
            return Err(
                "authorization requires an exact launcher worker thread identity".to_owned(),
            );
        }
        self.owner_manifest
            .as_ref()
            .ok_or_else(|| "authorization requires a frozen capability owner manifest".to_owned())?
            .validate()
            .map_err(str::to_owned)?;
        self.transition(WindowsAttemptStateV1::Authorized)?;
        self.authorization_unix_millis = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_millis()
                .try_into()
                .map_err(|_| "authorization timestamp exceeds record range".to_owned())?,
        );
        self.store()
    }

    pub fn retire(&mut self) -> Result<(), String> {
        self.transition(WindowsAttemptStateV1::Empty)?;
        self.cleanup_state.termination_requested = true;
        self.cleanup_state.active_processes_zero = true;
        self.cleanup_state.guardian_reaped = true;
        self.cleanup_state.final_handles_closed = true;
        self.store()?;
        super::attempt_store::retire(&self.attempt_id)?;
        let _owner = super::attempt_store::PublicationGuard::acquire(&self.attempt_id)?;

        fs::remove_file(record_path(&self.attempt_id)?).map_err(|error| error.to_string())?;
        remove_guardian_receipt(&self.attempt_id)
    }

    pub fn complete_retirement(&mut self) -> Result<(), String> {
        self.prepare_cleanup_completion(WindowsAttemptTerminalDispositionV1::Posttarget)?;
        self.lifecycle = memcordon_core::WindowsTerminalLifecycleV1::Retiring;
        self.store()
    }

    pub fn stage_terminal_proof(
        &mut self,
        receipt: &memcordon_core::WindowsTerminalReceiptV3,
        primary_failure: Option<memcordon_core::ProviderFailureDiagnosticV1>,
    ) -> Result<(), String> {
        self.stage_terminal_proof_with_store(receipt, primary_failure, &mut |record| record.store())
    }

    fn stage_terminal_proof_with_store<F>(
        &mut self,
        receipt: &memcordon_core::WindowsTerminalReceiptV3,
        primary_failure: Option<memcordon_core::ProviderFailureDiagnosticV1>,
        store: &mut F,
    ) -> Result<(), String>
    where
        F: FnMut(&mut Self) -> Result<(), String>,
    {
        if self.state != WindowsAttemptStateV1::Empty
            || self.lifecycle != memcordon_core::WindowsTerminalLifecycleV1::Retiring
            || self.owner_manifest.is_none()
            || self.retirement_proof.is_some()
            || receipt.attempt_id != self.attempt_id
            || receipt.nonce != self.nonce
            || receipt.request_sha256 != self.request_sha256
        {
            return Err("terminal proof cannot be staged outside exact retired attempt".to_owned());
        }
        receipt.validate_for_attempt().map_err(str::to_owned)?;
        let seed = memcordon_core::WindowsTerminalSeedV2 {
            schema_version: 2,
            attempt_id: self.attempt_id.clone(),
            nonce: self.nonce.clone(),
            request_sha256: self.request_sha256.clone(),
            process_observation: receipt.process_observation.clone(),
            primary_failure,
            premature_release: match &receipt.payload {
                memcordon_core::WindowsTerminalPayloadV3::PrematureReleaseFailure {
                    witness,
                    ..
                } => Some(witness.clone()),
                _ => None,
            },
        };
        if self
            .terminal_seed
            .as_ref()
            .is_some_and(|frozen| frozen != &seed)
        {
            return Err("terminal proof differs from the frozen seed".to_owned());
        }
        self.terminal_seed = Some(seed);
        self.retirement_proof = Some(receipt.retirement_proof.clone());
        self.lifecycle = memcordon_core::WindowsTerminalLifecycleV1::ProofReady;
        store(self)
    }

    #[cfg(test)]
    pub fn stage_terminal_proof_for_test<F>(
        &mut self,
        receipt: &memcordon_core::WindowsTerminalReceiptV3,
        primary_failure: Option<memcordon_core::ProviderFailureDiagnosticV1>,
        mut store: F,
    ) -> Result<(), String>
    where
        F: FnMut(&mut Self) -> Result<(), String>,
    {
        self.stage_terminal_proof_with_store(receipt, primary_failure, &mut store)
    }

    pub fn freeze_terminal_seed(
        &mut self,
        process_observation: memcordon_core::WindowsProcessObservationV2,
        primary_failure: Option<memcordon_core::ProviderFailureDiagnosticV1>,
    ) -> Result<(), String> {
        self.freeze_terminal_seed_with_store(process_observation, primary_failure, &mut |record| {
            record.store()
        })
    }

    fn freeze_terminal_seed_with_store<F>(
        &mut self,
        process_observation: memcordon_core::WindowsProcessObservationV2,
        primary_failure: Option<memcordon_core::ProviderFailureDiagnosticV1>,
        store: &mut F,
    ) -> Result<(), String>
    where
        F: FnMut(&mut Self) -> Result<(), String>,
    {
        if self.state != WindowsAttemptStateV1::Terminating
            || self.authorization_unix_millis.is_none()
            || self.owner_manifest.is_none()
            || self.terminal_seed.is_some()
            || self.retirement_proof.is_some()
            || self.terminal_response_json.is_some()
        {
            return Err("terminal seed cannot be frozen outside retiring authority".to_owned());
        }
        process_observation
            .validate(&self.attempt_id, &self.nonce, &self.request_sha256)
            .map_err(str::to_owned)?;
        self.terminal_seed = Some(memcordon_core::WindowsTerminalSeedV2 {
            schema_version: 2,
            attempt_id: self.attempt_id.clone(),
            nonce: self.nonce.clone(),
            request_sha256: self.request_sha256.clone(),
            process_observation,
            primary_failure,
            premature_release: None,
        });
        store(self)
    }

    pub fn begin_premature_release(
        &mut self,
        mutant: memcordon_core::WindowsSealedMutant,
    ) -> Result<(), String> {
        let disposition = WindowsAttemptTerminalDispositionV1::PrematureReleaseFailure { mutant };
        if disposition.premature_release_mutant().is_none()
            || self.authorization_unix_millis.is_some()
            || self.resume_attempted
            || self.target_released
            || self.terminal_disposition.is_some()
            || self.owner_manifest.is_none()
            || self.target_identity.is_none()
        {
            return Err("premature-release intent conflicts with native attempt".to_owned());
        }
        self.transition(WindowsAttemptStateV1::Terminating)?;
        self.cleanup_state.termination_requested = true;
        self.terminal_disposition = Some(disposition);
        self.store()
    }

    pub fn freeze_premature_release_seed(
        &mut self,
        witness: memcordon_core::WindowsPrematureReleaseWitnessV1,
        process_observation: memcordon_core::WindowsProcessObservationV2,
        primary_failure: Option<memcordon_core::ProviderFailureDiagnosticV1>,
    ) -> Result<(), String> {
        if !witness.is_consistent()
            || self
                .terminal_disposition
                .and_then(|value| value.premature_release_mutant())
                != Some(witness.mutant)
            || self.authorization_unix_millis.is_some()
            || self.resume_attempted
            || !self.target_released
            || self.state != WindowsAttemptStateV1::Terminating
            || self.owner_manifest.is_none()
            || self.terminal_seed.is_some()
            || self.retirement_proof.is_some()
            || self.terminal_response_json.is_some()
        {
            return Err("premature-release seed lacks exact observed native failure".to_owned());
        }
        process_observation
            .validate(&self.attempt_id, &self.nonce, &self.request_sha256)
            .map_err(str::to_owned)?;
        self.terminal_seed = Some(memcordon_core::WindowsTerminalSeedV2 {
            schema_version: 2,
            attempt_id: self.attempt_id.clone(),
            nonce: self.nonce.clone(),
            request_sha256: self.request_sha256.clone(),
            process_observation,
            primary_failure,
            premature_release: Some(witness),
        });
        self.store()
    }

    pub fn complete_premature_release(&mut self) -> Result<(), String> {
        let disposition = self
            .terminal_disposition
            .ok_or("premature-release disposition absent")?;
        if disposition.premature_release_mutant().is_none()
            || self
                .terminal_seed
                .as_ref()
                .and_then(|seed| seed.premature_release.as_ref())
                .is_none()
        {
            return Err("premature-release completion lacks frozen native witness".to_owned());
        }
        self.prepare_cleanup_completion(disposition)?;
        self.lifecycle = memcordon_core::WindowsTerminalLifecycleV1::Retiring;
        self.store()
    }

    #[cfg(test)]
    pub fn freeze_terminal_seed_for_test<F>(
        &mut self,
        process_observation: memcordon_core::WindowsProcessObservationV2,
        primary_failure: Option<memcordon_core::ProviderFailureDiagnosticV1>,
        mut store: F,
    ) -> Result<(), String>
    where
        F: FnMut(&mut Self) -> Result<(), String>,
    {
        self.freeze_terminal_seed_with_store(process_observation, primary_failure, &mut store)
    }

    fn prepare_cleanup_completion(
        &mut self,
        disposition: WindowsAttemptTerminalDispositionV1,
    ) -> Result<(), String> {
        self.transition(WindowsAttemptStateV1::Empty)?;
        self.cleanup_state.termination_requested = true;
        self.cleanup_state.active_processes_zero = true;
        self.cleanup_state.guardian_reaped = true;
        self.cleanup_state.final_handles_closed = true;
        self.terminal_disposition = Some(disposition);
        self.advance_terminalization(
            WindowsTerminalizationOwnerV1::LauncherWorker,
            WindowsTerminalizationCheckpointV1::CleanupProofReady,
        )?;
        Ok(())
    }

    pub fn begin_preauthorization_abort(&mut self) -> Result<(), String> {
        self.prepare_preauthorization_abort()?;
        self.store()
    }

    pub(super) fn prepare_preauthorization_abort(&mut self) -> Result<(), String> {
        if self.authorization_unix_millis.is_some() || self.resume_attempted {
            return Err(
                "preauthorization abort cannot replace durable authorization intent".to_owned(),
            );
        }
        match self.terminal_disposition {
            None | Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort) => {}
            Some(WindowsAttemptTerminalDispositionV1::Posttarget)
            | Some(WindowsAttemptTerminalDispositionV1::PrematureReleaseFailure { .. }) => {
                return Err(
                    "preauthorization abort conflicts with posttarget terminal disposition"
                        .to_owned(),
                );
            }
        }
        if self.state != WindowsAttemptStateV1::Terminating {
            self.transition(WindowsAttemptStateV1::Terminating)?;
        }
        self.cleanup_state.termination_requested = true;
        self.terminal_disposition =
            Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort);
        Ok(())
    }

    pub fn begin_postauthorization_retirement(&mut self) -> Result<(), String> {
        self.prepare_postauthorization_retirement()?;
        self.store()
    }

    fn prepare_postauthorization_retirement(&mut self) -> Result<(), String> {
        if self.authorization_unix_millis.is_none() {
            return Err(
                "postauthorization retirement requires durable authorization intent".to_owned(),
            );
        }
        if self.resume_attempted || self.target_released {
            return Err(
                "pre-resume postauthorization retirement conflicts with target release intent"
                    .to_owned(),
            );
        }
        match self.terminal_disposition {
            None | Some(WindowsAttemptTerminalDispositionV1::Posttarget) => {}
            Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort)
            | Some(WindowsAttemptTerminalDispositionV1::PrematureReleaseFailure { .. }) => {
                return Err(
                    "postauthorization retirement conflicts with preauthorization abort".to_owned(),
                );
            }
        }
        if !matches!(
            self.state,
            WindowsAttemptStateV1::Authorized | WindowsAttemptStateV1::Terminating
        ) {
            return Err(format!(
                "postauthorization retirement requires authorized state, observed {:?}",
                self.state
            ));
        }
        if self.state != WindowsAttemptStateV1::Terminating {
            self.transition(WindowsAttemptStateV1::Terminating)?;
        }
        self.cleanup_state.termination_requested = true;
        self.terminal_disposition = Some(WindowsAttemptTerminalDispositionV1::Posttarget);
        Ok(())
    }

    #[cfg(test)]
    pub fn begin_postauthorization_retirement_for_test(&mut self) -> Result<(), String> {
        self.prepare_postauthorization_retirement()?;
        self.validate_for_store_for_test()
    }

    pub fn complete_preauthorization_abort(&mut self) -> Result<(), String> {
        self.prepare_cleanup_completion(
            WindowsAttemptTerminalDispositionV1::PreauthorizationAbort,
        )?;
        self.store()
    }

    fn prepare_rejection_cleanup_completion(&mut self) -> Result<(), String> {
        if self.state != WindowsAttemptStateV1::Terminating {
            return Err(format!(
                "MCSEALED-WINDOWS-REJECTION-CLEANUP: expected terminating record before final-handle proof, observed {:?}",
                self.state
            ));
        }
        match self.terminal_disposition {
            Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort)
                if self.authorization_unix_millis.is_none() && !self.resume_attempted =>
            {
                self.prepare_cleanup_completion(
                    WindowsAttemptTerminalDispositionV1::PreauthorizationAbort,
                )
            }
            Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort) => Err(
                "MCSEALED-WINDOWS-REJECTION-CLEANUP: preauthorization disposition conflicts with durable authorization intent"
                    .to_owned(),
            ),
            Some(WindowsAttemptTerminalDispositionV1::Posttarget) => {
                self.prepare_cleanup_completion(WindowsAttemptTerminalDispositionV1::Posttarget)
            }
            Some(WindowsAttemptTerminalDispositionV1::PrematureReleaseFailure { .. }) => Err(
                "premature-release rejection requires its observed seed and native completion".to_owned(),
            ),
            None if self.authorization_unix_millis.is_some() || self.resume_attempted => {
                self.prepare_cleanup_completion(WindowsAttemptTerminalDispositionV1::Posttarget)
            }
            None => Err(
                "MCSEALED-WINDOWS-REJECTION-CLEANUP: terminating record has no typed terminal disposition"
                    .to_owned(),
            ),
        }
    }

    pub fn complete_rejection_cleanup(&mut self) -> Result<(), String> {
        self.prepare_rejection_cleanup_completion()?;
        self.store()
    }

    #[cfg(test)]
    pub fn complete_rejection_cleanup_for_test(&mut self) -> Result<(), String> {
        self.prepare_rejection_cleanup_completion()?;
        self.validate_for_store_for_test()
    }

    pub fn stage_terminal_response(
        &mut self,
        response: &memcordon_core::WindowsLauncherResponseV4,
    ) -> Result<(), String> {
        self.stage_terminal_response_with_store(response, &mut |record| record.store())?;
        // The exact relay event remains queryable until the outbox and its
        // completed proof are durable. It no longer needs a service owner then.
        super::launcher_service::retire_relay_retirement_event(&self.attempt_id)
    }

    fn stage_terminal_response_with_store<F>(
        &mut self,
        response: &memcordon_core::WindowsLauncherResponseV4,
        store: &mut F,
    ) -> Result<(), String>
    where
        F: FnMut(&mut Self) -> Result<(), String>,
    {
        let response_json = match self.prepare_terminal_response(response) {
            Ok(response_json) => response_json,
            Err(primary) => {
                return Err(self.persist_terminalization_failure(
                    WindowsTerminalizationOwnerV1::LauncherWorker,
                    WindowsTerminalizationErrorStageV1::ResponseValidate,
                    "MCSEALED-WINDOWS-TERMINAL-RESPONSE",
                    primary.clone(),
                    None,
                    primary,
                    store,
                ));
            }
        };
        self.advance_terminalization(
            WindowsTerminalizationOwnerV1::LauncherWorker,
            WindowsTerminalizationCheckpointV1::OutboxStaging,
        )?;
        if let Err(primary) = store(self) {
            return Err(self.persist_terminalization_failure(
                WindowsTerminalizationOwnerV1::LauncherWorker,
                WindowsTerminalizationErrorStageV1::AtomicStore,
                "MCSEALED-WINDOWS-TERMINAL-CHECKPOINT",
                format!("failed to persist the outbox-staging checkpoint: {primary}"),
                None,
                primary,
                store,
            ));
        }
        self.terminal_response_json = Some(response_json.into());
        let pre_outbox_lifecycle = self.lifecycle;
        self.lifecycle = memcordon_core::WindowsTerminalLifecycleV1::OutboxStaged;
        self.advance_terminalization(
            WindowsTerminalizationOwnerV1::LauncherWorker,
            WindowsTerminalizationCheckpointV1::OutboxStaged,
        )?;
        if let Err(primary) = store(self) {
            self.terminal_response_json = None;
            self.lifecycle = pre_outbox_lifecycle;
            return Err(self.persist_terminalization_failure(
                WindowsTerminalizationOwnerV1::LauncherWorker,
                WindowsTerminalizationErrorStageV1::AtomicStore,
                "MCSEALED-WINDOWS-TERMINAL-OUTBOX-STORE",
                format!("failed to publish the create-once terminal outbox: {primary}"),
                None,
                primary,
                store,
            ));
        }
        Ok(())
    }

    fn advance_terminalization(
        &mut self,
        owner: WindowsTerminalizationOwnerV1,
        checkpoint: WindowsTerminalizationCheckpointV1,
    ) -> Result<(), String> {
        self.terminalization.sequence = self
            .terminalization
            .sequence
            .checked_add(1)
            .ok_or_else(|| "terminalization sequence exhausted".to_owned())?;
        self.terminalization.owner = owner;
        self.terminalization.checkpoint = checkpoint;
        Ok(())
    }

    pub(super) fn persist_retirement_operation_failure(
        &mut self,
        stage: WindowsTerminalizationErrorStageV1,
        code: &str,
        primary: String,
    ) -> String {
        self.persist_terminalization_failure(
            WindowsTerminalizationOwnerV1::LauncherWorker,
            stage,
            code,
            primary.clone(),
            None,
            primary,
            &mut |record| record.store(),
        )
    }

    fn persist_terminalization_failure<F>(
        &mut self,
        owner: WindowsTerminalizationOwnerV1,
        stage: WindowsTerminalizationErrorStageV1,
        error_code: &str,
        detail: String,
        native_code: Option<i32>,
        primary: String,
        store: &mut F,
    ) -> String
    where
        F: FnMut(&mut Self) -> Result<(), String>,
    {
        let checkpoint = if self.terminal_response_json.is_some() {
            WindowsTerminalizationCheckpointV1::OutboxStaged
        } else {
            WindowsTerminalizationCheckpointV1::RetainedFailure
        };
        let diagnostic_result = self
            .advance_terminalization(owner, checkpoint)
            .and_then(|()| {
                self.retain_terminalization_error(terminalization_error(
                    stage,
                    error_code,
                    detail,
                    native_code,
                ));
                store(self)
            });
        match diagnostic_result {
            Ok(()) => primary,
            Err(secondary) => format!(
                "{primary}; secondary authenticated terminalization diagnostic failure: {secondary}"
            ),
        }
    }

    fn retain_terminalization_error(&mut self, error: WindowsTerminalizationErrorV1) -> bool {
        use memcordon_core::{
            FailureCategoryV1 as Category, FailureCodeV1 as Code, FailureOperationV1 as Operation,
        };
        let (category, operation, code) = match error.stage {
            WindowsTerminalizationErrorStageV1::LaunchRelay => (
                Category::Transport,
                Operation::ReadControlFrame,
                Code::ControlTransport,
            ),
            WindowsTerminalizationErrorStageV1::CleanupFinalize => (
                Category::Cleanup,
                Operation::CloseFinalHandles,
                Code::UnexpectedProviderFailure,
            ),
            WindowsTerminalizationErrorStageV1::ReceiptBuild
            | WindowsTerminalizationErrorStageV1::RejectionBuild => (
                Category::Terminalization,
                Operation::BuildRejection,
                Code::TerminalBinding,
            ),
            WindowsTerminalizationErrorStageV1::ResponseValidate => (
                Category::Terminalization,
                Operation::ValidateTerminalResponse,
                Code::TerminalBinding,
            ),
            WindowsTerminalizationErrorStageV1::ResponseSerialize => (
                Category::Terminalization,
                Operation::SerializeTerminalResponse,
                Code::TerminalBinding,
            ),
            WindowsTerminalizationErrorStageV1::RecordAuthenticate => (
                Category::Persistence,
                Operation::InspectRecoveryRecord,
                Code::RecordAuthentication,
            ),
            WindowsTerminalizationErrorStageV1::AtomicStore => (
                Category::Persistence,
                Operation::StoreRecord,
                Code::RecordIo,
            ),
            WindowsTerminalizationErrorStageV1::LiveDelivery => (
                Category::Transport,
                Operation::DeliverResponse,
                Code::ControlTransport,
            ),
            WindowsTerminalizationErrorStageV1::TerminalAck => (
                Category::Transport,
                Operation::AcknowledgeTerminal,
                Code::ControlTransport,
            ),
            WindowsTerminalizationErrorStageV1::OutboxRetirement => (
                Category::Terminalization,
                Operation::RetireOutbox,
                Code::RecordIo,
            ),
        };
        let terminalization_reference = if self.terminalization.last_error.is_none() {
            Some(memcordon_core::TerminalizationReferenceV1::FirstError)
        } else if self.terminalization.secondary_errors.len()
            < memcordon_core::WINDOWS_MAX_TERMINALIZATION_SECONDARY_ERRORS
        {
            Some(memcordon_core::TerminalizationReferenceV1::SecondaryError {
                index: u8::try_from(self.terminalization.secondary_errors.len())
                    .expect("bounded terminalization index"),
            })
        } else {
            None
        };
        let event = memcordon_core::CausalEventV1 {
            sequence: 0,
            origin: match self.terminalization.owner {
                WindowsTerminalizationOwnerV1::LauncherWorker => {
                    memcordon_core::DiagnosticOriginV1::Launcher
                }
                WindowsTerminalizationOwnerV1::ControlService => {
                    memcordon_core::DiagnosticOriginV1::ControlRelay
                }
                WindowsTerminalizationOwnerV1::StartupRecovery => {
                    memcordon_core::DiagnosticOriginV1::StartupRecovery
                }
                WindowsTerminalizationOwnerV1::GuardianRecovery => {
                    memcordon_core::DiagnosticOriginV1::GuardianRecovery
                }
            },
            category,
            operation,
            code,
            native_code: error
                .native_code
                .map(memcordon_core::NativeFailureCodeV1::Unclassified),
            observed_phase: memcordon_core::AttemptObservationPhaseV1::Terminalizing,
            safe_detail: memcordon_core::SafeDiagnosticDetailV1::NoAdditionalDetail,
            detail_redacted: true,
            detail_truncated: false,
            terminalization_reference,
        };
        super::diagnostics::observe_record(&mut self.causal_diagnostics, event, false);
        if self.terminalization.last_error.is_none() {
            self.terminalization.last_error = Some(error);
            true
        } else if self.terminalization.secondary_errors.len()
            < memcordon_core::WINDOWS_MAX_TERMINALIZATION_SECONDARY_ERRORS
        {
            self.terminalization.secondary_errors.push(error);
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    fn apply_terminalization_diagnostic(
        &mut self,
        error: WindowsTerminalizationErrorV1,
    ) -> Result<bool, String> {
        if self.terminalization.last_error.is_some()
            && self.terminalization.secondary_errors.len()
                >= memcordon_core::WINDOWS_MAX_TERMINALIZATION_SECONDARY_ERRORS
        {
            return Ok(false);
        }
        self.terminalization.sequence = self
            .terminalization
            .sequence
            .checked_add(1)
            .ok_or_else(|| "terminalization sequence exhausted".to_owned())?;
        Ok(self.retain_terminalization_error(error))
    }

    #[cfg(test)]
    pub fn record_terminalization_diagnostic_for_test(
        &mut self,
        error: WindowsTerminalizationErrorV1,
    ) -> Result<(), String> {
        self.apply_terminalization_diagnostic(error)?;
        self.validate_for_store_for_test()
    }

    fn prepare_terminal_response(
        &self,
        response: &memcordon_core::WindowsLauncherResponseV4,
    ) -> Result<String, String> {
        if self.state != WindowsAttemptStateV1::Empty || self.terminal_response_json.is_some() {
            return Err("attempt is not ready for a create-once terminal outbox".to_owned());
        }
        if !memcordon_core::windows_terminal_outbox_is_bound_v4(&decoded_v4(self), response) {
            return Err(
                "terminal outbox response is not bound and consistent for the attempt".to_owned(),
            );
        }
        let response_json = response
            .terminal_authority_json()
            .map_err(|error| error.to_string())?;
        if response_json.len() > memcordon_core::WINDOWS_MAX_FRAME_BYTES / 2 {
            return Err("terminal outbox response exceeds the bounded frame size".to_owned());
        }
        Ok(response_json)
    }

    #[cfg(test)]
    pub fn stage_terminal_response_for_test(
        &mut self,
        response: &memcordon_core::WindowsLauncherResponseV4,
    ) -> Result<(), String> {
        self.terminal_response_json = Some(self.prepare_terminal_response(response)?.into());
        self.advance_terminalization(
            WindowsTerminalizationOwnerV1::LauncherWorker,
            WindowsTerminalizationCheckpointV1::OutboxStaged,
        )?;
        self.validate_for_store_for_test()
    }

    #[cfg(test)]
    pub fn stage_terminal_response_with_store_for_test<F>(
        &mut self,
        response: &memcordon_core::WindowsLauncherResponseV4,
        mut store: F,
    ) -> Result<(), String>
    where
        F: FnMut(&mut Self) -> Result<(), String>,
    {
        self.stage_terminal_response_with_store(response, &mut store)
    }

    pub fn acknowledge_terminal_response(&mut self) -> Result<(), String> {
        if self.terminal_response_json.is_none() {
            return Err("attempt has no durable terminal outbox to acknowledge".to_owned());
        }
        let retired = self.terminal_retired_receipt(&self.nonce)?;
        // Validate the exact disposition's checked authority before committing ACK.
        let tombstone = ack_tombstone_for(self, &retired)?;
        if self.lifecycle != memcordon_core::WindowsTerminalLifecycleV1::AckCommitted {
            self.lifecycle = memcordon_core::WindowsTerminalLifecycleV1::AckCommitted;
            self.store()?;
        }
        stage_ack_tombstone(self, tombstone)?;
        if self.job_closure_contract.is_some() {
            retire_admission(&self.attempt_id)?;
        }
        remove_guardian_receipt(&self.attempt_id)?;
        super::attempt_store::retire(&self.attempt_id)?;
        let _owner = super::attempt_store::PublicationGuard::acquire(&self.attempt_id)?;

        fs::remove_file(record_path(&self.attempt_id)?).map_err(|error| error.to_string())?;
        complete_ack_tombstone(&self.attempt_id, &self.request_sha256)?;
        Ok(())
    }

    pub fn terminal_retired_receipt(
        &self,
        nonce: &str,
    ) -> Result<memcordon_core::WindowsRetirementMetadata, String> {
        if nonce != self.nonce {
            return Err("terminal ACK nonce does not match durable attempt".to_owned());
        }
        let response_json = self
            .terminal_response_json
            .as_ref()
            .ok_or_else(|| "attempt has no durable terminal outbox".to_owned())?;
        let disposition = self
            .terminal_disposition
            .ok_or_else(|| "attempt terminal disposition is absent".to_owned())?;
        Ok(memcordon_core::WindowsRetirementMetadata {
            attempt_id: self.attempt_id.clone(),
            nonce: nonce.to_owned(),
            request_sha256: self.request_sha256.clone(),
            terminal_response_sha256: digest(response_json.as_bytes()),
            disposition,
        })
    }

    pub fn completed_terminal_retired_receipt(
        &self,
    ) -> Result<memcordon_core::WindowsTerminalRetiredV2, String> {
        complete_ack_tombstone(&self.attempt_id, &self.request_sha256)
    }

    pub fn mark_released(&mut self) -> Result<(), String> {
        self.target_released = true;
        self.store()
    }

    pub fn mark_resume_attempted(&mut self) -> Result<(), String> {
        self.resume_attempted = true;
        self.store()
    }

    pub fn transition(&mut self, state: WindowsAttemptStateV1) -> Result<(), String> {
        if !windows_attempt_transition_allowed(self.state, state) {
            return Err(format!(
                "attempt state transition is invalid: {:?} -> {state:?}",
                self.state
            ));
        }
        self.state = state;
        if state == WindowsAttemptStateV1::Terminating
            && self.terminalization.checkpoint == WindowsTerminalizationCheckpointV1::Executing
        {
            self.advance_terminalization(
                WindowsTerminalizationOwnerV1::LauncherWorker,
                WindowsTerminalizationCheckpointV1::CleanupRequested,
            )?;
        }
        Ok(())
    }
}

pub fn bounded_terminalization_error(
    stage: WindowsTerminalizationErrorStageV1,
    error_code: &str,
    detail: impl AsRef<str>,
    native_code: Option<i32>,
) -> WindowsTerminalizationErrorV1 {
    let error_code = if !error_code.is_empty()
        && error_code.len() <= MAX_TERMINALIZATION_CODE_BYTES
        && error_code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
    {
        error_code.to_owned()
    } else {
        "MCSEALED-WINDOWS-TERMINALIZATION".to_owned()
    };
    let detail = bounded_nonempty_detail(
        detail.as_ref(),
        MAX_TERMINALIZATION_DETAIL_BYTES,
        "unspecified terminalization failure",
    );
    WindowsTerminalizationErrorV1 {
        stage,
        error_code,
        detail,
        native_code,
        observed_unix_millis: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok()),
    }
}

fn bounded_nonempty_detail(detail: &str, max_bytes: usize, default_detail: &str) -> String {
    let sanitized = detail.replace('\0', "�");
    let sanitized = if sanitized.is_empty() {
        default_detail.to_owned()
    } else {
        sanitized
    };
    if sanitized.len() <= max_bytes {
        return sanitized;
    }
    let mut end = max_bytes.min(sanitized.len());
    while !sanitized.is_char_boundary(end) {
        end -= 1;
    }
    sanitized[..end].to_owned()
}

fn bounded_rejection_detail(detail: String) -> String {
    bounded_nonempty_detail(
        &detail,
        memcordon_core::PROVIDER_REJECTION_MAX_DETAIL_BYTES,
        "unspecified provider rejection",
    )
}

fn terminalization_error(
    stage: WindowsTerminalizationErrorStageV1,
    error_code: &str,
    detail: String,
    native_code: Option<i32>,
) -> WindowsTerminalizationErrorV1 {
    bounded_terminalization_error(stage, error_code, detail, native_code)
}

fn recovery_terminalization_error(error: Option<&WindowsTerminalizationErrorV1>) -> String {
    let Some(error) = error else {
        return "none".into();
    };
    let mut end = error.detail.len().min(512);
    while !error.detail.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "stage={:?}; code={}; native-code={:?}; detail-truncated={}; detail={}",
        error.stage,
        error.error_code,
        error.native_code,
        end != error.detail.len(),
        &error.detail[..end],
    )
}

pub fn record_terminalization_failure(
    attempt_id: &str,
    owner: WindowsTerminalizationOwnerV1,
    error: WindowsTerminalizationErrorV1,
) -> Result<(), String> {
    let path = record_path(attempt_id)?;
    let bytes = read_record_bounded(&path).map_err(|read_error| read_error.to_string())?;
    let mut record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|parse_error| parse_error.to_string())?;
    authenticate(&record, attempt_id)?;
    let checkpoint = if record.terminal_response_json.is_some() {
        WindowsTerminalizationCheckpointV1::OutboxStaged
    } else {
        WindowsTerminalizationCheckpointV1::RetainedFailure
    };
    record.advance_terminalization(owner, checkpoint)?;
    record.retain_terminalization_error(error);
    record.store()
}

pub(super) fn replay_relay_failure_evidence(
    binding: (&str, &str, &str),
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
    caller_process_identity: &WindowsProcessIdentityV1,
    caller_token_sha256: &str,
    error: &WindowsTerminalizationErrorV1,
) -> Result<memcordon_core::WindowsAttemptRetainedV2, String> {
    let (attempt_id, _, request_sha256) = binding;
    let _reader = RecordReaderReservation::acquire(attempt_id, request_sha256)?;
    let path = record_path(attempt_id)?;
    let bytes = read_record_bounded(&path).map_err(|read_error| read_error.to_string())?;
    let record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|parse_error| parse_error.to_string())?;
    authenticate(&record, attempt_id)?;
    retained_relay_failure_from_snapshot(
        &record,
        binding,
        relay_phase,
        caller_process_identity,
        caller_token_sha256,
        error,
    )
}

pub(crate) fn retained_relay_failure_from_snapshot(
    record: &WindowsAttemptRecordV1,
    binding: (&str, &str, &str),
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
    caller_process_identity: &WindowsProcessIdentityV1,
    caller_token_sha256: &str,
    error: &WindowsTerminalizationErrorV1,
) -> Result<memcordon_core::WindowsAttemptRetainedV2, String> {
    let (attempt_id, nonce, request_sha256) = binding;
    if record.attempt_id != attempt_id
        || record.nonce != nonce
        || record.request_sha256 != request_sha256
        || record.caller_process_identity != *caller_process_identity
        || record.caller_token_sha256 != caller_token_sha256
        || !error.is_consistent()
    {
        return Err(
            "read-only relay failure does not match authenticated attempt credentials".into(),
        );
    }
    Ok(retained_attempt_evidence_from_snapshot(
        attempt_id, nonce, request_sha256, relay_phase,
        format!("observed uncommitted relay failure: {}", serde_json::to_string(error).map_err(|error| error.to_string())?),
        vec!["read-only observation; durable revision, terminalization and original causal journal unchanged".into()],
        Some(record),
    ))
}

pub fn recover() -> Result<(), String> {
    recover_until(Instant::now() + Duration::from_secs(35)).map_err(|error| error.to_string())
}

pub(super) struct StartupPendingTerminal {
    expected_ack: Option<TerminalAckTombstoneV1>,
    original: WindowsAttemptRecordV1,
}

pub(super) enum StartupRecoveryOutcome {
    Clear,
    RecoveryOnly(Vec<StartupPendingTerminal>),
}

/// Pending authenticated outboxes need the recovery listener in order to ACK.
/// They never grant admission or make strict package cleanup succeed.
pub(super) fn recover_for_startup() -> Result<StartupRecoveryOutcome, String> {
    let mut pending = Vec::new();
    reconcile_until(Instant::now() + Duration::from_secs(35), Some(&mut pending))
        .map_err(|error| error.to_string())?;
    Ok(if pending.is_empty() {
        StartupRecoveryOutcome::Clear
    } else {
        StartupRecoveryOutcome::RecoveryOnly(pending)
    })
}

pub(super) fn startup_outboxes_acknowledged(
    pending: &[StartupPendingTerminal],
) -> Result<bool, String> {
    for original in pending {
        let retired = &original.original;
        let (_, replay) = replay_record(&retired.attempt_id, &retired.request_sha256)?;
        let Some(ack) = replay.acknowledged else {
            return Ok(false);
        };
        let exact = match &original.expected_ack {
            Some(expected) => &ack == expected,
            None => {
                ack.retirement_complete
                    && ack.authority_is_consistent()
                    && ack.retired.attempt_id == retired.attempt_id
                    && ack.retired.nonce == retired.nonce
                    && ack.retired.request_sha256 == retired.request_sha256
                    && ack.provider_generation == retired.provider_generation
                    && ack.launch_incarnation == retired.launch_incarnation
                    && ack.original_boot_id == retired.boot_identity
                    && ack.job_identity == retired.job_identity_sha256
                    && ack.owner_manifest_sha256
                        == retired
                            .owner_manifest
                            .as_ref()
                            .ok_or("startup original manifest absent")?
                            .canonical_sha256()
                            .map_err(str::to_owned)?
                    && ack.caller_process_identity == retired.caller_process_identity
                    && ack.caller_token_sha256 == retired.caller_token_sha256
                    && Some(&ack.recovery_authorization) == retired.recovery_authorization.as_ref()
            }
        };
        if !exact
            || record_path(&retired.attempt_id)?
                .try_exists()
                .map_err(|error| error.to_string())?
            || guardian_receipt_path(&retired.attempt_id)?
                .try_exists()
                .map_err(|error| error.to_string())?
            || admissions_root()
                .join(&retired.attempt_id)
                .with_extension("json")
                .try_exists()
                .map_err(|error| error.to_string())?
            || admissions_root()
                .join(&retired.attempt_id)
                .with_extension("writer.json")
                .try_exists()
                .map_err(|error| error.to_string())?
            || admissions_root()
                .join(&retired.attempt_id)
                .with_extension("reader.json")
                .try_exists()
                .map_err(|error| error.to_string())?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn retain_startup_outbox(
    pending: &mut Vec<StartupPendingTerminal>,
    record: &WindowsAttemptRecordV1,
) -> Result<(), String> {
    authenticate(record, &record.attempt_id)?;
    let retired = record.terminal_retired_receipt(&record.nonce)?;
    let mut expected_ack = ack_tombstone_for(record, &retired)?;
    expected_ack.retirement_complete = true;
    pending.push(StartupPendingTerminal {
        expected_ack: Some(expected_ack),
        original: record.clone(),
    });
    Ok(())
}

#[derive(Debug)]
pub(crate) enum PackageCleanupError {
    Active(String),
    Ambiguous(String),
    Failed(String),
}

impl std::fmt::Display for PackageCleanupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active(detail) => write!(formatter, "MCSEALED-WINDOWS-PACKAGE-ACTIVE: {detail}"),
            Self::Ambiguous(detail) => {
                write!(formatter, "MCSEALED-WINDOWS-RECOVERY-AMBIGUOUS: {detail}")
            }
            Self::Failed(detail) => formatter.write_str(detail),
        }
    }
}

impl From<String> for PackageCleanupError {
    fn from(detail: String) -> Self {
        Self::Failed(detail)
    }
}

/// Converges active attempt state within the package transaction's single
/// deadline. The launcher first terminates every Job for which it still owns
/// authority; this durable phase then waits for guardian/process-zero proof
/// and retires only records without an unacknowledged terminal outbox.
pub fn converge_package_cleanup(deadline: Instant) -> Result<(), PackageCleanupError> {
    recover_until(deadline)
}

fn recover_until(deadline: Instant) -> Result<(), PackageCleanupError> {
    reconcile_until(deadline, None)
}

fn reconcile_until(
    deadline: Instant,
    mut startup_pending: Option<&mut Vec<StartupPendingTerminal>>,
) -> Result<(), PackageCleanupError> {
    use memcordon_core::{
        WindowsLauncherStartupReasonV1 as Reason, WindowsLauncherStartupStageV1 as Stage,
    };
    let startup = startup_pending.is_some();
    let stage = |value| {
        if startup {
            super::startup_diagnostics::launcher_stage(value);
        }
    };
    let blocker = |reason| {
        if startup {
            super::startup_diagnostics::launcher_blocker(reason);
        }
    };
    stage(Stage::WriterQuarantine);
    super::attempt_store::ensure_no_quarantined_writer()?;
    let attempts = attempts_root();
    fs::create_dir_all(&attempts).map_err(|error| error.to_string())?;
    fs::create_dir_all(quarantine_root()).map_err(|error| error.to_string())?;
    fs::create_dir_all(replay_root()).map_err(|error| error.to_string())?;
    stage(Stage::StagedAck);
    recover_staged_ack_tombstones().map_err(PackageCleanupError::Ambiguous)?;
    fs::create_dir_all(admissions_root()).map_err(|error| error.to_string())?;
    fs::create_dir_all(guardian_receipts_root()).map_err(|error| error.to_string())?;
    stage(Stage::WriterQuarantine);
    let mut ambiguous = fs::read_dir(quarantine_root())
        .map_err(|error| error.to_string())?
        .map(|entry| {
            entry
                .map(|entry| format!("{} (durable quarantine)", entry.path().to_string_lossy()))
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !ambiguous.is_empty() {
        blocker(Reason::RetainedAmbiguity);
    }
    stage(Stage::GuardianDirectory);
    for entry in fs::read_dir(guardian_receipts_root()).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        let parsed = (|| {
            let attempt_id = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("guardian receipt directory name is not UTF-8")?
                .to_owned();
            validate_attempt_id(&attempt_id)?;
            verify_guardian_receipt_directory(&path)?;
            for child in fs::read_dir(&path).map_err(|error| error.to_string())? {
                let child = child.map_err(|error| error.to_string())?;
                if child.file_name() != std::ffi::OsStr::new("receipt.json") {
                    blocker(Reason::UnknownGuardianChild);
                    return Err(
                        "guardian receipt directory has an unpublished or unknown child".into(),
                    );
                }
                read_guardian_receipt(&attempt_id)?;
            }
            Ok::<_, String>(attempt_id)
        })();
        match parsed {
            Ok(attempt_id) if !record_path(&attempt_id)?.exists() => {
                // Provisioning precedes the first durable guardian association.
                // Do not race a live writer or a still-owned guardian slot.
                let retirement = retire_writer_admission(&attempt_id, false)
                    .and_then(|()| require_empty_guardian_slot_state())
                    .and_then(|()| remove_guardian_receipt(&attempt_id));
                if let Err(error) = retirement {
                    blocker(Reason::RetainedAmbiguity);
                    ambiguous.push(format!(
                        "{} (guardian receipt directory remains owned: {error})",
                        path.display()
                    ));
                }
            }
            Ok(_) => {}
            Err(error) => {
                blocker(Reason::InvalidRecord);
                // An active guardian may still hold the CREATE_NEW staging
                // handle. Preserve its directory and all evidence in place.
                ambiguous.push(format!(
                    "{} (invalid guardian terminal receipt: {error})",
                    path.display()
                ));
            }
        }
    }
    for entry in fs::read_dir(admissions_root()).map_err(|error| error.to_string())? {
        stage(Stage::ReaderAdmission);
        let entry = entry.map_err(|error| error.to_string())?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.ends_with(".reader.json"))
        {
            let _reader_owner = super::attempt_store::PublicationGuard::acquire(&digest(
                b"installation-retained-reader-v1",
            ))?;
            let _budget = super::attempt_store::PublicationGuard::acquire(&digest(
                b"installation-attempt-storage-budget-v1",
            ))?;
            let admission: AdmissionRecordV1 = serde_json::from_slice(
                &read_record_bounded_with_limit(&entry.path(), 4096)
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            if admission
                .owner_process_identities
                .into_iter()
                .any(|owner| process_identity_is_live(owner).unwrap_or(true))
            {
                blocker(Reason::LiveReader);
                ambiguous.push("retained reader reservation remains charged".to_owned());
            } else {
                fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
            }
            continue;
        }
        if let Some(attempt_id) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_suffix(".writer.json"))
        {
            stage(Stage::WriterAdmission);
            if let Err(error) = retire_writer_admission(attempt_id, false) {
                blocker(Reason::UnconfirmedWriter);
                ambiguous.push(format!("writer reservation remains charged: {error}"));
            }
            continue;
        }
        stage(Stage::OwnedAdmission);
        if let Some(attempt_id) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_suffix(".json"))
        {
            let path = record_path(attempt_id)?;
            if path.try_exists().map_err(|error| error.to_string())? {
                stage(Stage::RecordRead);
                let bytes = read_record_bounded(&path).map_err(|error| error.to_string())?;
                let record: WindowsAttemptRecordV1 =
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                stage(Stage::RecordAuthentication);
                authenticate(&record, attempt_id)?;
                if record.job_closure_contract.is_some()
                    && record.authorization_unix_millis.is_some()
                {
                    stage(Stage::OwnedAdmission);
                    validate_admission(attempt_id, &record.request_sha256)?;
                    // This exact authenticated attempt still owns the charge.
                    // Only its real terminal ACK may retire it.
                    continue;
                }
            }
        }
        stage(Stage::OwnedAdmission);
        let quarantined = quarantine(&entry.path())?;
        blocker(Reason::UnjoinedAdmission);
        ambiguous.push(format!(
            "{} (abandoned launch admission)",
            quarantined.to_string_lossy()
        ));
    }
    for entry in fs::read_dir(&attempts).map_err(|error| error.to_string())? {
        stage(Stage::RecordRead);
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if reserved_writer_stage(&path, &admissions_root())? {
            blocker(Reason::UnconfirmedWriter);
            ambiguous.push(format!(
                "{} (live writer publication remains reserved)",
                path.to_string_lossy()
            ));
            continue;
        }
        stage(Stage::ReaderAdmission);
        let _reader = if let Ok(attempt_id) = record_attempt_id(&path) {
            Some(RecordReaderReservation::acquire(&attempt_id, &attempt_id)?)
        } else {
            None
        };
        stage(Stage::RecordRead);
        let parsed = (|| {
            let attempt_id = record_attempt_id(&path)?;
            let bytes = read_record_bounded(&path).map_err(|error| error.to_string())?;
            let record: WindowsAttemptRecordV1 =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            stage(Stage::RecordAuthentication);
            authenticate(&record, &attempt_id)?;
            Ok::<_, String>(record)
        })();
        let mut record = match parsed {
            Ok(record) => record,
            Err(error) => {
                blocker(Reason::InvalidRecord);
                let quarantined = quarantine(&path)?;
                ambiguous.push(format!("{} ({error})", quarantined.to_string_lossy()));
                continue;
            }
        };
        if record.lifecycle == memcordon_core::WindowsTerminalLifecycleV1::AckCommitted {
            record.acknowledge_terminal_response()?;
            continue;
        }
        if record.terminal_response_json.is_some() {
            stage(Stage::PendingOutbox);
            if let Some(pending) = startup_pending.as_deref_mut() {
                retain_startup_outbox(pending, &record)?;
            } else {
                blocker(Reason::RetainedAmbiguity);
                ambiguous.push(format!(
                    "{} (unacknowledged durable terminal outbox)",
                    path.to_string_lossy()
                ));
            }
            continue;
        }
        if record.authorization_unix_millis.is_some()
            || record.resume_attempted
            || record.target_released
        {
            stage(Stage::NativeOwnerClosure);
            let current_boot = boot_identity()?;
            let progress = if record.boot_identity != current_boot {
                stage_recovered_closure(&mut record, &current_boot, None)
            } else if guardian_receipt_path(&record.attempt_id)?.exists() {
                stage(Stage::GuardianReceiptBinding);
                let guardian = read_guardian_receipt(&record.attempt_id)?;
                if guardian_receipt_binds_record(&guardian, &record)?
                    && frozen_manifest_owners_extinct(&record)?
                {
                    stage_recovered_closure(&mut record, &current_boot, Some(&guardian))
                } else {
                    Err("guardian or owner closure evidence is incomplete".to_owned())
                }
            } else if record.job_closure_contract.is_some() && startup_pending.is_some() {
                stage(Stage::UnresolvedContract);
                // The authenticated closure contract authorizes recovery
                // serving, never admission or a claim of completed closure.
                if let Some(pending) = startup_pending.as_deref_mut() {
                    pending.push(StartupPendingTerminal {
                        expected_ack: None,
                        original: record.clone(),
                    });
                    continue;
                }
                unreachable!("startup pending was checked");
            } else {
                stage(Stage::NativeOwnerClosure);
                if let Some(extinction) = capability_extinction(&record)? {
                    stage_recovered_closure_with_extinction(
                        &mut record,
                        &current_boot,
                        None,
                        Some(extinction),
                    )
                } else {
                    Err("guardian native zero receipt is unavailable".to_owned())
                }
            };
            if progress.is_ok() {
                if let Some(pending) = startup_pending.as_deref_mut() {
                    retain_startup_outbox(pending, &record)?;
                    continue;
                }
            }
            blocker(Reason::RetainedAmbiguity);
            ambiguous.push(format!(
                "{} ({})",
                path.to_string_lossy(),
                match progress {
                    Ok(()) =>
                        "recovered terminal authority staged; exact caller ACK pending".to_owned(),
                    Err(error) => format!("postauthorization authority retained: {error}"),
                }
            ));
            continue;
        }
        let no_live_processes = !record_has_live_process(&record)?;
        let prior_boot = record.boot_identity != boot_identity()?;
        let durably_empty = record.state == WindowsAttemptStateV1::Empty
            && record.cleanup_state.termination_requested
            && record.cleanup_state.active_processes_zero
            && record.cleanup_state.guardian_reaped
            && record.cleanup_state.final_handles_closed;
        let kill_on_close_reconciled = record.state == WindowsAttemptStateV1::Terminating
            && record.cleanup_state.termination_requested
            && record.guardian_identity.is_some()
            && record.target_identity.is_some();
        if no_live_processes && (prior_boot || durably_empty || kill_on_close_reconciled) {
            super::attempt_store::retire(&record.attempt_id)?;
            let _owner = super::attempt_store::PublicationGuard::acquire(&record.attempt_id)?;

            fs::remove_file(path).map_err(|error| error.to_string())?;
            remove_guardian_receipt(&record.attempt_id)?;
            continue;
        }
        let reconciled = (|| {
            if record.authorization_unix_millis.is_none() && !record.resume_attempted {
                record.begin_preauthorization_abort()?;
            } else {
                if record.state != WindowsAttemptStateV1::Terminating {
                    record.transition(WindowsAttemptStateV1::Terminating)?;
                }
                record.cleanup_state.termination_requested = true;
                record.store()?;
            }
            while Instant::now() < deadline && record_has_live_process(&record)? {
                std::thread::sleep(Duration::from_millis(100));
            }
            if record_has_live_process(&record)? {
                Err(format!(
                    "guardian authority for live attempt {} did not retire",
                    record.attempt_id
                ))
            } else {
                let receipt = read_guardian_receipt(&record.attempt_id)?;
                if receipt.termination_requested
                    && receipt.native_job_query_succeeded
                    && receipt.active_processes_zero_observed
                    && guardian_receipt_binds_record(&receipt, &record)?
                {
                    record.cleanup_state.termination_requested = true;
                    record.cleanup_state.active_processes_zero = true;
                    record.cleanup_state.guardian_reaped = true;
                    record.store()?;
                    Ok(())
                } else {
                    Err(format!(
                        "guardian authority for attempt {} did not durably prove Job zero",
                        record.attempt_id
                    ))
                }
            }
        })();
        if let Err(error) = reconciled {
            let quarantined = quarantine(&path)?;
            ambiguous.push(format!("{} ({error})", quarantined.to_string_lossy(),));
            continue;
        }
        super::attempt_store::retire(&record.attempt_id)?;
        let _owner = super::attempt_store::PublicationGuard::acquire(&record.attempt_id)?;

        fs::remove_file(path).map_err(|error| error.to_string())?;
        remove_guardian_receipt(&record.attempt_id)?;
    }
    for entry in fs::read_dir(replay_root()).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let bytes = read_record_bounded_with_limit(
            &entry.path(),
            memcordon_core::WINDOWS_MAX_TERMINAL_FRAME_BYTES,
        )
        .map_err(|error| error.to_string())?;
        let replay: ReplayRecordV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if replay
            .acknowledged
            .as_ref()
            .is_some_and(|tombstone| !tombstone.retirement_complete)
        {
            if let Err(error) =
                recover_incomplete_ack_tombstone(&replay.attempt_id, &replay.request_sha256)
            {
                ambiguous.push(format!(
                    "incomplete ACK tombstone {}: {error}",
                    replay.attempt_id
                ));
            }
        }
    }
    stage(Stage::FinalAmbiguity);
    if ambiguous.is_empty() {
        Ok(())
    } else {
        Err(PackageCleanupError::Ambiguous(format!(
            "quarantined records: {}",
            ambiguous.join(", ")
        )))
    }
}

pub fn attempts_empty() -> Result<bool, String> {
    Ok(directory_empty(&attempts_root())?
        && directory_empty(&admissions_root())?
        && directory_empty(&quarantine_root())?
        && directory_empty(&guardian_receipts_root())?)
}

pub fn admissions_empty() -> Result<bool, String> {
    directory_empty(&admissions_root())
}

pub fn recovery_clear() -> Result<bool, String> {
    directory_empty(&quarantine_root())
}

pub fn certify_machine_restart_recovery() -> Result<bool, String> {
    if !attempts_empty()? {
        return Err("machine-restart recovery fixture requires idle provider state".to_owned());
    }
    let nonce = format!(
        "machine-restart-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos()
    );
    let attempt_id = digest(nonce.as_bytes());
    let request_sha256 = digest(attempt_id.as_bytes());
    let caller = super::process::process_identity(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })?;
    let mut record = WindowsAttemptRecordV1::new(
        attempt_id.clone(),
        request_sha256,
        caller,
        digest(b"machine-restart-token"),
        digest(b"machine-restart-job"),
    )?;
    record.boot_identity = digest(b"certified-prior-native-boot");
    record.store()?;
    recover()?;
    Ok(!record_path(&attempt_id)?.exists() && attempts_empty()?)
}

pub fn remove_empty_attempt_state() -> Result<(), PackageCleanupError> {
    if !attempts_empty()? {
        return Err(PackageCleanupError::Active(
            "attempt state is not empty".to_owned(),
        ));
    }
    require_empty_guardian_slot_state()?;
    // The replay ledger is intentionally not active-attempt state: completed
    // attempts remain replay-protected for the lifetime of an installation.
    // It is retired only by this authenticated, idle package-cleanup path.
    if replay_retiring_root().exists() {
        return Err("replay ledger retirement is already in progress"
            .to_owned()
            .into());
    }
    if replay_root().exists() {
        validate_replay_directory(&replay_root())?;
        fs::rename(replay_root(), replay_retiring_root()).map_err(|error| error.to_string())?;
        retire_detached_replay()?;
    }
    remove_empty_guardian_slot_state()?;
    for directory in [
        attempts_root(),
        admissions_root(),
        quarantine_root(),
        guardian_receipts_root(),
    ] {
        fs::remove_dir(directory).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn remove_empty_guardian_slot_state() -> Result<(), String> {
    inspect_guardian_slot_state(true)
}

fn require_empty_guardian_slot_state() -> Result<(), String> {
    inspect_guardian_slot_state(false)
}

fn inspect_guardian_slot_state(remove: bool) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;

    const RESIDUAL_LIMIT: usize = 16;

    let path = package::state_root().join("guardian-slots");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=inspect-guardian-slots path={} error={error}",
                path.display()
            ));
        }
    };
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!(
            "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=inspect-guardian-slots path={} expected=directory actual=reparse",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=inspect-guardian-slots path={} expected=directory actual=non-directory",
            path.display()
        ));
    }

    let mut residuals = Vec::new();
    let mut truncated = false;
    for entry in fs::read_dir(&path).map_err(|error| {
        format!(
            "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=enumerate-guardian-slots path={} error={error}",
            path.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=enumerate-guardian-slots path={} error={error}",
                path.display()
            )
        })?;
        if residuals.len() == RESIDUAL_LIMIT {
            truncated = true;
            break;
        }
        let entry_path = entry.path();
        let actual = match fs::symlink_metadata(&entry_path) {
            Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                "reparse"
            }
            Ok(metadata) if metadata.is_file() => "file",
            Ok(metadata) if metadata.is_dir() => "directory",
            Ok(_) => "other",
            Err(_) => "unreadable",
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        let artifact = guardian_slot_lease_artifact(&name);
        residuals.push(format!(
            "entry={name:?},actual={actual},artifact={artifact}"
        ));
    }
    residuals.sort();
    if !residuals.is_empty() {
        return Err(format!(
            "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=retire-guardian-slots path={} residual_count_at_least={} truncated={truncated} residuals=[{}]",
            path.display(),
            residuals.len(),
            residuals.join("; ")
        ));
    }
    if remove {
        fs::remove_dir(&path).map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-PACKAGE-ACTIVE: phase=remove-guardian-slots path={} error={error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn guardian_slot_lease_artifact(name: &str) -> &'static str {
    let (index, suffix, artifact) = if let Some(index) = name.strip_suffix(".json.new") {
        (index, ".json.new", "GuardianSlotLeaseStaged")
    } else if let Some(index) = name.strip_suffix(".json") {
        (index, ".json", "GuardianSlotLease")
    } else {
        return "Unknown";
    };
    match index.parse::<usize>() {
        Ok(value)
            if value < memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT
                && name == format!("{value:03}{suffix}") =>
        {
            artifact
        }
        _ => "Unknown",
    }
}

/// Completes a package-cleanup replay retirement that was atomically detached
/// before a control/package process crash. While the detached directory
/// exists, the required live `replay/` root is absent and every launch fails
/// closed in `reharden_attempt_state`.
pub fn recover_detached_replay() -> Result<(), String> {
    if !replay_retiring_root().exists() {
        return Ok(());
    }
    validate_replay_directory(&replay_retiring_root())?;
    retire_detached_replay()
}

/// Restores the fixed runtime skeleton after an authenticated package cleanup
/// was interrupted. This runs only inside the control service, whose service
/// SID carries the authority to create children beneath the sealed root.
pub fn reconcile_attempt_state() -> Result<(), String> {
    recover_detached_replay()?;
    for directory in [
        attempts_root(),
        admissions_root(),
        quarantine_root(),
        guardian_receipts_root(),
        replay_root(),
    ] {
        if !directory.exists() {
            fs::create_dir(&directory).map_err(|error| {
                format!(
                    "MCSEALED-WINDOWS-STATE-RECONCILE: cannot restore {}: {error}",
                    directory.display()
                )
            })?;
        }
    }
    reharden_attempt_state()
}

fn retire_detached_replay() -> Result<(), String> {
    for entry in fs::read_dir(replay_retiring_root()).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
    }
    fs::remove_dir(replay_retiring_root()).map_err(|error| error.to_string())
}

fn validate_replay_directory(path: &Path) -> Result<(), String> {
    for entry in fs::read_dir(path).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if !entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err("replay ledger contains a non-file entry".to_owned());
        }
        let bytes = fs::read(entry.path()).map_err(|error| error.to_string())?;
        let replay: ReplayRecordV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        validate_attempt_id(&replay.attempt_id)?;
        validate_attempt_id(&replay.request_sha256)?;
        if let Some(tombstone) = replay.acknowledged.as_ref() {
            if tombstone.schema_version != 1
                || tombstone.provider_generation.is_empty()
                || tombstone.launch_incarnation.is_empty()
                || tombstone.original_boot_id.is_empty()
                || validate_attempt_id(&tombstone.proof_sha256).is_err()
                || validate_attempt_id(&tombstone.job_identity).is_err()
                || !tombstone.authority_is_consistent()
                || validate_attempt_id(&tombstone.ledger_generation).is_err()
                || tombstone.caller_process_identity.process_id == 0
                || tombstone.caller_process_identity.creation_time_100ns == 0
                || validate_attempt_id(&tombstone.caller_token_sha256).is_err()
                || !tombstone.recovery_authorization.is_consistent()
                || !tombstone.retired.is_consistent_for(
                    &replay.attempt_id,
                    &tombstone.retired.nonce,
                    &replay.request_sha256,
                    &tombstone.retired.terminal_response_sha256,
                )
            {
                return Err("replay terminal ACK tombstone is not bound".to_owned());
            }
        }
        let expected_name = format!("{}.json", replay.attempt_id);
        if entry.file_name() != std::ffi::OsStr::new(&expected_name) {
            return Err("replay ledger filename does not match its attempt id".to_owned());
        }
    }
    Ok(())
}

pub fn reharden_attempt_state() -> Result<(), String> {
    let launcher_sddl = super::security::launcher_state_sddl()?;
    for directory in [attempts_root(), quarantine_root(), guardian_receipts_root()] {
        if !directory.exists() {
            return Err(format!(
                "MCSEALED-WINDOWS-STATE-CONVERGENCE: runtime attempt-state directory is absent: {}",
                directory.display()
            ));
        }
        converge_directory_security(&directory, &launcher_sddl, "runtime attempt state")?;
    }
    let replay_path = replay_root();
    if !replay_path.exists() {
        return Err(format!(
            "MCSEALED-WINDOWS-STATE-CONVERGENCE: runtime replay directory is absent: {}",
            replay_path.display()
        ));
    }
    let replay_sddl = super::security::replay_state_sddl()?;
    converge_directory_security(&replay_path, &replay_sddl, "runtime replay state")?;
    let admission_path = admissions_root();
    if !admission_path.exists() {
        return Err(format!(
            "MCSEALED-WINDOWS-STATE-CONVERGENCE: runtime admission directory is absent: {}",
            admission_path.display()
        ));
    }
    let admission_sddl = super::security::admission_state_sddl()?;
    converge_directory_security(&admission_path, &admission_sddl, "runtime admission state")
}

fn converge_directory_security(path: &Path, sddl: &str, phase: &str) -> Result<(), String> {
    let dacl = sddl
        .strip_prefix("O:BA")
        .ok_or_else(|| format!("{phase} policy is missing its fixed owner"))?;
    let expected = super::security::SecurityDescriptor::from_sddl(sddl)?;
    let applied = super::security::SecurityDescriptor::from_sddl(dacl)?;
    expected.converge_path(&applied, path).map_err(|error| {
        format!(
            "MCSEALED-WINDOWS-STATE-CONVERGENCE: {phase} at {}: {error}",
            path.display()
        )
    })
}

pub struct AdmissionLease {
    path: PathBuf,
}

#[derive(Deserialize, Serialize)]
enum AdmissionRecordFormat {
    #[serde(rename = "memcordon.windows-admission-record")]
    Native,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(try_from = "u32", into = "u32")]
struct AdmissionRecordRevision;

impl TryFrom<u32> for AdmissionRecordRevision {
    type Error = &'static str;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 1 {
            Ok(Self)
        } else {
            Err("unsupported native admission record revision")
        }
    }
}

impl From<AdmissionRecordRevision> for u32 {
    fn from(_: AdmissionRecordRevision) -> Self {
        1
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRecordV1 {
    format: AdmissionRecordFormat,
    revision: AdmissionRecordRevision,
    attempt_id: String,
    request_sha256: String,
    owner_process_identities: Vec<memcordon_core::WindowsProcessIdentityV1>,
    workload_reservation: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReplayRecordV1 {
    attempt_id: String,
    request_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acknowledged: Option<TerminalAckTombstoneV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalAckTombstoneV1 {
    schema_version: u32,
    retired: memcordon_core::WindowsRetirementMetadata,
    provider_generation: String,
    launch_incarnation: String,
    original_boot_id: String,
    proof_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preauthorization_retirement_proof:
        Option<memcordon_core::WindowsPreauthorizationRetirementProofV1>,
    job_identity: String,
    owner_manifest_sha256: String,
    ledger_generation: String,
    retirement_complete: bool,
    caller_process_identity: memcordon_core::WindowsProcessIdentityV1,
    caller_token_sha256: String,
    recovery_authorization: memcordon_core::WindowsRecoveryAuthorizationV1,
}

impl TerminalAckTombstoneV1 {
    fn authority_is_consistent(&self) -> bool {
        match (
            &self.retired.disposition,
            &self.preauthorization_retirement_proof,
        ) {
            (
                disposition @ WindowsAttemptTerminalDispositionV1::PrematureReleaseFailure {
                    ..
                },
                None,
            ) => {
                disposition.premature_release_mutant().is_some()
                    && validate_attempt_id(&self.owner_manifest_sha256).is_ok()
                    && validate_attempt_id(&self.proof_sha256).is_ok()
            }
            (WindowsAttemptTerminalDispositionV1::Posttarget, None) => {
                validate_attempt_id(&self.owner_manifest_sha256).is_ok()
            }
            (WindowsAttemptTerminalDispositionV1::PreauthorizationAbort, Some(proof)) => {
                self.owner_manifest_sha256.is_empty()
                    && proof.is_consistent()
                    && proof.attempt_id == self.retired.attempt_id
                    && proof.nonce == self.retired.nonce
                    && proof.request_sha256 == self.retired.request_sha256
                    && proof.terminal_response_sha256 == self.retired.terminal_response_sha256
                    && proof.provider_generation == self.provider_generation
                    && proof.original_boot_id == self.original_boot_id
                    && proof.launch_incarnation == self.launch_incarnation
                    && proof.job_identity == self.job_identity
                    && proof
                        .canonical_sha256()
                        .is_ok_and(|digest| digest == self.proof_sha256)
            }
            _ => false,
        }
    }
}

impl Drop for AdmissionLease {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn reserve_admission(attempt_id: &str, request_sha256: &str) -> Result<AdmissionLease, String> {
    validate_attempt_id(attempt_id)?;
    validate_attempt_id(request_sha256)?;
    sweep_expired_diagnostics()?;
    let _budget = super::attempt_store::PublicationGuard::acquire(&digest(
        b"installation-attempt-storage-budget-v1",
    ))?;
    enforce_storage_reservation(Some(attempt_id), false)?;
    fs::create_dir_all(admissions_root()).map_err(|error| error.to_string())?;
    let path = admissions_root().join(format!("{attempt_id}.json"));
    let mut bytes = serde_json::to_vec(&AdmissionRecordV1 {
        format: AdmissionRecordFormat::Native,
        revision: Default::default(),
        attempt_id: attempt_id.to_owned(),
        request_sha256: request_sha256.to_owned(),
        workload_reservation: true,
        owner_process_identities: Vec::new(),
    })
    .map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, &bytes))
        .map_err(|error| error.to_string())?;
    Ok(AdmissionLease { path })
}

fn sweep_expired_diagnostics() -> Result<(), String> {
    if !attempts_root().exists() {
        return Ok(());
    }
    for entry in fs::read_dir(attempts_root()).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        if reserved_writer_stage(&path, &admissions_root())? {
            continue;
        }
        let attempt_id = record_attempt_id(&path)?;
        let _reader = RecordReaderReservation::acquire(&attempt_id, &attempt_id)?;
        let bytes = read_record_bounded(&path).map_err(|error| error.to_string())?;
        let mut record: WindowsAttemptRecordV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        drop(bytes);
        authenticate(&record, &attempt_id)?;
        if record.diagnostic_retention.tombstone.is_some()
            || diagnostic_export_eligible(&record)
            || record.state != WindowsAttemptStateV1::Empty
        {
            continue;
        }
        record.causal_diagnostics = exportable_journal(&record);
        record.diagnostic_retention.tombstone =
            Some(memcordon_core::OriginalUnavailableReasonV1::RetentionExpired);
        record.store()?;
        super::attempt_store::retire(&attempt_id)?;
    }
    Ok(())
}

fn enforce_storage_reservation(
    reserving_attempt_id: Option<&str>,
    reserving_reader: bool,
) -> Result<(), String> {
    const RECORD_STATE_BUDGET: u64 = 128 * 1024 * 1024;
    const IMAGES_PER_ACTIVE_ATTEMPT: u64 = 5;
    let record_bound = memcordon_core::WINDOWS_MAX_FRAME_BYTES as u64;
    let mut reserved = if reserving_reader {
        3 * record_bound
    } else {
        0
    };
    let mut active = std::collections::BTreeSet::new();
    if admissions_root().exists() {
        for entry in fs::read_dir(admissions_root()).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let bytes = read_record_bounded_with_limit(&entry.path(), 4096)
                .map_err(|error| error.to_string())?;
            let admission: AdmissionRecordV1 =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            if entry
                .path()
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".reader.json"))
            {
                reserved += 3 * record_bound;
            }
            if admission.workload_reservation && active.insert(admission.attempt_id) {
                reserved = reserved
                    .checked_add(record_bound * IMAGES_PER_ACTIVE_ATTEMPT)
                    .ok_or_else(|| "attempt storage reservation overflow".to_owned())?;
            }
            if reserved > RECORD_STATE_BUDGET {
                return Err("installation attempt storage reservation exhausted".to_owned());
            }
        }
    }
    if reserving_attempt_id.is_some_and(|attempt| active.insert(attempt.to_owned())) {
        reserved = reserved
            .checked_add(record_bound * IMAGES_PER_ACTIVE_ATTEMPT)
            .ok_or_else(|| "attempt storage reservation overflow".to_owned())?;
    }
    if reserved > RECORD_STATE_BUDGET {
        return Err("installation attempt storage reservation exhausted".to_owned());
    }
    let mut retained_payloads = active.len();
    let mut retained_payload_bytes =
        retained_payloads * memcordon_core::MAX_DIAGNOSTIC_JOURNAL_BYTES;
    for root in [attempts_root(), quarantine_root()] {
        if !root.exists() {
            continue;
        }
        for entry in fs::read_dir(&root).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            if root == attempts_root() && reserved_writer_stage(&entry.path(), &admissions_root())?
            {
                let path = entry.path();
                let identity = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_suffix(".json.new"))
                    .ok_or("validated writer stage lost its exact filename")?;
                if !active.contains(identity) {
                    return Err("staged attempt has no charged active reservation".to_owned());
                }
                // The validated writer admission already charges all five
                // active images; a staging image grants no terminal authority.
                continue;
            }
            let identity = record_attempt_id(&entry.path())?;
            if !active.contains(&identity) {
                let metadata = entry.metadata().map_err(|error| error.to_string())?;
                if !metadata.is_file() || metadata.len() > record_bound {
                    return Err("retained record exceeds authenticated record bound".to_owned());
                }
                reserved = reserved
                    .checked_add(metadata.len())
                    .ok_or_else(|| "attempt storage reservation overflow".to_owned())?;
                // Reservation scans never decode a full retained record while
                // another reader/writer owns the installation heap budget.
                // Tombstones retain this conservative small payload slot until
                // the existing terminal authority permits record retirement.
                retained_payloads += 1;
                retained_payload_bytes += memcordon_core::MAX_DIAGNOSTIC_JOURNAL_BYTES;
            }
            if reserved > RECORD_STATE_BUDGET
                || retained_payloads > memcordon_core::MAX_RETAINED_DIAGNOSTIC_PAYLOADS
                || retained_payload_bytes > memcordon_core::MAX_RETAINED_DIAGNOSTIC_PAYLOAD_BYTES
            {
                return Err("installation retained attempt storage exhausted".to_owned());
            }
        }
    }
    Ok(())
}

pub fn reserve_attempt(attempt_id: &str, request_sha256: &str) -> Result<(), String> {
    validate_attempt_id(attempt_id)?;
    validate_attempt_id(request_sha256)?;
    fs::create_dir_all(replay_root()).map_err(|error| error.to_string())?;
    let path = replay_root().join(format!("{attempt_id}.json"));
    let mut bytes = serde_json::to_vec(&ReplayRecordV1 {
        attempt_id: attempt_id.to_owned(),
        request_sha256: request_sha256.to_owned(),
        acknowledged: None,
    })
    .map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, &bytes))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "MCSEALED-WINDOWS-REPLAY: attempt id or nonce was already consumed".to_owned()
            } else {
                error.to_string()
            }
        })
}

fn replay_record(
    attempt_id: &str,
    request_sha256: &str,
) -> Result<(PathBuf, ReplayRecordV1), String> {
    validate_attempt_id(attempt_id)?;
    validate_attempt_id(request_sha256)?;
    super::security::SecurityDescriptor::from_sddl(&super::security::replay_state_sddl()?)?
        .verify_path(&replay_root())?;
    let path = replay_root().join(format!("{attempt_id}.json"));
    let staged = path.with_extension("json.new");
    if staged.exists() {
        let prior_bytes =
            read_record_bounded_with_limit(&path, memcordon_core::WINDOWS_MAX_TERMINAL_FRAME_BYTES)
                .map_err(|error| error.to_string())?;
        let prior: ReplayRecordV1 =
            serde_json::from_slice(&prior_bytes).map_err(|error| error.to_string())?;
        let staged_bytes = read_record_bounded_with_limit(
            &staged,
            memcordon_core::WINDOWS_MAX_TERMINAL_FRAME_BYTES,
        )
        .map_err(|error| error.to_string())?;
        let next: ReplayRecordV1 =
            serde_json::from_slice(&staged_bytes).map_err(|error| error.to_string())?;
        if prior.attempt_id != attempt_id
            || prior.request_sha256 != request_sha256
            || next.attempt_id != attempt_id
            || next.request_sha256 != request_sha256
            || !match (&prior.acknowledged, &next.acknowledged) {
                (None, Some(next)) => !next.retirement_complete,
                (Some(prior), Some(next)) => {
                    !prior.retirement_complete
                        && next.retirement_complete
                        && TerminalAckTombstoneV1 {
                            retirement_complete: false,
                            ..next.clone()
                        } == *prior
                }
                _ => false,
            }
        {
            return Err("staged ACK tombstone conflicts with replay ledger".to_owned());
        }
        replace_atomically(&staged, &path)?;
    }
    let bytes =
        read_record_bounded_with_limit(&path, memcordon_core::WINDOWS_MAX_TERMINAL_FRAME_BYTES)
            .map_err(|error| error.to_string())?;
    let replay: ReplayRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if replay.attempt_id != attempt_id || replay.request_sha256 != request_sha256 {
        return Err("replay record is not bound to the acknowledged attempt".to_owned());
    }
    if replay
        .acknowledged
        .as_ref()
        .is_some_and(|tombstone| !tombstone.authority_is_consistent())
    {
        return Err("replay ACK retirement authority is inconsistent".to_owned());
    }
    Ok((path, replay))
}

fn recover_staged_ack_tombstones() -> Result<(), String> {
    for entry in fs::read_dir(replay_root()).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| "replay ledger filename is not UTF-8".to_owned())?;
        let Some(attempt_id) = name.strip_suffix(".json.new") else {
            continue;
        };
        validate_attempt_id(attempt_id)?;
        let bytes = read_record_bounded_with_limit(
            &entry.path(),
            memcordon_core::WINDOWS_MAX_TERMINAL_FRAME_BYTES,
        )
        .map_err(|error| error.to_string())?;
        let staged: ReplayRecordV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if staged.attempt_id != attempt_id || staged.acknowledged.is_none() {
            return Err("staged ACK tombstone lacks exact attempt binding".to_owned());
        }
        replay_record(attempt_id, &staged.request_sha256)?;
    }
    Ok(())
}

fn stage_ack_tombstone(
    record: &WindowsAttemptRecordV1,
    tombstone: TerminalAckTombstoneV1,
) -> Result<(), String> {
    let (path, replay) = replay_record(&record.attempt_id, &record.request_sha256)?;
    stage_ack_tombstone_at(record, tombstone, &path, replay)?;
    let (_, committed) = replay_record(&record.attempt_id, &record.request_sha256)?;
    if committed.acknowledged.is_none() {
        return Err("ACK tombstone readback is absent".to_owned());
    }
    Ok(())
}

fn stage_ack_tombstone_at(
    record: &WindowsAttemptRecordV1,
    tombstone: TerminalAckTombstoneV1,
    path: &Path,
    mut replay: ReplayRecordV1,
) -> Result<(), String> {
    if replay.attempt_id != record.attempt_id || replay.request_sha256 != record.request_sha256 {
        return Err("replay record is not bound to the acknowledged attempt".to_owned());
    }
    if let Some(existing) = replay.acknowledged.as_ref() {
        if existing.retired != tombstone.retired
            || existing.proof_sha256 != tombstone.proof_sha256
            || existing.preauthorization_retirement_proof
                != tombstone.preauthorization_retirement_proof
            || existing.launch_incarnation != tombstone.launch_incarnation
            || existing.caller_process_identity != tombstone.caller_process_identity
            || existing.caller_token_sha256 != tombstone.caller_token_sha256
            || existing.recovery_authorization != tombstone.recovery_authorization
            || existing.job_identity != tombstone.job_identity
            || existing.owner_manifest_sha256 != tombstone.owner_manifest_sha256
            || existing.ledger_generation != tombstone.ledger_generation
        {
            return Err("ACK tombstone conflicts with prior terminal authority".to_owned());
        }
        return Ok(());
    }
    replay.acknowledged = Some(tombstone);
    publish_replay_record_at(path, &replay)
}

fn ack_tombstone_for(
    record: &WindowsAttemptRecordV1,
    retired: &memcordon_core::WindowsRetirementMetadata,
) -> Result<TerminalAckTombstoneV1, String> {
    let preauthorization_retirement_proof = if retired.disposition
        == WindowsAttemptTerminalDispositionV1::PreauthorizationAbort
    {
        if record.authorization_unix_millis.is_some()
            || record.resume_attempted
            || record.target_released
            || record.state != WindowsAttemptStateV1::Empty
            || record.retirement_proof.is_some()
            || record.terminal_seed.is_some()
            || record.terminal_disposition
                != Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort)
        {
            return Err(
                "preauthorization ACK conflicts with durable execution authority".to_owned(),
            );
        }
        let response: memcordon_core::WindowsLauncherResponseV4 = serde_json::from_str(
            record
                .terminal_response_json
                .as_deref()
                .ok_or("preauthorization ACK has no original outbox")?,
        )
        .map_err(|error| error.to_string())?;
        if !memcordon_core::windows_terminal_outbox_is_bound_v4(&decoded_v4(record), &response) {
            return Err("preauthorization ACK outbox is not bound".to_owned());
        }
        let memcordon_core::WindowsLauncherResponseV4::Reject { rejection, .. } = response else {
            return Err("preauthorization ACK requires original rejection".to_owned());
        };
        if !matches!(
            rejection.disposition,
            memcordon_core::WindowsProviderRejectionDispositionV3::Preauthorization {
                terminal_ack_required: true
            }
        ) || !rejection.cleanup_attempted
            || rejection.target_released
            || !rejection.restart_safety.containment_removed
            || !rejection
                .restart_safety
                .containment_incapable_of_live_members
            || !rejection
                .restart_safety
                .is_safe_for(memcordon_core::BoundaryRequirement::Sealed)
            || record_has_live_process(record)?
        {
            return Err(
                "preauthorization ACK lacks checked owner extinction and cleanup".to_owned(),
            );
        }
        let proof = memcordon_core::WindowsPreauthorizationRetirementProofV1 {
            schema_version: 1,
            attempt_id: record.attempt_id.clone(),
            nonce: record.nonce.clone(),
            request_sha256: record.request_sha256.clone(),
            provider_generation: record.provider_generation.clone(),
            original_boot_id: record.boot_identity.clone(),
            launch_incarnation: record.launch_incarnation.clone(),
            job_identity: record.job_identity_sha256.clone(),
            terminal_response_sha256: retired.terminal_response_sha256.clone(),
            target_identity: record.target_identity.clone(),
            guardian_identity: record.guardian_identity.clone(),
            worker_identity: record.worker_identity.clone(),
            worker_thread_identity: record.worker_thread_identity,
            frozen_owner_manifest_sha256: record
                .owner_manifest
                .as_ref()
                .map(|manifest| manifest.canonical_sha256())
                .transpose()
                .map_err(str::to_owned)?,
            target_created: rejection.target_created,
            authorization_unix_millis: record.authorization_unix_millis,
            resume_attempted: record.resume_attempted,
            target_released: record.target_released,
            cleanup_state: memcordon_core::WindowsDurableCleanupStateV1 {
                termination_requested: record.cleanup_state.termination_requested,
                active_processes_zero: record.cleanup_state.active_processes_zero,
                guardian_reaped: record.cleanup_state.guardian_reaped,
                final_handles_closed: record.cleanup_state.final_handles_closed,
            },
            recorded_target_and_guardian_extinct: true,
        };
        if !proof.is_consistent() {
            return Err("preauthorization ACK proof is inconsistent".to_owned());
        }
        Some(proof)
    } else {
        None
    };
    let (proof_sha256, owner_manifest_sha256) = if let Some(proof) =
        preauthorization_retirement_proof.as_ref()
    {
        (
            proof
                .canonical_sha256()
                .map_err(|error| error.to_string())?,
            String::new(),
        )
    } else {
        let proof = record
            .retirement_proof
            .as_ref()
            .ok_or_else(|| "ACK tombstone requires checked retirement proof".to_owned())?;
        let proof_sha256 = digest(&serde_json::to_vec(proof).map_err(|error| error.to_string())?);
        let owner_manifest_sha256 = record
            .owner_manifest
            .as_ref()
            .ok_or_else(|| "ACK tombstone requires frozen owner manifest".to_owned())?
            .canonical_sha256()
            .map_err(str::to_owned)?;
        (proof_sha256, owner_manifest_sha256)
    };
    let ledger_generation = digest(
        &serde_json::to_vec(&(
            &record.attempt_id,
            &record.provider_generation,
            &record.launch_incarnation,
            &proof_sha256,
        ))
        .map_err(|error| error.to_string())?,
    );
    Ok(TerminalAckTombstoneV1 {
        schema_version: 1,
        retired: retired.clone(),
        provider_generation: record.provider_generation.clone(),
        launch_incarnation: record.launch_incarnation.clone(),
        original_boot_id: record.boot_identity.clone(),
        proof_sha256,
        preauthorization_retirement_proof,
        job_identity: record.job_identity_sha256.clone(),
        owner_manifest_sha256,
        ledger_generation,
        retirement_complete: false,
        caller_process_identity: record.caller_process_identity.clone(),
        caller_token_sha256: record.caller_token_sha256.clone(),
        recovery_authorization: record
            .recovery_authorization
            .clone()
            .ok_or_else(|| "ACK tombstone has no admitted recovery authorization".to_owned())?,
    })
}

fn publish_replay_record_at(path: &Path, replay: &ReplayRecordV1) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(replay).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let staged = path.with_extension("json.new");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .map_err(|error| error.to_string())?;
    use std::io::Write;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    replace_atomically(&staged, path)?;
    if read_record_bounded(path).map_err(|error| error.to_string())? != bytes {
        return Err("replay publication named readback differs".to_owned());
    }
    Ok(())
}

fn complete_ack_tombstone(
    attempt_id: &str,
    request_sha256: &str,
) -> Result<memcordon_core::WindowsTerminalRetiredV2, String> {
    if record_path(attempt_id)?.exists() || guardian_receipts_root().join(attempt_id).exists() {
        return Err(
            "ACK tombstone completion still has active record or guardian receipt".to_owned(),
        );
    }
    let (path, mut replay) = replay_record(attempt_id, request_sha256)?;
    let tombstone = replay
        .acknowledged
        .as_mut()
        .ok_or_else(|| "ACK tombstone completion has no committed ACK".to_owned())?;
    if !tombstone.retirement_complete {
        tombstone.retirement_complete = true;
        publish_replay_record_at(&path, &replay)?;
    }
    let (_, committed) = replay_record(attempt_id, request_sha256)?;
    let tombstone = committed
        .acknowledged
        .ok_or_else(|| "completed ACK tombstone readback is absent".to_owned())?;
    if !tombstone.retirement_complete {
        return Err("ACK tombstone completion did not survive readback".to_owned());
    }
    retired_from_ack_tombstone(tombstone, attempt_id, request_sha256)
}

fn retired_from_ack_tombstone(
    tombstone: TerminalAckTombstoneV1,
    attempt_id: &str,
    request_sha256: &str,
) -> Result<memcordon_core::WindowsTerminalRetiredV2, String> {
    if !tombstone.retirement_complete {
        return Err("ACK tombstone completion did not survive readback".to_owned());
    }
    let retired = memcordon_core::WindowsTerminalRetiredV2 {
        schema_version: 2,
        attempt_id: tombstone.retired.attempt_id,
        nonce: tombstone.retired.nonce,
        request_sha256: tombstone.retired.request_sha256,
        terminal_response_sha256: tombstone.retired.terminal_response_sha256,
        disposition: tombstone.retired.disposition,
        provider_generation: tombstone.provider_generation,
        original_boot_id: tombstone.original_boot_id,
        launch_incarnation: tombstone.launch_incarnation,
        job_identity: tombstone.job_identity,
        owner_manifest_sha256: tombstone.owner_manifest_sha256,
        retirement_proof_sha256: tombstone.proof_sha256,
        preauthorization_retirement_proof: tombstone.preauthorization_retirement_proof,
        ledger_generation: tombstone.ledger_generation,
        completion: memcordon_core::WindowsRetirementLedgerCompletionV1::RetirementComplete,
    };
    if !retired.is_consistent_for(
        attempt_id,
        &retired.nonce,
        request_sha256,
        &retired.terminal_response_sha256,
    ) {
        return Err("completed ACK tombstone does not bind V2 retirement".to_owned());
    }
    Ok(retired)
}

fn recover_incomplete_ack_tombstone(
    attempt_id: &str,
    request_sha256: &str,
) -> Result<memcordon_core::WindowsTerminalRetiredV2, String> {
    let (_, replay) = replay_record(attempt_id, request_sha256)?;
    let tombstone = replay
        .acknowledged
        .ok_or_else(|| "terminal acknowledgment has no ACK tombstone".to_owned())?;
    if !tombstone.retirement_complete {
        if record_path(attempt_id)?.exists() {
            return Err("ACK tombstone still has a durable attempt record".to_owned());
        }
        remove_guardian_receipt(attempt_id)?;
        super::attempt_store::retire(attempt_id)?;
    }
    complete_ack_tombstone(attempt_id, request_sha256)
}

pub fn acknowledged_terminal_from_tombstone(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    caller_process_identity: &memcordon_core::WindowsProcessIdentityV1,
    caller_token_sha256: &str,
) -> Result<Option<memcordon_core::WindowsTerminalRetiredV2>, String> {
    let (_, replay) = replay_record(attempt_id, request_sha256)?;
    let Some(tombstone) = replay.acknowledged else {
        return Ok(None);
    };
    validate_ack_replay_caller(
        &tombstone,
        attempt_id,
        nonce,
        request_sha256,
        caller_process_identity,
        caller_token_sha256,
    )?;
    Ok(Some(recover_incomplete_ack_tombstone(
        attempt_id,
        request_sha256,
    )?))
}

fn validate_ack_replay_caller(
    tombstone: &TerminalAckTombstoneV1,
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    caller_process_identity: &memcordon_core::WindowsProcessIdentityV1,
    caller_token_sha256: &str,
) -> Result<(), String> {
    if tombstone.schema_version != 1
        || tombstone.caller_process_identity != *caller_process_identity
        || tombstone.caller_token_sha256 != caller_token_sha256
        || tombstone.retired.nonce != nonce
        || !tombstone.retired.is_consistent_for(
            attempt_id,
            nonce,
            request_sha256,
            &tombstone.retired.terminal_response_sha256,
        )
    {
        return Err("terminal ACK tombstone does not match authenticated replay caller".to_owned());
    }
    Ok(())
}

/// Owned component fixture only: no installation roots, receipts or references.
#[cfg(test)]
pub(crate) fn stage_owned_component_ack_for_test(
    path: &Path,
    record: &WindowsAttemptRecordV1,
) -> Result<(), String> {
    owned_component_admission_root(path.parent().ok_or("owned replay parent absent")?)?;
    let replay = if path.exists() {
        serde_json::from_slice::<ReplayRecordV1>(
            &read_record_bounded(path).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?
    } else {
        ReplayRecordV1 {
            attempt_id: record.attempt_id.clone(),
            request_sha256: record.request_sha256.clone(),
            acknowledged: None,
        }
    };
    let retired = record.terminal_retired_receipt(&record.nonce)?;
    stage_ack_tombstone_at(record, ack_tombstone_for(record, &retired)?, path, replay)
}

#[cfg(test)]
pub(crate) fn complete_owned_component_ack_for_test(
    path: &Path,
    outbox: &Path,
    record: &WindowsAttemptRecordV1,
    nonce: &str,
    caller: &memcordon_core::WindowsProcessIdentityV1,
    token: &str,
) -> Result<memcordon_core::WindowsTerminalRetiredV2, String> {
    owned_component_admission_root(path.parent().ok_or("owned replay parent absent")?)?;
    if outbox.parent() != path.parent() || outbox.exists() {
        return Err("ACK tombstone still has a durable attempt record".to_owned());
    }
    let mut replay: ReplayRecordV1 =
        serde_json::from_slice(&read_record_bounded(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if replay.attempt_id != record.attempt_id || replay.request_sha256 != record.request_sha256 {
        return Err("replay record is not bound to the acknowledged attempt".to_owned());
    }
    let tombstone = replay
        .acknowledged
        .as_ref()
        .ok_or("terminal acknowledgment has no ACK tombstone")?;
    validate_ack_replay_caller(
        tombstone,
        &record.attempt_id,
        nonce,
        &record.request_sha256,
        caller,
        token,
    )?;
    if !tombstone.retirement_complete {
        replay
            .acknowledged
            .as_mut()
            .expect("checked ACK")
            .retirement_complete = true;
        publish_replay_record_at(path, &replay)?;
    }
    let committed: ReplayRecordV1 =
        serde_json::from_slice(&read_record_bounded(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    retired_from_ack_tombstone(
        committed
            .acknowledged
            .ok_or("completed ACK tombstone readback is absent")?,
        &record.attempt_id,
        &record.request_sha256,
    )
}

pub fn recover_attempt_for_caller(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    caller: &memcordon_core::WindowsRecoveryCallerEvidenceV1,
) -> Result<Option<memcordon_core::WindowsLauncherResponseV4>, String> {
    if !caller.is_consistent() || caller.current_boot_identity != boot_identity()? {
        return Err("recovery caller does not match the trusted current boot".to_owned());
    }
    let _reader = RecordReaderReservation::acquire(attempt_id, request_sha256)?;
    let path = record_path(attempt_id)?;
    match read_record_bounded(&path) {
        Ok(bytes) => {
            let mut record: WindowsAttemptRecordV1 =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            authenticate(&record, attempt_id)?;
            if record.request_sha256 != request_sha256 || record.nonce != nonce {
                return Err("recovery request differs from durable attempt binding".to_owned());
            }
            let authorization = record.recovery_authorization.as_ref().ok_or_else(|| {
                "current attempt has no original recovery authorization".to_owned()
            })?;
            let same_boot = record.boot_identity == caller.current_boot_identity;
            if !authorization.admits_recovery(
                &caller.user_sid,
                caller.logon_identity,
                &caller.access_floor,
                same_boot,
            ) || (same_boot
                && authorization.launch_token_binding_sha256 != caller.token_binding_sha256)
            {
                return Err("recovery caller does not meet admitted owner access floor".to_owned());
            }
            if record.terminal_response_json.is_none() && record.authorization_unix_millis.is_some()
            {
                if !same_boot {
                    stage_recovered_closure(&mut record, &caller.current_boot_identity, None)?;
                } else if guardian_receipt_path(attempt_id)?.exists() {
                    let guardian = read_guardian_receipt(attempt_id)?;
                    if !guardian_receipt_binds_record(&guardian, &record)? {
                        return Err("exact recovery pending checked closure: guardian receipt does not bind original record".to_owned());
                    }
                    if let Some(blocker) = frozen_manifest_owner_blocker(&record)? {
                        return Err(format!("exact recovery pending checked closure: {blocker}"));
                    }
                    super::process::retire_handed_off_guardian(
                        attempt_id,
                        &guardian.guardian_identity,
                    )?;
                    stage_recovered_closure(
                        &mut record,
                        &caller.current_boot_identity,
                        Some(&guardian),
                    )?;
                } else {
                    if record.job_closure_contract.is_some() {
                        return Ok(None);
                    }
                    return Err(format!(
                        "exact recovery pending checked closure: guardian receipt absent on original boot; durable-state={:?}; resume-attempted={}; target-released={}; termination-requested={}; active-processes-zero={}; guardian-reaped={}; final-handles-closed={}; terminal-seed-present={}; retirement-proof-present={}; owner-manifest-present={}; terminal-publication-reserved={}; first-terminalization-error={}",
                        record.state,
                        record.resume_attempted,
                        record.target_released,
                        record.cleanup_state.termination_requested,
                        record.cleanup_state.active_processes_zero,
                        record.cleanup_state.guardian_reaped,
                        record.cleanup_state.final_handles_closed,
                        record.terminal_seed.is_some(),
                        record.retirement_proof.is_some(),
                        record.owner_manifest.is_some(),
                        record.terminal_publication_reserved,
                        recovery_terminalization_error(record.terminalization.last_error.as_ref()),
                    ));
                }
            }
            let Some(outbox) = record.terminal_response_json.as_deref() else {
                return Err(format!(
                    "exact recovery pending checked closure: terminal outbox absent; authorized={}; same-boot={same_boot}",
                    record.authorization_unix_millis.is_some()
                ));
            };
            bound_recovery_terminal_response(&record, outbox).map(Some)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (_, replay) = replay_record(attempt_id, request_sha256)?;
            let Some(tombstone) = replay.acknowledged else {
                return Err("exact recovery pending checked closure: durable attempt absent and no acknowledged tombstone".to_owned());
            };
            if tombstone.retired.nonce != nonce {
                return Err("recovery tombstone nonce differs".to_owned());
            }
            let same_boot = tombstone.original_boot_id == caller.current_boot_identity;
            if !tombstone.recovery_authorization.admits_recovery(
                &caller.user_sid,
                caller.logon_identity,
                &caller.access_floor,
                same_boot,
            ) || (same_boot
                && tombstone.recovery_authorization.launch_token_binding_sha256
                    != caller.token_binding_sha256)
            {
                return Err("recovery caller does not meet tombstone owner access floor".to_owned());
            }
            let retired = recover_incomplete_ack_tombstone(attempt_id, request_sha256)?;
            Ok(Some(
                memcordon_core::WindowsLauncherResponseV4::TerminalRetiredV2(retired),
            ))
        }
        Err(error) => Err(error.to_string()),
    }
}

fn bound_recovery_terminal_response(
    record: &WindowsAttemptRecordV1,
    outbox: &str,
) -> Result<memcordon_core::WindowsLauncherResponseV4, String> {
    let mut response: memcordon_core::WindowsLauncherResponseV4 =
        serde_json::from_str(outbox).map_err(|error| error.to_string())?;
    if !memcordon_core::windows_terminal_outbox_is_bound_v4(&decoded_v4(record), &response) {
        return Err("recovery outbox is not bound to durable attempt".to_owned());
    }
    // The immutable outbox intentionally excludes expirable diagnostics. Export
    // the authenticated record's current projection separately, as live replay
    // does, without changing terminal authority or its acknowledgement digest.
    if let memcordon_core::WindowsLauncherResponseV4::Reject { rejection, .. } = &mut response {
        rejection.provider_failure = provider_projection(Some(record)).0;
        rejection.guardian_causal_receipt = guardian_causal_projection(record)?;
    }
    Ok(response)
}

fn frozen_manifest_owners_extinct(record: &WindowsAttemptRecordV1) -> Result<bool, String> {
    frozen_manifest_owner_blocker(record).map(|blocker| blocker.is_none())
}

fn capability_extinction(
    record: &WindowsAttemptRecordV1,
) -> Result<Option<memcordon_core::WindowsCapabilityExtinctionProofV2>, String> {
    let Some(contract) = record.job_closure_contract.as_ref() else {
        return Ok(None);
    };
    contract.validate().map_err(str::to_owned)?;
    if record.boot_identity != boot_identity()? || record.authorization_unix_millis.is_none() {
        return Ok(None);
    }
    let manifest = record
        .owner_manifest
        .as_ref()
        .ok_or("closure contract manifest absent")?;
    // A dead thread cannot establish closure of handles held by a live
    // process. This proof deliberately requires every original Job holder's
    // exact process to be extinct, including the guardian transfer recipient.
    for identity in [
        record.worker_identity.as_ref(),
        record.guardian_identity.as_ref(),
        record.target_identity.as_ref(),
    ] {
        let Some(identity) = identity else {
            return Ok(None);
        };
        if process_identity_is_live(identity.clone())? {
            return Ok(None);
        }
    }
    for entry in &manifest.entries {
        if entry.role == memcordon_core::WindowsCapabilityOwnerRoleV2::DesktopBootstrapProcess
            && entry.present
        {
            let Some(identity) = entry.process_identity.as_ref() else {
                return Ok(None);
            };
            if process_identity_is_live(identity.clone())? {
                return Ok(None);
            }
        }
    }
    if !frozen_manifest_owners_extinct(record)?
        || !super::launcher_service::attempt_job_registration_is_absent(&record.attempt_id)?
    {
        return Ok(None);
    }
    let proof = memcordon_core::WindowsCapabilityExtinctionProofV2 {
        contract: contract.clone(),
        owner_manifest: manifest.clone(),
        current_boot_id: boot_identity()?,
        job_holder_processes_extinct: true,
        target_process_extinct: true,
        relay_capabilities_retired: true,
        launch_gate_closed: true,
    };
    proof.validate().map_err(str::to_owned)?;
    Ok(Some(proof))
}

fn frozen_manifest_owner_blocker(
    record: &WindowsAttemptRecordV1,
) -> Result<Option<String>, String> {
    let manifest = record
        .owner_manifest
        .as_ref()
        .ok_or_else(|| "live recovery has no frozen owner manifest".to_owned())?;
    for entry in &manifest.entries {
        if !entry.present {
            continue;
        }
        let Some(identity) = entry.process_identity.as_ref() else {
            return Ok(Some(format!(
                "frozen owner lacks process identity; role={:?}",
                entry.role
            )));
        };
        if process_identity_is_live(identity.clone())? {
            if entry.role == memcordon_core::WindowsCapabilityOwnerRoleV2::FrontendRelay
                && identity == &record.caller_process_identity
                && super::launcher_service::frontend_relay_retired_for_recovery(
                    &record.attempt_id,
                    &record.nonce,
                    &record.request_sha256,
                    &record.caller_process_identity,
                    &relay_retirement_event_name(record),
                )?
            {
                continue;
            }
            // Several native handles belong to this attempt's launcher worker,
            // rather than to every thread in the still-running service process.
            // The exact thread must have exited and its active Job registration
            // must be absent before its stack and registry handles are closed.
            if matches!(
                entry.role,
                memcordon_core::WindowsCapabilityOwnerRoleV2::LauncherJob
                    | memcordon_core::WindowsCapabilityOwnerRoleV2::ActiveRegistryDuplicate
                    | memcordon_core::WindowsCapabilityOwnerRoleV2::ControlRelay
                    | memcordon_core::WindowsCapabilityOwnerRoleV2::LaunchGate
                    | memcordon_core::WindowsCapabilityOwnerRoleV2::DesktopBootstrapJob
            ) && record.worker_identity.as_ref() == Some(identity)
                && record
                    .worker_thread_identity
                    .map(worker_thread_is_extinct)
                    .transpose()?
                    .unwrap_or(false)
                && super::launcher_service::attempt_job_registration_is_absent(&record.attempt_id)?
            {
                continue;
            }
            return Ok(Some(format!(
                "frozen owner remains live without checked owner retirement; role={:?}; pid={}; birth={}",
                entry.role, identity.process_id, identity.creation_time_100ns
            )));
        }
    }
    Ok(None)
}

fn worker_thread_is_extinct(expected: WindowsWorkerThreadIdentityV1) -> Result<bool, String> {
    if expected.thread_id == 0 || expected.creation_time_100ns == 0 {
        return Err("worker thread identity is invalid".to_owned());
    }
    // SAFETY: authenticated durable identity supplies the id; only query and
    // synchronization rights are requested.
    let raw = unsafe {
        OpenThread(
            THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
            0,
            expected.thread_id,
        )
    };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        return if error
            .raw_os_error()
            .and_then(|code| u32::try_from(code).ok())
            == Some(ERROR_INVALID_PARAMETER)
        {
            Ok(true)
        } else {
            Err(error.to_string())
        };
    }
    let thread = OwnedHandle::new(raw)?;
    if thread_creation_time(thread.raw())? != expected.creation_time_100ns {
        return Ok(true);
    }
    // SAFETY: this is the same live thread object whose creation time was
    // compared above; a signaled thread has completed all stack destructors.
    match unsafe { WaitForSingleObject(thread.raw(), 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_FAILED => Err(io::Error::last_os_error().to_string()),
        _ => Ok(false),
    }
}

fn stage_recovered_closure(
    record: &mut WindowsAttemptRecordV1,
    current_boot_identity: &str,
    guardian_receipt: Option<&memcordon_core::WindowsGuardianReceiptV2>,
) -> Result<(), String> {
    stage_recovered_closure_with_extinction(record, current_boot_identity, guardian_receipt, None)
}

fn stage_recovered_closure_with_extinction(
    record: &mut WindowsAttemptRecordV1,
    current_boot_identity: &str,
    guardian_receipt: Option<&memcordon_core::WindowsGuardianReceiptV2>,
    extinction: Option<memcordon_core::WindowsCapabilityExtinctionProofV2>,
) -> Result<(), String> {
    if current_boot_identity.is_empty()
        || (current_boot_identity == record.boot_identity)
            != (guardian_receipt.is_some() || extinction.is_some())
        || record.authorization_unix_millis.is_none()
        || record.target_identity.is_none()
        || record.owner_manifest.is_none()
        || record.terminal_response_json.is_some()
    {
        return Err("recovery lacks exact authorized closure preconditions".to_owned());
    }
    let manifest_sha256 = record
        .owner_manifest
        .as_ref()
        .expect("checked frozen manifest")
        .canonical_sha256()
        .map_err(str::to_owned)?;
    let original = if matches!(
        record.causal_diagnostics.original,
        memcordon_core::OriginalFailureV1::Unavailable {
            reason: memcordon_core::OriginalUnavailableReasonV1::NoEarlierErrorObserved,
        }
    ) {
        memcordon_core::OriginalFailureV1::Unavailable {
            reason: memcordon_core::OriginalUnavailableReasonV1::WorkerLostBeforeObservation,
        }
    } else {
        record.causal_diagnostics.original.clone()
    };
    let mut journal = record.causal_diagnostics.clone();
    journal.original = original.clone();
    let binding = super::package::installed_public_provider_binding()?;
    if binding.generation.as_str() != record.provider_generation {
        return Err("prior-boot recovery provider generation differs".to_owned());
    }
    let provider_failure = memcordon_core::ProviderFailureDiagnosticV1::from_journal(
        binding,
        &record.attempt_id,
        &record.request_sha256,
        &journal,
    )
    .map_err(str::to_owned)?;
    let mut process_observation = record
        .terminal_seed
        .as_ref()
        .map(|seed| seed.process_observation.clone())
        .unwrap_or_else(|| {
            memcordon_core::WindowsProcessObservationV2::unavailable(
                memcordon_core::ProcessObservationUnavailableReasonV1::WorkerLostBeforeFreeze,
            )
        });
    if process_observation.root_identity.is_none() {
        process_observation.root_identity = record.target_identity.clone();
    }
    let guardian_recovery = guardian_receipt.is_some();
    let proof = memcordon_core::WindowsRetirementProofV3 {
        schema_version: 3,
        source: if extinction.is_some() {
            memcordon_core::WindowsRetirementProofSourceV2::CapabilityExtinction
        } else if guardian_recovery {
            memcordon_core::WindowsRetirementProofSourceV2::GuardianRecovery
        } else {
            memcordon_core::WindowsRetirementProofSourceV2::PriorBoot
        },
        attempt_id: record.attempt_id.clone(),
        nonce: record.nonce.clone(),
        request_sha256: record.request_sha256.clone(),
        provider_generation: record.provider_generation.clone(),
        launch_incarnation: record.launch_incarnation.clone(),
        original_boot_id: record.boot_identity.clone(),
        job_identity: record.job_identity_sha256.clone(),
        owner_manifest_sha256: manifest_sha256,
        // Guardian Job-zero proves extinction, not an identity-matched direct
        // target wait. Keep the historical completion observation absent.
        target_completion_observed: false,
        native_job_empty_observed: guardian_recovery,
        relay_closure_observed: guardian_recovery,
        guardian_completion_observed: guardian_recovery,
        owner_capabilities_closed: true,
        launch_gate_closed: true,
        guardian_receipt_sha256: guardian_receipt.map(|receipt| receipt.integrity_sha256.clone()),
        current_boot_id: (!guardian_recovery && extinction.is_none())
            .then(|| current_boot_identity.to_owned()),
        capability_extinction: extinction.clone(),
    };
    let restart_safety = memcordon_core::RestartSafetyProof {
        direct_child_reaped: false,
        workload_empty: Some(true),
        helpers_reaped: false,
        containment_removed: true,
        containment_incapable_of_live_members: true,
        sealed_boundary_retired: false,
        errors: Vec::new(),
    };
    let receipt = memcordon_core::WindowsTerminalReceiptV3 {
        schema_version: 3,
        attempt_id: record.attempt_id.clone(),
        nonce: record.nonce.clone(),
        request_sha256: record.request_sha256.clone(),
        payload: memcordon_core::WindowsTerminalPayloadV3::RecoveredClosure {
            primary_failure: original,
            target_creation_observed: true,
            resume_attempted: record.resume_attempted,
        },
        process_observation,
        cleanup_process_creation: None,
        restart_safety: restart_safety.clone(),
        retirement_proof: proof,
    };
    receipt.validate_for_attempt().map_err(str::to_owned)?;
    let rejection = memcordon_core::WindowsProviderRejectionV3 {
        schema_version: 3,
        provider_failure: Some(provider_failure.clone()),
        guardian_causal_receipt: None,
        code: "MCSEALED-WINDOWS-OWNER-LOST".to_owned(),
        phase: memcordon_core::BoundarySetupPhase::Retirement,
        detail: if extinction.is_some() {
            "original Job-holder processes exited; checked kill-on-last-handle policy proves capability extinction; native Job-zero and historical execution outcome were not observed".to_owned()
        } else if guardian_recovery {
            "original worker exited before authenticated terminal delivery; guardian proved Job zero and owner processes exited".to_owned()
        } else {
            "prior boot ended before authenticated terminal delivery; execution outcome unavailable"
                .to_owned()
        },
        os_code: None,
        loader_qualification: None,
        target_created: true,
        target_released: record.target_released,
        cleanup_attempted: true,
        restart_safety,
        disposition:
            memcordon_core::WindowsProviderRejectionDispositionV3::PostauthorizationFailure {
                receipt: Box::new(receipt.clone()),
            },
    };
    if !rejection.is_consistent() {
        return Err("recovered closure rejection lacks canonical original failure".to_owned());
    }
    if record.state != WindowsAttemptStateV1::Empty {
        if record.state != WindowsAttemptStateV1::Terminating {
            record.transition(WindowsAttemptStateV1::Terminating)?;
            record.store()?;
        }
        record.transition(WindowsAttemptStateV1::Empty)?;
    }
    record.causal_diagnostics = journal;
    record.lifecycle = memcordon_core::WindowsTerminalLifecycleV1::Retiring;
    record.terminal_disposition = Some(WindowsAttemptTerminalDispositionV1::Posttarget);
    record.store()?;
    match (&record.terminal_seed, &record.retirement_proof) {
        (None, None) => record.stage_terminal_proof(&receipt, Some(provider_failure))?,
        (Some(seed), None)
            if seed.process_observation == receipt.process_observation
                && seed.attempt_id == record.attempt_id
                && seed.nonce == record.nonce
                && seed.request_sha256 == record.request_sha256 =>
        {
            // Recovery completes proof without rewriting the pre-close seed.
            // In particular, owner loss after freeze cannot rewrite a genuine
            // earlier primary failure or turn it into observed exit data.
            record.retirement_proof = Some(receipt.retirement_proof.clone());
            record.lifecycle = memcordon_core::WindowsTerminalLifecycleV1::ProofReady;
            record.store()?;
        }
        (Some(_), Some(proof)) if proof == &receipt.retirement_proof => {}
        _ => return Err("recovered closure proof conflicts with durable terminal seed".to_owned()),
    }
    let response = memcordon_core::WindowsLauncherResponseV4::Reject {
        schema_version: memcordon_core::WINDOWS_CURRENT_PRIVATE_PROTOCOL_VERSION,
        attempt_id: record.attempt_id.clone(),
        nonce: record.nonce.clone(),
        request_sha256: record.request_sha256.clone(),
        rejection,
    };
    record.stage_terminal_response(&response)
}

pub fn recovery_inventory(
    challenge: &str,
) -> Result<memcordon_core::WindowsRecoveryInventoryV1, String> {
    if challenge.is_empty() || challenge.len() > 256 {
        return Err("recovery inventory challenge is invalid".to_owned());
    }
    let mut inventory = memcordon_core::WindowsRecoveryInventoryV1 {
        schema_version: 1,
        challenge: challenge.to_owned(),
        provider_generation: provider_generation(),
        current_boot_identity: boot_identity()?,
        executing: 0,
        incomplete_proof: 0,
        unacknowledged_outboxes: 0,
        ack_retirement_in_progress: 0,
        completed_tombstones: 0,
        active_admissions: 0,
        quarantined: 0,
    };
    for entry in fs::read_dir(attempts_root()).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        if reserved_writer_stage(&path, &admissions_root())? {
            // Active admissions below retain this owner's unsettled charge.
            continue;
        }
        let attempt_id = record_attempt_id(&path)?;
        let bytes = read_record_bounded(&path).map_err(|error| error.to_string())?;
        let record: WindowsAttemptRecordV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        authenticate(&record, &attempt_id)?;
        let counter =
            if record.lifecycle == memcordon_core::WindowsTerminalLifecycleV1::AckCommitted {
                &mut inventory.ack_retirement_in_progress
            } else if record.terminal_response_json.is_some() {
                &mut inventory.unacknowledged_outboxes
            } else if record.authorization_unix_millis.is_some() || record.resume_attempted {
                &mut inventory.incomplete_proof
            } else {
                &mut inventory.executing
            };
        *counter = counter
            .checked_add(1)
            .ok_or_else(|| "recovery inventory counter overflow".to_owned())?;
    }
    for entry in fs::read_dir(replay_root()).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        let bytes =
            read_record_bounded_with_limit(&path, memcordon_core::WINDOWS_MAX_TERMINAL_FRAME_BYTES)
                .map_err(|error| error.to_string())?;
        let replay: ReplayRecordV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if let Some(tombstone) = replay.acknowledged.as_ref() {
            // An AckCommitted attempt record and its staged tombstone describe
            // one retirement, not two outstanding authorities.
            if !tombstone.retirement_complete && record_path(&replay.attempt_id)?.exists() {
                continue;
            }
            let counter = if tombstone.retirement_complete {
                &mut inventory.completed_tombstones
            } else {
                &mut inventory.ack_retirement_in_progress
            };
            *counter = counter
                .checked_add(1)
                .ok_or_else(|| "recovery tombstone count overflow".to_owned())?;
        }
    }
    for entry in fs::read_dir(admissions_root()).map_err(|error| error.to_string())? {
        entry.map_err(|error| error.to_string())?;
        inventory.active_admissions = inventory
            .active_admissions
            .checked_add(1)
            .ok_or_else(|| "recovery admission count overflow".to_owned())?;
    }
    for entry in fs::read_dir(quarantine_root()).map_err(|error| error.to_string())? {
        entry.map_err(|error| error.to_string())?;
        inventory.quarantined = inventory
            .quarantined
            .checked_add(1)
            .ok_or_else(|| "recovery quarantine count overflow".to_owned())?;
    }
    if !inventory.is_consistent() {
        return Err("recovery inventory is inconsistent".to_owned());
    }
    Ok(inventory)
}

pub(super) fn reserve_writer_admission(
    attempt_id: &str,
    request_sha256: &str,
) -> Result<(), String> {
    validate_attempt_id(attempt_id)?;
    let _budget = super::attempt_store::PublicationGuard::acquire(&digest(
        b"installation-attempt-storage-budget-v1",
    ))?;
    reserve_writer_admission_at(&admissions_root(), attempt_id, request_sha256, || {
        enforce_storage_reservation(Some(attempt_id), false)
    })
}

fn reserve_writer_admission_at(
    root: &Path,
    attempt_id: &str,
    request_sha256: &str,
    enforce_budget: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    validate_attempt_id(attempt_id)?;
    validate_attempt_id(request_sha256)?;
    let path = root.join(attempt_id).with_extension("writer.json");
    if path.exists() {
        let old: AdmissionRecordV1 =
            serde_json::from_slice(&read_record_bounded(&path).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        if old.attempt_id != attempt_id || old.request_sha256 != request_sha256 {
            return Err("writer reservation binding differs".to_owned());
        }
        for owner in old.owner_process_identities {
            if process_identity_is_live(owner)? {
                return Err("another live process owns the writer reservation".to_owned());
            }
        }
        fs::remove_file(&path).map_err(|error| error.to_string())?;
    }
    enforce_budget()?;
    // SAFETY: the pseudo handle denotes this service process for identity capture.
    let owner = super::process::process_identity(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })?;
    let record = AdmissionRecordV1 {
        format: AdmissionRecordFormat::Native,
        revision: Default::default(),
        attempt_id: attempt_id.to_owned(),
        request_sha256: request_sha256.to_owned(),
        owner_process_identities: vec![owner],
        workload_reservation: true,
    };
    let mut bytes = serde_json::to_vec(&record).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

pub(super) fn retire_writer_admission(
    attempt_id: &str,
    local_writer_stopped: bool,
) -> Result<(), String> {
    validate_attempt_id(attempt_id)?;
    let _budget = super::attempt_store::PublicationGuard::acquire(&digest(
        b"installation-attempt-storage-budget-v1",
    ))?;
    retire_writer_admission_at(&admissions_root(), attempt_id, local_writer_stopped)
}

fn retire_writer_admission_at(
    root: &Path,
    attempt_id: &str,
    local_writer_stopped: bool,
) -> Result<(), String> {
    validate_attempt_id(attempt_id)?;
    let path = root.join(attempt_id).with_extension("writer.json");
    let bytes = match read_record_bounded(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    let admission: AdmissionRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if admission.attempt_id != attempt_id {
        return Err("writer reservation identity differs".to_owned());
    }
    // SAFETY: the pseudo handle identifies the current owner process.
    let current = super::process::process_identity(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })?;
    for owner in admission.owner_process_identities {
        if owner == current && local_writer_stopped {
            continue;
        }
        if process_identity_is_live(owner)? {
            return Err(
                "cannot release a live writer reservation without local retirement proof"
                    .to_owned(),
            );
        }
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
pub(crate) fn reserve_owned_component_writer_for_test(
    root: &Path,
    attempt_id: &str,
    request_sha256: &str,
) -> Result<(), String> {
    let root = owned_component_admission_root(root)?;
    let _budget = super::attempt_store::PublicationGuard::acquire_for_test(&digest(
        root.as_os_str().as_encoded_bytes(),
    ))?;
    reserve_writer_admission_at(&root, attempt_id, request_sha256, || {
        if fs::read_dir(&root)
            .map_err(|error| error.to_string())?
            .take(1)
            .count()
            >= 1
        {
            return Err("owned component writer reservation slot exhausted".into());
        }
        Ok(())
    })
}

#[cfg(test)]
pub(crate) fn retire_owned_component_writer_for_test(
    root: &Path,
    attempt_id: &str,
    local_writer_stopped: bool,
) -> Result<(), String> {
    let root = owned_component_admission_root(root)?;
    let _budget = super::attempt_store::PublicationGuard::acquire_for_test(&digest(
        root.as_os_str().as_encoded_bytes(),
    ))?;
    retire_writer_admission_at(&root, attempt_id, local_writer_stopped)
}

#[cfg(test)]
fn owned_component_admission_root(root: &Path) -> Result<PathBuf, String> {
    use std::os::windows::fs::MetadataExt;
    if !root.is_absolute() {
        return Err("owned component admission root must be absolute".into());
    }
    let metadata = fs::symlink_metadata(root).map_err(|error| error.to_string())?;
    if !metadata.is_dir()
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    {
        return Err("owned component admission root must be ordinary".into());
    }
    Ok(root.to_owned())
}

pub fn validate_admission(attempt_id: &str, request_sha256: &str) -> Result<(), String> {
    validate_attempt_id(attempt_id)?;
    validate_attempt_id(request_sha256)?;
    let path = admissions_root().join(format!("{attempt_id}.json"));
    let admission: AdmissionRecordV1 =
        serde_json::from_slice(&read_record_bounded(&path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if admission.attempt_id != attempt_id || admission.request_sha256 != request_sha256 {
        return Err("launch admission does not match the authenticated broker request".to_owned());
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub fn diagnostic_admission_is_exclusive(
    attempt_id: &str,
    request_sha256: &str,
) -> Result<bool, String> {
    validate_admission(attempt_id, request_sha256)?;
    let expected = format!("{attempt_id}.json");
    let mut entries = fs::read_dir(admissions_root()).map_err(|error| error.to_string())?;
    let Some(entry) = entries.next() else {
        return Ok(false);
    };
    let entry = entry.map_err(|error| error.to_string())?;
    if entry.file_name() != std::ffi::OsStr::new(&expected) || entries.next().is_some() {
        return Ok(false);
    }
    Ok(directory_empty(&attempts_root())?
        && directory_empty(&quarantine_root())?
        && directory_empty(&guardian_receipts_root())?)
}

pub fn retire_admission(attempt_id: &str) -> Result<(), String> {
    validate_attempt_id(attempt_id)?;
    let path = admissions_root().join(format!("{attempt_id}.json"));
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

pub fn rejection_evidence(
    attempt_id: &str,
    code: &str,
    detail: String,
    phase_override: Option<memcordon_core::BoundarySetupPhase>,
    os_code: Option<i32>,
    loader_qualification: Option<memcordon_core::WindowsLoaderQualificationOutcomeV2>,
    terminal_receipt: Option<Box<memcordon_core::WindowsTerminalReceiptV3>>,
) -> Result<memcordon_core::WindowsProviderRejectionV3, String> {
    super::attempt_store::wait_for_pending(attempt_id)?;
    let detail = bounded_rejection_detail(detail);
    let path = match record_path(attempt_id) {
        Ok(path) => path,
        Err(_) => {
            let mut rejection = match terminal_receipt {
                Some(terminal) => {
                    posttarget_rejection(code, detail, phase_override, os_code, terminal)
                }
                None => pretarget_rejection(code, detail),
            };
            rejection.loader_qualification = loader_qualification;
            return Ok(rejection);
        }
    };
    let bytes = match read_record_bounded(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut rejection = match terminal_receipt {
                Some(terminal) => {
                    posttarget_rejection(code, detail, phase_override, os_code, terminal)
                }
                None => pretarget_rejection(code, detail),
            };
            rejection.loader_qualification = loader_qualification;
            return Ok(rejection);
        }
        Err(error) => return Err(error.to_string()),
    };
    let mut record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    authenticate(&record, attempt_id)?;
    let target_created = record.target_identity.is_some();
    super::diagnostics::merge_into(&mut record.causal_diagnostics);
    let cleanup_attempted = record.cleanup_state.termination_requested;
    let live = record_has_live_process(&record)?;
    if cleanup_attempted
        && record.cleanup_state.active_processes_zero
        && record.cleanup_state.guardian_reaped
        && !record.cleanup_state.final_handles_closed
        && record.authorization_unix_millis.is_none()
        && !record.resume_attempted
        && !live
    {
        record.complete_rejection_cleanup()?;
    }
    let safe = cleanup_attempted
        && record.cleanup_state.active_processes_zero
        && record.cleanup_state.guardian_reaped
        && record.cleanup_state.final_handles_closed
        && !live;
    let restart_safety = if safe {
        memcordon_core::RestartSafetyProof {
            direct_child_reaped: true,
            workload_empty: Some(true),
            helpers_reaped: true,
            containment_removed: true,
            containment_incapable_of_live_members: true,
            sealed_boundary_retired: true,
            errors: Vec::new(),
        }
    } else {
        memcordon_core::RestartSafetyProof {
            errors: vec!["Windows rejection cleanup did not prove complete retirement".to_owned()],
            ..memcordon_core::RestartSafetyProof::default()
        }
    };
    let phase = phase_override.unwrap_or(match record.state {
        WindowsAttemptStateV1::BoundaryCreated | WindowsAttemptStateV1::GuardianReady => {
            memcordon_core::BoundarySetupPhase::BoundaryCreation
        }
        WindowsAttemptStateV1::TargetCreatedSuspended => {
            memcordon_core::BoundarySetupPhase::ResourceVerification
        }
        WindowsAttemptStateV1::Authorized => memcordon_core::BoundarySetupPhase::Authorization,
        WindowsAttemptStateV1::Terminating | WindowsAttemptStateV1::Empty => {
            memcordon_core::BoundarySetupPhase::Retirement
        }
    });
    Ok(memcordon_core::WindowsProviderRejectionV3 {
        provider_failure: provider_projection(Some(&record)).0,
        guardian_causal_receipt: guardian_causal_projection(&record)?,
        schema_version: 3,
        code: code.to_owned(),
        phase,
        detail,
        os_code,
        loader_qualification,
        target_created,
        target_released: record.target_released || record.resume_attempted,
        cleanup_attempted,
        restart_safety,
        disposition: match terminal_receipt {
            Some(receipt)
                if matches!(
                    receipt.payload,
                    memcordon_core::WindowsTerminalPayloadV3::PrematureReleaseFailure { .. }
                ) =>
            {
                memcordon_core::WindowsProviderRejectionDispositionV3::PrematureReleaseFailure {
                    receipt,
                }
            }
            Some(receipt) => {
                memcordon_core::WindowsProviderRejectionDispositionV3::PostauthorizationFailure {
                    receipt,
                }
            }
            None => memcordon_core::WindowsProviderRejectionDispositionV3::Preauthorization {
                terminal_ack_required: record.terminal_disposition.is_some(),
            },
        },
    })
}

pub fn attempt_requires_authoritative_terminal(attempt_id: &str) -> Result<bool, String> {
    let path = record_path(attempt_id)?;
    let bytes = match read_record_bounded(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    let record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    authenticate(&record, attempt_id)?;
    Ok(record.authorization_unix_millis.is_some()
        || record.resume_attempted
        || record.target_released
        || record.terminal_disposition == Some(WindowsAttemptTerminalDispositionV1::Posttarget))
}

fn posttarget_rejection(
    code: &str,
    detail: String,
    phase: Option<memcordon_core::BoundarySetupPhase>,
    os_code: Option<i32>,
    terminal: Box<memcordon_core::WindowsTerminalReceiptV3>,
) -> memcordon_core::WindowsProviderRejectionV3 {
    memcordon_core::WindowsProviderRejectionV3 {
        provider_failure: None,
        guardian_causal_receipt: None,
        schema_version: 3,
        code: code.to_owned(),
        phase: phase.unwrap_or(memcordon_core::BoundarySetupPhase::Retirement),
        detail: bounded_rejection_detail(detail),
        os_code,
        loader_qualification: None,
        target_created: true,
        target_released: true,
        cleanup_attempted: true,
        restart_safety: terminal.restart_safety.clone(),
        disposition:
            memcordon_core::WindowsProviderRejectionDispositionV3::PostauthorizationFailure {
                receipt: terminal,
            },
    }
}

pub fn stage_terminal_response(
    attempt_id: &str,
    response: &memcordon_core::WindowsLauncherResponseV4,
) -> Result<bool, String> {
    let path = record_path(attempt_id)?;
    let bytes = match read_record_bounded(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    let mut record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    authenticate(&record, attempt_id)?;
    record.stage_terminal_response(response)?;
    Ok(true)
}

pub struct LeasedTerminalResponse {
    response: Option<memcordon_core::WindowsLauncherResponseV4>,
    _reader: RecordReaderReservation,
}
impl std::ops::Deref for LeasedTerminalResponse {
    type Target = memcordon_core::WindowsLauncherResponseV4;
    fn deref(&self) -> &Self::Target {
        self.response
            .as_ref()
            .expect("terminal response payload released after delivery")
    }
}
impl Serialize for LeasedTerminalResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.response
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("terminal response already delivered"))?
            .serialize(serializer)
    }
}
impl LeasedTerminalResponse {
    pub(super) fn release_payload(&mut self) {
        self.response = None;
    }
    pub(super) fn acknowledge(
        &self,
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
    ) -> Result<memcordon_core::WindowsTerminalRetiredV2, String> {
        acknowledge_terminal_response_reserved(attempt_id, nonce, request_sha256)
    }
}

pub fn pending_terminal_response(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    caller_process_identity: &memcordon_core::WindowsProcessIdentityV1,
    caller_token_sha256: &str,
) -> Result<Option<LeasedTerminalResponse>, String> {
    let _reader = RecordReaderReservation::acquire(attempt_id, request_sha256)?;
    let path = record_path(attempt_id)?;
    let bytes = match read_record_bounded(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    authenticate(&record, attempt_id)?;
    let response = bound_pending_terminal_response(
        &record,
        attempt_id,
        nonce,
        request_sha256,
        caller_process_identity,
        caller_token_sha256,
    )?;
    Ok(response.map(|response| LeasedTerminalResponse {
        response: Some(response),
        _reader,
    }))
}

fn bound_pending_terminal_authority(
    record: &WindowsAttemptRecordV1,
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    caller_process_identity: &memcordon_core::WindowsProcessIdentityV1,
    caller_token_sha256: &str,
) -> Result<Option<memcordon_core::WindowsLauncherResponseV4>, String> {
    if record.request_sha256 != request_sha256
        || record.caller_process_identity != *caller_process_identity
        || record.caller_token_sha256 != caller_token_sha256
    {
        return Err(
            "pending terminal replay credentials are not bound to the exact attempt".to_owned(),
        );
    }
    let Some(response_json) = record.terminal_response_json.as_ref() else {
        return Ok(None);
    };
    let response: memcordon_core::WindowsLauncherResponseV4 =
        serde_json::from_str(response_json).map_err(|error| error.to_string())?;
    let binding_matches = match &response {
        memcordon_core::WindowsLauncherResponseV4::Terminal(receipt) => {
            receipt.attempt_id == attempt_id
                && receipt.nonce == nonce
                && receipt.request_sha256 == request_sha256
        }
        memcordon_core::WindowsLauncherResponseV4::Reject {
            attempt_id: response_attempt_id,
            nonce: response_nonce,
            request_sha256: response_request_sha256,
            rejection,
            ..
        } => {
            response_attempt_id == attempt_id
                && response_nonce == nonce
                && response_request_sha256 == request_sha256
                && rejection.terminal_ack_required()
        }
        _ => false,
    };
    if !binding_matches {
        return Err("pending terminal response is not bound to the replay request".to_owned());
    }
    Ok(Some(response))
}

fn bound_pending_terminal_response(
    record: &WindowsAttemptRecordV1,
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    caller_process_identity: &memcordon_core::WindowsProcessIdentityV1,
    caller_token_sha256: &str,
) -> Result<Option<memcordon_core::WindowsLauncherResponseV4>, String> {
    let mut response = bound_pending_terminal_authority(
        record,
        attempt_id,
        nonce,
        request_sha256,
        caller_process_identity,
        caller_token_sha256,
    )?;
    if let Some(memcordon_core::WindowsLauncherResponseV4::Reject { rejection, .. }) = &mut response
    {
        rejection.provider_failure = provider_projection(Some(record)).0;
        rejection.guardian_causal_receipt = guardian_causal_projection(record)?;
    }
    Ok(response)
}

/// Exercises the same authenticated decoder against a test's own tempfile.
/// This test-only helper never accesses installed attempt or replay roots.
#[cfg(test)]
pub(crate) fn pending_owned_component_response_for_test(
    path: &Path,
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    caller_process_identity: &memcordon_core::WindowsProcessIdentityV1,
    caller_token_sha256: &str,
) -> Result<Option<memcordon_core::WindowsLauncherResponseV4>, String> {
    let bytes = read_record_bounded(path).map_err(|error| error.to_string())?;
    let record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    authenticate(&record, attempt_id)?;
    bound_pending_terminal_authority(
        &record,
        attempt_id,
        nonce,
        request_sha256,
        caller_process_identity,
        caller_token_sha256,
    )
}

pub fn replay_unavailable_evidence(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
    caller_process_identity: &memcordon_core::WindowsProcessIdentityV1,
    caller_token_sha256: &str,
) -> Result<memcordon_core::WindowsAttemptRetainedV2, String> {
    let _reader = RecordReaderReservation::acquire(attempt_id, request_sha256)?;
    let path = record_path(attempt_id)?;
    let record = match read_record_bounded(&path) {
        Ok(bytes) => {
            let record: WindowsAttemptRecordV1 =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            authenticate(&record, attempt_id)?;
            if record.request_sha256 != request_sha256
                || record.caller_process_identity != *caller_process_identity
                || record.caller_token_sha256 != caller_token_sha256
            {
                return Err(
                    "terminal replay credentials are not bound to the retained attempt".to_owned(),
                );
            }
            Some(record)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.to_string()),
    };
    let cleanup_complete = record.as_ref().is_some_and(|record| {
        record.state == WindowsAttemptStateV1::Empty
            && record.cleanup_state.termination_requested
            && record.cleanup_state.active_processes_zero
            && record.cleanup_state.guardian_reaped
            && record.cleanup_state.final_handles_closed
    });
    let (provider_failure, diagnostic_availability) = provider_projection(record.as_ref());
    Ok(retained_v2(
        memcordon_core::WindowsRetainedMetadata {
            causal_diagnostics: record.as_ref().map_or_else(
                memcordon_core::WindowsCausalDiagnosticsV1::default,
                exportable_journal,
            ),
            provider_failure,
            diagnostic_availability,
            attempt_id: attempt_id.to_owned(),
            nonce: nonce.to_owned(),
            request_sha256: request_sha256.to_owned(),
            relay_phase,
            durable_state: record.as_ref().map(|record| record.state),
            terminal_disposition: record
                .as_ref()
                .and_then(|record| record.terminal_disposition),
            cleanup_complete,
            terminal_replay_available: false,
            authority_retained: true,
            primary_detail: "authenticated durable terminal response is unavailable".to_owned(),
            secondary_failures: Vec::new(),
        },
        record.as_ref(),
        memcordon_core::WindowsRetainedRecordUnavailableReasonV1::ReadFailure,
    ))
}

pub enum ReplayUnstagedEvidence {
    Pending(memcordon_core::WindowsReplayPendingV2),
    Retained(memcordon_core::WindowsAttemptRetainedV2),
}

fn missing_retirement_proofs(
    record: Option<&WindowsAttemptRecordV1>,
) -> Vec<memcordon_core::WindowsMissingRetirementProofV1> {
    use memcordon_core::WindowsMissingRetirementProofV1 as Missing;
    let Some(record) = record else {
        return vec![Missing::OwnerManifest];
    };
    let mut missing = Vec::new();
    if record.terminal_seed.is_none() {
        missing.push(Missing::TerminalSeed);
    }
    if !record.cleanup_state.active_processes_zero {
        missing.push(Missing::NativeJobEmpty);
    }
    if !record.cleanup_state.guardian_reaped {
        missing.push(Missing::GuardianReceipt);
    }
    if !record.cleanup_state.final_handles_closed {
        missing.push(Missing::OwnerCapabilityClosure);
    }
    if record.recovery_authorization.is_none() {
        missing.push(Missing::RecoveryAuthorization);
    }
    if record.owner_manifest.is_none() {
        missing.push(Missing::OwnerManifest);
    }
    if record.terminal_response_json.is_none() {
        missing.push(Missing::DurableOutbox);
    }
    if record.lifecycle != memcordon_core::WindowsTerminalLifecycleV1::RetirementComplete {
        missing.push(Missing::Ack);
    }
    missing
}

fn retained_v2(
    old: memcordon_core::WindowsRetainedMetadata,
    record: Option<&WindowsAttemptRecordV1>,
    unavailable_reason: memcordon_core::WindowsRetainedRecordUnavailableReasonV1,
) -> memcordon_core::WindowsAttemptRetainedV2 {
    let binding = record.map_or(
        memcordon_core::WindowsRetainedRecordBindingV1::Unavailable {
            reason: unavailable_reason,
        },
        |record| memcordon_core::WindowsRetainedRecordBindingV1::Bound {
            provider_generation: record.provider_generation.clone(),
            launch_incarnation: record.launch_incarnation.clone(),
            boot_identity: record.boot_identity.clone(),
            job_identity: record.job_identity_sha256.clone(),
            owner_manifest_sha256: record.owner_manifest.as_ref().map(|manifest| {
                manifest
                    .canonical_sha256()
                    .expect("authenticated manifest hashes")
            }),
        },
    );
    memcordon_core::WindowsAttemptRetainedV2 {
        schema_version: 3,
        attempt_id: old.attempt_id,
        nonce: old.nonce,
        request_sha256: old.request_sha256,
        record_binding: binding,
        relay_phase: old.relay_phase,
        durable_state: old.durable_state,
        terminal_disposition: old.terminal_disposition,
        checkpoint: record.map_or(
            memcordon_core::WindowsTerminalLifecycleV1::Retained,
            |record| record.lifecycle,
        ),
        missing_proofs: missing_retirement_proofs(record),
        cleanup_complete: old.cleanup_complete,
        terminal_replay_available: old.terminal_replay_available,
        authority_retained: old.authority_retained,
        primary_detail: old.primary_detail,
        secondary_failures: old.secondary_failures,
        causal_diagnostics: old.causal_diagnostics,
        provider_failure: old.provider_failure,
        diagnostic_availability: old.diagnostic_availability,
    }
}

fn pending_v2(
    old: memcordon_core::WindowsReplayMetadata,
    record: &WindowsAttemptRecordV1,
) -> memcordon_core::WindowsReplayPendingV2 {
    memcordon_core::WindowsReplayPendingV2 {
        schema_version: 5,
        attempt_id: old.attempt_id,
        nonce: old.nonce,
        request_sha256: old.request_sha256,
        provider_generation: record.provider_generation.clone(),
        launch_incarnation: record.launch_incarnation.clone(),
        boot_identity: record.boot_identity.clone(),
        job_identity: record.job_identity_sha256.clone(),
        owner_manifest_sha256: record.owner_manifest.as_ref().map(|manifest| {
            manifest
                .canonical_sha256()
                .expect("authenticated manifest hashes")
        }),
        relay_phase: old.relay_phase,
        durable_state: old.durable_state,
        terminal_disposition: old.terminal_disposition,
        checkpoint: record.lifecycle,
        missing_proofs: missing_retirement_proofs(Some(record)),
        authorization_present: old.authorization_present,
        resume_attempted: old.resume_attempted,
        target_released: old.target_released,
        cleanup_state: old.cleanup_state,
        cleanup_complete: old.cleanup_complete,
        outbox_stage: old.outbox_stage,
        terminalization: old.terminalization,
        detail: old.detail,
        causal_diagnostics: old.causal_diagnostics,
        provider_failure: old.provider_failure,
        diagnostic_availability: old.diagnostic_availability,
    }
}

fn render_terminalization_error(error: &WindowsTerminalizationErrorV1) -> String {
    format!(
        "stage={:?} code={} detail={} native_code={:?} observed_unix_millis={:?}",
        error.stage,
        error.error_code,
        error.detail.lines().collect::<Vec<_>>().join(" "),
        error.native_code,
        error.observed_unix_millis,
    )
}

fn classify_replay_unstaged_evidence(
    record: &WindowsAttemptRecordV1,
    nonce: &str,
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
) -> ReplayUnstagedEvidence {
    let (provider_failure, diagnostic_availability) = provider_projection(Some(record));
    let cleanup_complete = record.state == WindowsAttemptStateV1::Empty
        && record.cleanup_state.termination_requested
        && record.cleanup_state.active_processes_zero
        && record.cleanup_state.guardian_reaped
        && record.cleanup_state.final_handles_closed;
    if cleanup_complete
        && record.terminalization.checkpoint == WindowsTerminalizationCheckpointV1::RetainedFailure
    {
        let primary_detail = record.terminalization.last_error.as_ref().map_or_else(
            || {
                "authenticated terminalization retained failure without a primary diagnostic"
                    .to_owned()
            },
            |error| {
                format!(
                    "authenticated terminalization retained failure {}",
                    render_terminalization_error(error)
                )
            },
        );
        return ReplayUnstagedEvidence::Retained(retained_v2(
            memcordon_core::WindowsRetainedMetadata {
                causal_diagnostics: exportable_journal(record),
                provider_failure,
                diagnostic_availability,
                attempt_id: record.attempt_id.clone(),
                nonce: nonce.to_owned(),
                request_sha256: record.request_sha256.clone(),
                relay_phase,
                durable_state: Some(record.state),
                terminal_disposition: record.terminal_disposition,
                cleanup_complete,
                terminal_replay_available: false,
                authority_retained: true,
                primary_detail,
                secondary_failures: record
                    .terminalization
                    .secondary_errors
                    .iter()
                    .map(render_terminalization_error)
                    .collect(),
            },
            Some(record),
            memcordon_core::WindowsRetainedRecordUnavailableReasonV1::ReadFailure,
        ));
    }
    let outbox_stage = match record.terminalization.checkpoint {
        WindowsTerminalizationCheckpointV1::OutboxStaging => {
            memcordon_core::WindowsReplayOutboxStageV1::Attempting
        }
        WindowsTerminalizationCheckpointV1::OutboxStaged
        | WindowsTerminalizationCheckpointV1::AckRetiring => {
            memcordon_core::WindowsReplayOutboxStageV1::Staged
        }
        WindowsTerminalizationCheckpointV1::RetainedFailure => {
            memcordon_core::WindowsReplayOutboxStageV1::Failed
        }
        _ => memcordon_core::WindowsReplayOutboxStageV1::NotAttempted,
    };
    let detail = record.terminalization.last_error.as_ref().map_or_else(
        || "authenticated attempt is pending before durable terminal staging".to_owned(),
        |error| {
            format!(
                "authenticated terminalization failure {}",
                render_terminalization_error(error)
            )
        },
    );
    ReplayUnstagedEvidence::Pending(pending_v2(
        memcordon_core::WindowsReplayMetadata {
            causal_diagnostics: exportable_journal(record),
            provider_failure,
            diagnostic_availability,
            attempt_id: record.attempt_id.clone(),
            nonce: nonce.to_owned(),
            request_sha256: record.request_sha256.clone(),
            relay_phase,
            durable_state: record.state,
            terminal_disposition: record.terminal_disposition,
            authorization_present: record.authorization_unix_millis.is_some(),
            resume_attempted: record.resume_attempted,
            target_released: record.target_released,
            cleanup_state: memcordon_core::WindowsDurableCleanupStateV1 {
                termination_requested: record.cleanup_state.termination_requested,
                active_processes_zero: record.cleanup_state.active_processes_zero,
                guardian_reaped: record.cleanup_state.guardian_reaped,
                final_handles_closed: record.cleanup_state.final_handles_closed,
            },
            cleanup_complete,
            outbox_stage,
            terminalization: record.terminalization.clone(),
            detail,
        },
        record,
    ))
}

#[cfg(test)]
pub fn replay_unstaged_evidence_for_test(
    record: &WindowsAttemptRecordV1,
    nonce: &str,
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
) -> ReplayUnstagedEvidence {
    classify_replay_unstaged_evidence(record, nonce, relay_phase)
}

pub fn replay_unstaged_evidence(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
    caller_process_identity: &memcordon_core::WindowsProcessIdentityV1,
    caller_token_sha256: &str,
) -> Result<Option<ReplayUnstagedEvidence>, String> {
    let _reader = RecordReaderReservation::acquire(attempt_id, request_sha256)?;
    let path = record_path(attempt_id)?;
    let bytes = match read_record_bounded(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    authenticate(&record, attempt_id)?;
    if record.request_sha256 != request_sha256
        || record.caller_process_identity != *caller_process_identity
        || record.caller_token_sha256 != caller_token_sha256
    {
        return Err("terminal replay credentials are not bound to the active attempt".to_owned());
    }
    if record.terminal_response_json.is_some() {
        return Err("terminal replay outbox changed while availability was inspected".to_owned());
    }
    Ok(Some(classify_replay_unstaged_evidence(
        &record,
        nonce,
        relay_phase,
    )))
}

pub(super) fn retained_attempt_evidence(
    binding: &super::control_service::AuthenticatedAttemptBinding,
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
    primary_detail: String,
    secondary_failures: Vec<String>,
) -> memcordon_core::WindowsAttemptRetainedV2 {
    let attempt_id = binding.attempt_id();
    let nonce = binding.nonce();
    let request_sha256 = binding.request_sha256();
    let _reader = match RecordReaderReservation::acquire(attempt_id, request_sha256) {
        Ok(reader) => reader,
        Err(error) => {
            return retained_attempt_evidence_after_inspection_failure(
                attempt_id,
                nonce,
                request_sha256,
                relay_phase,
                primary_detail,
                secondary_failures,
                error,
            );
        }
    };
    let record = (|| -> Result<Option<WindowsAttemptRecordV1>, String> {
        let path = record_path(attempt_id)?;
        match read_record_bounded(&path) {
            Ok(bytes) => {
                let record: WindowsAttemptRecordV1 =
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                drop(bytes);
                authenticate(&record, attempt_id)?;
                if !binding.matches_record(&record) {
                    return Err("retained attempt request digest is not exact".to_owned());
                }
                Ok(Some(record))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    })();
    match record {
        Ok(record) => retained_attempt_evidence_from_snapshot(
            attempt_id,
            nonce,
            request_sha256,
            relay_phase,
            primary_detail,
            secondary_failures,
            record.as_ref(),
        ),
        Err(error) => retained_attempt_evidence_after_inspection_failure(
            attempt_id,
            nonce,
            request_sha256,
            relay_phase,
            primary_detail,
            secondary_failures,
            error,
        ),
    }
}

/// One installation-wide retained reader, charged before any full-file buffer.
/// The permit outlives the decoded snapshot and public projection construction.
struct RecordReaderReservation {
    path: PathBuf,
    _owner: super::attempt_store::PublicationGuard,
}
impl RecordReaderReservation {
    fn acquire(attempt_id: &str, request_sha256: &str) -> Result<Self, String> {
        let owner = super::attempt_store::PublicationGuard::acquire(&digest(
            b"installation-retained-reader-v1",
        ))?;
        let _budget = super::attempt_store::PublicationGuard::acquire(&digest(
            b"installation-attempt-storage-budget-v1",
        ))?;
        let path = admissions_root()
            .join(attempt_id)
            .with_extension("reader.json");
        if path.exists() {
            let prior: AdmissionRecordV1 = serde_json::from_slice(
                &read_record_bounded_with_limit(&path, 4096).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            for identity in prior.owner_process_identities {
                if process_identity_is_live(identity)? {
                    return Err("prior retained reader reservation is unresolved".to_owned());
                }
            }
            fs::remove_file(&path).map_err(|error| error.to_string())?;
        }
        enforce_storage_reservation(None, true)?;
        let record = AdmissionRecordV1 {
            format: AdmissionRecordFormat::Native,
            revision: Default::default(),
            attempt_id: attempt_id.to_owned(),
            request_sha256: request_sha256.to_owned(),
            owner_process_identities: vec![super::process::process_identity(unsafe {
                windows_sys::Win32::System::Threading::GetCurrentProcess()
            })?],
            workload_reservation: false,
        };
        let bytes = memcordon_core::bounded_json_bytes(&record, 4096, false)
            .map_err(|error| error.to_string())?;
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(Self {
            path,
            _owner: owner,
        })
    }
}
impl Drop for RecordReaderReservation {
    fn drop(&mut self) {
        if let Ok(_budget) = super::attempt_store::PublicationGuard::acquire(&digest(
            b"installation-attempt-storage-budget-v1",
        )) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn in_memory_retained_attempt_evidence(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
    primary_detail: String,
    secondary_failures: Vec<String>,
) -> memcordon_core::WindowsAttemptRetainedV2 {
    retained_attempt_evidence_from_snapshot(
        attempt_id,
        nonce,
        request_sha256,
        relay_phase,
        primary_detail,
        secondary_failures,
        None,
    )
}

fn retained_attempt_evidence_from_snapshot(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
    primary_detail: String,
    secondary_failures: Vec<String>,
    record: Option<&WindowsAttemptRecordV1>,
) -> memcordon_core::WindowsAttemptRetainedV2 {
    let (provider_failure, diagnostic_availability) = provider_projection(record);
    let cleanup_complete = record.as_ref().is_some_and(|record| {
        record.state == WindowsAttemptStateV1::Empty
            && record.cleanup_state.termination_requested
            && record.cleanup_state.active_processes_zero
            && record.cleanup_state.guardian_reaped
            && record.cleanup_state.final_handles_closed
    });
    retained_v2(
        memcordon_core::WindowsRetainedMetadata {
            causal_diagnostics: record.map_or_else(
                memcordon_core::WindowsCausalDiagnosticsV1::default,
                exportable_journal,
            ),
            provider_failure,
            diagnostic_availability,
            attempt_id: attempt_id.to_owned(),
            nonce: nonce.to_owned(),
            request_sha256: request_sha256.to_owned(),
            relay_phase,
            durable_state: record.as_ref().map(|record| record.state),
            terminal_disposition: record
                .as_ref()
                .and_then(|record| record.terminal_disposition),
            cleanup_complete,
            terminal_replay_available: record
                .as_ref()
                .is_some_and(|record| record.terminal_response_json.is_some()),
            authority_retained: true,
            primary_detail,
            secondary_failures,
        },
        record,
        memcordon_core::WindowsRetainedRecordUnavailableReasonV1::ReadFailure,
    )
}

fn retained_attempt_evidence_after_inspection_failure(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
    primary_detail: String,
    mut secondary_failures: Vec<String>,
    error: String,
) -> memcordon_core::WindowsAttemptRetainedV2 {
    secondary_failures.push(format!(
        "retained attempt record inspection failed: {error}"
    ));
    in_memory_retained_attempt_evidence(
        attempt_id,
        nonce,
        request_sha256,
        relay_phase,
        primary_detail,
        secondary_failures,
    )
}

fn diagnostic_export_eligible(record: &WindowsAttemptRecordV1) -> bool {
    let same_boot = boot_identity().is_ok_and(|identity| identity == record.boot_identity);
    // SAFETY: this monotonic system clock needs no pointer arguments.
    record
        .diagnostic_retention
        .export_eligible(same_boot, unsafe {
            windows_sys::Win32::System::SystemInformation::GetTickCount64()
        })
}

fn exportable_journal(
    record: &WindowsAttemptRecordV1,
) -> memcordon_core::WindowsCausalDiagnosticsV1 {
    exportable_journal_if_eligible(record, diagnostic_export_eligible(record))
}

fn exportable_journal_if_eligible(
    record: &WindowsAttemptRecordV1,
    eligible: bool,
) -> memcordon_core::WindowsCausalDiagnosticsV1 {
    if eligible {
        return record.causal_diagnostics.clone();
    }
    let mut journal = memcordon_core::WindowsCausalDiagnosticsV1::default();
    journal.original = memcordon_core::OriginalFailureV1::Unavailable {
        reason: memcordon_core::OriginalUnavailableReasonV1::RetentionExpired,
    };
    journal
}

/// Explicit deterministic retention boundary for an owned component record.
/// This does not override the production clock or mutate persisted authority.
#[cfg(test)]
pub(crate) fn owned_component_journal_at_for_test(
    record: &WindowsAttemptRecordV1,
    same_boot: bool,
    now: u64,
) -> memcordon_core::WindowsCausalDiagnosticsV1 {
    exportable_journal_if_eligible(
        record,
        record.diagnostic_retention.export_eligible(same_boot, now),
    )
}

fn provider_projection(
    record: Option<&WindowsAttemptRecordV1>,
) -> (
    Option<memcordon_core::ProviderFailureDiagnosticV1>,
    memcordon_core::DiagnosticProjectionAvailabilityV1,
) {
    use memcordon_core::DiagnosticProjectionAvailabilityV1 as Availability;
    let Some(record) = record else {
        return (None, Availability::RecordUnavailable);
    };
    if !diagnostic_export_eligible(record) {
        return (None, Availability::RetentionExpired);
    }
    let binding = match super::package::installed_public_provider_binding() {
        Ok(binding) if binding.generation.as_str() == record.provider_generation => binding,
        _ => return (None, Availability::ProviderBindingUnavailable),
    };
    match memcordon_core::ProviderFailureDiagnosticV1::from_journal(
        binding,
        &record.attempt_id,
        &record.request_sha256,
        &record.causal_diagnostics,
    ) {
        Ok(projection) => (Some(projection), Availability::Available),
        Err(_) => (None, Availability::InvalidProjection),
    }
}

#[cfg(test)]
pub(crate) fn retained_attempt_evidence_after_inspection_failure_for_test(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
    relay_phase: memcordon_core::WindowsRelayPhaseV1,
    primary_detail: String,
    secondary_failures: Vec<String>,
    error: String,
) -> memcordon_core::WindowsAttemptRetainedV2 {
    retained_attempt_evidence_after_inspection_failure(
        attempt_id,
        nonce,
        request_sha256,
        relay_phase,
        primary_detail,
        secondary_failures,
        error,
    )
}

pub fn terminal_outbox_count() -> Result<u32, String> {
    let mut count = 0_u32;
    let entries = match fs::read_dir(attempts_root()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.to_string()),
    };
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let attempt_id = terminal_inventory_attempt_id(&path)?;
        let _reader = RecordReaderReservation::acquire(&attempt_id, &attempt_id)?;
        if !entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err(format!(
                "MCSEALED-WINDOWS-TERMINAL-INVENTORY-ENTRY: attempt_id={attempt_id} is not a regular file"
            ));
        }
        let bytes = read_record_bounded(&path).map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-TERMINAL-INVENTORY-READ: attempt_id={attempt_id} error={error}"
            )
        })?;
        let record: WindowsAttemptRecordV1 = serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-TERMINAL-INVENTORY-PARSE: attempt_id={attempt_id} error={error}"
            )
        })?;
        authenticate(&record, &attempt_id).map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-TERMINAL-INVENTORY-AUTHENTICATION: attempt_id={attempt_id} error={error}"
            )
        })?;
        if record.terminal_response_json.is_some() {
            count = count
                .checked_add(1)
                .ok_or_else(|| "terminal outbox count overflowed".to_owned())?;
        }
    }
    Ok(count)
}

fn terminal_inventory_attempt_id(path: &Path) -> Result<String, String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "MCSEALED-WINDOWS-TERMINAL-INVENTORY-ENTRY: name is not UTF-8".to_owned())?;
    if let Some(attempt_id) = name.strip_suffix(".json.new") {
        validate_attempt_id(attempt_id).map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-TERMINAL-INVENTORY-ENTRY: staged attempt name is invalid: {error}"
            )
        })?;
        return Err(format!(
            "MCSEALED-WINDOWS-TERMINAL-INVENTORY-STAGED: attempt_id={attempt_id} requires durable recovery before inventory"
        ));
    }
    record_attempt_id(path).map_err(|error| {
        format!("MCSEALED-WINDOWS-TERMINAL-INVENTORY-ENTRY: name={name} error={error}")
    })
}

#[cfg(test)]
pub(crate) fn terminal_inventory_attempt_id_for_test(name: &str) -> Result<String, String> {
    terminal_inventory_attempt_id(Path::new(name))
}

pub fn acknowledge_terminal_response(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
) -> Result<memcordon_core::WindowsTerminalRetiredV2, String> {
    let _reader = RecordReaderReservation::acquire(attempt_id, request_sha256)?;
    acknowledge_terminal_response_reserved(attempt_id, nonce, request_sha256)
}

fn acknowledge_terminal_response_reserved(
    attempt_id: &str,
    nonce: &str,
    request_sha256: &str,
) -> Result<memcordon_core::WindowsTerminalRetiredV2, String> {
    let path = record_path(attempt_id)?;
    let bytes = match read_record_bounded(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let retired = recover_incomplete_ack_tombstone(attempt_id, request_sha256)?;
            if retired.nonce != nonce {
                return Err("terminal ACK tombstone nonce does not match".to_owned());
            }
            return Ok(retired);
        }
        Err(error) => return Err(error.to_string()),
    };
    let mut record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    authenticate(&record, attempt_id)?;
    if record.request_sha256 != request_sha256 {
        return Err("terminal acknowledgment request digest is not exact".to_owned());
    }
    let receipt = record.terminal_retired_receipt(nonce)?;
    record.acknowledge_terminal_response()?;
    let retired = complete_ack_tombstone(attempt_id, request_sha256)?;
    if retired.terminal_response_sha256 != receipt.terminal_response_sha256 {
        return Err("ACK tombstone changed terminal authority digest".to_owned());
    }
    Ok(retired)
}

pub fn pretarget_rejection(
    code: &str,
    detail: String,
) -> memcordon_core::WindowsProviderRejectionV3 {
    pretarget_rejection_at(
        code,
        memcordon_core::BoundarySetupPhase::ProviderConnection,
        detail,
    )
}

pub fn pretarget_rejection_at(
    code: &str,
    phase: memcordon_core::BoundarySetupPhase,
    detail: String,
) -> memcordon_core::WindowsProviderRejectionV3 {
    memcordon_core::WindowsProviderRejectionV3 {
        provider_failure: None,
        guardian_causal_receipt: None,
        schema_version: 3,
        code: code.to_owned(),
        phase,
        detail: bounded_rejection_detail(detail),
        os_code: None,
        loader_qualification: None,
        target_created: false,
        target_released: false,
        cleanup_attempted: false,
        restart_safety: memcordon_core::RestartSafetyProof::default(),
        disposition: memcordon_core::WindowsProviderRejectionDispositionV3::Preauthorization {
            terminal_ack_required: false,
        },
    }
}

pub fn attempts_root() -> PathBuf {
    package::state_root().join("attempts")
}

/// Read actual live association facts without reserving, authorizing, or
/// mutating an admission. Called only by the authenticated launcher owner.
pub fn observe_live_guardian_attempt(
    expected: &WindowsProcessIdentityV1,
) -> Result<memcordon_core::execution_facts::ProviderAttemptAssociationV1, String> {
    observe_live_guardian_details(expected).map(|details| details.0)
}

pub fn observe_live_guardian_details(
    expected: &WindowsProcessIdentityV1,
) -> Result<
    (
        memcordon_core::execution_facts::ProviderAttemptAssociationV1,
        String,
        WindowsProcessIdentityV1,
        WindowsWorkerThreadIdentityV1,
        WindowsProcessIdentityV1,
    ),
    String,
> {
    let root = attempts_root();
    super::security::SecurityDescriptor::from_sddl(&super::security::launcher_state_sddl()?)?
        .verify_path(&root)?;
    require_live_guardian(expected, GuardianObservationPhase::BeforeInventory)?;
    let provider = package::installed_public_provider_binding()?;
    let boot = boot_identity()?;
    let mut selected = None;
    for (index, entry) in fs::read_dir(&root)
        .map_err(|error| error.to_string())?
        .enumerate()
    {
        if index >= 256 {
            return Err("live association record inventory exceeds its bound".into());
        }
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let attempt = path
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or("live association record name is invalid")?;
        validate_attempt_id(attempt)?;
        let bytes = read_record_bounded(&path).map_err(|error| error.to_string())?;
        let record: WindowsAttemptRecordV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        authenticate(&record, attempt)?;
        if record.guardian_identity.as_ref() != Some(expected) {
            continue;
        }
        if selected.is_some()
            || record.boot_identity != boot
            || record.provider_generation != provider.generation.as_str()
            || !record.target_released
            || !record.resume_attempted
            || record.authorization_unix_millis.is_none()
        {
            return Err("live guardian association is ambiguous or not released".into());
        }
        selected = Some((
            memcordon_core::execution_facts::ProviderAttemptAssociationV1 {
                provider: provider.clone(),
                attempt_id: memcordon_core::DiagnosticSha256::try_from(
                    memcordon_core::BoundedText::new(&record.attempt_id).map_err(str::to_owned)?,
                )
                .map_err(str::to_owned)?,
                request_sha256: memcordon_core::DiagnosticSha256::try_from(
                    memcordon_core::BoundedText::new(&record.request_sha256)
                        .map_err(str::to_owned)?,
                )
                .map_err(str::to_owned)?,
            },
            record.nonce.clone(),
            record
                .worker_identity
                .clone()
                .ok_or("live worker process identity missing")?,
            record
                .worker_thread_identity
                .ok_or("live worker thread identity missing")?,
            record
                .target_identity
                .clone()
                .ok_or("live released target identity missing")?,
        ));
    }
    require_live_guardian(expected, GuardianObservationPhase::AfterInventory)?;
    selected.ok_or_else(|| "held live guardian has no unique native attempt record".into())
}

pub fn quarantine_root() -> PathBuf {
    package::state_root().join("quarantine")
}

pub fn admissions_root() -> PathBuf {
    package::state_root().join("admissions")
}

pub fn replay_root() -> PathBuf {
    package::state_root().join("replay")
}

fn replay_retiring_root() -> PathBuf {
    package::state_root().join("replay-retiring")
}

pub fn guardian_receipts_root() -> PathBuf {
    package::state_root().join("guardian-receipts")
}

pub(crate) fn prepare_guardian_receipt_directory(
    attempt_id: &str,
    slot: &str,
) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    validate_attempt_id(attempt_id)?;
    super::security::SecurityDescriptor::from_sddl(&super::security::launcher_state_sddl()?)?
        .verify_path(&guardian_receipts_root())?;
    let directory = guardian_receipts_root().join(attempt_id);
    let security = super::security::SecurityDescriptor::from_sddl(
        &super::security::guardian_receipt_directory_sddl(slot)?,
    )?;
    let attributes = security.attributes(false);
    let wide: Vec<u16> = directory.as_os_str().encode_wide().chain(Some(0)).collect();
    // A fresh attempt gets exactly one launcher-created, protected directory.
    // Existing names are refused rather than adopting another writer's state.
    if unsafe {
        windows_sys::Win32::Storage::FileSystem::CreateDirectoryW(wide.as_ptr(), &attributes)
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    verify_guardian_receipt_directory(&directory)?;
    security.verify_path(&directory)
}

fn verify_guardian_receipt_directory(directory: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    let metadata = fs::symlink_metadata(directory).map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("guardian receipt directory is not a plain directory".into());
    }
    // Only the launcher can create/rename these directories or change their
    // protected descriptor. A slot gets no inheritable child or directory
    // mutation rights. Match the complete policy, not merely an allowed ACE.
    for index in 0..memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT {
        let slot = super::security::guardian_slot_name(index)?;
        let security = super::security::SecurityDescriptor::from_sddl(
            &super::security::guardian_receipt_directory_sddl(&slot)?,
        )?;
        if security.verify_path(directory).is_ok() {
            return Ok(());
        }
    }
    Err("guardian receipt directory has no exact protected slot policy".into())
}

fn directory_empty(path: &Path) -> Result<bool, String> {
    match fs::read_dir(path) {
        Ok(mut entries) => Ok(entries.next().is_none()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.to_string()),
    }
}

fn quarantine(path: &Path) -> Result<PathBuf, String> {
    let root = quarantine_root();
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("unrecognized-attempt");
    let mut identity = path.as_os_str().to_string_lossy().as_bytes().to_vec();
    identity.extend_from_slice(
        &SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos()
            .to_le_bytes(),
    );
    let destination = root.join(format!("{}-{name}", digest(&identity)));
    fs::rename(path, &destination).map_err(|error| error.to_string())?;
    Ok(destination)
}

fn record_path(attempt_id: &str) -> Result<PathBuf, String> {
    validate_attempt_id(attempt_id)?;
    Ok(attempts_root().join(format!("{attempt_id}.json")))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuardianReceiptStage {
    Attempt,
    Directory,
    RecordRead,
    RecordDecode,
    RecordAuthenticate,
    OwnerBinding,
    Build,
    Validate,
    Serialize,
    Security,
    Create,
    Write,
    Sync,
    Verify,
    Publish,
}

impl GuardianReceiptStage {
    pub(crate) const ALL: [Self; 15] = [
        Self::Attempt,
        Self::Directory,
        Self::RecordRead,
        Self::RecordDecode,
        Self::RecordAuthenticate,
        Self::OwnerBinding,
        Self::Build,
        Self::Validate,
        Self::Serialize,
        Self::Security,
        Self::Create,
        Self::Write,
        Self::Sync,
        Self::Verify,
        Self::Publish,
    ];
    pub(crate) const fn exit_class(self) -> u32 {
        40 + self as u32
    }
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Attempt => "receipt-attempt",
            Self::Directory => "receipt-directory",
            Self::RecordRead => "receipt-record-read",
            Self::RecordDecode => "receipt-record-decode",
            Self::RecordAuthenticate => "receipt-record-authenticate",
            Self::OwnerBinding => "receipt-owner-binding",
            Self::Build => "receipt-build",
            Self::Validate => "receipt-validate",
            Self::Serialize => "receipt-serialize",
            Self::Security => "receipt-security",
            Self::Create => "receipt-create",
            Self::Write => "receipt-write",
            Self::Sync => "receipt-sync",
            Self::Verify => "receipt-verify",
            Self::Publish => "receipt-publish",
        }
    }
}

#[derive(Debug)]
pub(crate) struct GuardianReceiptWriteError {
    pub stage: GuardianReceiptStage,
    pub native_code: Option<i32>,
    pub source: String,
}

pub(crate) fn write_guardian_receipt(
    attempt_id: &str,
    worker_identity: &WindowsProcessIdentityV1,
    guardian_identity: &WindowsProcessIdentityV1,
    cleanup_trigger: memcordon_core::WindowsGuardianCleanupTriggerV1,
) -> Result<(), GuardianReceiptWriteError> {
    let mut stage = GuardianReceiptStage::Attempt;
    let mut native_code = None;
    let result = (|| -> Result<(), String> {
        validate_attempt_id(attempt_id)?;
        stage = GuardianReceiptStage::Directory;
        verify_guardian_receipt_directory(&guardian_receipts_root().join(attempt_id))?;
        stage = GuardianReceiptStage::RecordRead;
        let bytes = read_record_bounded(&record_path(attempt_id)?).map_err(|error| {
            native_code = error.raw_os_error();
            error.to_string()
        })?;
        stage = GuardianReceiptStage::RecordDecode;
        let record: WindowsAttemptRecordV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        stage = GuardianReceiptStage::RecordAuthenticate;
        authenticate(&record, attempt_id)?;
        stage = GuardianReceiptStage::OwnerBinding;
        match &cleanup_trigger {
            memcordon_core::WindowsGuardianCleanupTriggerV1::FrontendLost { frontend, .. }
            | memcordon_core::WindowsGuardianCleanupTriggerV1::FrontendExitStatusUnavailable {
                frontend,
                ..
            } if frontend != &record.caller_process_identity => {
                return Err(
                    "guardian observed frontend identity differs from authenticated caller".into(),
                );
            }
            _ => {}
        }
        if record.worker_identity.as_ref() != Some(worker_identity)
            || record.guardian_identity.as_ref() != Some(guardian_identity)
        {
            return Err(
                "guardian receipt worker or guardian identity differs from durable record"
                    .to_owned(),
            );
        }
        let manifest = record
            .owner_manifest
            .as_ref()
            .ok_or_else(|| "guardian receipt has no authorized owner manifest".to_owned())?;
        stage = GuardianReceiptStage::Build;
        let mut receipt = memcordon_core::WindowsGuardianReceiptV2 {
            schema_version: 2,
            attempt_id: attempt_id.to_owned(),
            nonce: record.nonce.clone(),
            request_sha256: record.request_sha256.clone(),
            provider_generation: record.provider_generation.clone(),
            launch_incarnation: record.launch_incarnation.clone(),
            original_boot_id: record.boot_identity.clone(),
            job_identity: record.job_identity_sha256.clone(),
            guardian_identity: guardian_identity.clone(),
            worker_identity: worker_identity.clone(),
            owner_manifest_sha256: manifest.canonical_sha256().map_err(str::to_owned)?,
            termination_requested: true,
            native_job_query_succeeded: true,
            active_processes_zero_observed: true,
            cleanup_trigger: Some(cleanup_trigger),
            observed_unix_millis: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_millis()
                .try_into()
                .map_err(|_| "guardian observation timestamp overflow".to_owned())?,
            integrity_sha256: String::new(),
        };
        receipt.integrity_sha256 = receipt.canonical_sha256().map_err(str::to_owned)?;
        stage = GuardianReceiptStage::Validate;
        if !receipt.is_consistent() {
            return Err("guardian native receipt failed V2 validation".to_owned());
        }
        stage = GuardianReceiptStage::Serialize;
        let mut bytes = serde_json::to_vec_pretty(&receipt).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        let path = guardian_receipt_path(attempt_id)?;
        let staged = path.with_extension("json.new");
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::FromRawHandle;
        stage = GuardianReceiptStage::Security;
        let security = guardian_receipt_file_security()?;
        let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: security.raw(),
            bInheritHandle: 0,
        };
        let wide: Vec<u16> = staged
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: the path and descriptor remain live; CREATE_NEW fails on collision.
        stage = GuardianReceiptStage::Create;
        let handle = unsafe {
            windows_sys::Win32::Storage::FileSystem::CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE_ACCESS | READ_CONTROL_ACCESS | DELETE_ACCESS,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &attributes,
                windows_sys::Win32::Storage::FileSystem::CREATE_NEW,
                windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            native_code = error.raw_os_error();
            return Err(error.to_string());
        }
        // SAFETY: CREATE_NEW returned a uniquely owned Win32 file handle.
        let mut staged_file = CreateOnceStagingFile {
            file: unsafe { fs::File::from_raw_handle(handle as _) },
            path: staged.clone(),
        };
        use std::io::Write;
        stage = GuardianReceiptStage::Write;
        staged_file.file_mut().write_all(&bytes).map_err(|error| {
            native_code = error.raw_os_error();
            error.to_string()
        })?;
        stage = GuardianReceiptStage::Sync;
        staged_file.sync_all().map_err(|error| {
            native_code = error.raw_os_error();
            error.to_string()
        })?;
        stage = GuardianReceiptStage::Verify;
        security.verify_path(&staged)?;
        stage = GuardianReceiptStage::Publish;
        publish_create_once_atomically(staged_file, &path).map_err(|error| {
            native_code = error.native_code();
            error.to_string()
        })
    })();
    result.map_err(|source| GuardianReceiptWriteError {
        stage,
        native_code,
        source,
    })
}

fn guardian_receipt_file_security() -> Result<super::security::SecurityDescriptor, String> {
    // Both writer and reader are LocalSystem; the file is created with this
    // protected descriptor, not an inherited or later-mutable DACL.
    super::security::SecurityDescriptor::from_sddl("O:SYD:P(A;;FA;;;SY)")
}

fn read_guardian_receipt(
    attempt_id: &str,
) -> Result<memcordon_core::WindowsGuardianReceiptV2, String> {
    super::security::SecurityDescriptor::from_sddl(&super::security::launcher_state_sddl()?)?
        .verify_path(&guardian_receipts_root())?;
    let path = guardian_receipt_path(attempt_id)?;
    verify_guardian_receipt_directory(path.parent().ok_or("guardian receipt parent is absent")?)?;
    let security = guardian_receipt_file_security()?;
    let bytes = read_record_bounded_with_limit_and_security(
        &path,
        memcordon_core::WINDOWS_MAX_FRAME_BYTES,
        Some(&security),
    )
    .map_err(|error| error.to_string())?;
    let receipt: memcordon_core::WindowsGuardianReceiptV2 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if receipt.attempt_id != attempt_id || !receipt.is_consistent() {
        return Err("guardian terminal receipt authentication failed".to_owned());
    }
    Ok(receipt)
}

fn guardian_receipt_binds_record(
    receipt: &memcordon_core::WindowsGuardianReceiptV2,
    record: &WindowsAttemptRecordV1,
) -> Result<bool, String> {
    let manifest = record
        .owner_manifest
        .as_ref()
        .ok_or_else(|| "guardian receipt has no frozen owner manifest".to_owned())?;
    let owner_manifest_sha256 = manifest.canonical_sha256().map_err(str::to_owned)?;
    Ok(
        receipt.binds(memcordon_core::WindowsGuardianReceiptBinding {
            attempt_id: &record.attempt_id,
            nonce: &record.nonce,
            request_sha256: &record.request_sha256,
            provider_generation: &record.provider_generation,
            launch_incarnation: &record.launch_incarnation,
            boot_identity: &record.boot_identity,
            job_identity: &record.job_identity_sha256,
            owner_manifest_sha256: &owner_manifest_sha256,
            caller_process_identity: &record.caller_process_identity,
        }) && record.guardian_identity.as_ref() == Some(&receipt.guardian_identity)
            && record.worker_identity.as_ref() == Some(&receipt.worker_identity),
    )
}

fn guardian_causal_projection(
    record: &WindowsAttemptRecordV1,
) -> Result<Option<Box<memcordon_core::WindowsGuardianReceiptV2>>, String> {
    guardian_causal_projection_if_eligible(record, diagnostic_export_eligible(record), || {
        let path = guardian_receipt_path(&record.attempt_id)?;
        if !path.try_exists().map_err(|error| error.to_string())? {
            return Ok(None);
        }
        // This reader checks the existing protected directory/file descriptor;
        // integrity_sha256 alone is never authentication.
        read_guardian_receipt(&record.attempt_id).map(Some)
    })
}

fn guardian_causal_projection_if_eligible(
    record: &WindowsAttemptRecordV1,
    eligible: bool,
    read_authenticated_receipt: impl FnOnce() -> Result<
        Option<memcordon_core::WindowsGuardianReceiptV2>,
        String,
    >,
) -> Result<Option<Box<memcordon_core::WindowsGuardianReceiptV2>>, String> {
    if !eligible {
        return Ok(None);
    }
    if record.guardian_identity.is_none() || record.owner_manifest.is_none() {
        return Ok(None);
    }
    let Some(receipt) = read_authenticated_receipt()? else {
        return Ok(None);
    };
    if !guardian_receipt_binds_record(&receipt, record)? {
        return Err("guardian causal diagnostic differs from authenticated attempt".into());
    }
    Ok(Some(Box::new(receipt)))
}

fn guardian_receipt_path(attempt_id: &str) -> Result<PathBuf, String> {
    validate_attempt_id(attempt_id)?;
    Ok(guardian_receipts_root()
        .join(attempt_id)
        .join("receipt.json"))
}

fn remove_guardian_receipt(attempt_id: &str) -> Result<(), String> {
    let path = guardian_receipt_path(attempt_id)?;
    let directory = path.parent().ok_or("guardian receipt parent is absent")?;
    match fs::symlink_metadata(directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
        Ok(_) => verify_guardian_receipt_directory(directory)?,
    }
    // Check the entire bounded namespace before deleting any original proof.
    // A retained stage or unknown child keeps the receipt and failure evidence.
    for child in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let child = child.map_err(|error| error.to_string())?;
        if child.file_name() != std::ffi::OsStr::new("receipt.json") {
            return Err("guardian receipt directory has an unpublished or unknown child".into());
        }
        read_guardian_receipt(attempt_id)?;
    }
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    // Never recursively delete unknown or staged evidence.
    fs::remove_dir(directory).map_err(|error| error.to_string())
}

fn record_name_refusal(path: &Path, reason: &str) -> String {
    let excerpt = |value: &std::ffi::OsStr, bound: usize| {
        let text = value.to_string_lossy();
        let lossy = matches!(&text, std::borrow::Cow::Owned(_));
        let mut observed = String::new();
        let mut truncated = false;
        for character in text.chars().flat_map(char::escape_debug) {
            if observed.len() + character.len_utf8() > bound {
                truncated = true;
                break;
            }
            observed.push(character);
        }
        (observed, truncated, lossy)
    };
    let (parent, parent_truncated, parent_lossy) =
        excerpt(path.parent().unwrap_or(Path::new("")).as_os_str(), 128);
    let (leaf, leaf_truncated, leaf_lossy) = excerpt(path.file_name().unwrap_or_default(), 256);
    format!(
        "{reason}; supplied-parent=\"{parent}\"; parent-truncated={parent_truncated}; parent-lossy={parent_lossy}; entry-name=\"{leaf}\"; entry-truncated={leaf_truncated}; entry-lossy={leaf_lossy}"
    )
}

fn record_attempt_id(path: &Path) -> Result<String, String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| record_name_refusal(path, "attempt record name is not UTF-8"))?;
    let attempt_id = name.strip_suffix(".json").ok_or_else(|| {
        record_name_refusal(path, "attempt directory contains an unrecognized entry")
    })?;
    validate_attempt_id(attempt_id).map_err(|error| record_name_refusal(path, &error))?;
    Ok(attempt_id.to_owned())
}

/// Recognize only a bounded transaction still owned by its exact live writer.
/// An abandoned or unknown stage remains a refusal, never committed authority.
fn reserved_writer_stage(path: &Path, admissions: &Path) -> Result<bool, String> {
    let Some(attempt_id) = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".json.new"))
    else {
        return Ok(false);
    };
    validate_attempt_id(attempt_id)?;
    let admission_path = admissions.join(attempt_id).with_extension("writer.json");
    let admission: AdmissionRecordV1 = serde_json::from_slice(
        &read_record_bounded_with_limit(&admission_path, 4096)
            .map_err(|error| format!("staged attempt writer admission unavailable: {error}"))?,
    )
    .map_err(|error| format!("staged attempt writer admission invalid: {error}"))?;
    validate_attempt_id(&admission.request_sha256)?;
    if admission.attempt_id != attempt_id
        || !admission.workload_reservation
        || admission.owner_process_identities.is_empty()
    {
        return Err("staged attempt lacks its exact writer reservation".to_owned());
    }
    let mut live = false;
    for owner in admission.owner_process_identities {
        if owner.process_id == 0 || owner.creation_time_100ns == 0 {
            return Err("staged attempt writer identity is invalid".to_owned());
        }
        live |= process_identity_is_live(owner)?;
    }
    if !live {
        return Err(
            "staged attempt writer is not live; exclusive authenticated recovery required"
                .to_owned(),
        );
    }
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > memcordon_core::WINDOWS_MAX_FRAME_BYTES as u64
    {
        return Err("staged attempt is not a bounded ordinary file".to_owned());
    }
    let mut standard = FILE_STANDARD_INFO::default();
    // SAFETY: query the exact held staging object without reading its partial bytes.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as _,
            FileStandardInfo,
            (&raw mut standard).cast(),
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    if standard.NumberOfLinks != 1 {
        return Err("staged attempt has multiple links".to_owned());
    }
    Ok(true)
}

#[cfg(test)]
pub(crate) fn reserved_writer_stage_for_test(
    path: &Path,
    admissions: &Path,
) -> Result<bool, String> {
    reserved_writer_stage(path, admissions)
}

pub fn validate_attempt_id(value: &str) -> Result<(), String> {
    let digest_length = digest(&[]).len();
    if value.len() == digest_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("attempt record has an invalid identity".to_owned())
    }
}

fn canonical_record_bytes(record: &WindowsAttemptRecordV1) -> Result<Vec<u8>, String> {
    let mut bytes =
        memcordon_core::bounded_json_bytes(record, memcordon_core::WINDOWS_MAX_FRAME_BYTES, false)
            .map_err(|error| error.to_string())?;
    bytes.pop();
    Ok(bytes)
}

pub(super) fn relay_retirement_event_name(record: &WindowsAttemptRecordV1) -> String {
    let binding = serde_json::to_vec(&(
        &record.attempt_id,
        &record.nonce,
        &record.provider_generation,
        &record.boot_identity,
        &record.launch_incarnation,
    ))
    .expect("validated attempt identity serializes");
    format!(
        "Global\\MemCordonSealedRelayRetirement-{}",
        digest(&binding)
    )
}

fn decoded_v4(record: &WindowsAttemptRecordV1) -> memcordon_core::WindowsDurableAttemptRecordV5 {
    memcordon_core::WindowsDurableAttemptRecordV5 {
        schema_version: record.schema_version,
        attempt_id: record.attempt_id.clone(),
        provider_generation: record.provider_generation.clone(),
        boot_identity: record.boot_identity.clone(),
        launch_incarnation: record.launch_incarnation.clone(),
        nonce: record.nonce.clone(),
        request_sha256: record.request_sha256.clone(),
        caller_process_identity: record.caller_process_identity.clone(),
        caller_token_sha256: record.caller_token_sha256.clone(),
        job_identity_sha256: record.job_identity_sha256.clone(),
        guardian_identity: record.guardian_identity.clone(),
        worker_identity: record.worker_identity.clone(),
        worker_thread_identity: record.worker_thread_identity,
        target_identity: record.target_identity.clone(),
        state: record.state,
        lifecycle: record.lifecycle,
        authorization_unix_millis: record.authorization_unix_millis,
        resume_attempted: record.resume_attempted,
        target_released: record.target_released,
        cleanup_state: memcordon_core::WindowsDurableCleanupStateV1 {
            termination_requested: record.cleanup_state.termination_requested,
            active_processes_zero: record.cleanup_state.active_processes_zero,
            guardian_reaped: record.cleanup_state.guardian_reaped,
            final_handles_closed: record.cleanup_state.final_handles_closed,
        },
        owner_manifest: record.owner_manifest.clone(),
        job_closure_contract: record.job_closure_contract.clone(),
        recovery_authorization: record.recovery_authorization.clone(),
        terminal_publication_reserved: record.terminal_publication_reserved,
        terminal_seed: record.terminal_seed.clone(),
        retirement_proof: record.retirement_proof.clone(),
        terminal_response_json: record.terminal_response_json.as_deref().map(str::to_owned),
        terminal_disposition: record.terminal_disposition,
        terminalization: record.terminalization.clone(),
        causal_diagnostics: record.causal_diagnostics.clone(),
        diagnostic_retention: record.diagnostic_retention.clone(),
        record_revision: record.record_revision,
        provider_incarnation: record.provider_incarnation.clone(),
        integrity_sha256: record.integrity_sha256.clone(),
    }
}

fn authenticate(record: &WindowsAttemptRecordV1, file_attempt_id: &str) -> Result<(), String> {
    let mut decoded = decoded_v4(record);
    memcordon_core::authenticate_decoded_windows_attempt_record_v5(
        &mut decoded,
        file_attempt_id,
        &provider_generation(),
    )
    .map_err(str::to_owned)
}

pub(super) fn read_record_bounded(path: &Path) -> io::Result<Vec<u8>> {
    read_record_bounded_with_limit(path, memcordon_core::WINDOWS_MAX_FRAME_BYTES)
}

fn read_record_bounded_with_limit(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    read_record_bounded_with_limit_and_security(path, maximum, None)
}

fn read_record_bounded_with_limit_and_security(
    path: &Path,
    maximum: usize,
    security: Option<&super::security::SecurityDescriptor>,
) -> io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > maximum as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid attempt record file",
        ));
    }
    let mut standard = FILE_STANDARD_INFO::default();
    // SAFETY: output describes the exact already-open file, preventing a
    // pathname substitution between link/size inspection and the bounded read.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as _,
            FileStandardInfo,
            (&raw mut standard).cast(),
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if standard.NumberOfLinks != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "attempt record has multiple links",
        ));
    }
    if let Some(security) = security {
        security
            .verify_file_object(file.as_raw_handle() as _)
            .map_err(io::Error::other)?;
    }
    let expected = usize::try_from(metadata.len()).map_err(io::Error::other)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected + 1)
        .map_err(io::Error::other)?;
    bytes.resize(expected + 1, 0);
    let mut reader = file;
    let mut length = 0;
    while length < bytes.len() {
        let read = reader.read(&mut bytes[length..])?;
        if read == 0 {
            break;
        }
        length += read;
    }
    if length > expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "attempt record grew beyond opened-handle byte bound",
        ));
    }
    bytes.truncate(length);
    memcordon_core::validate_record_json_structure(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(bytes)
}

fn provider_incarnation() -> Result<&'static str, String> {
    static INCARNATION: std::sync::OnceLock<Result<String, String>> = std::sync::OnceLock::new();
    INCARNATION
        .get_or_init(|| {
            let mut random = [0_u8; 32];
            // SAFETY: the buffer is writable and its length is passed exactly;
            // system-preferred RNG does not require an algorithm handle.
            let status = unsafe {
                windows_sys::Win32::Security::Cryptography::BCryptGenRandom(
                    ptr::null_mut(),
                    random.as_mut_ptr(),
                    u32::try_from(random.len()).expect("RNG buffer length"),
                    windows_sys::Win32::Security::Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status < 0 {
                return Err("could not allocate provider incarnation".to_owned());
            }
            Ok(digest(&random))
        })
        .as_ref()
        .map(String::as_str)
        .map_err(Clone::clone)
}

fn record_has_live_process(record: &WindowsAttemptRecordV1) -> Result<bool, String> {
    [
        record.guardian_identity.clone(),
        record.target_identity.clone(),
    ]
    .into_iter()
    .flatten()
    .try_fold(false, |live, identity| {
        if live {
            Ok(true)
        } else {
            process_identity_is_live(identity)
        }
    })
}

#[derive(Debug, PartialEq, Eq)]
enum ProcessLiveness {
    Live,
    PidAbsent {
        raw_os_error: i32,
    },
    Signaled {
        wait_status: u32,
    },
    IdentityMismatch {
        observed: WindowsProcessIdentityV1,
        wait_status: u32,
    },
}

#[derive(Clone, Copy)]
enum GuardianObservationPhase {
    BeforeInventory,
    AfterInventory,
}

fn guardian_liveness_refusal(
    expected: &WindowsProcessIdentityV1,
    observation: &ProcessLiveness,
    phase: GuardianObservationPhase,
) -> Option<String> {
    let (prefix, phase) = match phase {
        GuardianObservationPhase::BeforeInventory => (
            "observed guardian is no longer the live held process",
            "before-record-inventory",
        ),
        GuardianObservationPhase::AfterInventory => (
            "guardian retired during live association readback",
            "after-record-inventory",
        ),
    };
    let facts = match observation {
        ProcessLiveness::Live => return None,
        ProcessLiveness::PidAbsent { raw_os_error } => {
            format!("reason=pid-absent; raw-os-error={raw_os_error}")
        }
        ProcessLiveness::Signaled { wait_status } => {
            format!("reason=process-signaled; wait-status={wait_status}")
        }
        ProcessLiveness::IdentityMismatch {
            observed,
            wait_status,
        } => format!(
            "reason=identity-mismatch; wait-status={wait_status}; observed-pid={}; observed-birth={}",
            observed.process_id, observed.creation_time_100ns
        ),
    };
    // Only closed phase/reason text and fixed-width native scalars are rendered.
    Some(format!(
        "{prefix}; phase={phase}; expected-pid={}; expected-birth={}; {facts}",
        expected.process_id, expected.creation_time_100ns
    ))
}

fn require_live_guardian(
    expected: &WindowsProcessIdentityV1,
    phase: GuardianObservationPhase,
) -> Result<(), String> {
    let observation = observe_process_liveness(expected.clone())?;
    match guardian_liveness_refusal(expected, &observation, phase) {
        Some(detail) => Err(detail),
        None => Ok(()),
    }
}

fn process_identity_is_live(expected: WindowsProcessIdentityV1) -> Result<bool, String> {
    observe_process_liveness(expected).map(|observation| observation == ProcessLiveness::Live)
}

fn observe_process_liveness(expected: WindowsProcessIdentityV1) -> Result<ProcessLiveness, String> {
    // SAFETY: PID comes from an authenticated record and rights are query-only.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
            0,
            expected.process_id,
        )
    };
    if raw.is_null() {
        let error = std::io::Error::last_os_error();
        return process_open_failure(error);
    }
    let handle = OwnedHandle::new(raw)?;
    observe_held_process_liveness(handle.raw(), expected)
}

fn process_open_failure(error: std::io::Error) -> Result<ProcessLiveness, String> {
    match error
        .raw_os_error()
        .and_then(|value| u32::try_from(value).ok())
    {
        Some(ERROR_INVALID_PARAMETER) => Ok(ProcessLiveness::PidAbsent {
            raw_os_error: error.raw_os_error().expect("matched native code"),
        }),
        _ => Err(error.to_string()),
    }
}

fn observe_held_process_liveness(
    handle: HANDLE,
    expected: WindowsProcessIdentityV1,
) -> Result<ProcessLiveness, String> {
    // SAFETY: handle is live and queried without blocking.
    let wait_status = unsafe { WaitForSingleObject(handle, 0) };
    match wait_status {
        WAIT_OBJECT_0 => return Ok(ProcessLiveness::Signaled { wait_status }),
        WAIT_FAILED => return Err(std::io::Error::last_os_error().to_string()),
        _ => {}
    }
    let observed = super::process::process_identity(handle)?;
    Ok(if observed == expected {
        ProcessLiveness::Live
    } else {
        ProcessLiveness::IdentityMismatch {
            observed,
            wait_status,
        }
    })
}

pub fn replace_atomically(source: &Path, destination: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    let source_path = source;
    let destination_path = destination;
    let source = source_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both paths are live, NUL-terminated UTF-16 buffers and the flags
    // request an atomic same-volume replacement flushed before return.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        // Capture the original causal event before any diagnostic API can
        // replace the thread's last-error value. Never retry this mutation.
        let error = std::io::Error::last_os_error();
        let native_error = error.raw_os_error();
        let original = publication_io_error(error);
        Err(replacement_failure_context(
            &original,
            native_error,
            source_path,
            destination_path,
        ))
    } else {
        Ok(())
    }
}

fn replacement_failure_context(
    original: &str,
    native_error: Option<i32>,
    source: &Path,
    destination: &Path,
) -> String {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::ERROR_NO_TOKEN,
        Security::TOKEN_QUERY,
        Storage::FileSystem::{GetFileAttributesW, INVALID_FILE_ATTRIBUTES},
        System::Threading::{
            GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, GetCurrentThreadId,
            OpenProcessToken, OpenThreadToken,
        },
    };

    fn close_token(handle: windows_sys::Win32::Foundation::HANDLE) -> serde_json::Value {
        match OwnedHandle::new(handle) {
            Ok(mut owned) => match owned.close_checked() {
                Ok(()) => serde_json::json!({"closed":true}),
                Err(error) => serde_json::json!({"closed":false,"error":error}),
            },
            Err(error) => serde_json::json!({"owned":false,"error":error}),
        }
    }

    fn path_facts(path: &Path) -> serde_json::Value {
        let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
        // Allocate a finite fraction of the existing publisher-error carrier
        // to each path, including worst-case JSON escaping/number encoding.
        let prefix = units
            .iter()
            .take(MAX_TERMINALIZATION_DETAIL_BYTES / 32)
            .copied()
            .collect::<Vec<_>>();
        let native = units
            .iter()
            .copied()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: native is a live NUL-terminated path; this only queries attributes.
        let attributes = unsafe { GetFileAttributesW(native.as_ptr()) };
        let probe = if attributes == INVALID_FILE_ATTRIBUTES {
            serde_json::json!({"error":io::Error::last_os_error().raw_os_error()})
        } else {
            serde_json::json!({"value":attributes})
        };
        serde_json::json!({"utf16":prefix,"units":units.len(),
            "truncated":prefix.len()!=units.len(),"absolute":path.is_absolute(),
            "attributes":probe})
    }

    let mut token = ptr::null_mut();
    // SAFETY: current-thread pseudo handle and a live output pointer; query only.
    let thread_ok = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    let token_context = if thread_ok != 0 {
        serde_json::json!({"thread":"present","handle":close_token(token)})
    } else {
        let thread_error = io::Error::last_os_error().raw_os_error();
        if thread_error == Some(ERROR_NO_TOKEN as i32) {
            // Only an explicit NO_TOKEN result permits process-context observation.
            let mut process_token = ptr::null_mut();
            // SAFETY: query-only access to this process and a live output pointer.
            let ok =
                unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut process_token) };
            if ok != 0 {
                serde_json::json!({"thread":"absent","process":"present","handle":close_token(process_token)})
            } else {
                serde_json::json!({"thread":"absent","process_error":io::Error::last_os_error().raw_os_error()})
            }
        } else {
            serde_json::json!({"thread":"unknown","error":thread_error})
        }
    };
    let context = serde_json::json!({"format_revision":1,"api":"MoveFileExW","native_error":native_error,
        "flags":MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH,
        "source":path_facts(source),"destination":path_facts(destination),
        "same_parent":source.parent()==destination.parent(),
        "process":unsafe {GetCurrentProcessId()},"thread":unsafe {GetCurrentThreadId()},
        "token":token_context,"security_identity":"not-collected"});
    let message = format!("{original}; replacement-context={context}");
    if message.len() <= MAX_TERMINALIZATION_DETAIL_BYTES * 3 / 4 {
        message
    } else {
        format!(
            "{original}; replacement-context={{\"revision\":1,\"api\":\"MoveFileExW\",\"omitted\":\"context exceeds existing carrier allocation\"}}"
        )
    }
}

pub(crate) struct CreateOnceStagingFile {
    file: fs::File,
    path: PathBuf,
}

impl CreateOnceStagingFile {
    pub(crate) fn create(path: &Path) -> Result<Self, io::Error> {
        use std::os::windows::fs::OpenOptionsExt;

        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_WRITE_ACCESS | DELETE_ACCESS)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(path)?;
        Ok(Self {
            file,
            path: path.to_owned(),
        })
    }

    pub(crate) const fn file_mut(&mut self) -> &mut fs::File {
        &mut self.file
    }

    pub(crate) fn sync_all(&self) -> Result<(), io::Error> {
        self.file.sync_all()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateOncePublicationStage {
    PathValidation,
    DestinationEncoding,
    RenameBufferConstruction,
    SourceNameBeforeRenameReadback,
    SourceNameBeforeRenameParse,
    SourceLeafBeforeRenameVerification,
    SourceIdentityBeforeRename,
    SourceLinkCountBeforeRename,
    SourceLinkCountBeforeRenameVerification,
    Rename,
    FinalNameAfterRenameReadback,
    FinalNameAfterRenameParse,
    SourceIdentityAfterRename,
    FinalLinkCountAfterRename,
    VolumeIdentityVerification,
    FileIdentityVerification,
    FinalLinkCountAfterRenameVerification,
    FinalParentVerification,
    FinalComponentVerification,
    FinalSync,
}

impl CreateOncePublicationStage {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::PathValidation => "path-validation",
            Self::DestinationEncoding => "destination-encoding",
            Self::RenameBufferConstruction => "rename-buffer-construction",
            Self::SourceNameBeforeRenameReadback => "source-name-before-rename-readback",
            Self::SourceNameBeforeRenameParse => "source-name-before-rename-parse",
            Self::SourceLeafBeforeRenameVerification => "source-leaf-before-rename-verification",
            Self::SourceIdentityBeforeRename => "source-identity-before-rename",
            Self::SourceLinkCountBeforeRename => "source-link-count-before-rename",
            Self::SourceLinkCountBeforeRenameVerification => {
                "source-link-count-before-rename-verification"
            }
            Self::Rename => "rename",
            Self::FinalNameAfterRenameReadback => "final-name-after-rename-readback",
            Self::FinalNameAfterRenameParse => "final-name-after-rename-parse",
            Self::SourceIdentityAfterRename => "source-identity-after-rename",
            Self::FinalLinkCountAfterRename => "final-link-count-after-rename",
            Self::VolumeIdentityVerification => "volume-identity-verification",
            Self::FileIdentityVerification => "file-identity-verification",
            Self::FinalLinkCountAfterRenameVerification => {
                "final-link-count-after-rename-verification"
            }
            Self::FinalParentVerification => "final-parent-verification",
            Self::FinalComponentVerification => "final-component-verification",
            Self::FinalSync => "final-sync",
        }
    }

    pub(crate) const fn api(self) -> &'static str {
        match self {
            Self::PathValidation => "Path",
            Self::DestinationEncoding => "OsStrExt::encode_wide",
            Self::RenameBufferConstruction => "FILE_RENAME_INFO",
            Self::SourceNameBeforeRenameReadback | Self::FinalNameAfterRenameReadback => {
                "GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED|VOLUME_NAME_NT)"
            }
            Self::SourceNameBeforeRenameParse | Self::FinalNameAfterRenameParse => {
                "CreateOnceHandleLocation"
            }
            Self::SourceIdentityBeforeRename | Self::SourceIdentityAfterRename => {
                "GetFileInformationByHandleEx(FileIdInfo)"
            }
            Self::SourceLinkCountBeforeRename | Self::FinalLinkCountAfterRename => {
                "GetFileInformationByHandleEx(FileStandardInfo)"
            }
            Self::Rename => "SetFileInformationByHandle(FileRenameInfo)",
            Self::SourceLeafBeforeRenameVerification
            | Self::SourceLinkCountBeforeRenameVerification
            | Self::VolumeIdentityVerification
            | Self::FileIdentityVerification
            | Self::FinalLinkCountAfterRenameVerification
            | Self::FinalParentVerification
            | Self::FinalComponentVerification => "CreateOncePublicationPostcondition",
            Self::FinalSync => "FlushFileBuffers",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CreateOnceFileIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

#[derive(Clone, Debug, Default)]
struct CreateOncePublicationEvidence {
    rename_committed: bool,
    observed_source_path: Option<PathBuf>,
    observed_final_path: Option<PathBuf>,
    source_identity: Option<CreateOnceFileIdentity>,
    final_identity: Option<CreateOnceFileIdentity>,
    source_link_count: Option<u32>,
    final_link_count: Option<u32>,
}

#[derive(Debug)]
pub(crate) struct CreateOncePublicationFailure {
    stage: CreateOncePublicationStage,
    source: PathBuf,
    destination: PathBuf,
    requested_access: u32,
    io_error_kind: io::ErrorKind,
    native_code: Option<i32>,
    destination_name_bytes: Option<u32>,
    information_bytes: Option<u32>,
    backing_bytes: Option<u32>,
    rename_committed: bool,
    observed_source_path: Option<PathBuf>,
    observed_final_path: Option<PathBuf>,
    source_identity: Option<CreateOnceFileIdentity>,
    final_identity: Option<CreateOnceFileIdentity>,
    source_link_count: Option<u32>,
    final_link_count: Option<u32>,
    secondary_detail: Option<String>,
    detail: String,
}

impl CreateOncePublicationFailure {
    pub(crate) fn native_code(&self) -> Option<i32> {
        self.native_code
    }

    const fn requested_access() -> u32 {
        GENERIC_WRITE_ACCESS | DELETE_ACCESS
    }

    fn io(
        stage: CreateOncePublicationStage,
        source: &Path,
        destination: &Path,
        layout: Option<&CreateOnceRenameInformation>,
        evidence: &CreateOncePublicationEvidence,
        error: io::Error,
    ) -> Self {
        Self {
            stage,
            source: source.to_owned(),
            destination: destination.to_owned(),
            requested_access: Self::requested_access(),
            io_error_kind: error.kind(),
            native_code: error.raw_os_error(),
            destination_name_bytes: layout.map(|layout| layout.destination_name_bytes),
            information_bytes: layout.map(|layout| layout.information_bytes),
            backing_bytes: layout.map(|layout| layout.backing_bytes),
            rename_committed: evidence.rename_committed,
            observed_source_path: evidence.observed_source_path.clone(),
            observed_final_path: evidence.observed_final_path.clone(),
            source_identity: evidence.source_identity,
            final_identity: evidence.final_identity,
            source_link_count: evidence.source_link_count,
            final_link_count: evidence.final_link_count,
            secondary_detail: None,
            detail: error.to_string(),
        }
    }

    fn semantic(
        stage: CreateOncePublicationStage,
        source: &Path,
        destination: &Path,
        layout: Option<&CreateOnceRenameInformation>,
        evidence: &CreateOncePublicationEvidence,
        detail: impl Into<String>,
    ) -> Self {
        let io_error_kind = match stage {
            CreateOncePublicationStage::PathValidation
            | CreateOncePublicationStage::DestinationEncoding
            | CreateOncePublicationStage::RenameBufferConstruction => io::ErrorKind::InvalidInput,
            _ => io::ErrorKind::InvalidData,
        };
        Self {
            stage,
            source: source.to_owned(),
            destination: destination.to_owned(),
            requested_access: Self::requested_access(),
            io_error_kind,
            native_code: None,
            destination_name_bytes: layout.map(|layout| layout.destination_name_bytes),
            information_bytes: layout.map(|layout| layout.information_bytes),
            backing_bytes: layout.map(|layout| layout.backing_bytes),
            rename_committed: evidence.rename_committed,
            observed_source_path: evidence.observed_source_path.clone(),
            observed_final_path: evidence.observed_final_path.clone(),
            source_identity: evidence.source_identity,
            final_identity: evidence.final_identity,
            source_link_count: evidence.source_link_count,
            final_link_count: evidence.final_link_count,
            secondary_detail: None,
            detail: detail.into(),
        }
    }

    fn with_secondary(mut self, stage: CreateOncePublicationStage, error: io::Error) -> Self {
        self.secondary_detail = Some(format!(
            "stage={} api={} io_kind={:?} native_code={} detail={error}",
            stage.name(),
            stage.api(),
            error.kind(),
            error
                .raw_os_error()
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
        ));
        self
    }

    pub(crate) const fn stage(&self) -> CreateOncePublicationStage {
        self.stage
    }

    pub(crate) const fn kind(&self) -> io::ErrorKind {
        self.io_error_kind
    }

    pub(crate) const fn raw_os_error(&self) -> Option<i32> {
        self.native_code
    }
}

impl std::fmt::Display for CreateOncePublicationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-CREATE-ONCE-PUBLICATION: stage={} api={} staging_path={} final_path={} requested_access=0x{:08x} replace_if_exists=false root_directory=null name_query_flags=FILE_NAME_NORMALIZED|VOLUME_NAME_NT io_kind={:?} native_code={} destination_name_bytes={} information_bytes={} backing_bytes={} rename_committed={} observed_staging_path={} observed_final_path={} source_identity={} final_identity={} source_link_count={} final_link_count={} secondary={} detail={}",
            self.stage.name(),
            self.stage.api(),
            self.source.display(),
            self.destination.display(),
            self.requested_access,
            self.io_error_kind,
            self.native_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.destination_name_bytes
                .map_or_else(|| "none".to_owned(), |bytes| bytes.to_string()),
            self.information_bytes
                .map_or_else(|| "none".to_owned(), |bytes| bytes.to_string()),
            self.backing_bytes
                .map_or_else(|| "none".to_owned(), |bytes| bytes.to_string()),
            self.rename_committed,
            self.observed_source_path
                .as_deref()
                .map_or_else(|| "none".to_owned(), |path| path.display().to_string()),
            self.observed_final_path
                .as_deref()
                .map_or_else(|| "none".to_owned(), |path| path.display().to_string()),
            self.source_identity
                .map_or_else(|| "none".to_owned(), |identity| format!("{identity:?}"),),
            self.final_identity
                .map_or_else(|| "none".to_owned(), |identity| format!("{identity:?}"),),
            self.source_link_count
                .map_or_else(|| "none".to_owned(), |count| count.to_string()),
            self.final_link_count
                .map_or_else(|| "none".to_owned(), |count| count.to_string()),
            self.secondary_detail.as_deref().unwrap_or("none"),
            self.detail,
        )
    }
}

impl std::error::Error for CreateOncePublicationFailure {}

#[derive(Debug)]
struct CreateOnceRenameInformation {
    words: Vec<usize>,
    destination_name_bytes: u32,
    information_bytes: u32,
    backing_bytes: u32,
}

impl CreateOnceRenameInformation {
    fn new(source: &Path, destination_path: &Path) -> Result<Self, CreateOncePublicationFailure> {
        use std::os::windows::ffi::OsStrExt;

        let evidence = CreateOncePublicationEvidence::default();
        let destination = destination_path
            .as_os_str()
            .encode_wide()
            .collect::<Vec<_>>();
        if destination.is_empty() || destination.contains(&0) {
            return Err(CreateOncePublicationFailure::semantic(
                CreateOncePublicationStage::DestinationEncoding,
                source,
                destination_path,
                None,
                &evidence,
                "create-once destination is empty or contains an embedded NUL",
            ));
        }
        let destination_name_bytes = destination
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                CreateOncePublicationFailure::semantic(
                    CreateOncePublicationStage::DestinationEncoding,
                    source,
                    destination_path,
                    None,
                    &evidence,
                    "create-once destination length is not representable",
                )
            })?;
        let prefix_bytes = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
        let terminated_tail_bytes = destination
            .len()
            .checked_add(1)
            .and_then(|units| units.checked_mul(std::mem::size_of::<u16>()))
            .ok_or_else(|| {
                CreateOncePublicationFailure::semantic(
                    CreateOncePublicationStage::RenameBufferConstruction,
                    source,
                    destination_path,
                    None,
                    &evidence,
                    "create-once terminated destination length overflowed",
                )
            })?;
        let meaningful_bytes = prefix_bytes
            .checked_add(terminated_tail_bytes)
            .map(|bytes| bytes.max(std::mem::size_of::<FILE_RENAME_INFO>()))
            .ok_or_else(|| {
                CreateOncePublicationFailure::semantic(
                    CreateOncePublicationStage::RenameBufferConstruction,
                    source,
                    destination_path,
                    None,
                    &evidence,
                    "create-once rename information length overflowed",
                )
            })?;
        let aligned_words = meaningful_bytes
            .checked_add(std::mem::size_of::<usize>() - 1)
            .map(|value| value / std::mem::size_of::<usize>())
            .ok_or_else(|| {
                CreateOncePublicationFailure::semantic(
                    CreateOncePublicationStage::RenameBufferConstruction,
                    source,
                    destination_path,
                    None,
                    &evidence,
                    "create-once aligned rename information length overflowed",
                )
            })?;
        let backing_bytes = aligned_words
            .checked_mul(std::mem::size_of::<usize>())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                CreateOncePublicationFailure::semantic(
                    CreateOncePublicationStage::RenameBufferConstruction,
                    source,
                    destination_path,
                    None,
                    &evidence,
                    "create-once aligned rename information is not representable",
                )
            })?;
        let information_bytes = u32::try_from(meaningful_bytes).map_err(|_| {
            CreateOncePublicationFailure::semantic(
                CreateOncePublicationStage::RenameBufferConstruction,
                source,
                destination_path,
                None,
                &evidence,
                "create-once rename information is not representable",
            )
        })?;
        let mut layout = Self {
            words: vec![0_usize; aligned_words],
            destination_name_bytes,
            information_bytes,
            backing_bytes,
        };
        let rename = layout.words.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        // SAFETY: the native-word allocation is fully zero initialized and
        // covers the declared structure, the complete destination, one
        // explicit UTF-16 NUL, and native alignment padding.
        unsafe {
            (*rename).Anonymous.ReplaceIfExists = false;
            (*rename).RootDirectory = ptr::null_mut();
            (*rename).FileNameLength = destination_name_bytes;
            let filename = ptr::addr_of_mut!((*rename).FileName).cast::<u16>();
            ptr::copy_nonoverlapping(destination.as_ptr(), filename, destination.len());
            *filename.add(destination.len()) = 0;
        }
        Ok(layout)
    }

    fn as_mut_ptr(&mut self) -> *mut FILE_RENAME_INFO {
        self.words.as_mut_ptr().cast()
    }
}

#[derive(Debug)]
struct CreateOncePublicationObservation {
    source_path: PathBuf,
    final_path: PathBuf,
    identity_before: CreateOnceFileIdentity,
    identity_after: CreateOnceFileIdentity,
    source_link_count: u32,
    final_link_count: u32,
    destination_name_bytes: u32,
    information_bytes: u32,
    backing_bytes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CreateOnceHandleLocation {
    path: PathBuf,
    parent_units: Vec<u16>,
    leaf_units: Vec<u16>,
}

impl CreateOnceHandleLocation {
    fn from_normalized_nt_path(path: PathBuf) -> Result<Self, &'static str> {
        use std::os::windows::ffi::OsStrExt;

        let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if units.is_empty() || units.contains(&0) {
            return Err("normalized NT handle path is empty or contains an embedded NUL");
        }
        let separator = units
            .iter()
            .rposition(|unit| *unit == u16::from(b'\\'))
            .ok_or("normalized NT handle path has no parent separator")?;
        if separator == 0 || separator + 1 >= units.len() {
            return Err("normalized NT handle path has no complete parent and leaf");
        }
        let parent_units = units[..separator].to_vec();
        let leaf_units = units[separator + 1..].to_vec();
        if is_dot_component(&leaf_units) {
            return Err("normalized NT handle path has a dot leaf");
        }
        Ok(Self {
            path,
            parent_units,
            leaf_units,
        })
    }
}

fn create_once_requested_leaf(path: &Path) -> Result<Vec<u16>, &'static str> {
    use std::os::windows::ffi::OsStrExt;

    let leaf = path
        .file_name()
        .ok_or("create-once path has no final component")?
        .encode_wide()
        .collect::<Vec<_>>();
    if leaf.is_empty()
        || leaf.contains(&0)
        || leaf
            .iter()
            .any(|unit| *unit == u16::from(b'\\') || *unit == u16::from(b'/'))
        || is_dot_component(&leaf)
    {
        return Err("create-once path has an invalid final component");
    }
    Ok(leaf)
}

fn is_dot_component(units: &[u16]) -> bool {
    units == [u16::from(b'.')] || units == [u16::from(b'.'), u16::from(b'.')]
}

pub(crate) fn publish_create_once_atomically(
    source: CreateOnceStagingFile,
    destination: &Path,
) -> Result<(), CreateOncePublicationFailure> {
    publish_create_once_atomically_observed(source, destination).map(|_| ())
}

fn publish_create_once_atomically_observed(
    source: CreateOnceStagingFile,
    destination: &Path,
) -> Result<CreateOncePublicationObservation, CreateOncePublicationFailure> {
    use std::os::windows::io::AsRawHandle;

    let mut evidence = CreateOncePublicationEvidence::default();
    if source.path.parent() != destination.parent() {
        return Err(CreateOncePublicationFailure::semantic(
            CreateOncePublicationStage::PathValidation,
            &source.path,
            destination,
            None,
            &evidence,
            "create-once source and destination must have the same parent",
        ));
    }
    if !source.path.is_absolute() || !destination.is_absolute() {
        return Err(CreateOncePublicationFailure::semantic(
            CreateOncePublicationStage::PathValidation,
            &source.path,
            destination,
            None,
            &evidence,
            "create-once source and destination must be absolute paths",
        ));
    }
    let mut information = CreateOnceRenameInformation::new(&source.path, destination)?;
    let expected_source_leaf = create_once_requested_leaf(&source.path).map_err(|detail| {
        CreateOncePublicationFailure::semantic(
            CreateOncePublicationStage::PathValidation,
            &source.path,
            destination,
            Some(&information),
            &evidence,
            detail,
        )
    })?;
    let expected_final_leaf = create_once_requested_leaf(destination).map_err(|detail| {
        CreateOncePublicationFailure::semantic(
            CreateOncePublicationStage::DestinationEncoding,
            &source.path,
            destination,
            Some(&information),
            &evidence,
            detail,
        )
    })?;
    let source_path =
        create_once_normalized_nt_path(source.file.as_raw_handle() as _).map_err(|error| {
            CreateOncePublicationFailure::io(
                CreateOncePublicationStage::SourceNameBeforeRenameReadback,
                &source.path,
                destination,
                Some(&information),
                &evidence,
                error,
            )
        })?;
    evidence.observed_source_path = Some(source_path.clone());
    let source_location =
        CreateOnceHandleLocation::from_normalized_nt_path(source_path).map_err(|detail| {
            CreateOncePublicationFailure::semantic(
                CreateOncePublicationStage::SourceNameBeforeRenameParse,
                &source.path,
                destination,
                Some(&information),
                &evidence,
                detail,
            )
        })?;
    if source_location.leaf_units != expected_source_leaf {
        return Err(CreateOncePublicationFailure::semantic(
            CreateOncePublicationStage::SourceLeafBeforeRenameVerification,
            &source.path,
            destination,
            Some(&information),
            &evidence,
            "retained staging handle did not resolve to the exact staging leaf",
        ));
    }
    let identity_before =
        create_once_file_identity(source.file.as_raw_handle() as _).map_err(|error| {
            CreateOncePublicationFailure::io(
                CreateOncePublicationStage::SourceIdentityBeforeRename,
                &source.path,
                destination,
                Some(&information),
                &evidence,
                error,
            )
        })?;
    evidence.source_identity = Some(identity_before);
    let source_link_count =
        create_once_link_count(source.file.as_raw_handle() as _).map_err(|error| {
            CreateOncePublicationFailure::io(
                CreateOncePublicationStage::SourceLinkCountBeforeRename,
                &source.path,
                destination,
                Some(&information),
                &evidence,
                error,
            )
        })?;
    evidence.source_link_count = Some(source_link_count);
    if source_link_count != 1 {
        return Err(CreateOncePublicationFailure::semantic(
            CreateOncePublicationStage::SourceLinkCountBeforeRenameVerification,
            &source.path,
            destination,
            Some(&information),
            &evidence,
            format!(
                "retained staging file must have exactly one link before rename; observed {source_link_count}"
            ),
        ));
    }
    let rename = information.as_mut_ptr();
    // SAFETY: the owned CREATE_NEW handle remains live for this synchronous
    // no-replace rename and carries the one-use DELETE access requested when
    // the staging leaf was created. The fully initialized aligned buffer is
    // live and its advertised size includes the explicit NUL and padding.
    if unsafe {
        SetFileInformationByHandle(
            source.file.as_raw_handle() as _,
            FileRenameInfo,
            rename.cast(),
            information.backing_bytes,
        )
    } == 0
    {
        return Err(CreateOncePublicationFailure::io(
            CreateOncePublicationStage::Rename,
            &source.path,
            destination,
            Some(&information),
            &evidence,
            io::Error::last_os_error(),
        ));
    }
    evidence.rename_committed = true;

    // Collect all bounded post-rename evidence before selecting the primary
    // semantic result. No path is reopened: every observation comes from the
    // same authoritative handle that performed the rename.
    let final_path_result = create_once_normalized_nt_path(source.file.as_raw_handle() as _);
    if let Ok(path) = &final_path_result {
        evidence.observed_final_path = Some(path.clone());
    }
    let identity_after_result = create_once_file_identity(source.file.as_raw_handle() as _);
    if let Ok(identity) = &identity_after_result {
        evidence.final_identity = Some(*identity);
    }
    let final_link_count_result = create_once_link_count(source.file.as_raw_handle() as _);
    if let Ok(link_count) = &final_link_count_result {
        evidence.final_link_count = Some(*link_count);
    }

    let verification = verify_create_once_postcondition(
        &source.path,
        destination,
        &information,
        &evidence,
        &source_location,
        &expected_final_leaf,
        identity_before,
        final_path_result,
        identity_after_result,
        final_link_count_result,
    );
    // Once SetFileInformationByHandle commits, always attempt the final
    // durability barrier. A semantic/native proof failure remains primary;
    // a simultaneous flush failure is retained as secondary evidence.
    let final_sync = source.file.sync_all();
    let (final_location, identity_after, final_link_count) = match (verification, final_sync) {
        (Ok(observation), Ok(())) => observation,
        (Ok(_), Err(error)) => {
            return Err(CreateOncePublicationFailure::io(
                CreateOncePublicationStage::FinalSync,
                &source.path,
                destination,
                Some(&information),
                &evidence,
                error,
            ));
        }
        (Err(failure), Ok(())) => return Err(failure),
        (Err(failure), Err(error)) => {
            return Err(failure.with_secondary(CreateOncePublicationStage::FinalSync, error));
        }
    };
    Ok(CreateOncePublicationObservation {
        source_path: source_location.path,
        final_path: final_location.path,
        identity_before,
        identity_after,
        source_link_count,
        final_link_count,
        destination_name_bytes: information.destination_name_bytes,
        information_bytes: information.information_bytes,
        backing_bytes: information.backing_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_create_once_postcondition(
    source: &Path,
    destination: &Path,
    information: &CreateOnceRenameInformation,
    evidence: &CreateOncePublicationEvidence,
    source_location: &CreateOnceHandleLocation,
    expected_final_leaf: &[u16],
    identity_before: CreateOnceFileIdentity,
    final_path_result: Result<PathBuf, io::Error>,
    identity_after_result: Result<CreateOnceFileIdentity, io::Error>,
    final_link_count_result: Result<u32, io::Error>,
) -> Result<(CreateOnceHandleLocation, CreateOnceFileIdentity, u32), CreateOncePublicationFailure> {
    let final_path = final_path_result.map_err(|error| {
        CreateOncePublicationFailure::io(
            CreateOncePublicationStage::FinalNameAfterRenameReadback,
            source,
            destination,
            Some(information),
            evidence,
            error,
        )
    })?;
    let final_location =
        CreateOnceHandleLocation::from_normalized_nt_path(final_path).map_err(|detail| {
            CreateOncePublicationFailure::semantic(
                CreateOncePublicationStage::FinalNameAfterRenameParse,
                source,
                destination,
                Some(information),
                evidence,
                detail,
            )
        })?;
    let identity_after = identity_after_result.map_err(|error| {
        CreateOncePublicationFailure::io(
            CreateOncePublicationStage::SourceIdentityAfterRename,
            source,
            destination,
            Some(information),
            evidence,
            error,
        )
    })?;
    let final_link_count = final_link_count_result.map_err(|error| {
        CreateOncePublicationFailure::io(
            CreateOncePublicationStage::FinalLinkCountAfterRename,
            source,
            destination,
            Some(information),
            evidence,
            error,
        )
    })?;
    verify_create_once_transition(
        source_location,
        &final_location,
        expected_final_leaf,
        identity_before,
        identity_after,
        final_link_count,
    )
    .map_err(|(stage, detail)| {
        CreateOncePublicationFailure::semantic(
            stage,
            source,
            destination,
            Some(information),
            evidence,
            detail,
        )
    })?;
    Ok((final_location, identity_after, final_link_count))
}

fn verify_create_once_transition(
    source_location: &CreateOnceHandleLocation,
    final_location: &CreateOnceHandleLocation,
    expected_final_leaf: &[u16],
    identity_before: CreateOnceFileIdentity,
    identity_after: CreateOnceFileIdentity,
    final_link_count: u32,
) -> Result<(), (CreateOncePublicationStage, String)> {
    if identity_before.volume_serial != identity_after.volume_serial {
        return Err((
            CreateOncePublicationStage::VolumeIdentityVerification,
            format!(
                "retained staging file volume changed across rename: before={} after={}",
                identity_before.volume_serial, identity_after.volume_serial
            ),
        ));
    }
    if identity_before.file_id != identity_after.file_id {
        return Err((
            CreateOncePublicationStage::FileIdentityVerification,
            format!(
                "retained staging file 128-bit identity changed across rename: before={identity_before:?} after={identity_after:?}"
            ),
        ));
    }
    if final_link_count != 1 {
        return Err((
            CreateOncePublicationStage::FinalLinkCountAfterRenameVerification,
            format!(
                "retained final file must have exactly one link after rename; observed {final_link_count}"
            ),
        ));
    }
    if source_location.parent_units != final_location.parent_units {
        return Err((
            CreateOncePublicationStage::FinalParentVerification,
            "retained handle moved outside its canonical pre-rename parent".to_owned(),
        ));
    }
    if final_location.leaf_units != expected_final_leaf {
        return Err((
            CreateOncePublicationStage::FinalComponentVerification,
            "retained handle did not resolve to the exact requested final component".to_owned(),
        ));
    }
    Ok(())
}

fn create_once_file_identity(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<CreateOnceFileIdentity, io::Error> {
    // SAFETY: zero is a valid initial state for this output-only POD.
    let mut information = unsafe { std::mem::zeroed::<FILE_ID_INFO>() };
    // SAFETY: handle is the live retained staging/final file and information
    // is writable for the documented structure size.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut information).cast::<c_void>(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "FILE_ID_INFO size is not representable",
                )
            })?,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(CreateOnceFileIdentity {
        volume_serial: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    })
}

fn create_once_link_count(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<u32, io::Error> {
    // SAFETY: zero is a valid initial state for this output-only POD.
    let mut information = unsafe { std::mem::zeroed::<FILE_STANDARD_INFO>() };
    // SAFETY: handle is the live retained staging/final file and information
    // is writable for the documented structure size.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&raw mut information).cast::<c_void>(),
            u32::try_from(std::mem::size_of::<FILE_STANDARD_INFO>()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "FILE_STANDARD_INFO size is not representable",
                )
            })?,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(information.NumberOfLinks)
}

fn create_once_normalized_nt_path(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<PathBuf, io::Error> {
    use std::os::windows::ffi::OsStringExt;

    const NAME_QUERY_FLAGS: u32 = FILE_NAME_NORMALIZED | VOLUME_NAME_NT;
    // SAFETY: the sizing form writes no buffer and returns the required UTF-16
    // units, including terminator storage when the supplied buffer is short.
    let required =
        unsafe { GetFinalPathNameByHandleW(handle, ptr::null_mut(), 0, NAME_QUERY_FLAGS) };
    if required == 0 {
        return Err(io::Error::last_os_error());
    }
    let capacity = usize::try_from(required)
        .ok()
        .and_then(|units| units.checked_add(1))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "create-once final path length is not representable",
            )
        })?;
    let capacity_u32 = u32::try_from(capacity).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "create-once final path buffer is not representable",
        )
    })?;
    let mut buffer = vec![0_u16; capacity];
    // SAFETY: buffer is writable for capacity_u32 UTF-16 units and handle is
    // the live authoritative file object retained across rename.
    let written = unsafe {
        GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), capacity_u32, NAME_QUERY_FLAGS)
    };
    if written == 0 {
        return Err(io::Error::last_os_error());
    }
    if written >= capacity_u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "normalized NT handle path grew during readback: capacity={capacity_u32} required={written}"
            ),
        ));
    }
    buffer.truncate(written as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct CreateOncePublicationObservationForTest {
    pub(crate) source_path: PathBuf,
    pub(crate) final_path: PathBuf,
    pub(crate) identity_unchanged: bool,
    pub(crate) source_link_count: u32,
    pub(crate) final_link_count: u32,
    pub(crate) destination_name_bytes: u32,
    pub(crate) information_bytes: u32,
    pub(crate) backing_bytes: u32,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct CreateOnceRenameLayoutForTest {
    pub(crate) destination_name_bytes: u32,
    pub(crate) information_bytes: u32,
    pub(crate) backing_bytes: u32,
}

#[cfg(test)]
pub(crate) fn create_once_rename_layout_for_test(
    source: &Path,
    destination: &Path,
) -> Result<CreateOnceRenameLayoutForTest, CreateOncePublicationFailure> {
    CreateOnceRenameInformation::new(source, destination).map(|layout| {
        CreateOnceRenameLayoutForTest {
            destination_name_bytes: layout.destination_name_bytes,
            information_bytes: layout.information_bytes,
            backing_bytes: layout.backing_bytes,
        }
    })
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_create_once_transition_for_test(
    observed_source: &Path,
    observed_final: &Path,
    requested_source: &Path,
    requested_final: &Path,
    volume_before: u64,
    volume_after: u64,
    file_id_before: [u8; 16],
    file_id_after: [u8; 16],
    source_link_count: u32,
    final_link_count: u32,
) -> Result<(), CreateOncePublicationStage> {
    let source_location =
        CreateOnceHandleLocation::from_normalized_nt_path(observed_source.to_owned())
            .map_err(|_| CreateOncePublicationStage::SourceNameBeforeRenameParse)?;
    let final_location =
        CreateOnceHandleLocation::from_normalized_nt_path(observed_final.to_owned())
            .map_err(|_| CreateOncePublicationStage::FinalNameAfterRenameParse)?;
    let expected_source_leaf = create_once_requested_leaf(requested_source)
        .map_err(|_| CreateOncePublicationStage::PathValidation)?;
    let expected_final_leaf = create_once_requested_leaf(requested_final)
        .map_err(|_| CreateOncePublicationStage::DestinationEncoding)?;
    if source_location.leaf_units.as_slice() != expected_source_leaf.as_slice() {
        return Err(CreateOncePublicationStage::SourceLeafBeforeRenameVerification);
    }
    if !matches!(source_link_count, 1) {
        return Err(CreateOncePublicationStage::SourceLinkCountBeforeRenameVerification);
    }
    verify_create_once_transition(
        &source_location,
        &final_location,
        &expected_final_leaf,
        CreateOnceFileIdentity {
            volume_serial: volume_before,
            file_id: file_id_before,
        },
        CreateOnceFileIdentity {
            volume_serial: volume_after,
            file_id: file_id_after,
        },
        final_link_count,
    )
    .map_err(|(stage, _)| stage)
}

#[cfg(test)]
pub(crate) fn publish_create_once_atomically_for_test(
    source: CreateOnceStagingFile,
    destination: &Path,
) -> Result<CreateOncePublicationObservationForTest, CreateOncePublicationFailure> {
    publish_create_once_atomically_observed(source, destination).map(|observation| {
        CreateOncePublicationObservationForTest {
            source_path: observation.source_path,
            final_path: observation.final_path,
            identity_unchanged: observation.identity_before == observation.identity_after,
            source_link_count: observation.source_link_count,
            final_link_count: observation.final_link_count,
            destination_name_bytes: observation.destination_name_bytes,
            information_bytes: observation.information_bytes,
            backing_bytes: observation.backing_bytes,
        }
    })
}

fn provider_generation() -> String {
    format!("{}:{}", env!("CARGO_PKG_VERSION"), crate::SOURCE_COMMIT)
}

pub(crate) fn boot_identity() -> Result<String, String> {
    #[repr(C)]
    struct SystemTimeOfDayInformation {
        boot_time: i64,
        current_time: i64,
        time_zone_bias: i64,
        current_time_zone_id: u32,
        reserved: u32,
        boot_time_bias: u64,
        sleep_time_bias: u64,
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemInformation(
            system_information_class: u32,
            system_information: *mut c_void,
            system_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    let mut information = std::mem::MaybeUninit::<SystemTimeOfDayInformation>::zeroed();
    let mut returned = 0_u32;
    // SystemTimeOfDayInformation is the native class whose BootTime value is
    // stable for one boot and changes across every reboot. This avoids the
    // collision and clock-skew ambiguity of subtracting GetTickCount64 from
    // wall time.
    let status = unsafe {
        NtQuerySystemInformation(
            3,
            information.as_mut_ptr().cast(),
            u32::try_from(std::mem::size_of::<SystemTimeOfDayInformation>())
                .map_err(|_| "system time-of-day structure exceeds Win32 length".to_owned())?,
            &raw mut returned,
        )
    };
    if status < 0
        || usize::try_from(returned).ok() != Some(std::mem::size_of::<SystemTimeOfDayInformation>())
    {
        Err(format!(
            "NtQuerySystemInformation(SystemTimeOfDayInformation) failed with NTSTATUS {status:#010x} and length {returned}"
        ))
    } else {
        Ok(unsafe { information.assume_init() }.boot_time.to_string())
    }
}

pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
