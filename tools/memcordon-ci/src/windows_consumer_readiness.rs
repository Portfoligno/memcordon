//! Positive Windows workload assessment. Diagnostics cannot satisfy these cases.
use crate::{CiError, Result};
use memcordon_core::ChildTermination;
use memcordon_core::execution_facts::{CleanupStateV1, OutcomeKindV1};
use memcordon_core::result_v3::{ReleaseKnowledgeV3, ResultV3, RuntimeExecutionV3};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[path = "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/descriptor.rs"]
pub mod descriptor;
#[path = "windows_gate_label.rs"]
#[cfg(windows)]
mod gate_label;
#[cfg(windows)]
#[path = "windows_gate_namespace.rs"]
mod gate_namespace;
#[cfg(windows)]
#[path = "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/controller_gate_resolution.rs"]
mod gate_resolution;
#[cfg(windows)]
#[path = "windows_gate_security.rs"]
mod gate_security;
#[cfg(windows)]
#[path = "windows_guardian_query.rs"]
mod guardian_query;
#[path = "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/matched_control_input_record.rs"]
pub mod matched_control_input_record;
#[path = "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/matched_control_report.rs"]
pub mod matched_control_report;

/// A scoped measurement is positive only after every declared operation completes.
/// Matching stopped failures remain observations, never positive coverage.
pub fn matched_owned_positive(comparison: &descriptor::matched::Comparison) -> bool {
    matched_control_report::positive_coverage(comparison)
        == matched_control_report::PositiveCoverage::Complete
}

/// Includes separately named original application refusals. This pure scope
/// decision does not settle capture, actual status, ACK or native-owner debt.
pub fn matched_scope_validated(comparison: &descriptor::matched::Comparison) -> bool {
    matched_control_report::scoped_assessment(comparison).0
        != matched_control_report::ScopeValidation::Mismatch
}

/// Responsibility for deleting this controller's original registry projection.
/// Supplied handles and Arc counts do not establish lifetime ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryProjectionLifetime {
    ExecutionOwned,
    ExperimentBorrowed,
}

impl RegistryProjectionLifetime {
    /// Work verification must never gate the actual owner's independent cleanup
    /// budget. Borrowers verify for future use and never delete the namespace.
    pub fn finish_execution<Owner>(
        self,
        owner: &mut Owner,
        verify_borrowed: impl FnOnce(&mut Owner) -> Result<()>,
        retire_owned: impl FnOnce(&mut Owner) -> Result<()>,
    ) -> Result<()> {
        match self {
            Self::ExecutionOwned => retire_owned(owner),
            Self::ExperimentBorrowed => verify_borrowed(owner),
        }
    }
}

/// Diagnostic provenance from the original broker command, never a child
/// outcome, equivalence result, or permission to release retained custody.
pub fn matched_broker_command_failure(
    matched: bool,
    observed_status: Option<std::process::ExitStatus>,
    capture_complete: bool,
    stderr: &[u8],
) -> Option<CiError> {
    let status = observed_status?;
    if !matched || status.success() {
        return None;
    }
    // Keep the final broker cause even when preceding child diagnostics fill
    // the capture. Lossy UTF8 expands at most threefold, still below 8 KiB.
    let start = stderr.len().saturating_sub(2048);
    let excerpt = String::from_utf8_lossy(&stderr[start..]);
    Some(CiError::Message(format!(
        "matched broker command failed: status={status}; code={:?}; capture-complete={capture_complete}; stderr-tail-truncated={}: {excerpt}",
        status.code(),
        start != 0,
    )))
}

pub fn prioritize_matched_broker_failure(
    broker: Option<CiError>,
    assessed: Result<()>,
) -> Result<()> {
    match (broker, assessed) {
        (Some(primary), Err(secondary)) => Err(CiError::LaneFailures {
            primary: Box::new(primary),
            secondary: Box::new(secondary),
        }),
        (Some(primary), Ok(())) => Err(primary),
        (None, assessed) => assessed,
    }
}

pub fn matched_broker_outcome_failure(
    matched: bool,
    outcome: &std::result::Result<
        memcordon_testkit::ObservedOutput,
        memcordon_testkit::ProcessTestError,
    >,
) -> Option<CiError> {
    let observed = |output: &memcordon_testkit::ObservedOutput| {
        matched_broker_command_failure(matched, Some(output.status), true, &output.stderr)
    };
    let mut error = match outcome {
        Ok(output) => return observed(output),
        Err(error) => error,
    };
    loop {
        match error {
            memcordon_testkit::ProcessTestError::ApplicationEnded {
                settlement: Ok(output),
                ..
            } => return observed(output),
            memcordon_testkit::ProcessTestError::ApplicationEnded {
                settlement: Err(nested),
                ..
            } => error = nested,
            memcordon_testkit::ProcessTestError::Callback {
                observed_status,
                capture_complete,
                stderr,
                ..
            } => {
                return matched_broker_command_failure(
                    matched,
                    *observed_status,
                    *capture_complete,
                    stderr,
                );
            }
            // Controller termination, missing observation, and other failures
            // remain their existing errors; they do not supply a broker exit.
            _ => return None,
        }
    }
}

pub fn external_provider_probe_path(output: &Path, installed_agent: &Path) -> Result<PathBuf> {
    let installed = installed_agent
        .parent()
        .ok_or_else(|| CiError::Message("installed provider root absent".into()))?;
    if !output.is_absolute()
        || !installed_agent.is_absolute()
        || output
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        || installed_agent
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        || output.starts_with(installed)
    {
        return Err(CiError::Message(
            "fixture provider probe must be outside installation custody".into(),
        ));
    }
    Ok(output.join("protected-provider-probe"))
}
#[path = "windows_post_listener_end.rs"]
pub mod post_listener_end;
#[cfg(windows)]
#[path = "windows_start_gate_policy.rs"]
mod start_gate_policy;
#[cfg(windows)]
#[path = "windows_toolchain_sampling.rs"]
mod toolchain_sampling;

pub fn validate_toolchain_inventory(
    toolchain: &descriptor::Toolchain,
    measured: &[descriptor::ToolchainImage],
) -> Result<()> {
    toolchain
        .validate_selected_images()
        .map_err(CiError::Message)?;
    if toolchain.selected_images != measured {
        return Err(CiError::Message(
            "native compiler descriptor differs from measured executable inventory".into(),
        ));
    }
    Ok(())
}

#[path = "windows_loader_event_diagnostics.rs"]
pub mod loader_event_diagnostics;

#[cfg(windows)]
#[path = "windows_workload_diagnostic.rs"]
mod workload_diagnostic;

#[cfg(windows)]
#[path = "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/fixture_environment.rs"]
pub(crate) mod fixture_environment;

/// PID ancestry is meaningful only for processes that can belong to this
/// original root lifetime. A preexisting process cannot become its descendant
/// when an intermediate parent PID is reused in a later snapshot.
pub fn rooted_process_depth(
    candidate: (u32, u128),
    root: (u32, u128),
    parents: &std::collections::BTreeMap<u32, u32>,
) -> Option<usize> {
    if candidate.1 < root.1 || (candidate.0 == root.0 && candidate.1 != root.1) {
        return None;
    }
    let mut current = candidate.0;
    for depth in 0..=16 {
        if current == root.0 {
            return Some(depth);
        }
        current = *parents.get(&current)?;
    }
    None
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseKey {
    pub family: String,
    pub scenario: String,
}

pub fn controller_case_directory(output_directory: &Path, key: &CaseKey) -> PathBuf {
    output_directory.join(&key.family).join(&key.scenario)
}

pub fn loader_fileio_requested(
    key: &CaseKey,
    case: descriptor::Case,
    provider_input_experiment: bool,
) -> bool {
    key.family == "W-JOINT"
        && case == descriptor::Case::Joint
        && (key.scenario == "restricted"
            || (provider_input_experiment && key.scenario == "ordinary"))
}

pub fn loader_fileio_retention(
    key: &CaseKey,
    case: descriptor::Case,
    provider_input_experiment: bool,
) -> memcordon_platform::windows_fileio_record::RetentionMode {
    use memcordon_platform::windows_fileio_record::RetentionMode;
    if key.family == "W-JOINT"
        && case == descriptor::Case::Joint
        && key.scenario == "ordinary"
        && provider_input_experiment
    {
        RetentionMode::RollingCompleted
    } else {
        RetentionMode::Prefix
    }
}

/// Finite experiment facts, retaining the producer's original trust domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderExperimentRecord {
    ListenerTrace,
    PeerListenerTrace,
    NativeFileRequests,
    PeerNativeFileRequests,
    PeerSpawnTrace,
    PeerStdoutRecord,
    PeerStdout,
    StartupTrace,
    PeerStartupTrace,
    InputProbes,
    PeerInputProbes,
    InputRejection,
    PeerInputRejection,
    NativeListener,
    NativeTcpPeer,
    LoaderFileIo,
    CallbackFailure,
    CallbackStdout,
    CallbackStderr,
    FailedFrontend,
    FailedTerminalObservation,
    GuardianQuery,
    GuardianStdout,
    GuardianStderr,
}

impl ProviderExperimentRecord {
    pub const ALL: [Self; 24] = [
        Self::ListenerTrace,
        Self::PeerListenerTrace,
        Self::NativeFileRequests,
        Self::PeerNativeFileRequests,
        Self::PeerSpawnTrace,
        Self::PeerStdoutRecord,
        Self::PeerStdout,
        Self::StartupTrace,
        Self::PeerStartupTrace,
        Self::InputProbes,
        Self::PeerInputProbes,
        Self::InputRejection,
        Self::PeerInputRejection,
        Self::NativeListener,
        Self::NativeTcpPeer,
        Self::LoaderFileIo,
        Self::CallbackFailure,
        Self::CallbackStdout,
        Self::CallbackStderr,
        Self::FailedFrontend,
        Self::FailedTerminalObservation,
        Self::GuardianQuery,
        Self::GuardianStdout,
        Self::GuardianStderr,
    ];

    pub fn leaf(self) -> &'static str {
        match self {
            Self::ListenerTrace => "listener-call-trace.json",
            Self::PeerListenerTrace => "peer-listener-call-trace.json",
            Self::NativeFileRequests => "listener-native-file-requests.json",
            Self::PeerNativeFileRequests => "peer-listener-native-file-requests.json",
            Self::PeerSpawnTrace => "peer-spawn-call-trace.json",
            Self::PeerStdoutRecord => "tcp-peer-stdout.json",
            Self::PeerStdout => "tcp-peer-stdout.bin",
            Self::StartupTrace => "winsock-startup-trace.json",
            Self::PeerStartupTrace => "peer-winsock-startup-trace.json",
            Self::InputProbes => "provider-input-probes.json",
            Self::PeerInputProbes => "peer-provider-input-probes.json",
            Self::InputRejection => "provider-input-target-rejection.json",
            Self::PeerInputRejection => "peer-provider-input-target-rejection.json",
            Self::NativeListener => "native-listener.json",
            Self::NativeTcpPeer => "native-tcp-peer.json",
            Self::LoaderFileIo => "result.loader-fileio.json",
            Self::CallbackFailure => "result.callback-failure.json",
            Self::CallbackStdout => "result.stdout.bin",
            Self::CallbackStderr => "result.stderr.bin",
            Self::FailedFrontend => "result.failed-frontend.json",
            Self::FailedTerminalObservation => "result.failed-terminal-observation.json",
            Self::GuardianQuery => "result.guardian-query.json",
            Self::GuardianStdout => "result.guardian-query.stdout.bin",
            Self::GuardianStderr => "result.guardian-query.stderr.bin",
        }
    }

    /// These are separately bounded copies of existing controller captures,
    /// not a change to the producer's larger stream/record limits.
    pub fn capture_ceiling(self) -> Option<usize> {
        match self {
            Self::CallbackFailure
            | Self::CallbackStdout
            | Self::CallbackStderr
            | Self::FailedFrontend
            | Self::FailedTerminalObservation
            | Self::GuardianQuery
            | Self::GuardianStdout
            | Self::GuardianStderr
            | Self::PeerStdout => Some(64 * 1024),
            _ => None,
        }
    }

    pub fn capture_retention(
        self,
        source_bytes: Option<u64>,
        copied: Option<&[u8]>,
    ) -> serde_json::Value {
        let ceiling = self.capture_ceiling();
        let copied = copied.filter(|bytes| ceiling.is_some_and(|cap| bytes.len() <= cap));
        let complete = copied.is_some_and(|bytes| {
            source_bytes == Some(bytes.len() as u64)
                && ceiling.is_some_and(|cap| bytes.len() <= cap)
        });
        let state = if source_bytes.is_none() {
            "not-present"
        } else if source_bytes
            .zip(ceiling)
            .is_some_and(|(size, cap)| size > cap as u64)
        {
            "oversize-not-copied"
        } else if complete {
            "copied"
        } else {
            "not-completely-copied"
        };
        serde_json::json!({"leaf":self.leaf(),"copy_ceiling_bytes":ceiling,"source_metadata_bytes":source_bytes,
            "retained_bytes":copied.map(<[u8]>::len),"retained_sha256":copied.map(crate::windows_causal_acceptance::sha256),
            "file_copy_complete":complete,"state":state,"producer_capture_complete":null,
            "producer_capture_completeness":"not inferred; consult original callback-failure, guardian-query or owned-peer-stdout record",
            "acceptance_authority":false})
    }

    pub fn source_path(
        self,
        controller_output: &Path,
        key: &CaseKey,
        fixture_output: &Path,
    ) -> PathBuf {
        match self {
            Self::NativeListener
            | Self::NativeTcpPeer
            | Self::LoaderFileIo
            | Self::CallbackFailure
            | Self::CallbackStdout
            | Self::CallbackStderr
            | Self::FailedFrontend
            | Self::FailedTerminalObservation
            | Self::GuardianQuery
            | Self::GuardianStdout
            | Self::GuardianStderr => {
                controller_case_directory(controller_output, key).join(self.leaf())
            }
            _ => fixture_output.join(self.leaf()),
        }
    }
}

/// The native caller retains original held-file custody through each synchronous
/// copy. This shared finite algorithm supplies no file or mutation authority.
pub fn retain_provider_experiment_facts(
    controller_output: &Path,
    key: &CaseKey,
    fixture_output: &Path,
    facts_dir: &Path,
    mut retain_file: impl FnMut(&Path, &Path, u64) -> Result<Vec<u8>>,
    mut publish_index: impl FnMut(&Path, &[u8]) -> Result<()>,
) -> Result<()> {
    use std::{fs, io};
    fs::create_dir(facts_dir)?;
    let mut capture_index = Vec::new();
    for record in ProviderExperimentRecord::ALL {
        let path = record.source_path(controller_output, key, fixture_output);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                let maximum = record.capture_ceiling().unwrap_or(64 * 1024);
                if record
                    .capture_ceiling()
                    .is_some_and(|cap| metadata.len() > cap as u64)
                {
                    capture_index.push(record.capture_retention(Some(metadata.len()), None));
                    continue;
                }
                let bytes = retain_file(&path, &facts_dir.join(record.leaf()), maximum as u64)?;
                if record.capture_ceiling().is_some() {
                    capture_index
                        .push(record.capture_retention(Some(metadata.len()), Some(&bytes)));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if record.capture_ceiling().is_some() {
                    capture_index.push(record.capture_retention(None, None));
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    let index = serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.provider-controller-capture-retention","revision":1,
        "diagnostic_only":true,"acceptance_authority":false,"captures":capture_index,
    }))?;
    if index.len() > 8 * 1024 {
        return Err(CiError::Message(
            "provider capture retention index exceeds8KiB".into(),
        ));
    }
    publish_index(&facts_dir.join("controller-capture-retention.json"), &index)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseInput {
    pub key: CaseKey,
    pub descriptor: descriptor::Descriptor,
    pub descriptor_path: PathBuf,
    pub workload_request: PathBuf,
    pub expected_token: TokenObservation,
}

pub use descriptor::gate_precondition::TokenObservation;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteInput {
    pub format: String,
    pub revision: u32,
    pub cases: Vec<CaseInput>,
}

/// Explicit provisioning inputs, independent of consumer source or ambient
/// installation. The source/image and toolchain paths are measured by the owner.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsReadinessPlan {
    pub request_template: PathBuf,
    pub toolchain: descriptor::Toolchain,
    pub candidate_output_root: PathBuf,
    pub protected_write_probes: Vec<PathBuf>,
}

#[cfg(windows)]
pub fn prepare_installed(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    plan: &WindowsReadinessPlan,
    input: &Path,
) -> Result<()> {
    native::prepare(
        config,
        plan,
        input,
        crate::windows_installed_cases::WindowsLeaseDeadlines::finite_default().work,
    )
}

#[cfg(not(windows))]
pub fn prepare_installed(
    _: &crate::windows_installed_cases::InstalledWindowsPayload,
    _: &WindowsReadinessPlan,
    _: &Path,
) -> Result<()> {
    Err(CiError::Message(
        "Windows readiness provisioning requires a native Windows host".into(),
    ))
}

#[cfg(windows)]
pub fn provision_from_source(
    root: &Path,
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
) -> Result<()> {
    provision_from_source_until(
        root,
        config,
        crate::windows_installed_cases::WindowsLeaseDeadlines::finite_default().work,
    )
}

#[cfg(windows)]
pub fn provision_from_source_until(
    root: &Path,
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    work_deadline: std::time::Instant,
) -> Result<()> {
    native::provision(root, config, work_deadline)
}

#[cfg(windows)]
pub(crate) fn cleanup_provider_probe(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
) -> Result<()> {
    native::cleanup_provider_probe(config)
}

#[cfg(not(windows))]
pub fn provision_from_source(
    _: &Path,
    _: &crate::windows_installed_cases::InstalledWindowsPayload,
) -> Result<()> {
    Err(CiError::Message(
        "Windows readiness provisioning requires native Windows".into(),
    ))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseAssessment {
    pub revision: u32,
    pub key: CaseKey,
    pub contract: crate::windows_readiness_policy::CaseContract,
    pub behavior: std::result::Result<(), String>,
    pub collection: std::result::Result<(), String>,
    pub retirement: std::result::Result<(), String>,
    pub descriptor_sha256: String,
    pub result_sha256: Option<String>,
    pub stdout_sha256: Option<String>,
    pub stderr_sha256: Option<String>,
    pub transcript_sha256: Option<String>,
    pub request_sha256: Option<String>,
    pub provider_request_sha256: Option<String>,
    pub terminal_observation_sha256: Option<String>,
}

pub const CASE_ASSESSMENT_REVISION: u32 = 2;

pub const MAX_INVOCATION_READBACK_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationCwdIdentity {
    pub volume_serial: u32,
    pub file_index: u64,
    pub attributes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationEnvironment {
    pub sha256: [u8; 32],
    pub bytes: usize,
    pub entries: usize,
}

pub fn validate_invocation_cwd_identity(
    actual: &InvocationCwdIdentity,
    expected: &InvocationCwdIdentity,
) -> Result<()> {
    if actual.volume_serial != expected.volume_serial
        || actual.file_index != expected.file_index
        || actual.file_index == 0
        || actual.attributes & 0x400 != 0
        || actual.attributes & 0x10 == 0
        || expected.attributes & 0x400 != 0
        || expected.attributes & 0x10 == 0
    {
        return Err(CiError::Message(
            "invocation directory differs from original held cwd".into(),
        ));
    }
    Ok(())
}

/// Canonical UTF-16 includes special drive entries and exact native values;
/// names/values are never retained in the ordinary invocation observation.
pub fn invocation_environment(
    entries: &[memcordon_core::WindowsEnvironmentEntryV1],
) -> Result<InvocationEnvironment> {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|left, right| left.name.cmp(&right.name));
    let block = memcordon_core::encode_windows_environment_block(&sorted)
        .map_err(|error| CiError::Message(error.to_string()))?;
    let bytes: Vec<_> = block.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    Ok(InvocationEnvironment {
        sha256: descriptor::controller_start::descriptor_digest(&bytes),
        bytes: bytes.len(),
        entries: sorted.len(),
    })
}

#[derive(Clone, Debug)]
pub struct InvocationReadbackExpectation {
    pub root: memcordon_core::execution_facts::NativeProcessV2,
    pub descriptor_sha256: [u8; 32],
    pub challenge_sha256: [u8; 32],
    pub token_sha256: [u8; 32],
    pub environment: InvocationEnvironment,
    pub cwd_identity: InvocationCwdIdentity,
    pub work_cutoff_qpc: u64,
    pub qpc_frequency: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvocationReadback {
    format: String,
    revision: u32,
    pid: u32,
    birth: u64,
    descriptor_sha256: [u8; 32],
    challenge_sha256: [u8; 32],
    token_sha256: [u8; 32],
    environment_sha256: [u8; 32],
    environment_bytes: usize,
    environment_entries: usize,
    cwd_utf16: Vec<u16>,
    cwd_identity: InvocationCwdIdentity,
    started_qpc: u64,
    finished_qpc: u64,
    qpc_frequency: u64,
    cutoff_qpc: u64,
}

/// The caller supplies its original native owner, held intended cwd and exact
/// intended environment. This decoder cannot create authority from artifacts.
/// Cwd spelling remains observed data: directory identity, not path rewriting,
/// establishes the intended working directory.
pub fn validate_invocation_readback(
    bytes: &[u8],
    expected: &InvocationReadbackExpectation,
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_INVOCATION_READBACK_BYTES {
        return Err(CiError::Message(
            "invocation readback exceeds its bound".into(),
        ));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    let observed: InvocationReadback = serde_json::from_slice(bytes)?;
    validate_invocation_cwd_identity(&observed.cwd_identity, &expected.cwd_identity)?;
    if observed.format != "memcordon.windows-invocation-readback"
        || observed.revision != 1
        || expected.root.pid == 0
        || expected.root.birth == 0
        || observed.pid != expected.root.pid
        || observed.birth != expected.root.birth
        || observed.descriptor_sha256 != expected.descriptor_sha256
        || observed.challenge_sha256 != expected.challenge_sha256
        || observed.token_sha256 != expected.token_sha256
        || observed.environment_sha256 != expected.environment.sha256
        || observed.environment_bytes != expected.environment.bytes
        || observed.environment_entries != expected.environment.entries
        || !(4..=65534).contains(&observed.environment_bytes)
        || !observed.environment_bytes.is_multiple_of(2)
        || observed.environment_entries > (observed.environment_bytes - 2) / 6
        || observed.cwd_utf16.is_empty()
        || observed.cwd_utf16.len() > 32768
        || observed.cwd_utf16.contains(&0)
        || expected.qpc_frequency == 0
        || observed.qpc_frequency != expected.qpc_frequency
        || observed.cutoff_qpc != expected.work_cutoff_qpc
        || observed.started_qpc == 0
        || observed.finished_qpc < observed.started_qpc
        || observed.finished_qpc >= expected.work_cutoff_qpc
    {
        return Err(CiError::Message(
            "actual invocation readback differs from original held context".into(),
        ));
    }
    Ok(())
}

/// Keep later wrapper/fixture cleanup failures visible without erasing an
/// already measured outcome or mislabelling an attempted case as never run.
pub fn finalize_case_attempt(record: &mut CaseAssessment, result: Result<()>) -> Result<()> {
    if let Err(error) = &result {
        use crate::windows_readiness_policy::{ExecutionDisposition, IntrinsicContract};
        record.contract.intrinsic = IntrinsicContract::Invalid;
        if record.contract.execution == ExecutionDisposition::NotRun {
            record.contract.execution = ExecutionDisposition::Unvalidated;
        }
        record.behavior = Err(error.to_string());
    }
    result
}

/// Join a result to the caller's independently retained native root identity.
/// Scalar inputs do not create native ownership; the execution caller supplies
/// them from its original held process, never a rediscovered PID or artifact.
pub fn bind_execution_root(
    result: &ResultV3,
    held: crate::windows_listener_wait::Identity,
) -> Result<memcordon_core::execution_facts::NativeProcessV2> {
    let birth = u64::try_from(held.birth)
        .map_err(|_| CiError::Message("original root birth exceeds native width".into()))?;
    let reported = current_native(result)?
        .target_identity
        .as_ref()
        .ok_or_else(|| CiError::Message("result omitted its original root identity".into()))?;
    if held.pid == 0
        || birth == 0
        || reported.process_id != held.pid
        || reported.creation_time_100ns != birth
    {
        return Err(CiError::Message(
            "result root differs from original held process identity".into(),
        ));
    }
    Ok(memcordon_core::execution_facts::NativeProcessV2 {
        pid: held.pid,
        birth,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    sequence: u32,
    stage: String,
    pid: u32,
    ordinal: Option<u32>,
    value: Vec<u8>,
}

pub fn positive_keys() -> BTreeSet<CaseKey> {
    let mut keys = BTreeSet::new();
    for (family, scenarios) in [
        (
            "C-IO",
            &[
                "empty-input",
                "empty-message",
                "binary-streams",
                "binary-file",
                "native-argv",
                "bounded-large-output",
            ][..],
        ),
        (
            "C-STATUS",
            &[
                "zero", "nonzero", "exit-123", "exit-124", "exit-125", "exit-126", "exit-127",
                "deadline", "memory",
            ][..],
        ),
        ("C-PARSER", &["valid-current-result"][..]),
        ("C-LIFETIME", &["root-first"][..]),
        ("W-RETIREMENT", &["natural", "output-backpressure"][..]),
        ("W-UPGRADE", &["fresh-positive"][..]),
        ("C-ADMISSION", &["positive"][..]),
        (
            "W-BINDING",
            &["effective-caller-token", "restricted-token-preserved"][..],
        ),
        (
            "W-ENVELOPE",
            &["ordinary", "restricted", "sentinel-handles"][..],
        ),
        (
            "W-JOINT",
            &["ordinary", "restricted", "endpoint-mismatch"][..],
        ),
        ("W-TOOLCHAIN", &["ordinary", "restricted"][..]),
        (
            "W-IO",
            &[
                "empty-stdout-stderr",
                "empty-message",
                "embedded-nul",
                "all-bytes",
                "invalid-utf8",
                "final-fragment",
                "backpressure-separated-streams",
                "empty-file",
                "binary-file",
                "argv-empty",
                "argv-whitespace",
                "argv-quotes",
                "argv-backslashes",
                "argv-unicode",
                "argv-path",
            ][..],
        ),
        ("W-CHURN", &["natural-4096-three-generations"][..]),
        (
            "W-DESCENDANT",
            &[
                "root-first",
                "intermediate-parent-first",
                "nested-job",
                "breakaway-denial",
                "allowed-token-change",
            ][..],
        ),
        (
            "W-STATUS",
            &[
                "zero",
                "nonzero",
                "exit-123",
                "exit-124",
                "exit-125",
                "exit-126",
                "exit-127",
                "target-failure",
                "deadline",
                "memory",
            ][..],
        ),
    ] {
        for scenario in scenarios {
            keys.insert(CaseKey {
                family: family.into(),
                scenario: (*scenario).into(),
            });
        }
    }
    keys
}

pub fn validate_suite(input: &SuiteInput) -> Result<()> {
    if input
        .cases
        .iter()
        .any(|case| case.descriptor.matched_control.is_some())
    {
        return Err(CiError::Message(
            "matched observations are separate from required full-positive suite inputs".into(),
        ));
    }
    if input.format != "memcordon.windows-readiness-input" || input.revision != 2 {
        return Err(CiError::Message(
            "unsupported Windows readiness input format/revision".into(),
        ));
    }
    let mut keys = BTreeSet::new();
    for case in &input.cases {
        if !keys.insert(case.key.clone()) {
            return Err(CiError::Message("duplicate Windows positive case".into()));
        }
        validate_descriptor(&case.key, &case.descriptor)?;
        if !case.workload_request.is_absolute()
            || !case.descriptor_path.is_absolute()
            || matches!(
                case.key.scenario.as_str(),
                "restricted" | "restricted-token-preserved"
            ) && !case.expected_token.restricted
        {
            return Err(CiError::Message(
                "case input lacks exact contract/path/caller binding".into(),
            ));
        }
        validate_vectors(case)?;
        let expected = expected_fixture_case(&case.key)?;
        if case.descriptor.case != expected {
            return Err(CiError::Message(
                "case descriptor substituted another positive workload".into(),
            ));
        }
        let status = expected_status(&case.key);
        if case.descriptor.application_status != status {
            return Err(CiError::Message(
                "case descriptor substituted target outcome".into(),
            ));
        }
        if matches!(case.key.family.as_str(), "W-JOINT" | "W-ENVELOPE")
            && case.key.scenario == "restricted"
            && case.descriptor.denied_write_paths.len() < 2
        {
            return Err(CiError::Message(
                "restricted composite must probe protected driver/provider writes".into(),
            ));
        }
    }
    if keys != positive_keys() {
        return Err(CiError::Message(
            "Windows positive case set is incomplete or unknown".into(),
        ));
    }
    Ok(())
}

/// Preserve the entire catalogue while running independent prepared core
/// checks before contextual composites. This never reorders phases in a case.
pub fn readiness_execution_order(keys: &[CaseKey]) -> Result<Vec<usize>> {
    let actual: BTreeSet<_> = keys.iter().cloned().collect();
    if actual != positive_keys() || actual.len() != keys.len() {
        return Err(CiError::Message(
            "readiness schedule requires the exact unique catalogue".into(),
        ));
    }
    let mut order: Vec<_> = (0..keys.len()).collect();
    order.sort_by_key(|index| {
        (
            crate::windows_readiness_policy::requirement_class(&keys[*index])
                == Some(crate::windows_readiness_policy::RequirementClass::ContextualWorkload),
            keys[*index].clone(),
        )
    });
    Ok(order)
}

fn validate_vectors(case: &CaseInput) -> Result<()> {
    let d = &case.descriptor;
    if case.key.family == "W-IO" {
        let valid = match case.key.scenario.as_str() {
            "all-bytes" => {
                d.stdout == (0..=255).collect::<Vec<u8>>()
                    && d.stderr == (0..=255).rev().collect::<Vec<u8>>()
            }
            "embedded-nul" => d.stdout.contains(&0) && d.stderr.contains(&0),
            "invalid-utf8" => {
                std::str::from_utf8(&d.stdout).is_err() && std::str::from_utf8(&d.stderr).is_err()
            }
            "final-fragment" => {
                !d.stdout.is_empty()
                    && !d.stderr.is_empty()
                    && !d.stdout.ends_with(b"\n")
                    && !d.stderr.ends_with(b"\n")
            }
            "backpressure-separated-streams" => {
                d.stdout.len() >= 8192 && d.stderr.len() >= 8192 && d.stdout != d.stderr
            }
            "empty-stdout-stderr" => d.stdout.is_empty() && d.stderr.is_empty(),
            "argv-empty" => d.arguments.iter().any(String::is_empty),
            "argv-whitespace" => d
                .arguments
                .iter()
                .any(|a| a.contains(' ') || a.contains('\t')),
            "argv-quotes" => d.arguments.iter().any(|a| a.contains('"')),
            "argv-backslashes" => d.arguments.iter().any(|a| a.ends_with('\\')),
            "argv-unicode" => d.arguments.iter().any(|a| !a.is_ascii()),
            "argv-path" => d
                .arguments
                .iter()
                .any(|a| a.contains('\\') && a.contains(' ')),
            _ => true,
        };
        if !valid {
            return Err(CiError::Message(
                "Windows byte/argv scenario omitted its required vector".into(),
            ));
        }
    }
    if case.key.family == "W-CHURN" && d.churn_live != descriptor::CHURN_LIVE {
        return Err(CiError::Message("churn must retain 63 cohort leaves plus one TCP peer within the frozen 64-live-child bound".into()));
    }
    Ok(())
}

/// Deterministic execution inputs shared by provisioning and portable boundary checks.
pub struct FixtureParameters {
    pub case: descriptor::Case,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub arguments: Vec<String>,
    pub application_status: u32,
}

pub fn fixture_parameters(key: &CaseKey) -> Result<FixtureParameters> {
    let case = expected_fixture_case(key)?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut arguments = Vec::new();
    if key.family == "W-IO" {
        match key.scenario.as_str() {
            "all-bytes" => {
                stdout = (0..=255).collect();
                stderr = (0..=255).rev().collect();
            }
            "embedded-nul" => {
                stdout = vec![1, 0, 2];
                stderr = vec![3, 0, 4];
            }
            "invalid-utf8" => {
                stdout = vec![255, 128];
                stderr = vec![254, 129];
            }
            "final-fragment" => {
                stdout = b"final-fragment".to_vec();
                stderr = b"stderr-fragment".to_vec();
            }
            "backpressure-separated-streams" => {
                stdout = (0..=255).cycle().take(8192).collect();
                stderr = (0..=255).rev().cycle().take(8192).collect();
            }
            "argv-empty" => arguments.push(String::new()),
            "argv-whitespace" => arguments.push("space and\ttab".into()),
            "argv-quotes" => arguments.push("literal \"quotes\"".into()),
            "argv-backslashes" => arguments.push("trailing\\".into()),
            "argv-unicode" => arguments.push("日本語-λ".into()),
            "argv-path" => arguments.push("C:\\path with spaces\\file".into()),
            _ => {}
        }
    }
    if key.family == "W-RETIREMENT" && key.scenario == "output-backpressure" {
        stdout = (u8::MIN..=u8::MAX).cycle().take(16384).collect();
        stderr = (u8::MIN..=u8::MAX).rev().cycle().take(16384).collect();
    }
    if key.family == "C-IO" {
        match key.scenario.as_str() {
            "binary-streams" => {
                stdout = (u8::MIN..=u8::MAX).collect();
                stderr = (u8::MIN..=u8::MAX).rev().collect();
            }
            "bounded-large-output" => {
                stdout = (u8::MIN..=u8::MAX).cycle().take(16384).collect();
                stderr = (u8::MIN..=u8::MAX).rev().cycle().take(16384).collect();
            }
            "native-argv" => {
                arguments = vec![
                    String::new(),
                    "space and\ttab".into(),
                    "literal \"quotes\"".into(),
                    "trailing\\".into(),
                    "日本語-λ".into(),
                    "C:\\path with spaces\\file".into(),
                ]
            }
            _ => {}
        }
    }
    Ok(FixtureParameters {
        case,
        stdout,
        stderr,
        arguments,
        application_status: expected_status(key),
    })
}

#[derive(Clone, Copy)]
pub enum GateClock<'a> {
    PrepareFromDeadline,
    ExistingMatched(&'a descriptor::matched_plan::Plan),
}

impl GateClock<'_> {
    pub fn validate_selection(self, input: &descriptor::Descriptor) -> Result<()> {
        match self {
            Self::PrepareFromDeadline if input.matched_control.is_some() => Err(CiError::Message(
                "matched gate clock requires its original controller-owned plan".into(),
            )),
            Self::PrepareFromDeadline => Ok(()),
            Self::ExistingMatched(plan) => {
                if input.control_clock.as_ref() != Some(&plan.work_clock) {
                    return Err(CiError::Message(
                        "matched declared gate clock differs from its original plan".into(),
                    ));
                }
                let direct = plan
                    .direct_descriptor_for(input)
                    .map_err(CiError::Message)?;
                plan.validate(&direct, input).map_err(CiError::Message)
            }
        }
    }
}

/// Finalize the real gate preparation clock without reprojecting an owned pair.
/// The native caller selects ExistingMatched only from its held MatchedExecution.
pub fn prepare_gate_clock(
    input: &mut descriptor::Descriptor,
    selection: GateClock<'_>,
    original_deadline: std::time::Instant,
    project: impl FnOnce() -> Result<descriptor::ControlClock>,
    observe: impl FnOnce() -> Result<(u64, u64)>,
) -> Result<()> {
    if std::time::Instant::now() >= original_deadline {
        return Err(CiError::Message(
            "original gate preparation deadline exhausted".into(),
        ));
    }
    selection.validate_selection(input)?;
    let clock = match selection {
        GateClock::PrepareFromDeadline => {
            if matches!(
                input.start_transport,
                descriptor::StartTransport::ControllerStdin { .. }
            ) {
                Some(project()?)
            } else {
                None
            }
        }
        GateClock::ExistingMatched(plan) => {
            let (now, frequency) = observe()?;
            if now == 0
                || frequency != plan.work_clock.qpc_frequency
                || now >= plan.work_clock.work_cutoff_qpc
            {
                return Err(CiError::Message(
                    "original matched gate clock expired or native frequency differs".into(),
                ));
            }
            Some(plan.work_clock.clone())
        }
    };
    if std::time::Instant::now() >= original_deadline {
        return Err(CiError::Message(
            "original gate preparation deadline exhausted".into(),
        ));
    }
    input.control_clock = clock;
    Ok(())
}

/// Validate the actual input once complete, retaining its case and wire-size boundary.
pub fn validate_descriptor(key: &CaseKey, descriptor: &descriptor::Descriptor) -> Result<()> {
    if (descriptor.case == descriptor::Case::CapacityCompletion || key.family == "W-CAPACITY")
        && (descriptor.case != descriptor::Case::CapacityCompletion
            || !crate::windows_readiness_capacity::required_keys().contains(key))
    {
        return Err(CiError::Message(
            "capacity fixture and finite capacity identity differ".into(),
        ));
    }
    let explicit_registry = descriptor.winsock_registry.is_some()
        && needs_registry_input(key, descriptor.case)
        && matches!(
            descriptor.start_transport,
            descriptor::StartTransport::ControllerStdin {
                version
            } if version == descriptor::controller_start::REGISTRY_VERSION
                || (descriptor.provider_input_experiment && version == if descriptor.provider_input_binding.as_ref().is_some_and(|binding| binding.file_layout()) { descriptor::controller_start::PRIVATE_FILE_VERSION } else { descriptor::controller_start::PRIVATE_VERSION })
        );
    let explicit_matched = descriptor.matched_control.is_some()
        && matches!(
            descriptor.start_transport,
            descriptor::StartTransport::ControllerStdin {
                version: descriptor::controller_start::VERSION
            }
        );
    if !explicit_registry
        && !explicit_matched
        && descriptor.start_transport != expected_start_transport(key)
    {
        return Err(CiError::Message(
            "fixture START transport differs from its declared case".into(),
        ));
    }
    let bytes = serde_json::to_vec(descriptor).map_err(|error| {
        CiError::Message(format!(
            "Windows fixture {}/{} encoding failed: {error}; limit={}",
            key.family,
            key.scenario,
            descriptor::MAX_DESCRIPTOR_BYTES
        ))
    })?;
    if bytes.len() > descriptor::MAX_DESCRIPTOR_BYTES {
        return Err(CiError::Message(format!(
            "Windows fixture {}/{} descriptor exceeds aggregate wire bound; encoded-bytes={} limit={}",
            key.family,
            key.scenario,
            bytes.len(),
            descriptor::MAX_DESCRIPTOR_BYTES
        )));
    }
    descriptor.validate().map_err(|error| {
        CiError::Message(format!(
            "Windows fixture {}/{} descriptor invalid: {error}; encoded-bytes={} limit={}",
            key.family,
            key.scenario,
            bytes.len(),
            descriptor::MAX_DESCRIPTOR_BYTES
        ))
    })
}

pub fn expected_start_transport(key: &CaseKey) -> descriptor::StartTransport {
    if matches!(
        (key.family.as_str(), key.scenario.as_str()),
        ("W-ENVELOPE", "restricted")
            | ("W-BINDING", "restricted-token-preserved")
            | ("W-JOINT", "restricted")
    ) {
        descriptor::StartTransport::ControllerStdin {
            version: descriptor::controller_start::VERSION,
        }
    } else {
        descriptor::StartTransport::NamedEvent
    }
}

pub fn needs_toolchain_observer(case: descriptor::Case) -> bool {
    matches!(
        case,
        descriptor::Case::Toolchain | descriptor::Case::Joint | descriptor::Case::Churn
    )
}

/// Bind a clockless draft to the caller's existing native work cutoff before
/// serialization. A scalar clock is not evidence that the target executed.
pub fn bind_invocation_clock(
    input: &mut descriptor::Descriptor,
    clock: descriptor::ControlClock,
) -> Result<()> {
    if input.case != descriptor::Case::Envelope
        || input.matched_control.is_some()
        || input.start_transport != descriptor::StartTransport::NamedEvent
        || input.control_clock.is_some()
    {
        return Err(CiError::Message(
            "invocation clock requires an unbound ordinary Envelope draft".into(),
        ));
    }
    clock.validate().map_err(CiError::Message)?;
    input.control_clock = Some(clock);
    input.validate().map_err(CiError::Message)
}

/// Prepare a separate finite capacity operation from the frozen ordinary
/// invocation. This does not change the original Joint catalogue descriptor.
pub fn prepare_capacity_completion(base: &CaseInput, key: &CaseKey) -> Result<CaseInput> {
    if base.key.family != "W-JOINT"
        || base.key.scenario != "ordinary"
        || base.descriptor.case != descriptor::Case::Joint
        || base.descriptor.provider_input_experiment
        || base.descriptor.matched_control.is_some()
        || !crate::windows_readiness_capacity::required_keys().contains(key)
    {
        return Err(CiError::Message(
            "capacity preparation requires the original ordinary invocation and finite key".into(),
        ));
    }
    validate_descriptor(&base.key, &base.descriptor)?;
    let mut input = base.clone();
    input.key = key.clone();
    let d = &mut input.descriptor;
    d.case = descriptor::Case::CapacityCompletion;
    d.toolchain = None;
    d.winsock_registry = None;
    d.control_clock = None;
    d.start_transport = descriptor::StartTransport::NamedEvent;
    d.matched_control = None;
    d.generation_gate = None;
    d.descendant_gate = None;
    d.completion_gate = None;
    d.denied_write_paths.clear();
    d.stdout.clear();
    d.stderr.clear();
    d.application_status = 0;
    d.churn_creations = 0;
    d.churn_live = 0;
    d.cohort_gate = Some(format!(
        "{}-capacity-child",
        d.start_gate
            .as_ref()
            .ok_or_else(|| CiError::Message("capacity start owner absent".into()))?
    ));
    validate_descriptor(key, d)?;
    Ok(input)
}

pub fn needs_descriptor_toolchain_observer(input: &descriptor::Descriptor) -> Result<bool> {
    input.validate().map_err(CiError::Message)?;
    Ok(needs_toolchain_observer(input.case)
        && !input.matched_control.as_ref().is_some_and(|binding| {
            input.case == descriptor::Case::Joint
                && matches!(
                    binding.scope,
                    descriptor::matched::Scope::JointListenerPrefix
                        | descriptor::matched::Scope::ProviderListenerSelection
                )
        }))
}

/// Derive only the root-selection operation's input. Full Joint's protected
/// writes, compiler and descendant work remain on its unchanged original.
/// Native inputs, clocks and pair bindings are supplied by the existing caller.
pub fn prepare_provider_root_descriptor(
    original: &descriptor::Descriptor,
) -> Result<descriptor::Descriptor> {
    if original.case != descriptor::Case::Joint || original.matched_control.is_some() {
        return Err(CiError::Message(
            "provider root control requires an unpaired Joint input".into(),
        ));
    }
    let mut reduced = original.clone();
    reduced.toolchain = None;
    reduced.denied_write_paths.clear();
    reduced.stdout.clear();
    reduced.stderr.clear();
    reduced.sentinel_handles.clear();
    reduced.descendant_gate = None;
    reduced.completion_gate = None;
    reduced.cohort_gate = None;
    reduced.generation_gate = None;
    reduced.gate_precondition = None;
    reduced.gate_access_diagnostic = None;
    Ok(reduced)
}

/// Registry input belongs only to a catalog key with its expected fixture kind.
pub fn needs_registry_input(key: &CaseKey, case: descriptor::Case) -> bool {
    if key.family == "W-MATCHED-OWNED" && case == descriptor::Case::Joint {
        return matches!(key.scenario.as_str(), "ordinary" | "restricted");
    }
    positive_keys().contains(key)
        && expected_fixture_case(key).is_ok_and(|expected| {
            expected == case
                && matches!(
                    case,
                    descriptor::Case::Joint
                        | descriptor::Case::EndpointMismatch
                        | descriptor::Case::Churn
                )
        })
}

fn expected_fixture_case(key: &CaseKey) -> Result<descriptor::Case> {
    use descriptor::Case;
    let case = match key.family.as_str() {
        "W-CAPACITY" if crate::windows_readiness_capacity::required_keys().contains(key) => {
            Case::CapacityCompletion
        }
        "W-ENVELOPE" | "W-BINDING" | "C-ADMISSION" | "C-PARSER" | "W-UPGRADE" => Case::Envelope,
        "C-LIFETIME" if key.scenario == "root-first" => Case::RootFirst,
        "C-IO" => match key.scenario.as_str() {
            "empty-input" => Case::EmptyInput,
            "empty-message" => Case::Joint,
            "binary-file" => Case::BinaryFiles,
            "native-argv" => Case::NativeArgv,
            "binary-streams" | "bounded-large-output" => Case::BinaryStreams,
            _ => return Err(CiError::Message("unknown common IO scenario".into())),
        },
        "W-RETIREMENT" if key.scenario == "natural" => Case::ApplicationExit,
        "W-RETIREMENT" if key.scenario == "output-backpressure" => Case::BinaryStreams,
        "W-JOINT" if key.scenario == "endpoint-mismatch" => Case::EndpointMismatch,
        "W-JOINT" => Case::Joint,
        "W-TOOLCHAIN" => Case::Toolchain,
        "W-CHURN" => Case::Churn,
        "W-IO" => match key.scenario.as_str() {
            "empty-stdout-stderr" => Case::EmptyStreams,
            "empty-message" => Case::Joint,
            "empty-file" | "binary-file" => Case::BinaryFiles,
            value if value.starts_with("argv-") => Case::NativeArgv,
            _ => Case::BinaryStreams,
        },
        "W-STATUS" | "C-STATUS" if key.scenario == "deadline" => Case::DeadlineDemand,
        "W-STATUS" | "C-STATUS" if key.scenario == "memory" => Case::MemoryDemand,
        "W-STATUS" | "C-STATUS" => Case::ApplicationExit,
        "W-DESCENDANT" => match key.scenario.as_str() {
            "root-first" => Case::RootFirst,
            "intermediate-parent-first" => Case::IntermediateFirst,
            "nested-job" => Case::NestedJob,
            "breakaway-denial" => Case::BreakawayDenied,
            "allowed-token-change" => Case::AllowedTokenChange,
            _ => return Err(CiError::Message("unknown descendant scenario".into())),
        },
        _ => return Err(CiError::Message("unknown Windows positive family".into())),
    };
    Ok(case)
}

fn expected_status(key: &CaseKey) -> u32 {
    if key.family == "W-JOINT" && key.scenario == "endpoint-mismatch" {
        return 42;
    }
    if matches!(key.family.as_str(), "W-STATUS" | "C-STATUS") {
        match key.scenario.as_str() {
            "nonzero" | "target-failure" => 17,
            value => value
                .strip_prefix("exit-")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
        }
    } else {
        0
    }
}

pub fn public_command(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    case: &CaseInput,
) -> Result<crate::command::CommandSpec> {
    public_command_observation(
        cli,
        fixture,
        directory,
        report,
        case,
        FrontendObservation::Terminal,
    )
}

#[cfg(windows)]
pub(crate) fn public_refusal_command(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    case: &CaseInput,
) -> Result<crate::command::CommandSpec> {
    public_command_observation(
        cli,
        fixture,
        directory,
        report,
        case,
        FrontendObservation::Request,
    )
}

#[cfg(windows)]
pub(crate) fn public_component_command(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    case: &CaseInput,
) -> Result<crate::command::CommandSpec> {
    public_command_observation(
        cli,
        fixture,
        directory,
        report,
        case,
        FrontendObservation::None,
    )
}

enum FrontendObservation<'a> {
    Terminal,
    #[cfg(windows)]
    Request,
    #[cfg(windows)]
    None,
    Diagnostic {
        selection: &'a Path,
        observation: &'a Path,
        system_environment: bool,
    },
}

pub fn support_loader_command(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    case: &CaseInput,
    selection: &Path,
    observation: &Path,
) -> Result<crate::command::CommandSpec> {
    support_loader_command_with_environment::<false>(
        cli,
        fixture,
        directory,
        report,
        case,
        selection,
        observation,
    )
}

pub fn installed_support_loader_command(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    case: &CaseInput,
    selection: &Path,
    observation: &Path,
) -> Result<crate::command::CommandSpec> {
    support_loader_command_with_environment::<true>(
        cli,
        fixture,
        directory,
        report,
        case,
        selection,
        observation,
    )
}

fn support_loader_command_with_environment<const SYSTEM_ENVIRONMENT: bool>(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    case: &CaseInput,
    selection: &Path,
    observation: &Path,
) -> Result<crate::command::CommandSpec> {
    if case.key.family != "W-ENVELOPE"
        || case.key.scenario != "restricted"
        || !case.expected_token.restricted
        || case.descriptor.case != descriptor::Case::Envelope
        || !case.descriptor.arguments.is_empty()
        || !case.descriptor.stdout.is_empty()
        || !case.descriptor.stderr.is_empty()
        || case.descriptor.application_status != 0
    {
        return Err(CiError::Message(
            "loader diagnostic requires the exact restricted envelope case".into(),
        ));
    }
    case.descriptor.validate().map_err(CiError::Message)?;
    if !case.workload_request.is_absolute() || !case.descriptor_path.is_absolute() {
        return Err(CiError::Message(
            "diagnostic contract/input paths are not selected absolute paths".into(),
        ));
    }
    public_command_observation(
        cli,
        fixture,
        directory,
        report,
        case,
        FrontendObservation::Diagnostic {
            selection,
            observation,
            system_environment: SYSTEM_ENVIRONMENT,
        },
    )
}

fn public_command_observation(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    case: &CaseInput,
    observation: FrontendObservation<'_>,
) -> Result<crate::command::CommandSpec> {
    let terminal_observation = matches!(observation, FrontendObservation::Terminal);
    let system_environment = terminal_observation
        || matches!(
            observation,
            FrontendObservation::Diagnostic {
                system_environment: true,
                ..
            }
        );
    #[cfg(windows)]
    let request_observation = matches!(observation, FrontendObservation::Request);
    #[cfg(not(windows))]
    let request_observation = false;
    let mut args: Vec<OsString> = ["+4GiB", "+600s"].into_iter().map(OsString::from).collect();
    // A named request on the ordinary backend is a deliberately unsupported
    // public request. Every other readiness operation selects sealed runtime.
    if case.key.scenario != "unsupported-public-request" {
        args.push("--sealed".into());
    }
    args.push("--workload-request".into());
    if case.descriptor.case == descriptor::Case::DeadlineDemand {
        args[1] = "+10s".into();
    }
    if case.descriptor.case == descriptor::Case::MemoryDemand {
        args[0] = "+64MiB".into();
    }
    args.push(std::path::absolute(&case.workload_request)?.into_os_string());
    args.extend(["--report-format", "result-v3", "--report"].map(OsString::from));
    args.push(std::path::absolute(report)?.into_os_string());
    if terminal_observation {
        args.push("--windows-terminal-observation".into());
        args.push(
            std::path::absolute(report)?
                .with_extension("terminal-observation.json")
                .into_os_string(),
        );
    } else if request_observation && case.key.scenario != "unsupported-public-request" {
        args.push("--windows-request-observation".into());
        args.push(
            std::path::absolute(directory)?
                .join("provider-request.bin")
                .into_os_string(),
        );
    }
    args.push("--".into());
    args.push(std::path::absolute(fixture)?.into_os_string());
    args.push("consumer-readiness-windows".into());
    args.push(case.descriptor_path.clone().into_os_string());
    args.extend(case.descriptor.arguments.iter().map(OsString::from));
    if let FrontendObservation::Diagnostic {
        selection,
        observation,
        ..
    } = observation
    {
        args = [
            OsString::from("__windows-loader-diagnostic"),
            selection.as_os_str().to_owned(),
            observation.as_os_str().to_owned(),
        ]
        .into_iter()
        .chain(args)
        .collect();
    }
    let cli = std::path::absolute(cli)?;
    if case.expected_token.restricted {
        let gate_control = terminal_observation && case.descriptor.gate_precondition.is_some();
        let mut restricted: Vec<OsString> = vec![
            "consumer-readiness-windows".into(),
            if gate_control {
                "system-restricted-gate-control-frontend"
            } else if system_environment {
                "system-restricted-frontend"
            } else {
                "restricted-frontend"
            }
            .into(),
        ];
        if gate_control {
            restricted.push(case.descriptor_path.clone().into_os_string());
        }
        restricted.push(cli.into_os_string());
        restricted.extend(args);
        Ok(crate::command::CommandSpec::new(
            std::path::absolute(fixture)?,
            &std::path::absolute(directory)?,
            Duration::from_secs(660),
        )
        .args(restricted))
    } else if case.key.scenario == "sentinel-handles" {
        let mut sentinel: Vec<OsString> = vec![
            "consumer-readiness-windows".into(),
            if terminal_observation {
                "system-sentinel-frontend"
            } else {
                "sentinel-frontend"
            }
            .into(),
            case.descriptor_path.clone().into_os_string(),
            cli.into_os_string(),
        ];
        sentinel.extend(args);
        Ok(crate::command::CommandSpec::new(
            std::path::absolute(fixture)?,
            &std::path::absolute(directory)?,
            Duration::from_secs(660),
        )
        .args(sentinel))
    } else if terminal_observation {
        let mut ordinary: Vec<OsString> = vec![
            "consumer-readiness-windows".into(),
            "system-frontend".into(),
            cli.into_os_string(),
        ];
        ordinary.extend(args);
        Ok(crate::command::CommandSpec::new(
            std::path::absolute(fixture)?,
            &std::path::absolute(directory)?,
            Duration::from_secs(660),
        )
        .args(ordinary))
    } else {
        Ok(crate::command::CommandSpec::new(
            cli,
            &std::path::absolute(directory)?,
            Duration::from_secs(660),
        )
        .args(args))
    }
}

fn events(bytes: &[u8]) -> Result<Vec<Event>> {
    decode_events(bytes, false)
}

fn capacity_child_identity(
    events: &[Event],
    root_pid: u32,
) -> Result<Option<memcordon_core::WindowsProcessIdentityV1>> {
    let children: Vec<_> = events
        .iter()
        .filter(|event| event.stage == "capacity-child-created")
        .collect();
    if children.is_empty() {
        return Ok(None);
    }
    if children.len() != 1 || children[0].pid != root_pid || children[0].ordinal != Some(0) {
        return Err(CiError::Message(
            "capacity child publication count or original root differs".into(),
        ));
    }
    let child: memcordon_core::WindowsProcessIdentityV1 =
        serde_json::from_slice(&children[0].value)?;
    if child.process_id == 0 || child.process_id == root_pid || child.creation_time_100ns == 0 {
        return Err(CiError::Message(
            "capacity child native identity is invalid".into(),
        ));
    }
    Ok(Some(child))
}

/// Validate the finite original operation's final transcript; native ownership
/// and ancestry are independently established by the controller before release.
pub fn validate_capacity_completion(
    input: &descriptor::Descriptor,
    transcript: &[u8],
    root_pid: u32,
) -> Result<memcordon_core::WindowsProcessIdentityV1> {
    input.validate().map_err(CiError::Message)?;
    if input.case != descriptor::Case::CapacityCompletion {
        return Err(CiError::Message(
            "capacity validation requires its own operation".into(),
        ));
    }
    let events = events(transcript)?;
    let prefix = [
        "started",
        "native-argv-observed",
        "sentinel-handles-excluded",
        "token-envelope",
        "controller-released",
    ];
    if events.len() != 8 + usize::from(input.completion_gate.is_some())
        || events.iter().take(5).zip(prefix).any(|(event, stage)| {
            event.stage != stage || event.pid != root_pid || event.ordinal.is_some()
        })
        || events
            .get(4)
            .is_none_or(|event| event.value != input.challenge)
        || events
            .get(5)
            .is_none_or(|event| event.stage != "capacity-child-created")
    {
        return Err(CiError::Message(
            "capacity initial invocation prefix differs".into(),
        ));
    }
    if events.first().is_none_or(|event| {
        event.stage != "started"
            || event.pid != root_pid
            || event.ordinal.is_some()
            || event.value != input.challenge
    }) || events.last().is_none_or(|event| {
        event.stage != "finished"
            || event.pid != root_pid
            || event.ordinal.is_some()
            || event.value != input.challenge
    }) {
        return Err(CiError::Message(
            "capacity original started/finished boundary differs".into(),
        ));
    }
    let child = capacity_child_identity(&events, root_pid)?
        .ok_or_else(|| CiError::Message("capacity child readiness absent".into()))?;
    let created = events
        .iter()
        .find(|event| event.stage == "capacity-child-created")
        .expect("validated child");
    let completed: Vec<_> = events
        .iter()
        .filter(|event| event.stage == "capacity-child-completed")
        .collect();
    let held: Vec<_> = events
        .iter()
        .filter(|event| event.stage == "capacity-live-before-natural-completion")
        .collect();
    if completed.len() != 1
        || completed[0].pid != root_pid
        || completed[0].ordinal != Some(0)
        || !completed[0].value.is_empty()
        || completed[0].sequence <= created.sequence
        || held.len() != usize::from(input.completion_gate.is_some())
        || held.iter().any(|event| {
            event.pid != root_pid
                || event.ordinal.is_some()
                || event.value != input.challenge
                || event.sequence <= created.sequence
                || event.sequence >= completed[0].sequence
        })
        || events.iter().any(|event| {
            event.pid != root_pid
                || !matches!(
                    event.stage.as_str(),
                    "started"
                        | "native-argv-observed"
                        | "sentinel-handles-excluded"
                        | "token-envelope"
                        | "controller-released"
                        | "capacity-child-created"
                        | "capacity-live-before-natural-completion"
                        | "capacity-child-completed"
                        | "finished"
                )
        })
    {
        return Err(CiError::Message(
            "capacity natural completion or held barrier differs".into(),
        ));
    }
    Ok(child)
}

// Only the native controller uses this while holding the transcript writer
// alive. A partial final frame is a publication in progress, never evidence.
#[cfg(windows)]
fn live_events(bytes: &[u8]) -> Result<Vec<Event>> {
    decode_events(bytes, true)
}

#[cfg(windows)]
pub(crate) fn provider_prelude_complete(
    bytes: &[u8],
    binding: &descriptor::controller_start::Binding,
) -> Result<bool> {
    let events = live_events(bytes)?;
    let receipts: Vec<_> = events
        .iter()
        .filter(|event| event.stage == "provider-root-prelude-complete")
        .collect();
    if receipts.len() > 1 {
        return Err(CiError::Message("provider prelude receipt repeated".into()));
    }
    let Some(receipt) = receipts.first() else {
        return Ok(false);
    };
    let expected = serde_json::json!({"pid":binding.pid,"birth":binding.birth,"descriptor_sha256":binding.descriptor_sha256,"challenge_sha256":descriptor::controller_start::descriptor_digest(&binding.challenge)});
    if receipt.pid != binding.pid
        || receipt.ordinal.is_some()
        || serde_json::from_slice::<serde_json::Value>(&receipt.value)? != expected
    {
        return Err(CiError::Message(
            "provider prelude receipt differs from original held lane".into(),
        ));
    }
    Ok(true)
}

#[cfg(windows)]
pub(crate) fn live_capacity_completion(bytes: &[u8]) -> Result<bool> {
    Ok(live_events(bytes)?
        .iter()
        .any(|event| event.stage == "capacity-live-before-natural-completion"))
}

#[cfg(windows)]
pub(crate) fn live_demand_child(
    bytes: &[u8],
    root_pid: u32,
) -> Result<Option<memcordon_core::WindowsProcessIdentityV1>> {
    let events = live_events(bytes)?;
    if !events
        .iter()
        .any(|event| event.stage == "policy-demand-started" && event.pid == root_pid)
    {
        return Ok(None);
    }
    let children: Vec<_> = events
        .iter()
        .filter(|event| event.stage == "child-created")
        .collect();
    if children.len() != 1 || children[0].pid != root_pid || children[0].ordinal != Some(0) {
        return Err(CiError::Message(
            "demand live publication lacks the exact owned descendant".into(),
        ));
    }
    serde_json::from_slice(&children[0].value)
        .map(Some)
        .map_err(CiError::from)
}

fn decode_events(bytes: &[u8], live: bool) -> Result<Vec<Event>> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(CiError::Message("fixture transcript exceeds bound".into()));
    }
    let mut remaining = bytes;
    let mut result = Vec::new();
    while !remaining.is_empty() {
        if live && remaining.len() < 4 {
            break;
        }
        let length_bytes = remaining
            .get(..4)
            .ok_or_else(|| CiError::Message("truncated fixture event length".into()))?;
        let length =
            u32::from_le_bytes(length_bytes.try_into().expect("checked four-byte length")) as usize;
        remaining = &remaining[length_bytes.len()..];
        if length > 64 * 1024 {
            return Err(CiError::Message("fixture event exceeds bound".into()));
        }
        if live && remaining.len() < length {
            break;
        }
        let event_bytes = remaining
            .get(..length)
            .ok_or_else(|| CiError::Message("truncated fixture event".into()))?;
        let event: Event = serde_json::from_slice(event_bytes)?;
        if event.sequence as usize != result.len() || event.pid == 0 {
            return Err(CiError::Message(
                "fixture sequence or native process identity differs".into(),
            ));
        }
        result.push(event);
        if result.len() > 200_000 {
            return Err(CiError::Message("fixture event count exceeds bound".into()));
        }
        remaining = &remaining[length..];
    }
    Ok(result)
}

/// A launch refusal or abnormal completion cannot satisfy the live positive-fixture barrier.
/// This observation only rejects; it never supplies accepted workload authority.
pub fn current_native(result: &ResultV3) -> Result<&memcordon_core::WindowsSealedEvidenceV3> {
    match &result.runtime {
        RuntimeExecutionV3::WindowsSealed { native, .. } => Ok(native),
        _ => Err(CiError::Message(
            "current result lacks actual Windows native execution".into(),
        )),
    }
}
pub fn current_association(
    result: &ResultV3,
) -> Result<&memcordon_core::execution_facts::ProviderAttemptAssociationV1> {
    current_native(result)?
        .frontend_provider_association
        .as_ref()
        .ok_or_else(|| {
            CiError::Message("current Windows result lacks actual provider association".into())
        })
}
pub fn check_positive_barrier_result(
    bytes: &[u8],
    provider: &memcordon_core::PublicProviderBindingV1,
) -> Result<()> {
    let result = ResultV3::parse(bytes).map_err(CiError::Message)?;
    if result.provider.as_ref() != Some(provider) {
        return Err(CiError::Message(
            "positive fixture provider binding differs from selected installed image".into(),
        ));
    }
    if result.release != ReleaseKnowledgeV3::Released
        || matches!(
            result.outcome.kind,
            OutcomeKindV1::LaunchFailure | OutcomeKindV1::ProviderFailure | OutcomeKindV1::Unknown
        )
        || (result.outcome.kind == OutcomeKindV1::Completed && result.outcome.wrapper_status != 0)
    {
        let mut detail = format!(
            "positive fixture launch already failed or completed abnormally; wrapper-status={}; outcome={:?}; release={:?}",
            result.outcome.wrapper_status, result.outcome.kind, result.release
        );
        if let Some(ChildTermination::WindowsStatus { status }) = result.outcome.native_termination
        {
            detail.push_str(&format!("; windows-status={status} (0x{status:08X})"));
        }
        if let Some(rejection) = &result.windows_rejection {
            detail.push_str(&format!("; {}: {}", rejection.code, rejection.detail));
        }
        if let Some(failure) = &result.provider_failure {
            detail.push_str(&format!(
                "; original-provider-failure={:?}",
                failure.original
            ));
        } else {
            detail.push_str("; no original provider failure observed");
        }
        for diagnostic in result.diagnostics.as_slice() {
            detail.push_str("; ");
            detail.push_str(diagnostic.as_str());
        }
        return Err(CiError::Message(detail));
    }
    Ok(())
}
pub fn released_target_loader_event_candidate(result: &ResultV3) -> bool {
    result.release == ReleaseKnowledgeV3::Released
        && result.outcome.kind == OutcomeKindV1::Completed
        && result.outcome.wrapper_status == 125
        && matches!(
            result.outcome.native_termination,
            Some(ChildTermination::WindowsStatus { status: 0xC0000142 })
        )
        && validate_retirement(result).is_ok()
}

/// Original frontend exit observations retained by the running controller.
pub struct FrontendExit {
    pub status: i32,
    pub original_pid: Option<u32>,
}

/// Inputs already collected by the original owned invocation. This adapter
/// validates intrinsic facts only; its caller must still settle all native
/// owners and validate the authenticated terminal/request before accepting it.
pub struct IntrinsicListenerInput<'a> {
    pub case: &'a CaseInput,
    pub result: &'a [u8],
    pub stdout: &'a [u8],
    pub stderr: &'a [u8],
    pub transcript: &'a [u8],
    pub frontend: FrontendExit,
    pub ended: crate::windows_listener_wait::ApplicationEnd,
    pub association: &'a memcordon_core::execution_facts::ProviderAttemptAssociationV1,
    pub descriptor_sha256: [u8; 32],
    pub observation: &'a [u8],
}

pub fn assess_original_listener_unavailable(
    input: IntrinsicListenerInput<'_>,
) -> Result<descriptor::original_listener_observation::Observation> {
    use descriptor::original_listener_observation as observation;
    let case = input.case;
    if !crate::windows_readiness_policy::supports_listener_refusal(&case.key)
        || expected_fixture_case(&case.key)? != case.descriptor.case
        || case.descriptor.matched_control.is_some()
        || case.descriptor.provider_input_experiment
    {
        return Err(CiError::Message(
            "case does not support intrinsic listener refusal".into(),
        ));
    }
    validate_descriptor(&case.key, &case.descriptor)?;
    let clock = case.descriptor.control_clock.as_ref().ok_or_else(|| {
        CiError::Message("original listener refusal has no authenticated clock".into())
    })?;
    validate_ended_application_settlement(
        input.result,
        input.frontend.status,
        input.ended,
        input.association,
    )?;
    let result = ResultV3::parse(input.result).map_err(CiError::Message)?;
    if input.frontend.status != 2
        || input.ended.status != 2
        || result.outcome.kind != OutcomeKindV1::Completed
        || !result.diagnostics.as_slice().is_empty()
        || !input.stdout.is_empty()
        || input.stderr.len() > matched_control_report::MAX_BYTES
    {
        return Err(CiError::Message(
            "original listener status or complete streams differ".into(),
        ));
    }
    let event = events(input.transcript)?;
    let stages = [
        "started",
        "native-argv-observed",
        "sentinel-handles-excluded",
        "token-envelope",
        "controller-released",
    ];
    if event.len() != stages.len()
        || event.iter().zip(stages).any(|(event, stage)| {
            event.stage != stage || event.pid != input.ended.identity.pid || event.ordinal.is_some()
        })
        || event[0].value != case.descriptor.challenge
        || event[4].value != case.descriptor.challenge
        || event[2].value
            != u32::try_from(case.descriptor.sentinel_handles.len())
                .map_err(|_| CiError::Message("sentinel count exceeds native width".into()))?
                .to_le_bytes()
        || serde_json::from_slice::<TokenObservation>(&event[3].value)? != case.expected_token
    {
        return Err(CiError::Message(
            "original listener stopped prefix, token or START differs".into(),
        ));
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NativeArguments {
        encoding: String,
        values: Vec<Vec<u16>>,
    }
    let argv: NativeArguments = serde_json::from_slice(&event[1].value)?;
    if argv.encoding != "windows_utf16"
        || argv.values
            != case
                .descriptor
                .arguments
                .iter()
                .map(|value| value.encode_utf16().collect::<Vec<_>>())
                .collect::<Vec<_>>()
    {
        return Err(CiError::Message(
            "original listener actual native argv differs".into(),
        ));
    }
    observation::decode(
        input.observation,
        &observation::Expected {
            pid: input.ended.identity.pid,
            birth: u64::try_from(input.ended.identity.birth).map_err(|_| {
                CiError::Message("original listener birth is outside native width".into())
            })?,
            descriptor_sha256: input.descriptor_sha256,
            challenge_sha256: descriptor::controller_start::descriptor_digest(
                &case.descriptor.challenge,
            ),
            token_sha256: descriptor::controller_start::descriptor_digest(&event[3].value),
            cutoff_qpc: clock.work_cutoff_qpc,
            frequency: clock.qpc_frequency,
        },
    )
    .map_err(CiError::Io)
}

pub fn assess(
    case: &CaseInput,
    result_bytes: &[u8],
    stdout: &[u8],
    stderr: &[u8],
    transcript: &[u8],
    frontend: FrontendExit,
    expected_association: &memcordon_core::execution_facts::ProviderAttemptAssociationV1,
) -> Result<()> {
    let FrontendExit {
        status: native_status,
        original_pid: frontend_pid,
    } = frontend;
    let result = ResultV3::parse(result_bytes).map_err(CiError::Message)?;
    let target_status = expected_status(&case.key);
    let policy_kind = match case.descriptor.case {
        descriptor::Case::DeadlineDemand => Some(OutcomeKindV1::Deadline),
        descriptor::Case::MemoryDemand => Some(OutcomeKindV1::ConfirmedMemoryLimit),
        _ => None,
    };
    if result.release != ReleaseKnowledgeV3::Released
        || result.outcome.kind != policy_kind.unwrap_or(OutcomeKindV1::Completed)
        || result.outcome.wrapper_status != native_status
        || !result.diagnostics.as_slice().is_empty()
        || policy_kind.is_none()
            && !matches!(result.outcome.native_termination.as_ref(),
            Some(ChildTermination::WindowsStatus { status }) if *status == target_status)
            && !matches!(result.outcome.native_termination.as_ref(), Some(ChildTermination::ExitCode { code }) if *code == target_status as i32)
    {
        return Err(CiError::Message(format!(
            "positive Windows case {}/{} did not complete with exact application origin/status; expected-kind={:?}; expected-target-status={target_status}; observed-kind={:?}; wrapper-status={}; native-status={native_status}; release={:?}; termination={:?}; diagnostics={}",
            case.key.family,
            case.key.scenario,
            policy_kind.unwrap_or(OutcomeKindV1::Completed),
            result.outcome.kind,
            result.outcome.wrapper_status,
            result.release,
            result.outcome.native_termination,
            result.diagnostics.as_slice().len(),
        )));
    }
    if current_association(&result)? != expected_association {
        return Err(CiError::Message(
            "positive result differs from independently held provider/attempt/request association"
                .into(),
        ));
    }
    validate_retirement(&result)?;
    let event = events(transcript)?;
    let first = event
        .first()
        .ok_or_else(|| CiError::Message("empty fixture transcript".into()))?;
    let last = event.last().expect("nonempty transcript");
    if first.stage != "started"
        || first.value != case.descriptor.challenge
        || policy_kind.is_none()
            && (last.stage != "finished" || last.value != case.descriptor.challenge)
    {
        return Err(CiError::Message(
            "fixture start/finish/challenge evidence differs".into(),
        ));
    }
    if current_native(&result)?
        .target_identity
        .as_ref()
        .map(|identity| identity.process_id)
        != Some(first.pid)
    {
        return Err(CiError::Message(
            "fixture root differs from authenticated target identity".into(),
        ));
    }
    let envelope = event
        .iter()
        .find(|e| e.stage == "token-envelope")
        .ok_or_else(|| CiError::Message("fixture omitted target token readback".into()))?;
    let observed: TokenObservation = serde_json::from_slice(&envelope.value)?;
    if observed != case.expected_token {
        return Err(CiError::Message(
            "native target token differs from protected caller expectation".into(),
        ));
    }
    if (case.key.scenario == "sentinel-handles" || case.descriptor.matched_control.is_some())
        && !event.iter().any(|event| {
            event.stage == "sentinel-handles-excluded" && event.value == 1u32.to_le_bytes()
        })
    {
        return Err(CiError::Message(
            "frontend sentinel case did not independently exercise exclusion".into(),
        ));
    }
    if case.descriptor.case == descriptor::Case::BinaryStreams {
        if stdout != case.descriptor.stdout.repeat(128)
            || stderr != case.descriptor.stderr.repeat(128)
        {
            return Err(CiError::Message(
                "exact independent stdout/stderr bytes differ".into(),
            ));
        }
    } else {
        crate::windows_status_streams::validate(
            stdout,
            stderr,
            native_status,
            result.outcome.kind,
            frontend_pid,
            case.expected_token.restricted,
        )
        .map_err(CiError::Message)?;
    }
    let has = |stage: &str| event.iter().any(|e| e.stage == stage);
    if policy_kind.is_some() && (!has("policy-demand-started") || has("finished")) {
        return Err(CiError::Message(
            "policy case did not hold genuine demand until authenticated forced termination".into(),
        ));
    }
    if case.descriptor.case == descriptor::Case::AllowedTokenChange {
        let changed = event
            .iter()
            .find(|e| e.stage == "allowed-token-change-retained-job")
            .ok_or_else(|| {
                CiError::Message("allowed token-change job observation missing".into())
            })?;
        let changed: TokenObservation = serde_json::from_slice(&changed.value)?;
        if !changed.restricted
            || changed.user_sid != case.expected_token.user_sid
            || changed.restricting_sids != vec![vec![1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]]
        {
            return Err(CiError::Message(
                "allowed token-change descendant envelope differs".into(),
            ));
        }
    }
    match case.descriptor.case {
        descriptor::Case::CapacityCompletion => {
            validate_capacity_completion(&case.descriptor, transcript, first.pid)?;
        }
        descriptor::Case::Joint | descriptor::Case::Churn => {
            for stage in [
                "tcp-listener-owned",
                "named-pipe-while-tcp-owned",
                "binary-files",
                "toolchain-compiled",
                "toolchain-test-child-dll-complete",
                "tcp-peer-complete",
            ] {
                if !has(stage) {
                    return Err(CiError::Message(
                        "composite fixture omitted a required genuine operation".into(),
                    ));
                }
            }
        }
        descriptor::Case::EndpointMismatch => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Refusal {
                kind: String,
                allowed_port: u16,
                observed_port: u16,
            }
            let failure = event
                .iter()
                .find(|e| e.stage == "endpoint-policy-refused-before-readiness")
                .ok_or_else(|| {
                    CiError::Message("endpoint mismatch omitted typed refusal".into())
                })?;
            let refusal: Refusal = serde_json::from_slice(&failure.value)?;
            if refusal.kind != "numeric-port-policy-mismatch"
                || refusal.allowed_port == refusal.observed_port
                || has("tcp-peer-complete")
                || has("named-pipe-while-tcp-owned")
            {
                return Err(CiError::Message(
                    "endpoint mismatch was not refused before readiness/application dispatch"
                        .into(),
                ));
            }
        }
        descriptor::Case::Toolchain
            if !has("toolchain-compiled") || !has("toolchain-test-child-dll-complete") =>
        {
            return Err(CiError::Message(
                "toolchain fixture omitted compile/child/DLL stage".into(),
            ));
        }
        _ => {}
    }
    if case.descriptor.case == descriptor::Case::Churn {
        let created: BTreeSet<_> = event
            .iter()
            .filter(|e| e.stage == "child-created")
            .filter_map(|e| e.ordinal)
            .collect();
        let completed: BTreeSet<_> = event
            .iter()
            .filter(|e| e.stage == "child-completed")
            .filter_map(|e| e.ordinal)
            .collect();
        let expected: BTreeSet<_> = (0..case.descriptor.churn_creations).collect();
        if created != expected
            || completed != expected
            || event.iter().filter(|e| e.stage == "child-created").count() != expected.len()
            || event
                .iter()
                .filter(|e| e.stage == "child-completed")
                .count()
                != expected.len()
        {
            return Err(CiError::Message(
                "churn omitted/duplicated a planned creation or completion".into(),
            ));
        }
    }
    Ok(())
}

pub fn validate_retirement(result: &ResultV3) -> Result<()> {
    result.validate().map_err(CiError::Message)?;
    let observation = current_native(result)?;
    if result.cleanup.state != CleanupStateV1::Complete
        || result
            .cleanup
            .obligations
            .as_slice()
            .iter()
            .any(|obligation| !obligation.settled)
        || !observation.caller_token_authenticated
        || !observation.initial_target_token_matches_caller
        || !observation.job_list_applied_at_creation
        || !observation.handle_list_applied_at_creation
        || !observation.target_still_suspended_during_verification
        || !observation.inherited_handles_verified
        || !observation.active_processes_zero
        || !observation.direct_target_reaped
        || !observation.relays_retired
        || !observation.guardian_reaped
        || !observation.final_job_handles_closed
    {
        return Err(CiError::Message(
            "native Windows boundary or authoritative retirement is incomplete".into(),
        ));
    }
    Ok(())
}

pub fn validate_ended_application_settlement(
    result_bytes: &[u8],
    frontend_status: i32,
    ended: crate::windows_listener_wait::ApplicationEnd,
    expected: &memcordon_core::execution_facts::ProviderAttemptAssociationV1,
) -> Result<()> {
    let result = ResultV3::parse(result_bytes).map_err(CiError::Message)?;
    let target = current_native(&result)?.target_identity.as_ref();
    if result.release != ReleaseKnowledgeV3::Released
        || result.outcome.kind != OutcomeKindV1::Completed
        || result.outcome.wrapper_status != frontend_status
        || !result.diagnostics.as_slice().is_empty()
        || current_association(&result)? != expected
        || !matches!(target, Some(target) if target.process_id == ended.identity.pid
            && u128::from(target.creation_time_100ns) == ended.identity.birth)
        || !(matches!(result.outcome.native_termination.as_ref(),
            Some(ChildTermination::WindowsStatus { status }) if *status == ended.status)
            || matches!(result.outcome.native_termination.as_ref(),
                Some(ChildTermination::ExitCode { code }) if i64::from(*code) == i64::from(ended.status)))
    {
        return Err(CiError::Message(
            "naturally settled frontend result differs from the original held application exit"
                .into(),
        ));
    }
    validate_retirement(&result)
}

/// Status/ownership validation for this bounded application prefix only.
/// Availability and precise refusal comparison are established separately by
/// the mandatory original operation records, never by this exit code alone.
pub struct BoundPrefixExit {
    pub frontend: FrontendExit,
    pub target: crate::windows_listener_wait::ApplicationEnd,
}

pub fn validate_listener_prefix_frontend(
    case: &CaseInput,
    result_bytes: &[u8],
    stdout: &[u8],
    stderr: &[u8],
    transcript: &[u8],
    observed: BoundPrefixExit,
    expected: &memcordon_core::execution_facts::ProviderAttemptAssociationV1,
) -> Result<()> {
    let BoundPrefixExit {
        frontend,
        target: ended,
    } = observed;
    if case.descriptor.case != descriptor::Case::Joint
        || !case
            .descriptor
            .matched_control
            .as_ref()
            .is_some_and(|binding| {
                matches!(
                    binding.scope,
                    descriptor::matched::Scope::JointListenerPrefix
                        | descriptor::matched::Scope::ProviderListenerSelection
                ) && binding.lane == descriptor::matched::Lane::Installed
            })
        || !matches!(ended.status, 0 | 2)
    {
        return Err(CiError::Message(
            "listener-prefix result lacks its declared bounded scope".into(),
        ));
    }
    validate_ended_application_settlement(result_bytes, frontend.status, ended, expected)?;
    let events = events(transcript)?;
    if events
        .first()
        .is_none_or(|event| event.stage != "started" || event.value != case.descriptor.challenge)
        || events.iter().any(|event| event.pid != ended.identity.pid)
        || events
            .iter()
            .filter(|event| {
                event.stage == "controller-released" && event.value == case.descriptor.challenge
            })
            .count()
            != 1
        || events
            .iter()
            .filter(|event| {
                event.stage == "sentinel-handles-excluded" && event.value == 1u32.to_le_bytes()
            })
            .count()
            != 1
        || events.iter().any(|event| {
            matches!(
                event.stage.as_str(),
                "tcp-peer-spawn-intent"
                    | "tcp-peer-created"
                    | "tcp-peer-complete"
                    | "named-pipe-while-tcp-owned"
                    | "binary-files"
                    | "toolchain-compiled"
                    | "descendants-complete"
            )
        })
        || ended.status == 0
            && events.last().is_none_or(|event| {
                event.stage != "finished" || event.value != case.descriptor.challenge
            })
        || ended.status != 0 && events.iter().any(|event| event.stage == "finished")
    {
        return Err(CiError::Message(
            "listener-prefix transcript scope or original challenge differs".into(),
        ));
    }
    let tokens: Vec<_> = events
        .iter()
        .filter(|event| event.stage == "token-envelope")
        .collect();
    if tokens.len() != 1
        || serde_json::from_slice::<TokenObservation>(&tokens[0].value)? != case.expected_token
    {
        return Err(CiError::Message(
            "listener-prefix selected target token differs".into(),
        ));
    }
    // A refused fixture writes its real bounded error to stderr before exit2.
    // Those bytes are retained, not normalized or used as native evidence.
    if !stdout.is_empty()
        || stderr.len() > matched_control_report::MAX_BYTES
        || ended.status == 0 && !stderr.is_empty()
    {
        return Err(CiError::Message(
            "listener-prefix original stream capture differs or exceeds bound".into(),
        ));
    }
    Ok(())
}

pub fn accepted(records: &[CaseAssessment]) -> bool {
    crate::windows_readiness_policy::assess_suite(records).is_validated()
}

#[cfg(not(windows))]
pub fn run_installed(
    _: &crate::windows_installed_cases::InstalledWindowsPayload,
    _: &Path,
    _: &mut Vec<CaseAssessment>,
) -> Result<()> {
    Err(CiError::Message(
        "Windows readiness requires a native Windows execution host".into(),
    ))
}

#[cfg(windows)]
pub fn run_installed(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input_path: &Path,
    assessments: &mut Vec<CaseAssessment>,
) -> Result<()> {
    run_installed_until(
        config,
        input_path,
        assessments,
        std::time::Instant::now() + Duration::from_secs(660),
    )
}

#[cfg(any(windows, test))]
pub(crate) fn write_workload_request(
    output_directory: &Path,
    key: &CaseKey,
    bytes: &[u8],
) -> Result<PathBuf> {
    use std::io::Write;
    let directory = std::path::absolute(output_directory)?
        .join(&key.family)
        .join(&key.scenario);
    std::fs::create_dir_all(&directory)?;
    let path = directory.join("workload-request.json");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?
        .write_all(bytes)?;
    Ok(path)
}

#[cfg(test)]
#[path = "../tests/private/windows_activated_contract.rs"]
mod activated_contract_tests;

#[cfg(all(test, windows))]
#[path = "../tests/private/windows_component_barriers.rs"]
mod component_barrier_tests;

#[cfg(windows)]
pub fn run_installed_until(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input_path: &Path,
    assessments: &mut Vec<CaseAssessment>,
    work_deadline: std::time::Instant,
) -> Result<()> {
    native::run(config, input_path, assessments, work_deadline, None)
}

/// Selection is usable for experiment aggregation only after every independent
/// operation and ownership/publication obligation has settled successfully.
pub fn settle_provider_scenario(
    selection: Option<crate::windows_provider_projection_record::ScenarioSelectionAssessment>,
    settlement: Result<()>,
) -> Result<crate::windows_provider_projection_record::ScenarioSelectionAssessment> {
    settlement?;
    selection.ok_or_else(|| CiError::Message("completed provider scenario selection absent".into()))
}

/// Fixed diagnostic projection: raw descriptor, SID, event and token data never
/// cross this boundary. Unknown/malformed snapshots remain unavailable.
pub fn redacted_toolchain_held_gate_observation(
    security: &serde_json::Value,
    label: &serde_json::Value,
) -> serde_json::Value {
    use serde_json::{Value, json};
    use sha2::Digest;
    const SNAPSHOT_BYTE_BOUND: u64 = 64 * 1024;
    fn project(input: &Value, label: bool) -> Option<Value> {
        if input["state"] == "unavailable" {
            let kind = match input["kind"].as_str() {
                Some(
                    kind @ ("PermissionDenied" | "TimedOut" | "InvalidData" | "Other" | "NotFound"
                    | "Unsupported" | "OutOfMemory" | "Interrupted" | "UnexpectedEof"
                    | "InvalidInput" | "Uncategorized"),
                ) => kind,
                _ => "Unknown",
            };
            return Some(json!({"state":"unavailable","kind":kind,
                "raw_os_error":input["raw_os_error"].as_i64().and_then(|v|i32::try_from(v).ok())}));
        }
        if input["state"] != "observed" {
            return None;
        }
        let value = &input["value"];
        fn hash(value: &Value) -> bool {
            value.as_str().is_some_and(|s| {
                s.len() == sha2::Sha256::output_size() * 2
                    && s.bytes().all(|b| b.is_ascii_hexdigit())
            })
        }
        fn fields(
            value: &Value,
            numbers: &[(&str, u64, bool)],
            booleans: &[&str],
        ) -> Option<Value> {
            let mut output = serde_json::Map::new();
            for &(key, maximum, nullable) in numbers {
                let item = value.get(key)?;
                if !(nullable && item.is_null()) && !item.as_u64().is_some_and(|n| n <= maximum) {
                    return None;
                }
                output.insert(key.into(), item.clone());
            }
            for &key in booleans {
                let item = value.get(key)?;
                item.as_bool()?;
                output.insert(key.into(), item.clone());
            }
            Some(Value::Object(output))
        }
        let mut output = fields(
            value,
            &[
                ("descriptor_length", SNAPSHOT_BYTE_BOUND, false),
                ("control", u16::MAX.into(), false),
            ],
            if label {
                &["sacl_present", "sacl_null"]
            } else {
                &["dacl_present", "dacl_null"]
            },
        )?;
        if value["descriptor_length"].as_u64()? < 20 || !hash(&value["descriptor_sha256"]) {
            return None;
        }
        let control = value["control"].as_u64()?;
        if control & 0x8000 == 0 {
            return None;
        }
        output["descriptor_sha256"] = value["descriptor_sha256"].clone();
        if label {
            if value["information"] != 0x10 {
                return None;
            }
            let present = value["sacl_present"].as_bool()?;
            let null = value["sacl_null"].as_bool()?;
            if present != (control & 0x10 != 0) || (!present && null) || control & 4 != 0 {
                return None;
            }
            if present && !null && value["descriptor_length"].as_u64()? < 28 {
                return None;
            }
            output["information"] = json!(0x10);
            let label_value = value.get("label")?;
            output["label"] = if label_value.is_null() {
                Value::Null
            } else {
                if !present || null || value["descriptor_length"].as_u64()? < 48 {
                    return None;
                }
                let source = &value["label"];
                let mut projected = fields(
                    source,
                    &[
                        ("flags", u8::MAX.into(), false),
                        ("mask", u32::MAX.into(), false),
                    ],
                    &[],
                )?;
                if source["sid_revision"] != 1 || source["identifier_authority"] != 16 {
                    return None;
                }
                let levels = source["subauthorities"].as_array()?;
                if levels.len() != 1 || !levels[0].as_u64().is_some_and(|n| n <= u32::MAX.into()) {
                    return None;
                }
                projected["integrity_level"] = levels[0].clone();
                projected
            };
        } else {
            let metadata = fields(
                value,
                &[
                    ("revision", u8::MAX.into(), false),
                    ("acl_revision", u8::MAX.into(), true),
                    ("acl_bytes", SNAPSHOT_BYTE_BOUND, true),
                    ("declared_ace_count", 64, true),
                    ("unused_acl_bytes", SNAPSHOT_BYTE_BOUND, true),
                ],
                &[],
            )?;
            output
                .as_object_mut()?
                .extend(metadata.as_object()?.clone());
            let aces = value["aces"].as_array()?;
            let present = value["dacl_present"].as_bool()?;
            let null = value["dacl_null"].as_bool()?;
            if aces.len() > 64
                || value["revision"] != 1
                || present != (control & 4 != 0)
                || (!present && null)
            {
                return None;
            }
            if !present || null {
                if !aces.is_empty()
                    || [
                        "acl_revision",
                        "acl_bytes",
                        "declared_ace_count",
                        "unused_acl_bytes",
                    ]
                    .iter()
                    .any(|key| !value[*key].is_null())
                {
                    return None;
                }
            } else if !matches!(value["acl_revision"].as_u64(), Some(2 | 4))
                || value["declared_ace_count"].as_u64()? != aces.len() as u64
                || value["acl_bytes"].as_u64()? < 8
                || value["acl_bytes"].as_u64()? > value["descriptor_length"].as_u64()? - 20
            {
                return None;
            }
            let mut projected = Vec::new();
            let mut used_bytes = 8;
            for (ordinal, ace) in aces.iter().enumerate() {
                let mut row = fields(
                    ace,
                    &[
                        ("ordinal", 63, false),
                        ("native_type", u8::MAX.into(), false),
                        ("flags", u8::MAX.into(), false),
                        ("bytes", SNAPSHOT_BYTE_BOUND, false),
                        ("raw_u32_at_offset_four", u32::MAX.into(), true),
                    ],
                    &[],
                )?;
                let bytes = ace["bytes"].as_u64()?;
                if !hash(&ace["sha256"])
                    || ace["ordinal"].as_u64()? != ordinal as u64
                    || bytes < 4
                    || !bytes.is_multiple_of(4)
                    || ace["raw_u32_at_offset_four"].is_null() != (bytes < 8)
                {
                    return None;
                }
                used_bytes += bytes;
                row["sha256"] = ace["sha256"].clone();
                projected.push(row);
            }
            if present
                && !null
                && used_bytes + value["unused_acl_bytes"].as_u64()?
                    != value["acl_bytes"].as_u64()?
            {
                return None;
            }
            output["aces"] = json!(projected);
        }
        Some(json!({"state":"observed","value":output}))
    }
    let unavailable = || json!({"state":"unavailable","kind":"InvalidData","stage":"redacted-snapshot-projection"});
    json!({"same_held_event_security":project(security, false).unwrap_or_else(unavailable),
        "same_held_event_mandatory_label":project(label, true).unwrap_or_else(unavailable)})
}

/// Export only reviewed scalar observations. The reader owns each bounded local
/// original; unsupported formats never acquire a complete-file hash claim.
pub fn redacted_toolchain_failure_summary(
    mut read_source: impl FnMut(&str) -> std::result::Result<Option<Vec<u8>>, ()>,
) -> serde_json::Value {
    use serde_json::json;
    const MAXIMUM: usize = 64 * 1024;
    #[derive(Deserialize)]
    enum Cleanup {
        Ok(()),
        Err(String),
    }
    fn explicit_status<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<i32>, D::Error> {
        Option::<i32>::deserialize(deserializer)
    }
    #[derive(Deserialize)]
    struct Callback {
        format: String,
        revision: u32,
        #[serde(deserialize_with = "explicit_status")]
        observed_status: Option<i32>,
        #[serde(deserialize_with = "explicit_status")]
        termination: Option<i32>,
        capture_complete: bool,
        cleanup: Cleanup,
    }
    let callback_bytes = read_source("result.callback-failure.json");
    let callback = callback_bytes
        .as_ref()
        .ok()
        .and_then(|v| v.as_ref())
        .filter(|bytes| bytes.len() <= MAXIMUM)
        .and_then(|bytes| serde_json::from_slice::<Callback>(bytes).ok())
        .filter(|value| {
            value.format == "memcordon.windows-positive-callback-failure"
                && value.revision == 1
                && value
                    .observed_status
                    .zip(value.termination)
                    .is_none_or(|(status, termination)| status == termination)
        });
    let capture_complete = callback
        .as_ref()
        .is_some_and(|value| value.capture_complete);
    let mut sources = Vec::new();
    for leaf in [
        "result.callback-failure.json",
        "result.stderr.bin",
        "result.controller-gate-security.json",
        "result.failed-frontend.json",
        "result.failed-terminal-observation.json",
        "result.guardian-query.json",
        "result.guardian-query.stdout.bin",
        "result.guardian-query.stderr.bin",
    ] {
        let data = if leaf == "result.callback-failure.json" {
            callback_bytes.clone()
        } else {
            read_source(leaf)
        };
        let mut source = json!({"leaf":leaf,"state":"unavailable","reason":"unsupported-format"});
        match data {
            Ok(None) => {
                source["state"] = json!("absent");
                source["reason"] = json!("not-produced");
            }
            Err(()) => {
                source["reason"] = json!("owned-read-unavailable");
            }
            Ok(Some(bytes)) if bytes.len() > MAXIMUM => {
                source["reason"] = json!("byte-bound");
            }
            Ok(Some(bytes)) => {
                let projected = if leaf == "result.callback-failure.json" {
                    callback.as_ref().map(|value|json!({"observed_status":value.observed_status,
                        "termination":value.termination,"capture_complete":value.capture_complete,
                        "cleanup":match &value.cleanup { Cleanup::Ok(()) => "ok", Cleanup::Err(_error) => "error" }}))
                } else if leaf == "result.stderr.bin" && capture_complete {
                    std::str::from_utf8(&bytes).ok().and_then(|text| {
                        let mut lines = text.lines().filter_map(|line|line.strip_prefix(
                            "memcordon-test-fixture: operation=OpenEventW-controller-wait; access="));
                        let line = lines.next()?;
                        if lines.next().is_some() { return None; }
                        let mut fields = line.split("; ");
                        let access = u32::from_str_radix(fields.next()?.strip_prefix("0x")?, 16).ok()?;
                        let kind = fields.next()?.strip_prefix("kind=")?;
                        if !matches!(kind, "PermissionDenied" | "NotFound" | "InvalidInput" | "Other") { return None; }
                        let error = fields.next()?.strip_prefix("raw-os-error=Some(")?.strip_suffix(')')?.parse::<i32>().ok()?;
                        if fields.next()? != "wait-status=None" { return None; }
                        // The remainder is intentionally not copied, parsed or
                        // interpreted as a token/access/native identity proof.
                        Some(json!({"diagnostic_reported":true,"operation":"OpenEventW-controller-wait",
                            "requested_access":access,"error_kind":kind,"raw_os_error":error,"wait_status":null}))
                    })
                } else {
                    None
                };
                if let Some(projected) = projected {
                    source["observation"] = projected;
                    if capture_complete {
                        source["state"] = json!("complete");
                        source["reason"] = json!("supported-complete-observation");
                        source["byte_length"] = json!(bytes.len());
                        source["sha256"] = json!(crate::windows_causal_acceptance::sha256(&bytes));
                    } else {
                        source["reason"] = json!("capture-incomplete");
                    }
                }
            }
        }
        sources.push(source);
    }
    json!({"format":"memcordon.toolchain-failure-summary","revision":1,
        "case":{"family":"W-TOOLCHAIN","scenario":"restricted"},
        "diagnostic_only":true,"acceptance_authority":false,"sources":sources})
}

#[cfg(windows)]
pub fn run_provider_input_experiment_until(
    root: &Path,
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
    dot_local_file: bool,
) -> Result<serde_json::Value> {
    native::provider_input_experiment(root, config, deadlines, dot_local_file)
}

#[cfg(windows)]
pub fn run_matched_owned_until(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
) -> Result<serde_json::Value> {
    native::matched_owned(config, deadlines)
}

#[cfg(windows)]
pub fn run_installed_with_deadlines(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input_path: &Path,
    assessments: &mut Vec<CaseAssessment>,
    deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
) -> Result<()> {
    native::run(
        config,
        input_path,
        assessments,
        deadlines.work,
        Some(deadlines),
    )
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::command::CommandSpec;
    use crate::windows_owned_guardian::{
        GuardianAssociationIdentity, GuardianBaseline, HeldGuardian,
    };
    use memcordon_testkit::WindowsImageProcess;
    use std::fs::{self, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    struct HeldConsoleImage {
        _file: fs::File,
        path: PathBuf,
        sha256: String,
        identity: serde_json::Value,
    }

    fn hold_console_image() -> io::Result<HeldConsoleImage> {
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
        let path = memcordon_testkit::windows_console_host_path()?;
        // Deny write/delete sharing while the original measured image is held.
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() > 16 * 1024 * 1024
        {
            return Err(io::Error::other(
                "native console image is not a bounded ordinary file",
            ));
        }
        let information = memcordon_testkit::windows_held_file_identity(&file)?;
        if information.length != metadata.len() {
            return Err(io::Error::other(
                "held native console file identity length differs",
            ));
        }
        let mut bytes = Vec::new();
        (&file).take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(io::Error::other("held native console image length changed"));
        }
        Ok(HeldConsoleImage {
            _file: file,
            path,
            sha256: crate::windows_causal_acceptance::sha256(&bytes),
            identity: serde_json::to_value(information).map_err(io::Error::other)?,
        })
    }

    fn provision_budget(deadline: Instant) -> Result<Duration> {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(30));
        if remaining.is_zero() {
            return Err(CiError::Message(
                "original Windows provisioning work deadline exhausted".into(),
            ));
        }
        Ok(remaining)
    }

    pub fn provision(
        root: &Path,
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        work_deadline: Instant,
    ) -> Result<()> {
        use memcordon_core::workload_request::*;
        use std::num::NonZeroU64;
        let directory = std::path::absolute(&config.output_directory)?;
        fs::create_dir_all(&directory)?;
        let locked = crate::config::toolchains(root)?.stable;
        let locate_budget = provision_budget(work_deadline)?;
        let mut locate = CommandSpec::new("rustup", root, locate_budget)
            .args([
                OsString::from("which"),
                "--toolchain".into(),
                locked.clone().into(),
                "rustc".into(),
            ])
            .materialize()?;
        let located = memcordon_testkit::run_with_deadline_output_limit(
            &mut locate,
            locate_budget,
            16 * 1024,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        if !located.status.success() {
            return Err(CiError::Message(
                "locked native Rust compiler is unavailable".into(),
            ));
        }
        let compiler = PathBuf::from(
            std::str::from_utf8(&located.stdout)
                .map_err(|error| CiError::Message(error.to_string()))?
                .trim(),
        );
        if !compiler.is_absolute() {
            return Err(CiError::Message(
                "locked compiler resolved to a nonabsolute path".into(),
            ));
        }
        let version_budget = provision_budget(work_deadline)?;
        let mut version = CommandSpec::new(&compiler, root, version_budget)
            .arg("-vV")
            .materialize()?;
        let version = memcordon_testkit::run_with_deadline_output_limit(
            &mut version,
            version_budget,
            16 * 1024,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let text = std::str::from_utf8(&version.stdout)
            .map_err(|error| CiError::Message(error.to_string()))?;
        if !version.status.success()
            || !text
                .lines()
                .any(|line| line.strip_prefix("release: ") == Some(locked.as_str()))
            || !text
                .lines()
                .any(|line| line.strip_prefix("host: ") == Some(config.target.as_str()))
        {
            return Err(CiError::Message(
                "locked compiler version/native host differs from selected channel target".into(),
            ));
        }
        fs::write(
            directory.join("windows-toolchain-version.txt"),
            &version.stdout,
        )?;
        let sources = std::path::absolute(root)?
            .join("crates")
            .join("memcordon-cli")
            .join("tests")
            .join("fixtures")
            .join("windows_readiness");
        let (native_work_cutoff_ticks, native_work_frequency) =
            memcordon_testkit::windows_native_work_cutoff(work_deadline)?;
        let mut toolchain = descriptor::Toolchain {
            native_work_cutoff_ticks,
            native_work_frequency,
            linker_mode: descriptor::LinkerMode::BundledLldLink,
            input_root: PathBuf::new(),
            rustc: compiler,
            native_linker: PathBuf::new(),
            selected_images: Vec::new(),
            native_library_directories: Vec::new(),
            library_source: sources.join("library.rs"),
            test_source: sources.join("tests.rs"),
            child_source: sources.join("child.rs"),
            dll_source: sources.join("dll.rs"),
            loader_source: sources.join("loader.rs"),
            target: config.target.clone(),
        };
        let mut measured = Vec::new();
        for path in [
            &toolchain.rustc,
            &toolchain.library_source,
            &toolchain.test_source,
            &toolchain.child_source,
            &toolchain.dll_source,
            &toolchain.loader_source,
        ] {
            let bytes = read(path, 64 * 1024 * 1024)?;
            measured.push(crate::windows_installed_cases::SelectedArtifact {
                path: path.clone(),
                sha256: crate::windows_causal_acceptance::sha256(&bytes),
            });
        }
        let measurement = serde_json::to_vec_pretty(&measured)?;
        fs::write(
            directory.join("windows-toolchain-inputs.json"),
            &measurement,
        )?;
        let snapshot_budget = provision_budget(work_deadline)?;
        let mut snapshot = CommandSpec::new(&config.fixture.path, &directory, snapshot_budget)
            .args(["consumer-readiness-windows", "token-snapshot"])
            .materialize()?;
        let snapshot = memcordon_testkit::run_with_deadline_output_limit(
            &mut snapshot,
            snapshot_budget,
            16 * 1024,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        if !snapshot.status.success() {
            return Err(CiError::Message(
                "native caller SID observation failed".into(),
            ));
        }
        let token: TokenObservation = serde_json::from_slice(&snapshot.stdout)?;
        let sid = sid_text(&token.user_sid)?;
        let input_acl = format!("D:P(A;OICI;GA;;;{sid})(A;OICI;GRGX;;;RC)(A;OICI;GA;;;SY)");
        set_directory_acl(&directory, &input_acl)?;
        // Executable files have effective authority but no child inheritance.
        // Keep the same ordered principals and rights as the input directory.
        let image_acl = format!("D:P(A;;GA;;;{sid})(A;;GRGX;;;RC)(A;;GA;;;SY)");
        for image in [&config.cli.path, &config.fixture.path] {
            set_directory_acl(image, &image_acl)?;
        }
        let owned_inputs = directory.join("locked-inputs");
        fs::create_dir(&owned_inputs)?;
        let compiler_root = toolchain
            .rustc
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| {
                CiError::Message("locked native compiler has no toolchain root".into())
            })?;
        let copied_compiler = owned_inputs.join("toolchain");
        let mut copied_measurements = Vec::new();
        copy_owned_inputs(
            compiler_root,
            &copied_compiler,
            &mut copied_measurements,
            work_deadline,
        )?;
        toolchain.rustc = copied_compiler.join("bin").join("rustc.exe");
        let (_measured_msvc_linker, libraries) = provision_native_linker(
            config,
            &owned_inputs,
            &mut copied_measurements,
            work_deadline,
        )?;
        toolchain.input_root = owned_inputs.clone();
        toolchain.native_linker = copied_compiler
            .join("lib")
            .join("rustlib")
            .join(&toolchain.target)
            .join("bin")
            .join("rust-lld.exe");
        toolchain.native_library_directories = libraries;
        verify_native_pe(&toolchain.rustc, &toolchain.target)?;
        verify_native_pe(&toolchain.native_linker, &toolchain.target)?;
        let copied_sources = owned_inputs.join("sources");
        fs::create_dir(&copied_sources)?;
        for source in [
            &mut toolchain.library_source,
            &mut toolchain.test_source,
            &mut toolchain.child_source,
            &mut toolchain.dll_source,
            &mut toolchain.loader_source,
        ] {
            provision_budget(work_deadline)?;
            let destination = copied_sources.join(
                source
                    .file_name()
                    .ok_or_else(|| CiError::Message("native source name missing".into()))?,
            );
            let bytes = read(source, 1024 * 1024)?;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)?
                .write_all(&bytes)?;
            let persisted = read(&destination, 1024 * 1024)?;
            if persisted != bytes {
                return Err(CiError::Message(
                    "copied native source readback differs".into(),
                ));
            }
            copied_measurements.push(crate::windows_installed_cases::SelectedArtifact {
                path: destination.clone(),
                sha256: crate::windows_causal_acceptance::sha256(&persisted),
            });
            *source = destination;
        }
        toolchain.selected_images = descriptor::project_toolchain_images(
            copied_measurements
                .iter()
                .map(|image| (image.path.clone(), image.sha256.clone())),
        )
        .map_err(CiError::Message)?;
        toolchain
            .validate_selected_images()
            .map_err(CiError::Message)?;
        fs::write(
            directory.join("windows-owned-inputs.json"),
            serde_json::to_vec_pretty(&copied_measurements)?,
        )?;
        let request = memcordon_core::workload_request::WorkloadRequestV1::parse(br#"{"format":"memcordon.workload-request","revision":1,"runtime":{"kind":"windows-sealed","profile":"windows-sealed-current-token-v1"},"requirements":[]}"#).map_err(|error| CiError::Message(error.to_string()))?;
        let template = directory.join("windows-request-template.json");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&template)?
            .write_all(
                &request
                    .canonical_bytes()
                    .map_err(|error| CiError::Message(error.to_string()))?,
            )?;
        let candidate = directory.join("candidate-outputs");
        fs::create_dir(&candidate)?;
        let driver_probe = directory.join("protected-driver-probe");
        let provider_probe =
            super::external_provider_probe_path(&directory, &config.installed_agent.path)?;
        fs::create_dir(&driver_probe)?;
        let candidate_acl = format!("D:P(A;OICI;GA;;;{sid})(A;OICI;GA;;;RC)(A;OICI;GA;;;SY)");
        let protected_acl =
            format!("D:P(D;OICI;GW;;;RC)(A;OICI;GA;;;{sid})(A;OICI;GRGX;;;RC)(A;OICI;GA;;;SY)");
        set_directory_acl(&candidate, &candidate_acl)?;
        set_directory_acl(&driver_probe, &protected_acl)?;
        fs::write(
            directory.join("windows-readiness-acl.json"),
            serde_json::to_vec_pretty(&[
                (&candidate, &candidate_acl),
                (&driver_probe, &protected_acl),
                (&provider_probe, &protected_acl),
            ])?,
        )?;
        let plan = WindowsReadinessPlan {
            request_template: template,
            toolchain,
            candidate_output_root: candidate,
            protected_write_probes: vec![
                driver_probe.join("denied-write.bin"),
                provider_probe.join("denied-write.bin"),
            ],
        };
        prepare(
            config,
            &plan,
            &directory.join("windows-readiness-input.json"),
            work_deadline,
        )
    }

    fn copy_owned_inputs(
        source: &Path,
        destination: &Path,
        measured: &mut Vec<crate::windows_installed_cases::SelectedArtifact>,
        work_deadline: Instant,
    ) -> Result<()> {
        provision_budget(work_deadline)?;
        if destination.components().count() > 256 {
            return Err(CiError::Message(
                "owned native input depth exceeds bound".into(),
            ));
        }
        if measured.len() > 200_000 {
            return Err(CiError::Message(
                "owned native input file count exceeds bound".into(),
            ));
        }
        let metadata = fs::symlink_metadata(source)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(CiError::Message(
                "owned native inputs cannot follow reparse points".into(),
            ));
        }
        if metadata.is_dir() {
            fs::create_dir(destination)?;
            for entry in fs::read_dir(source)? {
                let entry = entry?;
                copy_owned_inputs(
                    &entry.path(),
                    &destination.join(entry.file_name()),
                    measured,
                    work_deadline,
                )?;
            }
        } else if metadata.is_file() {
            let bytes = read(source, 512 * 1024 * 1024)?;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?
                .write_all(&bytes)?;
            let persisted = read(destination, 512 * 1024 * 1024)?;
            if persisted != bytes {
                return Err(CiError::Message(
                    "copied native toolchain input readback differs".into(),
                ));
            }
            measured.push(crate::windows_installed_cases::SelectedArtifact {
                path: destination.to_owned(),
                sha256: crate::windows_causal_acceptance::sha256(&persisted),
            });
        } else {
            return Err(CiError::Message(
                "native toolchain input is not an ordinary file/directory".into(),
            ));
        }
        Ok(())
    }

    #[allow(unsafe_code)] // Read-only bounded native registry discovery; no ambient environment lookup.
    fn registry_text(key: &str, value: &str, view: u32) -> Result<String> {
        use windows_sys::Win32::System::Registry::{
            HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW,
        };
        let key: Vec<_> = key.encode_utf16().chain(Some(0)).collect();
        let value: Vec<_> = value.encode_utf16().chain(Some(0)).collect();
        let mut buffer = vec![0u16; 16_384];
        let mut bytes = (buffer.len() * 2) as u32;
        // SAFETY: held bounded writable UTF-16 buffer and terminated read-only registry names.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ | view,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32).into());
        }
        if bytes < 2 || bytes as usize > buffer.len() * 2 || bytes % 2 != 0 {
            return Err(CiError::Message(
                "native registry text exceeds bound".into(),
            ));
        }
        buffer.truncate(bytes as usize / 2);
        if buffer.pop() != Some(0) || buffer.contains(&0) {
            return Err(CiError::Message(
                "native registry text lacks exact terminator".into(),
            ));
        }
        String::from_utf16(&buffer).map_err(|error| CiError::Message(error.to_string()))
    }

    fn verify_native_pe(path: &Path, target: &str) -> Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let mut dos = [0u8; 64];
        file.read_exact(&mut dos)?;
        if &dos[..2] != b"MZ" {
            return Err(CiError::Message(
                "native compiler/linker lacks a DOS PE header".into(),
            ));
        }
        let offset = u32::from_le_bytes(dos[60..64].try_into().expect("fixed PE header width"));
        if u64::from(offset) > file.metadata()?.len().saturating_sub(6) {
            return Err(CiError::Message(
                "native compiler/linker PE header offset exceeds held input".into(),
            ));
        }
        file.seek(SeekFrom::Start(u64::from(offset)))?;
        let mut header = [0u8; 6];
        file.read_exact(&mut header)?;
        let expected = match target {
            "x86_64-pc-windows-msvc" => 0x8664u16,
            "aarch64-pc-windows-msvc" => 0xaa64u16,
            _ => {
                return Err(CiError::Message(
                    "unsupported native toolchain PE target".into(),
                ));
            }
        };
        if &header[..4] != b"PE\0\0" || u16::from_le_bytes([header[4], header[5]]) != expected {
            return Err(CiError::Message(
                "measured compiler/linker PE machine differs from native target".into(),
            ));
        }
        Ok(())
    }

    fn provision_native_linker(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        inputs: &Path,
        measured: &mut Vec<crate::windows_installed_cases::SelectedArtifact>,
        work_deadline: Instant,
    ) -> Result<(PathBuf, Vec<PathBuf>)> {
        use windows_sys::Win32::System::Registry::RRF_SUBKEY_WOW6432KEY;
        let program_files = PathBuf::from(registry_text(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion",
            "ProgramFilesDir (x86)",
            0,
        )?);
        let vswhere = program_files
            .join("Microsoft Visual Studio")
            .join("Installer")
            .join("vswhere.exe");
        if !vswhere.is_absolute() {
            return Err(CiError::Message(
                "native VS discovery path is not absolute".into(),
            ));
        }
        let bytes = read(&vswhere, 16 * 1024 * 1024)?;
        measured.push(crate::windows_installed_cases::SelectedArtifact {
            path: vswhere.clone(),
            sha256: crate::windows_causal_acceptance::sha256(&bytes),
        });
        let discover_budget = provision_budget(work_deadline)?;
        let mut discover = CommandSpec::new(&vswhere, &config.output_directory, discover_budget)
            .args([
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property",
                "installationPath",
                "-utf8",
            ])
            .materialize()?;
        let output = memcordon_testkit::run_with_deadline_output_limit(
            &mut discover,
            discover_budget,
            16 * 1024,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err(CiError::Message("native VS discovery failed".into()));
        }
        fs::write(
            config.output_directory.join("windows-vs-discovery.txt"),
            &output.stdout,
        )?;
        let installation = PathBuf::from(
            std::str::from_utf8(&output.stdout)
                .map_err(|error| CiError::Message(error.to_string()))?
                .trim(),
        );
        if !installation.is_absolute() {
            return Err(CiError::Message("native VS installation missing".into()));
        }
        let version_bytes = read(
            &installation
                .join("VC")
                .join("Auxiliary")
                .join("Build")
                .join("Microsoft.VCToolsVersion.default.txt"),
            1024,
        )?;
        let version = std::str::from_utf8(&version_bytes)
            .map_err(|error| CiError::Message(error.to_string()))?
            .trim();
        if version.is_empty()
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            return Err(CiError::Message(
                "native VC toolset version is invalid".into(),
            ));
        }
        let architecture = match config.target.as_str() {
            "x86_64-pc-windows-msvc" => "x64",
            "aarch64-pc-windows-msvc" => "arm64",
            _ => return Err(CiError::Message("unsupported native linker target".into())),
        };
        let toolset = installation
            .join("VC")
            .join("Tools")
            .join("MSVC")
            .join(version);
        let linker_root = toolset
            .join("bin")
            .join(format!("Host{architecture}"))
            .join(architecture);
        let linker = inputs.join("msvc-bin");
        copy_owned_inputs(&linker_root, &linker, measured, work_deadline)?;
        let vc_library = inputs.join("msvc-lib");
        copy_owned_inputs(
            &toolset.join("lib").join(architecture),
            &vc_library,
            measured,
            work_deadline,
        )?;
        let sdk = PathBuf::from(registry_text(
            r"SOFTWARE\Microsoft\Windows Kits\Installed Roots",
            "KitsRoot10",
            RRF_SUBKEY_WOW6432KEY,
        )?);
        if !sdk.is_absolute() {
            return Err(CiError::Message("native SDK root is not absolute".into()));
        }
        let mut versions = Vec::new();
        for entry in fs::read_dir(sdk.join("Lib"))? {
            provision_budget(work_deadline)?;
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let numbers: Option<Vec<u32>> = name.split('.').map(|part| part.parse().ok()).collect();
            if let Some(numbers) = numbers.filter(|numbers| numbers.len() == 4) {
                if versions.len() > 256 {
                    return Err(CiError::Message(
                        "native SDK version list exceeds bound".into(),
                    ));
                }
                versions.push((numbers, entry.path()));
            }
        }
        versions.sort_by(|left, right| left.0.cmp(&right.0));
        let selected = versions
            .pop()
            .ok_or_else(|| CiError::Message("native SDK libraries unavailable".into()))?
            .1;
        let ucrt = inputs.join("sdk-ucrt");
        copy_owned_inputs(
            &selected.join("ucrt").join(architecture),
            &ucrt,
            measured,
            work_deadline,
        )?;
        let um = inputs.join("sdk-um");
        copy_owned_inputs(
            &selected.join("um").join(architecture),
            &um,
            measured,
            work_deadline,
        )?;
        Ok((linker.join("link.exe"), vec![vc_library, ucrt, um]))
    }

    struct OwnedProviderProbe {
        path: PathBuf,
        identity: (u32, u64),
        guards: Vec<std::fs::File>,
        cleanup: Instant,
    }
    // This finite table retains only directories created by this controller.
    // Neither a path nor a serialized witness can populate it.
    static PROVIDER_PROBES: Mutex<Vec<OwnedProviderProbe>> = Mutex::new(Vec::new());

    #[allow(unsafe_code)] // Atomic new-directory creation relative to its retained original parent.
    fn create_probe_directory(
        parent: &std::fs::File,
        name: &std::ffi::OsStr,
        work: Instant,
    ) -> io::Result<std::fs::File> {
        use std::os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle},
        };
        use windows_sys::{
            Wdk::{
                Foundation::OBJECT_ATTRIBUTES,
                Storage::FileSystem::{
                    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT,
                    FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
                },
            },
            Win32::{
                Foundation::{
                    INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, UNICODE_STRING,
                },
                Storage::FileSystem::{
                    FILE_ATTRIBUTE_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                    FILE_SHARE_WRITE, READ_CONTROL, SYNCHRONIZE,
                },
                System::IO::IO_STATUS_BLOCK,
            },
        };
        provision_budget(work).map_err(io::Error::other)?;
        let mut units: Vec<_> = name.encode_wide().collect();
        if units.is_empty()
            || units.len() > 64
            || units.iter().any(|unit| [0, 47, 92, 58].contains(unit))
            || units == [46]
            || units == [46, 46]
        {
            return Err(io::Error::other(
                "fixture probe leaf is not one bounded component",
            ));
        }
        let length = (units.len() * 2) as u16;
        let mut name = UNICODE_STRING {
            Length: length,
            MaximumLength: length,
            Buffer: units.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent.as_raw_handle(),
            ObjectName: &mut name,
            Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let mut raw = std::ptr::null_mut();
        let mut status_block = IO_STATUS_BLOCK::default();
        let status = unsafe {
            NtCreateFile(
                &mut raw,
                FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                &attributes,
                &mut status_block,
                std::ptr::null(),
                FILE_ATTRIBUTE_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_CREATE,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null(),
                0,
            )
        };
        // A pending synchronous operation cannot outlive these stack outputs.
        if status == 0x103 {
            std::process::abort();
        }
        if status < 0 {
            return Err(io::Error::other(format!(
                "fixture new-directory NtCreateFile failed NTSTATUS={status:#x}"
            )));
        }
        if status != 0 || raw.is_null() || raw == INVALID_HANDLE_VALUE {
            std::process::abort();
        }
        let owner = unsafe { std::fs::File::from_raw_handle(raw) };
        if status_block.Information != 2 {
            return Err(io::Error::other("fixture directory was not newly created"));
        }
        Ok(owner)
    }

    fn provider_probe_parents(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        work: Instant,
    ) -> Result<Vec<std::fs::File>> {
        super::external_provider_probe_path(
            &config.output_directory,
            &config.installed_agent.path,
        )?;
        let guards = descriptor::matched_plan::hold_chain(&config.output_directory, work)?;
        let install = descriptor::matched_plan::hold_chain(
            config
                .installed_agent
                .path
                .parent()
                .ok_or_else(|| CiError::Message("installed provider root absent".into()))?,
            work,
        )?;
        let protected = memcordon_testkit::windows_held_file_metadata(
            install
                .last()
                .ok_or_else(|| CiError::Message("installed root custody absent".into()))?,
        )?;
        for guard in &guards {
            let actual = memcordon_testkit::windows_held_file_metadata(guard)?;
            if (actual.volume_serial, actual.file_index)
                == (protected.volume_serial, protected.file_index)
            {
                return Err(CiError::Message(
                    "fixture probe parent is physically within installed root".into(),
                ));
            }
        }
        Ok(guards)
    }

    fn create_provider_probe(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        acl: &str,
        work: Instant,
        cleanup: Instant,
    ) -> Result<PathBuf> {
        provision_budget(work)?;
        let path = super::external_provider_probe_path(
            &config.output_directory,
            &config.installed_agent.path,
        )?;
        let mut owners = PROVIDER_PROBES
            .lock()
            .map_err(|_| CiError::Message("owned provider probes poisoned".into()))?;
        if owners.len() >= 8 || owners.iter().any(|owner| owner.path == path) {
            return Err(CiError::Message(
                "owned provider probe count or path reused".into(),
            ));
        }
        let mut guards = provider_probe_parents(config, work)?;
        let acquired = (|| -> Result<(std::fs::File, (u32, u64))> {
            let leaf = create_probe_directory(
                guards.last().ok_or_else(|| {
                    CiError::Message("probe original parent reference absent".into())
                })?,
                path.file_name()
                    .ok_or_else(|| CiError::Message("probe leaf absent".into()))?,
                work,
            )?;
            let info = memcordon_testkit::windows_held_file_metadata(&leaf)?;
            Ok((leaf, (info.volume_serial, info.file_index)))
        })();
        let (leaf, identity) = match acquired {
            Ok(value) => value,
            Err(error) => {
                let _parents = Box::leak(Box::new(guards));
                return Err(error);
            }
        };
        guards.push(leaf);
        owners.push(OwnedProviderProbe {
            path: path.clone(),
            identity,
            guards,
            cleanup,
        });
        provision_budget(work)?;
        set_directory_acl(&path, acl)?;
        provision_budget(work)?;
        Ok(path)
    }

    pub fn cleanup_provider_probe(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
    ) -> Result<()> {
        let path = super::external_provider_probe_path(
            &config.output_directory,
            &config.installed_agent.path,
        )?;
        let mut owners = PROVIDER_PROBES
            .lock()
            .map_err(|_| CiError::Message("owned provider probes poisoned".into()))?;
        let Some(index) = owners.iter().position(|owner| owner.path == path) else {
            return if path.try_exists()? {
                Err(CiError::Message(
                    "provider probe exists without this controller's original native owner".into(),
                ))
            } else {
                Ok(())
            };
        };
        let mut owner = owners.remove(index);
        drop(owners);
        // Keep all original parents; only close the leaf before the existing
        // DELETE-owner helper joins its created identity and disposes that handle.
        drop(owner.guards.pop());
        let result = descriptor::matched_plan::remove_empty_directory(
            &owner.path,
            owner.identity,
            owner.cleanup,
        )
        .map_err(CiError::Io);
        if result.is_err() {
            let _retained = Box::leak(Box::new(owner));
        }
        result
    }

    pub(crate) fn prepare_owned_probe_image(path: &Path, caller_sid: &[u8]) -> Result<()> {
        let sid = sid_text(caller_sid)?;
        set_directory_acl(
            path,
            &format!("D:P(A;;GA;;;{sid})(A;;GRGX;;;RC)(A;;GA;;;SY)"),
        )
    }

    #[allow(unsafe_code)] // Native ACL installation/readback only on explicitly owned paths.
    fn set_directory_acl(path: &Path, sddl: &str) -> Result<()> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT, SetNamedSecurityInfoW,
        };
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
            IsValidAcl, PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        };
        let sddl: Vec<_> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut security = std::ptr::null_mut();
        // SAFETY: terminated explicit SDDL and writable native output pointer.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut security,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let operation = (|| -> Result<()> {
            let mut present = 0;
            let mut defaulted = 0;
            let mut acl = std::ptr::null_mut();
            // SAFETY: successful conversion owns a valid descriptor until LocalFree.
            if unsafe {
                GetSecurityDescriptorDacl(security, &mut present, &mut acl, &mut defaulted)
            } == 0
                || present == 0
                || acl.is_null()
            {
                return Err(CiError::Message(
                    "explicit readiness ACL did not contain a DACL".into(),
                ));
            }
            let mut name: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            // SAFETY: owned setup directory, exact parsed DACL, terminated mutable path.
            let status = unsafe {
                SetNamedSecurityInfoW(
                    name.as_mut_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    acl,
                    std::ptr::null_mut(),
                )
            };
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32).into());
            }
            let mut actual_acl = std::ptr::null_mut();
            let mut actual_security = std::ptr::null_mut();
            // SAFETY: same exact owned path; API allocates the returned descriptor.
            let status = unsafe {
                GetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut actual_acl,
                    std::ptr::null_mut(),
                    &mut actual_security,
                )
            };
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32).into());
            }
            let mut control = 0;
            let mut revision = 0;
            // SAFETY: descriptor/ACL pointers are owned API outputs, valid until
            // LocalFree. Native validation precedes every bounded ACL slice.
            let comparison = unsafe {
                if actual_acl.is_null() || IsValidAcl(acl) == 0 || IsValidAcl(actual_acl) == 0 {
                    Err("native readiness DACL is absent or malformed".to_owned())
                } else if GetSecurityDescriptorControl(actual_security, &mut control, &mut revision)
                    == 0
                {
                    Err(io::Error::last_os_error().to_string())
                } else {
                    crate::windows_readiness_acl::verify_file_dacl(
                        std::slice::from_raw_parts(acl.cast::<u8>(), (*acl).AclSize as usize),
                        std::slice::from_raw_parts(
                            actual_acl.cast::<u8>(),
                            (*actual_acl).AclSize as usize,
                        ),
                        control & SE_DACL_PROTECTED != 0,
                    )
                }
            };
            // SAFETY: GetNamedSecurityInfoW allocated this independent descriptor.
            unsafe { LocalFree(actual_security) };
            comparison.map_err(|detail| {
                let bytes = path.as_os_str().as_encoded_bytes();
                let object = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]);
                let object_type = match fs::symlink_metadata(path) {
                    Ok(metadata) if metadata.is_dir() => "directory",
                    Ok(metadata) if metadata.is_file() => "file",
                    Ok(_) => "other",
                    Err(_) => "unavailable",
                };
                CiError::Message(format!(
                    "native readiness directory DACL readback differs: {detail}; object={object:?}; object-path-truncated={}; object-type={object_type}",
                    bytes.len() > 512,
                ))
            })?;
            Ok(())
        })();
        // SAFETY: conversion allocated this one security descriptor with LocalAlloc.
        unsafe { LocalFree(security) };
        operation
    }

    #[allow(unsafe_code)] // Bounded aligned SID conversion with native allocation ownership.
    fn sid_text(bytes: &[u8]) -> Result<String> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        super::start_gate_policy::validate_sid(bytes)?;
        let mut aligned = vec![0u32; bytes.len().div_ceil(std::mem::size_of::<u32>())];
        // SAFETY: aligned allocation covers the full bounded SID byte representation.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), aligned.as_mut_ptr().cast(), bytes.len())
        };
        // Extent is checked before either native function may inspect the SID.
        if unsafe { windows_sys::Win32::Security::IsValidSid(aligned.as_mut_ptr().cast()) } == 0
            || unsafe { windows_sys::Win32::Security::GetLengthSid(aligned.as_mut_ptr().cast()) }
                as usize
                != bytes.len()
        {
            return Err(CiError::Message(
                "selected caller native SID validity or length differs".into(),
            ));
        }
        let mut text = std::ptr::null_mut();
        // SAFETY: bounded SID observed from the held native caller token.
        if unsafe { ConvertSidToStringSidW(aligned.as_mut_ptr().cast(), &mut text) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut length = 0usize;
        // SAFETY: successful conversion guarantees a terminated native SID string.
        let authority_width = ((1u64 << (bytes[2..8].len() * 8)) - 1)
            .to_string()
            .len()
            .max("0x".len() + bytes[2..8].len() * 2);
        let text_bound = "S-1-".len()
            + authority_width
            + usize::from(bytes[1]) * ("-".len() + u32::MAX.to_string().len())
            + 1;
        while length < text_bound && unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        let converted = if length == text_bound {
            Err(CiError::Message(
                "native caller SID string exceeds bound".into(),
            ))
        } else {
            String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
                .map_err(|error| CiError::Message(error.to_string()))
        };
        // SAFETY: conversion allocated this string with LocalAlloc.
        unsafe { LocalFree(text.cast()) };
        converted
    }

    fn bounded_vec<T, const N: usize>(values: Vec<T>) -> Result<memcordon_core::BoundedVec<T, N>> {
        let mut result = memcordon_core::BoundedVec::default();
        for value in values {
            result.try_push(value).map_err(|_| {
                CiError::Message("readiness collection exceeds its declared bound".into())
            })?;
        }
        Ok(result)
    }

    pub fn prepare(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        plan: &WindowsReadinessPlan,
        input_path: &Path,
        work_deadline: Instant,
    ) -> Result<()> {
        if !plan.candidate_output_root.is_absolute() || plan.protected_write_probes.len() < 2 {
            return Err(CiError::Message(
                "native Windows plan must grant a candidate root and protect driver/provider paths"
                    .into(),
            ));
        }
        // Observe each actual native caller context outside target execution.
        let snapshot = |restricted: bool| -> Result<TokenObservation> {
            let mut args: Vec<OsString> = vec!["consumer-readiness-windows".into()];
            if restricted {
                args.extend([
                    "restricted-frontend".into(),
                    config.fixture.path.clone().into_os_string(),
                    "consumer-readiness-windows".into(),
                ]);
            }
            args.push("token-snapshot".into());
            let budget = provision_budget(work_deadline)?;
            let mut command =
                CommandSpec::new(&config.fixture.path, &config.output_directory, budget)
                    .args(args)
                    .materialize()?;
            command.env_clear();
            let output =
                memcordon_testkit::run_with_deadline_output_limit(&mut command, budget, 16 * 1024)
                    .map_err(|error| CiError::Message(error.to_string()))?;
            crate::release::source::write_diagnostic_json(
                &config.output_directory.join(if restricted {
                    "windows-restricted-token-capture.json"
                } else {
                    "windows-ordinary-token-capture.json"
                }),
                &serde_json::json!({
                    "format":"memcordon.windows-caller-token-capture",
                    "revision":1,
                    "restricted":restricted,
                    "program_debug":format!("{:?}",command.get_program()),
                    "arguments_debug":command.get_args().map(|argument|format!("{argument:?}")).collect::<Vec<_>>(),
                    "status":output.status.code(),
                    "success":output.status.success(),
                    "stdout":output.stdout,
                    "stderr":output.stderr,
                }),
            )?;
            if !output.status.success() || !output.stderr.is_empty() {
                return Err(CiError::Message(
                    crate::windows_caller_snapshot_diagnostic::failure(
                        restricted,
                        output.status.code(),
                        &output.stdout,
                        &output.stderr,
                    ),
                ));
            }
            let token: TokenObservation = serde_json::from_slice(&output.stdout)?;
            if token.restricted != restricted {
                return Err(CiError::Message(
                    "native caller restriction differs from required variant".into(),
                ));
            }
            if restricted
                && token.restricting_sids != vec![vec![1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]]
            {
                return Err(CiError::Message("native restricted caller does not use the independently granted RestrictedCode principal".into()));
            }
            let path = config.output_directory.join(if restricted {
                "windows-restricted-token.json"
            } else {
                "windows-ordinary-token.json"
            });
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            file.write_all(&output.stdout)?;
            file.sync_all()?;
            if read(&path, 16 * 1024)? != output.stdout {
                return Err(CiError::Message(
                    "caller token named readback differs".into(),
                ));
            }
            Ok(token)
        };
        let ordinary = snapshot(false)?;
        let restricted = snapshot(true)?;
        let random = random_challenge()?;
        let run = crate::windows_causal_acceptance::sha256(&random);
        let mut cases = Vec::new();
        for key in positive_keys() {
            provision_budget(work_deadline)?;
            let output = plan
                .candidate_output_root
                .join(&key.family)
                .join(&key.scenario);
            let FixtureParameters {
                case,
                stdout,
                stderr,
                arguments,
                application_status: status,
            } = fixture_parameters(&key)?;
            let event_stem = format!(
                "Local\\memcordon-readiness-{run}-{}-{}",
                key.family, key.scenario
            );
            let start_gate = Some(event_stem.clone());
            let descendant_gate = matches!(
                case,
                descriptor::Case::RootFirst | descriptor::Case::IntermediateFirst
            )
            .then(|| {
                PathBuf::from(&event_stem)
                    .with_extension("descendant")
                    .to_string_lossy()
                    .into_owned()
            });
            let caller = if matches!(
                key.scenario.as_str(),
                "restricted" | "restricted-token-preserved"
            ) {
                restricted.clone()
            } else {
                ordinary.clone()
            };
            let descriptor = descriptor::Descriptor {
                matched_control: None,
                format: "memcordon.fixture-workload".into(),
                revision: descriptor::DESCRIPTOR_REVISION,
                case,
                output_root: output.clone(),
                transcript: output.join("fixture-events.bin"),
                challenge: random_challenge()?.to_vec(),
                stdout,
                stderr,
                arguments,
                application_status: status,
                churn_creations: descriptor::CHURN_CREATIONS,
                churn_live: descriptor::CHURN_LIVE,
                denied_write_paths: if matches!(
                    key.scenario.as_str(),
                    "restricted" | "restricted-token-preserved"
                ) {
                    plan.protected_write_probes.clone()
                } else {
                    Vec::new()
                },
                sentinel_handles: Vec::new(),
                descendant_gate,
                start_gate,
                start_transport: super::expected_start_transport(&key),
                control_clock: None,
                winsock_registry: None,
                provider_input_experiment: false,
                provider_input_paths: Vec::new(),
                provider_input_binding: None,
                gate_access_diagnostic: None,
                gate_precondition: None,
                completion_gate: None,
                cohort_gate: (case == descriptor::Case::Churn)
                    .then(|| format!("{event_stem}-cohort")),
                generation_gate: (case == descriptor::Case::Churn)
                    .then(|| format!("{event_stem}-generation")),
                toolchain: matches!(
                    case,
                    descriptor::Case::Toolchain | descriptor::Case::Joint | descriptor::Case::Churn
                )
                .then(|| plan.toolchain.clone()),
            };
            validate_descriptor(&key, &descriptor)?;
            cases.push(CaseInput {
                key,
                descriptor,
                descriptor_path: output.with_extension("input.json"),
                workload_request: plan.request_template.clone(),
                expected_token: caller,
            });
        }
        // The sentinel frontend creates/holds the exact native file and adds its
        // identity to the descriptor before launching the actual public frontend.
        let suite = SuiteInput {
            format: "memcordon.windows-readiness-input".into(),
            revision: 2,
            cases,
        };
        let bytes = serde_json::to_vec_pretty(&suite)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(input_path)?
            .write_all(&bytes)?;
        Ok(())
    }

    pub(crate) fn read(path: &Path, bound: usize) -> Result<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() > bound as u64
        {
            return Err(CiError::Message(
                "readiness evidence is not a bounded ordinary file".into(),
            ));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((bound + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > bound {
            return Err(CiError::Message(
                "readiness evidence exceeded bound during read".into(),
            ));
        }
        Ok(bytes)
    }

    fn retain_callback_product_context(
        public_report: &Path,
        report: &Path,
        provider: &memcordon_core::PublicProviderBindingV1,
    ) -> Result<serde_json::Value> {
        if !public_report.try_exists()? {
            return Ok(serde_json::json!({"authority":"diagnostic-only", "result":"absent"}));
        }
        let bytes = read(
            public_report,
            crate::windows_causal_acceptance::MAX_REPORT_BYTES,
        )?;
        let result = ResultV3::parse(&bytes).map_err(CiError::Message)?;
        let association = super::current_association(&result)?;
        if &association.provider != provider {
            return Err(CiError::Message(
                "callback product context provider differs".into(),
            ));
        }
        let retain = |extension: &str, bytes: &[u8]| -> Result<serde_json::Value> {
            let path = report.with_extension(extension);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            if read(&path, bytes.len())? != bytes {
                return Err(CiError::Message(
                    "callback product context copy differs".into(),
                ));
            }
            Ok(
                serde_json::json!({"path":path,"sha256":crate::windows_causal_acceptance::sha256(bytes)}),
            )
        };
        // Preserve the original independently of any sidecar read or validation error.
        let original = retain("failed-frontend.json", &bytes)?;
        let terminal_context = (|| -> Result<serde_json::Value> {
            let path = public_report.with_extension("terminal-observation.json");
            if !path.try_exists()? {
                return Ok(serde_json::json!({"state":"absent"}));
            }
            let bytes = read(&path, memcordon_platform::MAX_TERMINAL_OBSERVATION_BYTES)?;
            let terminal: memcordon_platform::AuthenticatedWindowsTerminalObservation =
                serde_json::from_slice(&bytes)?;
            if terminal.format != "memcordon.windows-terminal-observation"
                || terminal.revision != 2
                || terminal.provider != association.provider
                || terminal.terminal.attempt_id != String::from(association.attempt_id.clone())
                || terminal.terminal.request_sha256
                    != String::from(association.request_sha256.clone())
                || terminal.terminal.validate_for_attempt().is_err()
                || !terminal.frontend_delivery.is_consistent()
                || terminal.frontend_delivery.attempt_id != terminal.terminal.attempt_id
                || terminal.frontend_delivery.nonce != terminal.terminal.nonce
                || terminal.frontend_delivery.request_sha256 != terminal.terminal.request_sha256
                || crate::windows_causal_acceptance::sha256(&terminal.provider_request)
                    != terminal.terminal.request_sha256
            {
                return Err(CiError::Message(
                    "callback terminal context association differs".into(),
                ));
            }
            retain("failed-terminal-observation.json", &bytes)
        })()
        .map_err(|error| error.to_string());
        Ok(
            serde_json::json!({"authority":"diagnostic-only", "original":original,
            "terminal":terminal_context, "terminal_use":"associated context, never outcome acceptance"}),
        )
    }

    #[allow(unsafe_code)] // Fixed-size native cryptographic challenge generation.
    pub(crate) fn random_challenge() -> Result<[u8; 32]> {
        let mut random = [0u8; 32];
        // SAFETY: fixed writable output buffer and system-preferred native RNG.
        if unsafe {
            windows_sys::Win32::Security::Cryptography::BCryptGenRandom(
                std::ptr::null_mut(),
                random.as_mut_ptr(),
                random.len() as u32,
                windows_sys::Win32::Security::Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        } < 0
        {
            return Err(CiError::Message(
                "fresh readiness challenge generation failed".into(),
            ));
        }
        if random.iter().all(|byte| *byte == 0) {
            return Err(CiError::Message(
                "native readiness challenge was all zero".into(),
            ));
        }
        Ok(random)
    }

    const CONTROLLER_GATE_SDDL: &str = super::start_gate_policy::BASE_SDDL;

    #[derive(Debug)]
    struct StartWriteFailure {
        primary: io::Error,
        settlement: String,
    }
    impl std::fmt::Display for StartWriteFailure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{}; original START I/O deadline settlement: {}",
                self.primary, self.settlement
            )
        }
    }
    impl std::error::Error for StartWriteFailure {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.primary)
        }
    }
    struct ControlSession {
        writer: Option<std::process::ChildStdin>,
        binding: descriptor::controller_start::Binding,
        sender: descriptor::controller_start::Sender,
        deadline: Instant,
    }
    impl ControlSession {
        fn peer_held(
            &mut self,
            peer: &descriptor::controller_start::PeerRecipient,
        ) -> io::Result<()> {
            if self.writer.is_none() {
                return Err(io::Error::other(
                    "original peer admission writer unavailable",
                ));
            }
            let owner = match memcordon_platform::WindowsSynchronousIoDeadline::start(self.deadline)
            {
                Ok(owner) => owner,
                Err(error) => {
                    self.writer.take();
                    return Err(io::Error::other(error));
                }
            };
            let writer = self.writer.as_mut().expect("checked original peer writer");
            let primary = self.sender.send_peer_held(writer, &self.binding, peer, || {
                provision_budget(self.deadline)
                    .map(|_| ())
                    .map_err(io::Error::other)
            });
            if primary.is_err() {
                self.writer.take();
            }
            let settled = owner.finish();
            if settled.is_err() {
                self.writer.take();
            }
            match (primary, settled) {
                (Err(primary), Err(settlement)) => Err(io::Error::new(
                    primary.kind(),
                    StartWriteFailure {
                        primary,
                        settlement,
                    },
                )),
                (Err(primary), Ok(())) => Err(primary),
                (Ok(()), Err(settlement)) => Err(io::Error::other(settlement)),
                (Ok(()), Ok(())) => provision_budget(self.deadline)
                    .map(|_| ())
                    .map_err(io::Error::other),
            }
        }
        fn release(&mut self, phase: descriptor::controller_start::Phase) -> io::Result<()> {
            if self.writer.is_none() {
                return Err(io::Error::other("original control writer already closed"));
            }
            let owner = match memcordon_platform::WindowsSynchronousIoDeadline::start(self.deadline)
            {
                Ok(owner) => owner,
                Err(error) => {
                    self.writer.take();
                    return Err(io::Error::other(error));
                }
            };
            let writer = self.writer.as_mut().expect("checked original writer");
            let written = self.sender.send(writer, &self.binding, phase, || {
                provision_budget(self.deadline)
                    .map(|_| ())
                    .map_err(io::Error::other)
            });
            if self.sender.completed() || written.is_err() {
                self.writer.take();
            }
            let settled = owner.finish(); // Join before the calling thread begins any unrelated I/O.
            if settled.is_err() {
                self.writer.take();
            }
            match (written, settled) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(primary), Ok(())) => Err(primary),
                (Ok(()), Err(secondary)) => Err(io::Error::other(secondary)),
                (Err(primary), Err(settlement)) => Err(io::Error::new(
                    primary.kind(),
                    StartWriteFailure {
                        primary,
                        settlement,
                    },
                )),
            }
        }
    }

    struct PreparedGateInput {
        input: CaseInput,
        gate: Option<Arc<OwnedHandle>>,
        prelaunch_security: serde_json::Value,
        prelaunch_label: serde_json::Value,
        binding_setup: serde_json::Value,
        original_descriptor_sha256: Option<String>,
        requested_sddl: String,
        namespace: Option<super::gate_namespace::Discovery>,
        toolchain_held_gate: Option<serde_json::Value>,
    }

    fn prepare_gate_input(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        work_deadline: Instant,
        clock: GateClock<'_>,
    ) -> Result<PreparedGateInput> {
        let name = input.descriptor.start_gate.as_ref().ok_or_else(|| {
            CiError::Message("positive input omitted held-root native barrier".into())
        })?;
        provision_budget(work_deadline)?;
        let observed_path = config
            .output_directory
            .join(if input.expected_token.restricted {
                "windows-restricted-token.json"
            } else {
                "windows-ordinary-token.json"
            });
        let selected: TokenObservation = serde_json::from_slice(&read(&observed_path, 16 * 1024)?)?;
        if selected != input.expected_token {
            return Err(CiError::Message(
                "start-gate waiter differs from original selected native caller observation".into(),
            ));
        }
        provision_budget(work_deadline)?;
        let stdin_start = matches!(
            input.descriptor.start_transport,
            descriptor::StartTransport::ControllerStdin { .. }
        );
        let created = start_gate_create(name, &selected.user_sid, work_deadline);
        let (gate, requested_sddl, creation_error) = match created {
            Ok((gate, sddl)) => (Some(Arc::new(gate)), sddl, None),
            Err(error) if stdin_start => (None, String::new(), Some(error.to_string())),
            Err(error) => return Err(error),
        };
        let mut final_input = input.clone();
        // Serialized suite input is a plan, never a substitute descriptor owner.
        final_input.descriptor.gate_access_diagnostic = None;
        final_input.descriptor.gate_precondition = None;
        prepare_gate_clock(
            &mut final_input.descriptor,
            clock,
            work_deadline,
            || {
                let (work_cutoff_qpc, qpc_frequency) =
                    memcordon_testkit::windows_native_work_cutoff(work_deadline)?;
                Ok(descriptor::ControlClock {
                    revision: 1,
                    work_cutoff_qpc,
                    qpc_frequency,
                })
            },
            || memcordon_testkit::windows_performance_counter().map_err(CiError::from),
        )?;
        if final_input.descriptor.case == descriptor::Case::Envelope
            && final_input.descriptor.matched_control.is_none()
            && final_input.descriptor.start_transport == descriptor::StartTransport::NamedEvent
        {
            let (work_cutoff_qpc, qpc_frequency) =
                memcordon_testkit::windows_native_work_cutoff(work_deadline)?;
            bind_invocation_clock(
                &mut final_input.descriptor,
                descriptor::ControlClock {
                    revision: 1,
                    work_cutoff_qpc,
                    qpc_frequency,
                },
            )?;
        }
        let mut prelaunch_security =
            serde_json::json!({"state":"unavailable","reason":"comparison-not-requested"});
        let mut binding_setup = prelaunch_security.clone();
        let mut original_descriptor_sha256 = None;
        let mut prelaunch_label =
            serde_json::json!({"state":"unavailable","reason":"comparison-not-requested"});
        let mut namespace = None;
        // Two bounded passive queries only. Their setup cost is charged to the
        // original work cutoff and can perturb timing; OS calls cannot be cancelled.
        let toolchain_held_gate = super::start_gate_policy::capture_toolchain_held_gate(
            &input.key.family,
            &input.key.scenario,
        )
        .then(|| {
            let began = Instant::now();
            let (security, label) = match gate.as_ref() {
                Some(gate) => (
                    gate_query_result(super::workload_diagnostic::gate_security_snapshot(
                        gate.as_ref(),
                        work_deadline,
                    )),
                    gate_query_result(super::workload_diagnostic::gate_mandatory_label_snapshot(
                        gate.as_ref(),
                        work_deadline,
                    )),
                ),
                None => (
                    serde_json::json!({"state":"unavailable"}),
                    serde_json::json!({"state":"unavailable"}),
                ),
            };
            let mut value = super::redacted_toolchain_held_gate_observation(&security, &label);
            value["setup_elapsed_micros"] = serde_json::json!(began.elapsed().as_micros());
            value
        });
        if super::start_gate_policy::capture_restricted_gate(&input.key.family, &input.key.scenario)
        {
            let (work_cutoff_qpc, qpc_frequency) =
                memcordon_testkit::windows_native_work_cutoff(work_deadline)?;
            final_input.descriptor.gate_precondition = Some(descriptor::gate_precondition::Input {
                revision: 1,
                expected_token: selected.clone(),
                work_cutoff_qpc,
                qpc_frequency,
            });
            if let Some(gate) = gate.as_ref() {
                prelaunch_label =
                    gate_query_result(super::workload_diagnostic::gate_mandatory_label_snapshot(
                        gate.as_ref(),
                        work_deadline,
                    ));
                match super::workload_diagnostic::gate_security_snapshot(
                    gate.as_ref(),
                    work_deadline,
                ) {
                    Ok(snapshot) => {
                        original_descriptor_sha256 = Some(snapshot.descriptor_sha256.clone());
                        let binding = (|| -> io::Result<descriptor::gate_access::Input> {
                            let bytes =
                                hex::decode(&snapshot.descriptor_bytes_hex).map_err(|_| {
                                    io::Error::other(
                                        "original held gate descriptor encoding differs",
                                    )
                                })?;
                            let name: Vec<u16> = name.encode_utf16().collect();
                            let name_bytes: Vec<u8> =
                                name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
                            let (work_cutoff_qpc, qpc_frequency) =
                                memcordon_testkit::windows_native_work_cutoff(work_deadline)?;
                            let binding = descriptor::gate_access::Input {
                                revision: 1,
                                descriptor: bytes,
                                descriptor_sha256: snapshot.descriptor_sha256.clone(),
                                name_utf16_sha256: crate::windows_causal_acceptance::sha256(
                                    &name_bytes,
                                ),
                                challenge_sha256: crate::windows_causal_acceptance::sha256(
                                    &input.descriptor.challenge,
                                ),
                                work_cutoff_qpc,
                                qpc_frequency,
                                namespace: None,
                            };
                            binding.validate(&name, &input.descriptor.challenge)?;
                            Ok(binding)
                        })();
                        match binding {
                            Ok(mut binding) => {
                                let name: Vec<u16> = name.encode_utf16().collect();
                                let discovered = super::gate_namespace::discover(
                                    gate.as_ref(),
                                    &name,
                                    &binding,
                                    || {
                                        provision_budget(work_deadline)
                                            .map(|_| ())
                                            .map_err(io::Error::other)
                                    },
                                );
                                binding.namespace = discovered.proof.clone();
                                namespace = Some(discovered);
                                final_input.descriptor.gate_access_diagnostic = Some(binding);
                                binding_setup = serde_json::json!({"state":"observed","source":"same original held event before final descriptor freeze"});
                            }
                            Err(error) => binding_setup = gate_query_result::<()>(Err(error)),
                        }
                        prelaunch_security = gate_query_result(Ok(snapshot));
                    }
                    Err(error) => {
                        prelaunch_security = gate_query_result::<()>(Err(error));
                        binding_setup = serde_json::json!({"state":"unavailable","reason":"original-snapshot-unavailable"});
                    }
                }
            } else {
                prelaunch_security = serde_json::json!({"state":"unavailable","operation":"CreateEventW-independent-diagnostic","detail":creation_error});
                prelaunch_label = prelaunch_security.clone();
                binding_setup = prelaunch_security.clone();
            }
        }
        if final_input
            .descriptor
            .gate_access_diagnostic
            .as_ref()
            .is_some_and(|binding| binding.namespace.is_some())
            && serde_json::to_vec(&final_input.descriptor)?.len() > descriptor::MAX_DESCRIPTOR_BYTES
        {
            final_input
                .descriptor
                .gate_access_diagnostic
                .as_mut()
                .expect("checked access input")
                .namespace = None;
        }
        if final_input.descriptor.gate_access_diagnostic.is_some()
            && serde_json::to_vec(&final_input.descriptor)?.len() > descriptor::MAX_DESCRIPTOR_BYTES
        {
            final_input.descriptor.gate_access_diagnostic = None;
            binding_setup = serde_json::json!({"state":"unavailable","reason":"original-descriptor-aggregate-bound"});
        }
        validate_descriptor(&final_input.key, &final_input.descriptor)?;
        Ok(PreparedGateInput {
            input: final_input,
            gate,
            prelaunch_security,
            prelaunch_label,
            binding_setup,
            original_descriptor_sha256,
            requested_sddl,
            namespace,
            toolchain_held_gate,
        })
    }

    fn gate_query_result<T: serde::Serialize>(result: io::Result<T>) -> serde_json::Value {
        match result {
            Ok(value) => match serde_json::to_value(value) {
                Ok(value) => serde_json::json!({"state":"observed","value":value}),
                Err(_) => serde_json::json!({"state":"unavailable","stage":"serialize-query"}),
            },
            Err(error) => {
                serde_json::json!({"state":"unavailable","kind":format!("{:?}",error.kind()),
                "raw_os_error":error.raw_os_error()})
            }
        }
    }

    pub(crate) fn event_create(name: &str) -> Result<OwnedHandle> {
        event_create_with_policy(name, CONTROLLER_GATE_SDDL)
    }

    pub(crate) fn start_gate_create(
        name: &str,
        selected_user: &[u8],
        deadline: Instant,
    ) -> Result<(OwnedHandle, String)> {
        provision_budget(deadline)?;
        let sid = sid_text(selected_user)?;
        let policy = super::start_gate_policy::sddl(selected_user, &sid)?;
        provision_budget(deadline)?;
        let owner = event_create_with_policy(name, &policy)?;
        provision_budget(deadline)?;
        Ok((owner, policy))
    }

    #[allow(unsafe_code)] // Creates only the exclusive owned event with the supplied reviewed role policy.
    fn event_create_with_policy(name: &str, policy: &str) -> Result<OwnedHandle> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::System::Threading::CreateEventW;
        let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        let sddl: Vec<_> = policy.encode_utf16().chain(Some(0)).collect();
        let mut security = std::ptr::null_mut();
        // SAFETY: terminated reviewed event ACL; restricted caller receives wait only.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut security,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security,
            bInheritHandle: 0,
        };
        // SAFETY: exact terminated nonce name and held native ACL allocation.
        let handle = unsafe { CreateEventW(&attributes, 1, 0, name.as_ptr()) };
        let error = io::Error::last_os_error();
        // SAFETY: descriptor allocated by the conversion API and no longer borrowed.
        unsafe { LocalFree(security) };
        if handle.is_null() {
            return Err(error.into());
        }
        let reused = error.raw_os_error() == Some(183);
        // SAFETY: successful creation transfers one event reference.
        let owned = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
        if reused {
            return Err(CiError::Message(
                "readiness event name reused an existing resource".into(),
            ));
        }
        Ok(owned)
    }

    #[allow(unsafe_code)] // Signals only the independently held controller event.
    pub(crate) fn signal(event: &OwnedHandle) -> io::Result<()> {
        use windows_sys::Win32::System::Threading::SetEvent;
        // SAFETY: owned manual-reset event remains held through signaling.
        if unsafe { SetEvent(event.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[allow(unsafe_code)] // Opens only the protected descriptor's exact native event.
    fn descendant_release(name: &str) -> io::Result<()> {
        use windows_sys::Win32::System::Threading::{OpenEventW, SetEvent};
        let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: opens the exact nonce-bound event published in the protected input.
        let handle = unsafe { OpenEventW(2, 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh event reference transfers once.
        let _owned = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
        // SAFETY: explicit event has EVENT_MODIFY_STATE access.
        if unsafe { SetEvent(handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn fixture_products(input: &CaseInput) -> Result<()> {
        let root = &input.descriptor.output_root;
        let bytes: Vec<u8> = (0..=255).collect();
        match input.descriptor.case {
            descriptor::Case::NativeArgv => {
                let actual: serde_json::Value =
                    serde_json::from_slice(&read(&root.join("native-argv.json"), 64 * 1024)?)?;
                let expected = serde_json::json!({
                    "encoding": "windows_utf16",
                    "values": input.descriptor.arguments.iter().map(|argument| argument.encode_utf16().collect::<Vec<_>>()).collect::<Vec<_>>(),
                });
                if actual != expected {
                    return Err(CiError::Message(
                        "independently observed native argv differs from selected arguments".into(),
                    ));
                }
            }
            descriptor::Case::Joint | descriptor::Case::Churn | descriptor::Case::BinaryFiles => {
                if !read(&root.join("nested").join("empty.bin"), 1)?.is_empty()
                    || read(&root.join("nested").join("all-bytes.bin"), 256)? != bytes
                    || read(&root.join("nested").join("challenge.bin"), 4096)?
                        != input.descriptor.challenge
                {
                    return Err(CiError::Message(
                        "independent binary file products differ".into(),
                    ));
                }
                let names: BTreeSet<_> = fs::read_dir(root.join("nested"))?
                    .map(|entry| entry.map(|entry| entry.file_name()))
                    .collect::<io::Result<_>>()?;
                if names
                    != ["empty.bin", "all-bytes.bin", "challenge.bin"]
                        .map(OsString::from)
                        .into_iter()
                        .collect()
                {
                    return Err(CiError::Message(
                        "binary output filenames/count differ".into(),
                    ));
                }
            }
            descriptor::Case::RootFirst | descriptor::Case::IntermediateFirst => {
                if read(&root.join("descendant-output.bin"), 4096)? != input.descriptor.challenge {
                    return Err(CiError::Message(
                        "held descendant failed to produce its independent product".into(),
                    ));
                }
            }
            descriptor::Case::AllowedTokenChange => {
                if read(&root.join("token-change-output.bin"), 4096)? != input.descriptor.challenge
                {
                    return Err(CiError::Message(
                        "allowed token-change descendant byte product differs".into(),
                    ));
                }
            }
            _ => {}
        }
        if matches!(
            input.descriptor.case,
            descriptor::Case::Toolchain | descriptor::Case::Joint | descriptor::Case::Churn
        ) {
            if !read(&root.join("compiled").join("dll-empty.bin"), 1)?.is_empty()
                || read(&root.join("compiled").join("dll-output.bin"), 256)? != bytes
                || read(&root.join("compiled").join("child-output.bin"), 4096)?
                    != input.descriptor.challenge
            {
                return Err(CiError::Message(
                    "independent compiled child/DLL byte products differ".into(),
                ));
            }
        }
        if matches!(
            input.descriptor.case,
            descriptor::Case::Joint | descriptor::Case::Churn
        ) {
            let mut pipe_expected = Vec::new();
            for payload in [
                &[][..],
                &[0, 255, 128][..],
                input.descriptor.challenge.as_slice(),
            ] {
                pipe_expected.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                pipe_expected.extend_from_slice(payload);
            }
            for name in [
                "named-pipe-server-received.bin",
                "named-pipe-client-received.bin",
            ] {
                if read(&root.join(name), 8192)? != pipe_expected {
                    return Err(CiError::Message(format!(
                        "independent named pipe receiver product differs: {name}"
                    )));
                }
            }
            for (name, header) in [
                (
                    "tcp-peer-received.bin",
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
                ),
                (
                    "tcp-server-received.bin",
                    b"GET /readiness HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
                ),
            ] {
                let mut expected = Vec::new();
                for payload in [
                    header,
                    &[],
                    &[0, 255, 128, 10],
                    input.descriptor.challenge.as_slice(),
                ] {
                    expected.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                    expected.extend_from_slice(payload);
                }
                if read(&root.join(name), 8192)? != expected {
                    return Err(CiError::Message(format!(
                        "independent TCP receiver product differs: {name}"
                    )));
                }
            }
        }
        Ok(())
    }

    #[allow(unsafe_code)] // Zero-wait query of a duplicate of the original Child handle.
    fn original_broker_retired(handle: &std::os::windows::io::OwnedHandle) -> io::Result<bool> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::Threading::WaitForSingleObject,
        };
        match unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }

    #[allow(unsafe_code)] // Query-only creation time of the original borrowed Child handle.
    fn native_child_birth(child: &std::process::Child) -> io::Result<u64> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
        let mut birth = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: Child retains this process handle for the query; all four
        // output pointers refer to initialized, correctly aligned FILETIMEs.
        if unsafe {
            GetProcessTimes(
                child.as_raw_handle(),
                &mut birth,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((u64::from(birth.dwHighDateTime) << 32) | u64::from(birth.dwLowDateTime))
    }

    #[allow(unsafe_code)] // Query-only native TCP table; bounded aligned output buffer.
    fn native_listener_owner(pid: u32, port: u16) -> io::Result<()> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL,
        };
        let mut size = 0_u32;
        // SAFETY: size-only native query has no output table pointer.
        let sizing = unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                2,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if sizing != 122 || size == 0 || size > 4 * 1024 * 1024 {
            return Err(io::Error::other(format!(
                "native TCP table sizing failed: {sizing}"
            )));
        }
        let mut words = vec![0_u32; (size as usize).div_ceil(4)];
        let capacity = words.len() * 4;
        // SAFETY: DWORD-aligned initialized storage covers the supplied byte capacity.
        let status = unsafe {
            GetExtendedTcpTable(
                words.as_mut_ptr().cast(),
                &mut size,
                0,
                2,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if size as usize > capacity || size < 4 {
            return Err(io::Error::other("native TCP table size differs"));
        }
        let count = words[0] as usize;
        if count > (size as usize - 4) / 24 {
            return Err(io::Error::other(
                "native TCP table row count exceeds returned bytes",
            ));
        }
        let matching = words[1..1 + count * 6]
            .chunks_exact(6)
            .filter(|row| {
                row[0] == 2
                    && row[1] == u32::from_ne_bytes([127, 0, 0, 1])
                    && u16::from_be(row[2] as u16) == port
                    && row[5] == pid
            })
            .count();
        if matching != 1 {
            return Err(io::Error::other(
                "held fixture does not own exactly one native loopback listener",
            ));
        }
        Ok(())
    }

    #[allow(unsafe_code)] // Bounded query-only ToolHelp snapshot with owned handle.
    pub(crate) fn process_parents() -> io::Result<std::collections::BTreeMap<u32, u32>> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        };
        // SAFETY: bounded query-only native snapshot; no process state is changed.
        let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful snapshot transfers one owned native handle.
        let owned = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut parents = std::collections::BTreeMap::new();
        // SAFETY: correctly initialized output buffer and held snapshot handle.
        let mut next = unsafe { Process32FirstW(owned.as_raw_handle(), &mut entry) };
        while next != 0 {
            parents.insert(entry.th32ProcessID, entry.th32ParentProcessID);
            if parents.len() > 131_072 {
                return Err(io::Error::other(
                    "native process snapshot exceeds controller bound",
                ));
            }
            // SAFETY: same held snapshot and correctly sized output buffer.
            next = unsafe { Process32NextW(owned.as_raw_handle(), &mut entry) };
        }
        if io::Error::last_os_error().raw_os_error() != Some(18) {
            return Err(io::Error::last_os_error());
        }
        Ok(parents)
    }

    fn toolchain_observation_error(operation: &str, path: &Path, error: io::Error) -> io::Error {
        let displayed = path.to_string_lossy();
        let excerpt: String = displayed.chars().take(256).collect();
        io::Error::new(
            error.kind(),
            format!(
                "native toolchain observer {operation}; path={excerpt:?}; path-truncated={}; raw-os-error={:?}; {error}",
                displayed.chars().count() > 256,
                error.raw_os_error(),
            ),
        )
    }

    struct ToolchainTranscriptSnapshot {
        complete: bool,
        last_root_stage: &'static str,
    }

    fn toolchain_completion_published(
        transcript: &Path,
        root_pid: u32,
        deadline: Instant,
    ) -> io::Result<ToolchainTranscriptSnapshot> {
        let published = super::live_events(
            &read(transcript, 16 * 1024 * 1024)
                .map_err(io::Error::other)
                .map_err(|error| {
                    toolchain_observation_error("read fixture transcript", transcript, error)
                })?,
        )
        .map_err(io::Error::other)?;
        if Instant::now() >= deadline {
            return Err(io::Error::other(
                "native compiler descendant observer deadline expired",
            ));
        }
        // Only emit a closed static vocabulary from the already parsed frames.
        // Unknown stages remain explicitly unavailable, never arbitrary content.
        let last_root_stage = match published
            .iter()
            .rev()
            .find(|event| event.pid == root_pid)
            .map(|event| event.stage.as_str())
        {
            Some("started") => "started",
            Some("native-argv-observed") => "native-argv-observed",
            Some("token-envelope") => "token-envelope",
            Some("controller-released") => "controller-released",
            Some("tcp-listener-owned") => "tcp-listener-owned",
            Some("named-pipe-while-tcp-owned") => "named-pipe-while-tcp-owned",
            Some("binary-files") => "binary-files",
            Some("toolchain-ready-for-native-observer") => "toolchain-ready-for-native-observer",
            Some("toolchain-compiled") => "toolchain-compiled",
            Some("toolchain-test-child-dll-complete") => "toolchain-test-child-dll-complete",
            Some("tcp-peer-complete") => "tcp-peer-complete",
            Some("finished") => "finished",
            Some(_) => "unavailable-unrecognized-stage",
            None => "unavailable-no-root-event",
        };
        Ok(ToolchainTranscriptSnapshot {
            complete: published.iter().any(|event| {
                event.pid == root_pid && event.stage == "toolchain-test-child-dll-complete"
            }),
            last_root_stage,
        })
    }

    fn toolchain_observation_complete(
        transcript: &Path,
        root_pid: u32,
        family: &Arc<Mutex<Vec<WindowsImageProcess>>>,
        deadline: Instant,
    ) -> io::Result<bool> {
        if toolchain_completion_published(transcript, root_pid, deadline)?.complete {
            return Ok(true);
        }
        let (retired, native_status) = {
            let held = family
                .lock()
                .map_err(|_| io::Error::other("compiler family ownership poisoned"))?;
            // The original root is retained first; descendants are only appended.
            // Never reacquire ownership from a numeric PID after retirement.
            let root = held
                .first()
                .filter(|root| root.identity.pid == root_pid)
                .ok_or_else(|| {
                    io::Error::other("native compiler observer lost its held fixture root")
                })?;
            let retired = root.has_exited()?;
            // This diagnostic query uses THAT SAME original retained handle.
            // Its failure cannot replace the original premature-retirement error.
            let native_status = retired.then(|| root.native_exit_status());
            (retired, native_status)
        };
        if retired {
            // A final durable event may have raced the native retirement read.
            let final_snapshot = toolchain_completion_published(transcript, root_pid, deadline)?;
            if final_snapshot.complete {
                return Ok(true);
            }
            let native_status = match native_status {
                Some(Ok(Some(status))) => format!("observed:{status:#010x}"),
                Some(Ok(None)) => "unavailable-not-observed".into(),
                Some(Err(error)) => format!(
                    "unavailable-query-error; kind={:?}; raw-os-error={:?}",
                    error.kind(),
                    error.raw_os_error(),
                ),
                None => "unavailable-not-queried".into(),
            };
            return Err(io::Error::other(format!(
                "native compiler fixture retired before publishing toolchain completion; held-root-native-exit={native_status}; last-validated-root-stage={}",
                final_snapshot.last_root_stage,
            )));
        }
        Ok(false)
    }

    struct ToolchainObservationImages<'a> {
        images: &'a [descriptor::ToolchainImage],
        clock: (u64, u64),
    }

    struct PendingHelperSample {
        hint: super::toolchain_sampling::Hint,
        sample: memcordon_testkit::WindowsThreadActivitySample,
        path: PathBuf,
    }

    struct HelperSampleContext<'a> {
        directory: &'a Path,
        output_root: &'a Path,
        challenge: &'a [u8],
        root_pid: u32,
        family: &'a Arc<Mutex<Vec<WindowsImageProcess>>>,
        images: &'a [descriptor::ToolchainImage],
        clock: (u64, u64),
        deadline: Instant,
    }

    struct ToolchainAdmission {
        image_sha256: String,
        parent: super::toolchain_sampling::Identity,
    }

    fn validate_helper_owners(
        context: &HelperSampleContext<'_>,
        held: &[WindowsImageProcess],
        hint: &super::toolchain_sampling::Hint,
        admitted: &std::collections::BTreeMap<
            super::toolchain_sampling::Identity,
            ToolchainAdmission,
        >,
    ) -> io::Result<()> {
        use super::toolchain_sampling as sampling;
        let identity = |owner: &WindowsImageProcess| sampling::Identity {
            pid: owner.identity.pid,
            birth: owner.identity.birth,
        };
        let fixture = held
            .iter()
            .find(|owner| owner.identity.pid == context.root_pid)
            .ok_or_else(|| {
                io::Error::other("original held fixture absent from helper diagnostic")
            })?;
        let compiler = held
            .iter()
            .find(|owner| identity(owner) == hint.compiler)
            .ok_or_else(|| io::Error::other("hint compiler is not an original held owner"))?;
        if fixture.has_exited()?
            || !compiler.has_exited()?
            || admitted
                .get(&hint.compiler)
                .map(|admission| admission.image_sha256.as_str())
                != hint.binding["selected_image_sha256"].as_str()
            || admitted
                .get(&hint.compiler)
                .is_none_or(|admission| admission.parent != identity(fixture))
        {
            return Err(io::Error::other(
                "hint original compiler retirement or admitted image differs",
            ));
        }
        for survivor in &hint.survivors {
            let owner = held
                .iter()
                .find(|owner| identity(owner) == survivor.identity)
                .ok_or_else(|| io::Error::other("hint survivor lacks original held owner"))?;
            if owner.has_exited()?
                || owner.native_parent_process_id()? != survivor.parent.pid
                || !held
                    .iter()
                    .any(|parent| identity(parent) == survivor.parent)
                || admitted.get(&survivor.identity).is_none_or(|admission| {
                    admission.image_sha256 != survivor.image_sha256
                        || admission.parent != survivor.parent
                })
            {
                return Err(io::Error::other(
                    "hint survivor native parent, liveness or admitted image differs",
                ));
            }
        }
        super::toolchain_sampling::live(context.deadline)
    }

    fn begin_helper_sample(
        context: &HelperSampleContext<'_>,
        seen: &mut BTreeSet<super::toolchain_sampling::Identity>,
        attempted: &mut BTreeSet<(super::toolchain_sampling::Identity, u64)>,
        admitted: &std::collections::BTreeMap<
            super::toolchain_sampling::Identity,
            ToolchainAdmission,
        >,
        owners: &mut Vec<std::fs::File>,
    ) -> io::Result<Option<PendingHelperSample>> {
        use super::toolchain_sampling as sampling;
        if Instant::now() >= context.deadline {
            return Ok(None);
        }
        let mut records = Vec::new();
        for leaf in [
            "toolchain-current-phase.json",
            "toolchain-current-debug.json",
        ] {
            sampling::live(context.deadline)?;
            let path = context.output_root.join("compiled").join(leaf);
            if !path.try_exists()? {
                return Ok(None);
            }
            let bytes = read(&path, sampling::RECORD_BOUND).map_err(io::Error::other)?;
            sampling::live(context.deadline)?;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                .map_err(io::Error::other)?;
            records.push(
                serde_json::from_slice::<serde_json::Value>(&bytes).map_err(io::Error::other)?,
            );
            sampling::live(context.deadline)?;
            if records.len() == 1
                && seen.iter().any(|identity| {
                    records[0]["binding"]["original_child"]["process_id"].as_u64()
                        == Some(u64::from(identity.pid))
                        && records[0]["binding"]["original_child"]["creation_time_100ns"]
                            .as_u64()
                            .map(u128::from)
                            == Some(identity.birth)
                })
            {
                return Ok(None);
            }
        }
        // Most sweeps legitimately precede original compiler exit. These hints
        // never provide admission, ACK or native retirement authority.
        let Some(version) = sampling::candidate(&records[0], &records[1])? else {
            return Ok(None);
        };
        if attempted.contains(&version) || attempted.len() >= 4096 {
            return Ok(None);
        }
        attempted.insert(version);
        let held = context
            .family
            .lock()
            .map_err(|_| io::Error::other("compiler family ownership poisoned"))?;
        let identity = |owner: &WindowsImageProcess| sampling::Identity {
            pid: owner.identity.pid,
            birth: owner.identity.birth,
        };
        let fixture = held
            .iter()
            .find(|owner| owner.identity.pid == context.root_pid)
            .ok_or_else(|| {
                io::Error::other("original held fixture absent from helper diagnostic")
            })?;
        let images = context
            .images
            .iter()
            .map(|image| image.sha256.clone())
            .collect();
        let hint = sampling::hint(
            &records[0],
            &records[1],
            context.challenge,
            identity(fixture),
            context.clock,
            &images,
        )?;
        if seen.contains(&hint.compiler) {
            return Ok(None);
        }
        if seen.len() >= 4096 {
            return Err(io::Error::other(
                "helper diagnostic compiler inventory exceeds finite bound",
            ));
        }
        validate_helper_owners(context, &held, &hint, admitted)?;
        // One exact owner is sampled; additional survivors remain explicitly
        // omitted from this finite diagnostic rather than called complete.
        let survivor = hint
            .survivors
            .first()
            .expect("nonempty validated inventory");
        let owner = held
            .iter()
            .find(|owner| identity(owner) == survivor.identity)
            .expect("validated owner");
        seen.insert(hint.compiler);
        let sample = owner.begin_thread_activity_sample(context.deadline)?;
        let path = context.directory.join(format!(
            "native-toolchain-helper-activity-{}-{}.json",
            hint.compiler.pid, hint.compiler.birth
        ));
        let bytes = sampling::encode_until(
            &hint,
            &[sample.first_observation().clone()],
            false,
            context.deadline,
        )?;
        owners.push(sampling::publish(
            context.directory,
            &path,
            &bytes,
            context.deadline,
        )?);
        Ok(Some(PendingHelperSample { hint, sample, path }))
    }

    fn observe_toolchain_descendants(
        directory: &Path,
        output_root: &Path,
        challenge: &[u8],
        transcript: &Path,
        root_pid: u32,
        family: &Arc<Mutex<Vec<WindowsImageProcess>>>,
        selected: ToolchainObservationImages<'_>,
        work_deadline: Instant,
    ) -> io::Result<()> {
        let deadline = work_deadline.min(Instant::now() + Duration::from_secs(600));
        let mut ordinal = 0u32;
        let mut admitted = std::collections::BTreeMap::new();
        let mut seen = BTreeSet::new();
        let mut attempted = BTreeSet::new();
        let mut pending: Option<PendingHelperSample> = None;
        let mut diagnostic_owners = Vec::new();
        let mut diagnostic_error = None;
        let context = HelperSampleContext {
            directory,
            output_root,
            challenge,
            root_pid,
            family,
            images: selected.images,
            clock: selected.clock,
            deadline,
        };
        let outcome = (|| {
            loop {
                if let Some(mut round) = pending.take() {
                    let value = round.sample.finish(deadline);
                    let result = super::toolchain_sampling::encode_until(
                        &round.hint,
                        &[value],
                        true,
                        deadline,
                    )
                    .and_then(|bytes| {
                        super::toolchain_sampling::publish(directory, &round.path, &bytes, deadline)
                    });
                    match result {
                        Ok(owner) => diagnostic_owners.push(owner),
                        Err(error) => {
                            diagnostic_error.get_or_insert(error);
                        }
                    }
                }
                if toolchain_observation_complete(transcript, root_pid, family, deadline)? {
                    return Ok(());
                }
                for image in selected.images {
                    if toolchain_observation_complete(transcript, root_pid, family, deadline)? {
                        return Ok(());
                    }
                    let processes =
                        memcordon_testkit::windows_processes_for_image_until(&image.path, deadline)
                            .map_err(|error| {
                                toolchain_observation_error("image census", &image.path, error)
                            })?;
                    for process in processes {
                        if process.has_exited()? {
                            continue;
                        }
                        let mut held = family
                            .lock()
                            .map_err(|_| io::Error::other("compiler family ownership poisoned"))?;
                        if held
                            .iter()
                            .any(|existing| existing.identity == process.identity)
                        {
                            continue;
                        }
                        let parent_pid = process.native_parent_process_id()?;
                        let Some(parent) =
                            held.iter().find(|parent| parent.identity.pid == parent_pid)
                        else {
                            continue;
                        };
                        if parent.has_exited()?
                            || parent.identity.birth > process.identity.birth
                            || process.has_exited()?
                        {
                            continue;
                        }
                        let parent_birth = parent.identity.birth;
                        if held
                            .iter()
                            .find(|root| root.identity.pid == root_pid)
                            .is_none_or(|root| !matches!(root.has_exited(), Ok(false)))
                        {
                            return Err(io::Error::other(
                                "native compiler observer lost its held live fixture root",
                            ));
                        }
                        ordinal = ordinal.checked_add(1).ok_or_else(|| {
                            io::Error::other("compiler native observation count overflow")
                        })?;
                        if ordinal > 4096 {
                            return Err(io::Error::other(
                                "compiler native descendant observation exceeds finite bound",
                            ));
                        }
                        let bytes=serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-native-toolchain-descendant","revision":1,"ordinal":ordinal,
                        "root_pid":root_pid,"pid":process.identity.pid,"birth":process.identity.birth,
                        "parent_pid":parent_pid,"parent_birth":parent_birth,"image_sha256":image.sha256,
                        "native_parent_edge_observed":true,"parent_and_child_held_live":true,
                    })).map_err(io::Error::other)?;
                        let path =
                            directory.join(format!("native-toolchain-descendant-{ordinal}.json"));
                        let mut file = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&path)
                            .map_err(|error| {
                                toolchain_observation_error(
                                    "create exclusive descendant record",
                                    &path,
                                    error,
                                )
                            })?;
                        file.write_all(&bytes).map_err(|error| {
                            toolchain_observation_error("write descendant record", &path, error)
                        })?;
                        file.sync_all().map_err(|error| {
                            toolchain_observation_error("sync descendant record", &path, error)
                        })?;
                        if read(&path, 16 * 1024)
                            .map_err(io::Error::other)
                            .map_err(|error| {
                                toolchain_observation_error("read descendant record", &path, error)
                            })?
                            != bytes
                        {
                            return Err(io::Error::other(
                                "native compiler descendant named readback differs",
                            ));
                        }
                        let child_identity = process.identity;
                        held.push(process);
                        if Instant::now() >= deadline
                            || !held.iter().any(|owner| {
                                owner.identity == child_identity
                                    && matches!(owner.has_exited(), Ok(false))
                            })
                            || !held.iter().any(|owner| {
                                owner.identity.pid == parent_pid
                                    && owner.identity.birth == parent_birth
                                    && matches!(owner.has_exited(), Ok(false))
                            })
                        {
                            return Err(io::Error::other(
                                "toolchain creation acknowledgment lost live ownership or original cutoff",
                            ));
                        }
                        let descendant: serde_json::Value =
                            serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                        let ack = serde_json::to_vec(&serde_json::json!({
                            "format":"memcordon.windows-toolchain-creation-ack","revision":1,
                            "challenge":challenge,"descendant":descendant,
                        }))
                        .map_err(io::Error::other)?;
                        if ack.len() > 16 * 1024 {
                            return Err(io::Error::other(
                                "toolchain creation acknowledgment exceeds finite bound",
                            ));
                        }
                        let ack_path = output_root.join(format!(
                            "native-toolchain-{}-{}.ack.json",
                            child_identity.pid, child_identity.birth
                        ));
                        let mut ack_file = tempfile::NamedTempFile::new_in(output_root)?;
                        ack_file.write_all(&ack)?;
                        ack_file.as_file().sync_all()?;
                        if read(ack_file.path(), 16 * 1024).map_err(io::Error::other)? != ack {
                            return Err(io::Error::other(
                                "staged toolchain acknowledgment named readback differs",
                            ));
                        }
                        // Close the writable handle before the atomic no-clobber
                        // publication so the child never opens partial bytes or
                        // conflicts with the publisher's write-sharing access.
                        ack_file
                            .into_temp_path()
                            .persist_noclobber(&ack_path)
                            .map_err(io::Error::other)?;
                        if read(&ack_path, 16 * 1024).map_err(io::Error::other)? != ack {
                            return Err(io::Error::other(
                                "toolchain creation acknowledgment named readback differs",
                            ));
                        }
                        // Publish the sequencing hint only after the atomic rename
                        // and final ACK readback have both released their handles.
                        // The child still validates the complete original ACK.
                        drop(
                            OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .open(ack_path.with_extension("published"))?,
                        );
                        admitted.insert(
                            super::toolchain_sampling::Identity {
                                pid: child_identity.pid,
                                birth: child_identity.birth,
                            },
                            ToolchainAdmission {
                                image_sha256: image.sha256.clone(),
                                parent: super::toolchain_sampling::Identity {
                                    pid: parent_pid,
                                    birth: parent_birth,
                                },
                            },
                        );
                    }
                }
                {
                    match begin_helper_sample(
                        &context,
                        &mut seen,
                        &mut attempted,
                        &admitted,
                        &mut diagnostic_owners,
                    ) {
                        Ok(round) => pending = round,
                        Err(mut error) => {
                            if diagnostic_error.is_none() {
                                let bytes = super::toolchain_sampling::live(deadline).and_then(|_|serde_json::to_vec(&serde_json::json!({
                            "format":"memcordon.windows-held-compiler-helper-activity-error","revision":1,
                            "diagnostic_only":true,"sampling_refused_or_incomplete":true,"compiler_acceptance":false,
                            "fixture_pid":root_pid,"challenge":challenge,"native_identity_not_verified":true,
                            "native_work_cutoff_ticks":selected.clock.0,"native_work_frequency":selected.clock.1,
                            "error":crate::command::bounded_excerpt(error.to_string().as_bytes()),
                            "kind":format!("{:?}",error.kind()),"raw_os_error":error.raw_os_error(),
                        })).map_err(io::Error::other));
                                match bytes.and_then(|bytes| {
                                    super::toolchain_sampling::publish(
                                        directory,
                                        &directory
                                            .join("native-toolchain-helper-diagnostic-error.json"),
                                        &bytes,
                                        deadline,
                                    )
                                }) {
                                    Ok(owner) => diagnostic_owners.push(owner),
                                    Err(retention) => {
                                        error = io::Error::new(
                                            error.kind(),
                                            format!(
                                                "{error}; helper-diagnostic-retention={retention}"
                                            ),
                                        )
                                    }
                                }
                                diagnostic_error = Some(error);
                            }
                        }
                    }
                }
                if toolchain_observation_complete(transcript, root_pid, family, deadline)? {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::other(
                        "native compiler descendant observer deadline expired",
                    ));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        })();
        match (outcome, diagnostic_error) {
            (Err(original), Some(diagnostic)) => Err(io::Error::new(
                original.kind(),
                format!("{original}; held-helper-diagnostic={diagnostic}"),
            )),
            (Err(original), None) => Err(original),
            (Ok(()), Some(diagnostic)) => {
                eprintln!(
                    "held-helper diagnostic unavailable; original compiler observation succeeded: {diagnostic}"
                );
                Ok(())
            }
            (Ok(()), None) => Ok(()),
        }
    }

    pub(crate) fn execute(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        record: &mut CaseAssessment,
    ) -> Result<()> {
        execute_until(
            config,
            input,
            record,
            Instant::now() + Duration::from_secs(660),
        )
    }

    pub(crate) fn execute_until(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        record: &mut CaseAssessment,
        work_deadline: Instant,
    ) -> Result<()> {
        execute_until_with_cleanup(config, input, record, work_deadline, None)
    }

    fn execute_until_with_cleanup(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        record: &mut CaseAssessment,
        work_deadline: Instant,
        cleanup: Option<Instant>,
    ) -> Result<()> {
        let baseline = GuardianBaseline::quiescent(
            &config.installed_agent.path,
            &config.installed_manifest.path,
            &config.installed_agent.sha256,
            &config.installed_manifest.sha256,
        )?;
        execute_with_baseline_clocks(
            config,
            input,
            record,
            baseline,
            Vec::new(),
            None,
            ExecutionClocks {
                work: work_deadline,
                matched: None,
                cleanup,
                registry: None,
                registry_lifetime: RegistryProjectionLifetime::ExecutionOwned,
                projection_observation: None,
                private_custody: None,
            },
        )
    }

    pub(crate) struct HeldFixtureExclusion {
        pub observation: memcordon_core::WindowsGuardianAttemptObservation,
        pub family: Vec<WindowsImageProcess>,
    }

    pub(crate) fn execute_with_baseline(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        record: &mut CaseAssessment,
        baseline: GuardianBaseline,
        excluded: Vec<GuardianAssociationIdentity>,
        excluded_fixture: Option<HeldFixtureExclusion>,
    ) -> Result<()> {
        execute_with_baseline_until(
            config,
            input,
            record,
            baseline,
            excluded,
            excluded_fixture,
            Instant::now() + Duration::from_secs(660),
        )
    }

    pub(crate) fn execute_with_baseline_until(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        record: &mut CaseAssessment,
        baseline: GuardianBaseline,
        excluded: Vec<GuardianAssociationIdentity>,
        excluded_fixture: Option<HeldFixtureExclusion>,
        work_deadline: Instant,
    ) -> Result<()> {
        execute_with_baseline_clocks(
            config,
            input,
            record,
            baseline,
            excluded,
            excluded_fixture,
            ExecutionClocks {
                work: work_deadline,
                matched: None,
                cleanup: None,
                registry: None,
                registry_lifetime: RegistryProjectionLifetime::ExecutionOwned,
                projection_observation: None,
                private_custody: None,
            },
        )
    }

    struct ExecutionClocks {
        matched: Option<MatchedExecution>,
        work: Instant,
        cleanup: Option<Instant>,
        registry: Option<Arc<Mutex<memcordon_testkit::WindowsWinsockRegistryProjection>>>,
        registry_lifetime: RegistryProjectionLifetime,
        projection_observation: Option<Arc<Mutex<ProjectionObservation>>>,
        private_custody: Option<Arc<crate::windows_private_custody::PrivateFixtureCustody>>,
    }

    struct MatchedExecution {
        provider: Option<Arc<crate::windows_provider_control::native::RootPair>>,
        plan_path: PathBuf,
        plan: descriptor::matched_plan::Plan,
        guards: Vec<std::fs::File>,
        admitted: bool,
        settled: bool,
        custody: Arc<Mutex<MatchedPairCustody>>,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum MatchedPairCustody {
        Unadmitted,
        Admitted,
        Retired,
    }

    impl Drop for MatchedExecution {
        fn drop(&mut self) {
            if self.admitted && !self.settled && !self.guards.is_empty() {
                // An incomplete pair cannot release its original source namespace.
                // This quarantine owns actual guards for this controller lifetime.
                let _retained = Box::leak(Box::new(std::mem::take(&mut self.guards)));
            }
        }
    }

    #[derive(Default)]
    struct ProjectionObservation {
        root: Option<(u32, u128, memcordon_core::WindowsCallerTokenEnvelopeV1)>,
        peer: Option<(u32, u128, memcordon_core::WindowsCallerTokenEnvelopeV1)>,
    }

    fn execute_with_baseline_clocks(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        record: &mut CaseAssessment,
        baseline: GuardianBaseline,
        excluded: Vec<GuardianAssociationIdentity>,
        excluded_fixture: Option<HeldFixtureExclusion>,
        mut clocks: ExecutionClocks,
    ) -> Result<()> {
        record.contract.execution =
            crate::windows_readiness_policy::ExecutionDisposition::Unvalidated;
        let attempt = (|| -> Result<()> {
            let mut declared = input.clone();
            if clocks.registry_lifetime == RegistryProjectionLifetime::ExperimentBorrowed
                && (clocks.registry.is_none() || !input.descriptor.provider_input_experiment)
            {
                return Err(CiError::Message(
                    "borrowed experiment registry requires its original declared owner".into(),
                ));
            }
            if declared.descriptor.matched_control.is_some() != clocks.matched.is_some() {
                return Err(CiError::Message(
                    "matched descriptor requires its separate owned pair execution".into(),
                ));
            }
            if needs_registry_input(&input.key, input.descriptor.case) {
                if clocks.registry.is_some()
                    && !input.descriptor.provider_input_experiment
                    && !input
                        .descriptor
                        .matched_control
                        .as_ref()
                        .is_some_and(|binding| {
                            binding.scope == descriptor::matched::Scope::JointListenerPrefix
                        })
                {
                    return Err(CiError::Message("provided registry owner is restricted to the separately declared input experiment".into()));
                }
                if clocks.registry.is_none() {
                    let projection = memcordon_testkit::WindowsWinsockRegistryProjection::create(
                        &crate::windows_causal_acceptance::sha256(&input.descriptor.challenge),
                        clocks.work,
                        clocks.cleanup.unwrap_or(clocks.work),
                    )?;
                    declared.descriptor.winsock_registry = Some(projection.declaration().clone());
                    declared.descriptor.start_transport =
                        descriptor::StartTransport::ControllerStdin {
                            version: if declared.descriptor.provider_input_experiment {
                                if declared
                                    .descriptor
                                    .provider_input_binding
                                    .as_ref()
                                    .is_some_and(|binding| binding.file_layout())
                                {
                                    descriptor::controller_start::PRIVATE_FILE_VERSION
                                } else {
                                    descriptor::controller_start::PRIVATE_VERSION
                                }
                            } else {
                                descriptor::controller_start::REGISTRY_VERSION
                            },
                        };
                    clocks.registry = Some(Arc::new(Mutex::new(projection)));
                } else {
                    let owner = clocks
                        .registry
                        .as_ref()
                        .expect("provided projection")
                        .lock()
                        .map_err(|_| {
                            CiError::Message("provided registry input ownership poisoned".into())
                        })?;
                    owner.verify_owned()?;
                    declared.descriptor.winsock_registry = Some(owner.declaration().clone());
                    declared.descriptor.start_transport =
                        descriptor::StartTransport::ControllerStdin {
                            version: if declared.descriptor.provider_input_experiment {
                                if declared
                                    .descriptor
                                    .provider_input_binding
                                    .as_ref()
                                    .is_some_and(|binding| binding.file_layout())
                                {
                                    descriptor::controller_start::PRIVATE_FILE_VERSION
                                } else {
                                    descriptor::controller_start::PRIVATE_VERSION
                                }
                            } else {
                                descriptor::controller_start::REGISTRY_VERSION
                            },
                        };
                }
            }
            let registry = clocks.registry.clone();
            let registry_lifetime = clocks.registry_lifetime;
            let result = execute_with_registry(
                config,
                &declared,
                record,
                baseline,
                excluded,
                excluded_fixture,
                clocks,
            );
            let finalized = match registry {
                Some(owner) => match owner.lock() {
                    Ok(mut owner) => registry_lifetime.finish_execution(
                        &mut *owner,
                        |owner| owner.verify_owned().map_err(CiError::from),
                        |owner| owner.retire_if_safe().map_err(CiError::from),
                    ),
                    Err(_) => Err(CiError::Message("registry input ownership poisoned".into())),
                },
                None => Ok(()),
            };
            match (result, finalized) {
                (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                    primary: Box::new(primary),
                    secondary: Box::new(secondary.context("Winsock registry input finalization")),
                }),
                (Err(primary), _) => Err(primary),
                (Ok(()), retired) => retired,
            }
        })();
        finalize_case_attempt(record, attempt)
    }

    fn execute_with_registry(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        record: &mut CaseAssessment,
        baseline: GuardianBaseline,
        excluded: Vec<GuardianAssociationIdentity>,
        excluded_fixture: Option<HeldFixtureExclusion>,
        mut clocks: ExecutionClocks,
    ) -> Result<()> {
        let work_deadline = clocks.work;
        let work_budget = work_deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(660));
        if work_budget.is_zero() {
            return Err(CiError::Message(
                "original Windows work deadline exhausted before positive launch".into(),
            ));
        }
        let require_global_quiescence = excluded.is_empty();
        if let Some(owned) = &excluded_fixture {
            let root = owned
                .observation
                .live_target_identity
                .as_ref()
                .ok_or_else(|| {
                    CiError::Message("overlap excluded root identity unavailable".into())
                })?;
            if excluded.len() != 1
                || !owned.observation.is_consistent()
                || owned.observation.association.provider != config.provider
                || owned.observation.guardian_identity.process_id != excluded[0].process_id
                || owned.observation.guardian_identity.creation_time_100ns
                    != excluded[0].creation_time_100ns
                || owned.family.len() != 2
                || owned
                    .family
                    .iter()
                    .any(|process| !matches!(process.has_exited(), Ok(false)))
                || !owned.family.iter().any(|process| {
                    process.identity.pid == root.process_id
                        && process.identity.birth == u128::from(root.creation_time_100ns)
                })
            {
                return Err(CiError::Message(
                    "overlap exclusion is not the exact independently held live first family"
                        .into(),
                ));
            }
        } else if !excluded.is_empty() {
            return Err(CiError::Message(
                "guardian overlap exclusion requires independently held fixture family".into(),
            ));
        }
        let guardian_owner = Arc::new(Mutex::new(Vec::<HeldGuardian>::new()));
        let observed_guardian_owner = Arc::clone(&guardian_owner);
        let clock = match clocks.matched.as_ref() {
            Some(pair) => GateClock::ExistingMatched(&pair.plan),
            None => GateClock::PrepareFromDeadline,
        };
        clock.validate_selection(&input.descriptor)?;
        let prepared = prepare_gate_input(config, input, work_deadline, clock)?;
        let input = &prepared.input;
        let gate_name = input.descriptor.start_gate.as_ref().ok_or_else(|| {
            CiError::Message("positive input omitted held-root native barrier".into())
        })?;
        let gate = prepared.gate.clone();
        let callback_gate = gate.clone();
        let endpoint_event = (input.descriptor.case == descriptor::Case::EndpointMismatch)
            .then(|| event_create(&format!("{gate_name}-endpoint-observed")))
            .transpose()?;
        let needs_toolchain_observer =
            super::needs_descriptor_toolchain_observer(&input.descriptor)?;
        let toolchain_event = (needs_toolchain_observer
            && matches!(
                input.descriptor.start_transport,
                descriptor::StartTransport::NamedEvent
            ))
        .then(|| event_create(&format!("{gate_name}-toolchain-observer")))
        .transpose()?;
        let mut toolchain_images = Vec::new();
        if needs_toolchain_observer {
            let measured: Vec<crate::windows_installed_cases::SelectedArtifact> =
                serde_json::from_slice(&read(
                    &config.output_directory.join("windows-owned-inputs.json"),
                    64 * 1024 * 1024,
                )?)?;
            let selected = descriptor::project_toolchain_images(
                measured.into_iter().map(|image| (image.path, image.sha256)),
            )
            .map_err(CiError::Message)?;
            let toolchain = input.descriptor.toolchain.as_ref().ok_or_else(|| {
                CiError::Message("native compiler descriptor inventory absent".into())
            })?;
            super::validate_toolchain_inventory(toolchain, &selected)?;
            for image in selected {
                if crate::windows_causal_acceptance::sha256(&read(&image.path, 512 * 1024 * 1024)?)
                    != image.sha256
                {
                    return Err(CiError::Message("native compiler observer input image is unmeasured or exceeds finite closure".into()));
                }
                toolchain_images.push(image);
            }
            if toolchain_images.is_empty() {
                return Err(CiError::Message(
                    "native compiler observer has no measured compiler/linker images".into(),
                ));
            }
        }
        let cohort_event = input
            .descriptor
            .cohort_gate
            .as_ref()
            .map(|name| event_create(name))
            .transpose()?;
        let generation_event = input
            .descriptor
            .generation_gate
            .as_ref()
            .map(|name| event_create(name))
            .transpose()?;
        let private_custody = clocks.private_custody.clone();
        if input.descriptor.provider_input_experiment != private_custody.is_some() {
            return Err(CiError::Message(
                "private experiment original custody owner is absent or unexpected".into(),
            ));
        }
        if let Some(custody) = &private_custody {
            if input.descriptor.provider_input_binding.as_ref() != Some(custody.binding()) {
                return Err(CiError::Message(
                    "private descriptor is not the original held custody declaration".into(),
                ));
            }
        }
        let family = private_custody
            .as_ref()
            .map(|custody| Arc::clone(&custody.family))
            .unwrap_or_else(|| Arc::new(Mutex::new(Vec::<WindowsImageProcess>::new())));
        if !family
            .lock()
            .map_err(|_| CiError::Message("original family ownership poisoned".into()))?
            .is_empty()
        {
            return Err(CiError::Message(
                "original fixture family cannot be reused".into(),
            ));
        }
        let callback_private_custody = private_custody.clone();
        let console_owners = Arc::new(Mutex::new(Vec::<WindowsImageProcess>::new()));
        let held_console_owners = Arc::clone(&console_owners);
        let console_image = if input.descriptor.case == descriptor::Case::Churn {
            Some(Arc::new(hold_console_image()?))
        } else {
            None
        };
        let held_console_image = console_image.clone();
        let association = Arc::new(Mutex::new(None));
        let held_family = Arc::clone(&family);
        let held_association = Arc::clone(&association);
        let frontend = Arc::new(Mutex::new(None::<WindowsImageProcess>));
        let held_frontend = Arc::clone(&frontend);
        let capture_frontend_identity = input.descriptor.matched_control.is_some()
            || expected_status(&input.key) != 0
            || matches!(
                input.descriptor.case,
                descriptor::Case::DeadlineDemand | descriptor::Case::MemoryDemand
            );
        let report =
            controller_case_directory(&config.output_directory, &input.key).join("result.json");
        fs::create_dir_all(report.parent().expect("case report has parent"))?;
        if report.try_exists()?
            || input.descriptor_path.try_exists()?
            || input.descriptor.transcript.try_exists()?
        {
            return Err(CiError::Message(
                "positive case cannot reuse old report/input/transcript paths".into(),
            ));
        }
        provision_budget(work_deadline)?;
        fs::create_dir_all(&input.descriptor.output_root).map_err(|error| {
            CiError::from(error).context(format!(
                "prepare candidate case output directory {}",
                input.descriptor.output_root.display()
            ))
        })?;
        if let Some(owner) = &clocks.registry {
            provision_budget(work_deadline)?;
            let bytes = serde_json::to_vec(
                &owner
                    .lock()
                    .map_err(|_| CiError::Message("registry input ownership poisoned".into()))?
                    .diagnostic(),
            )?;
            let path = input
                .descriptor
                .output_root
                .join("winsock-registry-input.json");
            drop(
                crate::windows_native_files::publish_owned_file(&path, &bytes).map_err(
                    |error| {
                        CiError::from(error).context(format!(
                            "publish owned Winsock registry input diagnostic {}",
                            path.display()
                        ))
                    },
                )?,
            );
            provision_budget(work_deadline)?;
        }
        let descriptor_bytes = serde_json::to_vec(&input.descriptor)?;
        validate_descriptor(&input.key, &input.descriptor)?;
        descriptor::Descriptor::parse(&descriptor_bytes).map_err(|error| {
            CiError::Message(format!(
                "Windows fixture {}/{} publication failed: {error}; encoded-bytes={} limit={}",
                input.key.family,
                input.key.scenario,
                descriptor_bytes.len(),
                descriptor::MAX_DESCRIPTOR_BYTES
            ))
        })?;
        let mut descriptor_owner = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&input.descriptor_path)?;
        descriptor_owner.write_all(&descriptor_bytes)?;
        descriptor_owner.sync_all()?;
        let matched_plan = if let Some(pair) = &clocks.matched {
            let direct = pair
                .plan
                .direct_descriptor_for(&input.descriptor)
                .map_err(CiError::Message)?;
            fs::create_dir_all(&direct.output_root)?;
            let direct_path = pair.plan_path.with_extension("direct-input.json");
            drop(crate::windows_native_files::publish_owned_file(
                &direct_path,
                &serde_json::to_vec(&direct)?,
            )?);
            let plan = &pair.plan;
            if plan.direct_descriptor != direct_path
                || plan.installed_descriptor != input.descriptor_path
            {
                return Err(CiError::Message(
                    "matched final descriptor allocations differ".into(),
                ));
            }
            plan.validate(&direct, &input.descriptor)
                .map_err(CiError::Message)?;
            drop(crate::windows_native_files::publish_owned_file(
                &pair.plan_path,
                &serde_json::to_vec(plan)?,
            )?);
            Some(pair.plan_path.clone())
        } else {
            None
        };
        let mut descriptor_owner = if matched_plan.is_some() {
            use std::os::windows::fs::OpenOptionsExt;
            let reader = OpenOptions::new()
                .read(true)
                .share_mode(3)
                .custom_flags(0x0020_0000)
                .open(&input.descriptor_path)?;
            let before = memcordon_testkit::windows_held_file_metadata(&descriptor_owner)?;
            let after = memcordon_testkit::windows_held_file_metadata(&reader)?;
            if (before.volume_serial, before.file_index) != (after.volume_serial, after.file_index)
                || after.attributes & (0x400 | 0x10 | 0x40) != 0
                || after.links != 1
            {
                return Err(CiError::Message(
                    "matched original descriptor read owner identity differs".into(),
                ));
            }
            drop(descriptor_owner);
            reader
        } else {
            descriptor_owner
        };
        let challenge_path = report
            .parent()
            .expect("case report has parent")
            .join("challenge.bin");
        let mut challenge_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&challenge_path)?;
        challenge_file.write_all(&input.descriptor.challenge)?;
        challenge_file.sync_all()?;
        if read(&challenge_path, 4096)? != input.descriptor.challenge {
            return Err(CiError::Message(
                "positive challenge named readback differs".into(),
            ));
        }
        record.descriptor_sha256 = crate::windows_causal_acceptance::sha256(&descriptor_bytes);
        let public_report = input.descriptor.output_root.join("frontend-result.json");
        let invocation_cwd = if input.descriptor.case == descriptor::Case::Envelope
            && input.descriptor.matched_control.is_none()
        {
            use std::os::windows::fs::OpenOptionsExt;
            let file = OpenOptions::new()
                .access_mode(0x80)
                .share_mode(3)
                .custom_flags(0x0220_0000)
                .open(std::path::absolute(&config.output_directory)?)?;
            let metadata = memcordon_testkit::windows_held_file_metadata(&file)?;
            if metadata.attributes & 0x400 != 0 || metadata.attributes & 0x10 == 0 {
                return Err(CiError::Message(
                    "original invocation cwd is not a held ordinary directory".into(),
                ));
            }
            Some((
                file,
                InvocationCwdIdentity {
                    volume_serial: metadata.volume_serial,
                    file_index: metadata.file_index,
                    attributes: metadata.attributes,
                },
            ))
        } else {
            None
        };
        let mut command = public_command(
            &config.cli.path,
            &config.fixture.path,
            &config.output_directory,
            &public_report,
            input,
        )?
        .materialize()?;
        if let Some(plan) = matched_plan {
            let original: Vec<OsString> = command.get_args().map(OsString::from).collect();
            if original
                .first()
                .is_none_or(|arg| arg != "consumer-readiness-windows")
                || original.get(1).is_none_or(|arg| {
                    arg != "system-frontend" && arg != "system-restricted-frontend"
                })
            {
                return Err(CiError::Message(
                    "matched execution requires the original explicit system frontend command"
                        .into(),
                ));
            }
            let mut broker = std::process::Command::new(command.get_program());
            broker.current_dir(&config.output_directory);
            broker.args([
                OsString::from("consumer-readiness-windows"),
                OsString::from("matched-control-frontend"),
                plan.into_os_string(),
            ]);
            broker.args(original.into_iter().skip(2));
            command = broker;
        }
        // Workload inputs are absolute owned paths; ambient controller secrets
        // must never enter the authenticated launch request or its observation.
        command.env_clear();
        command.stdin(match input.descriptor.start_transport {
            descriptor::StartTransport::NamedEvent => std::process::Stdio::null(),
            descriptor::StartTransport::ControllerStdin { .. } => std::process::Stdio::piped(),
        });
        let execution_sha256 = if command.get_program() == config.fixture.path.as_os_str() {
            config.fixture.sha256.clone()
        } else {
            config.cli.sha256.clone()
        };
        use std::os::windows::ffi::OsStrExt;
        let invocation = serde_json::json!({
            "format":"memcordon.windows-positive-invocation","revision":1,
            "frontend_environment":fixture_environment::entries()?,
            "target":config.target,
            "executable_sha256":execution_sha256,
            "public_executable_sha256":config.cli.sha256,
            "public_program_utf16":config.cli.path.as_os_str().encode_wide().collect::<Vec<_>>(),
            "program_utf16":command.get_program().encode_wide().collect::<Vec<_>>(),
            "argv_utf16":command.get_args().map(|argument|argument.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
            "cwd_utf16":config.output_directory.as_os_str().encode_wide().collect::<Vec<_>>(),
            "environment_cleared":true,
            "fixture_start_transport":input.descriptor.start_transport,
        });
        let invocation_bytes = serde_json::to_vec(&invocation)?;
        let invocation_path = report
            .parent()
            .expect("case report has parent")
            .join("native-invocation.json");
        let mut invocation_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&invocation_path)?;
        invocation_file.write_all(&invocation_bytes)?;
        invocation_file.sync_all()?;
        if read(&invocation_path, 256 * 1024)? != invocation_bytes {
            return Err(CiError::Message(
                "positive native invocation named readback differs".into(),
            ));
        }
        let fixture = config.fixture.path.clone();
        let transcript = input.descriptor.transcript.clone();
        let toolchain_output_root = input.descriptor.output_root.clone();
        let toolchain_challenge = input.descriptor.challenge.clone();
        let toolchain_clock = input.descriptor.toolchain.as_ref().map(|toolchain| {
            (
                toolchain.native_work_cutoff_ticks,
                toolchain.native_work_frequency,
            )
        });
        let cli = config.cli.path.clone();
        let directory = report.parent().expect("case report has parent").to_owned();
        let guardian_query = Arc::new(Mutex::new(super::guardian_query::Trace::new(
            serde_json::json!({
                "case":input.key,"provider":config.provider,"source_commit":config.source_commit,
                "target":config.target,"selected_cli":config.cli,
                "challenge_sha256":crate::windows_causal_acceptance::sha256(&input.descriptor.challenge),
                "descriptor_sha256":record.descriptor_sha256,
            }),
        )));
        let callback_guardian_query = Arc::clone(&guardian_query);
        let gate_root_diagnostic = Arc::new(Mutex::new(None::<serde_json::Value>));
        let callback_gate_root_diagnostic = Arc::clone(&gate_root_diagnostic);
        let capture_gate_diagnostic = super::start_gate_policy::capture_restricted_gate(
            &input.key.family,
            &input.key.scenario,
        );
        let gate_diagnostic = capture_gate_diagnostic.then(|| {
            let name_utf16: Vec<_> = gate_name.encode_utf16().collect();
            let name_bytes: Vec<_> = name_utf16.iter().flat_map(|unit| unit.to_le_bytes()).collect();
            serde_json::json!({
                "format":"memcordon.windows-controller-gate-diagnostic","revision":1,
                "authority":"diagnostic-only; never gate access or workload acceptance",
                "case":input.key,"challenge_sha256":crate::windows_causal_acceptance::sha256(&input.descriptor.challenge),
                "source_commit":config.source_commit,"target":config.target,"fixture_sha256":config.fixture.sha256,
                "descriptor_sha256":record.descriptor_sha256,
                "requested_name_utf16":name_utf16,"requested_name_sha256":crate::windows_causal_acceptance::sha256(&name_bytes),
                "name_binding":"independent named diagnostic request; creation and security custody are reported separately",
                "positive_start_transport":input.descriptor.start_transport,
                "requested_sddl":prepared.requested_sddl,"independent_named_control_requested_access":0x0010_0000_u32,
                "actual_security_information":7,
                "same_held_event_security":prepared.prelaunch_security,
                "same_held_event_mandatory_label":prepared.prelaunch_label,
                "access_comparison_input":prepared.binding_setup,
                "controller":gate_query_result(super::workload_diagnostic::gate_controller_context(work_deadline)),
                "original_fixture":null,
            })
        });
        let expected_provider = config.provider.clone();
        let start_transport = input.descriptor.start_transport.clone();
        let start_challenge = input.descriptor.challenge.clone();
        let start_descriptor = input.descriptor.clone();
        let matched_listener_prefix =
            input
                .descriptor
                .matched_control
                .as_ref()
                .is_some_and(|binding| {
                    binding.scope == descriptor::matched::Scope::JointListenerPrefix
                });
        let matched_provider_root =
            input
                .descriptor
                .matched_control
                .as_ref()
                .is_some_and(|binding| {
                    binding.scope == descriptor::matched::Scope::ProviderListenerSelection
                });
        let provider_pair = clocks
            .matched
            .as_ref()
            .and_then(|pair| pair.provider.clone());
        if matched_provider_root != provider_pair.is_some() {
            return Err(CiError::Message(
                "provider root requires its original paired native custody".into(),
            ));
        }
        let spawn_provider_pair = provider_pair.clone();
        let callback_provider_pair = provider_pair.clone();
        let callback_provider_plan = clocks
            .matched
            .as_ref()
            .filter(|_| matched_provider_root)
            .map(|pair| pair.plan.clone());
        let start_descriptor_case_is_joint = matches!(
            input.descriptor.case,
            descriptor::Case::Joint | descriptor::Case::Churn
        ) && !matched_listener_prefix
            && !matched_provider_root;
        let barrier_report = public_report.clone();
        let descendant_gate = input.descriptor.descendant_gate.clone();
        let intermediate_first = input.descriptor.case == descriptor::Case::IntermediateFirst;
        let owns_capacity_child = input.descriptor.case == descriptor::Case::CapacityCompletion;
        let owns_tcp = matches!(
            input.descriptor.case,
            descriptor::Case::Joint | descriptor::Case::Churn | descriptor::Case::EndpointMismatch
        ) && !matched_listener_prefix
            && !matched_provider_root;
        let released_listener_prefix = input.descriptor.case == descriptor::Case::Joint
            && !input.descriptor.provider_input_experiment
            && input.descriptor.completion_gate.is_none()
            && input.descriptor.descendant_gate.is_none();
        let prefix_token = input.expected_token.clone();
        let native_started_utc = std::time::SystemTime::now();
        let registry_recipient = clocks.registry.clone();
        let spawn_registry = clocks.registry.clone();
        let broker_registry =
            Arc::new(Mutex::new(None::<descriptor::controller_start::Capability>));
        let broker_registry_recipient =
            Arc::new(Mutex::new(None::<std::os::windows::io::OwnedHandle>));
        let spawn_registry_recipient = Arc::clone(&broker_registry_recipient);
        let spawn_broker_registry = Arc::clone(&broker_registry);
        let callback_broker_registry = Arc::clone(&broker_registry);
        let projection_observation = clocks.projection_observation.clone();
        let fileio_requested = loader_fileio_requested(
            &input.key,
            input.descriptor.case,
            input.descriptor.provider_input_experiment,
        );
        let fileio_retention = loader_fileio_retention(
            &input.key,
            input.descriptor.case,
            input.descriptor.provider_input_experiment,
        );
        let fileio_state = Arc::new(Mutex::new(crate::windows_loader_fileio::Captured::default()));
        let callback_fileio = Arc::clone(&fileio_state);
        let fileio_owner: crate::windows_loader_fileio::OwnedCapture = Arc::new(Mutex::new(None));
        let callback_fileio_owner = Arc::clone(&fileio_owner);
        let cleanup_deadline = clocks.cleanup.unwrap_or(work_deadline);
        let work_budget = work_budget.min(work_deadline.saturating_duration_since(Instant::now()));
        if work_budget.is_zero() {
            return Err(CiError::Message(
                "original Windows work deadline exhausted during observer preparation".into(),
            ));
        }
        if let Some(pair) = clocks.matched.as_mut() {
            pair.admitted = true;
            *pair
                .custody
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = MatchedPairCustody::Admitted;
        }
        let matched_spawn = input.descriptor.matched_control.is_some();
        let broker_observation = Arc::new(Mutex::new(None::<io::Result<(u32, u64)>>));
        let spawn_observation = Arc::clone(&broker_observation);
        let callback_broker = Arc::clone(&broker_observation);
        let output = memcordon_testkit::run_until_owned_spawn_with_io_output_limit_outcome(
            command,
            work_deadline,
            4 * 1024 * 1024,
            move |mut command| {
                let child = command.spawn()?;
                if matched_spawn {
                    let observed = (|| -> io::Result<(u32, u64)> {
                        provision_budget(work_deadline).map_err(io::Error::other)?;
                        let birth = native_child_birth(&child)?;
                        provision_budget(work_deadline).map_err(io::Error::other)?;
                        if child.id() == 0 || birth == 0 {
                            return Err(io::Error::other(
                                "matched original broker identity is unavailable",
                            ));
                        }
                        if let Some(pair) = &spawn_provider_pair {
                            let original = WindowsImageProcess::from_original_child(
                                &child,
                                memcordon_platform::test_support::ProcessIdentity {
                                    pid: child.id(),
                                    birth: u128::from(birth),
                                },
                                work_deadline,
                            )?;
                            let mut slot = pair.broker.lock().map_err(|_| {
                                io::Error::other("provider original broker ownership poisoned")
                            })?;
                            if slot.is_some() {
                                return Err(io::Error::other(
                                    "provider original broker owner repeated",
                                ));
                            }
                            *slot = Some(original);
                        }
                        if matched_listener_prefix {
                            use std::os::windows::io::AsHandle;
                            let original = child.as_handle().try_clone_to_owned()?;
                            *spawn_registry_recipient
                                .lock()
                                .unwrap_or_else(|error| error.into_inner()) = Some(original);
                            let mut owner = spawn_registry
                                .as_ref()
                                .ok_or_else(|| {
                                    io::Error::other("prefix original registry owner absent")
                                })?
                                .lock()
                                .map_err(|_| io::Error::other("prefix registry owner poisoned"))?;
                            let handle = owner.duplicate_into_child(
                                &child,
                                child.id(),
                                birth,
                                work_deadline,
                            )?;
                            *spawn_broker_registry
                                .lock()
                                .unwrap_or_else(|error| error.into_inner()) =
                                Some(descriptor::controller_start::Capability {
                                    version: 1,
                                    handle,
                                    manifest_sha256: owner.declaration().sha256,
                                });
                        }
                        Ok((child.id(), birth))
                    })();
                    *spawn_observation
                        .lock()
                        .unwrap_or_else(|error| error.into_inner()) = Some(observed);
                }
                // Even a failed identity query returns this actual Child to its
                // existing owner loop; callback Abort performs owned cleanup.
                Ok(child)
            },
            move |wrapper_pid, mut stdin, _| {
                let mut application_ended = false;
                let callback = (|| -> io::Result<()> {
                    if matched_spawn {
                        let mut observed = callback_broker
                            .lock()
                            .map_err(|_| io::Error::other("matched broker observation poisoned"))?;
                        match observed.take() {
                            Some(Ok(identity)) => {
                                *observed = Some(Ok(identity));
                            }
                            Some(Err(error)) => return Err(error),
                            None => {
                                return Err(io::Error::other(
                                    "matched broker native observation missing",
                                ));
                            }
                        }
                    }
                    let mut control_session = None;
                    let _fileio_guard = crate::windows_loader_fileio::callback_guard(Arc::clone(
                        &callback_fileio_owner,
                    ));
                    let deadline = work_deadline.min(Instant::now() + Duration::from_secs(60));
                    let mut candidate_unavailable = None;
                    let (held, root_pid) = loop {
                        if barrier_report.try_exists()? {
                            super::check_positive_barrier_result(
                                &read(
                                    &barrier_report,
                                    crate::windows_causal_acceptance::MAX_REPORT_BYTES,
                                )
                                .map_err(io::Error::other)?,
                                &expected_provider,
                            )
                            .map_err(|error| {
                                io::Error::other(format!(
                                    "{error}; retained-result={}",
                                    barrier_report.display()
                                ))
                            })?;
                        }
                        if transcript.is_file() {
                            let published = super::live_events(
                                &read(&transcript, 16 * 1024 * 1024).map_err(io::Error::other)?,
                            )
                            .map_err(io::Error::other)?;
                            if let Some(started) = published.first() {
                                let mut held = if registry_recipient.is_some() {
                                    // Capability-transfer acquisition retains its strict census contract.
                                    memcordon_testkit::windows_fixture_input_processes_for_image_until(
                                    &fixture, deadline,
                                )?
                                } else {
                                    match memcordon_testkit::windows_process_candidate_for_image_until(
                                    &fixture, started.pid, deadline,
                                )? {
                                    memcordon_testkit::WindowsProcessCandidate::Held(process) => vec![process],
                                    memcordon_testkit::WindowsProcessCandidate::CandidateUnavailable { pid, raw_open_error } => {
                                        let observation = format!("published query-only candidate unavailable; pid={pid}; raw-open-error={raw_open_error:?}; identity-admitted=false; retirement-established=false");
                                        if candidate_unavailable.is_none() {
                                            // Keep the acquisition fact even if the wrapper fails before the loop cutoff.
                                            use std::io::Write;
                                            let _ = writeln!(std::io::stderr().lock(), "{observation}");
                                        }
                                        candidate_unavailable = Some(observation);
                                        Vec::new()
                                    },
                                }
                                };
                                held.retain(|process| process.identity.pid == started.pid);
                                if held.len() == 1 && !held[0].has_exited()? {
                                    break (held, started.pid);
                                }
                            }
                        }
                        if Instant::now() >= deadline {
                            return Err(io::Error::other(format!(
                                "native held fixture barrier unavailable; candidate-observation={candidate_unavailable:?}"
                            )));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    };
                    let root_identity = held
                        .first()
                        .expect("one original held fixture admitted")
                        .identity
                        .clone();
                    if capture_gate_diagnostic {
                        let root = held
                            .first()
                            .expect("one original held fixture was admitted");
                        let observation = serde_json::json!({
                            "pid":root.identity.pid,"birth":root.identity.birth.to_string(),
                            "binding":"same original held fixture admitted by existing barrier",
                            "retired_at_query":gate_query_result(root.has_exited()),
                            "token_envelope":gate_query_result(root.original_token_envelope(work_deadline)),
                        });
                        match callback_gate_root_diagnostic.lock() {
                            Ok(mut value) => *value = Some(observation),
                            Err(poisoned) => {
                                *poisoned.into_inner() = Some(
                                    serde_json::json!({"state":"unavailable","stage":"diagnostic-lock-poisoned"}),
                                )
                            }
                        }
                    }
                    *held_family
                        .lock()
                        .map_err(|_| io::Error::other("fixture ownership poisoned"))? = held;
                    if capture_frontend_identity {
                        let mut selected = Vec::new();
                        for process in
                            memcordon_testkit::windows_processes_for_image_until(&cli, deadline)?
                        {
                            if process.native_parent_process_id()? == wrapper_pid
                                && !process.has_exited()?
                            {
                                selected.push(process);
                            }
                        }
                        if selected.len() != 1 {
                            return Err(io::Error::other(
                                "status fixture lacks one original held frontend child",
                            ));
                        }
                        *held_frontend
                            .lock()
                            .map_err(|_| io::Error::other("frontend ownership poisoned"))? =
                            selected.pop();
                    }
                    let guardian = baseline
                        .hold_new_guardian_excluding(&excluded)
                        .map_err(io::Error::other)?;
                    let guardian_identity = guardian.identity.clone();
                    let adopted = super::guardian_query::adopt(&observed_guardian_owner, guardian);
                    super::guardian_query::update(&callback_guardian_query, |trace| {
                        trace.guardian(serde_json::json!(guardian_identity));
                        trace.stage(if adopted.is_ok() {
                            "command-materialization"
                        } else {
                            "guardian-adoption-failed"
                        });
                    });
                    adopted?;
                    let query_started = Instant::now();
                    let query_cutoff = work_deadline.min(query_started + Duration::from_secs(30));
                    let query_budget = query_cutoff.saturating_duration_since(query_started);
                    if query_budget.is_zero() {
                        return Err(io::Error::other(
                            "original Windows work deadline exhausted before association query",
                        ));
                    }
                    let mut query = CommandSpec::new(&cli, &directory, query_budget)
                        .args([
                            OsString::from("__observe-windows-guardian"),
                            guardian_identity.process_id.to_string().into(),
                            guardian_identity.creation_time_100ns.to_string().into(),
                        ])
                        .materialize()
                        .map_err(io::Error::other)?;
                    let query_budget = query_cutoff
                        .saturating_duration_since(Instant::now())
                        .min(work_deadline.saturating_duration_since(Instant::now()));
                    if query_budget.is_zero() {
                        return Err(io::Error::other(
                            "original Windows work deadline exhausted during association query setup",
                        ));
                    }
                    super::guardian_query::update(&callback_guardian_query, |trace| {
                        trace.stage("command-capture")
                    });
                    let observed = memcordon_testkit::run_with_deadline_output_limit(
                        &mut query,
                        query_budget,
                        super::guardian_query::STREAM_BOUND,
                    )
                    .map_err(io::Error::other)?;
                    let observed_stdout = observed.stdout.clone();
                    let failure =
                        super::guardian_query::update(&callback_guardian_query, |trace| {
                            trace.captured(observed);
                            trace.stage("returned-output");
                            trace.failure()
                        });
                    if let Some(failure) = failure {
                        return Err(failure);
                    }
                    super::guardian_query::update(&callback_guardian_query, |trace| {
                        trace.stage("association-parse")
                    });
                    let observed: memcordon_core::WindowsGuardianAttemptObservation =
                        serde_json::from_slice(&observed_stdout).map_err(io::Error::other)?;
                    super::guardian_query::update(&callback_guardian_query, |trace| {
                        trace.stage("association-validation")
                    });
                    if !observed.is_consistent()
                        || observed.association.provider != expected_provider
                        || observed.guardian_identity.process_id != guardian_identity.process_id
                        || observed.guardian_identity.creation_time_100ns
                            != guardian_identity.creation_time_100ns
                    {
                        return Err(io::Error::other(
                            "positive native guardian association differs",
                        ));
                    }
                    if matches!(
                        start_transport,
                        descriptor::StartTransport::ControllerStdin { .. }
                    ) && observed.live_target_identity.as_ref().is_none_or(|target| {
                        target.process_id != root_identity.pid
                            || u128::from(target.creation_time_100ns) != root_identity.birth
                    }) {
                        return Err(io::Error::other(
                            "START guardian association does not name the original held target",
                        ));
                    }
                    let expected = memcordon_core::execution_facts::ProviderAttemptAssociationV1 {
                        provider: observed.association.provider.clone(),
                        attempt_id: observed.association.attempt_id.clone(),
                        request_sha256: observed.association.request_sha256.clone(),
                    };
                    *held_association
                        .lock()
                        .map_err(|_| io::Error::other("association ownership poisoned"))? =
                        Some(expected);
                    super::guardian_query::update(&callback_guardian_query, |trace| {
                        trace.stage("association-publication")
                    });
                    let observation_path = directory.join("live-observation.json");
                    let staging = directory.join("live-observation.pending");
                    let bytes = serde_json::to_vec(&observed).map_err(io::Error::other)?;
                    let mut publication = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&staging)?;
                    publication.write_all(&bytes)?;
                    publication.sync_all()?;
                    drop(publication);
                    fs::rename(&staging, &observation_path)?;
                    if read(&observation_path, 32 * 1024).map_err(io::Error::other)? != bytes {
                        return Err(io::Error::other(
                            "live native association named publication differs",
                        ));
                    }
                    let identity_path = directory.join("live-held-guardian.json");
                    let staging = directory.join("live-held-guardian.pending");
                    let bytes = serde_json::to_vec(&guardian_identity).map_err(io::Error::other)?;
                    let mut publication = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&staging)?;
                    publication.write_all(&bytes)?;
                    publication.sync_all()?;
                    drop(publication);
                    fs::rename(&staging, &identity_path)?;
                    super::guardian_query::update(&callback_guardian_query, |trace| {
                        trace.stage("association-admitted")
                    });
                    match start_transport {
                        descriptor::StartTransport::NamedEvent => {
                            signal(callback_gate.as_deref().ok_or_else(|| {
                                io::Error::other("original named START owner unavailable")
                            })?)?
                        }
                        descriptor::StartTransport::ControllerStdin { .. } => {
                            use std::io::{Read, Seek, SeekFrom};
                            provision_budget(work_deadline).map_err(io::Error::other)?;
                            descriptor_owner.seek(SeekFrom::Start(0))?;
                            let mut actual_bytes = Vec::new();
                            Read::by_ref(&mut descriptor_owner)
                                .take((descriptor::MAX_DESCRIPTOR_BYTES + 1) as u64)
                                .read_to_end(&mut actual_bytes)?;
                            let actual = descriptor::Descriptor::parse(&actual_bytes)
                                .map_err(io::Error::other)?;
                            // The existing measured frontend changes only its sentinel
                            // inventory before launching this original target. Bind the
                            // frame to those final bytes through the same held file.
                            let mut expected = start_descriptor.clone();
                            expected.sentinel_handles = actual.sentinel_handles.clone();
                            if serde_json::to_value(&actual).map_err(io::Error::other)?
                                != serde_json::to_value(&expected).map_err(io::Error::other)?
                            {
                                return Err(io::Error::other(
                                    "original START descriptor changed beyond measured sentinel inventory",
                                ));
                            }
                            let writer = stdin.take().ok_or_else(|| {
                                io::Error::other(
                                    "original controller START stdin writer unavailable",
                                )
                            })?;
                            let binding = descriptor::controller_start::Binding {
                                challenge: start_challenge,
                                descriptor_sha256: descriptor::controller_start::descriptor_digest(
                                    &actual_bytes,
                                ),
                                pid: root_identity.pid,
                                birth: u64::try_from(root_identity.birth)
                                    .map_err(io::Error::other)?,
                            };
                            let joint = start_descriptor_case_is_joint;
                            let sender = if let Some(owner) = &registry_recipient {
                                let mut owner = owner.lock().map_err(|_| {
                                    io::Error::other("registry input ownership poisoned")
                                })?;
                                let recipient = {
                                    let held = held_family.lock().map_err(|_| {
                                        io::Error::other("fixture ownership poisoned")
                                    })?;
                                    if held.len() != 1 || held[0].identity != root_identity {
                                        return Err(io::Error::other(
                                            "original registry recipient identity differs",
                                        ));
                                    }
                                    held[0].clone()
                                };
                                let handle = owner.duplicate_into(&recipient, work_deadline)?;
                                let sender = descriptor::controller_start::Sender::with_registry(
                                    descriptor::controller_start::Capability {
                                        version: 1,
                                        handle,
                                        manifest_sha256: owner.declaration().sha256,
                                    },
                                    joint,
                                );
                                if let Some(custody) = &callback_private_custody {
                                    sender.with_directories(
                                        custody
                                            .duplicate_into(&recipient, work_deadline)
                                            .map_err(io::Error::other)?,
                                        custody
                                            .binding()
                                            .directory_expectation()
                                            .map_err(io::Error::other)?,
                                    )?
                                } else {
                                    sender
                                }
                            } else if joint {
                                descriptor::controller_start::Sender::joint()
                            } else {
                                descriptor::controller_start::Sender::default()
                            };
                            let sender = if matched_provider_root {
                                sender.provider_root()?
                            } else {
                                sender
                            };
                            let mut session = ControlSession {
                                writer: Some(writer),
                                binding,
                                sender,
                                deadline: work_deadline,
                            };
                            if fileio_requested {
                                let prepared = (|| -> io::Result<_> {
                                    let clock = actual.control_clock.as_ref().ok_or_else(|| {
                                        io::Error::other("original FileIo work clock unavailable")
                                    })?;
                                    let recipient = {
                                        let held = held_family.lock().map_err(|_| {
                                            io::Error::other("fixture ownership poisoned")
                                        })?;
                                        if held.len() != 1 || held[0].identity != root_identity {
                                            return Err(io::Error::other(
                                                "original FileIo recipient identity differs",
                                            ));
                                        }
                                        held[0].clone()
                                    };
                                    memcordon_platform::test_support::windows_fileio::OwnedFileIoSession::prepare(
                                    &recipient,
                                    memcordon_platform::windows_fileio_record::Binding {
                                        descriptor_sha256: session.binding.descriptor_sha256,
                                        challenge_sha256: descriptor::controller_start::descriptor_digest(&session.binding.challenge),
                                        cutoff_qpc: clock.work_cutoff_qpc,
                                        frequency: clock.qpc_frequency,
                                    },
                                    work_deadline,
                                    cleanup_deadline,
                                ).map(|prepared| prepared.with_retention_mode(fileio_retention))
                                })();
                                match prepared {
                                    Ok(prepared) => {
                                        // prepare only borrowed the held object; no family
                                        // mutex is held across ETW startup or helper waits.
                                        let capture = crate::windows_loader_fileio::Capture::begin(
                                            prepared,
                                            work_deadline,
                                            cleanup_deadline,
                                            Arc::clone(&callback_fileio),
                                        );
                                        *callback_fileio_owner
                                            .lock()
                                            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                                            Some(capture);
                                    }
                                    Err(error) => crate::windows_loader_fileio::unavailable(
                                        &callback_fileio,
                                        error,
                                    ),
                                }
                            }
                            if let Some(custody) = &callback_private_custody {
                                // Releasing this root permits its later original
                                // spawn. Missing/partial transcript publication or
                                // root exit cannot erase that interval's debt.
                                if !matched_provider_root {
                                    custody.note_spawn_uncertainty().map_err(io::Error::other)?;
                                }
                            }
                            if matched_provider_root {
                                use crate::windows_provider_control::native::{
                                    Admission, DirectRoot, wait_prelude,
                                };
                                let pair = callback_provider_pair.as_ref().ok_or_else(|| {
                                    io::Error::other("provider original pair custody absent")
                                })?;
                                let plan = callback_provider_plan.as_ref().ok_or_else(|| {
                                    io::Error::other("provider original plan absent")
                                })?;
                                let broker = pair
                                    .broker
                                    .lock()
                                    .map_err(|_| {
                                        io::Error::other("provider broker ownership poisoned")
                                    })?
                                    .clone()
                                    .ok_or_else(|| {
                                        io::Error::other("provider original broker owner absent")
                                    })?;
                                let installed = {
                                    let held = held_family.lock().map_err(|_| {
                                        io::Error::other("provider installed family poisoned")
                                    })?;
                                    if held.len() != 1 || held[0].identity != root_identity {
                                        return Err(io::Error::other(
                                            "provider original installed root differs",
                                        ));
                                    }
                                    held[0].clone()
                                };
                                let registry = registry_recipient.as_ref().ok_or_else(|| {
                                    io::Error::other("provider original registry owner absent")
                                })?;
                                let token = installed.original_token_envelope(work_deadline)?;
                                let token_sha256 = descriptor::controller_start::descriptor_digest(
                                    &serde_json::to_vec(&token).map_err(io::Error::other)?,
                                );
                                let mut installed_slot = pair.installed.lock().map_err(|_| {
                                    io::Error::other(
                                        "provider original installed observation poisoned",
                                    )
                                })?;
                                if installed_slot.is_some() {
                                    return Err(io::Error::other(
                                        "provider installed observation repeated",
                                    ));
                                }
                                *installed_slot = Some((installed.clone(), token_sha256));
                                drop(installed_slot);
                                let root = DirectRoot::admit(Admission {
                                    plan,
                                    broker: &broker,
                                    installed: &installed,
                                    installed_binding: &session.binding,
                                    direct_custody: &pair.direct_custody,
                                    registry,
                                    work: work_deadline,
                                })
                                .map_err(io::Error::other)?;
                                let mut direct = pair.direct.lock().map_err(|_| {
                                    io::Error::other("provider direct ownership poisoned")
                                })?;
                                if direct.is_some() {
                                    return Err(io::Error::other(
                                        "provider direct release repeated",
                                    ));
                                }
                                *direct = Some(root);
                                let direct =
                                    direct.as_mut().expect("inserted original direct owner");
                                let mut writer = session.writer.take().ok_or_else(|| {
                                    io::Error::other("provider original control writer absent")
                                })?;
                                let timer =
                                    memcordon_platform::WindowsSynchronousIoDeadline::start(
                                        work_deadline,
                                    )
                                    .map_err(io::Error::other)?;
                                let release = (|| -> io::Result<()> {
                                    pair.shared
                                        .verify(work_deadline)
                                        .map_err(io::Error::other)?;
                                    direct.start_direct(&mut writer, work_deadline)?;
                                    let direct_witness = direct
                                        .wait_prelude(
                                            &direct.descriptor,
                                            &pair.shared,
                                            work_deadline,
                                        )
                                        .map_err(io::Error::other)?;
                                    pair.probes.lock().map_err(|_| {
                                        io::Error::other(
                                            "provider direct witness ownership poisoned",
                                        )
                                    })?[0] = Some(direct_witness);
                                    direct.start_installed(
                                        &mut writer,
                                        &mut session.sender,
                                        &session.binding,
                                        work_deadline,
                                    )?;
                                    let installed_witness = wait_prelude(
                                        &actual,
                                        &installed,
                                        &session.binding,
                                        &pair.shared,
                                        plan.restricted,
                                        work_deadline,
                                    )
                                    .map_err(io::Error::other)?;
                                    pair.probes.lock().map_err(|_| {
                                        io::Error::other(
                                            "provider installed witness ownership poisoned",
                                        )
                                    })?[1] = Some(installed_witness);
                                    direct.release_originals(
                                        &mut writer,
                                        &mut session.sender,
                                        &session.binding,
                                        work_deadline,
                                    )?;
                                    writer.flush()?;
                                    Ok(())
                                })();
                                drop(writer);
                                let settled = timer.finish().map_err(io::Error::other);
                                match (release, settled) {
                                    (Err(primary), Err(secondary)) => {
                                        return Err(io::Error::other(format!(
                                            "{primary}; provider control settlement: {secondary}"
                                        )));
                                    }
                                    (Err(error), _) | (_, Err(error)) => return Err(error),
                                    (Ok(()), Ok(())) => {}
                                }
                            } else if matched_listener_prefix {
                                let mut installed_start = Vec::new();
                                session.sender.send(
                                    &mut installed_start,
                                    &session.binding,
                                    descriptor::controller_start::Phase::Start,
                                    || {
                                        provision_budget(work_deadline)
                                            .map(|_| ())
                                            .map_err(io::Error::other)
                                    },
                                )?;
                                let pair = actual.matched_control.as_ref().ok_or_else(|| {
                                    io::Error::other("prefix original pair binding absent")
                                })?;
                                let clock = actual.control_clock.as_ref().ok_or_else(|| {
                                    io::Error::other("prefix original clock absent")
                                })?;
                                let observed = callback_broker.lock().map_err(|_| {
                                    io::Error::other("prefix broker identity poisoned")
                                })?;
                                let identity = observed
                                    .as_ref()
                                    .ok_or_else(|| {
                                        io::Error::other("prefix broker identity missing")
                                    })?
                                    .as_ref()
                                    .map_err(|error| io::Error::other(error.to_string()))?;
                                let registry = callback_broker_registry
                                    .lock()
                                    .map_err(|_| {
                                        io::Error::other("prefix broker capability poisoned")
                                    })?
                                    .take()
                                    .ok_or_else(|| {
                                        io::Error::other(
                                            "prefix broker original registry capability absent",
                                        )
                                    })?;
                                let envelope =
                                    descriptor::controller_start::BrokerRegistryEnvelope {
                                        revision: 1,
                                        broker: descriptor::controller_start::BrokerIdentity {
                                            pid: identity.0,
                                            birth: identity.1,
                                        },
                                        pair_sha256: pair.pair_sha256,
                                        input_sha256: pair.input_sha256,
                                        descriptor_sha256: session.binding.descriptor_sha256,
                                        manifest_sha256: registry.manifest_sha256,
                                        qpc_frequency: clock.qpc_frequency,
                                        cutoff_qpc: clock.work_cutoff_qpc,
                                        registry,
                                        rights:
                                            descriptor::controller_start::BROKER_REGISTRY_RIGHTS,
                                        installed_start,
                                    };
                                let mut writer = session.writer.take().ok_or_else(|| {
                                    io::Error::other("prefix original stdin writer absent")
                                })?;
                                let timer =
                                    memcordon_platform::WindowsSynchronousIoDeadline::start(
                                        work_deadline,
                                    )
                                    .map_err(io::Error::other)?;
                                let sent = envelope.write(&mut writer, || {
                                    provision_budget(work_deadline)
                                        .map(|_| ())
                                        .map_err(io::Error::other)
                                });
                                drop(writer);
                                let finished = timer.finish();
                                match (sent, finished) {
                                    (Err(primary), Err(settlement)) => {
                                        return Err(io::Error::new(
                                            primary.kind(),
                                            StartWriteFailure {
                                                primary,
                                                settlement,
                                            },
                                        ));
                                    }
                                    (Err(primary), _) => return Err(primary),
                                    (_, Err(error)) => return Err(io::Error::other(error)),
                                    _ => {}
                                }
                            } else {
                                session.release(descriptor::controller_start::Phase::Start)?;
                            }
                            control_session = Some(session);
                            super::guardian_query::update(&callback_guardian_query, |trace| {
                                trace.stage("stdin-start-published")
                            });
                        }
                    }
                    if owns_tcp {
                        let deadline = work_deadline.min(Instant::now() + Duration::from_secs(60));
                        let port = loop {
                            use crate::windows_listener_wait::{Identity, Owner, Publication};
                            let port = crate::windows_listener_wait::poll(
                                Identity {
                                    pid: root_identity.pid,
                                    birth: root_identity.birth,
                                },
                                deadline,
                                Instant::now,
                                || {
                                    let held = held_family.lock().map_err(|_| {
                                        io::Error::other("fixture ownership poisoned")
                                    })?;
                                    if held.len() != 1 {
                                        return Err(io::Error::other(
                                            "original listener root ownership differs",
                                        ));
                                    }
                                    let root = &held[0];
                                    Ok(Owner {
                                        identity: Identity {
                                            pid: root.identity.pid,
                                            birth: root.identity.birth,
                                        },
                                        exit_status: root.native_exit_status()?,
                                    })
                                },
                                || {
                                    let bytes =
                                        read(&transcript, 16 * 1024 * 1024).map_err(|error| {
                                            match error {
                                                CiError::Io(error) => error,
                                                error => io::Error::other(error),
                                            }
                                        });
                                    let Some(bytes) =
                                        crate::windows_listener_wait::transcript_bytes(bytes)?
                                    else {
                                        return Ok(None);
                                    };
                                    let events =
                                        super::live_events(&bytes).map_err(io::Error::other)?;
                                    Ok(events
                                        .into_iter()
                                        .find(|event| event.stage == "tcp-listener-owned")
                                        .map(|event| Publication {
                                            pid: event.pid,
                                            value: event.value,
                                        }))
                                },
                            );
                            let port = match port {
                                Ok(port) => port,
                                Err(error) => {
                                    if released_listener_prefix
                                        && callback_private_custody.is_none()
                                        && Instant::now() < work_deadline
                                    {
                                        if let Some(failure @ crate::windows_listener_wait::Failure::Retired { .. }) =
                                        error.get_ref().and_then(|source| source.downcast_ref::<crate::windows_listener_wait::Failure>())
                                    {
                                        let held = held_family.lock().map_err(|_| io::Error::other("fixture ownership poisoned"))?;
                                        if held.len() != 1 {
                                            return Err(io::Error::other("retired listener root ownership differs"));
                                        }
                                        let root = held[0].clone();
                                        drop(held);
                                        let owner = Owner { identity: Identity { pid: root.identity.pid, birth: root.identity.birth }, exit_status: root.native_exit_status()? };
                                        // The retired original Joint prefix cannot create a peer or
                                        // compiler before listener publication. A complete transcript
                                        // excludes later phases; no missing record supplies that proof.
                                        let bytes = read(&transcript, 16 * 1024 * 1024).map_err(io::Error::other)?;
                                        let events = super::events(&bytes).map_err(io::Error::other)?;
                                        let stages: Vec<_> = events.iter().map(|event| event.stage.as_str()).collect();
                                        let bound_start = control_session.as_ref().is_some_and(|session| {
                                            session.binding.pid == root_identity.pid
                                                && u128::from(session.binding.birth) == root_identity.birth
                                                && events.iter().all(|event| event.pid == root_identity.pid)
                                                && events.first().is_some_and(|event| event.value == session.binding.challenge)
                                                && events.last().is_some_and(|event| event.value == session.binding.challenge)
                                        });
                                        let eligible = crate::windows_listener_wait::application_end(
                                            Identity { pid: root_identity.pid, birth: root_identity.birth },
                                            owner, failure, bound_start, &stages, Some(0), Some(false),
                                        ).is_some();
                                        if eligible {
                                            use std::io::{Read, Seek, SeekFrom};
                                            let session = control_session.as_ref().expect("eligible bound START");
                                            descriptor_owner.seek(SeekFrom::Start(0))?;
                                            let mut original = Vec::new();
                                            Read::by_ref(&mut descriptor_owner).take((descriptor::MAX_DESCRIPTOR_BYTES + 1) as u64).read_to_end(&mut original)?;
                                            if descriptor::controller_start::descriptor_digest(&original) != session.binding.descriptor_sha256 {
                                                return Err(io::Error::other("retired listener START descriptor bytes changed"));
                                            }
                                            let declared = descriptor::Descriptor::parse(&original).map_err(io::Error::other)?;
                                            let payload = |stage| events.iter().find(|event| event.stage == stage).expect("eligible complete prefix").value.as_slice();
                                            let argv = serde_json::to_vec(&serde_json::json!({"encoding":"windows_utf16","values":declared.arguments.iter().map(|argument|argument.encode_utf16().collect::<Vec<_>>()).collect::<Vec<_>>()})).map_err(io::Error::other)?;
                                            let token: TokenObservation = serde_json::from_slice(payload("token-envelope")).map_err(io::Error::other)?;
                                            if payload("native-argv-observed") != argv
                                                || payload("sentinel-handles-excluded") != u32::try_from(declared.sentinel_handles.len()).map_err(io::Error::other)?.to_le_bytes()
                                                || token != prefix_token
                                            {
                                                return Err(io::Error::other("retired listener prefix argv, sentinel or token readback differs"));
                                            }
                                        }
                                        provision_budget(work_deadline).map_err(io::Error::other)?;
                                        application_ended = eligible;
                                    }
                                    }
                                    return Err(error);
                                }
                            };
                            if let Some(port) = port {
                                break port;
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        };
                        crate::windows_loader_fileio::stop_collection(&callback_fileio_owner);
                        let root_owner = {
                            let held = held_family
                                .lock()
                                .map_err(|_| io::Error::other("fixture ownership poisoned"))?;
                            if held.len() != 1 {
                                return Err(io::Error::other(
                                    "native listener root cardinality differs",
                                ));
                            }
                            held[0].clone()
                        };
                        let mut ended_after_listener = |status,
                                                        stage: super::post_listener_end::Stage|
                         -> io::Result<
                            Option<super::post_listener_end::Failure>,
                        > {
                            use crate::windows_listener_wait::{Identity, Owner};
                            use std::io::{Read, Seek, SeekFrom};
                            if !start_descriptor.provider_input_experiment
                                || start_descriptor.case != descriptor::Case::Joint
                                || start_descriptor.completion_gate.is_some()
                                || start_descriptor.descendant_gate.is_some()
                            {
                                return Ok(None);
                            }
                            let session = control_session.as_ref().ok_or_else(|| {
                                io::Error::other("post-listener START session absent")
                            })?;
                            let custody = callback_private_custody.as_ref().ok_or_else(|| {
                                io::Error::other("post-listener private input custody absent")
                            })?;
                            descriptor_owner.seek(SeekFrom::Start(0))?;
                            let mut original = Vec::new();
                            Read::by_ref(&mut descriptor_owner)
                                .take((descriptor::MAX_DESCRIPTOR_BYTES + 1) as u64)
                                .read_to_end(&mut original)?;
                            let digest = descriptor::controller_start::descriptor_digest(&original);
                            let declared = descriptor::Descriptor::parse(&original)
                                .map_err(io::Error::other)?;
                            let bytes =
                                read(&transcript, 16 * 1024 * 1024).map_err(io::Error::other)?;
                            let events = super::events(&bytes).map_err(io::Error::other)?;
                            let stages: Vec<_> =
                                events.iter().map(|event| event.stage.as_str()).collect();
                            let expected_stages = [
                                "started",
                                "native-argv-observed",
                                "sentinel-handles-excluded",
                                "token-envelope",
                                "controller-released",
                                "tcp-conflicting-bind",
                                "tcp-listener-owned",
                                "tcp-peer-spawn-intent",
                            ];
                            if stages != expected_stages
                                || events.iter().any(|event| {
                                    event.pid != root_identity.pid || event.ordinal.is_some()
                                })
                            {
                                return Err(io::Error::other(
                                    "post-listener transcript differs from the original root spawn-intent interval",
                                ));
                            }
                            let payload = |stage| {
                                events
                                    .iter()
                                    .find(|event| event.stage == stage)
                                    .expect("validated exact transcript stages")
                                    .value
                                    .as_slice()
                            };
                            let argv = serde_json::to_vec(&serde_json::json!({"encoding":"windows_utf16","values":declared.arguments.iter().map(|argument|argument.encode_utf16().collect::<Vec<_>>()).collect::<Vec<_>>()})).map_err(io::Error::other)?;
                            let token: TokenObservation =
                                serde_json::from_slice(payload("token-envelope"))
                                    .map_err(io::Error::other)?;
                            let intent: descriptor::controller_start::PeerAdmissionBinding =
                                serde_json::from_slice(payload("tcp-peer-spawn-intent"))
                                    .map_err(io::Error::other)?;
                            if payload("started") != session.binding.challenge
                                || payload("controller-released") != session.binding.challenge
                                || payload("native-argv-observed") != argv
                                || payload("sentinel-handles-excluded") != u32::try_from(declared.sentinel_handles.len()).map_err(io::Error::other)?.to_le_bytes()
                                || token != prefix_token
                                || payload("tcp-conflicting-bind") != 10048_i32.to_le_bytes()
                                || payload("tcp-listener-owned") != port.to_le_bytes()
                                || intent != descriptor::controller_start::PeerAdmissionBinding::from_start(&session.binding)
                            {
                                return Err(io::Error::other("post-listener original START/readbacks differ"));
                            }
                            let guardians: Vec<_> = observed_guardian_owner
                                .lock()
                                .map_err(|_| {
                                    io::Error::other("post-listener guardian ownership poisoned")
                                })?
                                .iter()
                                .map(|guardian| Identity {
                                    pid: guardian.identity.process_id,
                                    birth: u128::from(guardian.identity.creation_time_100ns),
                                })
                                .collect();
                            provision_budget(work_deadline).map_err(io::Error::other)?;
                            Ok(super::post_listener_end::qualify(
                                super::post_listener_end::Evidence {
                                    expected_root: Identity {
                                        pid: root_identity.pid,
                                        birth: root_identity.birth,
                                    },
                                    owner: Owner {
                                        identity: Identity {
                                            pid: root_owner.identity.pid,
                                            birth: root_owner.identity.birth,
                                        },
                                        exit_status: Some(status),
                                    },
                                    start: Some(&session.binding),
                                    descriptor_sha256: digest,
                                    challenge: &declared.challenge,
                                    port,
                                    observed_guardian: Identity {
                                        pid: observed.guardian_identity.process_id,
                                        birth: u128::from(
                                            observed.guardian_identity.creation_time_100ns,
                                        ),
                                    },
                                    held_guardians: &guardians,
                                    declared_private: declared.provider_input_binding.as_ref(),
                                    retained_private: Some(custody.binding()),
                                },
                                stage,
                                Instant::now(),
                                work_deadline,
                            ))
                        };
                        if let Some(status) = root_owner.native_exit_status()? {
                            let stage = super::post_listener_end::Stage::BeforeOwnerCheck;
                            let ended = ended_after_listener(status, stage)
                                .map_err(|error| stage.abort(error))?;
                            if let Some(ended) = ended {
                                application_ended = true;
                                return Err(io::Error::other(ended));
                            }
                            return Err(stage.original());
                        }
                        native_listener_owner(root_pid, port)?;
                        let refusal = match std::net::TcpListener::bind((
                            std::net::Ipv4Addr::LOCALHOST,
                            port,
                        )) {
                            Ok(_) => {
                                return Err(io::Error::other(
                                    "controller acquired held fixture endpoint",
                                ));
                            }
                            Err(error) => error,
                        };
                        if refusal.raw_os_error() != Some(10048) {
                            return Err(refusal);
                        }
                        native_listener_owner(root_pid, port)?;
                        if let Some(status) = root_owner.native_exit_status()? {
                            let stage = super::post_listener_end::Stage::AfterOwnerCheck;
                            let ended = ended_after_listener(status, stage)
                                .map_err(|error| stage.abort(error))?;
                            if let Some(ended) = ended {
                                application_ended = true;
                                return Err(io::Error::other(ended));
                            }
                            return Err(stage.original());
                        }
                        if let Some(observation) = &projection_observation {
                            let token = root_owner.original_token_envelope(deadline)?;
                            observation
                                .lock()
                                .map_err(|_| {
                                    io::Error::other("experiment held observation poisoned")
                                })?
                                .root =
                                Some((root_owner.identity.pid, root_owner.identity.birth, token));
                        }
                        let bytes = serde_json::to_vec(&serde_json::json!({
                        "format": "memcordon.windows-native-listener", "revision": 1,
                        "root_pid": root_pid, "root_creation_time_100ns": root_owner.identity.birth,
                        "address": "127.0.0.1", "port": port, "held_owner_live": true,
                        "native_table_owner_observed_before_and_after": true, "conflicting_bind_win32_code": refusal.raw_os_error(),
                    })).map_err(io::Error::other)?;
                        let path = directory.join(ProviderExperimentRecord::NativeListener.leaf());
                        let mut file = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&path)?;
                        file.write_all(&bytes)?;
                        file.sync_all()?;
                        if read(&path, 16 * 1024).map_err(io::Error::other)? != bytes {
                            return Err(io::Error::other("native listener named readback differs"));
                        }
                        if let Some(endpoint_event) = endpoint_event {
                            signal(&endpoint_event)?;
                        } else {
                            if let Some(custody) = &callback_private_custody {
                                let start_binding = control_session
                                    .as_ref()
                                    .ok_or_else(|| {
                                        io::Error::other(
                                            "private peer admission START session absent",
                                        )
                                    })?
                                    .binding
                                    .clone();
                                let root = held_family
                                    .lock()
                                    .map_err(|_| {
                                        io::Error::other("private root ownership poisoned")
                                    })?
                                    .first()
                                    .cloned()
                                    .ok_or_else(|| {
                                        io::Error::other("private original root absent")
                                    })?;
                                let pending = loop {
                                    let events = super::live_events(
                                        &read(&transcript, 16 * 1024 * 1024)
                                            .map_err(io::Error::other)?,
                                    )
                                    .map_err(io::Error::other)?;
                                    let intent = events
                                        .iter()
                                        .filter(|event| event.stage == "tcp-peer-spawn-intent")
                                        .collect::<Vec<_>>();
                                    let pending = events
                                        .iter()
                                        .filter(|event| event.stage == "tcp-peer-pending-admission")
                                        .collect::<Vec<_>>();
                                    if intent.len() > 1 || pending.len() > 1 {
                                        custody.mark_unknown_spawn();
                                        return Err(io::Error::other(
                                            "private peer admission marker replay",
                                        ));
                                    }
                                    if let Some(intent) = intent.first() {
                                        custody
                                            .note_spawn_uncertainty()
                                            .map_err(io::Error::other)?;
                                        if intent.pid != root_pid || intent.value.len() > 1024 {
                                            return Err(io::Error::other(
                                                "private peer spawn-intent binding extent differs",
                                            ));
                                        }
                                        let observed:descriptor::controller_start::PeerAdmissionBinding = serde_json::from_slice(&intent.value).map_err(io::Error::other)?;
                                        if observed != descriptor::controller_start::PeerAdmissionBinding::from_start(&start_binding) {
                                        return Err(io::Error::other("private peer spawn-intent binding differs"));
                                    }
                                    }
                                    if let Some(pending) = pending.first() {
                                        custody
                                            .note_spawn_uncertainty()
                                            .map_err(io::Error::other)?;
                                        if intent.len() != 1
                                            || pending.sequence <= intent[0].sequence
                                            || pending.pid != root_pid
                                            || pending.value.len() > 1024
                                        {
                                            return Err(io::Error::other(
                                                "private pending peer lacks bound prior spawn intent",
                                            ));
                                        }
                                        let pending:descriptor::controller_start::PeerPendingAdmission = serde_json::from_slice(&pending.value).map_err(io::Error::other)?;
                                        pending.validate(&start_binding)?;
                                        break pending;
                                    }
                                    if let Some(status) = root.native_exit_status()? {
                                        let stage =
                                            super::post_listener_end::Stage::BeforePeerAdmission;
                                        let ended = ended_after_listener(status, stage)
                                            .map_err(|error| stage.abort(error))?;
                                        if let Some(ended) = ended {
                                            application_ended = true;
                                            return Err(io::Error::other(ended));
                                        }
                                        return Err(stage.original());
                                    }
                                    if Instant::now() >= deadline {
                                        return Err(io::Error::new(
                                            io::ErrorKind::TimedOut,
                                            "original peer admission deadline exhausted",
                                        ));
                                    }
                                    std::thread::sleep(Duration::from_millis(10));
                                };
                                let expected = memcordon_platform::test_support::ProcessIdentity {
                                    pid: pending.recipient.pid,
                                    birth: u128::from(pending.recipient.birth),
                                };
                                let _held_peer = custody
                                    .admit_peer(
                                        &root,
                                        pending.recipient.handle,
                                        expected,
                                        &fixture,
                                        deadline,
                                    )
                                    .map_err(io::Error::other)?;
                                // Native owner insertion is complete, and no family
                                // mutex remains held across this authenticated ACK.
                                control_session
                                    .as_mut()
                                    .expect("checked original private session")
                                    .peer_held(&pending.recipient)?;
                            }
                            let peer_identity = loop {
                                let published = super::live_events(
                                    &read(&transcript, 16 * 1024 * 1024)
                                        .map_err(io::Error::other)?,
                                )
                                .map_err(io::Error::other)?;
                                if callback_private_custody.is_some()
                                    && published
                                        .iter()
                                        .filter(|event| event.stage == "tcp-peer-created")
                                        .count()
                                        > 1
                                {
                                    return Err(io::Error::other(
                                        "private TCP peer publication count differs",
                                    ));
                                }
                                if let Some(peer) = published
                                    .iter()
                                    .find(|event| event.stage == "tcp-peer-created")
                                {
                                    if peer.pid != root_pid {
                                        return Err(io::Error::other(
                                            "TCP peer publisher differs from held root",
                                        ));
                                    }
                                    break serde_json::from_slice::<
                                        memcordon_core::WindowsProcessIdentityV1,
                                    >(&peer.value)
                                    .map_err(io::Error::other)?;
                                }
                                if Instant::now() >= deadline {
                                    return Err(io::Error::other(
                                        "native TCP peer publication deadline expired",
                                    ));
                                }
                                std::thread::sleep(Duration::from_millis(10));
                            };
                            let peer = if let Some(custody) = &callback_private_custody {
                                custody
                                    .admitted_peer(
                                        memcordon_platform::test_support::ProcessIdentity {
                                            pid: peer_identity.process_id,
                                            birth: u128::from(peer_identity.creation_time_100ns),
                                        },
                                    )
                                    .map_err(io::Error::other)?
                            } else {
                                memcordon_testkit::windows_processes_for_image_until(
                                    &fixture, deadline,
                                )?
                                .into_iter()
                                .find(|process| process.identity.pid == peer_identity.process_id)
                                .ok_or_else(|| {
                                    io::Error::other("native TCP peer handle unavailable")
                                })?
                            };
                            let (family_count, root) = {
                                let held = held_family
                                    .lock()
                                    .map_err(|_| io::Error::other("fixture ownership poisoned"))?;
                                (
                                    held.len(),
                                    held.first().cloned().ok_or_else(|| {
                                        io::Error::other("original root owner absent")
                                    })?,
                                )
                            };
                            let parent_matches = if callback_private_custody.is_some() {
                                peer.native_parent_process_id()? == root_pid
                            } else {
                                process_parents()?.get(&peer.identity.pid) == Some(&root_pid)
                            };
                            if family_count
                                != (if callback_private_custody.is_some() {
                                    2
                                } else {
                                    1
                                })
                                || root.has_exited()?
                                || peer.has_exited()?
                                || peer.identity.birth
                                    != u128::from(peer_identity.creation_time_100ns)
                                || root.identity.birth > peer.identity.birth
                                || !parent_matches
                            {
                                return Err(io::Error::other(
                                    "native held TCP peer identity or live ancestry differs",
                                ));
                            }
                            let bytes = serde_json::to_vec(&serde_json::json!({
                            "format":"memcordon.windows-native-tcp-peer", "revision":1,
                            "pid":peer.identity.pid, "birth":peer.identity.birth,
                            "parent_pid":root_pid, "parent_birth":root.identity.birth,
                            "native_parent_edge_observed":true, "parent_and_child_held_live":true,
                        }))
                        .map_err(io::Error::other)?;
                            if let Some(observation) = &projection_observation {
                                let token = peer.original_token_envelope(deadline)?;
                                observation
                                    .lock()
                                    .map_err(|_| {
                                        io::Error::other("experiment held observation poisoned")
                                    })?
                                    .peer = Some((peer.identity.pid, peer.identity.birth, token));
                            }
                            let path =
                                directory.join(ProviderExperimentRecord::NativeTcpPeer.leaf());
                            let mut file = OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .open(&path)?;
                            file.write_all(&bytes)?;
                            file.sync_all()?;
                            if read(&path, 16 * 1024).map_err(io::Error::other)? != bytes {
                                return Err(io::Error::other(
                                    "native TCP peer named readback differs",
                                ));
                            }
                            if callback_private_custody.is_none() {
                                held_family
                                    .lock()
                                    .map_err(|_| io::Error::other("fixture ownership poisoned"))?
                                    .push(peer);
                            }
                        }
                    }
                    if owns_capacity_child {
                        let child_identity = loop {
                            let published = super::live_events(
                                &read(&transcript, 16 * 1024 * 1024).map_err(io::Error::other)?,
                            )
                            .map_err(io::Error::other)?;
                            if let Some(identity) =
                                super::capacity_child_identity(&published, root_pid)
                                    .map_err(io::Error::other)?
                            {
                                break identity;
                            }
                            if Instant::now() >= work_deadline {
                                return Err(io::Error::other(
                                    "capacity native child publication deadline expired",
                                ));
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        };
                        let child = memcordon_testkit::windows_processes_for_image_until(
                            &fixture,
                            work_deadline,
                        )?
                        .into_iter()
                        .find(|process| {
                            process.identity.pid == child_identity.process_id
                                && process.identity.birth
                                    == u128::from(child_identity.creation_time_100ns)
                        })
                        .ok_or_else(|| {
                            io::Error::other("capacity original child native owner absent")
                        })?;
                        let mut held = held_family
                            .lock()
                            .map_err(|_| io::Error::other("capacity family ownership poisoned"))?;
                        let root = held
                            .first()
                            .ok_or_else(|| io::Error::other("capacity original root absent"))?;
                        if held.len() != 1
                            || root.identity.pid != root_pid
                            || root.has_exited()?
                            || child.has_exited()?
                            || root.identity.birth > child.identity.birth
                            || process_parents()?.get(&child.identity.pid) != Some(&root_pid)
                        {
                            return Err(io::Error::other(
                                "capacity held child live ancestry differs",
                            ));
                        }
                        let bytes = serde_json::to_vec(&serde_json::json!({"format":"memcordon.windows-native-capacity-child","revision":1,"pid":child.identity.pid,"birth":child.identity.birth,"parent_pid":root_pid,"parent_birth":root.identity.birth,"native_parent_edge_observed":true,"parent_and_child_held_live":true})).map_err(io::Error::other)?;
                        held.push(child);
                        drop(held);
                        let path = directory.join("native-capacity-child.json");
                        let mut file = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&path)?;
                        file.write_all(&bytes)?;
                        file.sync_all()?;
                        if read(&path, 16 * 1024).map_err(io::Error::other)? != bytes {
                            return Err(io::Error::other("capacity native child readback differs"));
                        }
                        signal(cohort_event.as_ref().ok_or_else(|| {
                            io::Error::other("capacity original child gate absent")
                        })?)?;
                    }
                    if needs_toolchain_observer {
                        match start_transport {
                            descriptor::StartTransport::NamedEvent => {
                                signal(toolchain_event.as_ref().ok_or_else(|| {
                                    io::Error::other("original toolchain observer event absent")
                                })?)?
                            }
                            descriptor::StartTransport::ControllerStdin { .. } => control_session
                                .as_mut()
                                .ok_or_else(|| {
                                    io::Error::other("original Joint control session absent")
                                })?
                                .release(
                                    descriptor::controller_start::Phase::ToolchainObserverRelease,
                                )?,
                        }
                        observe_toolchain_descendants(
                            &directory,
                            &toolchain_output_root,
                            &toolchain_challenge,
                            &transcript,
                            root_pid,
                            &held_family,
                            ToolchainObservationImages {
                                images: &toolchain_images,
                                clock: toolchain_clock.ok_or_else(|| {
                                    io::Error::other("toolchain diagnostic original clock absent")
                                })?,
                            },
                            work_deadline,
                        )?;
                    }
                    if let (Some(cohort), Some(generation)) = (cohort_event, generation_event) {
                        let deadline = work_deadline.min(Instant::now() + Duration::from_secs(600));
                        let mut released_cohort = 0;
                        let mut released_generation = 0;
                        loop {
                            let published = super::live_events(
                                &read(&transcript, 16 * 1024 * 1024).map_err(io::Error::other)?,
                            )
                            .map_err(io::Error::other)?;
                            for event in &published {
                                let controller = match (event.stage.as_str(), event.ordinal) {
                                    ("cohort-live", Some(ordinal)) if ordinal > released_cohort => {
                                        released_cohort = ordinal;
                                        Some(&cohort)
                                    }
                                    ("generation-live", Some(ordinal))
                                        if ordinal > released_generation =>
                                    {
                                        released_generation = ordinal;
                                        Some(&generation)
                                    }
                                    _ => None,
                                };
                                if let Some(controller) = controller {
                                    let parents = process_parents()?;
                                    let active =
                                        memcordon_testkit::windows_processes_for_image_until(
                                            &fixture, deadline,
                                        )?;
                                    let mut family = held_family.lock().map_err(|_| {
                                        io::Error::other("fixture ownership poisoned")
                                    })?;
                                    let root = family
                                        .iter()
                                        .find(|held| held.identity.pid == root_pid)
                                        .ok_or_else(|| {
                                            io::Error::other("original churn root owner absent")
                                        })?;
                                    if root.has_exited()? {
                                        return Err(io::Error::other(
                                            "original churn root retired before barrier",
                                        ));
                                    }
                                    let root_identity = (root.identity.pid, root.identity.birth);
                                    let mut generation_depths = std::collections::BTreeSet::new();
                                    let mut live_children = 0usize;
                                    for process in active {
                                        let Some(depth) = rooted_process_depth(
                                            (process.identity.pid, process.identity.birth),
                                            root_identity,
                                            &parents,
                                        ) else {
                                            continue;
                                        };
                                        if process.has_exited()? {
                                            continue;
                                        }
                                        if depth != 0 {
                                            live_children += 1;
                                        }
                                        if event.stage == "generation-live" {
                                            generation_depths.insert(depth);
                                        }
                                        if !family
                                            .iter()
                                            .any(|held| held.identity == process.identity)
                                        {
                                            if process.has_exited()? {
                                                return Err(io::Error::other(
                                                    "churn controller observed an already retired process",
                                                ));
                                            }
                                            family.push(process);
                                        }
                                    }
                                    if event.stage == "generation-live"
                                        && ![1, 2, 3]
                                            .iter()
                                            .all(|depth| generation_depths.contains(depth))
                                    {
                                        return Err(io::Error::other(
                                            "native held snapshot omitted a generation in the three-generation branch",
                                        ));
                                    }
                                    {
                                        for process in family
                                            .iter()
                                            .filter(|process| !process.has_exited().unwrap_or(true))
                                        {
                                            let Some(depth) = rooted_process_depth(
                                                (process.identity.pid, process.identity.birth),
                                                root_identity,
                                                &parents,
                                            ) else {
                                                continue;
                                            };
                                            if depth == 0 {
                                                continue;
                                            }
                                            let parent_pid = *parents
                                                .get(&process.identity.pid)
                                                .ok_or_else(|| {
                                                    io::Error::other("held ancestor edge missing")
                                                })?;
                                            let parent = family.iter().find(|parent| parent.identity.pid == parent_pid && !parent.has_exited().unwrap_or(true))
                                            .ok_or_else(|| {
                                                let candidates = family.iter().filter(|held| held.identity.pid == parent_pid);
                                                let candidate_count = candidates.clone().count();
                                                let candidates: Vec<_> = candidates.take(8).map(|held| {
                                                    let state = match held.has_exited() {
                                                        Ok(exited) => format!("exited={exited}"),
                                                        Err(error) => format!("unavailable-kind={:?}; raw-os-error={:?}", error.kind(), error.raw_os_error()),
                                                    };
                                                    (held.identity.birth, state)
                                                }).collect();
                                                io::Error::other(format!(
                                                    "generation ancestor was not independently held live; stage={}; ordinal={:?}; root-pid={root_pid}; child-pid={}; child-birth={}; depth={depth}; parent-pid={parent_pid}; held-parent-count={candidate_count}; held-parent-observations={candidates:?}; observations-truncated={}",
                                                    event.stage, event.ordinal, process.identity.pid, process.identity.birth, candidate_count > 8,
                                                ))
                                            })?;
                                            if parent.identity.birth > process.identity.birth {
                                                return Err(io::Error::other(
                                                    "ToolHelp parent PID was reused after child creation",
                                                ));
                                            }
                                        }
                                    }
                                    if event.stage == "cohort-live" {
                                        let end = event.ordinal.expect("matched ordinal");
                                        let count = u32::from_le_bytes(
                                            event.value.as_slice().try_into().map_err(|_| {
                                                io::Error::other("invalid cohort count")
                                            })?,
                                        );
                                        if count == 0
                                            || count > descriptor::CHURN_LIVE
                                            || count > end
                                        {
                                            return Err(io::Error::other(
                                                "cohort count differs from frozen controller bound",
                                            ));
                                        }
                                        if live_children != count as usize + 1 || live_children > 64
                                        {
                                            return Err(io::Error::other(
                                                "native live population differs from cohort leaves plus retained TCP peer",
                                            ));
                                        }
                                        let children: Vec<_> = published
                                            .iter()
                                            .filter(|e| {
                                                e.stage == "child-created"
                                                    && e.ordinal.is_some_and(|n| {
                                                        n >= end - count && n < end
                                                    })
                                            })
                                            .collect();
                                        let ordinals: BTreeSet<_> = children
                                            .iter()
                                            .filter_map(|child| child.ordinal)
                                            .collect();
                                        if children.len() != count as usize
                                            || ordinals != (end - count..end).collect()
                                        {
                                            return Err(io::Error::other(
                                                "cohort publication omitted or duplicated a required ordinal",
                                            ));
                                        }
                                        let mut unique = BTreeSet::new();
                                        for child in children {
                                            let identity: memcordon_core::WindowsProcessIdentityV1 =
                                                serde_json::from_slice(&child.value)
                                                    .map_err(io::Error::other)?;
                                            if !unique.insert((
                                                identity.process_id,
                                                identity.creation_time_100ns,
                                            )) {
                                                return Err(io::Error::other(
                                                    "cohort publication duplicated a native process identity",
                                                ));
                                            }
                                            if !family.iter().any(|p| {
                                                p.identity.pid == identity.process_id
                                                    && p.identity.birth
                                                        == u128::from(identity.creation_time_100ns)
                                                    && !p.has_exited().unwrap_or(true)
                                            }) {
                                                return Err(io::Error::other(
                                                    "churn cohort identity was not held live before release",
                                                ));
                                            }
                                        }
                                    }
                                    let mut live_members = Vec::new();
                                    for member in family
                                        .iter()
                                        .filter(|process| !process.has_exited().unwrap_or(true))
                                    {
                                        if rooted_process_depth(
                                            (member.identity.pid, member.identity.birth),
                                            root_identity,
                                            &parents,
                                        )
                                        .is_none()
                                        {
                                            continue;
                                        }
                                        let parent = if member.identity.pid == root_pid {
                                            None
                                        } else {
                                            let parent_pid = *parents
                                                .get(&member.identity.pid)
                                                .ok_or_else(|| {
                                                    io::Error::other(
                                                        "churn live ancestry edge missing",
                                                    )
                                                })?;
                                            Some(
                                                family
                                                    .iter()
                                                    .find(|parent| {
                                                        parent.identity.pid == parent_pid
                                                            && !parent.has_exited().unwrap_or(true)
                                                    })
                                                    .ok_or_else(|| {
                                                        io::Error::other(
                                                            "churn live ancestry owner missing",
                                                        )
                                                    })?,
                                            )
                                        };
                                        live_members.push(serde_json::json!({
                                        "pid":member.identity.pid,"birth":member.identity.birth,
                                        "parent_pid":parent.map(|parent| parent.identity.pid),
                                        "parent_birth":parent.map(|parent| parent.identity.birth),
                                        "held_live_before_release":true,
                                    }));
                                    }
                                    let bytes = serde_json::to_vec(&serde_json::json!({
                                    "format":"memcordon.windows-native-churn-barrier","revision":1,
                                    "stage":event.stage,"ordinal":event.ordinal,"root_pid":root_pid,
                                    "live_children":live_children,"members":live_members,
                                }))
                                .map_err(io::Error::other)?;
                                    let path = directory.join(format!(
                                        "native-{}-{}.json",
                                        event.stage,
                                        event.ordinal.expect("controller ordinal")
                                    ));
                                    let mut file = OpenOptions::new()
                                        .write(true)
                                        .create_new(true)
                                        .open(&path)?;
                                    file.write_all(&bytes)?;
                                    file.sync_all()?;
                                    if read(&path, 128 * 1024).map_err(io::Error::other)? != bytes {
                                        return Err(io::Error::other(
                                            "native churn ancestry named readback differs",
                                        ));
                                    }
                                    let root = family
                                        .iter()
                                        .find(|held| {
                                            (held.identity.pid, held.identity.birth)
                                                == root_identity
                                        })
                                        .ok_or_else(|| {
                                            io::Error::other(
                                                "original diagnostic root owner absent",
                                            )
                                        })?;
                                    let console_image =
                                        held_console_image.as_ref().ok_or_else(|| {
                                            io::Error::other("held native console image absent")
                                        })?;
                                    let candidates = root.direct_children_for_image_until(
                                        &console_image.path,
                                        deadline,
                                    )?;
                                    let mut console = held_console_owners.lock().map_err(|_| {
                                        io::Error::other("native console ownership poisoned")
                                    })?;
                                    for candidate in candidates {
                                        if candidate.has_exited()? {
                                            continue;
                                        }
                                        if family
                                            .iter()
                                            .any(|held| held.identity == candidate.identity)
                                        {
                                            return Err(io::Error::other(
                                                "console identity overlaps fixture ownership",
                                            ));
                                        }
                                        if console.iter().any(|held| {
                                            held.identity.pid == candidate.identity.pid
                                                && held.identity.birth != candidate.identity.birth
                                        }) {
                                            return Err(io::Error::other(
                                                "console PID differs from original held birth",
                                            ));
                                        }
                                        if !console
                                            .iter()
                                            .any(|held| held.identity == candidate.identity)
                                        {
                                            if console.len() >= 8 {
                                                return Err(io::Error::other(
                                                    "native console owners exceed finite bound",
                                                ));
                                            }
                                            console.push(candidate);
                                        }
                                    }
                                    if root.has_exited()? {
                                        return Err(io::Error::other(
                                            "original console parent retired before publication",
                                        ));
                                    }
                                    let owners = console
                                    .iter()
                                    .map(|owner| {
                                        Ok(serde_json::json!({
                                            "pid":owner.identity.pid,"birth":owner.identity.birth,
                                            "native_parent_pid":owner.native_parent_process_id()?,
                                            "exited":owner.has_exited()?,
                                        }))
                                    })
                                    .collect::<io::Result<Vec<_>>>()?;
                                    let console_bytes = serde_json::to_vec(&serde_json::json!({
                                    "format":"memcordon.windows-native-console-owners","revision":1,
                                    "root_pid":root_identity.0,"root_birth":root_identity.1,
                                    "root_held_live":true,"job_membership_established":false,
                                    "image_utf16":console_image.path.as_os_str().encode_wide().collect::<Vec<_>>(),
                                    "image_sha256":console_image.sha256,"image_file_identity":console_image.identity,
                                    "owners":owners,
                                })).map_err(io::Error::other)?;
                                    if console_bytes.len() > 256 * 1024 {
                                        return Err(io::Error::other(
                                            "native console ownership exceeds finite bound",
                                        ));
                                    }
                                    let console_path = directory.join(format!(
                                        "native-console-owners-{}-{}.json",
                                        event.stage,
                                        event.ordinal.expect("controller ordinal"),
                                    ));
                                    let mut console_file = OpenOptions::new()
                                        .write(true)
                                        .create_new(true)
                                        .open(&console_path)?;
                                    console_file.write_all(&console_bytes)?;
                                    console_file.sync_all()?;
                                    if read(&console_path, 256 * 1024).map_err(io::Error::other)?
                                        != console_bytes
                                    {
                                        return Err(io::Error::other(
                                            "native console ownership named readback differs",
                                        ));
                                    }
                                    drop(console);
                                    let known: Vec<_> =
                                        family.iter().map(|held| held.identity).collect();
                                    let diagnostic = match root
                                        .diagnose_unheld_direct_children(&known, deadline)
                                    {
                                        Ok(value) => value,
                                        Err(error) => {
                                            let detail = error.to_string();
                                            serde_json::json!({"format":"memcordon.windows-unheld-direct-child-diagnostic","revision":1,
                                            "root_pid":root_identity.0,"root_birth":root_identity.1,
                                            "job_membership_established":false,"accepted_family_modified":false,
                                            "unavailable_kind":format!("{:?}",error.kind()),"raw_os_error":error.raw_os_error(),
                                            "detail":detail.chars().take(512).collect::<String>(),"detail_truncated":detail.chars().count()>512})
                                        }
                                    };
                                    let bytes = serde_json::to_vec(&diagnostic)
                                        .map_err(io::Error::other)?;
                                    if bytes.len() > 256 * 1024 {
                                        return Err(io::Error::other(
                                            "native child diagnostic exceeds finite bound",
                                        ));
                                    }
                                    let path = directory.join(format!(
                                        "native-unheld-children-{}-{}.json",
                                        event.stage,
                                        event.ordinal.expect("controller ordinal"),
                                    ));
                                    let mut file = OpenOptions::new()
                                        .write(true)
                                        .create_new(true)
                                        .open(&path)?;
                                    file.write_all(&bytes)?;
                                    file.sync_all()?;
                                    if read(&path, 256 * 1024).map_err(io::Error::other)? != bytes {
                                        return Err(io::Error::other(
                                            "native child diagnostic named readback differs",
                                        ));
                                    }
                                    if Instant::now() >= deadline {
                                        return Err(io::Error::other(
                                            "original churn cutoff exhausted before release",
                                        ));
                                    }
                                    if root.has_exited()? {
                                        return Err(io::Error::other(
                                            "original console parent retired before barrier release",
                                        ));
                                    }
                                    drop(family);
                                    signal(controller)?;
                                }
                            }
                            if published.iter().any(|e| e.stage == "churn-complete") {
                                break;
                            }
                            if Instant::now() >= deadline {
                                return Err(io::Error::other(
                                    "churn native controller deadline expired",
                                ));
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                    if let Some(name) = descendant_gate {
                        let deadline = work_deadline.min(Instant::now() + Duration::from_secs(60));
                        let mut intermediate_held = false;
                        loop {
                            let events = super::live_events(
                                &read(&transcript, 16 * 1024 * 1024).map_err(io::Error::other)?,
                            )
                            .map_err(io::Error::other)?;
                            if intermediate_first && !intermediate_held {
                                if let Some(event) = events.iter().find(|event| {
                                    event.stage == "intermediate-live-with-descendant"
                                }) {
                                    #[derive(Deserialize)]
                                    #[serde(deny_unknown_fields)]
                                    struct Intermediate {
                                        parent: memcordon_core::WindowsProcessIdentityV1,
                                        child: memcordon_core::WindowsProcessIdentityV1,
                                    }
                                    let identities: Intermediate =
                                        serde_json::from_slice(&event.value)
                                            .map_err(io::Error::other)?;
                                    let mut active =
                                        memcordon_testkit::windows_processes_for_image_until(
                                            &fixture, deadline,
                                        )?;
                                    let parents = process_parents()?;
                                    let mut family = held_family.lock().map_err(|_| {
                                        io::Error::other("fixture ownership poisoned")
                                    })?;
                                    let root = family
                                        .first()
                                        .ok_or_else(|| io::Error::other("held root missing"))?;
                                    if root.has_exited()?
                                        || parents.get(&identities.parent.process_id)
                                            != Some(&root_pid)
                                        || parents.get(&identities.child.process_id)
                                            != Some(&identities.parent.process_id)
                                        || root.identity.birth
                                            > u128::from(identities.parent.creation_time_100ns)
                                        || identities.parent.creation_time_100ns
                                            > identities.child.creation_time_100ns
                                    {
                                        return Err(io::Error::other(
                                            "intermediate native ancestry/ordering differs",
                                        ));
                                    }
                                    for expected in
                                        [identities.parent.clone(), identities.child.clone()]
                                    {
                                        let index = active
                                            .iter()
                                            .position(|held| {
                                                held.identity.pid == expected.process_id
                                                    && held.identity.birth
                                                        == u128::from(expected.creation_time_100ns)
                                            })
                                            .ok_or_else(|| {
                                                io::Error::other(
                                                    "intermediate native held identity missing",
                                                )
                                            })?;
                                        let held = active.swap_remove(index);
                                        if held.has_exited()? {
                                            return Err(io::Error::other(
                                                "intermediate family already retired before controller",
                                            ));
                                        }
                                        family.push(held);
                                    }
                                    let bytes = serde_json::to_vec(&serde_json::json!({
                                    "format":"memcordon.windows-intermediate-live-family","revision":1,
                                    "root_pid":root_pid,"root_birth":family[0].identity.birth,
                                    "parent":identities.parent,"child":identities.child,
                                    "native_parent_edges_observed":true,"all_three_held_live":true
                                })).map_err(io::Error::other)?;
                                    let mut file = OpenOptions::new()
                                        .write(true)
                                        .create_new(true)
                                        .open(directory.join("held-intermediate-family.json"))?;
                                    file.write_all(&bytes)?;
                                    file.sync_all()?;
                                    drop(family);
                                    descendant_release(&format!("{name}-intermediate-live"))?;
                                    intermediate_held = true;
                                }
                            }
                            if let Some(event) = events.iter().find(|event| {
                                event.stage
                                    == if intermediate_first {
                                        "intermediate-exits-with-live-descendant"
                                    } else {
                                        "root-exits-with-live-descendant"
                                    }
                            }) {
                                let child: memcordon_core::WindowsProcessIdentityV1 =
                                    serde_json::from_slice(&event.value)
                                        .map_err(io::Error::other)?;
                                let active = memcordon_testkit::windows_processes_for_image_until(
                                    &fixture, deadline,
                                )?;
                                let held_child = active
                                    .into_iter()
                                    .find(|p| {
                                        p.identity.pid == child.process_id
                                            && p.identity.birth
                                                == u128::from(child.creation_time_100ns)
                                    })
                                    .ok_or_else(|| {
                                        io::Error::other(
                                            "descendant native barrier identity differs",
                                        )
                                    })?;
                                let mut family = held_family
                                    .lock()
                                    .map_err(|_| io::Error::other("fixture ownership poisoned"))?;
                                let root_live = family
                                    .first()
                                    .is_some_and(|p| !p.has_exited().unwrap_or(false));
                                if root_live != intermediate_first {
                                    drop(family);
                                } else {
                                    if held_child.has_exited()? {
                                        return Err(io::Error::other(
                                            "descendant exited before root native observation",
                                        ));
                                    }
                                    if intermediate_first
                                        && (!intermediate_held
                                            || family.len() != 3
                                            || !family[1].has_exited()?)
                                    {
                                        return Err(io::Error::other(
                                            "intermediate did not retire before its held live descendant",
                                        ));
                                    }
                                    if !family
                                        .iter()
                                        .any(|held| held.identity == held_child.identity)
                                    {
                                        family.push(held_child);
                                    }
                                    drop(family);
                                    descendant_release(&name)?;
                                    break;
                                }
                            }
                            if Instant::now() >= deadline {
                                return Err(io::Error::other(
                                    "root-first native ordering barrier not observed",
                                ));
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                    Ok(())
                })();
                match callback {
                    Ok(()) => memcordon_testkit::OwnedCallbackOutcome::Completed,
                    Err(error) if application_ended => {
                        memcordon_testkit::OwnedCallbackOutcome::ApplicationEnded(error)
                    }
                    Err(error) => memcordon_testkit::OwnedCallbackOutcome::Abort(error),
                }
            },
        );
        // Mandatory child/callback outcome is frozen before optional consumer
        // drain. The owner still stops on every callback exit and joins once.
        crate::windows_loader_fileio::finish(&fileio_owner);
        if fileio_requested {
            let retained = (|| -> Result<()> {
                if Instant::now() >= cleanup_deadline {
                    return Err(CiError::Message(
                        "original FileIo retention cutoff exhausted".into(),
                    ));
                }
                let listener = read(
                    &input
                        .descriptor
                        .output_root
                        .join("listener-call-trace.json"),
                    crate::windows_loader_fileio::RECORD_BYTES,
                )
                .map_err(io::Error::other);
                let value = crate::windows_loader_fileio::record(&fileio_state, listener);
                let bytes = serde_json::to_vec(&value)?;
                if bytes.len() > crate::windows_loader_fileio::RECORD_BYTES {
                    return Err(CiError::Message("FileIo carrier exceeds bound".into()));
                }
                drop(crate::windows_native_files::publish_owned_file(
                    &report.with_extension("loader-fileio.json"),
                    &bytes,
                )?);
                Ok(())
            })();
            if let Err(error) = retained {
                let _ = writeln!(
                    io::stderr().lock(),
                    "optional FileIo retention unavailable: {}",
                    crate::command::bounded_excerpt(error.to_string().as_bytes())
                );
            }
        }
        let controller_resolution = if capture_gate_diagnostic && output.is_err() {
            let name: Vec<u16> = gate_name.encode_utf16().chain(Some(0)).collect();
            Some(super::gate_resolution::query(
                &name,
                gate.as_deref(),
                || {
                    provision_budget(work_deadline)
                        .map(|_| ())
                        .map_err(io::Error::other)
                },
            ))
        } else {
            None
        };
        let gate_retention = (|| -> Result<()> {
            if prepared.toolchain_held_gate.is_some() {
                // Toolchain publication waits until mandatory retirement below.
                return Ok(());
            }
            let Some(mut diagnostic) = gate_diagnostic else {
                return Ok(());
            };
            diagnostic["controller_context_named_resolution"] =
                serde_json::to_value(controller_resolution)?;
            diagnostic["controller_native_namespace_discovery"] = prepared
                .namespace
                .as_ref()
                .map(|value| value.observation.clone())
                .unwrap_or_else(
                    || serde_json::json!({"state":"unavailable","reason":"not-requested"}),
                );
            diagnostic["controller_native_namespace_descriptor_included"] = serde_json::json!(
                prepared
                    .input
                    .descriptor
                    .gate_access_diagnostic
                    .as_ref()
                    .is_some_and(|input| input.namespace.is_some())
            );
            diagnostic["controller_native_namespace_final_readback"] = prepared
                .namespace
                .as_ref()
                .zip(gate.as_ref())
                .map(|(value, gate)| {
                    value.recheck(gate.as_ref(), || {
                        provision_budget(work_deadline)
                            .map(|_| ())
                            .map_err(io::Error::other)
                    })
                })
                .unwrap_or_else(
                    || serde_json::json!({"state":"unavailable","reason":"no-original-discovery"}),
                );
            let original = match gate_root_diagnostic.lock() {
                Ok(value) => value.clone(),
                Err(_) => Some(
                    serde_json::json!({"state":"unavailable","stage":"diagnostic-lock-poisoned"}),
                ),
            };
            diagnostic["original_fixture"] = original.unwrap_or_else(|| serde_json::json!({
                "state":"unavailable","reason":"existing barrier did not admit an original held fixture; no PID reopen attempted"
            }));
            let deadline = clocks.cleanup.unwrap_or(work_deadline);
            if Instant::now() >= deadline {
                return Err(CiError::Message(
                    "original controller-gate diagnostic retention cutoff elapsed".into(),
                ));
            }
            let final_security = gate
                .as_ref()
                .map(|gate| {
                    super::workload_diagnostic::gate_security_snapshot(gate.as_ref(), deadline)
                })
                .unwrap_or_else(|| {
                    Err(io::Error::other(
                        "independent named diagnostic owner unavailable",
                    ))
                });
            let unchanged = prepared
                .original_descriptor_sha256
                .as_ref()
                .zip(final_security.as_ref().ok())
                .map(|(original, current)| original == &current.descriptor_sha256);
            diagnostic["descriptor_unchanged_since_prelaunch"] = serde_json::json!(unchanged);
            diagnostic["descriptor_comparison"] = serde_json::json!(match unchanged {
                Some(true) => "unchanged; inspect failed-call access result",
                Some(false) => "inconclusive: original descriptor drift",
                None => "inconclusive: original or final descriptor unavailable",
            });
            diagnostic["final_same_held_event_security"] = gate_query_result(final_security);
            diagnostic["final_same_held_event_mandatory_label"] = gate_query_result(
                gate.as_ref()
                    .map(|gate| {
                        super::workload_diagnostic::gate_mandatory_label_snapshot(
                            gate.as_ref(),
                            deadline,
                        )
                    })
                    .unwrap_or_else(|| {
                        Err(io::Error::other(
                            "independent named diagnostic owner unavailable",
                        ))
                    }),
            );
            let bytes = serde_json::to_vec(&diagnostic)?;
            if bytes.len() > 8 * super::gate_security::BYTE_BOUND {
                return Err(CiError::Message(
                    "controller-gate diagnostic exceeds bounded record".into(),
                ));
            }
            drop(crate::windows_native_files::publish_owned_file(
                &report.with_extension("controller-gate-security.json"),
                &bytes,
            )?);
            if Instant::now() >= deadline {
                return Err(CiError::Message(
                    "original controller-gate diagnostic retention cutoff elapsed".into(),
                ));
            }
            Ok(())
        })();
        let query_retention = (|| -> Result<()> {
            let snapshot =
                super::guardian_query::update(&guardian_query, |trace| trace.snapshot())?;
            let Some(snapshot) = snapshot else {
                return Ok(());
            };
            let deadline = clocks.cleanup.unwrap_or(work_deadline);
            for (extension, bytes) in [
                ("guardian-query.stdout.bin", snapshot.stdout),
                ("guardian-query.stderr.bin", snapshot.stderr),
                ("guardian-query.json", Some(snapshot.record)),
            ] {
                let Some(bytes) = bytes else {
                    continue;
                };
                if Instant::now() >= deadline {
                    return Err(CiError::Message(
                        "original guardian query retention cutoff exhausted".into(),
                    ));
                }
                drop(crate::windows_native_files::publish_owned_file(
                    &report.with_extension(extension),
                    &bytes,
                )?);
                if Instant::now() >= deadline {
                    return Err(CiError::Message(
                        "original guardian query retention cutoff exhausted".into(),
                    ));
                }
            }
            Ok(())
        })();
        let (output, application_end_error) = match output {
            Err(memcordon_testkit::ProcessTestError::ApplicationEnded {
                error,
                settlement: Ok(output),
            }) => (Ok(*output), Some(error)),
            output => (output, None),
        };
        let matched_broker_failure =
            super::matched_broker_outcome_failure(clocks.matched.is_some(), &output);
        let failure_case = serde_json::to_value(input.descriptor.case).ok();
        let failure_challenge =
            crate::windows_causal_acceptance::sha256(&input.descriptor.challenge);
        let failure_name = input.descriptor.start_gate.as_ref().map(|name| {
            let bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            crate::windows_causal_acceptance::sha256(&bytes)
        });
        let failure_fixture = family.lock().ok().and_then(|held| {
            held.first()
                .map(|process| (process.identity.pid, process.identity.birth))
        });
        let failure_guardian = guardian_owner.lock().ok().and_then(|held| {
            held.first().map(|process| {
                (
                    process.identity.process_id,
                    u128::from(process.identity.creation_time_100ns),
                )
            })
        });
        let control_context = input.descriptor.gate_precondition.as_ref().map(|control| {
            if !matches!(
                &output,
                Err(memcordon_testkit::ProcessTestError::Callback {
                    capture_complete: true,
                    cleanup: Ok(()),
                    ..
                })
            ) {
                return "unavailable: original callback capture/cleanup not settled".into();
            }
            let observed = (|| -> Result<String> {
                let case = failure_case
                    .as_ref()
                    .ok_or_else(|| CiError::Message("control case unavailable".into()))?;
                let name = failure_name
                    .as_ref()
                    .ok_or_else(|| CiError::Message("control gate name unavailable".into()))?;
                let controller = read(
                    &input
                        .descriptor
                        .output_root
                        .join("gate-precondition-control.json"),
                    descriptor::gate_precondition::RECORD_BYTES,
                )?;
                let child = read(
                    &input
                        .descriptor
                        .output_root
                        .join("gate-precondition-child.json"),
                    descriptor::gate_precondition::RECORD_BYTES,
                )?;
                crate::windows_original_gate_failure::control_summary(
                    &controller,
                    &child,
                    control,
                    case,
                    &failure_challenge,
                    name,
                )
                .map_err(CiError::Message)
            })();
            match observed {
                Ok(value) => value,
                Err(error) => format!(
                    "unavailable: {}",
                    crate::command::bounded_excerpt(error.to_string().as_bytes())
                ),
            }
        });
        let expected_gate_failure = match (failure_case.as_ref(), failure_name.as_ref()) {
            (Some(case), Some(name)) => Some(crate::windows_original_gate_failure::Expected {
                case,
                challenge_sha256: &failure_challenge,
                gate_name_utf16_sha256: name,
                fixture: failure_fixture,
                guardian: failure_guardian,
                guardian_query_failed: super::guardian_query::update(&guardian_query, |trace| {
                    trace.failure().is_some()
                }),
                pre_handoff_control: control_context.as_deref(),
            }),
            _ => None,
        };
        let callback_error = |error| {
            crate::windows_original_gate_failure::callback_failure(
                error,
                expected_gate_failure.as_ref(),
            )
        };
        let mut terminal_settled = false;
        let mut intrinsic_listener = None;
        let mut execution_evidence = None;
        let collection = (|| -> Result<()> {
            let retain_calls = || {
                let trace_carrier = |name: &str, format: &str| -> Result<serde_json::Value> {
                    let source = input.descriptor.output_root.join(name);
                    if !source.try_exists()? {
                        return Ok(serde_json::json!({"state":"absent","authority":false}));
                    }
                    let bytes = read(&source, 64 * 1024)?;
                    let parsed: serde_json::Value = match serde_json::from_slice(&bytes) {
                        Ok(value) => value,
                        Err(error) => {
                            return Ok(
                                serde_json::json!({"state":"invalid","error":error.to_string(),"authority":false,"identity_admission":false}),
                            );
                        }
                    };
                    if parsed["format"] != format || parsed["revision"] != 1 {
                        return Ok(
                            serde_json::json!({"state":"invalid","error":"original-call diagnostic carrier format differs","authority":false,"identity_admission":false}),
                        );
                    }
                    let path = report.with_extension(name);
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    drop(file);
                    if read(&path, 64 * 1024)? != bytes {
                        return Err(CiError::Message(
                            "original-call diagnostic retained bytes differ".into(),
                        ));
                    }
                    Ok(
                        serde_json::json!({"state":"retained","path":path,"sha256":crate::windows_causal_acceptance::sha256(&bytes),"authority":false,"identity_admission":false}),
                    )
                };
                let mut retained = serde_json::Map::new();
                for (field, name, format) in [
                    (
                        "winsock_trace",
                        "winsock-startup-trace.json",
                        "memcordon.original-winsock-startup-trace",
                    ),
                    (
                        "listener_trace",
                        "listener-call-trace.json",
                        "memcordon.original-rust-listener-trace",
                    ),
                    (
                        "native_file_requests",
                        "listener-native-file-requests.json",
                        "memcordon.original-native-file-requests",
                    ),
                    (
                        "peer_spawn_trace",
                        "peer-spawn-call-trace.json",
                        "memcordon.original-peer-spawn-trace",
                    ),
                    (
                        "peer_stdout",
                        "tcp-peer-stdout.json",
                        "memcordon.owned-peer-stdout",
                    ),
                ] {
                    let value = trace_carrier(name, format).unwrap_or_else(|error|serde_json::json!({"state":"retention-error","error":crate::command::bounded_excerpt(error.to_string().as_bytes()),"authority":false,"identity_admission":false}));
                    retained.insert(field.into(), value);
                }
                serde_json::Value::Object(retained)
            };
            if let Err(memcordon_testkit::ProcessTestError::Callback {
                stdout,
                stderr,
                capture_complete,
                observed_status,
                termination,
                cleanup,
                error,
            }) = &output
            {
                let retention = (|| -> Result<()> {
                    let calls = retain_calls();
                    let product_context = if *capture_complete && cleanup.is_ok() {
                        retain_callback_product_context(&public_report, &report, &config.provider)
                            .map_err(|error| error.to_string())
                    } else {
                        Err("callback capture or cleanup is unsettled".to_owned())
                    };
                    let diagnostic = serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-positive-callback-failure", "revision":1,
                        "error":error.to_string(), "capture_complete":capture_complete,
                        "observed_status":observed_status.map(|status| status.code()),
                        "termination":termination.map(|status| status.code()), "cleanup":cleanup,
                        "product_context":product_context,
                        "peer_stdout":calls["peer_stdout"],
                        "winsock_trace":calls["winsock_trace"],
                        "listener_trace":calls["listener_trace"],
                        "native_file_requests":calls["native_file_requests"],
                        "peer_spawn_trace":calls["peer_spawn_trace"],
                    }))?;
                    for (extension, bytes) in [
                        ("stdout.bin", stdout.as_slice()),
                        ("stderr.bin", stderr.as_slice()),
                        ("callback-failure.json", diagnostic.as_slice()),
                    ] {
                        let path = report.with_extension(extension);
                        let mut file = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&path)?;
                        file.write_all(bytes)?;
                        file.sync_all()?;
                        if read(&path, 16 * 1024 * 1024)? != bytes {
                            return Err(CiError::Message(
                                "callback capture named readback differs".into(),
                            ));
                        }
                    }
                    Ok(())
                })();
                if let Err(retention) = retention {
                    return Err(CiError::LaneFailures {
                        primary: Box::new(callback_error(
                            output.expect_err("callback failure was matched"),
                        )),
                        secondary: Box::new(
                            retention.context("callback diagnostic retention failed"),
                        ),
                    });
                }
                if *capture_complete
                    && cleanup.is_ok()
                    && input.key.family == "W-ENVELOPE"
                    && input.key.scenario == "restricted"
                {
                    let diagnostics = (|| -> Result<()> {
                        let bytes = read(
                            &public_report,
                            crate::windows_causal_acceptance::MAX_REPORT_BYTES,
                        )?;
                        let original = ResultV3::parse(&bytes).map_err(CiError::Message)?;
                        if original.provider.as_ref() != Some(&config.provider) {
                            return Err(CiError::Message(
                                "OS diagnostic original result provider differs".into(),
                            ));
                        }
                        let bootstrap_refusal = original.release == ReleaseKnowledgeV3::NotReleased
                            && original.diagnostics.as_slice().iter().any(|detail| {
                                detail.as_str().contains("MCSPAWN-FAILED")
                                    && detail.as_str().contains("bootstrap_role=loader-control")
                            });
                        let released_target =
                            super::released_target_loader_event_candidate(&original);
                        if !bootstrap_refusal && !released_target {
                            return Ok(());
                        }
                        if let Some(gate) = gate.as_ref().filter(|_| released_target) {
                            let descriptor = super::workload_diagnostic::gate_sddl(gate.as_ref())?;
                            drop(crate::windows_native_files::publish_owned_file(
                                &report.with_extension("original-gate.sddl"),
                                descriptor.as_bytes(),
                            )?);
                        }
                        let capture = super::loader_event_diagnostics::observe(work_deadline);
                        let observed_utc = std::time::SystemTime::now();
                        let failure = &original.diagnostics;
                        let unix_millis = |time: std::time::SystemTime| {
                            time.duration_since(std::time::UNIX_EPOCH)
                                .map(|duration| duration.as_millis())
                                .map_err(|error| CiError::Message(error.to_string()))
                        };
                        let metadata = serde_json::to_vec(&serde_json::json!({
                            "format":"memcordon.windows-loader-os-event-candidates","revision":1,
                            "case":input.key,"provider":config.provider,"source_commit":config.source_commit,
                            "association":super::current_association(&original).ok(),
                            "installed_images":config.installed_components,"original_result":public_report,
                            "original_result_sha256":crate::windows_causal_acceptance::sha256(&bytes),
                            "original_failure":failure,
                            "trigger":if released_target { "released-target-initialization-failure" } else { "bootstrap-launch-refusal" },
                            "original_outcome":original.outcome,
                            "observed_target_pid":super::current_native(&original).ok().and_then(|native| native.target_identity.as_ref()).map(|identity| identity.process_id),
                            "observed_target_pid_is_not_faulting_identity":true,
                            "controller_started_unix_millis":unix_millis(native_started_utc)?,
                            "controller_observed_unix_millis":unix_millis(observed_utc)?,
                            "bootstrap_birth_identity":null,"event_correlation":"unverified-candidates",
                            "correlation_missing":["trusted-bootstrap-birth","validated-faulting-process-id-and-starttime"],
                            "event_execution_pid_is_not_faulting_process_identity":true,
                            "program":capture.program,"argv":super::loader_event_diagnostics::QUERY_ARGUMENTS,
                            "total_output_limit":super::loader_event_diagnostics::MAX_CAPTURE_BYTES,
                            "query":capture.state
                        }))?;
                        for (extension, bytes) in [
                            ("os-events.stdout.xml", capture.stdout.as_slice()),
                            ("os-events.stderr.bin", capture.stderr.as_slice()),
                            ("os-events.json", metadata.as_slice()),
                        ] {
                            let path = report.with_extension(extension);
                            let mut file = OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .open(&path)?;
                            file.write_all(bytes)?;
                            file.sync_all()?;
                            if read(&path, bytes.len())? != bytes {
                                return Err(CiError::Message(
                                    "OS diagnostic named readback differs".into(),
                                ));
                            }
                        }
                        Ok(())
                    })();
                    if let Err(diagnostic) = diagnostics {
                        return Err(CiError::LaneFailures {
                            primary: Box::new(callback_error(
                                output.expect_err("callback failure was matched"),
                            )),
                            secondary: Box::new(
                                diagnostic.context("secondary OS diagnostic retention failed"),
                            ),
                        });
                    }
                }
            }
            let output = output.map_err(callback_error)?;
            let mut original_ended = None;
            if let Some(error) = application_end_error.as_ref() {
                let calls = retain_calls();
                let product_context =
                    retain_callback_product_context(&public_report, &report, &config.provider)
                        .map_err(|error| error.to_string());
                let diagnostic = serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.windows-positive-callback-failure","revision":1,
                    "callback_outcome":"application-ended","frontend_exit":"natural",
                    "error":error.to_string(),"capture_complete":true,"observed_status":output.status.code(),
                    "termination":null,"cleanup":Ok::<(), String>(()),"product_context":product_context,
                    "peer_stdout":calls["peer_stdout"],"winsock_trace":calls["winsock_trace"],
                    "listener_trace":calls["listener_trace"],"native_file_requests":calls["native_file_requests"],
                    "peer_spawn_trace":calls["peer_spawn_trace"],
                }))?;
                let path = report.with_extension("callback-failure.json");
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)?;
                file.write_all(&diagnostic)?;
                file.sync_all()?;
                drop(file);
                if read(&path, 64 * 1024)? != diagnostic {
                    return Err(CiError::Message(
                        "natural application-end diagnostic retained bytes differ".into(),
                    ));
                }
            }
            let exit_bytes = serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.windows-positive-exit","revision":1,
                "target":config.target,"executable_sha256":execution_sha256,"public_executable_sha256":config.cli.sha256,
                "native_status":output.status.code(),"capture_complete":true,
                "frontend_exit":"natural","application_end_observed":application_end_error.is_some(),
            }))?;
            let exit_path = report
                .parent()
                .expect("case report has parent")
                .join("native-exit.json");
            let mut exit_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&exit_path)?;
            exit_file.write_all(&exit_bytes)?;
            exit_file.sync_all()?;
            if read(&exit_path, 16 * 1024)? != exit_bytes {
                return Err(CiError::Message(
                    "positive native exit named readback differs".into(),
                ));
            }
            fs::write(report.with_extension("stdout.bin"), &output.stdout)?;
            fs::write(report.with_extension("stderr.bin"), &output.stderr)?;
            let result_bytes = read(
                &public_report,
                crate::windows_causal_acceptance::MAX_REPORT_BYTES,
            )?;
            let terminal_bytes = read(
                &public_report.with_extension("terminal-observation.json"),
                memcordon_platform::MAX_TERMINAL_OBSERVATION_BYTES,
            )?;
            // The restricted frontend publishes only in its declared candidate
            // output tree. After native retirement the ordinary controller takes
            // immutable copies into its protected record tree for verification.
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&report)?
                .write_all(&result_bytes)?;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(report.with_extension("terminal-observation.json"))?
                .write_all(&terminal_bytes)?;
            let terminal: memcordon_platform::AuthenticatedWindowsTerminalObservation =
                serde_json::from_slice(&terminal_bytes)?;
            let final_descriptor_bytes =
                read(&input.descriptor_path, descriptor::MAX_DESCRIPTOR_BYTES)?;
            let mut final_descriptor: descriptor::Descriptor =
                serde_json::from_slice(&final_descriptor_bytes)?;
            final_descriptor.validate().map_err(CiError::Message)?;
            if (input.key.family == "W-ENVELOPE" && input.key.scenario == "sentinel-handles")
                || input.descriptor.matched_control.is_some()
            {
                if final_descriptor.sentinel_handles.len() != 1 {
                    return Err(CiError::Message(
                        "native sentinel frontend did not augment exactly one held identity".into(),
                    ));
                }
                final_descriptor.sentinel_handles.clear();
            }
            if serde_json::to_vec(&final_descriptor)? != descriptor_bytes {
                return Err(CiError::Message(
                    "final fixture descriptor differs beyond authorized sentinel augmentation"
                        .into(),
                ));
            }
            record.descriptor_sha256 =
                crate::windows_causal_acceptance::sha256(&final_descriptor_bytes);
            let transcript = read(&input.descriptor.transcript, 16 * 1024 * 1024)?;
            record.result_sha256 = Some(crate::windows_causal_acceptance::sha256(&result_bytes));
            record.stdout_sha256 = Some(crate::windows_causal_acceptance::sha256(&output.stdout));
            record.stderr_sha256 = Some(crate::windows_causal_acceptance::sha256(&output.stderr));
            record.transcript_sha256 = Some(crate::windows_causal_acceptance::sha256(&transcript));
            record.terminal_observation_sha256 =
                Some(crate::windows_causal_acceptance::sha256(&terminal_bytes));
            record.provider_request_sha256 = Some(crate::windows_causal_acceptance::sha256(
                &terminal.provider_request,
            ));
            record.collection = Ok(());
            let matched_exit = if input.descriptor.matched_control.is_some() {
                let target = {
                    let held = family
                        .lock()
                        .map_err(|_| CiError::Message("matched native family poisoned".into()))?;
                    if held.len() != 1 {
                        return Err(CiError::Message(
                            "matched application family differs from its original root".into(),
                        ));
                    }
                    held[0].clone()
                };
                let front = frontend
                    .lock()
                    .map_err(|_| CiError::Message("matched frontend ownership poisoned".into()))?
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| {
                        CiError::Message("matched original frontend owner absent".into())
                    })?;
                provision_budget(work_deadline)?;
                let target_status = target.native_exit_status()?.ok_or_else(|| {
                    CiError::Message("matched original target remains live".into())
                })?;
                let frontend_status = front.native_exit_status()?.ok_or_else(|| {
                    CiError::Message("matched original frontend remains live".into())
                })?;
                provision_budget(work_deadline)?;
                Some((
                    front.identity.pid,
                    i32::try_from(frontend_status).map_err(|_| {
                        CiError::Message("matched frontend status exceeds signed width".into())
                    })?,
                    crate::windows_listener_wait::ApplicationEnd {
                        identity: crate::windows_listener_wait::Identity {
                            pid: target.identity.pid,
                            birth: target.identity.birth,
                        },
                        status: target_status,
                    },
                ))
            } else {
                None
            };
            let held = association
                .lock()
                .map_err(|_| CiError::Message("association ownership poisoned".into()))?;
            let held = held.as_ref().ok_or_else(|| {
                CiError::Message("native request/attempt association not held".into())
            })?;
            if let Some((_, status, ended)) = matched_exit {
                validate_ended_application_settlement(&result_bytes, status, ended, held)?;
            }
            if let Some(error) = application_end_error.as_ref() {
                let ended = match error.get_ref().and_then(|source| {
                    source.downcast_ref::<crate::windows_listener_wait::Failure>()
                }) {
                    Some(crate::windows_listener_wait::Failure::Retired { identity, status }) => {
                        crate::windows_listener_wait::ApplicationEnd {
                            identity: *identity,
                            status: *status,
                        }
                    }
                    _ if error
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<post_listener_end::Failure>())
                        .is_some() =>
                    {
                        error
                            .get_ref()
                            .and_then(|source| source.downcast_ref::<post_listener_end::Failure>())
                            .expect("matched typed post-listener failure")
                            .ended
                    }
                    _ => {
                        return Err(CiError::Message(
                            "application-ended callback omitted its typed held-root exit".into(),
                        ));
                    }
                };
                validate_ended_application_settlement(
                    &result_bytes,
                    output.status.code().ok_or_else(|| {
                        CiError::Message("missing natural frontend status".into())
                    })?,
                    ended,
                    held,
                )?;
                original_ended = Some(ended);
            }
            let assess_case = |case,
                               bytes: &[u8],
                               stdout: &[u8],
                               stderr: &[u8],
                               transcript: &[u8],
                               frontend,
                               expected| {
                if matched_listener_prefix || matched_provider_root {
                    let ended = matched_exit.map(|(_, _, ended)| ended).ok_or_else(|| {
                        CiError::Message("listener-prefix held native exit absent".into())
                    })?;
                    validate_listener_prefix_frontend(
                        case,
                        bytes,
                        stdout,
                        stderr,
                        transcript,
                        BoundPrefixExit {
                            frontend,
                            target: ended,
                        },
                        expected,
                    )
                } else {
                    assess(case, bytes, stdout, stderr, transcript, frontend, expected)
                }
            };
            let frontend_exit = FrontendExit {
                status: match matched_exit {
                    Some((_, status, _)) => status,
                    None => output
                        .status
                        .code()
                        .ok_or_else(|| CiError::Message("missing native frontend status".into()))?,
                },
                original_pid: if let Some((pid, _, _)) = matched_exit {
                    Some(pid)
                } else {
                    let frontend = frontend
                        .lock()
                        .map_err(|_| CiError::Message("frontend ownership poisoned".into()))?;
                    match frontend.as_ref() {
                        Some(process) if process.has_exited()? => Some(process.identity.pid),
                        Some(_) => {
                            return Err(CiError::Message(
                                "original status frontend remains live after wrapper exit".into(),
                            ));
                        }
                        None => None,
                    }
                },
            };
            let assessment = if !matched_listener_prefix
                && !matched_provider_root
                && crate::windows_readiness_policy::supports_listener_refusal(&input.key)
                && let Some(ended) = original_ended.filter(|ended| ended.status == 2)
            {
                use descriptor::original_listener_observation as observation;
                provision_budget(work_deadline)?;
                let bytes = read(
                    &input.descriptor.output_root.join(observation::LEAF),
                    observation::MAX_BYTES,
                )?;
                assess_original_listener_unavailable(IntrinsicListenerInput {
                    case: input,
                    result: &result_bytes,
                    stdout: &output.stdout,
                    stderr: &output.stderr,
                    transcript: &transcript,
                    frontend: frontend_exit,
                    ended,
                    association: held,
                    descriptor_sha256: descriptor::controller_start::descriptor_digest(
                        &final_descriptor_bytes,
                    ),
                    observation: &bytes,
                })
                .and_then(|observed| {
                    // Retain the exact bounded facts independently of the
                    // optional causal trace. This does not settle any owner.
                    drop(crate::windows_native_files::publish_owned_file(
                        &report.with_extension(observation::LEAF),
                        &bytes,
                    )?);
                    provision_budget(work_deadline)?;
                    intrinsic_listener = Some(observed);
                    Ok(())
                })
            } else {
                assess_case(
                    input,
                    &result_bytes,
                    &output.stdout,
                    &output.stderr,
                    &transcript,
                    frontend_exit,
                    held,
                )
            };
            let deferred_assessment =
                if application_end_error.is_some() || input.descriptor.matched_control.is_some() {
                    Some(assessment)
                } else {
                    assessment?;
                    None
                };
            if terminal.format != "memcordon.windows-terminal-observation"
                || terminal.revision != 2
                || terminal.provider != held.provider
                || terminal.terminal.attempt_id != String::from(held.attempt_id.clone())
                || terminal.terminal.request_sha256 != String::from(held.request_sha256.clone())
                || terminal.terminal.validate_for_attempt().is_err()
                || !terminal.frontend_delivery.is_consistent()
                || terminal.frontend_delivery.attempt_id != terminal.terminal.attempt_id
                || terminal.frontend_delivery.nonce != terminal.terminal.nonce
                || terminal.frontend_delivery.request_sha256 != terminal.terminal.request_sha256
            {
                return Err(CiError::Message(
                    "authenticated terminal sidecar differs from held attempt/request/provider"
                        .into(),
                ));
            }
            let request: memcordon_core::WindowsLaunchRequestV2 =
                serde_json::from_slice(&terminal.provider_request)?;
            let contract = memcordon_core::workload_request::WorkloadRequestV1::parse(&read(
                &input.workload_request,
                256 * 1024,
            )?)
            .map_err(|error| CiError::Message(error.to_string()))?;
            if crate::windows_causal_acceptance::sha256(&terminal.provider_request)
                != terminal.terminal.request_sha256
                || request.expected_provider_binding != held.provider
                || request.nonce != terminal.terminal.nonce
                || request.workload_request.as_ref() != Some(&contract)
                || request.environment != fixture_environment::entries()?
            {
                return Err(CiError::Message("exact observed launch request differs from held binding, declared contract or native system prerequisite environment".into()));
            }
            terminal_settled = true;
            if let Some(assessment) = deferred_assessment {
                assessment?;
            }
            if input.descriptor.case == descriptor::Case::Churn && intrinsic_listener.is_none() {
                let observation = &terminal.terminal.process_observation;
                let native_family = family
                    .lock()
                    .map_err(|_| CiError::Message("fixture ownership poisoned".into()))?;
                let native_console = console_owners
                    .lock()
                    .map_err(|_| CiError::Message("native console ownership poisoned".into()))?;
                let identities: Vec<_> = native_family
                    .iter()
                    .chain(native_console.iter())
                    .map(|process| {
                        Ok(memcordon_core::WindowsProcessIdentityV1 {
                            process_id: process.identity.pid,
                            creation_time_100ns: u64::try_from(process.identity.birth).map_err(
                                |_| {
                                    CiError::Message(
                                        "native process birth exceeds Windows FILETIME width"
                                            .into(),
                                    )
                                },
                            )?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let root = identities
                    .first()
                    .cloned()
                    .ok_or_else(|| CiError::Message("native root handle missing".into()))?;
                crate::windows_causal_acceptance::validate_process_observation(
                    observation,
                    &identities,
                    &crate::windows_causal_acceptance::ObservationExpectation {
                        root,
                        attempt_id: terminal.terminal.attempt_id.clone(),
                        nonce: terminal.terminal.nonce.clone(),
                        request_sha256: terminal.terminal.request_sha256.clone(),
                        worker_loss_before_freeze: false,
                    },
                )?;
                let memcordon_core::ProcessObservationCoverageV1::Sampled {
                    policy,
                    counters,
                    omissions,
                    ..
                } = &observation.coverage
                else {
                    return Err(CiError::Message(
                        "successful churn cannot substitute unavailable sampling".into(),
                    ));
                };
                if input.descriptor.churn_creations as usize <= policy.sample_slots()
                    || counters.sample_evictions == 0
                    || omissions.sample_eviction == 0
                {
                    return Err(CiError::Message("successful churn did not exercise the selected sample capacity/eviction policy".into()));
                }
            }
            if !matched_listener_prefix && !matched_provider_root && intrinsic_listener.is_none() {
                fixture_products(input)?;
            }
            let parsed = ResultV3::parse(&result_bytes).map_err(CiError::Message)?;
            let root = {
                let held = family
                    .lock()
                    .map_err(|_| CiError::Message("original root ownership poisoned".into()))?;
                let identity = held
                    .first()
                    .ok_or_else(|| CiError::Message("original root owner absent".into()))?
                    .identity;
                bind_execution_root(
                    &parsed,
                    crate::windows_listener_wait::Identity {
                        pid: identity.pid,
                        birth: identity.birth,
                    },
                )?
            };
            if let Some((_owner, cwd_identity)) = &invocation_cwd {
                provision_budget(work_deadline)?;
                if request.current_directory.is_empty()
                    || request.current_directory.len() > 32768
                    || request.current_directory.contains(&0)
                {
                    return Err(CiError::Message(
                        "authenticated invocation cwd exceeds its bound".into(),
                    ));
                }
                use std::os::windows::{ffi::OsStringExt, fs::OpenOptionsExt};
                let requested_cwd =
                    std::path::PathBuf::from(OsString::from_wide(&request.current_directory));
                if !requested_cwd.is_absolute() {
                    return Err(CiError::Message(
                        "fixture request cwd is not an absolute native snapshot".into(),
                    ));
                }
                let query_timer =
                    memcordon_platform::WindowsSynchronousIoDeadline::start(work_deadline)
                        .map_err(CiError::Message)?;
                let queried = (|| -> Result<()> {
                    let requested = OpenOptions::new()
                        .access_mode(0x80)
                        .share_mode(3)
                        .custom_flags(0x0220_0000)
                        .open(&requested_cwd)?;
                    let metadata = memcordon_testkit::windows_held_file_metadata(&requested)?;
                    validate_invocation_cwd_identity(
                        &InvocationCwdIdentity {
                            volume_serial: metadata.volume_serial,
                            file_index: metadata.file_index,
                            attributes: metadata.attributes,
                        },
                        cwd_identity,
                    )
                })();
                let query_finished = query_timer.finish().map_err(CiError::Message);
                match (queried, query_finished) {
                    (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                        primary: Box::new(primary),
                        secondary: Box::new(
                            secondary.context("invocation request cwd query retirement"),
                        ),
                    }),
                    (Err(primary), _) => Err(primary),
                    (Ok(()), result) => result,
                }?;
                let bytes = read(
                    &input
                        .descriptor
                        .output_root
                        .join("invocation-readback.json"),
                    MAX_INVOCATION_READBACK_BYTES,
                )?;
                let observed_events = super::events(&transcript)?;
                let token: Vec<_> = observed_events
                    .iter()
                    .filter(|event| event.stage == "token-envelope")
                    .collect();
                let receipt: Vec<_> = observed_events
                    .iter()
                    .filter(|event| event.stage == "invocation-readback")
                    .collect();
                if token.len() != 1
                    || receipt.len() != 1
                    || token[0].pid != root.pid
                    || receipt[0].pid != root.pid
                    || receipt[0].ordinal.is_some()
                    || receipt[0].sequence <= token[0].sequence
                    || receipt[0].value != descriptor::controller_start::descriptor_digest(&bytes)
                {
                    return Err(CiError::Message(
                        "actual invocation receipt differs from original target transcript".into(),
                    ));
                }
                let clock = input.descriptor.control_clock.as_ref().ok_or_else(|| {
                    CiError::Message("actual invocation original clock absent".into())
                })?;
                validate_invocation_readback(
                    &bytes,
                    &InvocationReadbackExpectation {
                        root: root.clone(),
                        descriptor_sha256: descriptor::controller_start::descriptor_digest(
                            &final_descriptor_bytes,
                        ),
                        challenge_sha256: descriptor::controller_start::descriptor_digest(
                            &input.descriptor.challenge,
                        ),
                        token_sha256: descriptor::controller_start::descriptor_digest(
                            &token[0].value,
                        ),
                        environment: invocation_environment(&fixture_environment::entries()?)?,
                        cwd_identity: cwd_identity.clone(),
                        work_cutoff_qpc: clock.work_cutoff_qpc,
                        qpc_frequency: clock.qpc_frequency,
                    },
                )?;
                drop(crate::windows_native_files::publish_owned_file(
                    &report.with_extension("invocation-readback.json"),
                    &bytes,
                )?);
                provision_budget(work_deadline)?;
            }
            let digest = |bytes: &[u8]| {
                memcordon_core::DiagnosticSha256::from_bytes(
                    descriptor::controller_start::descriptor_digest(bytes),
                )
            };
            execution_evidence = Some(crate::windows_readiness_policy::ExecutionEvidence {
                association: held.clone(),
                workload_request_sha256: contract
                    .digest()
                    .map_err(|error| CiError::Message(error.to_string()))?,
                root,
                descriptor_sha256: digest(&final_descriptor_bytes),
                result_sha256: digest(&result_bytes),
                stdout_sha256: digest(&output.stdout),
                stderr_sha256: digest(&output.stderr),
                transcript_sha256: digest(&transcript),
                terminal_observation_sha256: digest(&terminal_bytes),
            });
            record.behavior = Ok(());
            Ok(())
        })();
        let retirement = (|| -> Result<()> {
            let held = family
                .lock()
                .map_err(|_| CiError::Message("fixture ownership poisoned".into()))?;
            crate::windows_original_gate_failure::retired_family(
                held.iter().map(|process| process.has_exited()),
            )?;
            let remaining = memcordon_testkit::windows_processes_for_image_until(
                &config.fixture.path,
                work_deadline,
            )?;
            if let Some(owned) = &excluded_fixture {
                let expected: BTreeSet<_> = owned
                    .family
                    .iter()
                    .map(|process| (process.identity.pid, process.identity.birth))
                    .collect();
                let actual: BTreeSet<_> = remaining
                    .iter()
                    .map(|process| (process.identity.pid, process.identity.birth))
                    .collect();
                if expected.len() != owned.family.len()
                    || actual != expected
                    || owned
                        .family
                        .iter()
                        .any(|process| !matches!(process.has_exited(), Ok(false)))
                {
                    return Err(CiError::Message(
                        "overlap remaining population differs from independently held first family"
                            .into(),
                    ));
                }
            } else if !remaining.is_empty() {
                return Err(CiError::Message(
                    "same-image population remains after isolated fixture retirement".into(),
                ));
            }
            let root = held
                .first()
                .ok_or_else(|| CiError::Message("native retirement root hold absent".into()))?
                .identity;
            let mut identities: Vec<_> = held.iter().map(|process|->Result<serde_json::Value> {
                let (parent_pid,parent_birth)=if process.identity==root {(None,None)} else {
                    let parent_pid=process.native_parent_process_id()?;
                    let parent=held.iter().find(|parent|parent.identity.pid==parent_pid&&parent.identity.birth<=process.identity.birth)
                        .ok_or_else(||CiError::Message("retained native descendant lacks its exact held ancestor".into()))?;
                    (Some(parent_pid),Some(parent.identity.birth))
                };
                Ok(serde_json::json!({"pid":process.identity.pid,"birth":process.identity.birth,
                    "parent_pid":parent_pid,"parent_birth":parent_birth,"retirement_observed":true}))
            }).collect::<Result<Vec<_>>>()?;
            let console = console_owners
                .lock()
                .map_err(|_| CiError::Message("native console ownership poisoned".into()))?;
            for process in console.iter() {
                if !process.has_exited()?
                    || process.native_parent_process_id()? != root.pid
                    || process.identity.birth < root.birth
                    || held.iter().any(|owner| owner.identity == process.identity)
                {
                    return Err(CiError::Message(
                        "original held console child retirement differs".into(),
                    ));
                }
                identities.push(serde_json::json!({
                    "pid":process.identity.pid,"birth":process.identity.birth,
                    "parent_pid":root.pid,"parent_birth":root.birth,"retirement_observed":true,
                }));
            }
            drop(console);
            drop(held);
            let guardian = guardian_owner
                .lock()
                .map_err(|_| CiError::Message("guardian ownership poisoned".into()))?;
            if guardian.len() != 1 {
                return Err(CiError::Message(format!(
                    "held native guardian cardinality differs; retained-owners={}",
                    guardian.len()
                )));
            }
            if !guardian[0].has_retired()? {
                return Err(CiError::Message(
                    "exact held native guardian has not retired".into(),
                ));
            }
            if require_global_quiescence {
                GuardianBaseline::quiescent(
                    &config.installed_agent.path,
                    &config.installed_manifest.path,
                    &config.installed_agent.sha256,
                    &config.installed_manifest.sha256,
                )?;
            }
            if let Some(custody) = &private_custody {
                custody.prove_retired(work_deadline)?;
            }
            let association = association
                .lock()
                .map_err(|_| CiError::Message("association ownership poisoned".into()))?;
            let association = association
                .as_ref()
                .ok_or_else(|| CiError::Message("held retirement association missing".into()))?;
            let mut observed = serde_json::json!({
                "format":"memcordon.windows-native-positive-retirement", "revision":1,
                "association":association, "held_processes":identities,
                "guardian_identity":guardian[0].identity,
                "guardian_retirement_observed":true, "same_image_processes_absent":remaining.is_empty(),
                "global_quiescence_required":require_global_quiescence,
            });
            if let Some(owned) = &excluded_fixture {
                observed["format"] = "memcordon.windows-native-overlap-retirement".into();
                observed["excluded_live_association"] = serde_json::to_value(&owned.observation)?;
                observed["excluded_held_processes"] = serde_json::json!(owned.family.iter().map(|process|serde_json::json!({
                    "pid":process.identity.pid,"birth":process.identity.birth,"held_live_before_overlap":true,"still_live_at_own_retirement":true,
                })).collect::<Vec<_>>());
            }
            let bytes = serde_json::to_vec(&observed)?;
            let path = report
                .parent()
                .expect("case report has parent")
                .join("native-retirement.json");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            if read(&path, 16 * 1024 * 1024)? != bytes {
                return Err(CiError::Message(
                    "native retirement named readback differs".into(),
                ));
            }
            Ok(())
        })();
        let retirement = retirement.and_then(|()| {
            if let Some(pair) = &provider_pair {
                let broker = pair
                    .broker
                    .lock()
                    .map_err(|_| {
                        CiError::Message("provider broker retirement ownership poisoned".into())
                    })?
                    .clone()
                    .ok_or_else(|| {
                        CiError::Message("provider broker retirement owner absent".into())
                    })?;
                if !broker.has_exited()? {
                    return Err(CiError::Message(
                        "provider original broker retirement unproved".into(),
                    ));
                }
                pair.direct_custody.prove_retired(cleanup_deadline)?;
                clocks
                    .private_custody
                    .as_ref()
                    .ok_or_else(|| CiError::Message("provider installed custody absent".into()))?
                    .prove_retired(cleanup_deadline)?;
            }
            if matched_listener_prefix {
                provision_budget(work_deadline)?;
                let held = broker_registry_recipient.lock().map_err(|_| {
                    CiError::Message("prefix original broker reference poisoned".into())
                })?;
                let retired = held
                    .as_ref()
                    .ok_or_else(|| {
                        CiError::Message("prefix original broker reference absent".into())
                    })
                    .and_then(|handle| original_broker_retired(handle).map_err(CiError::Io));
                if !matches!(retired, Ok(true)) {
                    drop(held);
                    let _owner = Box::leak(Box::new(Arc::clone(&broker_registry_recipient)));
                    return Err(CiError::Message(format!(
                        "prefix original broker registry recipient retirement unproved: {retired:?}"
                    )));
                }
                provision_budget(work_deadline)?;
            }
            Ok(())
        });
        let retirement = if retirement.is_ok() && !matched_listener_prefix && !matched_provider_root
        {
            if let Some(owner) = &clocks.registry {
                match owner.lock() {
                    Ok(mut owner) => {
                        owner.recipients_retired();
                        retirement
                    }
                    Err(_) => Err(CiError::Message(
                        "registry input ownership poisoned after original retirement".into(),
                    )),
                }
            } else {
                retirement
            }
        } else {
            retirement
        };
        record.retirement = retirement.as_ref().map(|_| ()).map_err(ToString::to_string);
        // A known application result is not a failed intrinsic contract once
        // its original typed observation, terminal/request and every actual
        // owner have settled. Otherwise retain the original error tree.
        let intrinsic_settled = intrinsic_listener.is_some()
            && terminal_settled
            && collection.is_ok()
            && retirement.is_ok();
        let collection = match (application_end_error, collection) {
            (Some(_), Ok(())) if intrinsic_settled => Ok(()),
            (Some(primary), Ok(())) => Err(CiError::Io(primary)),
            (Some(primary), Err(secondary)) => Err(CiError::LaneFailures {
                primary: Box::new(CiError::Io(primary)),
                secondary: Box::new(secondary),
            }),
            (None, collection) => collection,
        };
        record.collection = collection.as_ref().map(|_| ()).map_err(ToString::to_string);
        if let Err(error) = &collection {
            record.behavior = Err(error.to_string());
        }
        let gate_retention = match (gate_retention, query_retention) {
            (Err(original), Err(query)) => Err(CiError::Message(format!(
                "{original}; secondary guardian query retention={query}"
            ))),
            (Err(original), _) => Err(original),
            (Ok(()), query) => query,
        };
        if let Err(error) = gate_retention {
            eprintln!("optional native gate diagnostics unavailable: {error}");
        }
        if super::start_gate_policy::capture_toolchain_held_gate(
            &input.key.family,
            &input.key.scenario,
        ) {
            let summary_retention = (|| -> Result<()> {
                let deadline = clocks.cleanup.unwrap_or(work_deadline);
                if let Some(observation) = prepared.toolchain_held_gate.as_ref() {
                    provision_budget(deadline)?;
                    let name_bytes: Vec<_> = gate_name
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect();
                    let diagnostic = serde_json::json!({
                        "format":"memcordon.toolchain-held-gate-observation","revision":1,
                        "diagnostic_only":true,"acceptance_authority":false,
                        "provenance":"same original held event before fixture launch",
                        "case":input.key,"source_commit":config.source_commit,"target":config.target,
                        "descriptor_sha256":record.descriptor_sha256,
                        "challenge_sha256":crate::windows_causal_acceptance::sha256(&input.descriptor.challenge),
                        "name_utf16_sha256":crate::windows_causal_acceptance::sha256(&name_bytes),
                        "selected_token_sha256":crate::windows_causal_acceptance::sha256(&serde_json::to_vec(&input.expected_token)?),
                        "observation":observation,
                        "original_fixture":{"state":"unavailable","reason":"not-queried-by-held-only-diagnostic"},
                        "timing":"setup charged to original work cutoff; OS queries not cancellable",
                    });
                    let bytes = serde_json::to_vec(&diagnostic)?;
                    if bytes.len() > 8 * super::gate_security::BYTE_BOUND {
                        return Err(CiError::Message(
                            "redacted held-gate record exceeds bound".into(),
                        ));
                    }
                    drop(crate::windows_native_files::publish_owned_file(
                        &report.with_extension("toolchain-held-gate-summary.json"),
                        &bytes,
                    )?);
                    provision_budget(deadline)?;
                }
                let summary = super::redacted_toolchain_failure_summary(|leaf| {
                    provision_budget(deadline).map_err(|_| ())?;
                    let path = report.parent().ok_or(())?.join(leaf);
                    let source =
                        match crate::windows_native_files::hold_artifact(&path, None, 64 * 1024) {
                            Ok(source) => Ok(Some(source.bytes)),
                            Err(CiError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                                Ok(None)
                            }
                            Err(_) => Err(()),
                        };
                    provision_budget(deadline).map_err(|_| ())?;
                    source
                });
                provision_budget(deadline)?;
                let bytes = serde_json::to_vec(&summary)?;
                if bytes.len() > 16 * 1024 {
                    return Err(CiError::Message("toolchain summary exceeds bound".into()));
                }
                drop(crate::windows_native_files::publish_owned_file(
                    &report.with_extension("toolchain-failure-summary.json"),
                    &bytes,
                )?);
                provision_budget(deadline)?;
                Ok(())
            })();
            if let Err(error) = summary_retention {
                eprintln!("optional redacted toolchain summary unavailable: {error}");
            }
        }
        let matched_observation = (|| -> Result<Option<descriptor::matched::Comparison>> {
            let Some(pair) = clocks.matched.as_ref() else {
                return Ok(None);
            };
            provision_budget(work_deadline)?;
            let observed = matched_control_report::decode(&read(
                &pair.plan.record,
                matched_control_report::MAX_BYTES,
            )?)
            .map_err(CiError::Message)?;
            let installed_bytes = read(&input.descriptor_path, descriptor::MAX_DESCRIPTOR_BYTES)?;
            let installed =
                descriptor::Descriptor::parse(&installed_bytes).map_err(CiError::Message)?;
            let mut expected = input.descriptor.clone();
            expected.sentinel_handles = installed.sentinel_handles.clone();
            if installed.sentinel_handles.len() != 1
                || serde_json::to_vec(&installed)? != serde_json::to_vec(&expected)?
            {
                return Err(CiError::Message(
                    "matched final installed descriptor differs beyond the original sentinel"
                        .into(),
                ));
            }
            let direct = pair
                .plan
                .direct_descriptor_for(&installed)
                .map_err(CiError::Message)?;
            let direct_bytes = read(
                &pair.plan.direct_descriptor,
                descriptor::MAX_DESCRIPTOR_BYTES,
            )?;
            if direct_bytes != serde_json::to_vec(&direct)? {
                return Err(CiError::Message(
                    "matched final direct descriptor differs from the same plan".into(),
                ));
            }
            pair.plan
                .validate(&direct, &installed)
                .map_err(CiError::Message)?;
            let target = {
                let held = family
                    .lock()
                    .map_err(|_| CiError::Message("matched installed family poisoned".into()))?;
                if held.len() != 1 {
                    return Err(CiError::Message(
                        "matched installed family differs from one original root".into(),
                    ));
                }
                held[0].clone()
            };
            let frontend = frontend
                .lock()
                .map_err(|_| CiError::Message("matched frontend ownership poisoned".into()))?
                .as_ref()
                .cloned()
                .ok_or_else(|| {
                    CiError::Message("matched original frontend owner missing".into())
                })?;
            provision_budget(work_deadline)?;
            let target_status = target
                .native_exit_status()?
                .ok_or_else(|| CiError::Message("matched installed target remains live".into()))?;
            let frontend_status = frontend
                .native_exit_status()?
                .ok_or_else(|| CiError::Message("matched original frontend remains live".into()))?;
            provision_budget(work_deadline)?;
            if target_status != observed.installed_frontend.native_status
                || frontend_status != observed.installed_frontend.native_status
            {
                return Err(CiError::Message(
                    "matched native installed target/frontend status differs from retained report"
                        .into(),
                ));
            }
            let stdout = read(
                &pair.plan.record.with_extension("direct-stdout.bin"),
                64 * 1024,
            )?;
            let stderr = read(
                &pair.plan.record.with_extension("direct-stderr.bin"),
                64 * 1024,
            )?;
            let broker = broker_observation
                .lock()
                .map_err(|_| {
                    CiError::Message("matched original broker observation poisoned".into())
                })?
                .as_ref()
                .and_then(|entry| entry.as_ref().ok())
                .copied()
                .ok_or_else(|| {
                    CiError::Message("matched original broker identity unproved".into())
                })?;
            let compared = matched_control_report::validate(
                &observed,
                &pair.plan,
                &matched_control_report::Expected {
                    direct_target: pair
                        .provider
                        .as_ref()
                        .map(|provider| {
                            let owner = provider.direct.lock().map_err(|_| {
                                CiError::Message(
                                    "provider actual direct observation poisoned".into(),
                                )
                            })?;
                            let direct = owner.as_ref().ok_or_else(|| {
                                CiError::Message("provider actual direct observation absent".into())
                            })?;
                            if direct.process.native_exit_status()?
                                != Some(observed.direct.native_status)
                            {
                                return Err(CiError::Message(
                                    "provider original direct native status differs".into(),
                                ));
                            }
                            Ok((
                                direct.process.identity.pid,
                                u64::try_from(direct.process.identity.birth)
                                    .map_err(io::Error::other)?,
                            ))
                        })
                        .transpose()?,
                    broker,
                    direct_descriptor_sha256: descriptor::controller_start::descriptor_digest(
                        &direct_bytes,
                    ),
                    installed_descriptor_sha256: descriptor::controller_start::descriptor_digest(
                        &installed_bytes,
                    ),
                    installed_target: (
                        target.identity.pid,
                        u64::try_from(target.identity.birth).map_err(|_| {
                            CiError::Message("matched target birth width differs".into())
                        })?,
                    ),
                    frontend: (
                        frontend.identity.pid,
                        u64::try_from(frontend.identity.birth).map_err(|_| {
                            CiError::Message("matched frontend birth width differs".into())
                        })?,
                    ),
                    direct_stdout: matched_control_report::StreamEvidence {
                        bytes: stdout.len() as u64,
                        sha256: descriptor::controller_start::descriptor_digest(&stdout),
                    },
                    direct_stderr: matched_control_report::StreamEvidence {
                        bytes: stderr.len() as u64,
                        sha256: descriptor::controller_start::descriptor_digest(&stderr),
                    },
                },
            )
            .map_err(CiError::Message)?;
            provision_budget(work_deadline)?;
            Ok(Some(compared))
        })();
        if let Some(pair) = clocks.matched.as_mut() {
            pair.settled = terminal_settled && retirement.is_ok() && matched_observation.is_ok();
            if pair.settled {
                *pair
                    .custody
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = MatchedPairCustody::Retired;
            }
            if pair.settled && (matched_listener_prefix || matched_provider_root) {
                if let Some(owner) = &clocks.registry {
                    owner
                        .lock()
                        .map_err(|_| {
                            CiError::Message(
                                "prefix registry owner poisoned after settlement".into(),
                            )
                        })?
                        .recipients_retired();
                }
            }
        }
        let matched_positive = matched_observation.and_then(|observed| {
            if observed.is_some_and(|comparison| !matched_scope_validated(&comparison)) {
                Err(CiError::Message(
                    "matched owned positive/protected-negative scope did not complete exactly"
                        .into(),
                ))
            } else {
                Ok(())
            }
        });
        let collection = match (collection, matched_positive) {
            (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(secondary),
            }),
            (Err(primary), _) => Err(primary),
            (Ok(()), result) => result,
        };
        if let Err(error) = &collection {
            record.behavior = Err(error.to_string());
        }
        let assessed = match (collection, retirement) {
            (Err(primary), Err(cleanup)) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(cleanup.context("owned retirement")),
            }),
            (Err(primary), _) => Err(primary),
            (Ok(()), retirement) => retirement,
        };
        let broker_failed = matched_broker_failure.is_some();
        let assessed = super::prioritize_matched_broker_failure(matched_broker_failure, assessed);
        if broker_failed {
            if let Err(error) = &assessed {
                record.behavior = Err(error.to_string());
            }
        }
        let assessed = assessed.and_then(|()| {
            let evidence = execution_evidence.take().ok_or_else(|| {
                CiError::Message("validated case omitted its original execution evidence".into())
            })?;
            use crate::windows_readiness_policy::{
                CaseContract, ComparisonStatus, ExecutionDisposition, IntrinsicContract,
            };
            record.contract = CaseContract {
                intrinsic: IntrinsicContract::Validated,
                comparison: ComparisonStatus::NotMeasured,
                execution: match intrinsic_listener {
                    Some(observed) => ExecutionDisposition::OriginalListenerRefusal {
                        raw_os_error: observed.raw_os_error,
                    },
                    None => ExecutionDisposition::Completed,
                },
                evidence: Some(evidence),
            };
            Ok(())
        });
        if let Err(error) = &assessed {
            record.contract.intrinsic = crate::windows_readiness_policy::IntrinsicContract::Invalid;
            record.behavior = Err(error.to_string());
        }
        assessed
    }

    fn provider_root_pair(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        original: &CaseInput,
        deployment: &mut crate::windows_provider_projection::native::Deployment,
        registry: Arc<Mutex<memcordon_testkit::WindowsWinsockRegistryProjection>>,
        deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
    ) -> Result<crate::windows_provider_control::native::RootCapture> {
        use crate::windows_provider_control::native::{RootPair, SharedInputs};
        use descriptor::matched::{Binding, Lane, Scope};
        use descriptor::matched_plan::{DirectoryRole, Plan};
        let work = deadlines.work;
        let cleanup = deadlines.cleanup;
        let mut selected = config.clone();
        selected.fixture = deployment.fixture.clone();
        selected.output_directory = deployment.output_root.clone();
        let mut input = original.clone();
        input.descriptor = prepare_provider_root_descriptor(&original.descriptor)?;
        input.key.family = "W-MATCHED-OWNED".into();
        let direct_output = deployment.output_root.join("direct");
        let installed_output = deployment.output_root.join("installed");
        let sid = sid_text(&original.expected_token.user_sid)?;
        // Reuse the existing candidate-output role recipe only on these fresh
        // fixture outputs. Immutable inputs and product permissions stay sealed.
        let output_acl = format!("D:P(A;OICI;GA;;;{sid})(A;OICI;GA;;;RC)(A;OICI;GA;;;SY)");
        for output in [&direct_output, &installed_output] {
            fs::create_dir(output)?;
            set_directory_acl(output, &output_acl)?;
            provision_budget(work)?;
        }
        let lanes = deployment.prepare_pair_custody([&direct_output, &installed_output], work)?;
        let shared = SharedInputs::capture(deployment, work)?;
        let provider = Arc::new(RootPair::new(Arc::clone(&lanes[0]), shared));
        let pair_sha256 = random_challenge()?;
        let (work_cutoff_qpc, qpc_frequency) = memcordon_testkit::windows_native_work_cutoff(work)?;
        let (cleanup_cutoff_qpc, cleanup_frequency) =
            memcordon_testkit::windows_native_work_cutoff(cleanup)?;
        if cleanup_frequency != qpc_frequency {
            return Err(CiError::Message(
                "provider original work/cleanup clock frequency differs".into(),
            ));
        }
        let clock = descriptor::ControlClock {
            revision: 1,
            work_cutoff_qpc,
            qpc_frequency,
        };
        input.descriptor.matched_control = Some(Binding {
            pair_sha256,
            lane: Lane::Installed,
            scope: Scope::ProviderListenerSelection,
            input_sha256: [0; 32],
        });
        input.descriptor.case = descriptor::Case::Joint;
        input.descriptor.provider_input_experiment = true;
        input.descriptor.provider_input_paths = deployment.paths();
        input.descriptor.provider_input_binding = Some(lanes[1].binding().clone());
        input.descriptor.output_root = installed_output.clone();
        input.descriptor.transcript = installed_output.join("fixture-events.bin");
        input.descriptor.challenge = random_challenge()?.to_vec();
        input.descriptor.control_clock = Some(clock.clone());
        input.descriptor.start_gate = Some("provider-root-original-pair".into());
        input.descriptor.start_transport = descriptor::StartTransport::ControllerStdin {
            version: if lanes[1].binding().file_layout() {
                descriptor::controller_start::PRIVATE_FILE_VERSION
            } else {
                descriptor::controller_start::PRIVATE_VERSION
            },
        };
        input.descriptor.winsock_registry = Some(
            registry
                .lock()
                .map_err(|_| CiError::Message("provider registry owner poisoned".into()))?
                .declaration()
                .clone(),
        );
        let base = deployment.output_root.clone();
        let plan_path = base.join("root-plan.json");
        input.descriptor_path = base.join("installed-input.json");
        let mut directories = Vec::new();
        let mut guards = Vec::new();
        for (role, path) in [
            (DirectoryRole::Cwd, base.clone()),
            (DirectoryRole::DirectOutput, direct_output),
            (DirectoryRole::InstalledOutput, installed_output),
        ] {
            let held = descriptor::matched_plan::hold_chain(&path, work)?;
            directories.push(descriptor::matched_plan::observe_directory(
                role,
                &path,
                held.last().ok_or_else(|| {
                    CiError::Message("provider original directory owner absent".into())
                })?,
                work,
            )?);
            guards.extend(held);
        }
        let mut plan = Plan {
            revision: 1,
            pair_sha256,
            input_sha256: [0; 32],
            scope: Scope::ProviderListenerSelection,
            restricted: original.expected_token.restricted,
            fixture_sha256: selected.fixture.sha256.clone(),
            cli_sha256: selected.cli.sha256.clone(),
            direct_descriptor: plan_path.with_extension("direct-input.json"),
            installed_descriptor: input.descriptor_path.clone(),
            cwd: base.clone(),
            environment: fixture_environment::entries()?,
            directories,
            provider: Some(deployment.provider_control(work)?),
            work_clock: clock,
            cleanup_cutoff_qpc,
            record: base.join("broker.json"),
        };
        let direct = plan
            .direct_descriptor_for(&input.descriptor)
            .map_err(CiError::Message)?;
        plan.input_sha256 = plan.input_digest(&direct).map_err(CiError::Message)?;
        input
            .descriptor
            .matched_control
            .as_mut()
            .expect("root binding")
            .input_sha256 = plan.input_sha256;
        let token_path = base.join(if original.expected_token.restricted {
            "windows-restricted-token.json"
        } else {
            "windows-ordinary-token.json"
        });
        drop(crate::windows_native_files::publish_owned_file(
            &token_path,
            &serde_json::to_vec(&original.expected_token)?,
        )?);
        let mut assessment = CaseAssessment {
            revision: CASE_ASSESSMENT_REVISION,
            contract: crate::windows_readiness_policy::CaseContract::not_run(),
            key: input.key.clone(),
            behavior: Err("root control not run".into()),
            collection: Err("root control not collected".into()),
            retirement: Err("root control native retirement unproved".into()),
            descriptor_sha256: String::new(),
            result_sha256: None,
            stdout_sha256: None,
            stderr_sha256: None,
            transcript_sha256: None,
            request_sha256: None,
            provider_request_sha256: None,
            terminal_observation_sha256: None,
        };
        let baseline = GuardianBaseline::quiescent(
            &config.installed_agent.path,
            &config.installed_manifest.path,
            &config.installed_agent.sha256,
            &config.installed_manifest.sha256,
        )?;
        let custody = Arc::new(Mutex::new(MatchedPairCustody::Unadmitted));
        // Charge shared namespace custody before the first original broker/D/F
        // creation or registry/metadata transfer can become externally visible.
        deployment.launched();
        let execution = execute_with_baseline_clocks(
            &selected,
            &input,
            &mut assessment,
            baseline,
            Vec::new(),
            None,
            ExecutionClocks {
                work,
                cleanup: Some(cleanup),
                registry: Some(registry),
                registry_lifetime: RegistryProjectionLifetime::ExperimentBorrowed,
                projection_observation: None,
                private_custody: Some(Arc::clone(&lanes[1])),
                matched: Some(MatchedExecution {
                    provider: Some(Arc::clone(&provider)),
                    plan_path,
                    plan: plan.clone(),
                    guards,
                    admitted: false,
                    settled: false,
                    custody: Arc::clone(&custody),
                }),
            },
        );
        let retirement = if custody
            .lock()
            .is_ok_and(|state| *state == MatchedPairCustody::Retired)
        {
            deployment.retired(cleanup)
        } else {
            Err(CiError::Message("provider shared namespace retained: admitted pair delivery/ACK/native/report closure unproved".into()))
        };
        if retirement.is_err() {
            let _retained = Box::leak(Box::new(Arc::clone(&provider)));
        }
        let observed = (|| -> Result<crate::windows_provider_control::native::RootCapture> {
            execution?;
            if *custody
                .lock()
                .map_err(|_| CiError::Message("provider pair closure poisoned".into()))?
                != MatchedPairCustody::Retired
            {
                return Err(CiError::Message(
                    "provider pair lacks exact delivery/ACK/native/report closure".into(),
                ));
            }
            let report = matched_control_report::decode(&read(
                &plan.record,
                matched_control_report::MAX_BYTES,
            )?)
            .map_err(CiError::Message)?;
            let actual_installed = descriptor::Descriptor::parse(&read(
                &input.descriptor_path,
                descriptor::MAX_DESCRIPTOR_BYTES,
            )?)
            .map_err(CiError::Message)?;
            let comparison = descriptor::matched::compare(
                &report.direct_record,
                &report.installed_record,
                false,
            )
            .map_err(|error| CiError::Message(error.to_string()))?;
            let mut scoped = provider.assess(
                &comparison,
                deployment.witnesses(),
                [&report.direct_input, &report.installed_input],
                &actual_installed,
                cleanup,
            )?;
            let fields = scoped
                .report
                .as_object_mut()
                .expect("closed root assessment object");
            fields.insert(
                "direct_record".into(),
                serde_json::to_value(&report.direct_record)?,
            );
            fields.insert(
                "installed_record".into(),
                serde_json::to_value(&report.installed_record)?,
            );
            fields.insert(
                "direct_native_status".into(),
                report.direct.native_status.into(),
            );
            fields.insert(
                "installed_native_status".into(),
                report.installed_frontend.native_status.into(),
            );
            fields.insert(
                "physical_stream_security_equal".into(),
                report.physical_stream_security_equal.into(),
            );
            fields.insert(
                "direct_stream_security".into(),
                serde_json::to_value(&report.direct_input.streams)?,
            );
            fields.insert(
                "installed_stream_security".into(),
                serde_json::to_value(&report.installed_input.streams)?,
            );
            if serde_json::to_vec(&scoped.report)?.len() > 256 * 1024 {
                return Err(CiError::Message(
                    "complete root records exceed 256 KiB without truncation".into(),
                ));
            }
            Ok(scoped)
        })();
        drop(provider);
        drop(lanes);
        let namespace = deployment.finish(cleanup);
        let cleanup = match (retirement, namespace) {
            (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(secondary),
            }),
            (Err(primary), _) => Err(primary),
            (Ok(()), result) => result,
        };
        match (observed, cleanup) {
            (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(secondary),
            }),
            (Err(primary), _) => Err(primary),
            (Ok(mut capture), Err(error)) => {
                capture.report["namespace_cleanup_verified"] = false.into();
                capture.report["namespace_cleanup_error"] = error.to_string().into();
                capture.validation = match capture.validation {
                    Err(primary) => Err(CiError::LaneFailures {
                        primary: Box::new(primary),
                        secondary: Box::new(error),
                    }),
                    Ok(()) => Err(error),
                };
                Ok(capture)
            }
            (Ok(mut capture), Ok(())) => {
                capture.report["namespace_cleanup_verified"] = true.into();
                capture.report["namespace_cleanup_error"] = serde_json::Value::Null;
                Ok(capture)
            }
        }
    }

    pub fn provider_input_experiment(
        root: &Path,
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
        dot_local_file: bool,
    ) -> Result<serde_json::Value> {
        use crate::windows_provider_projection::native::Deployment;
        use crate::windows_provider_projection_record::{self as facts, BindingExpectation};
        use sha2::{Digest, Sha256};
        fn json_file(path: &Path, maximum: usize, phase: &str) -> Result<serde_json::Value> {
            (|| {
                let bytes = read(path, maximum)?;
                memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                    .map_err(CiError::Message)?;
                Ok(serde_json::from_slice(&bytes)?)
            })()
            .map_err(|error: CiError| {
                error.context(format!(
                    "provider experiment phase={phase}; artifact={}",
                    path.display()
                ))
            })
        }
        fn publish(path: &Path, value: &serde_json::Value) -> Result<()> {
            let bytes = serde_json::to_vec(value)?;
            if bytes.len() > 64 * 1024 {
                return Err(CiError::Message(
                    "provider experiment record exceeds64KiB; feasibility unproved".into(),
                ));
            }
            let _parents = crate::windows_native_files::hold_ancestors(
                path.parent()
                    .ok_or_else(|| CiError::Message("experiment record parent absent".into()))?,
            )?;
            drop(crate::windows_native_files::publish_owned_file(
                path, &bytes,
            )?);
            Ok(())
        }
        fn combine(primary: Result<()>, secondary: Result<()>) -> Result<()> {
            match (primary, secondary) {
                (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                    primary: Box::new(primary),
                    secondary: Box::new(secondary),
                }),
                (Err(primary), _) => Err(primary),
                (Ok(()), other) => other,
            }
        }
        let mut attempts = Vec::new();
        let mut settled_selections = Vec::new();
        for scenario in ["ordinary", "restricted"] {
            provision_budget(deadlines.work)?;
            let attempt_directory = config
                .output_directory
                .join("provider-input-experiment")
                .join(scenario);
            fs::create_dir_all(&attempt_directory)?;
            let mut deployment = Deployment::create(
                &config.fixture,
                &config.target,
                &attempt_directory,
                deadlines.work,
                dot_local_file,
            )?;
            let mut selected = config.clone();
            selected.fixture = deployment.fixture.clone();
            selected.output_directory = deployment.output_root.clone();
            provision(root, &selected, deadlines.work)?;
            let suite: SuiteInput = serde_json::from_slice(&read(
                &selected
                    .output_directory
                    .join("windows-readiness-input.json"),
                4 * 1024 * 1024,
            )?)?;
            validate_suite(&suite)?;
            let mut input = suite
                .cases
                .iter()
                .find(|case| case.key.family == "W-JOINT" && case.key.scenario == scenario)
                .cloned()
                .ok_or_else(|| CiError::Message("declared original Joint input absent".into()))?;
            let sid = sid_text(&input.expected_token.user_sid)?;
            let projection = Arc::new(Mutex::new(
                memcordon_testkit::WindowsWinsockRegistryProjection::create(
                    &crate::windows_causal_acceptance::sha256(&input.descriptor.challenge),
                    deadlines.work,
                    deadlines.cleanup,
                )?,
            ));
            let mut phase = "catalog-preparation";
            let mut assessment = CaseAssessment {
                revision: CASE_ASSESSMENT_REVISION,
                contract: crate::windows_readiness_policy::CaseContract::not_run(),
                key: input.key.clone(),
                behavior: Err("experiment not run".into()),
                collection: Err("experiment not collected".into()),
                retirement: Err("experiment retirement unproved".into()),
                descriptor_sha256: String::new(),
                result_sha256: None,
                stdout_sha256: None,
                stderr_sha256: None,
                transcript_sha256: None,
                request_sha256: None,
                provider_request_sha256: None,
                terminal_observation_sha256: None,
            };
            let mut selected_images = serde_json::Value::Null;
            let mut scenario_selection = None;
            let mut root_selection = None;
            let held_observation = Arc::new(Mutex::new(ProjectionObservation::default()));
            let mut probe_created = false;
            let mut workload_launched = false;
            let attempted = (|| -> Result<()> {
                let catalog = crate::windows_provider_catalog::collect(
                    Arc::clone(&projection),
                    crate::windows_causal_acceptance::sha256(&input.descriptor.challenge),
                    deadlines.work,
                    deadlines.cleanup,
                )?;
                let declaration_sha = projection
                    .lock()
                    .map_err(|_| CiError::Message("experiment registry owner poisoned".into()))?
                    .declaration()
                    .clone();
                let declaration_sha = crate::windows_provider_catalog::digest(&declaration_sha)?;
                let environment = fixture_environment::entries()?;
                let root_name = "SystemRoot".encode_utf16().collect::<Vec<_>>();
                let systemroot = environment
                    .iter()
                    .find(|entry| entry.name == root_name)
                    .ok_or_else(|| CiError::Message("declared SystemRoot absent".into()))?;
                facts::verify_expansion(&catalog, &systemroot.value).map_err(CiError::Message)?;
                let candidates =
                    facts::select(&catalog, &declaration_sha).map_err(CiError::Message)?;
                phase = "private-copy-and-seal";
                deployment.copy_providers(&candidates, &catalog, &config.target, deadlines.work)?;
                deployment.seal(&sid, deadlines.work)?;
                deployment.verify(deadlines.work)?;
                phase = "root-selection-control";
                let control_parent = attempt_directory.join("root-control");
                fs::create_dir_all(&control_parent)?;
                let mut control = Deployment::create(
                    &config.fixture,
                    &config.target,
                    &control_parent,
                    deadlines.work,
                    dot_local_file,
                )?;
                control.copy_providers(&candidates, &catalog, &config.target, deadlines.work)?;
                control.seal(&sid, deadlines.work)?;
                control.verify(deadlines.work)?;
                let capture = provider_root_pair(
                    config,
                    &input,
                    &mut control,
                    Arc::clone(&projection),
                    deadlines,
                )?;
                root_selection = Some(capture.report);
                capture.validation?;
                input.descriptor.provider_input_experiment = true;
                input.descriptor.provider_input_paths = deployment.paths();
                let private_custody = deployment
                    .prepare_fixture_custody(&input.descriptor.output_root, deadlines.work)?;
                let fixture_binding = private_custody.binding().clone();
                input.descriptor.provider_input_binding = Some(fixture_binding.clone());
                publish(
                    &attempt_directory.join("declaration.json"),
                    &serde_json::json!({"source_commit":config.source_commit,"target":config.target,"fixture_sha256":config.fixture.sha256,"registry_declaration_sha256":declaration_sha,"inputs":deployment.inventory,"layout_binding":fixture_binding,"diagnostic_only":true,"acceptance_authority":false}),
                )?;
                probe_created = true;
                create_provider_probe(
                    &selected,
                    &format!(
                        "D:P(D;OICI;GW;;;RC)(A;OICI;GA;;;{sid})(A;OICI;GRGX;;;RC)(A;OICI;GA;;;SY)"
                    ),
                    deadlines.work,
                    deadlines.cleanup,
                )?;
                let baseline = GuardianBaseline::quiescent(
                    &config.installed_agent.path,
                    &config.installed_manifest.path,
                    &config.installed_agent.sha256,
                    &config.installed_manifest.sha256,
                )?;
                phase = "original-joint-workload";
                deployment.launched();
                workload_launched = true;
                let executed =
                    deployment.with_fixture_custody(&fixture_binding, deadlines.work, || {
                        execute_with_baseline_clocks(
                            &selected,
                            &input,
                            &mut assessment,
                            baseline,
                            Vec::new(),
                            None,
                            ExecutionClocks {
                                work: deadlines.work,
                                matched: None,
                                cleanup: Some(deadlines.cleanup),
                                registry: Some(Arc::clone(&projection)),
                                registry_lifetime: RegistryProjectionLifetime::ExperimentBorrowed,
                                projection_observation: Some(Arc::clone(&held_observation)),
                                private_custody: Some(Arc::clone(&private_custody)),
                            },
                        )
                    });
                let retirement = if assessment.retirement.is_ok() {
                    deployment.retired(deadlines.cleanup)
                } else {
                    Ok(())
                };
                if let Err(error) = &retirement {
                    assessment.retirement = Err(error.to_string());
                }
                combine(executed, retirement)?;
                if assessment.behavior.is_err()
                    || assessment.collection.is_err()
                    || assessment.retirement.is_err()
                {
                    return Err(CiError::Message(
                        "declared Joint workload/collection/retirement did not complete".into(),
                    ));
                }
                phase = "original-image-selection";
                deployment.verify(deadlines.work).map_err(|error| {
                    error.context(format!(
                        "provider experiment phase={phase}; deployment custody verification"
                    ))
                })?;
                let root_observation = json_file(
                    &ProviderExperimentRecord::NativeListener.source_path(
                        &selected.output_directory,
                        &input.key,
                        &input.descriptor.output_root,
                    ),
                    16 * 1024,
                    phase,
                )?;
                let peer_observation = json_file(
                    &ProviderExperimentRecord::NativeTcpPeer.source_path(
                        &selected.output_directory,
                        &input.key,
                        &input.descriptor.output_root,
                    ),
                    16 * 1024,
                    phase,
                )?;
                let observed = held_observation
                    .lock()
                    .map_err(|_| CiError::Message("experiment held observation poisoned".into()))?;
                let (root_pid, root_birth, root_token) =
                    observed.root.as_ref().ok_or_else(|| {
                        CiError::Message("actual held root observation absent".into())
                    })?;
                let (peer_pid, peer_birth, peer_token) =
                    observed.peer.as_ref().ok_or_else(|| {
                        CiError::Message("actual held peer observation absent".into())
                    })?;
                let root_birth = u64::try_from(*root_birth)
                    .map_err(|_| CiError::Message("held root birth extent".into()))?;
                let peer_birth = u64::try_from(*peer_birth)
                    .map_err(|_| CiError::Message("held peer birth extent".into()))?;
                let (root_pid, peer_pid) = (*root_pid, *peer_pid);
                if root_token != peer_token
                    || root_token.user_sid != sid
                    || root_observation["root_pid"] != serde_json::json!(root_pid)
                    || root_observation["root_creation_time_100ns"] != serde_json::json!(root_birth)
                    || peer_observation["pid"] != serde_json::json!(peer_pid)
                    || peer_observation["birth"] != serde_json::json!(peer_birth)
                {
                    return Err(CiError::Message(
                        "retained root/peer identity or token join differs".into(),
                    ));
                }
                let descriptor_sha: [u8; 32] = hex::decode(&assessment.descriptor_sha256)
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .try_into()
                    .map_err(|_| {
                        CiError::Message("experimental descriptor digest extent".into())
                    })?;
                let challenge_sha: [u8; 32] = Sha256::digest(&input.descriptor.challenge).into();
                let token_sha: [u8; 32] = Sha256::digest(serde_json::to_vec(
                    &serde_json::to_value(&input.expected_token)?,
                )?)
                .into();
                let paths = input
                    .descriptor
                    .provider_input_paths
                    .iter()
                    .map(|path| {
                        use std::os::windows::ffi::OsStrExt;
                        crate::windows_causal_acceptance::sha256(
                            &path
                                .as_os_str()
                                .encode_wide()
                                .flat_map(u16::to_le_bytes)
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect::<Vec<_>>();
                let mut images = Vec::new();
                let mut private_witnesses = Vec::new();
                for (peer, pid, birth, trace_name, probe_name) in [
                    (
                        false,
                        root_pid,
                        root_birth,
                        "listener-call-trace.json",
                        "provider-input-probes.json",
                    ),
                    (
                        true,
                        peer_pid,
                        peer_birth,
                        "peer-listener-call-trace.json",
                        "peer-provider-input-probes.json",
                    ),
                ] {
                    let trace = json_file(
                        &input.descriptor.output_root.join(trace_name),
                        64 * 1024,
                        phase,
                    )?;
                    let probes = json_file(
                        &input.descriptor.output_root.join(probe_name),
                        16 * 1024,
                        phase,
                    )?;
                    facts::mutation_witness_for_layout(
                        &probes,
                        pid,
                        peer,
                        input.expected_token.restricted,
                        &paths,
                        dot_local_file,
                    )
                    .map_err(CiError::Message)?;
                    let binding = BindingExpectation {
                        pid,
                        birth,
                        descriptor_sha256: descriptor_sha,
                        challenge_sha256: challenge_sha,
                        token_sha256: token_sha,
                        peer,
                    };
                    let observed =
                        facts::observe_original_selection(&trace, &binding, deployment.witnesses())
                            .map_err(CiError::Message)?;
                    if observed
                        .rows()
                        .iter()
                        .all(|row| row.state == facts::OriginalSelectionState::PrivateSelected)
                    {
                        private_witnesses.push(
                            facts::image_witness(&trace, &binding, deployment.witnesses())
                                .map_err(CiError::Message)?,
                        );
                    }
                    images.push(observed);
                }
                let selection = facts::ScenarioSelectionAssessment::assess(
                    if scenario == "ordinary" {
                        facts::ProviderScenario::Ordinary
                    } else {
                        facts::ProviderScenario::Restricted
                    },
                    images,
                )
                .map_err(CiError::Message)?;
                selected_images = serde_json::json!({"selection_assessment":selection,"private_positive_witnesses":private_witnesses});
                scenario_selection = Some(selection);
                phase = "complete";
                Ok(())
            })();
            let registry_retired = projection
                .lock()
                .map_err(|_| CiError::Message("experiment registry owner poisoned".into()))
                .and_then(|mut owner| owner.retire_if_safe().map_err(CiError::from));
            let attempted = match (attempted, registry_retired) {
                (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                    primary: Box::new(primary),
                    secondary: Box::new(secondary),
                }),
                (Err(primary), Ok(())) => Err(primary),
                (Ok(()), other) => other,
            };
            // Retain finite bounded records while original TempDir custody is live.
            let retained = retain_provider_experiment_facts(
                &selected.output_directory,
                &input.key,
                &input.descriptor.output_root,
                &attempt_directory.join("facts"),
                crate::windows_native_files::retain_captured_artifact,
                |path, bytes| {
                    drop(crate::windows_native_files::publish_owned_file(
                        path, bytes,
                    )?);
                    Ok(())
                },
            );
            let root_retained = (|| -> Result<()> {
                if let Some(report) = &root_selection {
                    let bytes = serde_json::to_vec(report)?;
                    if bytes.len() > 256 * 1024 {
                        return Err(CiError::Message(
                            "root-selection publication exceeds 256 KiB".into(),
                        ));
                    }
                    drop(crate::windows_native_files::publish_owned_file(
                        &attempt_directory.join("facts").join("root-selection.json"),
                        &bytes,
                    )?);
                }
                Ok(())
            })();
            let retained = combine(retained, root_retained);
            let cleanup = if !probe_created {
                Ok(())
            } else if !workload_launched || assessment.retirement.is_ok() {
                cleanup_provider_probe(&selected)
            } else {
                Err(CiError::Message(
                    "owned protected probe retained: family retirement unproved".into(),
                ))
            };
            let namespace = deployment.finish(deadlines.cleanup);
            let result = serde_json::json!({"scenario":scenario,"phase":phase,"execution_completed":attempted.is_ok()&&cleanup.is_ok()&&namespace.is_ok()&&retained.is_ok(),"private_availability":scenario_selection.as_ref().map(|selection|selection.private_availability()),"availability_scope":"invoked original root and peer provider rows; configured uninvoked inputs unmeasured","feasibility_established":attempted.is_ok()&&cleanup.is_ok()&&namespace.is_ok()&&retained.is_ok()&&scenario_selection.as_ref().is_some_and(|selection|selection.private_availability()==facts::PrivateAvailability::Available),"workload":assessment,"selected_images":selected_images,"changed_private_file_identities":true,"acceptance_authority":false,"private_namespace_cleanup_verified":namespace.is_ok(),"private_namespace_cleanup_error":namespace.as_ref().err().map(ToString::to_string),"error":attempted.as_ref().err().map(ToString::to_string)});
            let published = publish(&attempt_directory.join("result.json"), &result);
            attempts.push(result);
            let settled = combine(
                combine(combine(combine(attempted, retained), cleanup), namespace),
                published,
            );
            settled_selections.push(settle_provider_scenario(scenario_selection, settled)?);
        }
        let selection = facts::ExperimentSelectionAssessment::assess(settled_selections)
            .map_err(CiError::Message)?;
        Ok(
            serde_json::json!({"format":"memcordon.declared-provider-input-experiment","revision":1,"diagnostic_only":true,"acceptance_authority":false,"execution_completed":true,"private_availability":selection.private_availability(),"selection_assessment":selection,"availability_scope":"invoked original root and peer provider rows; configured uninvoked inputs unmeasured","feasibility_established":selection.private_availability()==facts::PrivateAvailability::Available,"source_commit":config.source_commit,"target":config.target,"fixture_sha256":config.fixture.sha256,"attempts":attempts,"mandatory_unprojected_case_replaced":false,"historical_host_access_repaired":false}),
        )
    }

    pub fn run(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input_path: &Path,
        assessments: &mut Vec<CaseAssessment>,
        work_deadline: Instant,
        diagnostic_deadlines: Option<crate::windows_installed_cases::WindowsLeaseDeadlines>,
    ) -> Result<()> {
        let input: SuiteInput = serde_json::from_slice(&read(input_path, 4 * 1024 * 1024)?)?;
        validate_suite(&input)?;
        let order = readiness_execution_order(
            &input
                .cases
                .iter()
                .map(|case| case.key.clone())
                .collect::<Vec<_>>(),
        )?;
        if !assessments.is_empty() {
            return Err(CiError::Message(
                "readiness execution cannot reuse prior case assessments".into(),
            ));
        }
        let caller = input
            .cases
            .iter()
            .find(|case| case.key.scenario == "ordinary")
            .ok_or_else(|| CiError::Message("ordinary native caller snapshot missing".into()))?;
        let sid = sid_text(&caller.expected_token.user_sid)?;
        let expected_probe = super::external_provider_probe_path(
            &config.output_directory,
            &config.installed_agent.path,
        )?
        .join("denied-write.bin");
        if input.cases.iter().any(|case| {
            !case.descriptor.denied_write_paths.is_empty()
                && case.descriptor.denied_write_paths.get(1) != Some(&expected_probe)
        }) {
            return Err(CiError::Message(
                "provider negative input is not this external fixture namespace".into(),
            ));
        }
        create_provider_probe(
            config,
            &format!("D:P(D;OICI;GW;;;RC)(A;OICI;GA;;;{sid})(A;OICI;GRGX;;;RC)(A;OICI;GA;;;SY)"),
            work_deadline,
            diagnostic_deadlines
                .map(|deadlines| deadlines.cleanup)
                .unwrap_or(work_deadline),
        )?;
        assessments.extend(input.cases.iter().map(|case| CaseAssessment {
            revision: CASE_ASSESSMENT_REVISION,
            contract: crate::windows_readiness_policy::CaseContract::not_run(),
            key: case.key.clone(),
            behavior: Err("case not run".into()),
            collection: Err("case not collected".into()),
            retirement: Err("case retirement not observed".into()),
            descriptor_sha256: String::new(),
            result_sha256: None,
            stdout_sha256: None,
            stderr_sha256: None,
            transcript_sha256: None,
            request_sha256: None,
            provider_request_sha256: None,
            terminal_observation_sha256: None,
        }));
        let mut first_error = None;
        for index in order {
            let case = &input.cases[index];
            let assessment = &mut assessments[index];
            let mut execution = case.clone();
            let request_bytes = read(
                &case.workload_request,
                memcordon_core::workload_limits::REQUEST_BYTES,
            )?;
            execution.workload_request =
                write_workload_request(&config.output_directory, &case.key, &request_bytes)?;
            let request =
                memcordon_core::workload_request::WorkloadRequestV1::parse(&request_bytes)
                    .map_err(|error| CiError::Message(error.to_string()))?;
            assessment.request_sha256 = Some(String::from(
                request
                    .digest()
                    .map_err(|error| CiError::Message(error.to_string()))?,
            ));
            if let Err(error) = execute_until_with_cleanup(
                config,
                &execution,
                assessment,
                work_deadline,
                diagnostic_deadlines.map(|deadlines| deadlines.cleanup),
            ) {
                let error = error.context(format!(
                    "Windows required case {}/{} failed after original case cleanup",
                    case.key.family, case.key.scenario
                ));
                eprintln!("{error}");
                first_error = Some(error);
                break;
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else if accepted(assessments) {
            Ok(())
        } else {
            Err(CiError::Message("Windows positive suite incomplete".into()))
        }
    }

    pub(crate) fn matched_owned(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
    ) -> Result<serde_json::Value> {
        use descriptor::matched::{Binding, Lane, Scope};
        let snapshot = |restricted: bool| -> Result<TokenObservation> {
            let mut argv = vec![OsString::from("consumer-readiness-windows")];
            if restricted {
                argv.extend([
                    OsString::from("restricted-frontend"),
                    config.fixture.path.clone().into_os_string(),
                    OsString::from("consumer-readiness-windows"),
                ]);
            }
            argv.push(OsString::from("token-snapshot"));
            let budget = provision_budget(deadlines.work)?;
            let mut command =
                CommandSpec::new(&config.fixture.path, &config.output_directory, budget)
                    .args(argv)
                    .materialize()?;
            command.env_clear();
            let output =
                memcordon_testkit::run_with_deadline_output_limit(&mut command, budget, 16 * 1024)
                    .map_err(|error| CiError::Message(error.to_string()))?;
            if !output.status.success() || !output.stderr.is_empty() {
                return Err(CiError::Message(
                    "matched caller preparation snapshot failed".into(),
                ));
            }
            let observed: TokenObservation = serde_json::from_slice(&output.stdout)?;
            if observed.restricted != restricted {
                return Err(CiError::Message(
                    "matched caller preparation restriction differs".into(),
                ));
            }
            Ok(observed)
        };
        fs::create_dir_all(&config.output_directory)?;
        let ordinary = snapshot(false)?;
        let restricted = snapshot(true)?;
        let sid = sid_text(&ordinary.user_sid)?;
        set_directory_acl(
            &config.output_directory,
            &format!("D:P(A;OICI;GA;;;{sid})(A;OICI;GRGX;;;RC)(A;OICI;GA;;;SY)"),
        )?;
        for image in [&config.cli.path, &config.fixture.path] {
            set_directory_acl(
                image,
                &format!("D:P(A;;GA;;;{sid})(A;;GRGX;;;RC)(A;;GA;;;SY)"),
            )?;
        }
        let candidate = config.output_directory.join("candidate-outputs");
        fs::create_dir(&candidate)?;
        set_directory_acl(
            &candidate,
            &format!("D:P(A;OICI;GA;;;{sid})(A;OICI;GA;;;RC)(A;OICI;GA;;;SY)"),
        )?;
        let driver_probe = config.output_directory.join("protected-driver-probe");
        // New fixture probes belong to separately owned output custody, never
        // the installed provider tree or any prior uncertain fixture object.
        let provider_probe = super::external_provider_probe_path(
            &config.output_directory,
            &config.installed_agent.path,
        )?;
        let probe_parent_guards = provider_probe_parents(config, deadlines.work)?;
        let protected_acl =
            format!("D:P(D;OICI;GW;;;RC)(A;OICI;GA;;;{sid})(A;OICI;GRGX;;;RC)(A;OICI;GA;;;SY)");
        let mut probe_owners = Vec::<(PathBuf, Option<(u32, u64)>, Option<std::fs::File>)>::new();
        let mut pair_custody = Vec::<Arc<Mutex<MatchedPairCustody>>>::new();
        let operation = (|| -> Result<serde_json::Value> {
            for probe in [&driver_probe, &provider_probe] {
                let leaf = create_probe_directory(
                    probe_parent_guards
                        .last()
                        .ok_or_else(|| CiError::Message("matched probe parent absent".into()))?,
                    probe
                        .file_name()
                        .ok_or_else(|| CiError::Message("matched probe leaf absent".into()))?,
                    deadlines.work,
                )?;
                probe_owners.push((probe.clone(), None, Some(leaf)));
                let info = memcordon_testkit::windows_held_file_metadata(
                    probe_owners
                        .last()
                        .expect("new probe owner")
                        .2
                        .as_ref()
                        .expect("new probe native owner"),
                )?;
                probe_owners.last_mut().expect("new probe owner").1 =
                    Some((info.volume_serial, info.file_index));
                set_directory_acl(probe, &protected_acl)?;
            }
            let request=memcordon_core::workload_request::WorkloadRequestV1::parse(br#"{"format":"memcordon.workload-request","revision":1,"runtime":{"kind":"windows-sealed","profile":"windows-sealed-current-token-v1"},"requirements":[]}"#).map_err(|error| CiError::Message(error.to_string()))?;
            let request = request
                .canonical_bytes()
                .map_err(|error| CiError::Message(error.to_string()))?;
            let mut pairs = Vec::new();
            let mut first_error = None;
            for (scope, name) in [
                (Scope::BinaryFiles, "binary-files"),
                (Scope::Envelope, "envelope"),
                (Scope::JointListenerPrefix, "listener-prefix"),
            ] {
                for (is_restricted, profile, expected) in [
                    (false, "ordinary", &ordinary),
                    (true, "restricted", &restricted),
                ] {
                    let pair_started = Instant::now();
                    let work = deadlines.work.min(pair_started + Duration::from_secs(120));
                    let cleanup = deadlines
                        .cleanup
                        .min(pair_started + Duration::from_secs(180));
                    provision_budget(work)?;
                    let directory = config
                        .output_directory
                        .join("matched-owned-controls")
                        .join(name)
                        .join(profile);
                    fs::create_dir_all(&directory)?;
                    let mut selected = config.clone();
                    selected.output_directory = directory.clone();
                    let token_path = directory.join(if is_restricted {
                        "windows-restricted-token.json"
                    } else {
                        "windows-ordinary-token.json"
                    });
                    drop(crate::windows_native_files::publish_owned_file(
                        &token_path,
                        &serde_json::to_vec(expected)?,
                    )?);
                    let pair_sha256 = random_challenge()?;
                    let challenge = random_challenge()?.to_vec();
                    let denied = if is_restricted && scope == Scope::Envelope {
                        vec![
                            driver_probe.join("denied-write.bin"),
                            provider_probe.join("denied-write.bin"),
                        ]
                    } else {
                        Vec::new()
                    };
                    let output = candidate.join(name).join(profile).join("installed");
                    let direct_output = candidate.join(name).join(profile).join("direct");
                    let (work_cutoff_qpc, qpc_frequency) =
                        memcordon_testkit::windows_native_work_cutoff(work)?;
                    let mut descriptor = descriptor::Descriptor {
                        matched_control: Some(Binding {
                            pair_sha256,
                            lane: Lane::Installed,
                            scope,
                            input_sha256: [0; 32],
                        }),
                        provider_input_experiment: false,
                        provider_input_paths: Vec::new(),
                        provider_input_binding: None,
                        format: "memcordon.fixture-workload".into(),
                        revision: descriptor::DESCRIPTOR_REVISION,
                        case: match scope {
                            Scope::BinaryFiles => descriptor::Case::BinaryFiles,
                            Scope::Envelope => descriptor::Case::Envelope,
                            Scope::JointListenerPrefix | Scope::ProviderListenerSelection => {
                                descriptor::Case::Joint
                            }
                        },
                        output_root: output.clone(),
                        transcript: output.join("fixture-events.bin"),
                        challenge,
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        arguments: Vec::new(),
                        application_status: 0,
                        churn_creations: descriptor::CHURN_CREATIONS,
                        churn_live: descriptor::CHURN_LIVE,
                        denied_write_paths: denied,
                        sentinel_handles: Vec::new(),
                        descendant_gate: None,
                        start_gate: Some("matched-owned-scope".into()),
                        start_transport: descriptor::StartTransport::ControllerStdin {
                            version: descriptor::controller_start::VERSION,
                        },
                        control_clock: Some(descriptor::ControlClock {
                            revision: 1,
                            work_cutoff_qpc,
                            qpc_frequency,
                        }),
                        winsock_registry: None,
                        gate_access_diagnostic: None,
                        gate_precondition: None,
                        completion_gate: None,
                        cohort_gate: None,
                        generation_gate: None,
                        toolchain: None,
                    };
                    let registry = if scope == Scope::JointListenerPrefix {
                        let owner = memcordon_testkit::WindowsWinsockRegistryProjection::create(
                            &hex::encode(pair_sha256),
                            work,
                            cleanup,
                        )?;
                        descriptor.winsock_registry = Some(owner.declaration().clone());
                        descriptor.start_transport = descriptor::StartTransport::ControllerStdin {
                            version: descriptor::controller_start::REGISTRY_VERSION,
                        };
                        Some(Arc::new(Mutex::new(owner)))
                    } else {
                        None
                    };
                    fs::create_dir_all(&output)?;
                    fs::create_dir_all(&direct_output)?;
                    let plan_path = directory.join("plan.json");
                    let broker_record = directory.join("broker.json");
                    let (cleanup_cutoff_qpc, cleanup_frequency) =
                        memcordon_testkit::windows_native_work_cutoff(cleanup)?;
                    if cleanup_frequency != qpc_frequency {
                        return Err(CiError::Message(
                            "matched pair clock frequencies differ".into(),
                        ));
                    }
                    let mut roles = vec![
                        (
                            descriptor::matched_plan::DirectoryRole::Cwd,
                            directory.clone(),
                        ),
                        (
                            descriptor::matched_plan::DirectoryRole::DirectOutput,
                            direct_output,
                        ),
                        (
                            descriptor::matched_plan::DirectoryRole::InstalledOutput,
                            output,
                        ),
                    ];
                    if is_restricted && scope == Scope::Envelope {
                        roles.extend([
                            (
                                descriptor::matched_plan::DirectoryRole::DriverParent,
                                driver_probe.clone(),
                            ),
                            (
                                descriptor::matched_plan::DirectoryRole::ProviderParent,
                                provider_probe.clone(),
                            ),
                        ]);
                    }
                    let mut directories = Vec::new();
                    let mut guards = Vec::new();
                    for (role, path) in roles {
                        let held = descriptor::matched_plan::hold_chain(&path, work)?;
                        directories.push(descriptor::matched_plan::observe_directory(
                            role,
                            &path,
                            held.last().ok_or_else(|| {
                                CiError::Message("matched producer directory custody absent".into())
                            })?,
                            work,
                        )?);
                        guards.extend(held);
                    }
                    let mut plan = descriptor::matched_plan::Plan {
                        revision: 1,
                        pair_sha256,
                        input_sha256: [0; 32],
                        scope,
                        restricted: is_restricted,
                        fixture_sha256: config.fixture.sha256.clone(),
                        cli_sha256: config.cli.sha256.clone(),
                        direct_descriptor: plan_path.with_extension("direct-input.json"),
                        installed_descriptor: directory.join("installed-input.json"),
                        cwd: directory.clone(),
                        environment: fixture_environment::entries()?,
                        directories,
                        provider: None,
                        work_clock: descriptor
                            .control_clock
                            .clone()
                            .expect("matched work clock"),
                        cleanup_cutoff_qpc,
                        record: broker_record.clone(),
                    };
                    let direct = plan
                        .direct_descriptor_for(&descriptor)
                        .map_err(CiError::Message)?;
                    plan.input_sha256 = plan.input_digest(&direct).map_err(CiError::Message)?;
                    descriptor
                        .matched_control
                        .as_mut()
                        .expect("matched installed binding")
                        .input_sha256 = plan.input_sha256;
                    let key = CaseKey {
                        family: "W-MATCHED-OWNED".into(),
                        scenario: profile.into(),
                    };
                    let input = CaseInput {
                        key: key.clone(),
                        descriptor,
                        descriptor_path: directory.join("installed-input.json"),
                        workload_request: write_workload_request(&directory, &key, &request)?,
                        expected_token: expected.clone(),
                    };
                    let mut assessment = CaseAssessment {
                        revision: CASE_ASSESSMENT_REVISION,
                        contract: crate::windows_readiness_policy::CaseContract::not_run(),
                        key,
                        behavior: Err("not run".into()),
                        collection: Err("not collected".into()),
                        retirement: Err("not observed".into()),
                        descriptor_sha256: String::new(),
                        result_sha256: None,
                        stdout_sha256: None,
                        stderr_sha256: None,
                        transcript_sha256: None,
                        request_sha256: Some(crate::windows_causal_acceptance::sha256(&request)),
                        provider_request_sha256: None,
                        terminal_observation_sha256: None,
                    };
                    let baseline = GuardianBaseline::quiescent(
                        &config.installed_agent.path,
                        &config.installed_manifest.path,
                        &config.installed_agent.sha256,
                        &config.installed_manifest.sha256,
                    )?;
                    let custody = Arc::new(Mutex::new(MatchedPairCustody::Unadmitted));
                    pair_custody.push(Arc::clone(&custody));
                    let result = execute_with_baseline_clocks(
                        &selected,
                        &input,
                        &mut assessment,
                        baseline,
                        Vec::new(),
                        None,
                        ExecutionClocks {
                            work,
                            cleanup: Some(cleanup),
                            matched: Some(MatchedExecution {
                                provider: None,
                                plan_path,
                                plan,
                                guards,
                                admitted: false,
                                settled: false,
                                custody,
                            }),
                            registry,
                            registry_lifetime: RegistryProjectionLifetime::ExecutionOwned,
                            projection_observation: None,
                            private_custody: None,
                        },
                    );
                    let captured = (|| -> Result<serde_json::Value> {
                        let bytes = read(&broker_record, matched_control_report::MAX_BYTES)?;
                        let observed =
                            matched_control_report::decode(&bytes).map_err(CiError::Message)?;
                        Ok(
                            serde_json::json!({"path":broker_record,"sha256":crate::windows_causal_acceptance::sha256(&bytes),"scope":observed.scope,"claim_scope":observed.claim_scope,"validation":observed.validation,"native_availability":observed.native_availability,"paired_stdio":observed.paired_stdio,"positive_coverage":observed.positive_coverage,"physical_stream_security_equal":observed.physical_stream_security_equal,"comparison":observed.comparison,"direct_native_status":observed.direct.native_status,"frontend_native_status":observed.installed_frontend.native_status}),
                        )
                    })();
                    let capture_error = captured.as_ref().err().map(ToString::to_string);
                    let (broker, capture) = match captured {
                        Ok(value) => (Some(value), Ok(())),
                        Err(error) => (None, Err(error)),
                    };
                    let result = match (result, capture) {
                        (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                            primary: Box::new(primary),
                            secondary: Box::new(secondary),
                        }),
                        (Err(primary), _) => Err(primary),
                        (Ok(()), capture) => capture,
                    };
                    pairs.push(serde_json::json!({"scope":scope,"caller":profile,"installed":assessment,"broker":broker,"broker_capture_error":capture_error,"execution_error":result.as_ref().err().map(ToString::to_string)}));
                    if let Err(error) = result {
                        first_error = Some(error);
                        break;
                    }
                }
                if first_error.is_some() {
                    break;
                }
            }
            let report = serde_json::json!({"format":"memcordon.matched-owned-scopes","revision":3,"full_joint_coverage":"unestablished","pairs":pairs});
            drop(crate::windows_native_files::publish_owned_file(
                &config.output_directory.join("matched-owned-controls.json"),
                &serde_json::to_vec(&report)?,
            )?);
            match first_error {
                Some(error) => Err(error),
                None => Ok(report),
            }
        })();
        let cleanup = (|| -> Result<()> {
            // This state is set only by the original controller owner path,
            // after terminal validation, direct report and native retirement.
            // Neither matching outcomes nor terminal status can set it.
            for custody in &pair_custody {
                if *custody
                    .lock()
                    .map_err(|_| CiError::Message("matched pair custody poisoned".into()))?
                    == MatchedPairCustody::Admitted
                {
                    return Err(CiError::Message("external protected probes retained: admitted pair native retirement unproved".into()));
                }
            }
            for (path, expected, leaf) in &mut probe_owners {
                provision_budget(deadlines.cleanup)?;
                let expected = expected.ok_or_else(|| {
                    CiError::Message(
                        "matched probe creation identity unavailable; namespace retained".into(),
                    )
                })?;
                drop(leaf.take());
                descriptor::matched_plan::remove_empty_directory(
                    path,
                    expected,
                    deadlines.cleanup,
                )?;
                provision_budget(deadlines.cleanup)?;
            }
            Ok(())
        })();
        if cleanup.is_err() {
            let _probes = Box::leak(Box::new(probe_owners));
            let _parents = Box::leak(Box::new(probe_parent_guards));
        }
        match (operation, cleanup) {
            (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(secondary),
            }),
            (Err(primary), _) => Err(primary),
            (Ok(_), Err(error)) => Err(error),
            (Ok(report), Ok(())) => Ok(report),
        }
    }
}
