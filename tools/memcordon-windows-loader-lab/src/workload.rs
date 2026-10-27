//! A separate actual-image startup experiment. These records are never readiness authority.

use memcordon_core::{NativeWindowsCommandV1, WindowsLaunchRequestV1};
use memcordon_windows_launch_core::ProductionLoaderPlanV2;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PROBE_ELIGIBILITY_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DefaultDaclProbeKindV1 {
    #[serde(rename = "qualified-w-envelope-restricted-fixture")]
    QualifiedRestrictedEnvelopeFixture,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DefaultDaclProbeTargetV1 {
    #[serde(rename = "x86_64-pc-windows-msvc")]
    X86_64WindowsMsvc,
    #[serde(rename = "aarch64-pc-windows-msvc")]
    Aarch64WindowsMsvc,
}

impl TryFrom<&str> for DefaultDaclProbeTargetV1 {
    type Error = String;
    fn try_from(target: &str) -> Result<Self, String> {
        match target {
            "x86_64-pc-windows-msvc" => Ok(Self::X86_64WindowsMsvc),
            "aarch64-pc-windows-msvc" => Ok(Self::Aarch64WindowsMsvc),
            _ => Err("unsupported controlled diagnostic target".into()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultDaclProbeEligibilityV1 {
    pub revision: u32,
    pub kind: DefaultDaclProbeKindV1,
    pub source_commit: String,
    pub target: DefaultDaclProbeTargetV1,
    pub fixture_sha256: String,
    pub original_result_sha256: String,
    pub original_terminal_sha256: String,
    pub original_descriptor_sha256: String,
}

fn deserialize_probe_eligibility<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<DefaultDaclProbeEligibilityV1>, D::Error> {
    DefaultDaclProbeEligibilityV1::deserialize(decoder).map(Some)
}

impl DefaultDaclProbeEligibilityV1 {
    pub fn validate_native(&self, machine: u16) -> Result<(), String> {
        let expected = match self.target {
            DefaultDaclProbeTargetV1::X86_64WindowsMsvc if cfg!(target_arch = "x86_64") => 0x8664,
            DefaultDaclProbeTargetV1::Aarch64WindowsMsvc if cfg!(target_arch = "aarch64") => 0xaa64,
            _ => {
                return Err("controlled diagnostic target differs from helper architecture".into());
            }
        };
        if !cfg!(windows) || machine != expected {
            return Err("controlled diagnostic pinned image PE target differs".into());
        }
        Ok(())
    }

    pub fn validate_for(&self, request: &WorkloadDiagnosticRequestV1) -> Result<(), String> {
        if self.revision != 1
            || !matches!(self.source_commit.len(), 40 | 64)
            || !self
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.source_commit
                != request
                    .original_request
                    .expected_provider_binding
                    .source_commit
                    .as_str()
            || self.fixture_sha256 != request.image_sha256
            || self.original_result_sha256 != request.original_result_sha256
            || self.original_terminal_sha256 != request.original_terminal_sha256
            || self.original_descriptor_sha256 != request.original_descriptor_sha256
            || serde_json::to_vec(self)
                .map_err(|error| error.to_string())?
                .len()
                > MAX_PROBE_ELIGIBILITY_BYTES
        {
            return Err(
                "controlled diagnostic eligibility differs from qualified original evidence".into(),
            );
        }
        Ok(())
    }
}

/// Read-only mirror of the frontend-local custody envelope. No live scope or
/// native authority can be reconstructed from this diagnostic serialization.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalTerminalContext {
    format: String,
    revision: u32,
    provider: memcordon_core::PublicProviderBindingV1,
    terminal: memcordon_core::WindowsTerminalReceiptV2,
    frontend_delivery: memcordon_core::WindowsTerminalDeliveryEvidenceV1,
    provider_request: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadDiagnosticRequestV1 {
    pub schema_version: u32,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_probe_eligibility"
    )]
    pub default_dacl_probe: Option<DefaultDaclProbeEligibilityV1>,
    pub original_result_sha256: String,
    pub original_terminal_sha256: String,
    pub original_result_bytes: Vec<u8>,
    pub original_terminal_bytes: Vec<u8>,
    pub original_request_bytes: Vec<u8>,
    pub original_pid: u32,
    pub original_birth: u64,
    pub original_request: WindowsLaunchRequestV1,
    /// A token/object-policy reference, not an actual-workload launch plan.
    pub reference_plan: ProductionLoaderPlanV2,
    pub image_sha256: String,
    pub command: NativeWindowsCommandV1,
    pub original_descriptor: serde_json::Value,
    pub descriptor: serde_json::Value,
    pub original_descriptor_sha256: String,
    pub descriptor_sha256: String,
    pub descriptor_path: PathBuf,
    pub output_directory: PathBuf,
    pub diagnostic_id: String,
    pub gate_security_descriptor_sddl: String,
    /// Absolute GetTickCount64 readings, shared by controller and service.
    pub work_deadline_tick_ms: u64,
    pub cleanup_deadline_tick_ms: u64,
}

impl WorkloadDiagnosticRequestV1 {
    pub fn parse_transport(bytes: &[u8], expected_sha256: &str) -> Result<Self, String> {
        if bytes.len() > MAX_REQUEST_BYTES || hex::encode(Sha256::digest(bytes)) != expected_sha256
        {
            return Err("workload diagnostic raw request digest or bound differs".into());
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)?;
        let request: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), String> {
        let digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if self.schema_version != 1
            || self.original_pid == 0
            || self.original_birth == 0
            || self.diagnostic_id.is_empty()
            || self.diagnostic_id.len() > 64
            || self.gate_security_descriptor_sddl.is_empty()
            || self.gate_security_descriptor_sddl.len() > 16 * 1024
            || self.gate_security_descriptor_sddl.contains('\0')
            || !self
                .diagnostic_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || self.work_deadline_tick_ms == 0
            || self.cleanup_deadline_tick_ms < self.work_deadline_tick_ms
            || [
                &self.original_result_sha256,
                &self.original_terminal_sha256,
                &self.image_sha256,
                &self.original_descriptor_sha256,
                &self.descriptor_sha256,
            ]
            .into_iter()
            .any(|value| !digest(value))
        {
            return Err("workload diagnostic identity or finite budget differs".into());
        }
        if self.original_result_bytes.len() > 4 * 1024 * 1024
            || self.original_terminal_bytes.len() > 8 * 1024 * 1024
            || self.original_request_bytes.len() > 1024 * 1024
            || hex::encode(Sha256::digest(&self.original_result_bytes))
                != self.original_result_sha256
            || hex::encode(Sha256::digest(&self.original_terminal_bytes))
                != self.original_terminal_sha256
        {
            return Err("workload diagnostic original evidence bytes differ".into());
        }
        let original = memcordon_core::result_v1::ResultV1::parse(&self.original_result_bytes)?;
        use memcordon_core::result_v1::{
            AuthorizationV1, CleanupStateV1, LaunchStateV1, OutcomeKindV1,
        };
        if original.outcome.kind != OutcomeKindV1::Completed
            || original.outcome.wrapper_status != 125
            || original.authorization != AuthorizationV1::Granted
            || original.launch.state != LaunchStateV1::ReleaseIssued
            || !matches!(
                original.outcome.native_termination,
                Some(memcordon_core::ChildTermination::WindowsStatus { status: 0xC0000142 })
            )
            || original.cleanup.state != CleanupStateV1::Complete
            || !original.cleanup.direct_child_reaped
            || original.cleanup.workload_empty != Some(true)
            || !original.cleanup.outstanding.is_empty()
            || !original.cleanup.failed_operations.is_empty()
            || original.attempts.len() != 1
            || !original.attempts.last().is_some_and(|attempt| {
                let proof = &attempt.restart_safety;
                proof.direct_child_reaped
                    && proof.workload_empty == Some(true)
                    && proof.helpers_reaped
                    && proof.containment_removed
                    && proof.containment_incapable_of_live_members
                    && proof.sealed_boundary_retired
                    && proof.errors.is_empty()
            })
        {
            return Err(
                "workload diagnostic requires the original settled released initialization failure"
                    .into(),
            );
        }
        let association = original
            .provider_association
            .as_ref()
            .ok_or("original provider absent")?;
        if association.provider != self.original_request.expected_provider_binding
            || String::from(association.request_sha256.clone())
                != hex::encode(Sha256::digest(&self.original_request_bytes))
            || serde_json::from_slice::<WindowsLaunchRequestV1>(&self.original_request_bytes)
                .map_err(|error| error.to_string())?
                != self.original_request
            || original.launch.target_pid.map(std::num::NonZeroU32::get) != Some(self.original_pid)
        {
            return Err("workload diagnostic original request association differs".into());
        }
        let terminal: OriginalTerminalContext =
            serde_json::from_slice(&self.original_terminal_bytes)
                .map_err(|error| error.to_string())?;
        if terminal.format != "memcordon.windows-terminal-observation"
            || terminal.revision != 1
            || terminal.provider != association.provider
            || terminal.terminal.attempt_id != String::from(association.attempt_id.clone())
            || terminal.terminal.request_sha256 != String::from(association.request_sha256.clone())
            || terminal.provider_request != self.original_request_bytes
            || terminal.terminal.validate_for_attempt().is_err()
            || !terminal.frontend_delivery.is_consistent()
            || terminal.frontend_delivery.attempt_id != terminal.terminal.attempt_id
            || terminal.frontend_delivery.request_sha256 != terminal.terminal.request_sha256
            || terminal.frontend_delivery.nonce != terminal.terminal.nonce
            || terminal
                .terminal
                .process_observation
                .root_identity
                .as_ref()
                .is_none_or(|root| {
                    root.process_id != self.original_pid
                        || root.creation_time_100ns != self.original_birth
                })
        {
            return Err("workload diagnostic terminal association differs".into());
        }
        let proof = &terminal.terminal.retirement_proof;
        if !proof.target_completion_observed
            || !proof.native_job_empty_observed
            || !proof.relay_closure_observed
            || !proof.guardian_completion_observed
            || !proof.owner_capabilities_closed
            || !proof.launch_gate_closed
            || !proof.policy_reference_bound
        {
            return Err("workload diagnostic original native retirement incomplete".into());
        }
        let memcordon_core::WindowsTerminalPayloadV2::Execution {
            child_pid,
            outcome,
            boundary_detail,
            ..
        } = &terminal.terminal.payload
        else {
            return Err("workload diagnostic original terminal is not execution".into());
        };
        let memcordon_core::BoundaryMechanismEvidence::WindowsJobObjectV2(boundary) =
            boundary_detail.as_ref()
        else {
            return Err("workload diagnostic original native boundary differs".into());
        };
        if *child_pid != self.original_pid
            || !matches!(
                outcome,
                memcordon_core::RunOutcome::Exited {
                    child: memcordon_core::ChildTermination::WindowsStatus { status: 0xC0000142 },
                    ..
                }
            )
            || !boundary.target_released
            || !boundary.active_processes_zero
            || !boundary.direct_target_reaped
            || !boundary.relays_retired
            || !boundary.guardian_reaped
            || !boundary.final_job_handles_closed
            || !outcome.cleanup().direct_child_reaped
            || outcome.cleanup().workload_empty != Some(true)
            || !outcome.cleanup().errors.is_empty()
        {
            return Err(
                "workload diagnostic original terminal execution contradicts result".into(),
            );
        }
        let value = serde_json::to_value(&original).map_err(|error| error.to_string())?;
        let plan = value
            .pointer("/attempts/0/boundary_detail/loader_qualification/result/launch_plan_json")
            .and_then(serde_json::Value::as_str)
            .ok_or("original reference plan absent")?;
        let recorded: ProductionLoaderPlanV2 =
            serde_json::from_str(plan).map_err(|error| error.to_string())?;
        if recorded != self.reference_plan {
            return Err("workload diagnostic reference plan differs from original".into());
        }
        let terminal_plan = boundary
            .loader_qualification
            .as_ref()
            .and_then(|qualification| qualification.launch_plan_json())
            .ok_or("terminal object/token reference absent")?;
        if serde_json::from_str::<ProductionLoaderPlanV2>(terminal_plan)
            .map_err(|error| error.to_string())?
            != self.reference_plan
        {
            return Err("workload diagnostic terminal reference differs from result".into());
        }
        // The current fixture protocol has exactly a role and descriptor operand.
        // No arbitrary argv mutation is admitted by this diagnostic.
        let original = &self.original_request.command;
        if self.command.program != original.program
            || original.arguments.len() != 2
            || self.command.arguments.len() != 2
            || self.command.arguments[0] != original.arguments[0]
            || String::from_utf16(&original.arguments[0]).ok().as_deref()
                != Some("consumer-readiness-windows")
            || self.command.arguments[1] == original.arguments[1]
            || original.program.is_empty()
            || original.program.contains(&0)
            || self.original_request.current_directory.is_empty()
        {
            return Err("workload diagnostic changed the image or unsupported argv".into());
        }
        let descriptor_path = self
            .descriptor_path
            .to_str()
            .ok_or("descriptor path is not Unicode")?;
        let output = self
            .output_directory
            .to_str()
            .ok_or("output path is not Unicode")?;
        let transcript = self
            .descriptor
            .get("transcript")
            .and_then(serde_json::Value::as_str)
            .ok_or("diagnostic transcript absent")?;
        if !windows_absolute(descriptor_path)
            || !windows_absolute(output)
            || descriptor_path.strip_prefix(output) != Some("\\input.json")
            || transcript.strip_prefix(output) != Some("\\fixture-events.bin")
            || self
                .descriptor
                .get("output_root")
                .and_then(serde_json::Value::as_str)
                != Some(output)
            || self
                .descriptor
                .get("start_gate")
                .and_then(serde_json::Value::as_str)
                != Some(
                    format!(
                        "Local\\memcordon-workload-diagnostic-{}",
                        self.diagnostic_id
                    )
                    .as_str(),
                )
        {
            return Err("workload diagnostic outputs escape the separate owned namespace".into());
        }
        let expected = descriptor_path.encode_utf16().collect::<Vec<_>>();
        if self.command.arguments[1] != expected
            || self.descriptor == self.original_descriptor
            || !self.original_descriptor.is_object()
            || !self.descriptor.is_object()
        {
            return Err("workload diagnostic descriptor substitution is not explicit".into());
        }
        let mut original_descriptor = self.original_descriptor.clone();
        let mut descriptor = self.descriptor.clone();
        for key in ["output_root", "transcript", "start_gate"] {
            let old = original_descriptor
                .as_object_mut()
                .expect("object checked")
                .remove(key);
            let new = descriptor
                .as_object_mut()
                .expect("object checked")
                .remove(key);
            if old.as_ref().and_then(serde_json::Value::as_str).is_none()
                || new.as_ref().and_then(serde_json::Value::as_str).is_none()
                || old == new
            {
                return Err("workload diagnostic controlled descriptor difference absent".into());
            }
        }
        if original_descriptor != descriptor
            || self
                .descriptor
                .get("case")
                .and_then(serde_json::Value::as_str)
                != Some("envelope")
            || hex::encode(Sha256::digest(
                serde_json::to_vec(&self.original_descriptor).map_err(|error| error.to_string())?,
            )) != self.original_descriptor_sha256
            || hex::encode(Sha256::digest(
                serde_json::to_vec(&self.descriptor).map_err(|error| error.to_string())?,
            )) != self.descriptor_sha256
        {
            return Err("workload diagnostic descriptor policy or canonical hash differs".into());
        }
        if let Some(eligibility) = &self.default_dacl_probe {
            eligibility.validate_for(self)?;
        }
        Ok(())
    }
}

fn windows_absolute(path: &str) -> bool {
    let mut characters = path.chars();
    characters
        .next()
        .is_some_and(|drive| drive.is_ascii_alphabetic())
        && characters.next() == Some(':')
        && characters.next() == Some('\\')
        && !path.contains(['\0', '/'])
        && characters
            .as_str()
            .split('\\')
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains(':'))
}

#[cfg(windows)]
pub struct HeldWorkloadRequest {
    pub input: WorkloadDiagnosticRequestV1,
    file: std::fs::File,
    identity: RequestFileIdentity,
    raw_sha256: String,
}

#[cfg(windows)]
#[derive(Eq, PartialEq)]
struct RequestFileIdentity {
    volume: u64,
    id: [u8; 16],
    length: u64,
    written: u64,
}

#[cfg(windows)]
impl HeldWorkloadRequest {
    fn identity(file: &std::fs::File) -> Result<RequestFileIdentity, String> {
        use std::os::windows::{fs::MetadataExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
        };
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file()
            || metadata.len() > MAX_REQUEST_BYTES as u64
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err("workload request is not a bounded ordinary nonreparse file".into());
        }
        let mut native: FILE_ID_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: live held file and correctly sized native output buffer.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut native as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(RequestFileIdentity {
            volume: native.VolumeSerialNumber,
            id: native.FileId.Identifier,
            length: metadata.len(),
            written: metadata.last_write_time(),
        })
    }

    fn open_file(path: &std::path::Path) -> Result<std::fs::File, String> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| error.to_string())
    }

    fn bytes(file: &std::fs::File) -> Result<Vec<u8>, String> {
        use std::io::{Read, Seek, SeekFrom};
        let mut reader = file;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|error| error.to_string())?;
        let mut bytes = Vec::new();
        reader
            .take(MAX_REQUEST_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err("workload request grew beyond bound".into());
        }
        Ok(bytes)
    }

    pub fn open(path: &std::path::Path, expected_sha256: Option<&str>) -> Result<Self, String> {
        let file = Self::open_file(path)?;
        let identity = Self::identity(&file)?;
        let bytes = Self::bytes(&file)?;
        let raw_sha256 = hex::encode(Sha256::digest(&bytes));
        let input = WorkloadDiagnosticRequestV1::parse_transport(
            &bytes,
            expected_sha256.unwrap_or(&raw_sha256),
        )?;
        let held = Self {
            input,
            file,
            identity,
            raw_sha256,
        };
        held.recheck(path)?;
        Ok(held)
    }

    pub fn recheck(&self, path: &std::path::Path) -> Result<(), String> {
        let named = Self::open_file(path)?;
        if Self::identity(&self.file)? != self.identity
            || Self::identity(&named)? != self.identity
            || hex::encode(Sha256::digest(Self::bytes(&self.file)?)) != self.raw_sha256
            || hex::encode(Sha256::digest(Self::bytes(&named)?)) != self.raw_sha256
        {
            return Err("held workload request bytes or native file identity changed".into());
        }
        Ok(())
    }
}
