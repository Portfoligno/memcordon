//! Exact private native suite admission. This is not a completion producer.
//!
//! The suite cannot succeed until each declared case has a compiled native
//! implementation and the supervising runner can issue authenticated raw
//! observations. In particular, parsing a catalogue never creates a trusted
//! completion or qualification capability.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use memcordon_core::package_inspection_v6::{LinuxPackageInspectionV6, LinuxUnitHashesV6};
use memcordon_core::private_release_case_v1::{
    PRIVATE_RELEASE_RESULT_ROOT_V1, PrivateReleaseInstalledBindingV1, PrivateReleaseStageV1,
    private_release_case_key_v1,
};
use memcordon_core::runtime_manifest_v3::{RuntimeManifestV3, SealedRuntimeV3};
use memcordon_core::workload_codec::hash_bytes;
use serde::Deserialize;

use crate::certification_context::CertificationContext;
use crate::command::CommandSpec;
use crate::private_agent_path::{
    AGENT_PATH_SELECTOR, AgentPathSnapshotV1, validate_agent_path_observer,
};
use crate::private_child_live::{
    CHILD_RUNTIME_SELECTOR, join_live_sample_to_result, sample_and_ack_if_ready,
};
use crate::private_dual_live::{
    DUAL_SELECTOR, join_sampled_dual_to_result, sample_and_ack_if_ready as sample_dual_gate,
};
use crate::private_host_state::{
    HOST_PRESERVATION_SELECTOR, HostNetworkStateV1, validate_host_preservation_observer,
};
use crate::private_installed_h0::{
    join_installed_epoch_to_candidate_request, read_fixed_agent_identity,
    read_fixed_installation_epoch, read_fixed_installed_h0, validate_installed_h0_static,
};
use crate::private_native::{NativeRunStageV2, PRODUCERS, PrivateNativeProducerSpec};
use crate::private_protected_readback::{
    ProtectedCandidateReleaseRequestV1, read_structural_protected_native_case,
    validate_candidate_allocated_raw_attachments_with_agent_identity,
    validate_candidate_blocked_retirement_raw_attachments,
    validate_candidate_checkpoint_gate_raw_attachments, validate_candidate_child_raw_attachments,
    validate_candidate_frontend_loss_raw_attachments,
    validate_candidate_guardian_loss_raw_attachments, validate_candidate_socket_raw_attachments,
    validate_candidate_terminal_raw_attachments, validate_candidate_uncertain_raw_attachments,
    verify_blocked_candidate_worker_exited, verify_candidate_socket_processes_exited,
    verify_candidate_terminal_processes_exited, verify_candidate_worker_exited,
    verify_checkpoint_gate_processes_exited, verify_child_runtime_processes_exited,
    verify_frontend_loss_processes_exited, verify_guardian_loss_processes_exited,
    verify_uncertain_candidate_worker_exited,
};
use crate::private_socket_live::{
    SOCKET_SELECTOR, join_sampled_gate_to_result, sample_and_ack_if_ready as sample_socket_gate,
};
use crate::private_supervisor::{
    SupervisedProcessV2, supervise_private_case_process,
    supervise_private_case_process_with_observer, verify_recorded_process_exited,
};
use crate::private_terminal_live::{
    TERMINAL_JOIN_SELECTOR, join_sampled_midpoint_to_result,
    sample_and_ack_if_ready as sample_terminal_midpoint,
};
use crate::private_unix_live::{
    UNIX_INTENT_SELECTOR, join_sampled_unix_to_result, sample_and_ack_if_ready as sample_unix_gate,
};
use crate::release_private::{
    PreparedPrivateCandidateV2, PrivateCandidateInputs, prepare_private_candidate,
    validate_private_candidate_record,
};
use crate::{CiError, Result};

const AGENT: &str = "/usr/libexec/memcordon-sealed-agent";

pub struct DownloadedCandidateV2 {
    pub prepared: PreparedPrivateCandidateV2,
    pub compiled_units: LinuxUnitHashesV6,
}

struct CandidateInstalledH0V1 {
    manifest_sha256: memcordon_core::DiagnosticSha256,
    inspection_sha256: memcordon_core::DiagnosticSha256,
    inspection_bytes: Vec<u8>,
    installation_epoch: memcordon_core::DiagnosticSha256,
    agent_bytes: Vec<u8>,
}

fn observe_installed_candidate_h0(
    root: &Path,
    downloaded: &DownloadedCandidateV2,
) -> Result<CandidateInstalledH0V1> {
    let installed = read_fixed_installed_h0()?;
    let output = CommandSpec::new(AGENT, root, Duration::from_secs(30))
        .remove_github_token()
        .args(["package", "verify", "--json"])
        .run()?;
    if output.is_empty() || output.len() > 128 * 1024 {
        return Err(CiError::Message(
            "private installed H0 inspection size differs".into(),
        ));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&output)
        .map_err(CiError::Message)?;
    let inspection: memcordon_core::package_inspection_v6::LinuxInstalledInspectionV6 =
        serde_json::from_slice(&output)?;
    let compact = serde_json::to_vec(&inspection)?;
    let inspection_sha256 = validate_installed_h0_static(
        &downloaded.prepared,
        &downloaded.compiled_units,
        &installed,
        &compact,
    )?;
    Ok(CandidateInstalledH0V1 {
        manifest_sha256: downloaded.prepared.manifest_sha256.clone(),
        inspection_sha256,
        inspection_bytes: compact,
        installation_epoch: read_fixed_installation_epoch()?,
        agent_bytes: installed.agent,
    })
}

/// Checks the direct CI child observation against the separately protected
/// service coordinator identity. This is process custody, not target exec.
pub fn validate_candidate_child_observation(
    observed: &SupervisedProcessV2,
    request: &ProtectedCandidateReleaseRequestV1,
) -> Result<()> {
    let child = observed.linux_child.ok_or_else(|| {
        CiError::Message("private candidate child identity was not observed".into())
    })?;
    if !observed.status.success()
        || !observed.stdout.is_empty()
        || !observed.stderr.is_empty()
        || child.pid == 0
        || child.start_time_ticks == 0
        || request.coordinator.pid == 0
        || request.coordinator.start_time == 0
        || child.pid == request.coordinator.pid
    {
        return Err(CiError::Message(
            "private candidate child/coordinator custody differs".into(),
        ));
    }
    Ok(())
}

fn read_candidate_member(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(CiError::Message(
            "private candidate downloaded member differs".into(),
        ));
    }
    Ok(fs::read(path)?)
}

/// Rebuild B/M0 from the exact target-specific downloaded native artifact.
/// Actions artifact ownership and job provenance are checked separately; a
/// local directory cannot by itself authenticate a native release run.
pub fn read_downloaded_candidate(
    root: &Path,
    target: &str,
    source_commit: &str,
) -> Result<DownloadedCandidateV2> {
    let asset = match target {
        "x86_64-unknown-linux-gnu" => "linux-x64",
        "aarch64-unknown-linux-gnu" => "linux-arm64",
        _ => return Err(CiError::Message("private candidate target differs".into())),
    };
    let directory = root
        .join("target/ci/release-inputs")
        .join(format!("release-native-{asset}"))
        .join(format!("private-candidate-{asset}"));
    let expected = [
        "runtime-manifest.json",
        "package-inspection-v6.json",
        "candidate-build-v2.json",
        "memcordon",
        "memcordon-sealed-agent",
    ];
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.file_type().is_dir() {
        return Err(CiError::Message(
            "private candidate download directory differs".into(),
        ));
    }
    let mut observed = std::collections::BTreeSet::new();
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let leaf = entry.file_name();
        let leaf = leaf
            .to_str()
            .ok_or_else(|| CiError::Message("private candidate leaf is not UTF-8".into()))?
            .to_owned();
        if !expected.contains(&leaf.as_str())
            || !entry.file_type()?.is_file()
            || !observed.insert(leaf)
        {
            return Err(CiError::Message(
                "private candidate download inventory differs".into(),
            ));
        }
    }
    if observed.len() != expected.len() {
        return Err(CiError::Message(
            "private candidate download omits required member".into(),
        ));
    }
    let manifest_bytes = read_candidate_member(&directory.join(expected[0]), 1024 * 1024)?;
    let manifest = RuntimeManifestV3::parse(&manifest_bytes).map_err(CiError::Message)?;
    let SealedRuntimeV3::WorkloadV2 {
        native_protocols,
        profile_catalog_sha256,
        ..
    } = &manifest.sealed
    else {
        return Err(CiError::Message(
            "private candidate M0 schema differs".into(),
        ));
    };
    if manifest.version != env!("CARGO_PKG_VERSION")
        || manifest.source_commit != source_commit
        || manifest.target != target
    {
        return Err(CiError::Message(
            "private candidate downloaded identity differs".into(),
        ));
    }
    let mut component_bytes = BTreeMap::new();
    for leaf in ["memcordon", "memcordon-sealed-agent"] {
        component_bytes.insert(
            leaf.to_owned(),
            read_candidate_member(&directory.join(leaf), 128 * 1024 * 1024)?,
        );
    }
    let inspection_bytes = read_candidate_member(&directory.join(expected[1]), 128 * 1024)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&inspection_bytes)
        .map_err(CiError::Message)?;
    let inspection: LinuxPackageInspectionV6 = serde_json::from_slice(&inspection_bytes)?;
    if inspection.version.as_str() != manifest.version
        || inspection.source_commit.as_str() != source_commit
        || inspection.target.as_str() != target
        || inspection.runtime_manifest_sha256 != hash_bytes(&manifest_bytes)
        || inspection.components != manifest.components
        || inspection.native_protocols != *native_protocols
        || inspection.profile_catalog_sha256 != *profile_catalog_sha256
        || !inspection.compiled_metadata_valid
    {
        return Err(CiError::Message(
            "private candidate downloaded V6 differs from B/M0".into(),
        ));
    }
    let prepared = prepare_private_candidate(PrivateCandidateInputs {
        version: &manifest.version,
        source_commit,
        target,
        components: &manifest.components,
        component_bytes: &component_bytes,
        compiled_units: &inspection.compiled_units,
        filter_sha256: &inspection.private_filter_sha256,
    })?;
    if prepared.manifest_bytes != manifest_bytes {
        return Err(CiError::Message(
            "private candidate downloaded M0 is not canonical B".into(),
        ));
    }
    let record = read_candidate_member(&directory.join(expected[2]), 16 * 1024)?;
    validate_private_candidate_record(&record, &prepared)?;
    Ok(DownloadedCandidateV2 {
        prepared,
        compiled_units: inspection.compiled_units,
    })
}

pub const REQUIRED_CASES: [&str; 25] = [
    "private_tcp::abi_alternate_entry_denied",
    "private_tcp::af_unix_abstract_and_pathname_denied",
    "private_tcp::af_unix_socketpair_denied",
    "private_tcp::authorization_uncertainty_retired",
    "private_tcp::caller_identity_and_epoch_bound",
    "private_tcp::checkpoint_persisted_before_release",
    "private_tcp::child_runtime_and_threads_retired",
    "private_tcp::descriptor_table_and_stdio_bound",
    "private_tcp::dual_attempt_namespace_isolation",
    "private_tcp::elf_ancestor_and_identity_pinned",
    "private_tcp::frontend_loss_retired",
    "private_tcp::guardian_loss_retired",
    "private_tcp::host_namespace_and_sysctl_unchanged",
    "private_tcp::io_uring_and_pidfd_import_denied",
    "private_tcp::namespace_reentry_denied",
    "private_tcp::native_filter_digest_and_abi_bound",
    "private_tcp::native_tcp_bind_listen_connect",
    "private_tcp::port_collision_same_namespace",
    "private_tcp::private_namespace_topology_exact",
    "private_tcp::release_checkpoint_terminal_joined",
    "private_tcp::retirement_failure_blocks_reuse",
    "private_tcp::scm_rights_and_precreated_socket_denied",
    "private_tcp::target_credentials_and_capabilities_dropped",
    "private_tcp::target_exec_and_fd_leak_observed",
    "private_tcp::wrong_grant_profile_and_port_rejected",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalogue {
    schema_version: u32,
    profile: String,
    targets: Vec<String>,
    tests: Vec<String>,
}

/// Checks both the checked-in policy and the compiled selector inventory.
/// This does not assert that those selectors have executable implementations.
pub fn validate_catalogue(bytes: &str) -> Result<()> {
    let catalogue: Catalogue = toml::from_str(bytes)?;
    if catalogue.schema_version != 1
        || catalogue.profile != "linux-tcp4-private-v1"
        || catalogue.targets != ["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"]
        || catalogue.tests.len() != REQUIRED_CASES.len()
        || catalogue
            .tests
            .iter()
            .map(String::as_str)
            .ne(REQUIRED_CASES)
    {
        return Err(CiError::Message(
            "private native catalogue differs from compiled required selectors".into(),
        ));
    }
    Ok(())
}

pub fn producer_for_host(
    stage: NativeRunStageV2,
    target: &str,
) -> Result<PrivateNativeProducerSpec> {
    validate_catalogue(include_str!("../../../ci/private-native-v2.toml"))?;
    let spec = PRODUCERS
        .into_iter()
        .find(|spec| spec.stage == stage && spec.target == target)
        .ok_or_else(|| CiError::Message("unsupported private native stage or target".into()))?;
    if !cfg!(target_os = "linux")
        || !cfg!(target_env = "gnu")
        || std::env::consts::ARCH != spec.native_machine
    {
        return Err(CiError::Message(
            "private native suite requires the exact native GNU Linux host".into(),
        ));
    }
    Ok(spec)
}

fn stage_argument(stage: NativeRunStageV2) -> &'static str {
    match stage {
        NativeRunStageV2::CandidateCapability => "candidate-capability",
        NativeRunStageV2::FinalPublic => "final-public",
    }
}

/// Matches the native fixed release-case leaf algorithm. This is a pathname
/// prediction only; it authenticates neither its contents nor its producer.
pub fn release_case_result_path(
    stage: NativeRunStageV2,
    selector: &str,
    challenge: [u8; 32],
) -> Result<PathBuf> {
    let stage = match stage {
        NativeRunStageV2::CandidateCapability => PrivateReleaseStageV1::CandidateCapability,
        NativeRunStageV2::FinalPublic => PrivateReleaseStageV1::FinalPublic,
    };
    let digest: String = private_release_case_key_v1(stage, selector, &challenge)
        .map_err(CiError::Message)?
        .into();
    Ok(Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(format!("{digest}.json")))
}

fn fresh_challenge() -> Result<[u8; 32]> {
    let mut challenge = [0_u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut challenge)?;
    if challenge == [0; 32] {
        return Err(CiError::Message("private release challenge is zero".into()));
    }
    Ok(challenge)
}

/// The CI process is the supervising parent for every fixed selector. An
/// exit code or target output never creates a completion: until the native
/// protected result schema/readback exists, every case remains incomplete.
pub fn validate_private_job_context(
    context: &CertificationContext,
    producer: &PrivateNativeProducerSpec,
) -> Result<()> {
    context.validate("backend-linux-private-v4")?;
    let provenance = context.provenance.as_ref().ok_or_else(|| {
        CiError::Message("private native suite requires hosted provenance".into())
    })?;
    let expected_arch = match producer.native_machine {
        "x86_64" => "X64",
        "aarch64" => "ARM64",
        _ => {
            return Err(CiError::Message(
                "private producer architecture differs".into(),
            ));
        }
    };
    if provenance.job != producer.job_id
        || provenance.runner_os != "Linux"
        || provenance.runner_arch != expected_arch
        || provenance.workflow_commit != context.source_commit
        || !provenance
            .workflow_ref
            .contains("/.github/workflows/release.yml@")
    {
        return Err(CiError::Message(
            "private native hosted job context differs".into(),
        ));
    }
    Ok(())
}

pub fn run(root: &Path, stage: NativeRunStageV2, target: &str) -> Result<()> {
    let producer = producer_for_host(stage, target)?;
    require_public_dispatch_evidence(stage)?;
    let context = CertificationContext::capture(root, "backend-linux-private-v4")?;
    validate_private_job_context(&context, &producer)?;
    let candidate_h0 = if stage == NativeRunStageV2::CandidateCapability {
        let token = std::env::var("GITHUB_TOKEN")
            .map_err(|_| CiError::Message("candidate Actions readback token absent".into()))?;
        crate::private_actions_readback::validate_running_candidate_actions(
            &context, producer, &token,
        )?;
        let downloaded = read_downloaded_candidate(root, target, &context.source_commit)?;
        let h0 = observe_installed_candidate_h0(root, &downloaded)?;
        Some((downloaded, h0))
    } else {
        None
    };
    let challenge = fresh_challenge()?;
    let mut structural_results = Vec::with_capacity(REQUIRED_CASES.len());
    for selector in REQUIRED_CASES {
        let image_before = if selector == "private_tcp::target_exec_and_fd_leak_observed"
            || selector == AGENT_PATH_SELECTOR
            || selector == TERMINAL_JOIN_SELECTOR
            || selector == DUAL_SELECTOR
        {
            let (_, h0) = candidate_h0.as_ref().ok_or_else(|| {
                CiError::Message("candidate installed agent identity is unavailable".into())
            })?;
            Some(read_fixed_agent_identity(&h0.agent_bytes)?)
        } else {
            None
        };
        let path_before = if selector == AGENT_PATH_SELECTOR {
            let (_, h0) = candidate_h0.as_ref().expect("candidate path requires H0");
            Some(AgentPathSnapshotV1::capture(&h0.agent_bytes)?)
        } else {
            None
        };
        let host_before = if selector == HOST_PRESERVATION_SELECTOR {
            Some(HostNetworkStateV1::capture()?)
        } else {
            None
        };
        let result_path = release_case_result_path(stage, selector, challenge)?;
        match std::fs::symlink_metadata(&result_path) {
            Ok(_) => {
                return Err(CiError::Message(
                    "private release result path already exists".into(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let arguments = [
            OsString::from("package"),
            OsString::from("release-case"),
            OsString::from("--stage"),
            OsString::from(stage_argument(stage)),
            OsString::from("--selector"),
            OsString::from(selector),
            OsString::from("--challenge"),
            OsString::from(hex::encode(challenge)),
        ];
        let (observed, child_live, socket_live, terminal_live, dual_live, unix_live) = if selector
            == CHILD_RUNTIME_SELECTOR
        {
            let (process, sampled) = supervise_private_case_process_with_observer(
                Path::new(AGENT),
                &arguments,
                Duration::from_secs(120),
                || sample_and_ack_if_ready(challenge),
            )?;
            (process, sampled, None, None, None, None)
        } else if selector == SOCKET_SELECTOR {
            let (downloaded, _) = candidate_h0.as_ref().ok_or_else(|| {
                CiError::Message("SCM installed candidate B/M0/H0 is unavailable".into())
            })?;
            let filter = downloaded.prepared.filter_sha256.clone();
            let (process, sampled) = supervise_private_case_process_with_observer(
                Path::new(AGENT),
                &arguments,
                Duration::from_secs(120),
                || sample_socket_gate(challenge, &filter),
            )?;
            (process, None, sampled, None, None, None)
        } else if selector == TERMINAL_JOIN_SELECTOR {
            let (downloaded, _) = candidate_h0.as_ref().ok_or_else(|| {
                CiError::Message("terminal installed candidate B/M0/H0 is unavailable".into())
            })?;
            let image = image_before.ok_or_else(|| {
                CiError::Message("terminal installed image identity absent".into())
            })?;
            let filter = downloaded.prepared.filter_sha256.clone();
            let (process, sampled) = supervise_private_case_process_with_observer(
                Path::new(AGENT),
                &arguments,
                Duration::from_secs(120),
                || sample_terminal_midpoint(challenge, &filter, image),
            )?;
            (process, None, None, sampled, None, None)
        } else if selector == DUAL_SELECTOR {
            let (downloaded, _) = candidate_h0.as_ref().ok_or_else(|| {
                CiError::Message("dual installed candidate B/M0/H0 is unavailable".into())
            })?;
            let image = image_before
                .ok_or_else(|| CiError::Message("dual installed image identity absent".into()))?;
            let filter = downloaded.prepared.filter_sha256.clone();
            let (process, sampled) = supervise_private_case_process_with_observer(
                Path::new(AGENT),
                &arguments,
                Duration::from_secs(120),
                || sample_dual_gate(challenge, &filter, image),
            )?;
            (process, None, None, None, sampled, None)
        } else if selector == UNIX_INTENT_SELECTOR {
            let (process, sampled) = supervise_private_case_process_with_observer(
                Path::new(AGENT),
                &arguments,
                Duration::from_secs(120),
                || sample_unix_gate(challenge),
            )?;
            (process, None, None, None, None, sampled)
        } else {
            (
                supervise_private_case_process(
                    Path::new(AGENT),
                    &arguments,
                    Duration::from_secs(120),
                )?,
                None,
                None,
                None,
                None,
                None,
            )
        };
        let image_after = if image_before.is_some() {
            let (_, h0) = candidate_h0.as_ref().expect("candidate image was required");
            Some(read_fixed_agent_identity(&h0.agent_bytes)?)
        } else {
            None
        };
        if image_before != image_after {
            return Err(CiError::Message(
                "candidate installed image changed during native case".into(),
            ));
        }
        let path_after = if path_before.is_some() {
            let (_, h0) = candidate_h0.as_ref().expect("candidate path requires H0");
            Some(AgentPathSnapshotV1::capture(&h0.agent_bytes)?)
        } else {
            None
        };
        if path_before != path_after {
            return Err(CiError::Message(
                "candidate agent ancestor changed during native case".into(),
            ));
        }
        let host_after = if host_before.is_some() {
            Some(HostNetworkStateV1::capture()?)
        } else {
            None
        };
        if observed.linux_child.is_none() {
            return Err(CiError::Message(
                "private native child kernel identity was not observed".into(),
            ));
        }
        if !observed.status.success() {
            let stdout_digest: String = hash_bytes(&observed.stdout).into();
            let stderr_digest: String = hash_bytes(&observed.stderr).into();
            return Err(CiError::Message(format!(
                "private native {stage:?} selector {selector} has no completed physical result; child status {:?}, stdout {stdout_digest}, stderr {stderr_digest}",
                observed.status.code()
            )));
        }
        let structural = read_structural_protected_native_case(stage, target, selector, challenge)?;
        let observer = structural.attachments.get(3).ok_or_else(|| {
            CiError::Message("protected native observer attachment absent".into())
        })?;
        validate_host_preservation_observer(
            selector,
            observer,
            host_before.as_ref(),
            host_after.as_ref(),
        )?;
        let path_current = if path_before.is_some() {
            let (_, h0) = candidate_h0.as_ref().expect("candidate path requires H0");
            Some(AgentPathSnapshotV1::capture(&h0.agent_bytes)?)
        } else {
            None
        };
        validate_agent_path_observer(
            selector,
            observer,
            path_before.as_ref(),
            path_after.as_ref(),
            path_current.as_ref(),
        )?;
        if let Some((downloaded, h0)) = &candidate_h0 {
            validate_candidate_child_observation(&observed, &structural.candidate_request)?;
            let child = observed.linux_child.expect("candidate child was validated");
            verify_recorded_process_exited(child)?;
            verify_recorded_process_exited(crate::private_supervisor::LinuxChildIdentityV1 {
                pid: structural.candidate_request.coordinator.pid,
                start_time_ticks: structural.candidate_request.coordinator.start_time,
            })?;
            let fresh_installed = read_fixed_installed_h0()?;
            if validate_installed_h0_static(
                &downloaded.prepared,
                &downloaded.compiled_units,
                &fresh_installed,
                &h0.inspection_bytes,
            )? != h0.inspection_sha256
            {
                return Err(CiError::Message(
                    "private candidate installed B/M0/H0 changed during case".into(),
                ));
            }
            let PrivateReleaseInstalledBindingV1::CandidateCapability {
                installation_epoch,
                candidate_manifest_sha256,
                installed_inspection_sha256,
            } = &structural.result.installed
            else {
                return Err(CiError::Message(
                    "candidate result lacks installed H0 binding".into(),
                ));
            };
            if installation_epoch != &h0.installation_epoch
                || candidate_manifest_sha256 != &h0.manifest_sha256
                || installed_inspection_sha256 != &h0.inspection_sha256
                || structural.candidate_request.candidate_manifest_sha256 != h0.manifest_sha256
                || read_fixed_installation_epoch()? != h0.installation_epoch
                || structural.result.native_machine != producer.native_machine
            {
                return Err(CiError::Message(
                    "candidate result differs from independently installed B/M0/H0".into(),
                ));
            }
            join_installed_epoch_to_candidate_request(
                &structural.candidate_request,
                &h0.installation_epoch,
            )?;
            if let Some(attempt) = &structural.attempt_record
                && attempt.checkpoint_filter_sha256() != Some(&downloaded.prepared.filter_sha256)
            {
                return Err(CiError::Message(
                    "private candidate native checkpoint filter differs from independent B".into(),
                ));
            }
            if selector == DUAL_SELECTOR {
                let sampled = dual_live.as_ref().ok_or_else(|| {
                    CiError::Message("independent dual live sample absent".into())
                })?;
                join_sampled_dual_to_result(
                    &structural,
                    sampled,
                    challenge,
                    &downloaded.prepared.filter_sha256,
                    &h0.inspection_sha256,
                )?;
            } else if matches!(
                structural.result.observation,
                memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::AllocatedRetired { .. }
            ) {
                if selector == "private_tcp::authorization_uncertainty_retired" {
                    validate_candidate_uncertain_raw_attachments(
                        &structural,
                        challenge,
                        &h0.inspection_sha256,
                    )?;
                    verify_uncertain_candidate_worker_exited(&structural)?;
                } else if selector == "private_tcp::guardian_loss_retired" {
                    validate_candidate_guardian_loss_raw_attachments(
                        &structural,
                        challenge,
                        &h0.inspection_sha256,
                    )?;
                    verify_guardian_loss_processes_exited(&structural)?;
                } else if selector == "private_tcp::frontend_loss_retired" {
                    validate_candidate_frontend_loss_raw_attachments(
                        &structural,
                        challenge,
                        &h0.inspection_sha256,
                    )?;
                    verify_frontend_loss_processes_exited(&structural)?;
                } else if selector == "private_tcp::checkpoint_persisted_before_release" {
                    validate_candidate_checkpoint_gate_raw_attachments(
                        &structural,
                        challenge,
                        &h0.inspection_sha256,
                    )?;
                    verify_checkpoint_gate_processes_exited(&structural)?;
                } else if selector == UNIX_INTENT_SELECTOR {
                    let sampled = unix_live.as_ref().ok_or_else(|| {
                        CiError::Message("independent Unix live sample absent".into())
                    })?;
                    validate_candidate_allocated_raw_attachments_with_agent_identity(
                        &structural,
                        challenge,
                        &h0.inspection_sha256,
                        image_after,
                    )?;
                    join_sampled_unix_to_result(&structural, sampled, challenge)?;
                    verify_candidate_worker_exited(&structural)?;
                } else if selector == CHILD_RUNTIME_SELECTOR {
                    let sampled = child_live.as_ref().ok_or_else(|| {
                        CiError::Message("independent child live sample absent".into())
                    })?;
                    validate_candidate_child_raw_attachments(
                        &structural,
                        challenge,
                        &h0.inspection_sha256,
                    )?;
                    join_live_sample_to_result(&structural, sampled)?;
                    verify_child_runtime_processes_exited(&structural)?;
                } else if selector == SOCKET_SELECTOR {
                    let sampled = socket_live.as_ref().ok_or_else(|| {
                        CiError::Message("independent SCM socket sample absent".into())
                    })?;
                    validate_candidate_socket_raw_attachments(
                        &structural,
                        challenge,
                        &h0.inspection_sha256,
                    )?;
                    join_sampled_gate_to_result(
                        &structural,
                        sampled,
                        challenge,
                        &downloaded.prepared.filter_sha256,
                    )?;
                    verify_candidate_socket_processes_exited(&structural)?;
                } else if selector == TERMINAL_JOIN_SELECTOR {
                    let sampled = terminal_live.as_ref().ok_or_else(|| {
                        CiError::Message("independent terminal midpoint sample absent".into())
                    })?;
                    let midpoint = join_sampled_midpoint_to_result(
                        &structural,
                        sampled,
                        challenge,
                        &downloaded.prepared.filter_sha256,
                    )?;
                    validate_candidate_terminal_raw_attachments(
                        &structural,
                        challenge,
                        &h0.inspection_sha256,
                        &midpoint,
                        &sampled.gate_sha256,
                        &sampled.target_pid_chain,
                    )?;
                    verify_candidate_terminal_processes_exited(&structural)?;
                } else {
                    validate_candidate_allocated_raw_attachments_with_agent_identity(
                        &structural,
                        challenge,
                        &h0.inspection_sha256,
                        image_after,
                    )?;
                    verify_candidate_worker_exited(&structural)?;
                }
            } else if matches!(
                structural.result.observation,
                memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::RetirementFailureBlockedReuse { .. }
            ) {
                validate_candidate_blocked_retirement_raw_attachments(
                    &structural,
                    challenge,
                    &h0.inspection_sha256,
                )?;
                verify_blocked_candidate_worker_exited(&structural)?;
            }
        }
        structural_results.push(structural);
    }
    Err(CiError::Message(format!(
        "private native {stage:?} suite structurally read {} protected results but lacks independent supervisor semantics and hosted provenance; no Q or P was produced",
        structural_results.len()
    )))
}

/// Root-only release-case fixtures cannot prove the installed public V2
/// plan/grant/launch path. Keep this stage closed until that separate
/// dispatcher and its A/M1/Q/H1 evidence joins are implemented.
pub fn require_public_dispatch_evidence(stage: NativeRunStageV2) -> Result<()> {
    if stage == NativeRunStageV2::FinalPublic {
        return Err(CiError::Message(
            "final-public requires installed public V2 plan/grant/launch evidence; root release-case fixtures are not public proof".into(),
        ));
    }
    Ok(())
}
