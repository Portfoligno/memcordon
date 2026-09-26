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
use memcordon_core::{BoundedText, DiagnosticSha256};
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
    pub build_sha256: DiagnosticSha256,
}

struct CandidateInstalledH0V1 {
    manifest_sha256: memcordon_core::DiagnosticSha256,
    inspection_sha256: memcordon_core::DiagnosticSha256,
    inspection_bytes: Vec<u8>,
    installation_epoch: memcordon_core::DiagnosticSha256,
    agent_bytes: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalEpochReplayReadbackV1 {
    schema_version: u8,
    selector: String,
    result_key: memcordon_core::DiagnosticSha256,
    original_request_sha256: memcordon_core::DiagnosticSha256,
    e0_installation_epoch_sha256: memcordon_core::DiagnosticSha256,
    e1_installation_epoch_sha256: memcordon_core::DiagnosticSha256,
    mismatch: String,
}

/// Runs the historical-generation control outside every case's package lease.
/// This is only a physical sequence/readback; the Q verifier must separately
/// supply a loss-free allocation interval around replay and detached raw joins.
fn run_candidate_epoch_choreography(
    root: &Path,
    target: &str,
    downloaded: &DownloadedCandidateV2,
    e0: &CandidateInstalledH0V1,
) -> Result<CandidateInstalledH0V1> {
    const CONTROL: &str = "private_tcp::native_tcp_bind_listen_connect";
    let target_id = match target {
        "x86_64-unknown-linux-gnu" => "linux-x64",
        "aarch64-unknown-linux-gnu" => "linux-arm64",
        _ => return Err(CiError::Message("historical epoch target differs".into())),
    };
    let run_control = |challenge: [u8; 32]| -> Result<
        crate::private_protected_readback::StructuralProtectedNativeCaseV1,
    > {
        let result_path =
            release_case_result_path(NativeRunStageV2::CandidateCapability, CONTROL, challenge)?;
        match std::fs::symlink_metadata(&result_path) {
            Ok(_) => {
                return Err(CiError::Message(
                    "historical control case key already exists".into(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let args = [
            OsString::from("package"),
            OsString::from("release-case"),
            OsString::from("--stage"),
            OsString::from("candidate-capability"),
            OsString::from("--selector"),
            OsString::from(CONTROL),
            OsString::from("--challenge"),
            OsString::from(hex::encode(challenge)),
        ];
        let process =
            supervise_private_case_process(Path::new(AGENT), &args, Duration::from_secs(120))?;
        if !process.status.success() {
            return Err(CiError::Message(
                "historical TCP control did not complete".into(),
            ));
        }
        let structural = read_structural_protected_native_case(
            NativeRunStageV2::CandidateCapability,
            target,
            CONTROL,
            challenge,
        )?;
        verify_candidate_worker_exited(&structural)?;
        Ok(structural)
    };
    let e0_challenge = fresh_challenge()?;
    let accepted_e0 = run_control(e0_challenge)?;
    let PrivateReleaseInstalledBindingV1::CandidateCapability {
        installation_epoch: e0_recorded_epoch,
        candidate_manifest_sha256: e0_manifest,
        installed_inspection_sha256: e0_inspection,
    } = &accepted_e0.result.installed
    else {
        return Err(CiError::Message(
            "historical E0 control lacks H0 binding".into(),
        ));
    };
    if *e0_recorded_epoch != e0.installation_epoch
        || *e0_manifest != e0.manifest_sha256
        || *e0_inspection != e0.inspection_sha256
        || read_fixed_installation_epoch()? != e0.installation_epoch
    {
        return Err(CiError::Message(
            "historical E0 control differs from installed H0".into(),
        ));
    }
    // This invocation ends before the exclusive upgrade. The source is the
    // exact downloaded B already checked by read_downloaded_candidate.
    let source = root
        .join("target/ci/release-inputs")
        .join(format!("release-native-{target_id}"))
        .join(format!("private-candidate-{target_id}"))
        .join("memcordon-sealed-agent");
    CommandSpec::new(&source, root, Duration::from_secs(180))
        .remove_github_token()
        .args(["package", "upgrade", "--ephemeral-ci"])
        .run()?;
    let e1 = observe_installed_candidate_h0(root, downloaded)?;
    if e1.installation_epoch == e0.installation_epoch
        || e1.manifest_sha256 != e0.manifest_sha256
        || e1.agent_bytes != e0.agent_bytes
    {
        return Err(CiError::Message(
            "historical E1 did not advance byte-identical B".into(),
        ));
    }
    let replay = CommandSpec::new(AGENT, root, Duration::from_secs(30))
        .remove_github_token()
        .args([
            "package",
            "release-case-epoch-replay",
            "--stage",
            "candidate-capability",
            "--selector",
            CONTROL,
            "--challenge",
            &hex::encode(e0_challenge),
        ])
        .run()?;
    if replay.len() > 16 * 1024 {
        return Err(CiError::Message(
            "historical E1 replay readback exceeds bound".into(),
        ));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&replay)
        .map_err(CiError::Message)?;
    let replay: HistoricalEpochReplayReadbackV1 = serde_json::from_slice(&replay)?;
    if replay.schema_version != 1
        || replay.selector != CONTROL
        || replay.result_key != accepted_e0.result.result_key().map_err(CiError::Message)?
        || replay.original_request_sha256 != hash_bytes(&accepted_e0.candidate_request_bytes)
        || replay.e0_installation_epoch_sha256 != e0.installation_epoch
        || replay.e1_installation_epoch_sha256 != e1.installation_epoch
        || replay.mismatch != "installation-epoch"
        || read_fixed_installation_epoch()? != e1.installation_epoch
    {
        return Err(CiError::Message(
            "historical E1 replay mismatch differs".into(),
        ));
    }
    let fresh_e1 = run_control(fresh_challenge()?)?;
    let PrivateReleaseInstalledBindingV1::CandidateCapability {
        installation_epoch: fresh_epoch,
        candidate_manifest_sha256: fresh_manifest,
        installed_inspection_sha256: fresh_inspection,
    } = fresh_e1.result.installed
    else {
        return Err(CiError::Message(
            "historical E1 control lacks H0 binding".into(),
        ));
    };
    if fresh_epoch != e1.installation_epoch
        || fresh_manifest != e1.manifest_sha256
        || fresh_inspection != e1.inspection_sha256
    {
        return Err(CiError::Message(
            "fresh E1 control differs from renewed H0".into(),
        ));
    }
    Ok(e1)
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
    let mut expected = vec![
        "runtime-manifest.json",
        "package-inspection-v6.json",
        "candidate-build-v2.json",
        "memcordon",
        "memcordon-sealed-agent",
    ];
    if target == "aarch64-unknown-linux-gnu" {
        expected.push("memcordon-arm32-abi-helper");
    }
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
    for leaf in ["memcordon", "memcordon-sealed-agent"]
        .into_iter()
        .chain((target == "aarch64-unknown-linux-gnu").then_some("memcordon-arm32-abi-helper"))
    {
        component_bytes.insert(
            leaf.to_owned(),
            read_candidate_member(&directory.join(leaf), 128 * 1024 * 1024)?,
        );
    }
    if target == "aarch64-unknown-linux-gnu"
        && component_bytes.get("memcordon-arm32-abi-helper")
            != Some(&crate::arm32_abi_helper::static_aarch32_helper())
    {
        return Err(CiError::Message(
            "private candidate ARM32 helper differs from reviewed image".into(),
        ));
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
        build_sha256: hash_bytes(&record),
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

pub fn parse_collector_intent_digest(value: &str) -> Result<DiagnosticSha256> {
    let bounded = BoundedText::<64>::new(value).map_err(|error| CiError::Message(error.into()))?;
    let digest =
        DiagnosticSha256::try_from(bounded).map_err(|error| CiError::Message(error.into()))?;
    if digest == DiagnosticSha256::from_bytes([0; 32]) || digest == hash_bytes(&[]) {
        return Err(CiError::Message(
            "collector intent digest has no authority binding".into(),
        ));
    }
    Ok(digest)
}

/// Execute the five physical policy branches under separately armed kernel
/// intervals. The returned bytes are evidence inputs, not a Q capability.
fn run_candidate_policy_branches(
    root: &Path,
    fixture: &crate::private_policy_provision::ProvisionedPolicyFixtureV1,
    h0: &CandidateInstalledH0V1,
    target: &str,
    native_machine: &str,
) -> Result<crate::private_candidate_c_v3::CandidateCaseBytesV3> {
    use crate::private_kernel_observer::{
        ExpectedKernelAdapterV1, InstalledObserverRoleV1,
        activate_installed_network_broker_for_observation, observe_installed_observer_subject,
        observe_live_kernel_subject,
    };
    use crate::private_probe_bundle::{ExpectedProbeBundleV1, verify_probe_bundle};
    use memcordon_core::private_release_branch_v1::{
        PolicyBranchOutcomeV1, PolicyBranchV1, PolicyFourBranchTranscriptV1,
        PolicyOperationBranchV1, PolicyOperationOutcomeV1, ProtectedPolicyBranchRawV1,
        RejectedPolicyBranchV1, policy_branch_challenge_v1,
    };

    let pinned = fixture.observer();
    let probe = verify_probe_bundle(ExpectedProbeBundleV1 {
        bpf_source_sha256: pinned.bpf_source_sha256.clone(),
        loader_source_sha256: pinned.loader_source_sha256.clone(),
        object_sha256: pinned.object_sha256.clone(),
        loader_sha256: pinned.loader_sha256.clone(),
        agent_sha256: pinned.agent_sha256.clone(),
        agent_build_id: pinned.agent_build_id.clone(),
        request_entry_offset: pinned.request_entry_offset,
        request_exit_offset: pinned.request_exit_offset,
        allocation_entry_offset: pinned.allocation_entry_offset,
    })?;
    let reader = observe_live_kernel_subject(std::process::id())?;
    let service = observe_installed_observer_subject(InstalledObserverRoleV1::SealedService)?;
    let broker = activate_installed_network_broker_for_observation()?;
    let expected =
        |key: DiagnosticSha256,
         primary: crate::private_kernel_observer::LiveKernelSubjectV1,
         secondary: crate::private_kernel_observer::LiveKernelSubjectV1| {
            ExpectedKernelAdapterV1 {
                boot_id: pinned.boot_id.clone(),
                kernel_release: pinned.kernel_release.clone(),
                btf_sha256: pinned.btf_sha256.clone(),
                probe_map_sha256: probe.attestation_digest(),
                result_key: key,
                coordinator_pid: primary.pid,
                coordinator_start_time: 0,
                coordinator_start_ticks: primary.start_ticks,
                cgroup_inode: primary.cgroup_inode,
                broker_pid: secondary.pid,
                broker_start_ticks: secondary.start_ticks,
                broker_cgroup_inode: secondary.cgroup_inode,
            }
        };
    let controls = crate::private_probe_controls::run_fixed_known_action_controls(
        &probe,
        expected(pinned.control_result_key.clone(), reader, service),
    )?;
    let mut keys = Vec::with_capacity(5);
    let mut expected_intervals = Vec::with_capacity(5);
    for branch in PolicyOperationBranchV1::ALL {
        let challenge = policy_branch_challenge_v1(fixture.base_challenge(), branch)
            .map_err(|error| CiError::Message(error.into()))?;
        let key = private_release_case_key_v1(
            PrivateReleaseStageV1::CandidateCapability,
            "private_tcp::wrong_grant_profile_and_port_rejected",
            &challenge,
        )
        .map_err(CiError::Message)?;
        expected_intervals.push(expected(key.clone(), service, broker));
        keys.push(key);
    }
    let expected_intervals: [ExpectedKernelAdapterV1; 5] = expected_intervals
        .try_into()
        .map_err(|_| CiError::Message("policy branch interval count differs".into()))?;
    let base_hex = hex::encode(fixture.base_challenge());
    let mut supervised = Vec::with_capacity(5);
    let intervals = crate::private_policy_intervals::run_policy_intervals(
        &probe,
        controls.controls(),
        expected_intervals,
        |branch| {
            let output = CommandSpec::new(AGENT, root, Duration::from_secs(120))
                .remove_github_token()
                .args([
                    "package",
                    "release-case-policy-branches",
                    "--challenge",
                    base_hex.as_str(),
                    "--branch",
                    branch.as_str(),
                ])
                .run()?;
            supervised.push(output);
            Ok(())
        },
    )?;
    let mut raws = Vec::with_capacity(5);
    let mut raw_bytes = Vec::with_capacity(5);
    let mut request_bytes = Vec::with_capacity(5);
    let mut service_generation = None;
    let clock = crate::private_process_clock::VerifiedProcClockCalibrationV1::observe_live_reader(
        reader.pid,
        reader.start_ticks,
    )?;
    for (index, branch) in PolicyOperationBranchV1::ALL.into_iter().enumerate() {
        let key = &keys[index];
        let raw_path = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1)
            .join(String::from(key.clone()))
            .join("policy-branches.raw.json");
        let case_directory = raw_path.parent().expect("fixed policy raw has parent");
        let request = crate::private_protected_readback::read_protected_raw_case_file(
            &case_directory.join("request.json"),
        )?;
        memcordon_core::workload_contract::reject_duplicate_json_keys(&request)
            .map_err(CiError::Message)?;
        let protected: ProtectedCandidateReleaseRequestV1 = serde_json::from_slice(&request)?;
        if serde_json::to_vec(&protected)? != request {
            return Err(CiError::Message(
                "policy protected request encoding is not canonical".into(),
            ));
        }
        let derived = policy_branch_challenge_v1(fixture.base_challenge(), branch)
            .map_err(|error| CiError::Message(error.into()))?;
        let interval = if index == 0 {
            intervals.positive()
        } else {
            &intervals.rejected()[index - 1]
        };
        crate::private_policy_request_join::join_policy_decision_request(
            root,
            &request,
            &protected,
            interval,
            &clock,
            &service,
            &h0.manifest_sha256,
            &h0.installation_epoch,
            &derived,
            key,
        )?;
        if protected.schema_version != 1
            || protected.stage != "candidate-capability"
            || protected.selector != "private_tcp::wrong_grant_profile_and_port_rejected"
            || protected.challenge != hex::encode(derived)
            || protected.result_key != *key
            || protected.installation_epoch != h0.installation_epoch
            || protected.candidate_manifest_sha256 != h0.manifest_sha256
            || protected.service_generation_sha256 == DiagnosticSha256::from_bytes([0; 32])
            || protected.coordinator.pid == 0
            || protected.coordinator.start_time == 0
            || service_generation
                .as_ref()
                .is_some_and(|value| value != &protected.service_generation_sha256)
        {
            return Err(CiError::Message(
                "policy protected request differs from derived branch/H0".into(),
            ));
        }
        service_generation = Some(protected.service_generation_sha256.clone());
        verify_recorded_process_exited(crate::private_supervisor::LinuxChildIdentityV1 {
            pid: protected.coordinator.pid,
            start_time_ticks: protected.coordinator.start_time,
        })?;
        for forbidden in ["attempt.json", "attempt.json.new", "result.json"] {
            if !matches!(std::fs::symlink_metadata(case_directory.join(forbidden)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound)
            {
                return Err(CiError::Message(
                    "policy decision-only branch created native attempt/result".into(),
                ));
            }
        }
        let bytes = crate::private_protected_readback::read_protected_raw_case_file(&raw_path)?;
        let raw = ProtectedPolicyBranchRawV1::parse(&bytes, fixture.base_challenge())
            .map_err(CiError::Message)?;
        if raw.branch != branch
            || &raw.result_key != key
            || raw.fixture_sha256 != *fixture.fixture_sha256()
            || raw.reviewed_topology_sha256 != *fixture.reviewed_topology_sha256()
            || raw.installed_inspection_sha256 != h0.inspection_sha256
            || raw.installation_epoch_sha256 != h0.installation_epoch
            || raw.registry_sha256 != *fixture.registry_sha256()
            || raw.authenticated_caller_uid != fixture.authenticated_caller_uid()
            || raw.authenticated_caller_sha256 != *fixture.authenticated_caller_sha256()
            || raw.accepted_request_sha256 != *fixture.accepted_request_sha256()
            || raw.changed_request_sha256 != *fixture.changed_request_sha256()
            || raw.committed_tamper_request_sha256 != *fixture.committed_tamper_request_sha256()
            || intervals.positive().result_key() != &keys[0]
        {
            return Err(CiError::Message(
                "policy protected branch differs from independent intent/H0".into(),
            ));
        }
        raws.push(raw);
        raw_bytes.push(bytes);
        request_bytes.push(request);
    }
    if raws.len() != supervised.len() || intervals.rejected().len() != 4 {
        return Err(CiError::Message(
            "policy five-branch supervisor inventory differs".into(),
        ));
    }
    let rejected = std::array::from_fn(|index| {
        let raw = &raws[index + 1];
        let outcome = match raw.outcome {
            PolicyOperationOutcomeV1::Admission(code) => PolicyBranchOutcomeV1::Admission(code),
            PolicyOperationOutcomeV1::FrozenBindingMismatch => {
                PolicyBranchOutcomeV1::FrozenBindingMismatch
            }
            PolicyOperationOutcomeV1::AcceptedControl => {
                unreachable!("negative policy branch accepted")
            }
        };
        RejectedPolicyBranchV1 {
            branch: match index {
                0 => PolicyBranchV1::WrongGrant,
                1 => PolicyBranchV1::WrongProfile,
                2 => PolicyBranchV1::UnapprovedChangedPortPlan,
                _ => PolicyBranchV1::CommittedPortTamper,
            },
            exact_request_sha256: raw.exact_branch_request_sha256.clone(),
            exact_registry_sha256: raw.registry_sha256.clone(),
            authenticated_caller_sha256: raw.authenticated_caller_sha256.clone(),
            outcome,
            independent_interval_sha256: intervals.rejected()[index].trace_sha256().clone(),
        }
    });
    let transcript = PolicyFourBranchTranscriptV1 {
        schema_version: 1,
        challenge_sha256: hash_bytes(fixture.base_challenge()),
        accepted_control_request_sha256: fixture.accepted_request_sha256().clone(),
        accepted_control_registry_sha256: fixture.registry_sha256().clone(),
        authenticated_caller_sha256: fixture.authenticated_caller_sha256().clone(),
        rejected,
    };
    crate::private_policy_semantics::join_policy_kernel_intervals(
        &transcript,
        &hash_bytes(fixture.base_challenge()),
        fixture.accepted_request_sha256(),
        fixture.registry_sha256(),
        fixture.authenticated_caller_sha256(),
        &keys[0],
        keys[1..]
            .try_into()
            .map_err(|_| CiError::Message("policy negative key count differs".into()))?,
        &intervals.all_no_allocation()[0],
        [
            &intervals.all_no_allocation()[1],
            &intervals.all_no_allocation()[2],
            &intervals.all_no_allocation()[3],
            &intervals.all_no_allocation()[4],
        ],
    )?;
    let transcript_bytes = serde_json::to_vec(&transcript)?;
    let intent_bytes = crate::private_protected_readback::read_protected_raw_case_file(Path::new(
        "/var/lib/memcordon/sealed/private-release-policy-intent-v1.json",
    ))?;
    if hash_bytes(&intent_bytes) != *fixture.intent_sha256() {
        return Err(CiError::Message(
            "policy aggregate release-intent bytes differ".into(),
        ));
    }
    let captures = std::iter::once(intervals.positive())
        .chain(intervals.rejected().iter())
        .map(|interval| interval.capture_bytes().map(ToOwned::to_owned))
        .collect::<Result<Vec<_>>>()?;
    let interval_inventory = serde_json::to_vec(
        &PolicyOperationBranchV1::ALL
            .iter()
            .enumerate()
            .map(|(index, branch)| {
                serde_json::json!({
                    "branch": branch.as_str(),
                    "result_key": keys[index],
                    "capture_sha256": hash_bytes(&captures[index]),
                    "capture_size": captures[index].len(),
                })
            })
            .collect::<Vec<_>>(),
    )?;
    let raw_inventory = serde_json::to_vec(
        &raw_bytes
            .iter()
            .map(|bytes| hash_bytes(bytes))
            .collect::<Vec<_>>(),
    )?;
    let attachments = [
        intent_bytes.clone(),
        transcript_bytes.clone(),
        serde_json::to_vec(&supervised)?,
        interval_inventory.clone(),
        raw_inventory,
    ];
    let result = memcordon_core::private_release_case_v1::PrivateReleaseCaseResultV1 {
        schema_version: 1,
        selector: "private_tcp::wrong_grant_profile_and_port_rejected".into(),
        challenge: hex::encode(fixture.base_challenge()),
        target: target.into(),
        native_machine: native_machine.into(),
        installed: PrivateReleaseInstalledBindingV1::CandidateCapability {
            installation_epoch: h0.installation_epoch.clone(),
            candidate_manifest_sha256: h0.manifest_sha256.clone(),
            installed_inspection_sha256: h0.inspection_sha256.clone(),
        },
        observation:
            memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::PolicyComposite {
                accepted_decision_sha256: hash_bytes(&raw_bytes[0]),
                branch_transcript_sha256: hash_bytes(&transcript_bytes),
                independent_interval_inventory_sha256: hash_bytes(&interval_inventory),
                native_observer_sha256: hash_bytes(&attachments[3]),
            },
        attachments: memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL
            .into_iter()
            .zip(attachments.iter())
            .map(|(role, bytes)| {
                memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1 {
                    role,
                    size: bytes.len() as u64,
                    sha256: hash_bytes(bytes),
                }
            })
            .collect(),
    };
    result.validate().map_err(CiError::Message)?;
    let mut family_raw = BTreeMap::new();
    family_raw.insert("policy-intent.v1.json".into(), intent_bytes);
    family_raw.insert("policy-branches.raw.json".into(), transcript_bytes);
    for (index, branch) in PolicyOperationBranchV1::ALL.iter().enumerate() {
        family_raw.insert(
            format!("{}.request.json", branch.as_str()),
            request_bytes[index].clone(),
        );
        family_raw.insert(
            format!("{}.raw.json", branch.as_str()),
            raw_bytes[index].clone(),
        );
        family_raw.insert(
            format!("{}.kernel.capture.bin", branch.as_str()),
            captures[index].clone(),
        );
    }
    Ok(crate::private_candidate_c_v3::CandidateCaseBytesV3 {
        result: serde_json::to_vec(&result)?,
        attachments,
        kernel_capture: captures[0].clone(),
        family_raw,
    })
}

/// The raw-only ABI command has no producer-signed `result.json`. CI composes
/// the case only after the positive lifecycle and every ABI child join one
/// loss-free kernel interval.

#[cfg(target_os = "linux")]
fn installed_arm_helper_identity() -> Result<(u64, u64)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let path = Path::new("/usr/libexec/memcordon-arm32-abi-helper");
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.uid() != 0 || before.mode() & 0o022 != 0 || before.nlink() != 1 {
        return Err(CiError::Message(
            "installed ARM32 helper identity differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    (&mut file).take(1024 * 1024).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != bytes.len() as u64
        || hash_bytes(&bytes) != hash_bytes(&crate::arm32_abi_helper::static_aarch32_helper())
    {
        return Err(CiError::Message(
            "installed ARM32 helper differs from reviewed B".into(),
        ));
    }
    Ok((before.dev(), before.ino()))
}

#[cfg(not(target_os = "linux"))]
fn installed_arm_helper_identity() -> Result<(u64, u64)> {
    Err(CiError::Message(
        "ARM32 ABI helper identity requires Linux".into(),
    ))
}

fn run_candidate_abi_subwitness(
    root: &Path,
    fixture: &crate::private_policy_provision::ProvisionedPolicyFixtureV1,
    downloaded: &DownloadedCandidateV2,
    h0: &CandidateInstalledH0V1,
    challenge: [u8; 32],
) -> Result<crate::private_candidate_c_v3::CandidateCaseBytesV3> {
    const ABI: &str = "private_tcp::abi_alternate_entry_denied";
    let result_key =
        private_release_case_key_v1(PrivateReleaseStageV1::CandidateCapability, ABI, &challenge)
            .map_err(CiError::Message)?;
    let directory =
        Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(String::from(result_key.clone()));
    if !matches!(fs::symlink_metadata(&directory), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return Err(CiError::Message(
            "ABI protected result key already exists".into(),
        ));
    }
    let challenge_hex = hex::encode(challenge);
    let (_, interval) = run_candidate_case_interval(fixture, result_key.clone(), || {
        CommandSpec::new(AGENT, root, Duration::from_secs(180))
            .remove_github_token()
            .args([
                "package",
                "release-case-abi-raw",
                "--stage",
                "candidate-capability",
                "--selector",
                ABI,
                "--challenge",
                challenge_hex.as_str(),
            ])
            .run()
    })?;
    interval.verify_allocation(&result_key)?;
    let request = crate::private_protected_readback::read_protected_raw_case_file(
        &directory.join("request.json"),
    )?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&request)
        .map_err(CiError::Message)?;
    let protected: ProtectedCandidateReleaseRequestV1 = serde_json::from_slice(&request)?;
    if serde_json::to_vec(&protected)? != request
        || protected.schema_version != 1
        || protected.stage != "candidate-capability"
        || protected.selector != ABI
        || protected.challenge != challenge_hex
        || protected.result_key != result_key
        || protected.candidate_manifest_sha256 != h0.manifest_sha256
        || protected.installation_epoch != h0.installation_epoch
        || protected.coordinator.pid == 0
        || protected.coordinator.start_time == 0
    {
        return Err(CiError::Message(
            "ABI protected request differs from H0/challenge".into(),
        ));
    }
    let filter = &downloaded.prepared.filter_sha256;
    let mut family_raw = BTreeMap::from([("request.json".into(), request.clone())]);
    let raw = if downloaded.prepared.manifest.target == "x86_64-unknown-linux-gnu" {
        let x32 = crate::private_protected_readback::read_protected_raw_case_file(
            &directory.join("x32-alternate.raw.json"),
        )?;
        let i386 = crate::private_protected_readback::read_protected_raw_case_file(
            &directory.join("i386-entry.raw.json"),
        )?;
        let verified = crate::private_abi_raw_readback::readback_x86_abi_raw(
            &protected,
            &challenge,
            &h0.inspection_sha256,
            filter,
            &x32,
            &i386,
        )?;
        family_raw.insert("x32-alternate.raw.json".into(), x32);
        family_raw.insert("i386-entry.raw.json".into(), i386);
        verified
    } else {
        let helper = memcordon_core::workload_codec::hash_bytes(
            &crate::arm32_abi_helper::static_aarch32_helper(),
        );
        let arm = crate::private_protected_readback::read_protected_raw_case_file(
            &directory.join("arm32-alternate.raw.json"),
        )?;
        let verified = crate::private_abi_raw_readback::readback_arm64_abi_raw(
            &protected,
            &challenge,
            &h0.inspection_sha256,
            filter,
            &helper,
            &arm,
        )?;
        family_raw.insert("arm32-alternate.raw.json".into(), arm);
        verified
    };
    let attachment_bytes =
        memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL
            .iter()
            .map(|role| {
                crate::private_protected_readback::read_protected_raw_case_file(
                    &directory.join(role.leaf()),
                )
            })
            .collect::<Result<Vec<_>>>()?;
    let attachments: [&[u8]; 5] = attachment_bytes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| CiError::Message("ABI positive attachment count differs".into()))?;
    let attempt = crate::private_protected_readback::read_protected_raw_case_file(
        &directory.join("attempt.json"),
    )?;
    family_raw.insert("attempt.json".into(), attempt.clone());
    let positive = crate::private_abi_raw_readback::readback_abi_positive_raw(
        &protected,
        &challenge,
        &h0.inspection_sha256,
        filter,
        attachments,
        &attempt,
    )?;
    let worker = match &raw {
        crate::private_abi_raw_readback::VerifiedAbiRawV1::X86 { worker, .. }
        | crate::private_abi_raw_readback::VerifiedAbiRawV1::Arm64 { worker, .. } => worker,
    };
    if worker != &positive.worker {
        return Err(CiError::Message(
            "ABI positive and alternate worker identities differ".into(),
        ));
    }
    let clock = crate::private_process_clock::VerifiedProcClockCalibrationV1::observe_live_reader(
        std::process::id(),
        crate::private_process_clock::read_live_start_ticks(std::process::id())?,
    )?;
    let service = crate::private_kernel_observer::observe_installed_observer_subject(
        crate::private_kernel_observer::InstalledObserverRoleV1::SealedService,
    )?;
    crate::private_abi_raw_readback::join_abi_request_origin(
        root,
        &protected,
        &challenge,
        &h0.manifest_sha256,
        &h0.installation_epoch,
        &interval,
        &clock,
        &service,
    )?;
    let broker = crate::private_kernel_observer::observe_installed_observer_subject(
        crate::private_kernel_observer::InstalledObserverRoleV1::NetworkBroker,
    )?;
    let parent = crate::private_abi_raw_readback::AbiProcessIdentityV1 {
        pid: broker.pid,
        start_time: broker.start_ticks,
    };
    let worker_kernel =
        crate::private_abi_raw_readback::join_abi_branch_task(&interval, &clock, worker, &parent)?;
    let task = |identity| {
        crate::private_abi_raw_readback::join_abi_branch_task(&interval, &clock, identity, worker)
    };
    let guardian = task(&positive.guardian)?;
    let namespace_init = task(&positive.namespace_init)?;
    let target = crate::private_abi_raw_readback::join_abi_branch_task(
        &interval,
        &clock,
        &positive.target,
        &positive.namespace_init,
    )?;
    if !interval.retired_task(target.kernel)
        || !interval.retired_task(namespace_init.kernel)
        || !interval.retired_task(guardian.kernel)
        || !interval.retired_task(worker_kernel.kernel)
    {
        return Err(CiError::Message(
            "ABI positive target/guardian/worker exit-reap chain absent".into(),
        ));
    }
    let agent_image = read_fixed_agent_identity(&h0.agent_bytes)?;
    if interval
        .events()
        .iter()
        .filter(|event| {
            matches!(event,
                crate::private_kernel_observer::KernelEventV1::Exec {
                    task, image_dev, image_inode, ..
                } if *task == target.kernel && (*image_dev, *image_inode) == agent_image
            )
        })
        .count()
        != 1
    {
        return Err(CiError::Message(
            "ABI positive target pinned agent exec absent".into(),
        ));
    }
    let target_reap = interval.events().iter().position(|event| matches!(event,
        crate::private_kernel_observer::KernelEventV1::Reap { task } if *task == target.kernel
    )).ok_or_else(|| CiError::Message("ABI positive target reap absent".into()))?;
    let init_reap = interval.events().iter().position(|event| matches!(event,
        crate::private_kernel_observer::KernelEventV1::Reap { task } if *task == namespace_init.kernel
    )).ok_or_else(|| CiError::Message("ABI positive namespace init reap absent".into()))?;
    if !interval.events()[target_reap.max(init_reap) + 1..]
        .iter()
        .any(|event| {
            matches!(event,
                crate::private_kernel_observer::KernelEventV1::NamespaceFdClosed {
                    task, namespace_inode
                } if *namespace_inode == positive.network_namespace_inode
                    && *task == worker_kernel.kernel
            )
        })
    {
        return Err(CiError::Message(
            "ABI positive worker namespace FD close after retirement absent".into(),
        ));
    }
    use crate::private_abi_composite::AbiCompositeIntentV1;
    let abi_intent = match &raw {
        crate::private_abi_raw_readback::VerifiedAbiRawV1::X86 {
            native,
            x32_control,
            x32_result,
            x32_filtered,
            i386_control,
            i386_filtered,
            ..
        } => AbiCompositeIntentV1::X86 {
            native: task(native)?,
            x32_control: task(x32_control)?,
            x32_result: *x32_result,
            x32_filtered: task(x32_filtered)?,
            i386_control: task(i386_control)?,
            i386_filtered: task(i386_filtered)?,
        },
        crate::private_abi_raw_readback::VerifiedAbiRawV1::Arm64 {
            native,
            arm32_control,
            arm32_filtered,
            ..
        } => {
            let (helper_dev, helper_inode) = installed_arm_helper_identity()?;
            AbiCompositeIntentV1::Arm64 {
                native: task(native)?,
                arm32_control: task(arm32_control)?,
                arm32_filtered: task(arm32_filtered)?,
                helper_dev,
                helper_inode,
            }
        }
    };
    let joined = crate::private_abi_composite::join_abi_kernel_events(
        &interval,
        &clock,
        clock.reader_identity(),
        abi_intent,
    )?;
    if joined.capture_sha256() != interval.trace_sha256()
        || joined.branch_count()
            != if downloaded.prepared.manifest.target == "x86_64-unknown-linux-gnu" {
                5
            } else {
                3
            }
    {
        return Err(CiError::Message(
            "ABI independent child inventory differs".into(),
        ));
    }
    for forbidden in ["result.json", "result.json.new"] {
        if !matches!(fs::symlink_metadata(directory.join(forbidden)), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            return Err(CiError::Message(
                "ABI raw-only path minted a premature result".into(),
            ));
        }
    }
    use memcordon_core::private_release_case_v1::{
        PrivateReleaseAbiRawInventoryV1, PrivateReleaseAttachmentRoleV1,
        PrivateReleaseAttachmentV1, PrivateReleaseCaseResultV1, PrivateReleaseObservationV1,
    };
    let abi_raw = match raw {
        crate::private_abi_raw_readback::VerifiedAbiRawV1::X86 {
            x32_sha256,
            i386_sha256,
            ..
        } => PrivateReleaseAbiRawInventoryV1::X86_64 {
            x32_sha256,
            i386_sha256,
        },
        crate::private_abi_raw_readback::VerifiedAbiRawV1::Arm64 { arm32_sha256, .. } => {
            PrivateReleaseAbiRawInventoryV1::Aarch64 { arm32_sha256 }
        }
    };
    let native_machine = if downloaded.prepared.manifest.target == "x86_64-unknown-linux-gnu" {
        "x86_64"
    } else {
        "aarch64"
    };
    let result = PrivateReleaseCaseResultV1 {
        schema_version: 1,
        selector: ABI.into(),
        challenge: challenge_hex,
        target: downloaded.prepared.manifest.target.clone(),
        native_machine: native_machine.into(),
        installed: PrivateReleaseInstalledBindingV1::CandidateCapability {
            installation_epoch: h0.installation_epoch.clone(),
            candidate_manifest_sha256: h0.manifest_sha256.clone(),
            installed_inspection_sha256: h0.inspection_sha256.clone(),
        },
        observation: PrivateReleaseObservationV1::AbiComposite {
            attempt_id: positive.attempt_id,
            checkpoint_sha256: positive.checkpoint_sha256,
            terminal_sha256: positive.terminal_sha256,
            retirement_sha256: positive.retirement_sha256,
            abi_raw,
            independent_interval_sha256: interval.trace_sha256().clone(),
            native_observer_sha256: positive.observer_sha256,
        },
        attachments: PrivateReleaseAttachmentRoleV1::ALL
            .into_iter()
            .zip(attachment_bytes.iter())
            .map(|(role, bytes)| PrivateReleaseAttachmentV1 {
                role,
                size: bytes.len() as u64,
                sha256: hash_bytes(bytes),
            })
            .collect(),
    };
    result.validate().map_err(CiError::Message)?;
    let attachments: [Vec<u8>; 5] = attachment_bytes
        .try_into()
        .map_err(|_| CiError::Message("ABI positive attachment count differs".into()))?;
    Ok(crate::private_candidate_c_v3::CandidateCaseBytesV3 {
        result: serde_json::to_vec(&result)?,
        attachments,
        kernel_capture: interval.capture_bytes()?.to_vec(),
        family_raw,
    })
}

fn run_candidate_case_interval<T>(
    fixture: &crate::private_policy_provision::ProvisionedPolicyFixtureV1,
    result_key: DiagnosticSha256,
    operation: impl FnOnce() -> Result<T>,
) -> Result<(T, crate::private_kernel_observer::VerifiedKernelIntervalV1)> {
    use crate::private_kernel_observer::{
        ExpectedKernelAdapterV1, InstalledObserverRoleV1,
        activate_installed_network_broker_for_observation, observe_installed_observer_subject,
        observe_live_kernel_subject, run_probe_case_interval,
    };
    use crate::private_probe_bundle::{ExpectedProbeBundleV1, verify_probe_bundle};
    let pinned = fixture.observer();
    let probe = verify_probe_bundle(ExpectedProbeBundleV1 {
        bpf_source_sha256: pinned.bpf_source_sha256.clone(),
        loader_source_sha256: pinned.loader_source_sha256.clone(),
        object_sha256: pinned.object_sha256.clone(),
        loader_sha256: pinned.loader_sha256.clone(),
        agent_sha256: pinned.agent_sha256.clone(),
        agent_build_id: pinned.agent_build_id.clone(),
        request_entry_offset: pinned.request_entry_offset,
        request_exit_offset: pinned.request_exit_offset,
        allocation_entry_offset: pinned.allocation_entry_offset,
    })?;
    let reader = observe_live_kernel_subject(std::process::id())?;
    let service = observe_installed_observer_subject(InstalledObserverRoleV1::SealedService)?;
    let broker = activate_installed_network_broker_for_observation()?;
    let expected =
        |key: DiagnosticSha256,
         primary: crate::private_kernel_observer::LiveKernelSubjectV1,
         secondary: crate::private_kernel_observer::LiveKernelSubjectV1| {
            ExpectedKernelAdapterV1 {
                boot_id: pinned.boot_id.clone(),
                kernel_release: pinned.kernel_release.clone(),
                btf_sha256: pinned.btf_sha256.clone(),
                probe_map_sha256: probe.attestation_digest(),
                result_key: key,
                coordinator_pid: primary.pid,
                coordinator_start_time: 0,
                coordinator_start_ticks: primary.start_ticks,
                cgroup_inode: primary.cgroup_inode,
                broker_pid: secondary.pid,
                broker_start_ticks: secondary.start_ticks,
                broker_cgroup_inode: secondary.cgroup_inode,
            }
        };
    let controls = crate::private_probe_controls::run_fixed_known_action_controls(
        &probe,
        expected(pinned.control_result_key.clone(), reader, service),
    )?;
    let mut output = None;
    let interval = run_probe_case_interval(
        &probe,
        expected(result_key.clone(), service, broker),
        controls.controls(),
        || {
            output = Some(operation()?);
            Ok(())
        },
    )?;
    if interval.result_key() != &result_key || interval.capture_bytes()?.is_empty() {
        return Err(CiError::Message(
            "candidate case independent kernel capture differs".into(),
        ));
    }
    Ok((
        output.ok_or_else(|| {
            CiError::Message("candidate case operation not run under kernel interval".into())
        })?,
        interval,
    ))
}

pub fn run(
    root: &Path,
    stage: NativeRunStageV2,
    target: &str,
    collector_intent_sha256: Option<&str>,
    policy_intent_sha256: Option<&str>,
) -> Result<()> {
    let _collector_intent_digest = match (stage, collector_intent_sha256) {
        (NativeRunStageV2::CandidateCapability, Some(value)) => {
            Some(parse_collector_intent_digest(value)?)
        }
        (NativeRunStageV2::CandidateCapability, None) => {
            return Err(CiError::Message(
                "candidate C collector-intent digest is absent".into(),
            ));
        }
        (NativeRunStageV2::FinalPublic, None) => None,
        (NativeRunStageV2::FinalPublic, Some(_)) => {
            return Err(CiError::Message(
                "collector-intent digest is candidate-only".into(),
            ));
        }
    };
    let policy_intent_digest = match (stage, policy_intent_sha256) {
        (NativeRunStageV2::CandidateCapability, Some(value)) => {
            Some(parse_collector_intent_digest(value)?)
        }
        (NativeRunStageV2::CandidateCapability, None) => {
            return Err(CiError::Message(
                "candidate policy release-intent digest is absent".into(),
            ));
        }
        (_, None) => None,
        (_, Some(_)) => {
            return Err(CiError::Message(
                "policy release-intent digest belongs only to candidate stage".into(),
            ));
        }
    };
    let producer = producer_for_host(stage, target)?;
    let context = CertificationContext::capture(root, "backend-linux-private-v4")?;
    validate_private_job_context(&context, &producer)?;
    if stage == NativeRunStageV2::FinalPublic {
        return crate::private_public_dispatch::run_final_public_suite(root, target);
    }
    let mut candidate_h0 = if stage == NativeRunStageV2::CandidateCapability {
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
    if let Some((downloaded, h0)) = candidate_h0.as_mut() {
        *h0 = run_candidate_epoch_choreography(root, target, downloaded, h0)?;
    }
    let policy_fixture = if let Some((downloaded, h0)) = &candidate_h0 {
        let digest = policy_intent_digest.as_ref().ok_or_else(|| {
            CiError::Message("candidate policy release-intent digest is absent".into())
        })?;
        Some(crate::private_policy_provision::provision_policy_fixture(
            digest,
            &crate::private_policy_provision::PolicyLiveExpectationV1 {
                target: target.to_owned(),
                candidate_build_sha256: downloaded.build_sha256.clone(),
                installed_inspection_sha256: h0.inspection_sha256.clone(),
                installation_epoch_sha256: h0.installation_epoch.clone(),
                agent_sha256: hash_bytes(&h0.agent_bytes),
            },
        )?)
    } else {
        None
    };
    let challenge = fresh_challenge()?;
    let mut structural_results = Vec::with_capacity(REQUIRED_CASES.len());
    let mut policy_case = None;
    let mut abi_subwitness = None;
    for selector in REQUIRED_CASES {
        if selector == "private_tcp::abi_alternate_entry_denied" {
            let fixture = policy_fixture.as_ref().ok_or_else(|| {
                CiError::Message("candidate ABI observer intent is absent".into())
            })?;
            let (downloaded, h0) = candidate_h0.as_ref().ok_or_else(|| {
                CiError::Message("candidate ABI installed B/M0/H0 is absent".into())
            })?;
            abi_subwitness = Some(run_candidate_abi_subwitness(
                root, fixture, downloaded, h0, challenge,
            )?);
            continue;
        }
        if selector == "private_tcp::wrong_grant_profile_and_port_rejected" {
            let fixture = policy_fixture.as_ref().ok_or_else(|| {
                CiError::Message("candidate policy fixture was not provisioned".into())
            })?;
            let (_, h0) = candidate_h0.as_ref().ok_or_else(|| {
                CiError::Message("candidate policy installed H0 is absent".into())
            })?;
            policy_case = Some(run_candidate_policy_branches(
                root,
                fixture,
                h0,
                target,
                producer.native_machine,
            )?);
            continue;
        }
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
        let result_key = private_release_case_key_v1(
            PrivateReleaseStageV1::CandidateCapability,
            selector,
            &challenge,
        )
        .map_err(CiError::Message)?;
        let fixture = policy_fixture
            .as_ref()
            .ok_or_else(|| CiError::Message("candidate kernel observer intent is absent".into()))?;
        let (
            (observed, child_live, socket_live, terminal_live, dual_live, unix_live),
            kernel_interval,
        ) = run_candidate_case_interval(fixture, result_key.clone(), || {
            let value = if selector == CHILD_RUNTIME_SELECTOR {
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
                let image = image_before.ok_or_else(|| {
                    CiError::Message("dual installed image identity absent".into())
                })?;
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
            Ok(value)
        })?;
        if kernel_interval.result_key() != &result_key
            || !kernel_interval.has_allocation_boundary()
            || kernel_interval.capture_bytes()?.is_empty()
        {
            return Err(CiError::Message(
                "candidate case lacks complete independent kernel interval".into(),
            ));
        }
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
        match &structural.result.observation {
            memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::PreallocationRejected { .. }
                if !kernel_interval.no_allocation() => {
                    return Err(CiError::Message("candidate preallocation branch has independent allocation".into()));
                }
            memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::AllocatedRetired { .. }
            | memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::DualAttemptsRetired { .. }
            | memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::RetirementFailureBlockedReuse { .. }
                if !kernel_interval.has_allocation_boundary() => {
                    return Err(CiError::Message("candidate allocated branch lacks independent allocation boundary".into()));
                }
            memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::PolicyComposite { .. } => {
                return Err(CiError::Message("ordinary candidate selector substituted policy composite".into()));
            }
            _ => {}
        }
        if matches!(structural.result.observation,
            memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::AllocatedRetired { .. }
            | memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::DualAttemptsRetired { .. }
            | memcordon_core::private_release_case_v1::PrivateReleaseObservationV1::RetirementFailureBlockedReuse { .. }
        ) {
            kernel_interval.verify_allocation(&result_key)?;
        }
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
        structural_results.push((structural, kernel_interval));
    }
    Err(CiError::Message(format!(
        "private native {stage:?} suite structurally read {} protected results, composed policy aggregate {} and ABI positive/branch aggregate {}, but the full 25-case independent supervisor semantics and completed C export remain absent; no Q or P was produced",
        structural_results.len(),
        policy_case.is_some(),
        abi_subwitness.as_ref().is_some_and(
            |value: &crate::private_candidate_c_v3::CandidateCaseBytesV3| !value.result.is_empty()
                && !value.family_raw.is_empty()
                && !value.kernel_capture.is_empty()
        )
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
