//! Exact private native suite admission and enrolled raw-evidence production.
//!
//! The suite cannot succeed until each declared case has a compiled native
//! implementation and the supervising runner can issue authenticated raw
//! observations. Live origin can authorize bounded C export only after full
//! replay; completed Actions custody remains mandatory for qualification.
//! Parsing a catalogue never creates a trusted completion capability.

use std::collections::BTreeMap;
const POLICY_SELECTOR: &str = "private_tcp::wrong_grant_profile_and_port_rejected";
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
use crate::private_child_live::{CHILD_RUNTIME_SELECTOR, join_live_sample_to_result};
use crate::private_dual_live::{DUAL_SELECTOR, join_sampled_dual_to_result};
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
use crate::private_unix_live::{UNIX_INTENT_SELECTOR, join_sampled_unix_to_result};
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
    mut journal: Option<&mut crate::private_candidate_producer::CandidateProducerJournalV1>,
    plan: Option<&crate::private_candidate_producer::StaticCandidateProducerIntentV1>,
) -> Result<CandidateInstalledH0V1> {
    const CONTROL: &str = "private_tcp::native_tcp_bind_listen_connect";
    let target_id = match target {
        "x86_64-unknown-linux-gnu" => "linux-x64",
        "aarch64-unknown-linux-gnu" => "linux-arm64",
        _ => return Err(CiError::Message("historical epoch target differs".into())),
    };
    let run_control = |journal: Option<
        &mut crate::private_candidate_producer::CandidateProducerJournalV1,
    >,
                       ordinal: u32|
     -> Result<(
        [u8; 32],
        crate::private_protected_readback::StructuralProtectedNativeCaseV1,
    )> {
        let prepared = journal
            .as_ref()
            .map(|journal| {
                journal.prepare_case(
                    CONTROL,
                    crate::private_kernel_replay::IntervalPurposeV1::Historical,
                    ordinal,
                )
            })
            .transpose()?;
        let challenge = prepared
            .as_ref()
            .map(|case| case.challenge)
            .map_or_else(fresh_challenge, Ok)?;
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
        let mut phases = crate::private_candidate_producer::CandidateLivePhasesV1::default();
        let mut execute =
            || -> Result<crate::private_protected_readback::StructuralProtectedNativeCaseV1> {
                let process = if let Some(prepared) = &prepared {
                    let plan = plan
                        .ok_or_else(|| CiError::Message("historical live recipe absent".into()))?;
                    let directory = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1)
                        .join(String::from(prepared.key.clone()));
                    supervise_private_case_process_with_observer(
                        Path::new(AGENT),
                        &args,
                        Duration::from_secs(120),
                        || {
                            match std::fs::symlink_metadata(&directory) {
                                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                    return Ok(None);
                                }
                                Err(error) => return Err(error.into()),
                                Ok(_) => {}
                            }
                            if crate::private_candidate_producer::sample_candidate_phases_if_ready(
                                &directory,
                                CONTROL,
                                target,
                                &challenge,
                                &plan.observer.agent_sha256,
                                &prepared.recipe,
                                &prepared.argv,
                                &mut phases,
                            )? {
                                Ok(Some(()))
                            } else {
                                Ok(None)
                            }
                        },
                    )?
                    .0
                } else {
                    supervise_private_case_process(
                        Path::new(AGENT),
                        &args,
                        Duration::from_secs(120),
                    )?
                };
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
                phases.close_observer_namespaces()?;
                Ok(structural)
            };
        let structural = if let (Some(journal), Some(prepared)) = (journal, prepared.as_ref()) {
            let (raw, detached) = run_candidate_journal_interval(
                journal,
                &plan
                    .ok_or_else(|| CiError::Message("historical enrolled observer absent".into()))?
                    .observer,
                prepared,
                execute,
            )?;
            retain_candidate_raw_interval(journal, prepared, &detached, &raw, &phases, None)?;
            raw
        } else {
            execute()?
        };
        Ok((challenge, structural))
    };
    let (e0_challenge, accepted_e0) = run_control(journal.as_deref_mut(), 0)?;
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
    if let Some(journal) = journal.as_deref_mut() {
        let (generation, raw, _) = crate::private_candidate_producer::observe_candidate_generation(
            plan.ok_or_else(|| CiError::Message("historical generation recipe absent".into()))?,
            1,
            e1.manifest_sha256.clone(),
            e1.inspection_sha256.clone(),
            &e1.inspection_bytes,
            e1.installation_epoch.clone(),
        )?;
        journal.observe_upgrade(generation)?;
        journal.queue_generation_raw(raw)?;
    }
    let replay_operation = || {
        CommandSpec::new(AGENT, root, Duration::from_secs(30))
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
            .run()
    };
    let replay = if let Some(journal) = journal.as_deref_mut() {
        let mut case = journal.prepare_case(
            CONTROL,
            crate::private_kernel_replay::IntervalPurposeV1::Historical,
            1,
        )?;
        case.challenge = e0_challenge;
        case.key = accepted_e0.result.result_key().map_err(CiError::Message)?;
        case.interval_id.logical_case_key = case.key.clone();
        let (replay, detached) = run_candidate_journal_interval(
            journal,
            &plan
                .ok_or_else(|| CiError::Message("historical replay observer absent".into()))?
                .observer,
            &case,
            replay_operation,
        )?;
        let prefix = Path::new("candidate-c-v3/observer/intervals")
            .join(String::from(case.interval_id.storage_sha256()));
        let capture = prefix.join("capture.bin").to_string_lossy().into_owned();
        let clock = prefix.join("clock.json").to_string_lossy().into_owned();
        journal.append_raw(capture.clone(), detached.interval.capture_bytes()?.to_vec())?;
        journal.append_raw(
            clock.clone(),
            crate::private_observer_session::canonical_bytes(
                detached.interval.clock_inputs().ok_or_else(|| {
                    CiError::Message("historical replay original clock inputs absent".into())
                })?,
            )?,
        )?;
        journal.append_raw(
            prefix.join("request.json").to_string_lossy().into_owned(),
            accepted_e0.candidate_request_bytes.clone(),
        )?;
        journal.append_raw(
            prefix
                .join("replay-rejection.json")
                .to_string_lossy()
                .into_owned(),
            replay.clone(),
        )?;
        journal.close_after_detach(
            &case,
            &detached.interval,
            capture,
            vec![detached.controls_path],
            vec![clock],
            detached.arm_monotonic_ns,
            detached.detach_monotonic_ns,
        )?;
        replay
    } else {
        replay_operation()?
    };
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
    let (_, fresh_e1) = run_control(journal.as_deref_mut(), 2)?;
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
    mut journal: Option<&mut crate::private_candidate_producer::CandidateProducerJournalV1>,
    collector: Option<&DiagnosticSha256>,
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
    let controls = if journal.is_none() {
        Some(
            crate::private_probe_controls::run_fixed_known_action_controls(
                &probe,
                expected(pinned.control_result_key.clone(), reader, service),
            )?,
        )
    } else {
        None
    };
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
    let mut enrolled_policy = Vec::new();
    let intervals = if let Some(journal) = journal.as_deref_mut() {
        let base = journal.prepare_case(
            POLICY_SELECTOR,
            crate::private_kernel_replay::IntervalPurposeV1::Policy,
            0,
        )?;
        if &base.challenge != fixture.base_challenge() || collector.is_none() {
            return Err(CiError::Message(
                "policy live base challenge/collector absent or different".into(),
            ));
        }
        let mut detached_intervals = Vec::with_capacity(5);
        for (index, branch) in PolicyOperationBranchV1::ALL.into_iter().enumerate() {
            let mut prepared = journal.prepare_case(
                POLICY_SELECTOR,
                crate::private_kernel_replay::IntervalPurposeV1::Policy,
                0,
            )?;
            prepared.challenge = policy_branch_challenge_v1(fixture.base_challenge(), branch)
                .map_err(|error| CiError::Message(error.into()))?;
            prepared.key = keys[index].clone();
            prepared.interval_id.logical_case_key = prepared.key.clone();
            prepared.interval_id.ordinal = index as u32;
            let (expected_key, expected_id) =
                crate::private_candidate_replay::candidate_policy_interval_identity_v1(
                    &journal.descriptor().session_nonce,
                    prepared.interval_id.generation,
                    fixture.base_challenge(),
                    branch,
                )?;
            if prepared.key != expected_key || prepared.interval_id.storage_sha256() != expected_id
            {
                return Err(CiError::Message(
                    "policy independent branch physical recipe differs".into(),
                ));
            }
            let (output, detached) =
                run_candidate_journal_interval(journal, pinned, &prepared, || {
                    CommandSpec::new(AGENT, root, Duration::from_secs(120))
                        .remove_github_token()
                        .args([
                            "package",
                            "release-case-policy-branches",
                            "--challenge",
                            base_hex.as_str(),
                            "--branch",
                            branch.as_str(),
                        ])
                        .run()
                })?;
            supervised.push(output);
            let prefix = Path::new("candidate-c-v3/observer/intervals")
                .join(String::from(prepared.interval_id.storage_sha256()));
            let path = |leaf: &str| prefix.join(leaf).to_string_lossy().into_owned();
            let case_directory =
                Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(String::from(prepared.key.clone()));
            let request = crate::private_protected_readback::read_protected_raw_case_file(
                &case_directory.join("request.json"),
            )?;
            let raw = crate::private_protected_readback::read_protected_raw_case_file(
                &case_directory.join("policy-branches.raw.json"),
            )?;
            let raw_record = ProtectedPolicyBranchRawV1::parse(&raw, fixture.base_challenge())
                .map_err(CiError::Message)?;
            let protected = crate::private_protected_readback::parse_protected_candidate_request(
                &request,
                POLICY_SELECTOR,
                prepared.challenge,
                &prepared.key,
            )?;
            if raw_record.branch != branch
                || raw_record.result_key != prepared.key
                || protected.result_key != prepared.key
            {
                return Err(CiError::Message(
                    "policy live branch original key differs".into(),
                ));
            }
            let capture_path = if index == 0 {
                Path::new("candidate-c-v3/cases")
                    .join(String::from(base.key.clone()))
                    .join(format!(
                        "kernel-{}.capture.bin",
                        String::from(collector.expect("checked collector").clone())
                    ))
                    .to_string_lossy()
                    .into_owned()
            } else {
                path("capture.bin")
            };
            let clock_path = path("clock.json");
            let original_clock = detached
                .interval
                .clock_inputs()
                .ok_or_else(|| CiError::Message("policy original reader clock absent".into()))?;
            journal.append_raw(
                capture_path.clone(),
                detached.interval.capture_bytes()?.to_vec(),
            )?;
            journal.append_raw(
                clock_path.clone(),
                crate::private_observer_session::canonical_bytes(original_clock)?,
            )?;
            journal.append_raw(path("request.json"), request)?;
            journal.append_raw(path("policy-branches.raw.json"), raw)?;
            if index == 0 {
                let fixture_bytes =
                    crate::private_protected_readback::read_protected_raw_case_file(Path::new(
                        "/var/lib/memcordon/sealed/private-release-policy-v1.json",
                    ))?;
                if hash_bytes(&fixture_bytes) != *fixture.fixture_sha256() {
                    return Err(CiError::Message(
                        "policy retained actual fixture digest differs".into(),
                    ));
                }
                let activation_bytes =
                    crate::private_protected_readback::read_protected_raw_case_file(Path::new(
                        "/var/lib/memcordon/policy/policy-activation.json",
                    ))?;
                let activation: serde_json::Value = serde_json::from_slice(&activation_bytes)?;
                let registry: memcordon_core::workload_registry_v2::PolicyRegistryV2 =
                    serde_json::from_value(
                        activation
                            .get("registry")
                            .ok_or_else(|| {
                                CiError::Message("policy activation registry absent".into())
                            })?
                            .clone(),
                    )?;
                if registry.canonical_digest().map_err(CiError::Message)?
                    != *fixture.registry_sha256()
                {
                    return Err(CiError::Message(
                        "policy retained actual registry digest differs".into(),
                    ));
                }
                journal.append_raw(path("fixture.json"), fixture_bytes)?;
                journal.append_raw(path("activation.json"), activation_bytes)?;
                journal.append_raw(path("registry.json"), serde_json::to_vec(&registry)?)?;
            }
            journal.close_after_detach(
                &prepared,
                &detached.interval,
                capture_path.clone(),
                vec![detached.controls_path.clone()],
                vec![clock_path.clone()],
                detached.arm_monotonic_ns,
                detached.detach_monotonic_ns,
            )?;
            enrolled_policy.push((
                prepared,
                prefix,
                capture_path,
                clock_path,
                detached.controls_path,
            ));
            detached_intervals.push(detached.interval);
        }
        crate::private_policy_intervals::VerifiedPolicyIntervalsV1::from_detached(
            detached_intervals
                .try_into()
                .map_err(|_| CiError::Message("policy detached interval count differs".into()))?,
        )?
    } else {
        crate::private_policy_intervals::run_policy_intervals(
            &probe,
            controls.as_ref().expect("diagnostic controls").controls(),
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
        )?
    };
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
    let case_bytes = crate::private_candidate_c_v3::CandidateCaseBytesV3 {
        result: serde_json::to_vec(&result)?,
        attachments,
        kernel_capture: captures[0].clone(),
        family_raw,
    };
    if let Some(journal) = journal.as_deref_mut() {
        use crate::private_candidate_replay::{
            CaseFactV1, CaseReplayFactsV1, PolicyBranchV1 as ReplayPolicyBranch, ReplayLeafRoleV1,
            ReplayLeafV1, ReplayTaskV1,
        };
        let base = journal.prepare_case(
            POLICY_SELECTOR,
            crate::private_kernel_replay::IntervalPurposeV1::Policy,
            0,
        )?;
        let case_prefix = Path::new("candidate-c-v3/cases").join(String::from(base.key.clone()));
        let case_path = |leaf: &str| case_prefix.join(leaf).to_string_lossy().into_owned();
        let mut replay_branches = Vec::with_capacity(5);
        for (index, (prepared, prefix, capture_path, _, _)) in enrolled_policy.iter().enumerate() {
            let events =
                crate::private_kernel_replay::parse_capture_v2(&captures[index], &prepared.key)?;
            let request: ProtectedCandidateReleaseRequestV1 =
                serde_json::from_slice(&request_bytes[index])?;
            let clock = intervals
                .positive()
                .clock_inputs()
                .ok_or_else(|| CiError::Message("policy original branch clock absent".into()))?;
            let clock = if index == 0 {
                clock
            } else {
                intervals.rejected()[index - 1]
                    .clock_inputs()
                    .ok_or_else(|| CiError::Message("policy original branch clock absent".into()))?
            };
            let calibrated =
                crate::private_process_clock::ParsedProcClockCalibrationV1::parse(clock)?;
            let callers: Vec<_> = events
                .events()
                .iter()
                .filter(|event| {
                    event.kind == 1
                        && event.task.tid == request.coordinator.pid
                        && calibrated.matches(
                            crate::private_kernel_observer::KernelTaskIdentityV1 {
                                pid: event.task.tid,
                                start_time: event.task.start_boottime_ns,
                                cgroup_inode: event.task.cgroup_inode,
                                time_ns_inode: event.task.time_ns_inode,
                            },
                            request.coordinator.start_time,
                        )
                })
                .collect();
            let [caller] = callers.as_slice() else {
                return Err(CiError::Message(
                    "policy exact actual request caller absent or duplicated".into(),
                ));
            };
            let (name, predicate) = match index {
                0 => ("accepted", None),
                1 => ("wrong-grant", Some("grant-caller")),
                2 => ("wrong-profile", Some("profile-digest")),
                3 => ("unapproved-port", Some("plan-membership")),
                4 => ("frozen-tamper", Some("frozen-binding")),
                _ => unreachable!("closed policy branch count"),
            };
            let source_path = |leaf: &str| prefix.join(leaf).to_string_lossy().into_owned();
            replay_branches.push(ReplayPolicyBranch {
                branch: name.into(),
                capture_path: capture_path.clone(),
                request_path: source_path("request.json"),
                response_path: source_path("policy-branches.raw.json"),
                caller_uid: fixture.authenticated_caller_uid(),
                caller_task: ReplayTaskV1 {
                    tid: caller.task.tid,
                    tgid: caller.task.tgid,
                    start_boottime_ns: caller.task.start_boottime_ns,
                    cgroup_inode: caller.task.cgroup_inode,
                    time_ns_inode: caller.task.time_ns_inode,
                },
                rejection_predicate: predicate.map(str::to_owned),
                registry_sha256: fixture.registry_sha256().clone(),
                fixture_sha256: fixture.fixture_sha256().clone(),
                raw_path: source_path("policy-branches.raw.json"),
            });
        }
        let (accepted, prefix, _, clock_path, controls_path) = enrolled_policy
            .first()
            .ok_or_else(|| CiError::Message("policy enrolled accepted capture absent".into()))?;
        let sources =
            crate::private_candidate_replay::expand_replay_payload(journal.raw_payload())?;
        let source = |path: &str| {
            sources
                .get(path)
                .cloned()
                .ok_or_else(|| CiError::Message("policy original custody leaf absent".into()))
        };
        let facts = CaseReplayFactsV1 {
            schema_version: 1,
            selector: POLICY_SELECTOR.into(),
            result_key: base.key.clone(),
            generation: accepted.interval_id.generation,
            interval_id: accepted.interval_id.storage_sha256(),
            target: replay_branches[0].caller_task.clone(),
            facts: vec![CaseFactV1::Policy {
                branches: replay_branches,
                accepted_registry_path: prefix.join("registry.json").to_string_lossy().into_owned(),
                fixture_path: prefix.join("fixture.json").to_string_lossy().into_owned(),
            }],
            clock_path: clock_path.clone(),
            held_sample_paths: Vec::new(),
        };
        let bundle = crate::private_candidate_replay::encode_replay_bundle(&[
            ReplayLeafV1 {
                role: ReplayLeafRoleV1::Facts,
                ordinal: 0,
                bytes: crate::private_observer_session::canonical_bytes(&facts)?,
            },
            ReplayLeafV1 {
                role: ReplayLeafRoleV1::Request,
                ordinal: 0,
                bytes: request_bytes[0].clone(),
            },
            ReplayLeafV1 {
                role: ReplayLeafRoleV1::Clock,
                ordinal: 0,
                bytes: source(clock_path)?,
            },
            ReplayLeafV1 {
                role: ReplayLeafRoleV1::Controls,
                ordinal: 0,
                bytes: source(controls_path)?,
            },
        ])?;
        journal.append_representation(case_path("result.json"), case_bytes.result.clone())?;
        for (role, bytes) in
            memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL
                .into_iter()
                .zip(&case_bytes.attachments)
        {
            journal.append_representation(case_path(role.leaf()), bytes.clone())?;
        }
        for (leaf, bytes) in &case_bytes.family_raw {
            journal.append_representation(
                case_path(&Path::new("family").join(leaf).to_string_lossy()),
                bytes.clone(),
            )?;
        }
        journal.append_representation(case_path("family/replay-bundle.v1.bin"), bundle)?;
        let original_paths = journal
            .raw_payload()
            .keys()
            .filter(|path| path.starts_with("candidate-c-v3/observer/"))
            .cloned()
            .collect();
        journal.repack_sources(case_path("family/source-carrier.v1.bin"), original_paths)?;
    }
    Ok(case_bytes)
}

/// The raw-only ABI command has no producer-signed `result.json`. CI composes
/// the case only after the positive lifecycle and every ABI child join one
/// loss-free kernel interval.

#[cfg(target_os = "linux")]
fn observe_installed_arm_helper(
    operation: impl FnOnce() -> Result<()>,
) -> Result<(
    crate::private_candidate_abi_facts::ArmHelperMeasurementV1,
    Vec<u8>,
)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let path = Path::new("/usr/libexec/memcordon-arm32-abi-helper");
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let begin_monotonic_ns = memcordon_platform::test_support::private_observer_monotonic_ns()?;
    let before = file.metadata()?;
    if !before.is_file() || before.uid() != 0 || before.mode() & 0o022 != 0 || before.nlink() != 1 {
        return Err(CiError::Message(
            "installed ARM32 helper identity differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    (&mut file).take(1024 * 1024).read_to_end(&mut bytes)?;
    operation()?;
    let after = file.metadata()?;
    let end_monotonic_ns = memcordon_platform::test_support::private_observer_monotonic_ns()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || before.mode() != after.mode()
        || before.nlink() != after.nlink()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.len() != bytes.len() as u64
        || hash_bytes(&bytes) != hash_bytes(&crate::arm32_abi_helper::static_aarch32_helper())
    {
        return Err(CiError::Message(
            "installed ARM32 helper differs from reviewed B".into(),
        ));
    }
    Ok((
        crate::private_candidate_abi_facts::ArmHelperMeasurementV1 {
            schema_version: 1,
            device: before.dev(),
            inode: before.ino(),
            uid: before.uid(),
            mode: before.mode(),
            nlink: before.nlink(),
            size: before.len(),
            sha256: hash_bytes(&bytes),
            begin_monotonic_ns,
            end_monotonic_ns,
        },
        bytes,
    ))
}

#[cfg(not(target_os = "linux"))]
fn observe_installed_arm_helper(
    _operation: impl FnOnce() -> Result<()>,
) -> Result<(
    crate::private_candidate_abi_facts::ArmHelperMeasurementV1,
    Vec<u8>,
)> {
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
    mut journal: Option<&mut crate::private_candidate_producer::CandidateProducerJournalV1>,
    prepared: Option<&crate::private_candidate_producer::PreparedCandidateCaseV1>,
    collector: Option<&DiagnosticSha256>,
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
    let mut phases = crate::private_candidate_producer::CandidateLivePhasesV1::default();
    let mut arm_helper = None;
    let operation = || -> Result<()> {
        let mut produce = || -> Result<()> {
            if let Some(case) = prepared {
                let arguments = [
                    "package",
                    "release-case-abi-raw",
                    "--stage",
                    "candidate-capability",
                    "--selector",
                    ABI,
                    "--challenge",
                    challenge_hex.as_str(),
                ]
                .map(OsString::from);
                let (process, _) = supervise_private_case_process_with_observer(
                    Path::new(AGENT),
                    &arguments,
                    Duration::from_secs(180),
                    || {
                        match std::fs::symlink_metadata(&directory) {
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                return Ok(None);
                            }
                            Err(error) => return Err(error.into()),
                            Ok(_) => (),
                        }
                        let sampled =
                            crate::private_candidate_producer::sample_candidate_phases_if_ready(
                                &directory,
                                ABI,
                                &downloaded.prepared.manifest.target,
                                &challenge,
                                &fixture.observer().agent_sha256,
                                &case.recipe,
                                &case.argv,
                                &mut phases,
                            )?;
                        Ok(sampled.then_some(()))
                    },
                )?;
                if !process.status.success() {
                    return Err(CiError::Message(
                        "candidate ABI supervised native producer failed".into(),
                    ));
                }
                phases.close_observer_namespaces()?;
            } else {
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
                    .run()?;
            }
            Ok(())
        };
        if downloaded.prepared.manifest.target == "aarch64-unknown-linux-gnu" {
            let (measurement, bytes) = observe_installed_arm_helper(produce)?;
            phases.source_leaves.insert("abi-helper.raw".into(), bytes);
            phases.source_leaves.insert(
                "abi-helper-metadata.json".into(),
                crate::private_observer_session::canonical_bytes(&measurement)?,
            );
            arm_helper = Some((measurement.device, measurement.inode));
        } else {
            produce()?;
        }
        Ok(())
    };
    let captured = if let (Some(journal), Some(case)) = (journal.as_deref_mut(), prepared) {
        let (_, detached) =
            run_candidate_journal_interval(journal, fixture.observer(), case, operation)?;
        CandidateCapturedIntervalV1::Enrolled(detached)
    } else {
        let (_, interval) = run_candidate_case_interval(fixture, result_key.clone(), operation)?;
        CandidateCapturedIntervalV1::Diagnostic(interval)
    };
    let interval = captured.interval();
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
            let (helper_dev, helper_inode) = arm_helper.ok_or_else(|| {
                CiError::Message("actual held ARM ABI helper source absent".into())
            })?;
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
    let bytes = crate::private_candidate_c_v3::CandidateCaseBytesV3 {
        result: serde_json::to_vec(&result)?,
        attachments,
        kernel_capture: interval.capture_bytes()?.to_vec(),
        family_raw,
    };
    if let (Some(journal), Some(case), CandidateCapturedIntervalV1::Enrolled(detached)) =
        (journal.as_deref_mut(), prepared, &captured)
    {
        for (name, raw) in &bytes.family_raw {
            journal.append_raw(
                Path::new("candidate-c-v3/cases")
                    .join(String::from(case.key.clone()))
                    .join("family")
                    .join(name)
                    .to_string_lossy()
                    .into_owned(),
                raw.clone(),
            )?;
        }
        let result = PrivateReleaseCaseResultV1::parse(&bytes.result).map_err(CiError::Message)?;
        let attempt_bytes = bytes
            .family_raw
            .get("attempt.json")
            .ok_or_else(|| CiError::Message("candidate ABI actual native terminal absent".into()))?
            .clone();
        let attempt = crate::private_protected_readback::parse_protected_candidate_attempt(
            &attempt_bytes,
            &protected,
            &result.observation,
            challenge,
        )?;
        let raw = crate::private_protected_readback::StructuralProtectedNativeCaseV1 {
            result,
            candidate_request: protected,
            candidate_request_bytes: request,
            attempt_record: Some(attempt),
            attempt_record_bytes: Some(attempt_bytes),
            fault_marker_bytes: None,
            checkpoint_gate_bytes: None,
            attachments: bytes.attachments.to_vec(),
        };
        retain_candidate_raw_interval(journal, case, detached, &raw, &phases, collector)?;
        let sources = journal
            .raw_payload()
            .keys()
            .filter(|path| path.starts_with("candidate-c-v3/observer/"))
            .cloned()
            .collect();
        journal.repack_sources(
            Path::new("candidate-c-v3/cases")
                .join(String::from(case.key.clone()))
                .join("family/source-carrier.v1.bin")
                .to_string_lossy()
                .into_owned(),
            sources,
        )?;
    }
    Ok(bytes)
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

struct CandidateDetachedIntervalV1 {
    interval: crate::private_kernel_observer::VerifiedKernelIntervalV1,
    controls_path: String,
    arm_monotonic_ns: u64,
    detach_monotonic_ns: u64,
    host_sources: Option<BTreeMap<String, Vec<u8>>>,
}

enum CandidateCapturedIntervalV1 {
    Enrolled(CandidateDetachedIntervalV1),
    Diagnostic(crate::private_kernel_observer::VerifiedKernelIntervalV1),
}
impl CandidateCapturedIntervalV1 {
    fn interval(&self) -> &crate::private_kernel_observer::VerifiedKernelIntervalV1 {
        match self {
            Self::Enrolled(value) => &value.interval,
            Self::Diagnostic(value) => value,
        }
    }
    fn into_interval(self) -> crate::private_kernel_observer::VerifiedKernelIntervalV1 {
        match self {
            Self::Enrolled(value) => value.interval,
            Self::Diagnostic(value) => value,
        }
    }
}

#[cfg(target_os = "linux")]
fn candidate_monotonic_ns() -> Result<u64> {
    Ok(memcordon_platform::test_support::private_observer_monotonic_ns()?)
}
#[cfg(not(target_os = "linux"))]
fn candidate_monotonic_ns() -> Result<u64> {
    Err(CiError::Message(
        "candidate interval clock requires native Linux".into(),
    ))
}

/// Each actual BPF interval is independently enrolled before execution. The
/// known-action interval closes with its immutable bytes before the product
/// interval is armed; no future per-case bundle is needed to calibrate it.
fn run_candidate_journal_interval<T>(
    journal: &mut crate::private_candidate_producer::CandidateProducerJournalV1,
    pinned: &memcordon_core::private_release_branch_v1::PrivatePolicyObserverIntentV1,
    case: &crate::private_candidate_producer::PreparedCandidateCaseV1,
    operation: impl FnOnce() -> Result<T>,
) -> Result<(T, CandidateDetachedIntervalV1)> {
    run_candidate_journal_interval_with_reuse(journal, pinned, case, None, operation)
}

fn run_candidate_journal_interval_with_reuse<T>(
    journal: &mut crate::private_candidate_producer::CandidateProducerJournalV1,
    pinned: &memcordon_core::private_release_branch_v1::PrivatePolicyObserverIntentV1,
    case: &crate::private_candidate_producer::PreparedCandidateCaseV1,
    reuse_pins: Option<&[(u64, u64); 3]>,
    operation: impl FnOnce() -> Result<T>,
) -> Result<(T, CandidateDetachedIntervalV1)> {
    use crate::private_kernel_observer::*;
    use crate::private_kernel_replay::IntervalPurposeV1;
    let probe = crate::private_probe_bundle::verify_probe_bundle(
        crate::private_probe_bundle::ExpectedProbeBundleV1 {
            bpf_source_sha256: pinned.bpf_source_sha256.clone(),
            loader_source_sha256: pinned.loader_source_sha256.clone(),
            object_sha256: pinned.object_sha256.clone(),
            loader_sha256: pinned.loader_sha256.clone(),
            agent_sha256: pinned.agent_sha256.clone(),
            agent_build_id: pinned.agent_build_id.clone(),
            request_entry_offset: pinned.request_entry_offset,
            request_exit_offset: pinned.request_exit_offset,
            allocation_entry_offset: pinned.allocation_entry_offset,
        },
    )?;
    let reader = observe_live_kernel_subject(std::process::id())?;
    let service = observe_installed_observer_subject(InstalledObserverRoleV1::SealedService)?;
    let broker = activate_installed_network_broker_for_observation()?;
    let expected = |key: DiagnosticSha256,
                    primary: LiveKernelSubjectV1,
                    secondary: LiveKernelSubjectV1| ExpectedKernelAdapterV1 {
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
    };
    let control = journal.prepare_case(
        &case.selector,
        IntervalPurposeV1::KnownControls,
        case.interval_id.ordinal,
    )?;
    let arm = candidate_monotonic_ns()?;
    journal.arm_before_execution(&control)?;
    let controls = crate::private_probe_controls::run_fixed_known_action_controls_with_id(
        &probe,
        expected(control.key.clone(), reader, service),
        control.interval_id.clone(),
    )?;
    let detach = candidate_monotonic_ns()?;
    let prefix = Path::new("candidate-c-v3/observer/intervals")
        .join(String::from(control.interval_id.storage_sha256()));
    let control_path = prefix.join("capture.bin").to_string_lossy().into_owned();
    let clock_path = prefix.join("clock.json").to_string_lossy().into_owned();
    journal.append_raw(
        control_path.clone(),
        controls.interval().capture_bytes()?.to_vec(),
    )?;
    journal.append_raw(
        clock_path.clone(),
        crate::private_observer_session::canonical_bytes(
            controls.interval().clock_inputs().ok_or_else(|| {
                CiError::Message("native control original clock inputs absent".into())
            })?,
        )?,
    )?;
    journal.append_raw(
        prefix
            .join("control-output.raw")
            .to_string_lossy()
            .into_owned(),
        controls.command_output().to_vec(),
    )?;
    journal.close_after_detach(
        &control,
        controls.interval(),
        control_path.clone(),
        vec![control_path.clone()],
        vec![clock_path],
        arm,
        detach,
    )?;
    let host_watch = if let Some(revision) = &case.recipe.host_preservation_source_sha256 {
        if revision
            != &crate::private_candidate_host_facts::host_preservation_source_revision_sha256()
        {
            return Err(CiError::Message(
                "host continuity source revision not approved".into(),
            ));
        }
        Some(memcordon_platform::test_support::HostNetworkWatchV1::start()?)
    } else {
        None
    };
    let arm_monotonic_ns = candidate_monotonic_ns()?;
    journal.arm_before_execution(case)?;
    let mut output = None;
    let operation = || {
        output = Some(operation()?);
        Ok(())
    };
    let interval = if let Some(pins) = reuse_pins {
        if case.recipe.reuse_source_sha256.as_ref()
            != Some(&memcordon_core::private_reuse_source_v1::reuse_source_revision_sha256())
            || !matches!(
                case.interval_id.purpose,
                IntervalPurposeV1::ReuseBlocked | IntervalPurposeV1::Recovery
            )
            || host_watch.is_some()
            || case.recipe.filter_install_source_sha256.is_some()
        {
            return Err(CiError::Message(
                "Reuse operand capture lacks exact reviewed source purpose".into(),
            ));
        }
        run_probe_interval_raw_with_reuse_sources(
            &probe,
            expected(case.key.clone(), reader, broker),
            controls.controls(),
            case.interval_id.clone(),
            pins,
            operation,
        )?
    } else if let Some(watch) = &host_watch {
        if case.recipe.filter_install_source_sha256.as_ref().is_some_and(|revision|revision!=&crate::private_candidate_filter_facility_facts::filter_install_source_revision_sha256()){return Err(CiError::Message("filter source revision not approved".into()));}
        run_probe_interval_raw_with_host_sources(
            &probe,
            expected(case.key.clone(), reader, broker),
            controls.controls(),
            case.interval_id.clone(),
            crate::private_kernel_replay::CaptureStageV2::Candidate,
            case.recipe.filter_install_source_sha256.is_some(),
            watch.object_pins(),
            operation,
        )?
    } else if case.recipe.filter_install_source_sha256.as_ref()
        == Some(
            &crate::private_candidate_filter_facility_facts::filter_install_source_revision_sha256(
            ),
        )
    {
        run_probe_interval_raw_with_filter_sources(
            &probe,
            expected(case.key.clone(), reader, broker),
            controls.controls(),
            case.interval_id.clone(),
            crate::private_kernel_replay::CaptureStageV2::Candidate,
            operation,
        )?
    } else {
        if case.recipe.filter_install_source_sha256.is_some() {
            return Err(CiError::Message(
                "candidate filter source opt-in is not the reviewed revision".into(),
            ));
        }
        run_probe_interval_raw_with_id(
            &probe,
            expected(case.key.clone(), reader, broker),
            controls.controls(),
            case.interval_id.clone(),
            operation,
        )?
    };
    let detach_monotonic_ns = candidate_monotonic_ns()?;
    let host_sources = host_watch.map(|watch| watch.finish()).transpose()?;
    Ok((
        output.ok_or_else(|| {
            CiError::Message("enrolled candidate operation was not invoked".into())
        })?,
        CandidateDetachedIntervalV1 {
            interval,
            controls_path: control_path,
            arm_monotonic_ns,
            detach_monotonic_ns,
            host_sources,
        },
    ))
}

/// Retains parsed measurements, never a semantic success bit. Completed
/// verification still demands every closed family and reopens every source.
fn record_candidate_replay_sources(
    journal: &mut crate::private_candidate_producer::CandidateProducerJournalV1,
    case: &crate::private_candidate_producer::PreparedCandidateCaseV1,
    detached: &CandidateDetachedIntervalV1,
    raw: &crate::private_protected_readback::StructuralProtectedNativeCaseV1,
    phases: &crate::private_candidate_producer::CandidateLivePhasesV1,
    prefix: &Path,
) -> Result<()> {
    use crate::private_candidate_replay::{CaseReplayFactsV1, ReplayLeafRoleV1, ReplayLeafV1};
    let path = |leaf: &str| prefix.join(leaf).to_string_lossy().into_owned();
    let capture = detached.interval.capture_bytes()?;
    let clock = detached
        .interval
        .clock_inputs()
        .ok_or_else(|| CiError::Message("candidate original clock source absent".into()))?;
    let clock_bytes = crate::private_observer_session::canonical_bytes(clock)?;
    let before = phases.pre.as_ref().ok_or_else(|| {
        CiError::Message("candidate independently held pre-exec source absent".into())
    })?;
    let parsed = crate::private_kernel_replay::parse_capture_v2_with_budget(
        capture,
        &case.key,
        crate::private_kernel_replay::CaptureStageV2::Candidate,
    )?;
    let authorization_rejected = case.selector == "private_tcp::authorization_uncertainty_retired";
    let after = if authorization_rejected {
        before
    } else {
        phases.baseline.as_ref().ok_or_else(|| {
            CiError::Message("candidate independently held early baseline source absent".into())
        })?
    };
    let stdio = raw
        .attachments
        .get(2)
        .ok_or_else(|| CiError::Message("candidate actual stdio source absent".into()))?;
    let mut common = if authorization_rejected {
        let calibrated = crate::private_process_clock::ParsedProcClockCalibrationV1::parse(clock)?;
        let event = parsed
            .events()
            .iter()
            .find(|event| {
                event.task.tid == before.pid
                    && calibrated.matches(
                        crate::private_kernel_observer::KernelTaskIdentityV1 {
                            pid: event.task.tid,
                            start_time: event.task.start_boottime_ns,
                            cgroup_inode: event.task.cgroup_inode,
                            time_ns_inode: event.task.time_ns_inode,
                        },
                        before.start_time_ticks,
                    )
            })
            .ok_or_else(|| {
                CiError::Message("candidate rejected target original kernel identity absent".into())
            })?;
        crate::private_live_fact_recording::CommonSourceFactsV1 {
            target: crate::private_candidate_replay::ReplayTaskV1 {
                tid: event.task.tid,
                tgid: event.task.tgid,
                start_boottime_ns: event.task.start_boottime_ns,
                cgroup_inode: event.task.cgroup_inode,
                time_ns_inode: event.task.time_ns_inode,
            },
            facts: Vec::new(),
        }
    } else {
        let netns = after
            .tasks
            .iter()
            .find(|task| task.tid == after.pid)
            .and_then(|task| task.namespace_inodes.get("net").copied());
        let expected =
            memcordon_core::private_release_case_v1::candidate_fixture_expected_response_v1(
                &raw.result.target,
                &case.selector,
                &case.challenge,
                netns,
                Some((after.executable_device, after.executable_inode)),
            )
            .map_err(|error| CiError::Message(error.into()))?;
        let response = if case.selector == DUAL_SELECTOR {
            let second = phases.second_baseline.as_ref().ok_or_else(|| {
                CiError::Message("dual independent second baseline absent".into())
            })?;
            let second_netns = second
                .tasks
                .iter()
                .find(|task| task.tid == second.pid)
                .and_then(|task| task.namespace_inodes.get("net").copied());
            let second_expected =
                memcordon_core::private_release_case_v1::candidate_fixture_expected_response_v1(
                    &raw.result.target,
                    &case.selector,
                    &case.challenge,
                    second_netns,
                    Some((second.executable_device, second.executable_inode)),
                )
                .map_err(|error| CiError::Message(error.into()))?;
            let mut exact = case.challenge.to_vec();
            exact.extend_from_slice(&expected);
            exact.extend_from_slice(&second_expected);
            if *stdio != exact {
                return Err(CiError::Message(
                    "dual original stdout differs from both independent READY codecs".into(),
                ));
            }
            journal.append_raw(
                path("second-response.raw"),
                stdio[case.challenge.len() + expected.len()..].to_vec(),
            )?;
            &stdio[case.challenge.len()..case.challenge.len() + expected.len()]
        } else {
            if expected.is_empty()
                || !stdio.starts_with(&case.challenge)
                || !stdio.ends_with(&expected)
            {
                return Err(CiError::Message(
                "candidate actual stdout does not end with independently derived fixture response"
                    .into(),
            ));
            }
            &stdio[stdio.len() - expected.len()..]
        };
        journal.append_raw(path("response.raw"), response.to_vec())?;
        crate::private_live_fact_recording::record_common_source_facts(
            capture,
            &case.key,
            crate::private_kernel_replay::CaptureStageV2::Candidate,
            &raw.result.target,
            &clock_bytes,
            before,
            after,
            path("response.raw"),
        )?
    };
    if !authorization_rejected {
        let image_path = journal.retain_shared_image(
            after
                .leaves
                .get("image.raw")
                .ok_or_else(|| CiError::Message("candidate held ELF bytes absent".into()))?
                .clone(),
        )?;
        for leaf in ["ancestors-before.json", "ancestors-after.json"] {
            journal.append_raw(
                path(leaf),
                after
                    .leaves
                    .get(leaf)
                    .ok_or_else(|| {
                        CiError::Message("candidate actual ELF ancestor source absent".into())
                    })?
                    .clone(),
            )?;
        }
        common
            .facts
            .push(crate::private_live_fact_recording::record_elf_source_fact(
                after,
                image_path,
                path("ancestors-before.json"),
                path("ancestors-after.json"),
            )?);
    }
    let retirement_target = if case.selector == CHILD_RUNTIME_SELECTOR {
        phases.post.as_ref().ok_or_else(|| {
            CiError::Message("candidate simultaneous held parent/thread source absent".into())
        })?
    } else {
        after
    };
    let mut held = vec![("target", retirement_target)];
    if let Some(second) = &phases.second_baseline {
        held.push(("target", second));
    }
    held.extend(phases.held_roles.iter().map(|(role, sample)| {
        (
            role.rsplit('/').next().expect("held role is nonempty"),
            sample,
        )
    }));
    let observer: serde_json::Value = crate::private_observer_session::strict_json(
        raw.attachments
            .get(3)
            .ok_or_else(|| CiError::Message("candidate raw observer absent".into()))?,
        1024 * 1024,
    )?;
    let branches: &[&str] = if case.selector == DUAL_SELECTOR {
        &["first", "second"]
    } else {
        &["settlement"]
    };
    let mut cgroup_bytes = Vec::new();
    for branch in branches {
        let cgroup = observer
            .get(*branch)
            .and_then(|value| value.get("cgroup_retirement_raw"))
            .filter(|value| !value.is_null())
            .ok_or_else(|| {
                CiError::Message("candidate actual cgroup retirement source absent".into())
            })?;
        let bytes = crate::private_observer_session::canonical_bytes(cgroup)?;
        let name = if case.selector == DUAL_SELECTOR {
            Path::new(if *branch == "first" {
                "dual-first"
            } else {
                "dual-second"
            })
            .join("cgroup-retirement-v1.json")
        } else {
            PathBuf::from("cgroup-retirement-v1.json")
        };
        journal.append_raw(
            path(name.to_str().expect("fixed source path is UTF-8")),
            bytes.clone(),
        )?;
        cgroup_bytes.push(bytes);
    }
    let mut retirement = crate::private_live_fact_recording::record_retirement_source_fact(
        parsed.events(),
        clock,
        &held,
        &cgroup_bytes,
        &crate::private_observer_session::canonical_bytes(&phases.namespace_closes)?,
        path("attempt.json"),
    )?;
    if case.selector == DUAL_SELECTOR {
        let crate::private_candidate_replay::CaseFactV1::Retirement { tasks, .. } = &mut retirement
        else {
            unreachable!("retirement recorder returns Retirement")
        };
        for task in tasks
            .iter_mut()
            .filter(|task| matches!(task.role.as_str(), "guardian" | "frontend"))
        {
            let branch = phases
                .held_roles
                .iter()
                .find(|(role, sample)| {
                    role.rsplit('/').next() == Some(task.role.as_str())
                        && sample.pid == task.task.tid
                })
                .and_then(|(role, _)| role.split_once('/').map(|(branch, _)| branch))
                .filter(|branch| matches!(*branch, "dual-first" | "dual-second"))
                .ok_or_else(|| {
                    CiError::Message("actual dual role child journal branch absent".into())
                })?;
            task.terminal_source_path = Some(path(
                &Path::new("journal")
                    .join(branch)
                    .join("attempt.json")
                    .to_string_lossy(),
            ));
        }
    }
    common.facts.push(retirement);
    if case.selector == "private_tcp::caller_identity_and_epoch_bound" {
        common.facts.push(
            crate::private_candidate_caller_facts::record_candidate_caller_fact(
                journal.descriptor(),
                path("request.json"),
            )?,
        );
    }
    let raw_leaves = crate::private_candidate_replay::expand_replay_payload(journal.raw_payload())?;
    let optional = |leaf: &str| raw_leaves.contains_key(&path(leaf)).then(|| path(leaf));
    let causal = crate::private_candidate_causal_facts::CandidateCausalPathsV1 {
        raw_leaves: raw_leaves.clone(),
        result_path: path("result.json"),
        request_path: path("request.json"),
        attempt_path: optional("attempt.json"),
        checkpoint_path: optional("journal/release-intent-v1.json"),
        checkpoint_metadata_path: optional("journal/release-intent-v1.json.metadata.json"),
        midpoint_path: optional("journal/terminal-join-midflight.json"),
        observer_path: path("observer.bin"),
        cleanup_path: path("cleanup.bin"),
        stdout_path: path("uncertain-stdout-v1.bin"),
        stderr_path: path("uncertain-stderr-v1.bin"),
        clock_path: path("clock.json"),
        dual: (case.selector == DUAL_SELECTOR).then(|| {
            crate::private_candidate_causal_facts::NativeDualPathsV1 {
                result_path: path("result.json"),
                request_path: path("request.json"),
                first_midpoint_path: path("journal/dual-first-midflight.json"),
                second_midpoint_path: path("journal/dual-second-midflight.json"),
                first_terminal_path: path("journal/dual-first/attempt.json"),
                second_terminal_path: path("journal/dual-second/attempt.json"),
                post_retirement_path: path("journal/dual-second-post-retirement.json"),
                first_sample_path: path("first-ready-samples.json"),
                second_sample_path: path("second-ready-samples.json"),
                post_sample_path: path("second-after-retirement-samples.json"),
                clock_path: path("clock.json"),
            }
        }),
    };
    let mut causal_sample_paths = Vec::new();
    for (leaf, sample) in [
        ("pre-samples.json", &phases.pre),
        ("baseline-samples.json", &phases.baseline),
        ("second-baseline-samples.json", &phases.second_baseline),
        ("first-ready-samples.json", &phases.first_ready),
        ("second-ready-samples.json", &phases.second_ready),
        ("post-samples.json", &phases.post),
        (
            "second-after-retirement-samples.json",
            &phases.second_after_retirement,
        ),
    ] {
        if let Some(sample) = sample {
            causal_sample_paths.push((path(leaf), sample));
        }
    }
    for (role, sample) in &phases.held_roles {
        causal_sample_paths.push((
            prefix
                .join("roles")
                .join(role)
                .join("held-samples.v1.bin")
                .to_string_lossy()
                .into_owned(),
            sample,
        ));
    }
    let causal_held = causal_sample_paths
        .iter()
        .map(|(path, sample)| (path.as_str(), *sample))
        .collect::<Vec<_>>();
    common.facts.extend(
        crate::private_candidate_causal_facts::record_candidate_causal_facts(
            raw,
            parsed.events(),
            clock,
            &common.target,
            &causal_held,
            &causal,
        )?,
    );
    if case.selector == "private_tcp::abi_alternate_entry_denied" {
        let family_prefix = Path::new("candidate-c-v3/cases")
            .join(String::from(case.key.clone()))
            .join("family");
        let family = |leaf: &str| family_prefix.join(leaf).to_string_lossy().into_owned();
        let branches = if raw.result.target == "x86_64-unknown-linux-gnu" {
            crate::private_candidate_abi_facts::NativeAbiBranchesV1::X86 {
                x32_path: family("x32-alternate.raw.json"),
                i386_path: family("i386-entry.raw.json"),
            }
        } else {
            crate::private_candidate_abi_facts::NativeAbiBranchesV1::Arm64 {
                arm32_path: family("arm32-alternate.raw.json"),
                helper_bytes_path: path("journal/abi-helper.raw"),
                helper_metadata_path: path("journal/abi-helper-metadata.json"),
            }
        };
        let sources = crate::private_candidate_abi_facts::NativeAbiSourcesV1 {
            result_path: path("result.json"),
            request_path: path("request.json"),
            attempt_path: path("attempt.json"),
            attachments:
                memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL
                    .map(|role| path(role.leaf())),
            branches,
        };
        common.facts.push(
            crate::private_candidate_abi_facts::record_candidate_abi_fact(
                sources,
                parsed.events(),
                clock,
                &common.target,
                raw.attempt_record
                    .as_ref()
                    .and_then(|attempt| attempt.checkpoint_filter_sha256())
                    .ok_or_else(|| {
                        CiError::Message("ABI original checkpoint filter absent".into())
                    })?,
                detached.interval.trace_sha256(),
                |path| {
                    raw_leaves.get(path).map(Vec::as_slice).ok_or_else(|| {
                        CiError::Message(format!("original ABI source absent: {path}"))
                    })
                },
            )?,
        );
    }
    let late = if case.selector == DUAL_SELECTOR {
        phases.first_ready.as_ref()
    } else {
        phases.post.as_ref()
    };
    let late_path = path(if case.selector == DUAL_SELECTOR {
        "first-ready-samples.json"
    } else {
        "post-samples.json"
    });
    let init_path = phases
        .held_roles
        .keys()
        .find(|role| {
            role.rsplit('/').next() == Some("namespace-init")
                && (case.selector != DUAL_SELECTOR || role.starts_with("dual-first/"))
        })
        .map(|role| {
            prefix
                .join("roles")
                .join(role)
                .join("held-samples.v1.bin")
                .to_string_lossy()
                .into_owned()
        });
    let network = crate::private_candidate_network_facts::CandidateNetworkPathsV1 {
        raw_leaves: raw_leaves.clone(),
        request_path: path("request.json"),
        response_path: path("response.raw"),
        held_sample_path: late_path.clone(),
        host_sample_path: late_path.clone(),
        init_sample_path: init_path,
    };
    let network_held = late
        .map(|sample| vec![(late_path.as_str(), sample)])
        .unwrap_or_default();
    common.facts.extend(
        crate::private_candidate_network_facts::record_candidate_network_facts(
            raw,
            parsed.events(),
            clock,
            &common.target,
            &network_held,
            &network,
        )?,
    );
    let spec = crate::private_case_semantics::closed_candidate_case_spec(
        &case.selector,
        &raw.result.target,
    )?;
    if spec
        .facts
        .contains(&crate::private_case_semantics::CaseFactKindV1::FacilityControls)
    {
        let record = journal
            .descriptor()
            .intervals
            .iter()
            .filter(|record| {
                record.logical_case_key == case.key
                    && record.generation == case.interval_id.generation
                    && record.purpose == "facility-controls"
            })
            .collect::<Vec<_>>();
        let [record] = record.as_slice() else {
            return Err(CiError::Message(
                "candidate Facility original physical interval absent or duplicated".into(),
            ));
        };
        let facility_prefix = Path::new(&record.capture_path)
            .parent()
            .ok_or_else(|| CiError::Message("Facility capture parent absent".into()))?;
        let facility_path = |leaf: &str| facility_prefix.join(leaf).to_string_lossy().into_owned();
        let sources = crate::private_candidate_facility_replay::NativeFacilitySourcesV1 {
            schema_version: 1,
            capture_path: record.capture_path.clone(),
            clock_path: facility_path("clock.json"),
            admission_path: facility_path("request.json"),
            report_path: facility_path("facility-source-v1.json"),
            outer_gate_path: facility_path("facility-helper-outer-v1.json"),
            outer_ack_path: facility_path("facility-helper-outer-v1.ack"),
            outer_held_path: facility_path("outer-held.v1.bin"),
            private_gate_path: facility_path("facility-helper-private-v1.json"),
            private_ack_path: facility_path("facility-helper-private-v1.ack"),
            private_held_path: facility_path("private-held.v1.bin"),
            source_outer_held_path: (case.selector
                == "private_tcp::io_uring_and_pidfd_import_denied")
                .then(|| facility_path("source-outer-held.v1.bin")),
            source_private_held_path: (case.selector
                == "private_tcp::io_uring_and_pidfd_import_denied")
                .then(|| facility_path("source-private-held.v1.bin")),
            product_request_path: Some(path("request.json")),
        };
        let filter = raw
            .attempt_record
            .as_ref()
            .and_then(|attempt| attempt.checkpoint_filter_sha256())
            .ok_or_else(|| {
                CiError::Message("Facility product original checkpoint filter absent".into())
            })?;
        let exact_response = raw_leaves
            .get(&path("response.raw"))
            .ok_or_else(|| CiError::Message("Facility product actual response absent".into()))?;
        let expected = crate::private_candidate_replay::ExpectedCaseSubjectV1 {
            selector: &case.selector,
            result_key: &case.key,
            fixture_sha256: &case.recipe.fixture_sha256,
            filter_sha256: filter,
            fixture_argv: &case.argv,
            uid: case.recipe.uid,
            gid: case.recipe.gid,
            groups: &case.recipe.groups,
            port: case.port,
            challenge: &case.challenge,
            auxiliary_semantics_sha256: case.recipe.auxiliary_semantics_sha256.as_ref(),
            filter_install_source_sha256: case.recipe.filter_install_source_sha256.as_ref(),
            facility_source_sha256: case.recipe.facility_source_sha256.as_ref(),
            host_preservation_source_sha256: case.recipe.host_preservation_source_sha256.as_ref(),
            reuse_source_sha256: case.recipe.reuse_source_sha256.as_ref(),
            exact_response,
        };
        let facility_events = crate::private_kernel_replay::parse_capture_v2(
            raw_leaves.get(&sources.capture_path).ok_or_else(|| {
                CiError::Message("Facility actual original capture absent".into())
            })?,
            &case.key,
        )?;
        common.facts.extend(
            crate::private_candidate_facility_replay::record_facility_source_facts(
                journal.descriptor(),
                &expected,
                &common.target,
                &record.capture_path,
                case.interval_id.generation,
                sources,
                facility_events.events(),
                |path| {
                    raw_leaves.get(path).cloned().ok_or_else(|| {
                        CiError::Message(format!("Facility original source absent: {path}"))
                    })
                },
            )?,
        );
    }
    if spec
        .facts
        .contains(&crate::private_case_semantics::CaseFactKindV1::HostState)
    {
        if case.recipe.host_preservation_source_sha256.as_ref()
            != Some(
                &crate::private_candidate_host_facts::host_preservation_source_revision_sha256(),
            )
        {
            return Err(CiError::Message(
                "host preservation requires explicitly approved continuity source revision".into(),
            ));
        }
        let source = detached
            .host_sources
            .as_ref()
            .ok_or_else(|| CiError::Message("actual host continuity source absent".into()))?;
        let timing = detached
            .interval
            .observation_timing()
            .ok_or_else(|| CiError::Message("host interval measured endpoints absent".into()))?;
        crate::private_candidate_host_facts::verify_host_sources(
            source,
            parsed.events(),
            timing.armed_monotonic_ns,
            timing.detached_monotonic_ns,
        )?;
        crate::private_candidate_host_facts::verify_host_reader_clock(
            source,
            parsed.events(),
            clock,
        )?;
        common
            .facts
            .push(crate::private_candidate_replay::CaseFactV1::NativeHostV1 {
                sources: crate::private_candidate_host_facts::NativeHostSourcesV1 {
                    schema_version: 1,
                    source_path: path("host-continuity.v1.bin"),
                },
            });
    }
    if spec
        .facts
        .contains(&crate::private_case_semantics::CaseFactKindV1::Filter)
    {
        if case.recipe.filter_install_source_sha256.as_ref()!=Some(&crate::private_candidate_filter_facility_facts::filter_install_source_revision_sha256()){return Err(CiError::Message("installed filter source requires explicitly approved revision".into()));}
        let sources = crate::private_candidate_filter_facility_facts::NativeFilterSourcesV1 {
            schema_version: 1,
            pre_path: path("pre-samples.json"),
            baseline_path: path("baseline-samples.json"),
            instruction_path: path("installed-filter.raw"),
        };
        let filter = raw
            .attempt_record
            .as_ref()
            .and_then(|attempt| attempt.checkpoint_filter_sha256())
            .ok_or_else(|| {
                CiError::Message("installed filter actual checkpoint pin absent".into())
            })?;
        let (facts, bytes) =
            crate::private_candidate_filter_facility_facts::record_filter_source_facts(
                parsed.events(),
                clock,
                &common.target,
                before,
                after,
                sources,
                filter,
            )?;
        journal.append_raw(path("installed-filter.raw"), bytes)?;
        common.facts.extend(facts);
    }
    if case.selector == UNIX_INTENT_SELECTOR {
        let sources = crate::private_candidate_unix_facts::NativeUnixSourcesV1 {
            result_path: path("result.json"),
            request_path: path("request.json"),
            gate_path: path("unix-intent-gate.json"),
            ack_path: path("unix-intent-ack.json"),
            held_sample_path: path("post-samples.json"),
            response_path: path("response.raw"),
        };
        crate::private_candidate_unix_facts::verify_native_unix_sources(
            &sources,
            &common.target,
            parsed.events(),
            clock,
            |path| {
                raw_leaves
                    .get(path)
                    .map(Vec::as_slice)
                    .ok_or_else(|| CiError::Message(format!("original Unix source absent: {path}")))
            },
        )?;
        common
            .facts
            .push(crate::private_candidate_replay::CaseFactV1::NativeUnixV1 { sources });
    }
    let mut closed_facts = Vec::with_capacity(spec.facts.len());
    for required in spec.facts {
        if required == crate::private_case_semantics::CaseFactKindV1::Reuse
            && case.selector == memcordon_core::private_reuse_source_v1::REUSE_SELECTOR_V1
            && case.recipe.reuse_source_sha256.as_ref()
                == Some(&memcordon_core::private_reuse_source_v1::reuse_source_revision_sha256())
        {
            continue;
        }
        let positions = common
            .facts
            .iter()
            .enumerate()
            .filter(|(_, fact)| fact.kind() == required)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let [position] = positions.as_slice() else {
            return Err(CiError::Message(format!(
                "candidate actual source family {required:?} is missing or duplicated for {}",
                case.selector
            )));
        };
        closed_facts.push(common.facts.remove(*position));
    }
    let facts = CaseReplayFactsV1 {
        schema_version: 1,
        selector: case.selector.clone(),
        result_key: case.key.clone(),
        generation: case.interval_id.generation,
        interval_id: case.interval_id.storage_sha256(),
        target: common.target,
        facts: closed_facts,
        clock_path: path("clock.json"),
        held_sample_paths: if authorization_rejected {
            Vec::new()
        } else {
            vec![path("baseline-samples.json")]
        },
    };
    if case.selector == memcordon_core::private_reuse_source_v1::REUSE_SELECTOR_V1 {
        if case.interval_id.purpose != crate::private_kernel_replay::IntervalPurposeV1::ReuseFirst
            || case.recipe.reuse_source_sha256.as_ref()
                != Some(&memcordon_core::private_reuse_source_v1::reuse_source_revision_sha256())
        {
            return Err(CiError::Message(
                "Reuse first source is not explicitly approved".into(),
            ));
        }
        // This is visibly pending measurement data, never a family bundle or
        // proof. Only the three closed physical intervals can complete it.
        journal.append_raw(
            path("pending-facts.json"),
            crate::private_observer_session::canonical_bytes(&facts)?,
        )?;
        return Ok(());
    }
    if case.interval_id.purpose == crate::private_kernel_replay::IntervalPurposeV1::Historical {
        // Historical helpers are source operands of the one all25 caller
        // case, not additional candidate cases or nested semantic carriers.
        journal.append_raw(
            path("facts.json"),
            crate::private_observer_session::canonical_bytes(&facts)?,
        )?;
        return Ok(());
    }
    let controls = raw_leaves
        .get(&detached.controls_path)
        .ok_or_else(|| CiError::Message("candidate original known-action controls absent".into()))?
        .clone();
    let leaves = vec![
        ReplayLeafV1 {
            role: ReplayLeafRoleV1::Facts,
            ordinal: 0,
            bytes: crate::private_observer_session::canonical_bytes(&facts)?,
        },
        ReplayLeafV1 {
            role: ReplayLeafRoleV1::Request,
            ordinal: 0,
            bytes: raw.candidate_request_bytes.clone(),
        },
        ReplayLeafV1 {
            role: ReplayLeafRoleV1::Clock,
            ordinal: 0,
            bytes: clock_bytes,
        },
        ReplayLeafV1 {
            role: ReplayLeafRoleV1::Controls,
            ordinal: 0,
            bytes: controls,
        },
    ];
    let bundle = crate::private_candidate_replay::encode_replay_bundle(&leaves)?;
    let bundle_path = Path::new("candidate-c-v3/cases")
        .join(String::from(case.key.clone()))
        .join("family/replay-bundle.v1.bin");
    journal.append_raw(bundle_path.to_string_lossy().into_owned(), bundle)?;
    Ok(())
}

/// A separately armed decision-only source interval. The ordinary positive
/// capture cannot stand in for absence of allocation in this rejection.
fn run_candidate_caller_spoof_source(
    journal: &mut crate::private_candidate_producer::CandidateProducerJournalV1,
    plan: &crate::private_candidate_producer::StaticCandidateProducerIntentV1,
    parent: &crate::private_candidate_producer::PreparedCandidateCaseV1,
) -> Result<()> {
    use crate::private_kernel_replay::IntervalPurposeV1;
    const SELECTOR: &str = "private_tcp::caller_identity_and_epoch_bound";
    let spoof =
        crate::private_candidate_caller_frames::caller_spoof_challenge_v1(&parent.challenge);
    let mut case = journal.prepare_case(SELECTOR, IntervalPurposeV1::CallerSpoof, 0)?;
    case.challenge = parent.challenge;
    case.key =
        private_release_case_key_v1(PrivateReleaseStageV1::CandidateCapability, SELECTOR, &spoof)
            .map_err(CiError::Message)?;
    case.interval_id.logical_case_key = case.key.clone();
    let directory = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1)
        .join("caller-spoof-v1")
        .join(String::from(parent.key.clone()));
    if !matches!(fs::symlink_metadata(&directory),Err(error) if error.kind()==std::io::ErrorKind::NotFound)
    {
        return Err(CiError::Message(
            "independent caller auxiliary key already exists".into(),
        ));
    }
    let arguments = [
        OsString::from("package"),
        OsString::from("release-case-caller-spoof"),
        OsString::from("--stage"),
        OsString::from("candidate-capability"),
        OsString::from("--selector"),
        OsString::from(SELECTOR),
        OsString::from("--challenge"),
        OsString::from(hex::encode(parent.challenge)),
    ];
    let mut sampled = crate::private_candidate_producer::CandidateCallerSourcesV1::default();
    let (witness, detached) =
        run_candidate_journal_interval(journal, &plan.observer, &case, || {
            let (process, _) = supervise_private_case_process_with_observer(
                Path::new(AGENT),
                &arguments,
                Duration::from_secs(60),
                || {
                    if crate::private_candidate_producer::sample_candidate_caller_if_ready(
                        &directory,
                        parent,
                        &plan.observer.agent_sha256,
                        &mut sampled,
                    )? {
                        Ok(Some(()))
                    } else {
                        Ok(None)
                    }
                },
            )?;
            if !process.status.success() {
                return Err(CiError::Message(
                    "independent caller native producer failed".into(),
                ));
            }
            let bytes = crate::private_protected_readback::read_protected_raw_case_file(
                &directory.join("caller-rejection-v1.json"),
            )?;
            crate::private_candidate_caller_frames::parse_candidate_caller_frames_v1(
                &bytes,
                &parent.challenge,
                parent.recipe.uid,
                parent.recipe.gid,
            )?;
            Ok(bytes)
        })?;
    let prefix = Path::new("candidate-c-v3/observer/intervals")
        .join(String::from(case.interval_id.storage_sha256()));
    let path = |leaf: &str| prefix.join(leaf).to_string_lossy().into_owned();
    let capture = path("capture.bin");
    journal.append_raw(capture.clone(), detached.interval.capture_bytes()?.to_vec())?;
    let clock = path("clock.json");
    journal.append_raw(
        clock.clone(),
        crate::private_observer_session::canonical_bytes(
            detached
                .interval
                .clock_inputs()
                .ok_or_else(|| CiError::Message("caller original reader clock absent".into()))?,
        )?,
    )?;
    let admission = sampled
        .admission
        .ok_or_else(|| CiError::Message("caller independently observed admission absent".into()))?;
    let ready = sampled
        .ready
        .ok_or_else(|| CiError::Message("caller independently observed ready absent".into()))?;
    let sample = sampled.sample.ok_or_else(|| {
        CiError::Message("caller independently held credential source absent".into())
    })?;
    let image = journal.retain_shared_image(
        sample
            .leaves
            .get("image.raw")
            .ok_or_else(|| CiError::Message("caller original held ELF absent".into()))?
            .clone(),
    )?;
    let mut sources = vec![clock.clone()];
    for (name, bytes) in [
        ("request.json", admission),
        ("caller-ready-v1.json", ready),
        ("caller-rejection-v1.json", witness),
        (
            "caller-held.v1.bin",
            crate::private_source_carrier::encode_held_source(&sample, image)?,
        ),
        (
            "caller-ready-v1.ack",
            crate::private_protected_readback::read_protected_raw_case_file(
                &directory.join("caller-ready-v1.ack"),
            )?,
        ),
    ] {
        let name = path(name);
        journal.append_raw(name.clone(), bytes)?;
        sources.push(name);
    }
    journal.close_after_detach(
        &case,
        &detached.interval,
        capture,
        vec![detached.controls_path],
        sources,
        detached.arm_monotonic_ns,
        detached.detach_monotonic_ns,
    )
}

/// The disposable valid-context helper is observed in its own physical
/// interval, before any ordinary product target is admitted. It is not a
/// clean-FD exception for that later target.
fn run_candidate_facility_source(
    journal: &mut crate::private_candidate_producer::CandidateProducerJournalV1,
    plan: &crate::private_candidate_producer::StaticCandidateProducerIntentV1,
    parent: &crate::private_candidate_producer::PreparedCandidateCaseV1,
) -> Result<()> {
    use crate::private_kernel_replay::IntervalPurposeV1;
    let revision = memcordon_core::private_facility_source_v1::facility_source_revision_sha256();
    if parent.recipe.facility_source_sha256.as_ref() != Some(&revision) {
        return Err(CiError::Message(
            "candidate Facility source requires explicitly protected revision".into(),
        ));
    }
    let ordinal = parent
        .interval_id
        .ordinal
        .checked_add(1000)
        .ok_or_else(|| CiError::Message("Facility controls ordinal overflow".into()))?;
    let mut case = journal.prepare_case(
        &parent.selector,
        IntervalPurposeV1::FacilityControls,
        ordinal,
    )?;
    case.challenge = parent.challenge;
    case.key = parent.key.clone();
    case.interval_id.logical_case_key = parent.key.clone();
    // The explicitly approved Facility protocol requires two actual installed
    // programs; its own physical capture requests source16 independently of
    // whether the later product selector needs a Filter family.
    case.recipe.filter_install_source_sha256 = Some(
        crate::private_candidate_filter_facility_facts::filter_install_source_revision_sha256(),
    );
    case.recipe.host_preservation_source_sha256 = None;
    let generation = journal
        .descriptor()
        .generations
        .iter()
        .find(|generation| generation.generation == case.interval_id.generation)
        .ok_or_else(|| CiError::Message("Facility enrolled generation absent".into()))?
        .clone();
    let directory = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1)
        .join("facility-controls-v1")
        .join(String::from(parent.key.clone()));
    if !matches!(fs::symlink_metadata(&directory),Err(error)if error.kind()==std::io::ErrorKind::NotFound)
    {
        return Err(CiError::Message(
            "candidate Facility auxiliary directory already exists".into(),
        ));
    }
    let arguments = [
        OsString::from("release-facility-controls"),
        OsString::from("candidate-capability"),
        OsString::from(&parent.selector),
        OsString::from(hex::encode(parent.challenge)),
        OsString::from("--source-revision"),
        OsString::from(String::from(revision)),
    ];
    let mut sampled =
        crate::private_candidate_facility_live::CandidateFacilityLiveSourcesV1::default();
    let (report, detached) =
        run_candidate_journal_interval(journal, &plan.observer, &case, || {
            let (process, observed) = supervise_private_case_process_with_observer(
                Path::new(AGENT),
                &arguments,
                Duration::from_secs(120),
                || {
                    if crate::private_candidate_facility_live::sample_candidate_facility_if_ready(
                        &directory,
                        parent,
                        &generation,
                        &plan.observer.agent_sha256,
                        &mut sampled,
                    )? {
                        Ok(Some(()))
                    } else {
                        Ok(None)
                    }
                },
            )?;
            if !process.status.success() || observed.is_none() {
                return Err(CiError::Message(
                    "candidate Facility actual helper failed or missed held phases".into(),
                ));
            }
            crate::private_protected_readback::read_protected_raw_case_file(
                &directory.join("facility-source-v1.json"),
            )
        })?;
    let prefix = Path::new("candidate-c-v3/observer/intervals")
        .join(String::from(case.interval_id.storage_sha256()));
    let path = |leaf: &str| prefix.join(leaf).to_string_lossy().into_owned();
    let capture = path("capture.bin");
    let clock = path("clock.json");
    journal.append_raw(capture.clone(), detached.interval.capture_bytes()?.to_vec())?;
    journal.append_raw(
        clock.clone(),
        crate::private_observer_session::canonical_bytes(
            detached
                .interval
                .clock_inputs()
                .ok_or_else(|| CiError::Message("Facility original reader clock absent".into()))?,
        )?,
    )?;
    let mut sources = vec![clock];
    sampled
        .originals
        .insert("facility-source-v1.json".into(), report);
    for (name, bytes) in sampled.originals {
        let name = path(&name);
        journal.append_raw(name.clone(), bytes)?;
        sources.push(name);
    }
    for (name, sample) in sampled.held {
        let image = journal.retain_shared_image(
            sample
                .leaves
                .get("image.raw")
                .ok_or_else(|| CiError::Message("Facility held original ELF absent".into()))?
                .clone(),
        )?;
        let name = path(&name);
        journal.append_raw(
            name.clone(),
            crate::private_source_carrier::encode_held_source(&sample, image)?,
        )?;
        sources.push(name);
    }
    journal.close_after_detach(
        &case,
        &detached.interval,
        capture,
        vec![detached.controls_path],
        sources,
        detached.arm_monotonic_ns,
        detached.detach_monotonic_ns,
    )
}

/// Actual first physical retirement is already closed. Both subsequent
/// helpers use its original owned objects, never a fresh attempt directory.
fn run_candidate_reuse_sources(
    journal: &mut crate::private_candidate_producer::CandidateProducerJournalV1,
    plan: &crate::private_candidate_producer::StaticCandidateProducerIntentV1,
    parent: &crate::private_candidate_producer::PreparedCandidateCaseV1,
    original: &crate::private_protected_readback::StructuralProtectedNativeCaseV1,
) -> Result<()> {
    use crate::private_candidate_replay::{
        CaseReplayFactsV1, ExpectedCaseSubjectV1, ReplayLeafRoleV1, ReplayLeafV1,
    };
    use crate::private_candidate_reuse_facts::{NativeReuseSourcesV1, ReusePhaseSourcesV1};
    use crate::private_kernel_replay::IntervalPurposeV1;
    use memcordon_core::private_reuse_source_v1::*;
    let revision = reuse_source_revision_sha256();
    if parent.selector != REUSE_SELECTOR_V1
        || parent.recipe.reuse_source_sha256.as_ref() != Some(&revision)
        || parent.interval_id.purpose != IntervalPurposeV1::ReuseFirst
    {
        return Err(CiError::Message(
            "candidate three-interval Reuse is not explicitly approved".into(),
        ));
    }
    let marker = original
        .fault_marker_bytes
        .as_ref()
        .ok_or_else(|| CiError::Message("Reuse original owned marker absent".into()))?;
    let record = original
        .attempt_record_bytes
        .as_ref()
        .ok_or_else(|| CiError::Message("Reuse original retiring journal absent".into()))?;
    let directory =
        Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(String::from(parent.key.clone()));
    let mut held = crate::private_candidate_reuse_live::CandidateReuseLiveV1::hold(
        &directory, marker, record,
    )?;
    let generation = journal
        .descriptor()
        .generations
        .iter()
        .find(|entry| entry.generation == parent.interval_id.generation)
        .ok_or_else(|| CiError::Message("Reuse original enrolled generation absent".into()))?
        .clone();
    let mut phase_sources = Vec::new();
    for (phase, purpose, offset) in [
        (
            ReuseSourcePhaseV1::Blocked,
            IntervalPurposeV1::ReuseBlocked,
            2000_u32,
        ),
        (
            ReuseSourcePhaseV1::Recover,
            IntervalPurposeV1::Recovery,
            3000_u32,
        ),
    ] {
        let ordinal = parent
            .interval_id
            .ordinal
            .checked_add(offset)
            .ok_or_else(|| CiError::Message("Reuse source ordinal overflow".into()))?;
        let mut case = journal.prepare_case(&parent.selector, purpose, ordinal)?;
        case.challenge = parent.challenge;
        case.key = parent.key.clone();
        case.interval_id.logical_case_key = parent.key.clone();
        case.recipe.host_preservation_source_sha256 = None;
        case.recipe.filter_install_source_sha256 = None;
        held.helper = None;
        held.originals.clear();
        let args = [
            OsString::from("release-case-reuse-source"),
            OsString::from("candidate-capability"),
            OsString::from(&parent.selector),
            OsString::from(hex::encode(parent.challenge)),
            OsString::from("--source-revision"),
            OsString::from(String::from(revision.clone())),
            OsString::from("--phase"),
            OsString::from(match phase {
                ReuseSourcePhaseV1::Blocked => "blocked",
                ReuseSourcePhaseV1::Recover => "recover",
            }),
        ];
        let pins = held.pins;
        let (_, detached) = run_candidate_journal_interval_with_reuse(
            journal,
            &plan.observer,
            &case,
            Some(&pins),
            || {
                let (process, sampled) = supervise_private_case_process_with_observer(
                    Path::new(AGENT),
                    &args,
                    Duration::from_secs(120),
                    || {
                        if held.sample_if_ready(
                            phase,
                            &case,
                            &generation,
                            &plan.observer.agent_sha256,
                        )? {
                            Ok(Some(()))
                        } else {
                            Ok(None)
                        }
                    },
                )?;
                if !process.status.success() || sampled.is_none() {
                    return Err(CiError::Message(
                        "actual Reuse helper failed or never reached independent held gate".into(),
                    ));
                }
                // This independent readback is inside operation_end/detach.
                held.retain_after(phase)?;
                Ok(())
            },
        )?;
        let prefix = Path::new("candidate-c-v3/observer/intervals")
            .join(String::from(case.interval_id.storage_sha256()));
        let path = |name: &str| prefix.join(name).to_string_lossy().into_owned();
        let capture = path("capture.bin");
        let clock = path("clock.json");
        journal.append_raw(capture.clone(), detached.interval.capture_bytes()?.to_vec())?;
        journal.append_raw(
            clock.clone(),
            crate::private_observer_session::canonical_bytes(
                detached
                    .interval
                    .clock_inputs()
                    .ok_or_else(|| CiError::Message("Reuse original reader clock absent".into()))?,
            )?,
        )?;
        let mut sample_paths = vec![clock.clone()];
        for (name, bytes) in std::mem::take(&mut held.originals) {
            let name = path(&name);
            journal.append_raw(name.clone(), bytes)?;
            sample_paths.push(name);
        }
        let helper = held
            .helper
            .take()
            .ok_or_else(|| CiError::Message("Reuse actual root helper sample absent".into()))?;
        let image = journal.retain_shared_image(
            helper
                .leaves
                .get("image.raw")
                .ok_or_else(|| CiError::Message("Reuse held helper ELF source absent".into()))?
                .clone(),
        )?;
        let helper_path = path("helper-held.v1.bin");
        journal.append_raw(
            helper_path.clone(),
            crate::private_source_carrier::encode_held_source(&helper, image)?,
        )?;
        sample_paths.push(helper_path.clone());
        journal.close_after_detach(
            &case,
            &detached.interval,
            capture.clone(),
            vec![detached.controls_path],
            sample_paths,
            detached.arm_monotonic_ns,
            detached.detach_monotonic_ns,
        )?;
        phase_sources.push(ReusePhaseSourcesV1 {
            capture_path: capture,
            clock_path: clock,
            admission_path: path("admission.json"),
            gate_path: path("gate.json"),
            ack_path: path("ack.json"),
            helper_path,
            objects_path: path("objects.json"),
            report_path: path("report.json"),
            after_path: path("after.json"),
        });
    }
    let first = journal
        .descriptor()
        .intervals
        .iter()
        .find(|entry| entry.interval_id == parent.interval_id.storage_sha256())
        .ok_or_else(|| CiError::Message("Reuse first physical enrollment absent".into()))?
        .clone();
    let prefix = Path::new("candidate-c-v3/observer/intervals")
        .join(String::from(parent.interval_id.storage_sha256()));
    let path = |name: &str| prefix.join(name).to_string_lossy().into_owned();
    let mut phases = phase_sources.into_iter();
    let sources = NativeReuseSourcesV1 {
        result_path: path("result.json"),
        request_path: path("request.json"),
        attempt_path: path("attempt.json"),
        marker_path: path("attempt.json.new"),
        attachments: memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL
            .map(|role| path(role.leaf())),
        first_capture_path: first.capture_path.clone(),
        blocked: phases.next().expect("two literal Reuse phases"),
        recovery: phases.next().expect("two literal Reuse phases"),
    };
    let raw = crate::private_source_carrier::expand_source_payload(journal.raw_payload())?;
    let leaf = |path: &str| {
        raw.get(path).cloned().ok_or_else(|| {
            CiError::Message(format!("Reuse actual acknowledged source absent: {path}"))
        })
    };
    let mut facts: CaseReplayFactsV1 = crate::private_observer_session::strict_json(
        &leaf(&path("pending-facts.json"))?,
        8 * 1024 * 1024,
    )?;
    let filter = original
        .attempt_record
        .as_ref()
        .and_then(|attempt| attempt.checkpoint_filter_sha256())
        .ok_or_else(|| CiError::Message("Reuse original checkpoint filter absent".into()))?;
    let response = leaf(&path("response.raw"))?;
    let expected = ExpectedCaseSubjectV1 {
        selector: &parent.selector,
        result_key: &parent.key,
        fixture_sha256: &parent.recipe.fixture_sha256,
        filter_sha256: filter,
        fixture_argv: &parent.argv,
        uid: parent.recipe.uid,
        gid: parent.recipe.gid,
        groups: &parent.recipe.groups,
        port: parent.port,
        challenge: &parent.challenge,
        auxiliary_semantics_sha256: parent.recipe.auxiliary_semantics_sha256.as_ref(),
        filter_install_source_sha256: parent.recipe.filter_install_source_sha256.as_ref(),
        facility_source_sha256: parent.recipe.facility_source_sha256.as_ref(),
        host_preservation_source_sha256: parent.recipe.host_preservation_source_sha256.as_ref(),
        reuse_source_sha256: parent.recipe.reuse_source_sha256.as_ref(),
        exact_response: &response,
    };
    facts.facts.extend(
        crate::private_candidate_reuse_facts::record_reuse_source_facts(
            journal.descriptor(),
            &expected,
            parent.interval_id.generation,
            sources,
            leaf,
        )?,
    );
    let spec =
        crate::private_case_semantics::closed_case_spec(&parent.selector, &plan.subject.target)?;
    let mut ordered = Vec::new();
    for kind in spec.facts {
        let indexes = facts
            .facts
            .iter()
            .enumerate()
            .filter(|(_, fact)| fact.kind() == kind)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let [index] = indexes.as_slice() else {
            return Err(CiError::Message(
                "Reuse completed source family missing or duplicated".into(),
            ));
        };
        ordered.push(facts.facts.remove(*index));
    }
    if !facts.facts.is_empty() {
        return Err(CiError::Message(
            "Reuse pending source invents additional family".into(),
        ));
    }
    facts.facts = ordered;
    let controls = first
        .controls_paths
        .first()
        .ok_or_else(|| CiError::Message("Reuse original known controls absent".into()))?;
    let leaves = [
        ReplayLeafV1 {
            role: ReplayLeafRoleV1::Facts,
            ordinal: 0,
            bytes: crate::private_observer_session::canonical_bytes(&facts)?,
        },
        ReplayLeafV1 {
            role: ReplayLeafRoleV1::Request,
            ordinal: 0,
            bytes: original.candidate_request_bytes.clone(),
        },
        ReplayLeafV1 {
            role: ReplayLeafRoleV1::Clock,
            ordinal: 0,
            bytes: raw
                .get(&path("clock.json"))
                .ok_or_else(|| CiError::Message("Reuse first original clock absent".into()))?
                .clone(),
        },
        ReplayLeafV1 {
            role: ReplayLeafRoleV1::Controls,
            ordinal: 0,
            bytes: raw
                .get(controls)
                .ok_or_else(|| {
                    CiError::Message("Reuse first original controls bytes absent".into())
                })?
                .clone(),
        },
    ];
    let bundle = crate::private_candidate_replay::encode_replay_bundle(&leaves)?;
    journal.append_representation(
        Path::new("candidate-c-v3/cases")
            .join(String::from(parent.key.clone()))
            .join("family/replay-bundle.v1.bin")
            .to_string_lossy()
            .into_owned(),
        bundle,
    )
}

fn retain_candidate_raw_interval(
    journal: &mut crate::private_candidate_producer::CandidateProducerJournalV1,
    case: &crate::private_candidate_producer::PreparedCandidateCaseV1,
    detached: &CandidateDetachedIntervalV1,
    raw: &crate::private_protected_readback::StructuralProtectedNativeCaseV1,
    phases: &crate::private_candidate_producer::CandidateLivePhasesV1,
    collector: Option<&DiagnosticSha256>,
) -> Result<()> {
    let prefix = Path::new("candidate-c-v3/observer/intervals")
        .join(String::from(case.interval_id.storage_sha256()));
    let path = |leaf: &str| prefix.join(leaf).to_string_lossy().into_owned();
    let case_prefix = Path::new("candidate-c-v3/cases").join(String::from(case.key.clone()));
    let capture = if let Some(collector) = collector {
        case_prefix
            .join(format!(
                "kernel-{}.capture.bin",
                String::from(collector.clone())
            ))
            .to_string_lossy()
            .into_owned()
    } else {
        path("capture.bin")
    };
    let clock = path("clock.json");
    journal.append_raw(capture.clone(), detached.interval.capture_bytes()?.to_vec())?;
    journal.append_raw(
        clock.clone(),
        crate::private_observer_session::canonical_bytes(
            detached.interval.clock_inputs().ok_or_else(|| {
                CiError::Message("native candidate original clock inputs absent".into())
            })?,
        )?,
    )?;
    journal.append_raw(path("request.json"), raw.candidate_request_bytes.clone())?;
    journal.append_raw(path("result.json"), serde_json::to_vec(&raw.result)?)?;
    if collector.is_some() {
        journal.append_raw(
            case_prefix
                .join("result.json")
                .to_string_lossy()
                .into_owned(),
            serde_json::to_vec(&raw.result)?,
        )?;
    }
    if let Some(bytes) = &raw.attempt_record_bytes {
        journal.append_raw(path("attempt.json"), bytes.clone())?;
    }
    if let Some(bytes) = &raw.fault_marker_bytes {
        journal.append_raw(path("attempt.json.new"), bytes.clone())?;
    }
    if let Some(bytes) = &raw.checkpoint_gate_bytes {
        journal.append_raw(path("checkpoint-gate.json"), bytes.clone())?;
    }
    for (role, bytes) in
        memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL
            .into_iter()
            .zip(&raw.attachments)
    {
        journal.append_raw(path(role.leaf()), bytes.clone())?;
        if collector.is_some() {
            journal.append_raw(
                case_prefix.join(role.leaf()).to_string_lossy().into_owned(),
                bytes.clone(),
            )?;
        }
    }
    let mut samples = vec![clock, path("request.json")];
    if case.selector == memcordon_core::private_reuse_source_v1::REUSE_SELECTOR_V1 {
        samples.extend([
            path("result.json"),
            path("attempt.json"),
            path("attempt.json.new"),
        ]);
        samples.extend(
            memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL
                .into_iter()
                .map(|role| path(role.leaf())),
        );
    }
    if let Some(source) = &detached.host_sources {
        let name = path("host-continuity.v1.bin");
        journal.append_raw(
            name.clone(),
            crate::private_source_carrier::encode_source_carrier(source)?,
        )?;
        samples.push(name);
    }
    if !phases.namespace_closes.is_empty() {
        let name = path("namespace-closes.json");
        journal.append_raw(
            name.clone(),
            crate::private_observer_session::canonical_bytes(&phases.namespace_closes)?,
        )?;
        samples.push(name);
    }
    for (leaf, sample) in [
        ("pre-samples.json", &phases.pre),
        ("second-pre-samples.json", &phases.second_pre),
        ("release-intent-samples.json", &phases.release_intent),
        (
            "second-release-intent-samples.json",
            &phases.second_release_intent,
        ),
        ("baseline-samples.json", &phases.baseline),
        ("second-baseline-samples.json", &phases.second_baseline),
        ("first-ready-samples.json", &phases.first_ready),
        ("second-ready-samples.json", &phases.second_ready),
        (
            "second-after-retirement-samples.json",
            &phases.second_after_retirement,
        ),
        ("post-samples.json", &phases.post),
    ] {
        if let Some(sample) = sample {
            let name = path(leaf);
            let image = journal.retain_shared_image(
                sample
                    .leaves
                    .get("image.raw")
                    .ok_or_else(|| CiError::Message("held original ELF bytes absent".into()))?
                    .clone(),
            )?;
            journal.append_raw(
                name.clone(),
                crate::private_source_carrier::encode_held_source(sample, image)?,
            )?;
            samples.push(name);
        }
    }
    for (role, sample) in &phases.held_roles {
        let name = prefix
            .join("roles")
            .join(role)
            .join("held-samples.v1.bin")
            .to_string_lossy()
            .into_owned();
        let image = journal.retain_shared_image(
            sample
                .leaves
                .get("image.raw")
                .ok_or_else(|| CiError::Message("actual held role ELF bytes absent".into()))?
                .clone(),
        )?;
        journal.append_raw(
            name.clone(),
            crate::private_source_carrier::encode_held_source(sample, image)?,
        )?;
        samples.push(name);
    }
    for (leaf, bytes) in &phases.source_leaves {
        journal.append_raw(
            prefix
                .join("journal")
                .join(leaf)
                .to_string_lossy()
                .into_owned(),
            bytes.clone(),
        )?;
    }
    if case.selector == DUAL_SELECTOR {
        let native = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(String::from(case.key.clone()));
        for branch in ["dual-first", "dual-second"] {
            let bytes = crate::private_protected_readback::read_protected_raw_case_file(
                &native.join(branch).join("attempt.json"),
            )?;
            journal.append_raw(
                prefix
                    .join("journal")
                    .join(branch)
                    .join("attempt.json")
                    .to_string_lossy()
                    .into_owned(),
                bytes,
            )?;
        }
    }
    for (leaf, bytes) in &phases.gates {
        let leaf = match leaf.as_str() {
            "candidate-live-pre-v1.json" => "pre-gate.json",
            "candidate-first-pre-v1.json" => "first-pre-gate.json",
            "candidate-second-pre-v1.json" => "second-pre-gate.json",
            "candidate-live-release-intent-v1.json" => "release-intent-gate.json",
            "candidate-first-release-intent-v1.json" => "first-release-intent-gate.json",
            "candidate-second-release-intent-v1.json" => "second-release-intent-gate.json",
            "candidate-live-post-v1.json" => "post-gate.json",
            "candidate-live-baseline-v1.json" => "baseline-gate.json",
            "candidate-first-baseline-v1.json" => "first-baseline-gate.json",
            "candidate-second-baseline-v1.json" => "second-baseline-gate.json",
            "candidate-second-post-retirement-v1.json" => "second-after-retirement-gate.json",
            _ => {
                return Err(CiError::Message(
                    "candidate phase gate path is not closed".into(),
                ));
            }
        };
        journal.append_raw(path(leaf), bytes.clone())?;
    }
    if case.selector == "private_tcp::authorization_uncertainty_retired" {
        let native = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(String::from(case.key.clone()));
        for leaf in [
            "uncertain-stdout-v1.bin",
            "uncertain-stderr-v1.bin",
            "uncertain-streams-v1.json",
        ] {
            journal.append_raw(
                path(leaf),
                crate::private_protected_readback::read_protected_raw_case_file(
                    &native.join(leaf),
                )?,
            )?;
        }
    }
    if case.selector == UNIX_INTENT_SELECTOR {
        let native = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(String::from(case.key.clone()));
        for leaf in ["unix-intent-gate.json", "unix-intent-ack.json"] {
            journal.append_raw(
                path(leaf),
                crate::private_protected_readback::read_protected_raw_case_file(
                    &native.join(leaf),
                )?,
            )?;
        }
    }
    record_candidate_replay_sources(journal, case, detached, raw, phases, &prefix)?;
    journal.close_after_detach(
        case,
        &detached.interval,
        capture,
        vec![detached.controls_path.clone()],
        samples,
        detached.arm_monotonic_ns,
        detached.detach_monotonic_ns,
    )
}

pub fn run(
    root: &Path,
    stage: NativeRunStageV2,
    target: &str,
    collector_intent_sha256: Option<&str>,
    policy_intent_sha256: Option<&str>,
) -> Result<()> {
    run_with_observer_intent(
        root,
        stage,
        target,
        collector_intent_sha256,
        policy_intent_sha256,
        None,
    )
}

pub fn run_with_observer_intent(
    root: &Path,
    stage: NativeRunStageV2,
    target: &str,
    collector_intent_sha256: Option<&str>,
    policy_intent_sha256: Option<&str>,
    observer_intent: Option<&Path>,
) -> Result<()> {
    let observed_plan = observer_intent
        .filter(|_| stage == NativeRunStageV2::CandidateCapability)
        .map(crate::private_candidate_producer::StaticCandidateProducerIntentV1::read_protected)
        .transpose()?;
    if observed_plan.as_ref().is_some_and(|plan| {
        stage != NativeRunStageV2::CandidateCapability || plan.subject.target != target
    }) {
        return Err(CiError::Message(
            "candidate observer intent stage/target differs".into(),
        ));
    }
    let collector_intent_digest = match (stage, collector_intent_sha256) {
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
    if let Some(plan) = &observed_plan {
        let provenance = context
            .provenance
            .as_ref()
            .ok_or_else(|| CiError::Message("observed candidate has no Actions context".into()))?;
        if plan.subject.source_commit != context.source_commit
            || plan.subject.run_id != provenance.run_id.get()
            || plan.subject.run_attempt != provenance.run_attempt.get()
        {
            return Err(CiError::Message(
                "candidate observer static subject differs from live Actions context".into(),
            ));
        }
    }
    if stage == NativeRunStageV2::FinalPublic {
        if let Some(path) = observer_intent {
            return crate::private_public_driver::run(root, target, path);
        }
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
    let mut live_journal =
        if let (Some(plan), Some((downloaded, h0))) = (&observed_plan, &candidate_h0) {
            if plan.subject.build_sha256 != downloaded.build_sha256
                || plan.observer.agent_sha256 != hash_bytes(&h0.agent_bytes)
            {
                return Err(CiError::Message(
                    "candidate observed B/agent differs from protected static plan".into(),
                ));
            }
            let (generation, raw, exe) =
                crate::private_candidate_producer::observe_candidate_generation(
                    plan,
                    0,
                    h0.manifest_sha256.clone(),
                    h0.inspection_sha256.clone(),
                    &h0.inspection_bytes,
                    h0.installation_epoch.clone(),
                )?;
            let mut journal = crate::private_candidate_producer::CandidateProducerJournalV1::begin(
                plan.clone(),
                plan.observer.boot_id.clone(),
                plan.observer.btf_sha256.clone(),
                exe,
                generation,
            )?;
            journal.queue_generation_raw(raw)?;
            Some(journal)
        } else {
            None
        };
    if let Some((downloaded, h0)) = candidate_h0.as_mut() {
        *h0 = run_candidate_epoch_choreography(
            root,
            target,
            downloaded,
            h0,
            live_journal.as_mut(),
            observed_plan.as_ref(),
        )?;
    }
    let policy_fixture = if let Some((downloaded, h0)) = &candidate_h0 {
        let digest = policy_intent_digest.as_ref().ok_or_else(|| {
            CiError::Message("candidate policy release-intent digest is absent".into())
        })?;
        let live = crate::private_policy_provision::PolicyLiveExpectationV1 {
            target: target.to_owned(),
            candidate_build_sha256: downloaded.build_sha256.clone(),
            installed_inspection_sha256: h0.inspection_sha256.clone(),
            installation_epoch_sha256: h0.installation_epoch.clone(),
            agent_sha256: hash_bytes(&h0.agent_bytes),
        };
        Some(if let Some(journal) = &live_journal {
            let prepared = journal.prepare_case(
                "private_tcp::wrong_grant_profile_and_port_rejected",
                crate::private_kernel_replay::IntervalPurposeV1::Policy,
                0,
            )?;
            crate::private_policy_provision::provision_static_policy_fixture(
                digest,
                &live,
                prepared.challenge,
            )?
        } else {
            crate::private_policy_provision::provision_policy_fixture(digest, &live)?
        })
    } else {
        None
    };
    let challenge = fresh_challenge()?;
    let mut structural_results = Vec::with_capacity(REQUIRED_CASES.len());
    let mut policy_case = None;
    let mut abi_subwitness = None;
    for (ordinal, selector) in REQUIRED_CASES.into_iter().enumerate() {
        let prepared_case = live_journal
            .as_ref()
            .map(|journal| {
                journal.prepare_case(
                    selector,
                    if selector == DUAL_SELECTOR {
                        crate::private_kernel_replay::IntervalPurposeV1::DualContinuous
                    } else if selector == memcordon_core::private_reuse_source_v1::REUSE_SELECTOR_V1
                    {
                        crate::private_kernel_replay::IntervalPurposeV1::ReuseFirst
                    } else {
                        crate::private_kernel_replay::IntervalPurposeV1::Ordinary
                    },
                    u32::try_from(ordinal).map_err(|_| {
                        CiError::Message("candidate ordinal exceeds native width".into())
                    })?,
                )
            })
            .transpose()?;
        let challenge = prepared_case
            .as_ref()
            .map_or(challenge, |case| case.challenge);
        if memcordon_core::private_facility_source_v1::facility_operations_v1(selector).is_ok() {
            if let (Some(journal), Some(case), Some(plan)) = (
                live_journal.as_mut(),
                prepared_case.as_ref(),
                observed_plan.as_ref(),
            ) {
                run_candidate_facility_source(journal, plan, case)?;
            }
        }
        if selector == "private_tcp::caller_identity_and_epoch_bound" {
            if let (Some(journal), Some(case), Some(plan)) = (
                live_journal.as_mut(),
                prepared_case.as_ref(),
                observed_plan.as_ref(),
            ) {
                run_candidate_caller_spoof_source(journal, plan, case)?;
            }
        }
        if selector == "private_tcp::abi_alternate_entry_denied" {
            let fixture = policy_fixture.as_ref().ok_or_else(|| {
                CiError::Message("candidate ABI observer intent is absent".into())
            })?;
            let (downloaded, h0) = candidate_h0.as_ref().ok_or_else(|| {
                CiError::Message("candidate ABI installed B/M0/H0 is absent".into())
            })?;
            abi_subwitness = Some(run_candidate_abi_subwitness(
                root,
                fixture,
                downloaded,
                h0,
                challenge,
                live_journal.as_mut(),
                prepared_case.as_ref(),
                collector_intent_digest.as_ref(),
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
                live_journal.as_mut(),
                collector_intent_digest.as_ref(),
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
        let mut phases = crate::private_candidate_producer::CandidateLivePhasesV1::default();
        let operation = || {
            let sample_general = |state:&mut crate::private_candidate_producer::CandidateLivePhasesV1| -> Result<bool> {
                let Some(case) = &prepared_case else {
                    return Ok(false);
                };
                let directory =
                    Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(String::from(case.key.clone()));
                match std::fs::symlink_metadata(&directory) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                    Err(error) => return Err(error.into()),
                    Ok(_) => {}
                }
                crate::private_candidate_producer::sample_candidate_phases_if_ready(
                    &directory,
                    selector,
                    target,
                    &challenge,
                    &observed_plan
                        .as_ref()
                        .ok_or_else(|| {
                            CiError::Message("candidate phase static plan absent".into())
                        })?
                        .observer
                        .agent_sha256,
                    &case.recipe,
                    &case.argv,
                    state,
                )
            };
            let value = if selector == CHILD_RUNTIME_SELECTOR {
                let (process, sampled) = supervise_private_case_process_with_observer(
                    Path::new(AGENT),
                    &arguments,
                    Duration::from_secs(120),
                    || {
                        sample_general(&mut phases)?;
                        crate::private_child_live::sample_and_ack_if_ready_with_source(
                            challenge,
                            |parent, parent_ticks, child, child_ticks| {
                                let Some(case) = prepared_case.as_ref() else {
                                    return Ok(());
                                };
                                let parent_sample =
                                    crate::private_public_live::sample_held_target_raw(
                                        parent,
                                        parent_ticks,
                                        &case.recipe.fixture_sha256,
                                    )?;
                                let child_sample =
                                    crate::private_public_live::sample_held_target_raw(
                                        child,
                                        child_ticks,
                                        &case.recipe.fixture_sha256,
                                    )?;
                                if phases.post.is_some() {
                                    return Err(CiError::Message(
                                        "candidate child held parent source duplicated".into(),
                                    ));
                                }
                                phases.post = Some(parent_sample);
                                phases.retain_held_role("child".into(), child_sample)
                            },
                        )
                    },
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
                    || {
                        sample_general(&mut phases)?;
                        sample_socket_gate(challenge, &filter)
                    },
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
                    || {
                        sample_general(&mut phases)?;
                        sample_terminal_midpoint(challenge, &filter, image)
                    },
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
                    || {
                        sample_general(&mut phases)?;
                        crate::private_dual_live::sample_and_ack_if_ready_with_source(
                            challenge,
                            &filter,
                            image,
                            |first, first_ticks, second, second_ticks| {
                                let Some(case) = prepared_case.as_ref() else {
                                    return Ok(());
                                };
                                if phases.first_ready.is_some() || phases.second_ready.is_some() {
                                    return Err(CiError::Message(
                                        "dual independently held READY sources repeated".into(),
                                    ));
                                }
                                let mut first_sample =
                                    crate::private_public_live::sample_held_public_target(
                                        first,
                                        first_ticks,
                                        case.recipe.uid,
                                        case.recipe.gid,
                                        &case.recipe.fixture_sha256,
                                        &case.argv,
                                    )?;
                                let mut second_sample =
                                    crate::private_public_live::sample_held_public_target(
                                        second,
                                        second_ticks,
                                        case.recipe.uid,
                                        case.recipe.gid,
                                        &case.recipe.fixture_sha256,
                                        &case.argv,
                                    )?;
                                crate::private_public_live::sample_held_network_source(
                                    &mut first_sample,
                                )?;
                                crate::private_public_live::sample_held_network_source(
                                    &mut second_sample,
                                )?;
                                phases.first_ready = Some(first_sample);
                                phases.second_ready = Some(second_sample);
                                Ok(())
                            },
                        )
                    },
                )?;
                (process, None, None, None, sampled, None)
            } else if selector == UNIX_INTENT_SELECTOR {
                let (process, sampled) = supervise_private_case_process_with_observer(
                    Path::new(AGENT),
                    &arguments,
                    Duration::from_secs(120),
                    || {
                        sample_general(&mut phases)?;
                        crate::private_unix_live::sample_and_ack_if_ready_with_source(
                            challenge,
                            |pid, ticks| {
                                let Some(case) = prepared_case.as_ref() else {
                                    return Ok(());
                                };
                                if phases.post.is_some() {
                                    return Err(CiError::Message(
                                        "held Unix source duplicated".into(),
                                    ));
                                }
                                let mut sample =
                                    crate::private_public_live::sample_held_public_target(
                                        pid,
                                        ticks,
                                        case.recipe.uid,
                                        case.recipe.gid,
                                        &case.recipe.fixture_sha256,
                                        &case.argv,
                                    )?;
                                crate::private_candidate_unix_facts::sample_held_unix_source(
                                    &mut sample,
                                    challenge,
                                )?;
                                phases.post = Some(sample);
                                Ok(())
                            },
                        )
                    },
                )?;
                (process, None, None, None, None, sampled)
            } else {
                (
                    supervise_private_case_process_with_observer(
                        Path::new(AGENT),
                        &arguments,
                        Duration::from_secs(120),
                        || {
                            if sample_general(&mut phases)? {
                                Ok(Some(()))
                            } else {
                                Ok(None)
                            }
                        },
                    )?
                    .0,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            };
            phases.close_observer_namespaces()?;
            Ok(value)
        };
        let ((observed, child_live, socket_live, terminal_live, dual_live, unix_live), captured) =
            if let (Some(journal), Some(case)) = (live_journal.as_mut(), prepared_case.as_ref()) {
                let (output, detached) =
                    run_candidate_journal_interval(journal, fixture.observer(), case, operation)?;
                (output, CandidateCapturedIntervalV1::Enrolled(detached))
            } else {
                let (output, interval) =
                    run_candidate_case_interval(fixture, result_key.clone(), operation)?;
                (output, CandidateCapturedIntervalV1::Diagnostic(interval))
            };
        let kernel_interval = captured.interval();
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
        ) && matches!(captured,CandidateCapturedIntervalV1::Diagnostic(_)) {
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
        if let (Some(journal), Some(case), CandidateCapturedIntervalV1::Enrolled(detached)) =
            (live_journal.as_mut(), prepared_case.as_ref(), &captured)
        {
            retain_candidate_raw_interval(
                journal,
                case,
                detached,
                &structural,
                &phases,
                collector_intent_digest.as_ref(),
            )?;
            if case.selector == memcordon_core::private_reuse_source_v1::REUSE_SELECTOR_V1 {
                run_candidate_reuse_sources(
                    journal,
                    observed_plan.as_ref().ok_or_else(|| {
                        CiError::Message("Reuse static source plan absent".into())
                    })?,
                    case,
                    &structural,
                )?;
            }
            let sources = journal
                .raw_payload()
                .keys()
                .filter(|path| path.starts_with("candidate-c-v3/observer/"))
                .cloned()
                .collect::<Vec<_>>();
            let carrier = Path::new("candidate-c-v3/cases")
                .join(String::from(case.key.clone()))
                .join("family/source-carrier.v1.bin")
                .to_string_lossy()
                .into_owned();
            journal.repack_sources(carrier, sources)?;
        }
        structural_results.push((structural, captured.into_interval()));
    }
    if let (Some(journal), Some(plan), Some(collector)) = (
        live_journal,
        observed_plan.as_ref(),
        collector_intent_digest,
    ) {
        let filter = candidate_h0
            .as_ref()
            .ok_or_else(|| CiError::Message("candidate independent build readback absent".into()))?
            .0
            .prepared
            .filter_sha256
            .clone();
        return finalize_candidate_custody_export(root, journal, plan, collector, filter);
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

fn finalize_candidate_custody_export(
    root: &Path,
    journal: crate::private_candidate_producer::CandidateProducerJournalV1,
    plan: &crate::private_candidate_producer::StaticCandidateProducerIntentV1,
    collector: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
) -> Result<()> {
    use crate::private_candidate_replay::{
        CaseReplayFactsV1, ExpectedCaseSubjectV1, ReplayLeafRoleV1,
    };
    use crate::private_observer_session::{
        ORIGIN_COMMITMENT_LEAF, ORIGIN_RECEIPT_LEAF, ObserverEvidenceV1, PAYLOAD_INDEX_LEAF,
    };
    const POLICY_SELECTOR: &str = "private_tcp::wrong_grant_profile_and_port_rejected";
    let payload = journal.raw_payload().clone();
    let views = crate::private_candidate_replay::expand_replay_payload(&payload)?;
    let mut indexed = BTreeMap::new();
    for (path, bytes) in payload.iter().filter(|(path, _)| {
        path.starts_with("candidate-c-v3/cases/") && path.ends_with("/result.json")
    }) {
        let result =
            memcordon_core::private_release_case_v1::PrivateReleaseCaseResultV1::parse(bytes)
                .map_err(CiError::Message)?;
        if indexed
            .insert(
                result.selector.clone(),
                (path.clone(), bytes.clone(), result),
            )
            .is_some()
        {
            return Err(CiError::Message(
                "candidate duplicate completed selector".into(),
            ));
        }
    }
    if indexed.len() != REQUIRED_CASES.len()
        || REQUIRED_CASES
            .iter()
            .any(|selector| !indexed.contains_key(*selector))
    {
        return Err(CiError::Message(
            "candidate literal all-25 custody source inventory is incomplete".into(),
        ));
    }
    let cleanup_sources = views
        .iter()
        .filter(|(path, _)| {
            path.ends_with("/cgroup-retirement-v1.json") || path.ends_with("/namespace-closes.json")
        })
        .map(|(path, bytes)| (path.clone(), hash_bytes(bytes)))
        .collect::<BTreeMap<_, _>>();
    if cleanup_sources.is_empty() {
        return Err(CiError::Message(
            "candidate observed cleanup source inventory absent".into(),
        ));
    }
    let cleanup = hash_bytes(&crate::private_observer_session::canonical_bytes(
        &cleanup_sources,
    )?);
    let (origin, receipt) = journal.seal(cleanup, candidate_monotonic_ns()?)?;
    let mut proofs = Vec::with_capacity(REQUIRED_CASES.len());
    let mut results = Vec::with_capacity(REQUIRED_CASES.len());
    let mut cases = Vec::with_capacity(REQUIRED_CASES.len());
    for (ordinal, selector) in REQUIRED_CASES.iter().enumerate() {
        let (result_path, result_bytes, result) = indexed
            .get(*selector)
            .expect("closed selector inventory checked");
        let prefix = Path::new(result_path)
            .parent()
            .expect("closed result path has parent");
        let case_path = |leaf: &str| prefix.join(leaf).to_string_lossy().into_owned();
        let bundle_path = case_path("family/replay-bundle.v1.bin");
        let facts_path = crate::private_candidate_replay::replay_role_path(
            &bundle_path,
            ReplayLeafRoleV1::Facts,
            0,
        )?;
        let facts: CaseReplayFactsV1 = crate::private_observer_session::strict_json(
            origin.leaf(&facts_path)?,
            8 * 1024 * 1024,
        )?;
        let purpose = if *selector == POLICY_SELECTOR {
            crate::private_kernel_replay::IntervalPurposeV1::Policy
        } else if *selector == DUAL_SELECTOR {
            crate::private_kernel_replay::IntervalPurposeV1::DualContinuous
        } else if *selector == memcordon_core::private_reuse_source_v1::REUSE_SELECTOR_V1 {
            crate::private_kernel_replay::IntervalPurposeV1::ReuseFirst
        } else {
            crate::private_kernel_replay::IntervalPurposeV1::Ordinary
        };
        let recipe = crate::private_candidate_producer::prepared_candidate_case_recipe_v1(
            plan,
            &origin.descriptor().session_nonce,
            facts.generation,
            selector,
            purpose,
            if *selector == POLICY_SELECTOR {
                0
            } else {
                ordinal as u32
            },
        )?;
        if result.challenge_bytes().map_err(CiError::Message)? != recipe.challenge {
            return Err(CiError::Message(
                "candidate completed challenge differs from actual enrolled preparation".into(),
            ));
        }
        let capture_path = case_path(&format!(
            "kernel-{}.capture.bin",
            String::from(collector.clone())
        ));
        let capture = origin.leaf(&capture_path)?;
        let interval_key = &origin
            .descriptor()
            .intervals
            .iter()
            .find(|interval| {
                interval.interval_id == facts.interval_id && interval.capture_path == capture_path
            })
            .ok_or_else(|| {
                CiError::Message("candidate exact physical replay interval absent".into())
            })?
            .logical_case_key;
        let parsed = crate::private_kernel_replay::parse_capture_v2(capture, interval_key)?;
        let image = parsed
            .events()
            .iter()
            .find(|event| {
                event.kind == 6
                    && event.task.tid == facts.target.tid
                    && event.task.start_boottime_ns == facts.target.start_boottime_ns
            })
            .map(|event| (event.image_dev, event.image_inode));
        let netns = facts
            .held_sample_paths
            .iter()
            .map(|path| {
                crate::private_source_carrier::decode_held_source(origin.leaf(path)?, |image| {
                    origin.leaf(image).map(ToOwned::to_owned)
                })
            })
            .collect::<Result<Vec<_>>>()?
            .iter()
            .find_map(|sample| {
                sample
                    .tasks
                    .iter()
                    .find(|task| task.tid == facts.target.tid)
                    .and_then(|task| task.namespace_inodes.get("net").copied())
            });
        let response = if matches!(
            *selector,
            "private_tcp::authorization_uncertainty_retired" | POLICY_SELECTOR
        ) {
            Vec::new()
        } else {
            memcordon_core::private_release_case_v1::candidate_fixture_expected_response_v1(
                &plan.subject.target,
                selector,
                &recipe.challenge,
                netns,
                image,
            )
            .map_err(|error| CiError::Message(error.into()))?
        };
        let expected = ExpectedCaseSubjectV1 {
            selector,
            result_key: &recipe.key,
            fixture_sha256: &recipe.recipe.fixture_sha256,
            filter_sha256: &filter_sha256,
            fixture_argv: &recipe.argv,
            uid: recipe.recipe.uid,
            gid: recipe.recipe.gid,
            groups: &recipe.recipe.groups,
            port: recipe.port,
            challenge: &recipe.challenge,
            auxiliary_semantics_sha256: recipe.recipe.auxiliary_semantics_sha256.as_ref(),
            filter_install_source_sha256: recipe.recipe.filter_install_source_sha256.as_ref(),
            facility_source_sha256: recipe.recipe.facility_source_sha256.as_ref(),
            host_preservation_source_sha256: recipe.recipe.host_preservation_source_sha256.as_ref(),
            reuse_source_sha256: recipe.recipe.reuse_source_sha256.as_ref(),
            exact_response: &response,
        };
        proofs.push(crate::private_candidate_replay::verify_origin_bound_case(
            &origin,
            &expected,
            &facts_path,
            result_bytes,
            &capture_path,
        )?);
        let mut family = BTreeMap::new();
        for leaf in crate::private_candidate_c_v3::required_case_family_leaves_v4(
            selector,
            &plan.subject.target,
        )
        .into_iter()
        .chain(["source-carrier.v1.bin"])
        {
            let bytes = match leaf {
                PAYLOAD_INDEX_LEAF => receipt.payload_index.clone(),
                ORIGIN_COMMITMENT_LEAF => receipt.origin_commitment.clone(),
                ORIGIN_RECEIPT_LEAF => receipt.origin_receipt.clone(),
                _ => origin.leaf(&case_path(&format!("family/{leaf}")))?.to_vec(),
            };
            family.insert(leaf.into(), bytes);
        }
        let attachments =
            memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL
                .map(|role| origin.leaf(&case_path(role.leaf())).map(ToOwned::to_owned));
        let attachments = attachments
            .into_iter()
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| CiError::Message("candidate exact five attachments differ".into()))?;
        cases.push(crate::private_candidate_c_v3::CandidateCaseBytesV3 {
            result: result_bytes.clone(),
            attachments,
            kernel_capture: capture.to_vec(),
            family_raw: family,
        });
        results.push((result_bytes.clone(), result.clone()));
    }
    let semantics =
        crate::private_native_verify::verify_candidate_semantics(&origin, &results, &proofs)?;
    let target_id = match plan.subject.target.as_str() {
        "x86_64-unknown-linux-gnu" => "linux-x64",
        "aarch64-unknown-linux-gnu" => "linux-arm64",
        _ => return Err(CiError::Message("candidate export target differs".into())),
    };
    let parent = root.join("target/ci/reports/private-candidate-c-v3");
    std::fs::create_dir_all(&parent)?;
    crate::private_candidate_c_v3::export_candidate_c_v3(
        &semantics,
        &plan.subject.target,
        &plan.subject.source_commit,
        &plan.subject.release_version,
        collector,
        &cases,
        &BTreeMap::new(),
        &parent.join(target_id),
    )
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
