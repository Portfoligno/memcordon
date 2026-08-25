use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use memcordon_ci::command::{CommandSpec, git, rustup_cargo};
use memcordon_ci::runtime_manifest::{RuntimeManifestV1, SealedRuntimeV1};
use memcordon_ci::{CiError, Result};
use memcordon_core::{
    BoundaryMechanismEvidence, CredentialTransitionDisposition, MemcordonReport,
    WINDOWS_QUALIFICATION_SCHEMA_VERSION, WINDOWS_RELEASE_MUTANT_VARIANTS, WINDOWS_RELEASE_MUTANTS,
    WindowsAuthorityLossEvidenceV1, WindowsCertificationObservationsV1,
    WindowsMutantKillEvidenceV1, WindowsMutantObservationV1, WindowsQualificationReceiptV1,
    WindowsSealedMutant, WindowsTokenMatrixEvidenceV1,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::release::{create_package_archives, extract_crate_source};

const DEADLINE: Duration = Duration::from_secs(30 * 60);
const REPORT_DIRECTORY: &str = "target/ci/reports/windows-sealed-v2";
const WINDOWS_TESTS: &[&str] = &[
    "package_install_verify_probe_and_same_version_upgrade",
    "active_attempt_upgrade_and_uninstall_are_refused",
    "public_sealed_launch_preserves_status_and_native_evidence",
    "frontend_loss_retires_the_job_and_durable_record",
    "package_uninstall_leaves_no_provider_state",
    "deadline_memory_and_raw_ntstatus_are_preserved",
    "production_package_lifecycle_without_ci_fault_gate",
    "windows_target_token_identity",
    "windows_creation_time_job_list",
    "windows_exact_handle_manifest",
    "windows_job_policy_readback",
    "windows_caller_token_authentication",
    "windows_job_membership_readback",
    "windows_preauthorization_gate",
    "windows_recursive_provider_rejection",
    "windows_guardian_authority",
    "windows_active_process_accounting",
    "windows_relay_retirement",
    "windows_final_handle_ordering",
    "windows_sealed_mechanism_selection",
    "windows_native_archive_inventory",
    "windows_qualification_advertisement",
];

#[derive(Serialize)]
struct CertificationTest {
    name: &'static str,
    result: &'static str,
}

#[derive(Serialize)]
struct WindowsRuntimeEvidence<'a> {
    qualification: &'a WindowsQualificationReceiptV1,
    public_launch: &'a MemcordonReport,
    active_attempt_upgrade_refused: bool,
    active_attempt_uninstall_refused: bool,
    frontend_loss_record_retired: bool,
    provider_state_removed: bool,
    status_matrix: StatusMatrixEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StatusMatrixEvidence {
    schema_version: u32,
    ordinary_exit_codes: Vec<u32>,
    deadline_outcome: memcordon_core::RunOutcome,
    memory_limit_outcome: memcordon_core::RunOutcome,
    raw_ntstatus_outcome: memcordon_core::RunOutcome,
    orphan_descendant_outcome: memcordon_core::RunOutcome,
    command_not_found: memcordon_core::SupervisionErrorRecord,
    command_not_executable: memcordon_core::SupervisionErrorRecord,
    provider_setup_failure: memcordon_core::ProviderRejectionEvidence,
    relay_failure: memcordon_core::ProviderRejectionEvidence,
    terminal_truncation_rejected: bool,
    report_consistency_verified: bool,
}

#[derive(Serialize)]
struct CertificationSummary<'a> {
    schema: u32,
    backend: &'static str,
    certified: bool,
    commit: &'a str,
    runner_class: &'static str,
    runner_provider: &'static str,
    runner_label: String,
    architecture: &'static str,
    native_archive_sha256: Option<&'a str>,
    runtime_manifest_sha256: Option<&'a str>,
    native_target: Option<&'a str>,
    runtime: WindowsRuntimeEvidence<'a>,
    tests: Vec<CertificationTest>,
    tests_run: u32,
    tests_skipped: u32,
}

#[derive(Serialize)]
struct EvidenceEnvelope<'a, T: ?Sized> {
    schema_version: u32,
    mechanism: &'static str,
    architecture: &'static str,
    commit: &'a str,
    result: &'static str,
    evidence: &'a T,
}

#[derive(Serialize)]
struct TokenEnvelopeEvidence<'a> {
    service_identity: &'a str,
    caller_token_authenticated: bool,
    initial_target_token_matches_caller: bool,
    credential_transition_disposition: CredentialTransitionDisposition,
    restricted_caller_token_verified: bool,
    primary_token_duplication_verified: bool,
    token_matrix: &'a WindowsTokenMatrixEvidenceV1,
}

#[derive(Serialize)]
struct HandleInventoryEvidence {
    job_list_applied_at_creation: bool,
    handle_list_applied_at_creation: bool,
    inherited_handles_verified: bool,
    exact_handle_inheritance_verified: bool,
    relays_retired: bool,
}

#[derive(Serialize)]
struct PreauthorizationEvidence<'a> {
    guardian_ready: bool,
    target_created_suspended: bool,
    target_job_membership_verified: bool,
    target_still_suspended_during_verification: bool,
    target_released: bool,
    fault_matrix: &'a WindowsCertificationObservationsV1,
    mutant_kills: &'a WindowsMutantKillEvidenceV1,
}

#[derive(Serialize)]
struct AlternateTokenEvidence {
    alternate_token_child_contained: bool,
    initial_target_token_matches_caller: bool,
    job_membership_independent_of_token: bool,
}

#[derive(Serialize)]
struct NestedJobEvidence {
    nested_host_job_supported: bool,
    nested_child_job_contained: bool,
    target_job_membership_verified: bool,
}

#[derive(Serialize)]
struct FrontendLossEvidence {
    frontend_loss_cleanup_verified: bool,
    record_retired: bool,
    active_processes_zero_verified: bool,
    guardian_verified: bool,
    authority_loss: WindowsAuthorityLossEvidenceV1,
}

#[derive(Serialize)]
struct RecoveryEvidence {
    recovery_complete: bool,
    active_processes_zero_verified: bool,
    relays_retired_verified: bool,
    authority_loss: WindowsAuthorityLossEvidenceV1,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ChannelFingerprint {
    package_identity: Value,
    qualification_schema: u32,
    provider_identity: String,
    provider_protocol_schema: u32,
    execution_report_schema: u32,
    boundary_evidence_schema: u32,
    execution_mechanism: String,
    sealed_behavior: Value,
}

pub fn certify(root: &Path, stable: &str) -> Result<()> {
    require_windows()?;
    require_native_architecture()?;
    let native = native_channel_binaries(root, stable)?;
    let reports = report_directory(root);
    if reports.exists() {
        fs::remove_dir_all(&reports)?;
    }
    fs::create_dir_all(&reports)?;
    let agent = native.root.join("memcordon-sealed-agent.exe");
    let cli = native.root.join("memcordon.exe");
    let commit = String::from_utf8(git(root, ["rev-parse", "HEAD"])?)
        .map_err(|error| CiError::Message(format!("git commit identity was not UTF-8: {error}")))?;
    let commit = commit.trim_end_matches(['\r', '\n']);

    let package =
        run_json(&CommandSpec::new(&agent, root, DEADLINE).args(["package", "inspect", "--json"]))?;
    write_json(&reports.join("windows-package-inspection.json"), &package)?;
    CommandSpec::new(&agent, root, DEADLINE)
        .args(["package", "install", "--ephemeral-ci"])
        .run()?;
    let installed =
        run_json(&CommandSpec::new(&agent, root, DEADLINE).args(["package", "verify", "--json"]))?;
    write_json(&reports.join("windows-installed-provider.json"), &installed)?;
    let qualification_value = run_json(&CommandSpec::new(&agent, root, DEADLINE).arg("qualify"))?;
    let qualification: WindowsQualificationReceiptV1 =
        serde_json::from_value(qualification_value.clone())?;
    if qualification.schema_version != WINDOWS_QUALIFICATION_SCHEMA_VERSION
        || !qualification.qualified
        || !qualification.is_consistent()
    {
        return Err(CiError::Message(
            "Windows qualification receipt is incomplete or contradictory".to_owned(),
        ));
    }
    write_json(
        &reports.join("windows-qualification.json"),
        &qualification_value,
    )?;
    let fault_matrix: WindowsCertificationObservationsV1 = serde_json::from_value(run_json(
        &CommandSpec::new(&agent, root, DEADLINE).arg("windows-certification-observations"),
    )?)?;
    if !fault_matrix.is_complete() {
        return Err(CiError::Message(
            "Windows preauthorization fault matrix is incomplete".to_owned(),
        ));
    }
    let token_matrix: WindowsTokenMatrixEvidenceV1 = serde_json::from_value(run_json(
        &CommandSpec::new(&agent, root, DEADLINE).arg("windows-token-observations"),
    )?)?;
    if !token_matrix.is_complete() {
        return Err(CiError::Message(
            "Windows token qualification matrix is incomplete".to_owned(),
        ));
    }
    let authority_loss: WindowsAuthorityLossEvidenceV1 = serde_json::from_value(run_json(
        &CommandSpec::new(&agent, root, DEADLINE).arg("windows-authority-loss-observations"),
    )?)?;
    if !authority_loss.is_complete() {
        return Err(CiError::Message(
            "Windows authority-loss evidence is incomplete".to_owned(),
        ));
    }
    let mutant_kills = collect_mutant_kill_evidence(root, &agent)?;
    let _doctor = run_json(&CommandSpec::new(&cli, root, DEADLINE).args([
        "doctor",
        "--json",
        "--require",
        "sealed",
    ]))?;

    CommandSpec::new(&agent, root, DEADLINE)
        .args(["package", "upgrade", "--ephemeral-ci"])
        .run()?;

    let active_report = reports.join("active-attempt.json");
    let mut active = spawn_hold(root, &cli, &agent, &active_report)?;
    wait_for_active_attempt(root, &agent)?;
    let upgrade_refused = command_failed_with(
        &CommandSpec::new(&agent, root, DEADLINE).args(["package", "upgrade", "--ephemeral-ci"]),
        "MCSEALED-WINDOWS-UPGRADE-ACTIVE",
    )?;
    let uninstall_refused = command_failed_with(
        &CommandSpec::new(&agent, root, DEADLINE).args(["package", "uninstall", "--ephemeral-ci"]),
        "MCSEALED-WINDOWS-UNINSTALL-ACTIVE",
    )?;
    if !upgrade_refused || !uninstall_refused {
        terminate_child(&mut active);
        return Err(CiError::Message(
            "Windows package mutation did not refuse an active attempt".to_owned(),
        ));
    }
    terminate_child(&mut active);
    wait_for_attempts_empty(root, &agent)?;

    let public_report_path = reports.join("public-launch.json");
    let arguments = vec![
        OsString::from("--sealed"),
        OsString::from("--report"),
        public_report_path.as_os_str().to_os_string(),
        OsString::from("--"),
        agent.as_os_str().to_os_string(),
        OsString::from("--version"),
    ];
    CommandSpec::new(&cli, root, DEADLINE)
        .args(arguments)
        .run()?;
    let public_launch: MemcordonReport = serde_json::from_slice(&fs::read(&public_report_path)?)?;
    validate_public_launch(&public_launch)?;
    let status_matrix =
        certify_status_matrix(root, &cli, &agent, &reports, &fault_matrix, &public_launch)?;

    write_auxiliary_reports(
        &reports,
        commit,
        &qualification_value,
        &fault_matrix,
        &token_matrix,
        &authority_loss,
        &mutant_kills,
        &public_launch,
    )?;

    CommandSpec::new(&agent, root, DEADLINE)
        .args(["package", "uninstall", "--ephemeral-ci"])
        .run()?;
    certify_production_lifecycle(root, &agent, &cli, &reports)?;
    let provider_state_removed = provider_state_absent(root, &agent)?;
    if !provider_state_removed {
        return Err(CiError::Message(
            "Windows package uninstall left provider files or state".to_owned(),
        ));
    }
    let tests = certification_test_results(
        &qualification,
        &public_launch,
        upgrade_refused,
        uninstall_refused,
        provider_state_removed,
        native.target.is_some(),
    )?;
    let summary = CertificationSummary {
        schema: 2,
        backend: "windows-job-object-v2",
        certified: true,
        commit,
        runner_class: "ephemeral-certified",
        runner_provider: "github-hosted",
        runner_label: runner_label(),
        architecture: std::env::consts::ARCH,
        native_archive_sha256: native.archive_sha256.as_deref(),
        runtime_manifest_sha256: native.runtime_manifest_sha256.as_deref(),
        native_target: native.target.as_deref(),
        runtime: WindowsRuntimeEvidence {
            qualification: &qualification,
            public_launch: &public_launch,
            active_attempt_upgrade_refused: upgrade_refused,
            active_attempt_uninstall_refused: uninstall_refused,
            frontend_loss_record_retired: qualification.frontend_loss_cleanup_verified,
            provider_state_removed,
            status_matrix,
        },
        tests_run: u32::try_from(tests.len())
            .map_err(|_| CiError::Message("too many Windows certification tests".to_owned()))?,
        tests,
        tests_skipped: 0,
    };
    write_json(&reports.join("windows-cleanup.json"), &summary)?;
    fs::remove_file(public_report_path)?;
    if active_report.exists() {
        fs::remove_file(active_report)?;
    }
    Ok(())
}

fn collect_mutant_kill_evidence(root: &Path, agent: &Path) -> Result<WindowsMutantKillEvidenceV1> {
    let runtime: WindowsMutantKillEvidenceV1 = serde_json::from_value(run_json(
        &CommandSpec::new(agent, root, DEADLINE).arg("windows-runtime-mutant-observations"),
    )?)?;
    let archive_mutant = WindowsSealedMutant::OmitAgentFromArchive;
    let archive_test = WINDOWS_RELEASE_MUTANTS
        .iter()
        .find_map(|(name, test)| (*name == archive_mutant.as_str()).then_some(*test))
        .ok_or_else(|| CiError::Message("archive mutant has no mapped test".to_owned()))?;
    let mut available = runtime.observations;
    let configuration_rejected =
        memcordon_ci::config::certify_windows_archive_omission_mutant(root)?;
    let native_observation =
        memcordon_core::WindowsMutantNativeObservationV1::ArchiveInventoryOmission {
            sealed_agent_removed: true,
            configuration_rejected,
        };
    if !native_observation.rejects(archive_mutant) {
        return Err(CiError::Message(
            "archive omission mutant survived release configuration validation".to_owned(),
        ));
    }
    available.push(WindowsMutantObservationV1 {
        mutant: archive_mutant,
        mapped_test: archive_test.to_owned(),
        native_observation,
    });
    let mut observations = Vec::with_capacity(WINDOWS_RELEASE_MUTANTS.len());
    for (variant, (name, mapped_test)) in WINDOWS_RELEASE_MUTANT_VARIANTS
        .iter()
        .copied()
        .zip(WINDOWS_RELEASE_MUTANTS)
    {
        let index = available
            .iter()
            .position(|observation| observation.mutant == variant)
            .ok_or_else(|| {
                CiError::Message(format!(
                    "Windows executable mutant {name} was not exercised"
                ))
            })?;
        let observation = available.remove(index);
        if observation.mutant.as_str() != *name
            || observation.mapped_test != *mapped_test
            || !observation.native_observation.rejects(observation.mutant)
        {
            return Err(CiError::Message(format!(
                "Windows executable mutant {name} survived {mapped_test}"
            )));
        }
        observations.push(observation);
    }
    if !available.is_empty() {
        return Err(CiError::Message(
            "Windows executable mutant runner returned an unknown duplicate observation".to_owned(),
        ));
    }
    let evidence = WindowsMutantKillEvidenceV1 {
        schema_version: 1,
        observations,
    };
    if !evidence.is_complete() {
        return Err(CiError::Message(
            "Windows executable mutant kill evidence is incomplete".to_owned(),
        ));
    }
    Ok(evidence)
}

fn certification_test_results(
    qualification: &WindowsQualificationReceiptV1,
    public_launch: &MemcordonReport,
    upgrade_refused: bool,
    uninstall_refused: bool,
    provider_state_removed: bool,
    native_archive_bound: bool,
) -> Result<Vec<CertificationTest>> {
    let attempt = public_launch
        .attempts
        .last()
        .ok_or_else(|| CiError::Message("Windows certification attempt is absent".to_owned()))?;
    let native = match &attempt.boundary_detail {
        BoundaryMechanismEvidence::WindowsJobObjectV2(native) => native,
        _ => {
            return Err(CiError::Message(
                "Windows certification attempt has the wrong mechanism".to_owned(),
            ));
        }
    };
    let observed = [
        qualification.qualified,
        upgrade_refused && uninstall_refused,
        validate_public_launch(public_launch).is_ok(),
        qualification.frontend_loss_cleanup_verified,
        provider_state_removed,
        qualification.active_processes_zero_verified,
        qualification.qualified && provider_state_removed,
        native.initial_target_token_matches_caller,
        native.job_list_applied_at_creation && native.target_created_suspended,
        native.handle_list_applied_at_creation
            && native.inherited_handles_verified
            && qualification.exact_handle_inheritance_verified,
        native.job_limits_verified && native.kill_on_close_verified && native.breakaway_denied,
        native.caller_token_authenticated && qualification.caller_token_authentication_verified,
        native.target_job_membership_verified,
        native.guardian_ready
            && native.target_created_suspended
            && native.target_still_suspended_during_verification
            && native.target_released,
        qualification.recursive_provider_request_denied,
        qualification.guardian_verified,
        native.active_processes_zero && qualification.active_processes_zero_verified,
        native.relays_retired && qualification.relays_retired_verified,
        native.final_job_handles_closed,
        attempt.launch.mechanism == "windows-job-object-v2",
        native_archive_bound,
        qualification.qualified && qualification.recovery_complete,
    ];
    if observed.len() != WINDOWS_TESTS.len() {
        return Err(CiError::Message(
            "Windows certification observation inventory differs from its named tests".to_owned(),
        ));
    }
    WINDOWS_TESTS
        .iter()
        .zip(observed)
        .map(|(name, passed)| {
            if !passed {
                return Err(CiError::Message(format!(
                    "Windows native certification test did not produce its required observation: {name}"
                )));
            }
            Ok(CertificationTest {
                name,
                result: "passed",
            })
        })
        .collect()
}

fn certify_production_lifecycle(
    root: &Path,
    agent: &Path,
    cli: &Path,
    reports: &Path,
) -> Result<()> {
    CommandSpec::new(agent, root, DEADLINE)
        .args(["package", "install"])
        .run()?;
    let installed =
        run_json(&CommandSpec::new(agent, root, DEADLINE).args(["package", "verify", "--json"]))?;
    if installed
        .get("qualification_complete")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(CiError::Message(
            "production Windows package install did not commit qualification".to_owned(),
        ));
    }
    let report_path = reports.join("production-lifecycle.json");
    CommandSpec::new(cli, root, DEADLINE)
        .args([
            OsString::from("--sealed"),
            OsString::from("--report"),
            report_path.as_os_str().to_os_string(),
            OsString::from("--"),
            agent.as_os_str().to_os_string(),
            OsString::from("--version"),
        ])
        .run()?;
    let report: MemcordonReport = serde_json::from_slice(&fs::read(&report_path)?)?;
    validate_public_launch(&report)?;
    fs::remove_file(report_path)?;
    CommandSpec::new(agent, root, DEADLINE)
        .args(["package", "upgrade"])
        .run()?;
    CommandSpec::new(agent, root, DEADLINE)
        .args(["package", "uninstall"])
        .run()?;
    if !provider_state_absent(root, agent)? {
        return Err(CiError::Message(
            "production Windows package lifecycle left provider state".to_owned(),
        ));
    }
    Ok(())
}

fn certify_status_matrix(
    root: &Path,
    cli: &Path,
    agent: &Path,
    reports: &Path,
    fault_matrix: &WindowsCertificationObservationsV1,
    public_launch: &MemcordonReport,
) -> Result<StatusMatrixEvidence> {
    let mut ordinary_exit_codes = Vec::with_capacity(usize::from(u8::MAX) + 1);
    for code in u8::MIN..=u8::MAX {
        let outcome = run_status_scenario_args(
            root,
            cli,
            reports,
            &format!("exit-{code}"),
            None,
            agent,
            &[
                OsString::from("windows-certification-exit"),
                OsString::from(code.to_string()),
            ],
        )?;
        match outcome {
            memcordon_core::RunOutcome::Exited {
                child: memcordon_core::ChildTermination::ExitCode { code: observed },
                ..
            } if observed == i32::from(code) => ordinary_exit_codes.push(u32::from(code)),
            other => {
                return Err(CiError::Message(format!(
                    "Windows exit-code {code} did not round-trip: {other:?}"
                )));
            }
        }
    }
    let deadline = run_status_scenario(
        root,
        cli,
        agent,
        reports,
        "deadline",
        Some("+100ms"),
        "windows-certification-hold",
    )?;
    let memory = run_status_scenario(
        root,
        cli,
        agent,
        reports,
        "memory",
        Some("+8MiB"),
        "windows-certification-memory",
    )?;
    let ntstatus = run_status_scenario(
        root,
        cli,
        agent,
        reports,
        "ntstatus",
        None,
        "windows-certification-ntstatus",
    )?;
    let orphan = run_status_scenario(
        root,
        cli,
        agent,
        reports,
        "orphan",
        None,
        "windows-certification-orphan",
    )?;
    let missing = reports.join("windows-certification-missing.exe");
    let command_not_found =
        run_spawn_failure_scenario(root, cli, reports, "command-not-found", &missing)?;
    let non_executable = reports.join("windows-certification-non-executable.txt");
    fs::write(&non_executable, b"not a Windows executable\n")?;
    let command_not_executable = run_spawn_failure_scenario(
        root,
        cli,
        reports,
        "command-not-executable",
        &non_executable,
    )?;
    fs::remove_file(non_executable)?;
    let public_report = serde_json::to_vec(public_launch)?;
    let mut truncated = public_report.clone();
    truncated.pop();
    let provider_setup_failure = fault_matrix
        .preauthorization
        .rejections
        .iter()
        .find(|observation| observation.fault == memcordon_core::WindowsSealedFault::JobCreate)
        .map(|observation| observation.rejection.clone())
        .ok_or_else(|| {
            CiError::Message("Windows JobCreate rejection evidence is absent".to_owned())
        })?;
    let relay_failure = fault_matrix
        .retirement
        .rejections
        .iter()
        .find(|observation| observation.fault == memcordon_core::WindowsSealedFault::RelayRetire)
        .map(|observation| observation.rejection.clone())
        .ok_or_else(|| {
            CiError::Message("Windows RelayRetire rejection evidence is absent".to_owned())
        })?;
    let evidence = StatusMatrixEvidence {
        schema_version: 1,
        ordinary_exit_codes,
        deadline_outcome: deadline,
        memory_limit_outcome: memory,
        raw_ntstatus_outcome: ntstatus,
        orphan_descendant_outcome: orphan,
        command_not_found,
        command_not_executable,
        provider_setup_failure,
        relay_failure,
        terminal_truncation_rejected: fault_matrix
            .preauthorization
            .terminal_frame_truncation_rejected
            && serde_json::from_slice::<MemcordonReport>(&truncated).is_err(),
        report_consistency_verified: serde_json::from_slice::<MemcordonReport>(&public_report)
            .is_ok(),
    };
    if status_matrix_is_complete(&evidence) {
        Ok(evidence)
    } else {
        Err(CiError::Message(format!(
            "Windows status certification matrix failed: {evidence:?}"
        )))
    }
}

fn status_matrix_is_complete(evidence: &StatusMatrixEvidence) -> bool {
    evidence.schema_version == 1
        && evidence.ordinary_exit_codes == (u8::MIN..=u8::MAX).map(u32::from).collect::<Vec<_>>()
        && matches!(
            evidence.deadline_outcome,
            memcordon_core::RunOutcome::DeadlineExceeded { .. }
        )
        && matches!(
            evidence.memory_limit_outcome,
            memcordon_core::RunOutcome::LimitExceeded { .. }
        )
        && matches!(
            evidence.raw_ntstatus_outcome,
            memcordon_core::RunOutcome::Exited {
                child: memcordon_core::ChildTermination::WindowsStatus {
                    status: 0xC000_013A
                },
                ..
            }
        )
        && matches!(
            evidence.orphan_descendant_outcome,
            memcordon_core::RunOutcome::Exited {
                child: memcordon_core::ChildTermination::ExitCode { code: 0 },
                ..
            }
        )
        && evidence.command_not_found.initial_spawn_failure
            == Some(memcordon_core::InitialSpawnFailure::NotFound)
        && evidence.command_not_found.os_code == Some(2)
        && evidence.command_not_executable.initial_spawn_failure
            == Some(memcordon_core::InitialSpawnFailure::NotExecutable)
        && evidence.command_not_executable.os_code == Some(193)
        && evidence.provider_setup_failure.phase
            == memcordon_core::BoundarySetupPhase::BoundaryCreation
        && !evidence.provider_setup_failure.target_released
        && evidence.provider_setup_failure.is_consistent()
        && evidence.relay_failure.phase == memcordon_core::BoundarySetupPhase::Retirement
        && evidence.relay_failure.target_released
        && evidence.relay_failure.is_consistent()
        && evidence.terminal_truncation_rejected
        && evidence.report_consistency_verified
}

fn run_status_scenario(
    root: &Path,
    cli: &Path,
    agent: &Path,
    reports: &Path,
    name: &str,
    budget: Option<&str>,
    target_command: &str,
) -> Result<memcordon_core::RunOutcome> {
    run_status_scenario_args(
        root,
        cli,
        reports,
        name,
        budget,
        agent,
        &[OsString::from(target_command)],
    )
}

fn run_status_scenario_args(
    root: &Path,
    cli: &Path,
    reports: &Path,
    name: &str,
    budget: Option<&str>,
    target_program: &Path,
    target_arguments: &[OsString],
) -> Result<memcordon_core::RunOutcome> {
    let report_path = reports.join(format!("status-{name}.json"));
    let mut arguments = Vec::new();
    if let Some(budget) = budget {
        arguments.push(OsString::from(budget));
    }
    arguments.extend([
        OsString::from("--sealed"),
        OsString::from("--report"),
        report_path.as_os_str().to_os_string(),
        OsString::from("--"),
        target_program.as_os_str().to_os_string(),
    ]);
    arguments.extend(target_arguments.iter().cloned());
    let _ = CommandSpec::new(cli, root, DEADLINE)
        .args(arguments)
        .output()?;
    let report: MemcordonReport = serde_json::from_slice(&fs::read(&report_path)?)?;
    validate_public_launch(&report)?;
    let outcome = report
        .attempts
        .last()
        .and_then(|attempt| attempt.outcome.clone())
        .ok_or_else(|| CiError::Message(format!("Windows {name} report has no outcome")))?;
    fs::remove_file(report_path)?;
    Ok(outcome)
}

fn run_spawn_failure_scenario(
    root: &Path,
    cli: &Path,
    reports: &Path,
    name: &str,
    target_program: &Path,
) -> Result<memcordon_core::SupervisionErrorRecord> {
    let report_path = reports.join(format!("status-{name}.json"));
    let _ = CommandSpec::new(cli, root, DEADLINE)
        .args([
            OsString::from("--sealed"),
            OsString::from("--report"),
            report_path.as_os_str().to_os_string(),
            OsString::from("--"),
            target_program.as_os_str().to_os_string(),
        ])
        .output()?;
    let report: MemcordonReport = serde_json::from_slice(&fs::read(&report_path)?)?;
    let error = report
        .attempts
        .last()
        .and_then(|attempt| attempt.error.clone())
        .ok_or_else(|| CiError::Message(format!("Windows {name} report has no typed error")))?;
    fs::remove_file(report_path)?;
    Ok(error)
}

pub fn package_certify(root: &Path, stable: &str) -> Result<()> {
    require_windows()?;
    require_native_architecture()?;
    let channel = root.join("target").join("ci").join("windows-sealed-cargo");
    fs::create_dir_all(&channel)?;
    let install_root = channel.join("install");
    if install_root.exists() {
        fs::remove_dir_all(&install_root)?;
    }
    let sources = channel.join("packaged-sources");
    if sources.exists() {
        fs::remove_dir_all(&sources)?;
    }
    fs::create_dir_all(&sources)?;
    let version = env!("CARGO_PKG_VERSION");
    let packages = [
        "memcordon-core".to_owned(),
        "memcordon-platform".to_owned(),
        "memcordon".to_owned(),
    ];
    create_package_archives(root, stable, &packages)?;
    let core = sources.join("memcordon-core");
    let platform = sources.join("memcordon-platform");
    let cli_source = sources.join("memcordon");
    for (package, destination) in [
        ("memcordon-core", &core),
        ("memcordon-platform", &platform),
        ("memcordon", &cli_source),
    ] {
        extract_crate_source(
            &root
                .join("target")
                .join("package")
                .join(format!("{package}-{version}.crate")),
            destination,
        )?;
    }
    write_packaged_source_configuration(&sources, &core, &platform)?;
    rustup_cargo(
        &sources,
        stable,
        [
            OsString::from("install"),
            OsString::from("--locked"),
            OsString::from("--path"),
            cli_source.into_os_string(),
            OsString::from("--root"),
            install_root.clone().into_os_string(),
            OsString::from("--force"),
        ],
        DEADLINE,
    )
    .run()?;
    let agent = install_root.join("bin").join("memcordon-sealed-agent.exe");
    let cli = install_root.join("bin").join("memcordon.exe");
    let cargo_fingerprint = channel_smoke(root, &agent, &cli, &channel)?;
    let native_fingerprint = fingerprint_from_reports(&report_directory(root))?;
    if cargo_fingerprint != native_fingerprint {
        return Err(CiError::Message(format!(
            "Cargo/native Windows sealed channel identity differs: cargo={cargo_fingerprint:?} native={native_fingerprint:?}"
        )));
    }
    write_json(&channel.join("cargo-fingerprint.json"), &cargo_fingerprint)?;
    write_json(
        &channel.join("native-fingerprint.json"),
        &native_fingerprint,
    )
}

fn write_packaged_source_configuration(sources: &Path, core: &Path, platform: &Path) -> Result<()> {
    let cargo_configuration = sources.join(".cargo");
    fs::create_dir_all(&cargo_configuration)?;
    let mut core_specification = toml::Table::new();
    core_specification.insert(
        "path".to_owned(),
        toml::Value::String(core.to_string_lossy().into_owned()),
    );
    let mut platform_specification = toml::Table::new();
    platform_specification.insert(
        "path".to_owned(),
        toml::Value::String(platform.to_string_lossy().into_owned()),
    );
    let mut crates_io = toml::Table::new();
    crates_io.insert(
        "memcordon-core".to_owned(),
        toml::Value::Table(core_specification),
    );
    crates_io.insert(
        "memcordon-platform".to_owned(),
        toml::Value::Table(platform_specification),
    );
    let mut patch_table = toml::Table::new();
    patch_table.insert("crates-io".to_owned(), toml::Value::Table(crates_io));
    let mut configuration = toml::Table::new();
    configuration.insert("patch".to_owned(), toml::Value::Table(patch_table));
    fs::write(
        cargo_configuration.join("config.toml"),
        toml::to_string(&toml::Value::Table(configuration)).map_err(|error| {
            CiError::Message(format!(
                "packaged-source Cargo configuration serialization failed: {error}"
            ))
        })?,
    )?;
    Ok(())
}

struct NativeChannel {
    root: PathBuf,
    archive_sha256: Option<String>,
    runtime_manifest_sha256: Option<String>,
    target: Option<String>,
}

fn native_channel_binaries(root: &Path, stable: &str) -> Result<NativeChannel> {
    let input = root.join("target").join("ci").join("release-input");
    if !input.is_dir() {
        build(root, stable)?;
        return Ok(NativeChannel {
            root: root
                .join("target")
                .join("ci")
                .join("windows-sealed")
                .join("debug"),
            archive_sha256: None,
            runtime_manifest_sha256: None,
            target: None,
        });
    }
    let mut archives = fs::read_dir(&input)?
        .map(|entry| entry.map(|entry| entry.path()).map_err(CiError::from))
        .collect::<Result<Vec<_>>>()?;
    archives.retain(|path| {
        path.extension().and_then(|extension| extension.to_str()) == Some("zip")
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("memcordon-v"))
    });
    if archives.len() != 1 {
        return Err(CiError::Message(format!(
            "Windows release certification requires exactly one downloaded native archive, found {}",
            archives.len()
        )));
    }
    let destination = root
        .join("target")
        .join("ci")
        .join("windows-sealed-native-archive");
    if destination.exists() {
        fs::remove_dir_all(&destination)?;
    }
    fs::create_dir_all(&destination)?;
    let archive_sha256 = sha256_file(&archives[0])?;
    let archive_file = fs::File::open(&archives[0])?;
    let mut archive = ZipArchive::new(archive_file)
        .map_err(|error| CiError::Message(format!("Windows native archive is invalid: {error}")))?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| {
            CiError::Message(format!("Windows native archive member is invalid: {error}"))
        })?;
        let relative = entry.enclosed_name().ok_or_else(|| {
            CiError::Message("Windows native archive member escapes extraction root".to_owned())
        })?;
        let output = destination.join(relative);
        if entry.is_dir() {
            fs::create_dir_all(&output)?;
        } else {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = fs::File::create(output)?;
            std::io::copy(&mut entry, &mut file)?;
        }
    }
    let mut roots = fs::read_dir(&destination)?
        .map(|entry| entry.map(|entry| entry.path()).map_err(CiError::from))
        .collect::<Result<Vec<_>>>()?;
    if roots.len() != 1 || !roots[0].is_dir() {
        return Err(CiError::Message(
            "Windows native archive must have exactly one top-level directory".to_owned(),
        ));
    }
    let extracted = roots.remove(0);
    let manifest_path = extracted.join("runtime-manifest.json");
    let runtime_manifest_sha256 = sha256_file(&manifest_path)?;
    let manifest: RuntimeManifestV1 = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let expected_target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-pc-windows-msvc",
        "aarch64" => "aarch64-pc-windows-msvc",
        architecture => {
            return Err(CiError::Message(format!(
                "Windows native certification does not support host architecture {architecture}"
            )));
        }
    };
    let commit = String::from_utf8(git(root, ["rev-parse", "HEAD"])?)
        .map_err(|error| CiError::Message(format!("git commit identity was not UTF-8: {error}")))?;
    if manifest.schema_version != 1
        || manifest.project != "memcordon"
        || manifest.version != env!("CARGO_PKG_VERSION")
        || manifest.source_commit != commit.trim_end_matches(['\r', '\n'])
        || manifest.target != expected_target
        || !matches!(
            manifest.sealed,
            SealedRuntimeV1::Included {
                provider_protocol: memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION,
                mechanism: ref value,
                execution_report_schema: memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
                qualification_schema: memcordon_core::WINDOWS_QUALIFICATION_SCHEMA_VERSION,
                ..
            } if value == "windows-job-object-v2"
        )
    {
        return Err(CiError::Message(
            "Windows native archive runtime manifest does not match this certification host"
                .to_owned(),
        ));
    }
    for component in &manifest.components {
        let relative = Path::new(&component.path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(CiError::Message(
                "Windows runtime manifest contains a non-local component path".to_owned(),
            ));
        }
        let component_path = extracted.join(relative);
        if fs::metadata(&component_path)?.len() != component.size
            || sha256_file(&component_path)? != component.sha256
        {
            return Err(CiError::Message(format!(
                "Windows runtime component does not match its manifest: {}",
                component.id
            )));
        }
    }
    Ok(NativeChannel {
        root: extracted,
        archive_sha256: Some(archive_sha256),
        runtime_manifest_sha256: Some(runtime_manifest_sha256),
        target: Some(manifest.target),
    })
}

fn sha256_file(path: &Path) -> Result<String> {
    use std::io::Read;

    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn channel_parity(root: &Path, stable: &str) -> Result<()> {
    require_windows()?;
    let channel = root.join("target").join("ci").join("windows-sealed-cargo");
    if !channel.join("cargo-fingerprint.json").is_file() {
        package_certify(root, stable)?;
    }
    let cargo: ChannelFingerprint =
        serde_json::from_slice(&fs::read(channel.join("cargo-fingerprint.json"))?)?;
    let native: ChannelFingerprint =
        serde_json::from_slice(&fs::read(channel.join("native-fingerprint.json"))?)?;
    if cargo == native {
        Ok(())
    } else {
        Err(CiError::Message(
            "Cargo/native Windows sealed channel parity failed".to_owned(),
        ))
    }
}

fn channel_smoke(
    root: &Path,
    agent: &Path,
    cli: &Path,
    channel: &Path,
) -> Result<ChannelFingerprint> {
    let package =
        run_json(&CommandSpec::new(agent, root, DEADLINE).args(["package", "inspect", "--json"]))?;
    CommandSpec::new(agent, root, DEADLINE)
        .args(["package", "install", "--ephemeral-ci"])
        .run()?;
    let qualification_value = run_json(&CommandSpec::new(agent, root, DEADLINE).arg("qualify"))?;
    let qualification: WindowsQualificationReceiptV1 = serde_json::from_value(qualification_value)?;
    let report_path = channel.join("cargo-public-launch.json");
    CommandSpec::new(cli, root, DEADLINE)
        .args([
            OsString::from("--sealed"),
            OsString::from("--report"),
            report_path.as_os_str().to_os_string(),
            OsString::from("--"),
            agent.as_os_str().to_os_string(),
            OsString::from("--version"),
        ])
        .run()?;
    let report: MemcordonReport = serde_json::from_slice(&fs::read(&report_path)?)?;
    validate_public_launch(&report)?;
    let fingerprint = channel_fingerprint(package, &qualification, &report)?;
    CommandSpec::new(agent, root, DEADLINE)
        .args(["package", "uninstall", "--ephemeral-ci"])
        .run()?;
    if !provider_state_absent(root, agent)? {
        return Err(CiError::Message(
            "Cargo-installed Windows provider left persistent state".to_owned(),
        ));
    }
    Ok(fingerprint)
}

fn fingerprint_from_reports(reports: &Path) -> Result<ChannelFingerprint> {
    let package: Value =
        serde_json::from_slice(&fs::read(reports.join("windows-package-inspection.json"))?)?;
    let qualification: WindowsQualificationReceiptV1 =
        serde_json::from_slice(&fs::read(reports.join("windows-qualification.json"))?)?;
    let cleanup: Value = serde_json::from_slice(&fs::read(reports.join("windows-cleanup.json"))?)?;
    let report: MemcordonReport = serde_json::from_value(
        cleanup
            .pointer("/runtime/public_launch")
            .cloned()
            .ok_or_else(|| {
                CiError::Message("native channel launch evidence is missing".to_owned())
            })?,
    )?;
    channel_fingerprint(package, &qualification, &report)
}

fn channel_fingerprint(
    mut package: Value,
    qualification: &WindowsQualificationReceiptV1,
    report: &MemcordonReport,
) -> Result<ChannelFingerprint> {
    package
        .as_object_mut()
        .ok_or_else(|| CiError::Message("Windows package inspection is not an object".to_owned()))?
        .remove("executable_sha256");
    let attempt = report
        .attempts
        .last()
        .ok_or_else(|| CiError::Message("channel report has no attempt".to_owned()))?;
    let BoundaryMechanismEvidence::WindowsJobObjectV2(native) = &attempt.boundary_detail else {
        return Err(CiError::Message(
            "channel report has the wrong native evidence".to_owned(),
        ));
    };
    Ok(ChannelFingerprint {
        package_identity: package,
        qualification_schema: qualification.schema_version,
        provider_identity: qualification.provider_identity.clone(),
        provider_protocol_schema: memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION,
        execution_report_schema: memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
        boundary_evidence_schema: native.schema_version,
        execution_mechanism: attempt.launch.mechanism.clone(),
        sealed_behavior: serde_json::json!({
            "target_released": attempt.launch.target_released,
            "containment_verified_before_authorization": attempt.launch.containment_verified_before_authorization,
            "guardian_started_before_authorization": attempt.launch.guardian_started_before_authorization,
            "target_spawn_error_reported": attempt.launch.target_spawn_error_reported,
            "active_processes_zero": native.active_processes_zero,
            "relays_retired": native.relays_retired,
            "guardian_reaped": native.guardian_reaped,
            "final_job_handles_closed": native.final_job_handles_closed,
        }),
    })
}

fn build(root: &Path, stable: &str) -> Result<()> {
    rustup_cargo(
        root,
        stable,
        [
            "build",
            "--locked",
            "--target-dir",
            "target/ci/windows-sealed",
            "--package",
            "memcordon",
            "--bins",
        ],
        DEADLINE,
    )
    .run()?;
    Ok(())
}

fn require_windows() -> Result<()> {
    if cfg!(target_os = "windows") {
        Ok(())
    } else {
        Err(CiError::Message(
            "Windows sealed certification requires a native Windows runner".to_owned(),
        ))
    }
}

fn require_native_architecture() -> Result<()> {
    if matches!(std::env::consts::ARCH, "x86_64" | "aarch64") {
        Ok(())
    } else {
        Err(CiError::Message(format!(
            "Windows sealed certification does not support architecture {}",
            std::env::consts::ARCH
        )))
    }
}

fn report_directory(root: &Path) -> PathBuf {
    root.join(REPORT_DIRECTORY)
}

fn run_json(spec: &CommandSpec) -> Result<Value> {
    Ok(serde_json::from_slice(&spec.run()?)?)
}

fn command_failed_with(spec: &CommandSpec, diagnostic: &str) -> Result<bool> {
    let output = spec.output()?;
    Ok(!output.status.success() && String::from_utf8_lossy(&output.stderr).contains(diagnostic))
}

fn spawn_hold(root: &Path, cli: &Path, agent: &Path, report: &Path) -> Result<Child> {
    let mut command = Command::new(cli);
    command
        .args([
            OsString::from("--sealed"),
            OsString::from("--report"),
            report.as_os_str().to_os_string(),
            OsString::from("--"),
            agent.as_os_str().to_os_string(),
            OsString::from("windows-certification-hold"),
        ])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.spawn().map_err(Into::into)
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn attempts_root() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("MemCordon")
        .join("sealed")
        .join("attempts")
}

fn attempts_empty(root: &Path, agent: &Path) -> Result<bool> {
    let output = CommandSpec::new(agent, root, DEADLINE)
        .arg("windows-recovery-status")
        .run()?;
    match String::from_utf8(output)
        .map_err(|error| CiError::Message(error.to_string()))?
        .trim()
    {
        "true" => Ok(true),
        "false" => Ok(false),
        value => Err(CiError::Message(format!(
            "invalid Windows recovery status: {value}"
        ))),
    }
}

fn wait_for_active_attempt(root: &Path, agent: &Path) -> Result<()> {
    wait_for_attempt_state(
        root,
        agent,
        false,
        "active Windows sealed attempt was not observed",
    )
}

fn wait_for_attempts_empty(root: &Path, agent: &Path) -> Result<()> {
    wait_for_attempt_state(
        root,
        agent,
        true,
        "Windows sealed attempt record did not retire",
    )
}

fn wait_for_attempt_state(
    root: &Path,
    agent: &Path,
    expected_empty: bool,
    message: &str,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if attempts_empty(root, agent)? == expected_empty {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(CiError::Message(message.to_owned()));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn validate_public_launch(report: &MemcordonReport) -> Result<()> {
    let attempt = report.attempts.last().ok_or_else(|| {
        CiError::Message("Windows sealed launch has no attempt evidence".to_owned())
    })?;
    let native = match &attempt.boundary_detail {
        BoundaryMechanismEvidence::WindowsJobObjectV2(native) => native,
        _ => {
            return Err(CiError::Message(
                "Windows sealed launch did not contain Windows v2 evidence".to_owned(),
            ));
        }
    };
    if !attempt.launch.target_released
        || !attempt.launch.containment_verified_before_authorization
        || !attempt.launch.guardian_started_before_authorization
        || !attempt.launch.target_spawn_error_reported
        || !attempt.launch.boundary_assignment_verified
        || !attempt.launch.boundary_reconfiguration_denied
        || !attempt.launch.inherited_resources_restricted
        || !attempt.launch.frontend_loss_cleanup_authority_verified
        || !native.caller_token_authenticated
        || !native.initial_target_token_matches_caller
        || native.credential_transition_disposition
            != CredentialTransitionDisposition::PreserveCallerEnvelope
        || !native.job_membership_independent_of_token
        || !native.job_created
        || !native.job_limits_verified
        || !native.kill_on_close_verified
        || !native.breakaway_denied
        || !native.completion_port_associated
        || !native.guardian_ready
        || !native.target_created_suspended
        || !native.job_list_applied_at_creation
        || !native.handle_list_applied_at_creation
        || !native.target_job_membership_verified
        || !native.target_still_suspended_during_verification
        || !native.inherited_handles_verified
        || !native.target_released
        || !native.terminate_job_invoked
        || !native.active_processes_zero
        || !native.direct_target_reaped
        || !native.relays_retired
        || !native.guardian_reaped
        || !native.final_job_handles_closed
        || !memcordon_core::boundary_evidence_is_consistent(
            &attempt.launch,
            &attempt.restart_safety,
            &attempt.boundary_detail,
        )
    {
        return Err(CiError::Message(
            "Windows sealed public launch evidence is incomplete".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Each argument is a distinct certified evidence class.
fn write_auxiliary_reports(
    reports: &Path,
    commit: &str,
    qualification: &Value,
    fault_matrix: &WindowsCertificationObservationsV1,
    token_matrix: &WindowsTokenMatrixEvidenceV1,
    authority_loss: &WindowsAuthorityLossEvidenceV1,
    mutant_kills: &WindowsMutantKillEvidenceV1,
    public_launch: &MemcordonReport,
) -> Result<()> {
    let qualification: WindowsQualificationReceiptV1 =
        serde_json::from_value(qualification.clone())?;
    let attempt = public_launch
        .attempts
        .last()
        .ok_or_else(|| CiError::Message("Windows launch evidence has no attempt".to_owned()))?;
    let BoundaryMechanismEvidence::WindowsJobObjectV2(native) = &attempt.boundary_detail else {
        return Err(CiError::Message(
            "Windows launch evidence has the wrong mechanism".to_owned(),
        ));
    };
    write_scenario_evidence(
        reports,
        commit,
        "windows-token-envelope.json",
        &TokenEnvelopeEvidence {
            service_identity: &native.service_identity,
            caller_token_authenticated: native.caller_token_authenticated,
            initial_target_token_matches_caller: native.initial_target_token_matches_caller,
            credential_transition_disposition: native.credential_transition_disposition,
            restricted_caller_token_verified: qualification.restricted_caller_token_verified,
            primary_token_duplication_verified: qualification.primary_token_duplication_verified,
            token_matrix,
        },
    )?;
    write_scenario_evidence(
        reports,
        commit,
        "windows-handle-inventory.json",
        &HandleInventoryEvidence {
            job_list_applied_at_creation: native.job_list_applied_at_creation,
            handle_list_applied_at_creation: native.handle_list_applied_at_creation,
            inherited_handles_verified: native.inherited_handles_verified,
            exact_handle_inheritance_verified: qualification.exact_handle_inheritance_verified,
            relays_retired: native.relays_retired,
        },
    )?;
    write_scenario_evidence(
        reports,
        commit,
        "windows-preauthorization.json",
        &PreauthorizationEvidence {
            guardian_ready: native.guardian_ready,
            target_created_suspended: native.target_created_suspended,
            target_job_membership_verified: native.target_job_membership_verified,
            target_still_suspended_during_verification: native
                .target_still_suspended_during_verification,
            target_released: native.target_released,
            fault_matrix,
            mutant_kills,
        },
    )?;
    write_scenario_evidence(
        reports,
        commit,
        "windows-alternate-token.json",
        &AlternateTokenEvidence {
            alternate_token_child_contained: qualification.alternate_token_child_contained,
            initial_target_token_matches_caller: native.initial_target_token_matches_caller,
            job_membership_independent_of_token: native.job_membership_independent_of_token,
        },
    )?;
    write_scenario_evidence(
        reports,
        commit,
        "windows-nested-job.json",
        &NestedJobEvidence {
            nested_host_job_supported: qualification.nested_host_job_supported,
            nested_child_job_contained: qualification.nested_child_job_contained,
            target_job_membership_verified: native.target_job_membership_verified,
        },
    )?;
    write_scenario_evidence(
        reports,
        commit,
        "windows-front-end-loss.json",
        &FrontendLossEvidence {
            frontend_loss_cleanup_verified: qualification.frontend_loss_cleanup_verified,
            record_retired: qualification.frontend_loss_cleanup_verified,
            active_processes_zero_verified: qualification.active_processes_zero_verified,
            guardian_verified: qualification.guardian_verified,
            authority_loss: authority_loss.clone(),
        },
    )?;
    write_scenario_evidence(
        reports,
        commit,
        "windows-recovery.json",
        &RecoveryEvidence {
            recovery_complete: qualification.recovery_complete,
            active_processes_zero_verified: qualification.active_processes_zero_verified,
            relays_retired_verified: qualification.relays_retired_verified,
            authority_loss: authority_loss.clone(),
        },
    )?;
    Ok(())
}

fn write_scenario_evidence<T: Serialize>(
    reports: &Path,
    commit: &str,
    name: &str,
    evidence: &T,
) -> Result<()> {
    write_json(
        &reports.join(name),
        &EvidenceEnvelope {
            schema_version: 1,
            mechanism: "windows-job-object-v2",
            architecture: std::env::consts::ARCH,
            commit,
            result: "passed",
            evidence,
        },
    )
}

fn provider_state_absent(root: &Path, agent: &Path) -> Result<bool> {
    let program_data = attempts_root()
        .parent()
        .map(Path::to_path_buf)
        .is_some_and(|path| !path.exists());
    let program_files = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
        .join("MemCordon");
    let native_absence = CommandSpec::new(agent, root, DEADLINE)
        .arg("windows-provider-state-absent")
        .output()?;
    if !native_absence.status.success() {
        return Err(CiError::Message(
            "native Windows provider absence probe failed".to_owned(),
        ));
    }
    let native_absence = String::from_utf8(native_absence.stdout).map_err(|error| {
        CiError::Message(format!("provider absence result was not UTF-8: {error}"))
    })?;
    Ok(program_data && !program_files.exists() && native_absence.trim() == "true")
}

fn runner_label() -> String {
    match std::env::consts::ARCH {
        "x86_64" => "windows-2025".to_owned(),
        "aarch64" => "windows-11-arm".to_owned(),
        architecture => architecture.to_owned(),
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}
