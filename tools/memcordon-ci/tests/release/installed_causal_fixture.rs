//! Synthetic installed-Windows evidence for release-transport tests only.
//! This does not assert that native Windows acceptance ran on this host.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use memcordon_ci::release_evidence::CertificationRecord;
use memcordon_ci::windows_causal_acceptance::{
    CleanupEvidenceV1, FixtureExitEvidenceV1, FixtureProcessIdentityV1, InstalledChannel,
    InvocationEvidenceV1, RAW_SUFFIXES, raw_name, write_acceptance, write_raw,
};
use memcordon_core::runtime_manifest::{
    RuntimeComponentRecord, RuntimeComponentRole, RuntimeManifestV2,
};
use memcordon_core::{
    AttemptObservationPhaseV1, BackendCapabilityReport, BoundaryCapability, BoundaryClass,
    BoundaryQualificationReport, BoundaryRequirement, BoundarySetupPhase, BudgetKindReport,
    BudgetTokenReport, CausalEventV1, DeadlinePolicyReport, DeadlineScope, DiagnosticOriginV1,
    EffectivePolicyReport, EffectiveRestartPolicyReport, ExecutionErrorReport, FailureCategoryV1,
    FailureCodeV1, FailureOperationV1, InvocationReport, MemcordonReport, NativeArgument,
    PolicyEnvelopeReport, ProviderFailureDiagnosticV1, ProviderRejectionEvidence,
    RequestedPolicyReport, RequestedRestartPolicyReport, RestartConditions, RestartLimit,
    RestartSafetyProof, SafeDiagnosticDetailV1, SafeMessageIdV1, ToolReport,
    WINDOWS_QUALIFICATION_SCHEMA_VERSION, WindowsCausalDiagnosticsV1,
    WindowsQualificationReceiptV1,
};
use serde_json::json;
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn qualification() -> WindowsQualificationReceiptV1 {
    let receipt = WindowsQualificationReceiptV1 {
        schema_version: WINDOWS_QUALIFICATION_SCHEMA_VERSION,
        provider_identity: format!(
            "memcordon-sealed-agent-windows-v1:{}",
            env!("CARGO_PKG_VERSION")
        ),
        control_service_identity: "MemCordonSealedControl:LocalService:restricted".into(),
        launcher_service_identity: "MemCordonSealedLauncher:LocalSystem:restricted".into(),
        guardian_pool_identity: "MemCordonSealedGuardian-000..007:LocalSystem:restricted:demand"
            .into(),
        package_verified: true,
        public_pipe_security_verified: true,
        private_pipe_security_verified: true,
        control_service_privileges_verified: true,
        launcher_service_privileges_verified: true,
        guardian_slot_tokens_verified: true,
        guardian_slot_loader_verified: true,
        guardian_capacity_verified: true,
        caller_token_authentication_verified: true,
        restricted_caller_token_verified: true,
        primary_token_duplication_verified: true,
        create_process_as_user_verified: true,
        job_list_supported: true,
        handle_list_supported: true,
        nested_host_job_supported: true,
        kill_on_close_verified: true,
        breakaway_denied: true,
        completion_port_verified: true,
        guardian_verified: true,
        frontend_loss_cleanup_verified: true,
        alternate_token_child_contained: true,
        nested_child_job_contained: true,
        recursive_provider_request_denied: true,
        exact_handle_inheritance_verified: true,
        active_processes_zero_verified: true,
        relays_retired_verified: true,
        recovery_complete: true,
        loader_qualification: memcordon_core::WindowsLoaderQualificationOutcomeV2::Ready(
            memcordon_core::WindowsLoaderReadyEvidenceV1 {
                schema_version: 1,
                launch_plan_sha256: digest(b"production-plan"),
                launch_plan_json: None,
                elapsed_millis: 1,
            },
        ),
        qualified: true,
    };
    assert!(receipt.is_consistent());
    receipt
}

fn failed_report(
    receipt: &WindowsQualificationReceiptV1,
    manifest_bytes: &[u8],
) -> MemcordonReport {
    let manifest = RuntimeManifestV2::parse(manifest_bytes).expect("fixture manifest should parse");
    let binding = manifest
        .public_binding(manifest_bytes)
        .expect("fixture manifest should bind");
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal
        .observe(CausalEventV1 {
            sequence: 0,
            origin: DiagnosticOriginV1::Launcher,
            category: FailureCategoryV1::Monitor,
            operation: FailureOperationV1::AccumulateProcessInventory,
            code: FailureCodeV1::ProcessInventoryCapacity,
            native_code: None,
            observed_phase: AttemptObservationPhaseV1::Monitoring,
            safe_detail: SafeDiagnosticDetailV1::CountAndLimit {
                observed: 257,
                limit: 256,
            },
            detail_redacted: false,
            detail_truncated: false,
            terminalization_reference: None,
        })
        .expect("original failure should append");
    journal
        .observe(CausalEventV1 {
            sequence: 0,
            origin: DiagnosticOriginV1::Launcher,
            category: FailureCategoryV1::Terminalization,
            operation: FailureOperationV1::ValidateTerminalResponse,
            code: FailureCodeV1::TerminalBinding,
            native_code: None,
            observed_phase: AttemptObservationPhaseV1::Terminalizing,
            safe_detail: SafeDiagnosticDetailV1::ProviderMessage {
                id: SafeMessageIdV1::ReceiptRequiredForPosttarget,
            },
            detail_redacted: false,
            detail_truncated: false,
            terminalization_reference: None,
        })
        .expect("secondary failure should append");
    journal.durable_through_sequence = Some(journal.sequence);
    let projection = ProviderFailureDiagnosticV1::from_journal(
        binding,
        &"11".repeat(32),
        &"22".repeat(32),
        &journal,
    )
    .expect("projection should bind");
    let rejection = ProviderRejectionEvidence {
        workload_admission: None,
        provider_failure: Some(projection.clone()),
        schema_version: 1,
        code: "MCSEALED-WINDOWS-TERMINAL-BINDING".into(),
        phase: BoundarySetupPhase::Monitoring,
        detail: "receipt required for posttarget refusal".into(),
        os_code: None,
        loader_qualification: None,
        target_created: true,
        target_released: true,
        cleanup_attempted: true,
        restart_safety: RestartSafetyProof::default(),
        terminal_ack_required: false,
        terminal_receipt: None,
    };
    let error = ExecutionErrorReport {
        runtime: None,
        native_startup: None,
        policy_enforcement: None,
        category: "monitor".into(),
        code: "MCSEALED-WINDOWS-PROCESS-INVENTORY-CAPACITY".into(),
        message: "inventory capacity observed".into(),
        os_code: None,
        attempt_number: Some(1),
        supervision_phase: Some("monitoring".into()),
        launch_phase: Some("monitoring".into()),
        target_released: true,
        workload_may_be_alive: false,
        boundary_setup_failure: None,
        provider_rejection: Some(rejection),
        provider_failure: Some(projection),
    };
    let backend = BackendCapabilityReport {
        name: "windows-job-object".into(),
        boundary: BoundaryCapability {
            class: BoundaryClass::Sealed,
            mechanism: "windows-job-object-v2".into(),
            target_gated: true,
            boundary_verified_before_authorization: true,
            target_can_reconfigure_boundary: false,
            frontend_loss_cleanup_authority: true,
            workload_empty_proof: true,
            limitations: Vec::new(),
        },
        boundary_qualification: Some(BoundaryQualificationReport {
            provider_identity: receipt.provider_identity.clone(),
            receipt_digest: digest(&serde_json::to_vec(receipt).expect("serialize receipt")),
            mechanism: "windows-job-object-v2".into(),
        }),
        ..BackendCapabilityReport::default()
    };
    let invocation = InvocationReport {
        syntax: "plus-budgets-v1".into(),
        budget_tokens: vec![BudgetTokenReport {
            kind: BudgetKindReport::Time,
            token: "+1s".into(),
        }],
        memory_token: None,
        deadline_token: Some("+1s".into()),
        argv: vec![
            NativeArgument::from_os(OsStr::new("inventory-fixture.exe")),
            NativeArgument::from_os(OsStr::new("windows-inventory-capacity")),
        ],
    };
    let policy = PolicyEnvelopeReport {
        requested: RequestedPolicyReport {
            workload: Default::default(),
            boundary: BoundaryRequirement::Sealed,
            memory: None,
            deadline: Some(DeadlinePolicyReport {
                duration_ms: 1_000,
                scope: DeadlineScope::Attempt,
                origin: None,
                clock: "rust-instant".into(),
            }),
            wait_for: "command".into(),
            signal_grace_ms: 2_000,
            command_exit_grace_ms: 0,
            limit_grace_ms: 0,
            restart: RequestedRestartPolicyReport {
                enabled: false,
                enablement_source: None,
                configured_conditions: RestartConditions::NONE,
                limit: RestartLimit::Unlimited,
                backoff: None,
                circuit_breaker: None,
            },
        },
        effective: EffectivePolicyReport {
            workload: memcordon_core::workload_evidence::WorkloadResolutionReportV1::unresolved(
                None,
                memcordon_core::workload_evidence::BaselineRestrictionObservationV1::UnmanagedStandardBackend,
            ),
            boundary: BoundaryClass::Sealed,
            memory: None,
            deadline: Some(DeadlinePolicyReport {
                duration_ms: 1_000,
                scope: DeadlineScope::Attempt,
                origin: Some("fixture".into()),
                clock: "rust-instant".into(),
            }),
            wait_for: "command".into(),
            signal_grace_ms: 2_000,
            command_exit_grace_ms: 0,
            limit_grace_ms: 0,
            restart: EffectiveRestartPolicyReport {
                enabled: false,
                conditions: RestartConditions::NONE,
                dormant_conditions: Vec::new(),
                cleanup_proof_required: true,
            },
        },
        effects: Vec::new(),
    };
    MemcordonReport::schema9(
        ToolReport {
            name: "memcordon".into(),
            version: "test".into(),
        },
        invocation,
        policy,
        Some(backend),
        None,
        Some(error),
    )
    .expect("failed public invocation should be valid")
}

pub(super) fn write_installed_causal_fixture(
    output: &Path,
    source_commit: &str,
) -> BTreeMap<String, CertificationRecord> {
    let directory = output.join("certification/windows-causal");
    fs::create_dir_all(&directory).expect("installed causal fixture directory should exist");
    let receipt = qualification();
    let receipt_bytes = serde_json::to_vec_pretty(&receipt).expect("serialize qualification");
    let fixture_sha256 = "cc".repeat(32);
    let family = std::iter::once(FixtureProcessIdentityV1 {
        ordinal: None,
        pid: 41,
        birth: 101,
    })
    .chain(
        (0..memcordon_core::WINDOWS_MAX_JOB_PROCESS_IDENTITIES).map(|ordinal| {
            FixtureProcessIdentityV1 {
                ordinal: Some(ordinal),
                pid: u32::try_from(ordinal).expect("fixture ordinal fits u32") + 42,
                birth: u128::try_from(ordinal).expect("fixture ordinal fits u128") + 102,
            }
        }),
    )
    .collect::<Vec<_>>();
    let mut stdout_bytes = Vec::new();
    for identity in &family {
        let kind = if identity.ordinal.is_some() {
            "inventory-leaf-ready"
        } else {
            "inventory-root-ready"
        };
        let line = json!({
            "kind": kind,
            "ordinal": identity.ordinal,
            "pid": identity.pid,
            "birth": identity.birth,
        });
        stdout_bytes.extend_from_slice(b"MEMCORDON-INVENTORY-READY:");
        stdout_bytes.extend_from_slice(line.to_string().as_bytes());
        stdout_bytes.push(b'\n');
    }
    let fixture_bytes = serde_json::to_vec_pretty(&FixtureExitEvidenceV1 {
        schema_version: 1,
        image_sha256: fixture_sha256.clone(),
        root_ready: true,
        observed_family: family,
        root_exited: true,
        all_matching_processes_gone: true,
    })
    .expect("serialize fixture exit evidence");
    let cleanup_bytes = serde_json::to_vec_pretty(&CleanupEvidenceV1 {
        schema_version: 1,
        attempts_empty: true,
        package_recovered: true,
    })
    .expect("serialize cleanup evidence");
    let invocation_bytes = serde_json::to_vec_pretty(&InvocationEvidenceV1 {
        schema_version: 1,
        exit_code: Some(1),
        runner_timed_out: false,
        cli_sha256: "dd".repeat(32),
        fixture_sha256: fixture_sha256.clone(),
    })
    .expect("serialize invocation evidence");
    let mut records = BTreeMap::new();
    for (target, channel, artifact, prefix) in
        memcordon_ci::workload_qualification::INSTALLED_CAUSAL_ARTIFACTS
    {
        let manifest = RuntimeManifestV2::windows(
            env!("CARGO_PKG_VERSION").into(),
            source_commit.into(),
            target.into(),
            vec![
                RuntimeComponentRecord {
                    id: "public-cli".into(),
                    path: "memcordon.exe".into(),
                    role: RuntimeComponentRole::PublicCli,
                    size: 1,
                    mode: 0,
                    sha256: "dd".repeat(32),
                },
                RuntimeComponentRecord {
                    id: "sealed-agent".into(),
                    path: "memcordon-sealed-agent.exe".into(),
                    role: RuntimeComponentRole::SealedAgent,
                    size: 1,
                    mode: 0,
                    sha256: "aa".repeat(32),
                },
            ],
        );
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).expect("serialize manifest");
        let report_bytes = serde_json::to_vec_pretty(&failed_report(&receipt, &manifest_bytes))
            .expect("serialize failed report");
        let package_bytes = serde_json::to_vec_pretty(&json!({
            "source_commit": source_commit,
            "version": env!("CARGO_PKG_VERSION"),
            "execution_report_schema": memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
            "compiled_metadata_valid": true,
        }))
        .expect("serialize package inventory");
        for (suffix, bytes) in [
            ("report.json", report_bytes.as_slice()),
            ("stdout.bin", stdout_bytes.as_slice()),
            ("stderr.bin", b"".as_slice()),
            ("package.json", package_bytes.as_slice()),
            ("qualification.json", receipt_bytes.as_slice()),
            ("fixture.json", fixture_bytes.as_slice()),
            ("cleanup.json", cleanup_bytes.as_slice()),
            ("invocation.json", invocation_bytes.as_slice()),
            ("runtime-manifest.json", manifest_bytes.as_slice()),
        ] {
            write_raw(&directory, prefix, suffix, bytes).expect("write installed raw evidence");
        }
        write_acceptance(
            &directory,
            prefix,
            artifact,
            source_commit,
            target,
            match channel {
                "native-bundle" => InstalledChannel::NativeBundle,
                "cargo-package" => InstalledChannel::CargoPackage,
                _ => panic!("unexpected installed channel"),
            },
            env!("CARGO_PKG_VERSION"),
            memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
            &fixture_sha256,
        )
        .expect("write validated installed acceptance");
        for name in std::iter::once(artifact.to_owned()).chain(
            RAW_SUFFIXES
                .into_iter()
                .map(|suffix| raw_name(prefix, suffix)),
        ) {
            let path = directory.join(&name);
            let relative = format!("certification/windows-causal/{name}");
            let bytes = fs::read(path).expect("read installed causal evidence");
            records.insert(
                format!("windows-causal/{name}"),
                CertificationRecord {
                    evidence_path: relative,
                    sha256: digest(&bytes),
                },
            );
        }
    }
    records
}
