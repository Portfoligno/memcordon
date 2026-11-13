use memcordon_ci::windows_causal_acceptance::{
    CaseFailure, CleanupFailure, CollectedFailure, CollectionFailure, InstalledCase,
    InstalledCaseResult, validate_guardian_failure_projection,
};
use memcordon_core::diagnostics::*;

#[test]
fn rooted_process_membership_rejects_preexisting_pid_ancestry() {
    use memcordon_ci::windows_consumer_readiness::rooted_process_depth;
    use std::collections::BTreeMap;
    let root = (3232, 134362137570896696);
    let old = (2320, 134362137552439155);
    let parents = BTreeMap::from([(2320, 11060), (11060, 3232), (4000, 3232), (4001, 4000)]);
    assert_eq!(rooted_process_depth(old, root, &parents), None);
    assert_eq!(rooted_process_depth(root, root, &parents), Some(0));
    assert_eq!(
        rooted_process_depth((3232, root.1 + 1), root, &parents),
        None
    );
    assert_eq!(
        rooted_process_depth((4000, root.1 + 1), root, &parents),
        Some(1)
    );
    assert_eq!(
        rooted_process_depth((4001, root.1 + 2), root, &parents),
        Some(2)
    );
    assert_eq!(
        rooted_process_depth((9999, root.1 + 1), root, &parents),
        None
    );
    let cycle = BTreeMap::from([(4000, 4001), (4001, 4000)]);
    assert_eq!(rooted_process_depth((4000, root.1 + 1), root, &cycle), None);
}

#[test]
fn working_windows_selection_requires_all_real_production_companions_on_each_native_architecture() {
    use memcordon_ci::release::windows_installed_consumer::selected_distribution;
    for target in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"] {
        let selection = selected_distribution(target).unwrap();
        assert_eq!(selection.target, target);
        assert_eq!(selection.features, ["windows-sealed-runtime"]);
        assert_eq!(
            selection.binaries,
            [
                "memcordon",
                "memcordon-sealed-agent",
                "memcordon-target-desktop-bootstrap",
                "memcordon-session-broker"
            ]
        );
        assert!(selection.units.is_empty());
    }
    assert!(selected_distribution("x86_64-unknown-linux-gnu").is_err());
    assert!(selected_distribution("aarch64-apple-darwin").is_err());
}

#[test]
fn materialized_windows_payload_binds_actual_bytes_and_rejects_source_or_binary_substitution() {
    use memcordon_ci::release::{
        artifacts,
        distribution::TargetDistribution,
        source::{BuildSourceIdentity, SelectedSource},
    };
    use memcordon_ci::windows_causal_acceptance::InstalledChannel;
    use memcordon_ci::windows_installed_cases::{InstalledWindowsPayload, SelectedArtifact};
    use memcordon_core::runtime_components::RuntimeComponentRole;
    use memcordon_core::runtime_manifest_v2::RuntimeManifestV2;

    let directory = tempfile::tempdir().unwrap();
    let source = SelectedSource {
        format: "memcordon.selected-source".into(),
        revision: 1,
        repository: "Portfoligno/memcordon".into(),
        tag_ref: "refs/tags/0.5.7-dev".into(),
        commit: "0123456789012345678901234567890123456789".into(),
        version: semver::Version::parse("0.5.7-dev").unwrap(),
    };
    let distribution = TargetDistribution {
        target: "x86_64-pc-windows-msvc".into(),
        features: vec!["windows-sealed-runtime".into()],
        binaries: vec![
            "memcordon".into(),
            "memcordon-sealed-agent".into(),
            "memcordon-target-desktop-bootstrap".into(),
            "memcordon-session-broker".into(),
        ],
        units: vec![],
    };
    // A minimal architecture header is enough for the byte identity constructor;
    // this test does not claim an executable or installed native lifecycle pass.
    let mut pe = vec![0; 70];
    pe[..2].copy_from_slice(b"MZ");
    pe[60..64].copy_from_slice(&64u32.to_le_bytes());
    pe[64..70].copy_from_slice(b"PE\0\0\x64\x86");
    let mut components = vec![];
    for (binary, role) in distribution.binaries.iter().zip([
        RuntimeComponentRole::PublicCli,
        RuntimeComponentRole::SealedAgent,
        RuntimeComponentRole::DesktopBootstrap,
        RuntimeComponentRole::SessionBroker,
    ]) {
        let name = format!("{binary}.exe");
        std::fs::write(directory.path().join(&name), &pe).unwrap();
        components.push(memcordon_ci::release::target::runtime_component(
            role, name, &pe,
        ));
    }
    let manifest = RuntimeManifestV2::windows(
        source.version.to_string(),
        source.commit.clone(),
        distribution.target.clone(),
        components,
    )
    .unwrap();
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    std::fs::write(
        directory.path().join("runtime-manifest.json"),
        &manifest_bytes,
    )
    .unwrap();
    let fixture = SelectedArtifact {
        path: directory.path().join("test-fixture.exe"),
        sha256: artifacts::checksum(&pe),
    };
    std::fs::write(&fixture.path, &pe).unwrap();
    let archive = SelectedArtifact {
        path: directory.path().join("native.zip"),
        sha256: artifacts::checksum(b"selected archive"),
    };
    std::fs::write(&archive.path, b"selected archive").unwrap();
    let cwd = std::env::current_dir().unwrap();
    let output_owner = tempfile::tempdir_in(&cwd).unwrap();
    let relative_output = output_owner
        .path()
        .strip_prefix(&cwd)
        .unwrap()
        .join("fresh/cases/windows-installed");
    assert!(!relative_output.is_absolute());
    assert!(!cwd.join(&relative_output).exists());
    let construct = |source: &SelectedSource| {
        InstalledWindowsPayload::from_materialized(
            InstalledChannel::NativeBundle,
            &BuildSourceIdentity::from(source.clone()),
            &distribution,
            vec![archive.clone()],
            directory.path(),
            fixture.clone(),
            &directory.path().join("installed"),
            relative_output.clone(),
        )
    };
    let payload = construct(&source).unwrap();
    assert_eq!(
        payload.fixture_manifest_inventory,
        memcordon_ci::windows_pe_manifest::inventory(&pe)
    );
    let select_agent = |source: &SelectedSource| {
        memcordon_ci::release::installed_consumer::materialized_windows_agent(
            &BuildSourceIdentity::from(source.clone()),
            &distribution,
            directory.path(),
        )
    };
    let agent = select_agent(&source).unwrap();
    assert_eq!(
        agent.path,
        directory.path().join("memcordon-sealed-agent.exe")
    );
    assert_eq!(agent.sha256, artifacts::checksum(&pe));
    assert_eq!(payload.artifacts.len(), 1);
    assert_eq!(payload.artifacts[0].path, archive.path);
    assert_eq!(payload.artifacts[0].sha256, archive.sha256);
    let select_components = || {
        memcordon_ci::release::installed_consumer::materialized_windows_components(
            &BuildSourceIdentity::from(source.clone()),
            &distribution,
            directory.path(),
        )
    };
    let (selected_manifest, components) = select_components().unwrap();
    assert_eq!(
        selected_manifest.path,
        directory.path().join("runtime-manifest.json")
    );
    assert_eq!(
        selected_manifest.sha256,
        artifacts::checksum(&manifest_bytes)
    );
    assert_eq!(components.len(), distribution.binaries.len());
    let actual_names: std::collections::BTreeSet<_> = components
        .iter()
        .map(|component| {
            assert!(component.path.is_absolute());
            assert_eq!(component.sha256, artifacts::checksum(&pe));
            component.path.file_name().unwrap().to_str().unwrap()
        })
        .collect();
    assert_eq!(
        actual_names,
        [
            "memcordon.exe",
            "memcordon-sealed-agent.exe",
            "memcordon-target-desktop-bootstrap.exe",
            "memcordon-session-broker.exe"
        ]
        .into_iter()
        .collect()
    );
    for field in ["role", "sha256"] {
        let mut corrupt = serde_json::to_value(&manifest).unwrap();
        corrupt["components"][1][field] = if field == "role" {
            serde_json::json!("public-cli")
        } else {
            serde_json::json!("00".repeat(32))
        };
        std::fs::write(
            &selected_manifest.path,
            serde_json::to_vec(&corrupt).unwrap(),
        )
        .unwrap();
        assert!(select_components().is_err(), "manifest component {field}");
    }
    std::fs::write(&selected_manifest.path, &manifest_bytes).unwrap();
    let omitted = directory.path().join("memcordon-session-broker.exe");
    std::fs::remove_file(&omitted).unwrap();
    assert!(
        select_components().is_err(),
        "missing materialized production component"
    );
    std::fs::write(omitted, &pe).unwrap();
    assert_eq!(payload.output_directory, cwd.join(&relative_output));
    assert!(payload.output_directory.is_absolute());
    assert!(!payload.output_directory.exists());
    let retained: InstalledWindowsPayload =
        serde_json::from_slice(&serde_json::to_vec(&payload).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(&retained).unwrap(),
        serde_json::to_value(&payload).unwrap()
    );
    let original_pending = payload.output_directory.join("pending-loader-diagnostic");
    let support_pending = retained.output_directory.join("pending-loader-diagnostic");
    assert_eq!(original_pending, support_pending);
    for selected in [
        original_pending.join("memcordon-target-desktop-bootstrap.exe"),
        support_pending.join("original-payload.json"),
        retained.output_directory.join("separate-loader-support"),
    ] {
        assert!(selected.is_absolute());
        assert!(selected.starts_with(&payload.output_directory));
    }
    assert_eq!(payload.components.len(), 4);
    assert_eq!(payload.cli.path, directory.path().join("memcordon.exe"));
    assert_eq!(payload.installed_components.len(), 3);
    let installed_names: std::collections::BTreeSet<_> = payload
        .installed_components
        .iter()
        .map(|artifact| artifact.path.file_name().unwrap().to_str().unwrap())
        .collect();
    assert_eq!(
        installed_names,
        [
            "memcordon-sealed-agent.exe",
            "memcordon-target-desktop-bootstrap.exe",
            "memcordon-session-broker.exe"
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        payload.provider,
        manifest.public_binding(&manifest_bytes).unwrap()
    );
    assert_eq!(
        payload.installed_manifest.sha256,
        artifacts::checksum(&manifest_bytes)
    );
    let mut foreign_source = source.clone();
    foreign_source.commit = "1123456789012345678901234567890123456789".into();
    assert!(construct(&foreign_source).is_err());
    assert!(select_agent(&foreign_source).is_err());
    assert!(
        memcordon_ci::release::installed_consumer::materialized_windows_agent(
            &BuildSourceIdentity::from(source.clone()),
            &distribution,
            &directory.path().join("absent"),
        )
        .is_err()
    );
    pe.push(1);
    std::fs::write(directory.path().join("memcordon.exe"), &pe).unwrap();
    assert!(construct(&source).is_err());
    assert!(select_agent(&source).is_err());
}

fn provider() -> PublicProviderBindingV1 {
    PublicProviderBindingV1 {
        generation: BoundedText::new("installed-generation-1").unwrap(),
        source_commit: BoundedText::new("0123456789012345678901234567890123456789").unwrap(),
        runtime_manifest_sha256: DiagnosticSha256::from_bytes([1; 32]),
    }
}

#[test]
fn late_transport_authority_requires_actual_bound_operation_and_peer_code() {
    use memcordon_ci::windows_readiness_components::transport_injection_authority;
    use memcordon_core::WindowsSealedFault;
    let selected = WindowsSealedFault::FrontendDisconnectedAfterAuthorization;
    let attempt = "02".repeat(32);
    let request = "03".repeat(32);
    let evaluate = |operation, phase, native_code, fault, actual_attempt: &str| {
        let mut journal = WindowsCausalDiagnosticsV1::default();
        journal
            .observe(CausalEventV1 {
                sequence: 0,
                origin: DiagnosticOriginV1::Launcher,
                category: FailureCategoryV1::Transport,
                operation,
                code: FailureCodeV1::ControlTransport,
                native_code,
                observed_phase: phase,
                safe_detail: SafeDiagnosticDetailV1::InjectedWindowsFault { fault },
                detail_redacted: true,
                detail_truncated: false,
                terminalization_reference: None,
            })
            .unwrap();
        let diagnostic =
            ProviderFailureDiagnosticV1::from_journal(provider(), &attempt, &request, &journal)
                .unwrap();
        transport_injection_authority(&diagnostic, selected, &provider(), actual_attempt, &request)
    };
    for code in [109, 232, 233] {
        assert!(evaluate(
            FailureOperationV1::DeliverResponse,
            AttemptObservationPhaseV1::Cleaning,
            Some(NativeFailureCodeV1::Win32(code)),
            selected,
            &attempt
        ));
        assert!(evaluate(
            FailureOperationV1::ReadControlFrame,
            AttemptObservationPhaseV1::Cleaning,
            Some(NativeFailureCodeV1::Win32(code)),
            selected,
            &attempt
        ));
    }
    assert!(evaluate(
        FailureOperationV1::ReadControlFrame,
        AttemptObservationPhaseV1::Cleaning,
        None,
        selected,
        &attempt
    ));
    assert!(!evaluate(
        FailureOperationV1::DeliverResponse,
        AttemptObservationPhaseV1::Cleaning,
        None,
        selected,
        &attempt
    ));
    assert!(!evaluate(
        FailureOperationV1::DeliverResponse,
        AttemptObservationPhaseV1::Cleaning,
        Some(NativeFailureCodeV1::Win32(5)),
        selected,
        &attempt
    ));
    assert!(!evaluate(
        FailureOperationV1::DeliverResponse,
        AttemptObservationPhaseV1::Monitoring,
        Some(NativeFailureCodeV1::Win32(232)),
        selected,
        &attempt
    ));
    assert!(!evaluate(
        FailureOperationV1::DeliverResponse,
        AttemptObservationPhaseV1::Cleaning,
        Some(NativeFailureCodeV1::Win32(232)),
        selected,
        &"04".repeat(32)
    ));
    assert!(!evaluate(
        FailureOperationV1::DeliverResponse,
        AttemptObservationPhaseV1::Cleaning,
        Some(NativeFailureCodeV1::Win32(232)),
        WindowsSealedFault::FrontendKilledAfterAuthorization,
        &attempt
    ));
}

#[test]
fn report_from_another_invocation_cannot_replace_independently_observed_live_association() {
    let observed = memcordon_core::WindowsGuardianAttemptObservation {
        format: "memcordon.windows-live-guardian-observation".into(),
        revision: 1,
        live_nonce: None,
        worker_process_identity: None,
        worker_thread_identity: None,
        live_target_identity: None,
        challenge: BoundedText::new("fresh-native-query").unwrap(),
        guardian_identity: memcordon_core::WindowsProcessIdentityV1 {
            process_id: 42,
            creation_time_100ns: 1234,
        },
        association: memcordon_core::execution_facts::ProviderAttemptAssociationV1 {
            provider: provider(),
            attempt_id: DiagnosticSha256::from_bytes([2; 32]),
            request_sha256: DiagnosticSha256::from_bytes([3; 32]),
        },
    };
    let validate = |reported: &memcordon_core::execution_facts::ProviderAttemptAssociationV1| {
        memcordon_ci::windows_causal_acceptance::validate_live_guardian_association(
            reported,
            &observed,
            &provider(),
        )
    };
    validate(&observed.association).unwrap();
    let mut another = observed.association.clone();
    another.attempt_id = DiagnosticSha256::from_bytes([4; 32]);
    assert!(validate(&another).is_err());
    another = observed.association.clone();
    another.request_sha256 = DiagnosticSha256::from_bytes([4; 32]);
    assert!(validate(&another).is_err());
    let mut malformed = observed.clone();
    malformed.revision = 2;
    assert!(!malformed.is_consistent());
    malformed = observed.clone();
    malformed.guardian_identity.creation_time_100ns = 0;
    assert!(!malformed.is_consistent());
}

fn projection() -> ProviderFailureDiagnosticV1 {
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal
        .observe(CausalEventV1 {
            sequence: 0,
            origin: DiagnosticOriginV1::Launcher,
            category: FailureCategoryV1::Monitor,
            operation: FailureOperationV1::CheckGuardian,
            code: FailureCodeV1::GuardianLoss,
            native_code: None,
            observed_phase: AttemptObservationPhaseV1::Monitoring,
            safe_detail: SafeDiagnosticDetailV1::NoAdditionalDetail,
            detail_redacted: true,
            detail_truncated: false,
            terminalization_reference: None,
        })
        .unwrap();
    ProviderFailureDiagnosticV1::from_journal(
        provider(),
        &"02".repeat(32),
        &"03".repeat(32),
        &journal,
    )
    .unwrap()
}

#[test]
fn injected_guardian_authority_requires_bound_ordered_physical_loss() {
    use memcordon_ci::windows_readiness_components::guardian_injection_authority;
    use memcordon_core::WindowsSealedFault;
    let selected = WindowsSealedFault::GuardianKilledBeforeAuthorization;
    let original = CausalEventV1 {
        sequence: 0,
        origin: DiagnosticOriginV1::Launcher,
        category: FailureCategoryV1::Monitor,
        operation: FailureOperationV1::CheckGuardian,
        code: FailureCodeV1::GuardianLoss,
        native_code: None,
        observed_phase: AttemptObservationPhaseV1::BeforeAuthorization,
        safe_detail: SafeDiagnosticDetailV1::NoAdditionalDetail,
        detail_redacted: true,
        detail_truncated: false,
        terminalization_reference: None,
    };
    let mut injected = original.clone();
    injected.category = FailureCategoryV1::Launch;
    injected.operation = FailureOperationV1::UnclassifiedProviderOperation;
    injected.code = FailureCodeV1::UnexpectedProviderFailure;
    injected.safe_detail = SafeDiagnosticDetailV1::InjectedWindowsFault { fault: selected };
    let make = |first: CausalEventV1, second: Option<CausalEventV1>| {
        let mut journal = WindowsCausalDiagnosticsV1::default();
        journal.observe(first).unwrap();
        if let Some(second) = second {
            journal.observe(second).unwrap();
        }
        ProviderFailureDiagnosticV1::from_journal(
            provider(),
            &"02".repeat(32),
            &"03".repeat(32),
            &journal,
        )
        .unwrap()
    };
    let valid = make(original.clone(), Some(injected.clone()));
    let accepts = |value: &ProviderFailureDiagnosticV1| {
        guardian_injection_authority(
            value,
            selected,
            &provider(),
            &"02".repeat(32),
            &"03".repeat(32),
        )
    };
    assert!(accepts(&valid));
    assert!(!accepts(&make(original.clone(), None)));
    assert!(!accepts(&make(injected.clone(), Some(original.clone()))));
    let mut other = original.clone();
    other.observed_phase = AttemptObservationPhaseV1::Monitoring;
    assert!(!accepts(&make(other, Some(injected.clone()))));
    let mut other = original.clone();
    other.code = FailureCodeV1::UnexpectedProviderFailure;
    assert!(!accepts(&make(other, Some(injected.clone()))));
    let mut other = injected.clone();
    other.safe_detail = SafeDiagnosticDetailV1::InjectedWindowsFault {
        fault: WindowsSealedFault::GuardianCreate,
    };
    assert!(!accepts(&make(original, Some(other))));
    assert!(!guardian_injection_authority(
        &valid,
        WindowsSealedFault::GuardianCreate,
        &provider(),
        &"02".repeat(32),
        &"03".repeat(32)
    ));
    assert!(!guardian_injection_authority(
        &valid,
        selected,
        &provider(),
        &"04".repeat(32),
        &"03".repeat(32)
    ));
    assert!(!guardian_injection_authority(
        &valid,
        selected,
        &provider(),
        &"02".repeat(32),
        &"04".repeat(32)
    ));
    let mut other_provider = provider();
    other_provider.generation = BoundedText::new("other-generation").unwrap();
    assert!(!guardian_injection_authority(
        &valid,
        selected,
        &other_provider,
        &"02".repeat(32),
        &"03".repeat(32)
    ));
}

#[test]
fn installed_guardian_projection_requires_exact_actual_association() {
    let projection = projection();
    let bytes = serde_json::to_vec(&projection).unwrap();
    validate_guardian_failure_projection(
        &bytes,
        &provider(),
        &DiagnosticSha256::from_bytes([2; 32]),
        &DiagnosticSha256::from_bytes([3; 32]),
    )
    .unwrap();
    let mut other_generation = provider();
    other_generation.generation = BoundedText::new("installed-generation-2").unwrap();
    for (binding, attempt, request) in [
        (other_generation, [2; 32], [3; 32]),
        (provider(), [4; 32], [3; 32]),
        (provider(), [2; 32], [4; 32]),
    ] {
        assert!(
            validate_guardian_failure_projection(
                &bytes,
                &binding,
                &DiagnosticSha256::from_bytes(attempt),
                &DiagnosticSha256::from_bytes(request),
            )
            .is_err()
        );
    }
}

#[test]
fn installed_guardian_projection_rejects_capacity_failure_and_invented_native_error() {
    for (operation, code, native_code) in [
        (
            FailureOperationV1::AccumulateProcessInventory,
            FailureCodeV1::ProcessInventoryCapacity,
            None,
        ),
        (
            FailureOperationV1::CheckGuardian,
            FailureCodeV1::GuardianLoss,
            Some(NativeFailureCodeV1::Win32(6)),
        ),
    ] {
        let mut projection = projection();
        let OriginalFailureV1::Observed { event } = &mut projection.original else {
            panic!("fixture must retain an observed original");
        };
        event.operation = operation;
        event.code = code;
        event.native_code = native_code;
        projection.projection_sha256 = projection.canonical_digest();
        assert!(
            validate_guardian_failure_projection(
                &serde_json::to_vec(&projection).unwrap(),
                &provider(),
                &DiagnosticSha256::from_bytes([2; 32]),
                &DiagnosticSha256::from_bytes([3; 32]),
            )
            .is_err()
        );
    }
}

fn sampling_result() -> InstalledCaseResult {
    InstalledCaseResult {
        case: InstalledCase::SamplingPopulation,
        behavior: Ok(()),
        collection: Ok(CollectedFailure {
            report_sha256: "1".repeat(64),
            stdout_sha256: "2".repeat(64),
            stderr_sha256: "3".repeat(64),
            provider_failure: None,
        }),
        workload_cleanup: Ok(()),
        package_cleanup: Ok(()),
    }
}

// Structured assessment fixtures exercise aggregation only. They do not
// establish any native process, artifact, capacity or retirement authority.
fn complete_installed_assessment()
-> memcordon_ci::windows_installed_cases::InstalledWindowsAssessment {
    use memcordon_ci::windows_consumer_readiness::{
        CASE_ASSESSMENT_REVISION, CaseAssessment, positive_keys,
    };
    use memcordon_ci::windows_installed_cases::{InstalledWindowsAssessment, SelectedArtifact};
    use memcordon_ci::windows_readiness_policy::*;
    use memcordon_core::execution_facts::{NativeProcessV2, ProviderAttemptAssociationV1};
    let digest = DiagnosticSha256::from_bytes([1; 32]);
    let cases: Vec<_> = positive_keys()
        .into_iter()
        .enumerate()
        .map(|(index, key)| {
            let evidence = ExecutionEvidence {
                association: ProviderAttemptAssociationV1 {
                    provider: provider(),
                    attempt_id: DiagnosticSha256::from_bytes([index as u8 + 1; 32]),
                    request_sha256: DiagnosticSha256::from_bytes([2; 32]),
                },
                workload_request_sha256: digest.clone(),
                root: NativeProcessV2 {
                    pid: index as u32 + 100,
                    birth: index as u64 + 1000,
                },
                descriptor_sha256: digest.clone(),
                result_sha256: digest.clone(),
                stdout_sha256: digest.clone(),
                stderr_sha256: digest.clone(),
                transcript_sha256: digest.clone(),
                terminal_observation_sha256: digest.clone(),
            };
            let execution = if supports_listener_refusal(&key) {
                ExecutionDisposition::OriginalListenerRefusal {
                    raw_os_error: 12345,
                }
            } else {
                ExecutionDisposition::Completed
            };
            CaseAssessment {
                revision: CASE_ASSESSMENT_REVISION,
                key,
                contract: CaseContract {
                    intrinsic: IntrinsicContract::Validated,
                    comparison: ComparisonStatus::NotMeasured,
                    execution,
                    evidence: Some(evidence),
                },
                behavior: Ok(()),
                collection: Ok(()),
                retirement: Ok(()),
                descriptor_sha256: String::from(digest.clone()),
                result_sha256: Some(String::from(digest.clone())),
                stdout_sha256: Some(String::from(digest.clone())),
                stderr_sha256: Some(String::from(digest.clone())),
                transcript_sha256: Some(String::from(digest.clone())),
                request_sha256: Some(String::from(digest.clone())),
                provider_request_sha256: Some(String::from(DiagnosticSha256::from_bytes([2; 32]))),
                terminal_observation_sha256: Some(String::from(digest.clone())),
            }
        })
        .collect();
    let artifact = SelectedArtifact {
        path: std::env::temp_dir().join("collected-fixture.json"),
        sha256: String::from(digest),
    };
    let mut guardian = sampling_result();
    guardian.case = InstalledCase::GuardianLossAfterRelease;
    guardian.collection.as_mut().unwrap().provider_failure = Some(projection());
    let mut lifetime = guardian.clone();
    lifetime.case = InstalledCase::GuardianLossLifetime;
    InstalledWindowsAssessment {
        revision: 2,
        channel: memcordon_ci::windows_causal_acceptance::InstalledChannel::NativeBundle,
        target: "aarch64-pc-windows-msvc".into(),
        source_commit: "ab".repeat(20),
        version: "fixture".into(),
        artifacts: vec![artifact.clone()],
        public_smoke_before: Ok(()),
        cases: vec![sampling_result(), guardian, lifetime],
        readiness: assess_suite(&cases),
        positive_suite: Ok(()),
        loss_cases: memcordon_ci::windows_readiness_faults::required_loss_keys()
            .into_iter()
            .map(
                |key| memcordon_ci::windows_readiness_faults::LossAssessment {
                    key,
                    behavior: Ok(()),
                    collection: Ok(()),
                    retirement: Ok(()),
                    artifacts: vec![artifact.clone()],
                },
            )
            .collect(),
        loss_suite: Ok(()),
        capacity_cases: memcordon_ci::windows_readiness_capacity::required_keys()
            .into_iter()
            .enumerate()
            .map(
                |(group, key)| memcordon_ci::windows_readiness_capacity::CapacityAssessment {
                    attempts: (0..memcordon_ci::windows_readiness_capacity::planned_attempt_count(
                        &key,
                    )
                    .unwrap())
                        .map(|ordinal| {
                            let mut attempt = cases[0].clone();
                            attempt.key = key.clone();
                            let unique = (100 + group * 10 + ordinal) as u8;
                            let evidence = attempt.contract.evidence.as_mut().unwrap();
                            evidence.root.pid = u32::from(unique) + 10_000;
                            evidence.root.birth = u64::from(unique) + 100_000;
                            evidence.association.attempt_id =
                                DiagnosticSha256::from_bytes([unique; 32]);
                            evidence.association.request_sha256 =
                                DiagnosticSha256::from_bytes([unique; 32]);
                            attempt.provider_request_sha256 =
                                Some(String::from(evidence.association.request_sha256.clone()));
                            attempt
                        })
                        .collect(),
                    key,
                    behavior: Ok(()),
                    collection: Ok(()),
                    retirement: Ok(()),
                    artifacts: vec![artifact.clone()],
                },
            )
            .collect(),
        capacity_suite: Ok(()),
        refusal_cases: memcordon_ci::windows_readiness_refusals::required_keys()
            .into_iter()
            .map(
                |key| memcordon_ci::windows_readiness_refusals::RefusalAssessment {
                    key,
                    behavior: Ok(()),
                    collection: Ok(()),
                    retirement: Ok(()),
                    artifacts: vec![artifact.clone()],
                },
            )
            .collect(),
        refusal_suite: Ok(()),
        positive_cases: cases,
        retained_state_recovery: Ok(()),
        public_smoke_after: Ok(()),
        package_upgrade: Ok(()),
        package_uninstall: Ok(()),
    }
}

#[test]
fn scoped_unavailability_never_replaces_independent_installed_obligations() {
    use memcordon_ci::windows_installed_cases::InstalledWindowsAssessment;
    let assessment = complete_installed_assessment();
    assert!(assessment.readiness_validated());
    assert!(assessment.accepted());
    let mutations: &[fn(&mut InstalledWindowsAssessment)] = &[
        |a| a.revision = 1,
        |a| a.public_smoke_before = Err("smoke absent".into()),
        |a| a.positive_suite = Err("unvalidated invocation".into()),
        |a| a.positive_cases[0].retirement = Err("owner unknown".into()),
        |a| {
            a.positive_cases.pop();
        },
        |a| a.loss_suite = Err("loss not executed".into()),
        |a| {
            a.loss_cases.pop();
        },
        |a| a.loss_cases[0].retirement = Err("loss owner unknown".into()),
        |a| a.capacity_suite = Err("capacity not executed".into()),
        |a| {
            a.capacity_cases.pop();
        },
        |a| a.capacity_cases[0].retirement = Err("capacity owner unknown".into()),
        |a| a.refusal_suite = Err("refusal not executed".into()),
        |a| {
            a.refusal_cases.pop();
        },
        |a| a.refusal_cases[0].collection = Err("refusal capture missing".into()),
        |a| {
            a.cases[0].behavior = Err(CaseFailure {
                reason: "causal behavior differs".into(),
            })
        },
        |a| a.retained_state_recovery = Err("recovery absent".into()),
        |a| a.public_smoke_after = Err("postrecovery smoke absent".into()),
        |a| a.package_upgrade = Err("upgrade failed".into()),
        |a| a.package_uninstall = Err("uninstall failed".into()),
    ];
    for mutate in mutations {
        let mut changed = assessment.clone();
        mutate(&mut changed);
        assert!(!changed.accepted());
    }
    for missing in ["revision", "readiness"] {
        let mut wire = serde_json::to_value(&assessment).unwrap();
        wire.as_object_mut().unwrap().remove(missing);
        assert!(serde_json::from_value::<InstalledWindowsAssessment>(wire).is_err());
    }
    let mut forged = assessment;
    forged.readiness = memcordon_ci::windows_readiness_policy::SuiteDecision::Validated {
        coverage: Vec::new(),
        unavailable_cases: Vec::new(),
    };
    assert!(!forged.readiness_validated());
    assert!(!forged.accepted());
}

#[test]
fn installed_case_uninstall_success_does_not_erase_behavior_or_collection_failure() {
    let mut result = sampling_result();
    assert!(result.accepted());
    result.behavior = Err(CaseFailure {
        reason: "wrong native outcome".to_owned(),
    });
    assert!(!result.accepted());
    result.behavior = Ok(());
    result.collection = Err(CollectionFailure {
        reason: "truncated report".to_owned(),
    });
    assert!(!result.accepted());
    assert!(result.workload_cleanup.is_ok());
    assert!(result.package_cleanup.is_ok());
}

#[test]
fn installed_case_observed_causal_failure_cannot_certify_unknown_retirement() {
    let mut result = sampling_result();
    result.case = InstalledCase::GuardianLossAfterRelease;
    result.collection.as_mut().unwrap().provider_failure = Some(projection());
    assert!(result.accepted());
    result.workload_cleanup = Err(CleanupFailure {
        reason: "fixture family still live".to_owned(),
    });
    assert!(!result.accepted());
    result.workload_cleanup = Ok(());
    result.package_cleanup = Err(CleanupFailure {
        reason: "uninstall failed".to_owned(),
    });
    assert!(!result.accepted());
}

#[test]
fn owned_guardian_association_rejects_wrong_service_process_image_or_generation() {
    use memcordon_ci::windows_owned_guardian::{
        GuardianAssociationIdentity, guardian_slot_names, validate_guardian_association,
    };
    let held = GuardianAssociationIdentity {
        service_name: guardian_slot_names()[0].clone(),
        process_id: 41,
        creation_time_100ns: 100,
        image_volume: 3,
        image_file_index: 42,
        image_sha256: "1".repeat(64),
        generation_manifest_sha256: "2".repeat(64),
    };
    validate_guardian_association(&held, &held).unwrap();
    let mut mutations = Vec::new();
    let mut other = held.clone();
    other.service_name = memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME.to_owned();
    mutations.push(other);
    let mut other = held.clone();
    other.process_id += 1;
    mutations.push(other);
    let mut other = held.clone();
    other.creation_time_100ns += 1;
    mutations.push(other);
    let mut other = held.clone();
    other.image_file_index += 1;
    mutations.push(other);
    let mut other = held.clone();
    other.generation_manifest_sha256 = "3".repeat(64);
    mutations.push(other);
    for other in mutations {
        assert!(validate_guardian_association(&held, &other).is_err());
    }
}

#[test]
fn actual_job_error_constructor_inventory_has_only_reviewed_operations() {
    use std::collections::BTreeSet;
    use syn::visit::Visit;

    #[derive(Default)]
    struct Constructors {
        operations: BTreeSet<String>,
    }
    impl Constructors {
        fn record(&mut self, expression: &syn::Expr) {
            let syn::Expr::Path(path) = expression else {
                panic!("JobObservationError constructor needs an explicitly reviewed operation");
            };
            self.operations
                .insert(path.path.segments.last().unwrap().ident.to_string());
        }
    }
    impl<'ast> Visit<'ast> for Constructors {
        fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
            if expression
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "JobObservationError")
            {
                let field = expression.fields.iter().find(|field| {
                    matches!(&field.member, syn::Member::Named(name) if name == "operation")
                }).expect("typed constructor retains operation");
                self.record(&field.expr);
            }
            syn::visit::visit_expr_struct(self, expression);
        }
        fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*expression.func {
                let segments = path.path.segments.iter().collect::<Vec<_>>();
                if segments.len() >= 2
                    && segments[segments.len() - 2].ident == "JobObservationError"
                    && matches!(
                        segments.last().unwrap().ident.to_string().as_str(),
                        "last" | "semantic"
                    )
                {
                    self.record(
                        expression
                            .args
                            .first()
                            .expect("typed constructor operation"),
                    );
                }
            }
            syn::visit::visit_expr_call(self, expression);
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows");
    let mut constructors = Constructors::default();
    for path in ["job.rs", "process_impl/target.rs", "launcher_service.rs"] {
        let source = std::fs::read_to_string(root.join(path)).unwrap();
        constructors.visit_file(&syn::parse_file(&source).expect("production Rust syntax"));
    }
    let reviewed = [
        "QueryJobAccounting",
        "QueryJobProcessIds",
        "QueryPeakMemory",
        "ReadJobNotification",
        "ResumeTarget",
        "VerifySuspendedTarget",
        "PollTarget",
        "ReadTargetExit",
        "CheckGuardian",
        "TerminateJob",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    assert_eq!(
        constructors.operations, reviewed,
        "new emitted operations require mapping review and converter regressions"
    );
}
#[test]
fn provider_private_unavailability_does_not_hide_operation_or_uninstall_failure() {
    use memcordon_ci::windows_installed_cases::provider_experiment_execution_status;
    let observed = Ok(serde_json::json!({"private_availability":"unavailable"}));
    let complete = provider_experiment_execution_status(&observed, &Ok(()));
    assert_eq!(complete["execution_completed"], true);
    assert_eq!(complete["private_availability"], "unavailable");
    let cleanup = Err(memcordon_ci::CiError::Message("uninstall125".into()));
    let failed = provider_experiment_execution_status(&observed, &cleanup);
    assert_eq!(failed["execution_completed"], true);
    assert_eq!(failed["completed"], false);
    assert_eq!(failed["private_availability"], "unavailable");
    assert!(
        failed["installation_cleanup_error"]
            .as_str()
            .unwrap()
            .contains("uninstall125")
    );
    let operation = Err(memcordon_ci::CiError::Message(
        "restricted peer debt".into(),
    ));
    let failed = provider_experiment_execution_status(&operation, &cleanup);
    assert_eq!(failed["execution_completed"], false);
    assert!(failed["private_availability"].is_null());
    assert!(
        failed["execution_error"]
            .as_str()
            .unwrap()
            .contains("restricted peer debt")
    );
    assert!(
        failed["installation_cleanup_error"]
            .as_str()
            .unwrap()
            .contains("uninstall125")
    );
}
