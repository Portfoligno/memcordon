use memcordon_windows_launch_core::{
    ArtifactRefV1, CleanupOutcomeV1, HandshakeOutcomeV1, NativeCallOutcomeV1, NativeStatusV1,
    RedactionClassV1, WindowsLoaderQualificationStageV2,
};
use memcordon_windows_loader_lab::scenario::{
    DiagnosticDesktopVariantV1, DiagnosticEnvironmentVariantV1, DiagnosticObserverV1,
    DiagnosticParentVariantV1, DiagnosticProfileVariantV1, DiagnosticSecurityDescriptorVariantV1,
    DiagnosticTokenVariantV1, ExternalCaptureBindingV1, ExternalCaptureSummaryV1,
    ExternalCaptureToolV1, ExternalFirstDivergenceV1, HarnessStatusV1, LoaderLabRunV1,
    LoaderLabScenarioResultV1, PreparedInputEvidenceV1, WindowsBuildIdentityV1,
};
use sha2::Digest;

fn digest() -> String {
    "a".repeat(sha2::Sha256::output_size() * 2)
}

fn artifact(name: &str) -> ArtifactRefV1 {
    ArtifactRefV1::new(
        name.to_owned(),
        digest(),
        1,
        String::from("application/json"),
        RedactionClassV1::RedactedSummary,
    )
    .expect("artifact fixture must be valid")
}

fn scenario(id: &str, production_equivalent: bool) -> LoaderLabScenarioResultV1 {
    LoaderLabScenarioResultV1 {
        scenario_id: id.to_owned(),
        production_equivalent,
        perturbed: !production_equivalent,
        launch_plan_sha256: Some(digest()),
        token_variant: DiagnosticTokenVariantV1::ProductionTarget,
        desktop_variant: DiagnosticDesktopVariantV1::ProductionPrivate,
        environment_variant: DiagnosticEnvironmentVariantV1::ProductionPrepared,
        security_descriptor_variant: DiagnosticSecurityDescriptorVariantV1::ProductionExact,
        profile_variant: DiagnosticProfileVariantV1::ProductionUnloaded,
        parent_variant: DiagnosticParentVariantV1::ProductionLauncher,
        observer: DiagnosticObserverV1::None,
        observer_evidence: None,
        target_token_envelope_sha256: Some(digest()),
        prepared_inputs: Some(PreparedInputEvidenceV1 {
            command_line_sha256: digest(),
            command_line_units: 2,
            environment_sha256: digest(),
            environment_units: 2,
            current_directory_sha256: digest(),
            current_directory_units: 2,
        }),
        suspended_process: None,
        loader_ready_process_identity: None,
        loader_ready_token_envelope_sha256: None,
        loader_ready_process_snapshot: None,
        process_create: NativeCallOutcomeV1 {
            completed: true,
            status: None,
        },
        failure_stage: None,
        failure_status: None,
        target_exit_code: Some(0),
        handshake: HandshakeOutcomeV1::Authenticated {
            protocol_version: 4,
        },
        cleanup: CleanupOutcomeV1::complete(),
        attachments: vec![artifact(&format!("{id}.json"))],
    }
}

fn run() -> LoaderLabRunV1 {
    let production = scenario("stage-a", true);
    let comparison = scenario("stage-b", false);
    LoaderLabRunV1 {
        schema_version: 1,
        run_id: String::from("run-1"),
        os: WindowsBuildIdentityV1 {
            os: String::from("windows"),
            architecture: String::from("x86_64"),
            major_version: 10,
            minor_version: 0,
            build_number: 26_100,
        },
        package_sha256: digest(),
        harness_status: HarnessStatusV1::Complete,
        artifacts: vec![
            production.attachments[0].clone(),
            comparison.attachments[0].clone(),
        ],
        scenarios: vec![production, comparison],
    }
}

#[test]
fn harness_rejects_failed_cleanup_even_when_scenario_failure_is_observational() {
    let mut run = run();
    run.scenarios[1].cleanup = CleanupOutcomeV1::failed("job-drain-failed");
    assert!(run.validate().is_err());
}

#[test]
fn harness_rejects_duplicate_scenario_identity() {
    let mut run = run();
    run.scenarios[1].scenario_id = run.scenarios[0].scenario_id.clone();
    assert!(run.validate().is_err());
}

#[test]
fn harness_accepts_loader_failure_when_cleanup_and_manifest_are_complete() {
    let mut run = run();
    run.scenarios[1].handshake = HandshakeOutcomeV1::Failed {
        stable_code: String::from("loader-ready-authentication-failed"),
    };
    run.scenarios[1].failure_stage = Some(WindowsLoaderQualificationStageV2::LoaderReadyHandshake);
    assert_eq!(run.validate(), Ok(()));
}

#[test]
fn harness_accepts_post_ready_exit_drain_failure_as_scenario_data() {
    let mut run = run();
    run.scenarios[1].failure_stage = Some(WindowsLoaderQualificationStageV2::ExitDrain);
    run.scenarios[1].target_exit_code = None;
    assert_eq!(run.validate(), Ok(()));
}

#[test]
fn harness_accepts_preplan_failure_as_scenario_data() {
    let mut run = run();
    let production = &mut run.scenarios[0];
    let status = NativeStatusV1::Stable {
        code: String::from("command-preparation"),
    };
    production.launch_plan_sha256 = None;
    production.target_token_envelope_sha256 = None;
    production.prepared_inputs = None;
    production.process_create = NativeCallOutcomeV1 {
        completed: false,
        status: Some(status.clone()),
    };
    production.failure_stage = Some(WindowsLoaderQualificationStageV2::PlanValidation);
    production.failure_status = Some(status);
    production.target_exit_code = None;
    production.handshake = HandshakeOutcomeV1::NotStarted;
    assert_eq!(run.validate(), Ok(()));
}

#[test]
fn artifact_references_reject_parent_traversal() {
    assert!(
        ArtifactRefV1::new(
            String::from("../secret.json"),
            digest(),
            1,
            String::from("application/json"),
            RedactionClassV1::RestrictedTrace,
        )
        .is_err()
    );
}

#[test]
fn external_capture_summary_is_bound_to_side_trace_plan_package_and_target() {
    let summary = ExternalCaptureSummaryV1 {
        schema_version: 1,
        run_id: String::from("run-1"),
        side: String::from("left"),
        source_scenario_id: String::from("stage-a"),
        source_result_sha256: digest(),
        production_plan_sha256: digest(),
        package_sha256: digest(),
        trace_sha256: digest(),
        target_process_id: 42,
        descendant_process_ids: vec![43],
        capture_started_unix_millis: 10,
        capture_ended_unix_millis: 20,
        tool: ExternalCaptureToolV1::Procmon,
        tool_build_sha256: digest(),
        symbol_identity_sha256: digest(),
        capture_profile: String::from("process-thread-image-file-registry"),
        result_filter: String::from("pid-result-time-window"),
        first_divergence: ExternalFirstDivergenceV1 {
            object_identity_sha256: digest(),
            operation: String::from("CreateFile"),
            requested_rights: String::from("FILE_EXECUTE"),
            result: String::from("ACCESS DENIED"),
            stack_module_sha256: vec![digest()],
        },
        event_count: 1,
        collector_session_started: true,
        provider_enabled: true,
        collector_cleanup_complete: true,
        raw_trace_restricted: true,
        summary_redacted: true,
    };
    assert_eq!(
        summary.validate(ExternalCaptureBindingV1 {
            run_id: "run-1",
            side: "left",
            source_scenario_id: "stage-a",
            source_result_sha256: &digest(),
            production_plan_sha256: &digest(),
            package_sha256: &digest(),
            trace_sha256: &digest(),
            target_process_id: 42,
        }),
        Ok(())
    );
    assert!(
        summary
            .validate(ExternalCaptureBindingV1 {
                run_id: "run-1",
                side: "right",
                source_scenario_id: "stage-a",
                source_result_sha256: &digest(),
                production_plan_sha256: &digest(),
                package_sha256: &digest(),
                trace_sha256: &digest(),
                target_process_id: 42,
            })
            .is_err()
    );
    assert!(
        summary
            .validate(ExternalCaptureBindingV1 {
                run_id: "run-1",
                side: "left",
                source_scenario_id: "stage-a",
                source_result_sha256: &digest(),
                production_plan_sha256: &digest(),
                package_sha256: &digest(),
                trace_sha256: &digest(),
                target_process_id: 41,
            })
            .is_err()
    );
}
