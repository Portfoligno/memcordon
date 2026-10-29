use memcordon_core::*;
#[path = "windows_current_postauthorization.rs"]
mod postauthorization;

pub fn fixture() -> (
    WindowsProviderRejectionV3,
    WindowsGuardianAttemptObservation,
    serde_json::Value,
    serde_json::Value,
) {
    let mut rejection = postauthorization::rejection();
    let failure = rejection.provider_failure.as_ref().unwrap();
    let provider = failure.provider_binding.clone();
    let attempt = failure.attempt_id.clone();
    let request = failure.request_sha256.clone();
    let OriginalFailureV1::Observed { event: original } = &failure.original else {
        panic!("fixture original required")
    };
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal.observe(original.clone()).unwrap();
    journal
        .observe(CausalEventV1 {
            sequence: 0,
            origin: DiagnosticOriginV1::Launcher,
            category: FailureCategoryV1::Transport,
            operation: FailureOperationV1::DeliverResponse,
            code: FailureCodeV1::ControlTransport,
            native_code: Some(NativeFailureCodeV1::Win32(232)),
            observed_phase: AttemptObservationPhaseV1::Cleaning,
            safe_detail: SafeDiagnosticDetailV1::InjectedWindowsFault {
                fault: WindowsSealedFault::FrontendKilledAfterAuthorization,
            },
            detail_redacted: true,
            detail_truncated: false,
            terminalization_reference: None,
        })
        .unwrap();
    rejection.provider_failure = Some(
        ProviderFailureDiagnosticV1::from_journal(
            provider.clone(),
            &String::from(attempt.clone()),
            &String::from(request.clone()),
            &journal,
        )
        .unwrap(),
    );
    let terminal = rejection.terminal_receipt().unwrap();
    let proof = &terminal.retirement_proof;
    let frontend = WindowsProcessIdentityV1 {
        process_id: 1372,
        creation_time_100ns: 134364958296860014,
    };
    let guardian = WindowsProcessIdentityV1 {
        process_id: 9880,
        creation_time_100ns: 134364958304946298,
    };
    let worker = WindowsProcessIdentityV1 {
        process_id: 7,
        creation_time_100ns: 134364958299999999,
    };
    let mut cause = WindowsGuardianReceiptV2 {
        schema_version: 2,
        attempt_id: terminal.attempt_id.clone(),
        nonce: terminal.nonce.clone(),
        request_sha256: terminal.request_sha256.clone(),
        provider_generation: proof.provider_generation.clone(),
        launch_incarnation: proof.launch_incarnation.clone(),
        original_boot_id: proof.original_boot_id.clone(),
        job_identity: proof.job_identity.clone(),
        guardian_identity: guardian.clone(),
        worker_identity: worker.clone(),
        owner_manifest_sha256: proof.owner_manifest_sha256.clone(),
        termination_requested: true,
        native_job_query_succeeded: true,
        active_processes_zero_observed: true,
        cleanup_trigger: Some(WindowsGuardianCleanupTriggerV1::FrontendLost {
            frontend: frontend.clone(),
            native_exit_status: 0xc000013a,
        }),
        observed_unix_millis: 1,
        integrity_sha256: String::new(),
    };
    cause.integrity_sha256 = cause.canonical_sha256().unwrap();
    let live = WindowsGuardianAttemptObservation {
        format: "memcordon.windows-live-guardian-observation".into(),
        revision: 1,
        challenge: BoundedText::new("independently-held-native-guardian").unwrap(),
        guardian_identity: guardian,
        association: execution_facts::ProviderAttemptAssociationV1 {
            provider,
            attempt_id: attempt,
            request_sha256: request,
        },
        live_nonce: Some(terminal.nonce.clone()),
        live_target_identity: terminal.process_observation.root_identity.clone(),
        worker_process_identity: Some(worker),
        worker_thread_identity: Some(WindowsWorkerThreadIdentityV1 {
            thread_id: 19,
            creation_time_100ns: 23,
        }),
    };
    let action = serde_json::json!({"format":"memcordon.windows-component-frontend-action","revision":1,
        "kind":"exit-process","process":frontend,"target_pid":1234,"target_authorization_observed":true,
        "controller_release_observed":true,"requested_exit_status":0xc000013a_u32});
    let exit = serde_json::json!({"format":"memcordon.windows-component-frontend-exit","revision":1,
        "process_id":frontend.process_id,"creation_time_100ns":frontend.creation_time_100ns,
        "held_before_fault":true,"retirement_observed":true,"native_status":0xc000013a_u32});
    rejection.guardian_causal_receipt = Some(Box::new(cause));
    assert!(rejection.is_consistent());
    assert!(live.is_consistent());
    (rejection, live, action, exit)
}
