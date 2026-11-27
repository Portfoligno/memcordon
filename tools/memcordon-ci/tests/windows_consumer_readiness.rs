use memcordon_ci::windows_consumer_readiness::descriptor::{
    self, CHURN_CREATIONS, CHURN_LIVE, Case, Descriptor, Toolchain,
};
use memcordon_ci::windows_consumer_readiness::{
    CASE_ASSESSMENT_REVISION, CaseAssessment, SuiteInput, accepted, check_positive_barrier_result,
    positive_keys, validate_suite, validate_toolchain_inventory,
};
#[path = "private/windows_current_result_fixture.rs"]
mod current_fixture;

fn broker_exit(code: i32) -> std::process::ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code << 8)
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code as u32)
    }
}

#[test]
fn original_broker_failure_precedes_missing_report_without_erasing_retirement_failure() {
    use memcordon_ci::{
        CiError,
        windows_consumer_readiness::{
            matched_broker_outcome_failure, prioritize_matched_broker_failure,
        },
    };
    let outcome = Ok(memcordon_testkit::ObservedOutput {
        status: broker_exit(2),
        stdout: Vec::new(),
        stderr: b"child diagnostic\nopaque application error cannot establish equivalence".to_vec(),
        elapsed: std::time::Duration::ZERO,
    });
    let broker = matched_broker_outcome_failure(true, &outcome);
    let directory = tempfile::tempdir().unwrap();
    let Err(missing) = std::fs::read(directory.path().join("broker.json")) else {
        panic!("owned report must be absent")
    };
    assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
    let retirement_attempted = std::cell::Cell::new(false);
    let retirement: memcordon_ci::Result<()> = {
        retirement_attempted.set(true);
        Err(CiError::Message(
            "owned native retirement remains unproved".into(),
        ))
    };
    let assessed = Err(CiError::LaneFailures {
        primary: Box::new(missing.into()),
        secondary: Box::new(retirement.unwrap_err().context("owned retirement")),
    });
    let failure = prioritize_matched_broker_failure(broker, assessed).unwrap_err();
    assert!(retirement_attempted.get());
    let CiError::LaneFailures { primary, secondary } = failure else {
        panic!("broker and secondary diagnostics must both remain")
    };
    let cause = primary.to_string();
    assert!(cause.starts_with("matched broker command failed:"));
    assert!(cause.contains("code=Some(2)") && cause.contains("capture-complete=true"));
    assert!(cause.ends_with("opaque application error cannot establish equivalence"));
    let CiError::LaneFailures { primary, secondary } = *secondary else {
        panic!("report and retirement failures must both remain")
    };
    assert!(
        matches!(*primary, CiError::Io(ref error) if error.kind() == std::io::ErrorKind::NotFound)
    );
    assert!(
        secondary
            .to_string()
            .contains("owned native retirement remains unproved")
    );
}

#[test]
fn broker_diagnostics_use_only_known_command_exit_and_keep_capture_loss_explicit() {
    use memcordon_ci::windows_consumer_readiness::{
        matched_broker_command_failure, prioritize_matched_broker_failure,
    };
    let child_failure =
        b"installed child status=2; native error observed; broker measurement succeeded";
    assert!(
        matched_broker_command_failure(true, Some(broker_exit(0)), true, child_failure).is_none()
    );
    assert!(
        matched_broker_command_failure(false, Some(broker_exit(2)), true, child_failure).is_none()
    );
    assert!(matched_broker_command_failure(true, None, false, child_failure).is_none());
    let mut stderr = vec![0xff; 8192];
    stderr.extend_from_slice(b"\nactual broker tail");
    let failure =
        matched_broker_command_failure(true, Some(broker_exit(2)), false, &stderr).unwrap();
    let text = failure.to_string();
    assert!(text.len() < 8192);
    assert!(text.contains("capture-complete=false") && text.contains("stderr-tail-truncated=true"));
    assert!(text.ends_with("actual broker tail"));
    assert!(prioritize_matched_broker_failure(None, Ok(())).is_ok());
    let failed = prioritize_matched_broker_failure(Some(failure), Ok(())).unwrap_err();
    assert_eq!(failed.to_string(), text);
}

#[test]
fn nested_owned_callback_exit_is_observed_but_controller_termination_is_not() {
    use memcordon_ci::windows_consumer_readiness::matched_broker_outcome_failure;
    use memcordon_testkit::ProcessTestError;
    let callback = |observed_status| ProcessTestError::Callback {
        error: std::io::Error::other("original callback error"),
        stdout: Vec::new(),
        stderr: b"retained broker cause".to_vec(),
        capture_complete: false,
        observed_status,
        termination: Some(broker_exit(9)),
        cleanup: Err("owned cleanup unproved".into()),
    };
    let outcome = Err(ProcessTestError::ApplicationEnded {
        error: std::io::Error::other("original application ended"),
        settlement: Err(Box::new(callback(Some(broker_exit(2))))),
    });
    let failure = matched_broker_outcome_failure(true, &outcome).unwrap();
    assert!(failure.to_string().contains("code=Some(2)"));
    assert!(failure.to_string().contains("capture-complete=false"));
    assert!(matches!(
        outcome,
        Err(ProcessTestError::ApplicationEnded { .. })
    ));
    assert!(matched_broker_outcome_failure(true, &Err(callback(None))).is_none());
    assert!(matched_broker_outcome_failure(true, &Err(callback(Some(broker_exit(0))))).is_none());
}

#[cfg(unix)]
#[test]
fn abnormal_original_broker_exit_is_not_rewritten_as_a_numeric_child_status() {
    use std::os::unix::process::ExitStatusExt;
    let status = std::process::ExitStatus::from_raw(9);
    assert_eq!(status.code(), None);
    let failure = memcordon_ci::windows_consumer_readiness::matched_broker_command_failure(
        true,
        Some(status),
        true,
        b"signal capture",
    )
    .unwrap();
    assert!(failure.to_string().contains("code=None"));
}

#[test]
fn precise_listener_refusal_is_scoped_validation_without_positive_availability() {
    use memcordon_ci::windows_consumer_readiness::{
        descriptor::matched::{Comparison, ComparisonOutcome, NativeStatusDomain, Scope},
        matched_control_report::{NativeAvailability, ScopeValidation, scoped_assessment},
        matched_owned_positive, matched_scope_validated,
    };
    let refusal = Comparison {
        outcome: ComparisonOutcome::SameObservedFailure,
        scope: Scope::JointListenerPrefix,
        native_status_domain: NativeStatusDomain::PerOperation,
    };
    assert!(matched_scope_validated(&refusal));
    assert!(!matched_owned_positive(&refusal));
    assert_eq!(
        scoped_assessment(&refusal),
        (
            ScopeValidation::MatchedNativeRefusal,
            NativeAvailability::Unavailable
        )
    );
    for scope in [Scope::BinaryFiles, Scope::Envelope] {
        let stopped = Comparison {
            scope,
            native_status_domain: NativeStatusDomain::Win32,
            ..refusal
        };
        assert!(!matched_scope_validated(&stopped));
        assert_eq!(
            scoped_assessment(&stopped),
            (ScopeValidation::Mismatch, NativeAvailability::Unestablished)
        );
    }
    let mismatch = Comparison {
        outcome: ComparisonOutcome::DifferentOutcome,
        ..refusal
    };
    assert!(!matched_scope_validated(&mismatch));
}

#[test]
fn original_application_refusal_has_distinct_nonpositive_scope_validation() {
    use memcordon_ci::windows_consumer_readiness::{
        descriptor::matched::{Comparison, ComparisonOutcome, NativeStatusDomain, Scope},
        matched_control_report::{NativeAvailability, ScopeValidation, scoped_assessment},
        matched_owned_positive, matched_scope_validated,
    };
    for scope in [Scope::JointListenerPrefix, Scope::ProviderListenerSelection] {
        let refusal = Comparison {
            outcome: ComparisonOutcome::SameOriginalApplicationFailure,
            scope,
            native_status_domain: NativeStatusDomain::PerOperation,
        };
        assert!(matched_scope_validated(&refusal));
        assert!(!matched_owned_positive(&refusal));
        assert_eq!(
            scoped_assessment(&refusal),
            (
                ScopeValidation::MatchedApplicationRefusal,
                NativeAvailability::Unavailable,
            )
        );
        for invalid in [
            Comparison {
                scope: Scope::BinaryFiles,
                ..refusal
            },
            Comparison {
                scope: Scope::Envelope,
                ..refusal
            },
            Comparison {
                native_status_domain: NativeStatusDomain::Winsock,
                ..refusal
            },
            Comparison {
                outcome: ComparisonOutcome::DifferentOutcome,
                ..refusal
            },
        ] {
            assert!(!matched_scope_validated(&invalid));
            assert!(!matched_owned_positive(&invalid));
        }
    }
}

#[test]
fn future_provider_negative_probes_are_outside_installation_and_not_legacy_paths() {
    use memcordon_ci::windows_consumer_readiness::external_provider_probe_path;
    let base = std::env::temp_dir().join("memcordon-external-probe-contract");
    let install = base.join("installed").join("agent.exe");
    let output = base.join("controller-output");
    let probe = external_provider_probe_path(&output, &install).unwrap();
    assert_eq!(probe, output.join("protected-provider-probe"));
    assert!(!probe.starts_with(install.parent().unwrap()));
    assert!(external_provider_probe_path(install.parent().unwrap(), &install).is_err());
    assert!(
        external_provider_probe_path(&install.parent().unwrap().join("nested"), &install).is_err()
    );
    assert!(external_provider_probe_path(std::path::Path::new("relative"), &install).is_err());
    assert!(external_provider_probe_path(&output.join("..").join("installed"), &install).is_err());
}

#[test]
fn intrinsic_listener_result_needs_its_own_bound_prefix_without_inventing_a_reference() {
    use descriptor::original_listener_observation as observation;
    use memcordon_ci::windows_consumer_readiness::{
        CaseInput, CaseKey, FrontendExit, IntrinsicListenerInput, TokenObservation,
        assess_original_listener_unavailable, current_association, current_native,
    };
    use memcordon_ci::windows_listener_wait::{ApplicationEnd, Identity};
    let mut result = current_fixture::completed_loader_failure();
    result.outcome.native_termination =
        Some(memcordon_core::ChildTermination::WindowsStatus { status: 2 });
    result.outcome.wrapper_status = 2;
    let root = current_native(&result)
        .unwrap()
        .target_identity
        .as_ref()
        .unwrap();
    let ended = ApplicationEnd {
        identity: Identity {
            pid: root.process_id,
            birth: root.creation_time_100ns.into(),
        },
        status: 2,
    };
    let association = current_association(&result).unwrap().clone();
    let mut descriptor = descriptor();
    descriptor.case = Case::Joint;
    descriptor.start_transport = descriptor::StartTransport::ControllerStdin {
        version: descriptor::controller_start::REGISTRY_VERSION,
    };
    descriptor.control_clock = Some(descriptor::ControlClock {
        revision: 1,
        work_cutoff_qpc: 1000,
        qpc_frequency: 100,
    });
    descriptor.winsock_registry = Some(descriptor::winsock_registry::Declaration {
        version: descriptor::winsock_registry::VERSION,
        view: descriptor::winsock_registry::View::Native,
        sha256: [3; 32],
    });
    let token = TokenObservation {
        user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0],
        restricted: true,
        integrity_rid: 8192,
        elevated: false,
        restricting_sids: Vec::new(),
    };
    let case = CaseInput {
        key: CaseKey {
            family: "W-JOINT".into(),
            scenario: "restricted".into(),
        },
        descriptor,
        descriptor_path: std::env::temp_dir().join("intrinsic-input.json"),
        workload_request: std::env::temp_dir().join("intrinsic-request.json"),
        expected_token: token.clone(),
    };
    let descriptor_sha256 = descriptor::controller_start::descriptor_digest(
        &serde_json::to_vec(&case.descriptor).unwrap(),
    );
    let token_bytes = serde_json::to_vec(&token).unwrap();
    let mut transcript = Vec::new();
    for (sequence, (stage, value)) in [
        ("started", case.descriptor.challenge.clone()),
        (
            "native-argv-observed",
            serde_json::to_vec(
                &serde_json::json!({"encoding":"windows_utf16", "values":Vec::<Vec<u16>>::new()}),
            )
            .unwrap(),
        ),
        ("sentinel-handles-excluded", 0u32.to_le_bytes().to_vec()),
        ("token-envelope", token_bytes.clone()),
        ("controller-released", case.descriptor.challenge.clone()),
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = serde_json::to_vec(&serde_json::json!({"sequence":sequence,"stage":stage,"pid":ended.identity.pid,"ordinal":null,"value":value})).unwrap();
        transcript.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        transcript.extend_from_slice(&bytes);
    }
    let observed = observation::Observation {
        format: observation::FORMAT.into(),
        revision: observation::REVISION,
        operation: observation::Operation::TcpListenerBind,
        domain: observation::ErrorDomain::RustIoRawOsErrorOnWindows,
        raw_os_error: 12345,
        binding: observation::Binding {
            pid: root.process_id,
            birth: root.creation_time_100ns,
            descriptor_sha256,
            challenge_sha256: descriptor::controller_start::descriptor_digest(
                &case.descriptor.challenge,
            ),
            token_sha256: descriptor::controller_start::descriptor_digest(&token_bytes),
            thread: 7,
            started_qpc: 10,
            finished_qpc: 20,
            cutoff_qpc: 1000,
            frequency: 100,
        },
        ipv4: [127, 0, 0, 1],
        port: 0,
    };
    let assess = |case: &CaseInput, result: &[u8], transcript: &[u8], observation: &[u8]| {
        assess_original_listener_unavailable(IntrinsicListenerInput {
            case,
            result,
            stdout: b"",
            stderr: b"opaque diagnostic is not evidence",
            transcript,
            frontend: FrontendExit {
                status: 2,
                original_pid: Some(41),
            },
            ended,
            association: &association,
            descriptor_sha256: descriptor::controller_start::descriptor_digest(
                &serde_json::to_vec(&case.descriptor).unwrap(),
            ),
            observation,
        })
    };
    let bytes = serde_json::to_vec(&result).unwrap();
    let wire = observation::encode(&observed).unwrap();
    assert_eq!(
        assess(&case, &bytes, &transcript, &wire)
            .unwrap()
            .raw_os_error,
        12345
    );
    assert!(assess(&case, &bytes, &transcript, b"").is_err());
    for mutation in ["pid", "birth", "token", "descriptor", "clock"] {
        let mut wrong = observed.clone();
        match mutation {
            "pid" => wrong.binding.pid += 1,
            "birth" => wrong.binding.birth += 1,
            "token" => wrong.binding.token_sha256 = [99; 32],
            "descriptor" => wrong.binding.descriptor_sha256 = [99; 32],
            "clock" => wrong.binding.cutoff_qpc += 1,
            _ => unreachable!(),
        }
        assert!(
            assess(
                &case,
                &bytes,
                &transcript,
                &observation::encode(&wrong).unwrap()
            )
            .is_err(),
            "{mutation}"
        );
    }
    let mut wrong_status = result.clone();
    wrong_status.outcome.native_termination =
        Some(memcordon_core::ChildTermination::WindowsStatus { status: 0 });
    assert!(
        assess(
            &case,
            &serde_json::to_vec(&wrong_status).unwrap(),
            &transcript,
            &wire
        )
        .is_err()
    );
    let mut unsettled = result;
    if let memcordon_core::result_v3::RuntimeExecutionV3::WindowsSealed { native, .. } =
        &mut unsettled.runtime
    {
        native.guardian_reaped = false;
    }
    assert!(
        assess(
            &case,
            &serde_json::to_vec(&unsettled).unwrap(),
            &transcript,
            &wire
        )
        .is_err()
    );
    let mut private = case.clone();
    private.descriptor = experiment_descriptor();
    private.descriptor.control_clock = case.descriptor.control_clock.clone();
    let mut private_observed = observed;
    private_observed.binding.descriptor_sha256 = descriptor::controller_start::descriptor_digest(
        &serde_json::to_vec(&private.descriptor).unwrap(),
    );
    let private_wire = observation::encode(&private_observed).unwrap();
    assert_eq!(
        assess(&private, &bytes, &transcript, &private_wire)
            .unwrap()
            .raw_os_error,
        12345
    );
    private.key.scenario = "ordinary".into();
    assert!(assess(&private, &bytes, &transcript, &private_wire).is_err());
    let mut wrong_scope = case;
    wrong_scope.key = CaseKey {
        family: "W-ENVELOPE".into(),
        scenario: "restricted".into(),
    };
    assert!(assess(&wrong_scope, &bytes, &transcript, &wire).is_err());
    assert!(
        assess(
            &wrong_scope,
            &bytes,
            &transcript[..transcript.len() - 1],
            &wire
        )
        .is_err()
    );
}

#[test]
fn original_peer_spawn_codec_binds_the_exact_rust_error_and_completed_grant() {
    use descriptor::original_listener_observation::{Binding, Expected};
    use descriptor::original_peer_spawn_observation::{
        self as obs, ErrorDomain, Grant, Observation, Operation,
    };
    use std::io::Error;
    let original = Error::from_raw_os_error(5);
    assert_eq!(obs::original_raw_error(Some(&original), Some(5)), Some(5));
    for (actual, reported) in [
        (None, Some(5)),
        (Some(&original), None),
        (Some(&original), Some(6)),
    ] {
        assert_eq!(obs::original_raw_error(actual, reported), None);
    }
    assert_eq!(
        obs::original_raw_error(Some(&Error::other("Win32 error 5")), Some(5)),
        None
    );
    let grant = Grant {
        intent_sequence: 7,
        intent_sha256: [6; 32],
    };
    let binding = Binding {
        pid: 13,
        birth: 27,
        descriptor_sha256: [1; 32],
        challenge_sha256: [2; 32],
        token_sha256: [3; 32],
        thread: 4,
        started_qpc: 200,
        finished_qpc: 210,
        cutoff_qpc: 220,
        frequency: 10,
    };
    let expected = Expected {
        pid: binding.pid,
        birth: binding.birth,
        descriptor_sha256: binding.descriptor_sha256,
        challenge_sha256: binding.challenge_sha256,
        token_sha256: binding.token_sha256,
        cutoff_qpc: binding.cutoff_qpc,
        frequency: binding.frequency,
    };
    let value = Observation {
        format: obs::FORMAT.to_owned(),
        revision: 1,
        operation: Operation::CommandSpawn,
        domain: ErrorDomain::RustIoRawOsErrorOnWindows,
        raw_os_error: 5,
        binding,
        grant,
    };
    let bytes = obs::encode(&value).unwrap();
    assert_eq!(obs::decode(&bytes, &expected, grant).unwrap(), value);
    assert!(
        obs::decode(
            &bytes,
            &expected,
            Grant {
                intent_sequence: 8,
                ..grant
            }
        )
        .is_err()
    );
    assert!(
        obs::decode(
            &bytes,
            &Expected {
                birth: 28,
                ..expected.clone()
            },
            grant
        )
        .is_err()
    );
    assert!(obs::decode(&vec![b' '; obs::MAX_BYTES + 1], &expected, grant).is_err());
    let mut changed = value.clone();
    changed.binding.finished_qpc = changed.binding.cutoff_qpc;
    assert!(obs::encode(&changed).is_err());
    let mut wrong_operation = serde_json::to_value(value).unwrap();
    wrong_operation["operation"] = "tcp-listener-bind".into();
    assert!(
        obs::decode(
            &serde_json::to_vec(&wrong_operation).unwrap(),
            &expected,
            grant
        )
        .is_err()
    );
}

fn settled_application_receipt(
    result: &mut memcordon_core::result_v3::ResultV3,
) -> (
    memcordon_core::WindowsTerminalReceiptV3,
    memcordon_core::WindowsFrontendDeliveryV3,
    String,
) {
    use memcordon_core::{self as core, result_v3::RuntimeExecutionV3};
    let RuntimeExecutionV3::WindowsSealed { native, .. } = &mut result.runtime else {
        panic!("Windows native evidence expected");
    };
    let root = native.target_identity.clone().unwrap();
    let mut observer = core::ProcessObserver::without_sample_storage();
    observer.observe_accounting(3, 0, true);
    let observation = observer.freeze(Some(root.clone()), None);
    native.process_observation = Some(Box::new(observation.clone()));
    let proof = native.retirement.as_deref().unwrap().clone();
    let nonce = proof.nonce.clone();
    let mut boundary = native.clone();
    boundary.retirement = None;
    boundary.frontend_delivery = None;
    boundary.frontend_provider_association = None;
    let terminal = core::WindowsTerminalReceiptV3 {
        schema_version: 3,
        attempt_id: proof.attempt_id.clone(),
        nonce: nonce.clone(),
        request_sha256: proof.request_sha256.clone(),
        payload: core::WindowsTerminalPayloadV3::Execution {
            child_pid: root.process_id,
            duration_millis: 2,
            authorization_offset_millis: 1,
            outcome: core::RunOutcome::Exited {
                child: result.outcome.native_termination.clone().unwrap(),
                peak: None,
                cleanup: core::CleanupSummary {
                    direct_child_reaped: true,
                    workload_empty: Some(true),
                    ..Default::default()
                },
            },
            boundary_detail: Box::new(core::BoundaryMechanismEvidence::WindowsJobObjectV3(
                boundary,
            )),
        },
        process_observation: observation,
        cleanup_process_creation: None,
        restart_safety: core::RestartSafetyProof {
            direct_child_reaped: true,
            workload_empty: Some(true),
            helpers_reaped: true,
            containment_removed: true,
            containment_incapable_of_live_members: true,
            sealed_boundary_retired: true,
            errors: Vec::new(),
        },
        retirement_proof: proof,
    };
    let authority = core::WindowsProviderResponseV4::Terminal(terminal.clone())
        .terminal_authority_json()
        .unwrap();
    let delivery = native.frontend_delivery.as_mut().unwrap();
    delivery.terminal_sha256 =
        memcordon_ci::windows_causal_acceptance::sha256(authority.as_bytes());
    (terminal, delivery.clone(), authority)
}

#[test]
fn post_grant_refusal_needs_the_same_native_job_owner_and_terminal_retirement() {
    use memcordon_ci::windows_consumer_readiness::{
        current_association, current_native, validate_peer_spawn_job_retirement,
    };
    use memcordon_core::{self as core, result_v3::RuntimeExecutionV3};
    let mut result = current_fixture::completed_loader_failure();
    result.outcome.wrapper_status = 2;
    result.outcome.native_termination = Some(core::ChildTermination::ExitCode { code: 2 });
    let (terminal, delivery, authority) = settled_application_receipt(&mut result);
    let live = current_association(&result).unwrap().clone();
    let root = current_native(&result)
        .unwrap()
        .target_identity
        .clone()
        .unwrap();
    let nonce = terminal.nonce.clone();
    validate_peer_spawn_job_retirement(
        &result, &terminal, &delivery, &authority, &live, &nonce, &root,
    )
    .unwrap();
    let wrong_root = core::WindowsProcessIdentityV1 {
        creation_time_100ns: root.creation_time_100ns + 1,
        ..root.clone()
    };
    assert!(
        validate_peer_spawn_job_retirement(
            &result,
            &terminal,
            &delivery,
            &authority,
            &live,
            &nonce,
            &wrong_root
        )
        .is_err()
    );
    let mut wrong_provider = live.clone();
    wrong_provider.provider.generation = core::BoundedText::new("foreign-generation").unwrap();
    assert!(
        validate_peer_spawn_job_retirement(
            &result,
            &terminal,
            &delivery,
            &authority,
            &wrong_provider,
            &nonce,
            &root
        )
        .is_err()
    );
    let mut missing_ack = delivery.clone();
    missing_ack.acknowledgement_observed = false;
    assert!(
        validate_peer_spawn_job_retirement(
            &result,
            &terminal,
            &missing_ack,
            &authority,
            &live,
            &nonce,
            &root
        )
        .is_err()
    );
    assert!(
        validate_peer_spawn_job_retirement(
            &result,
            &terminal,
            &delivery,
            &authority,
            &live,
            "other-live-nonce",
            &root
        )
        .is_err()
    );
    let mut wrong = result.clone();
    let RuntimeExecutionV3::WindowsSealed { native, .. } = &mut wrong.runtime else {
        unreachable!()
    };
    native.retirement.as_mut().unwrap().job_identity = "cd".repeat(32);
    assert!(
        validate_peer_spawn_job_retirement(
            &wrong, &terminal, &delivery, &authority, &live, &nonce, &root
        )
        .is_err()
    );
    let RuntimeExecutionV3::WindowsSealed { native, .. } = &mut wrong.runtime else {
        unreachable!()
    };
    native.retirement = None;
    assert!(
        validate_peer_spawn_job_retirement(
            &wrong, &terminal, &delivery, &authority, &live, &nonce, &root
        )
        .is_err()
    );
}

#[test]
fn console_calibration_needs_owned_settled_processes_and_exact_detachment() {
    use memcordon_ci::windows_consumer_readiness::classify_reduced_console_pair;
    use serde_json::json;
    let mut record = json!({
        "state":"complete","desktop_closed":true,
        "same_held_inputs":{"reduced_primary":true,"desktop":true,"stdio_endpoints":true,"creation_job":true},
        "baseline":{"flags":0x80604,"pid":41,"birth":100,
            "natural_exit":true,"suspended_token_and_image_verified":true,
            "job_empty_verified":true,"native_status":0xc000_0142u32,"snapshot_matches":false,
            "stdout_bytes":0},
        "detached":{"flags":0x8060c,"pid":42,"birth":101,
            "natural_exit":true,"suspended_token_and_image_verified":true,
            "job_empty_verified":true,"native_status":0,"snapshot_matches":true},
        "new_console":{"flags":0x80614,"pid":43,"birth":102,
            "natural_exit":true,"suspended_token_and_image_verified":true,
            "job_empty_verified":true,"native_status":0,"snapshot_matches":true},
    });
    assert_eq!(
        classify_reduced_console_pair(&record),
        Some("detachment-changed-fixture-startup"),
    );
    for (field, value) in [
        ("/state", json!("unavailable")),
        ("/desktop_closed", json!(false)),
        ("/same_held_inputs/creation_job", json!(false)),
        ("/baseline/job_empty_verified", json!(false)),
        ("/detached/natural_exit", json!(false)),
        ("/detached/suspended_token_and_image_verified", json!(false)),
        ("/detached/flags", json!(0x8040c)),
        ("/baseline/pid", json!(0)),
        ("/new_console/flags", json!(0x80604)),
        ("/new_console/natural_exit", json!(false)),
        ("/new_console/pid", json!(0)),
    ] {
        let mut wrong = record.clone();
        *wrong.pointer_mut(field).unwrap() = value;
        assert_eq!(classify_reduced_console_pair(&wrong), None, "{field}");
    }
    record["detached"]["snapshot_matches"] = json!(false);
    assert_eq!(classify_reduced_console_pair(&record), Some("inconclusive"));
    record["detached"]["native_status"] = json!(0xc000_0142u32);
    assert_eq!(
        classify_reduced_console_pair(&record),
        Some("detachment-did-not-resolve-fixture-startup"),
    );
}

#[test]
fn console_calibration_separates_new_console_allocation_from_inherited_console() {
    use memcordon_ci::windows_consumer_readiness::classify_reduced_console_pair;
    use serde_json::json;
    let settled = |flags: u32, pid: u32, status: u32, matches: bool, stdout: usize| {
        json!({"flags":flags,"pid":pid,"birth":100 + pid,
            "natural_exit":true,"suspended_token_and_image_verified":true,
            "job_empty_verified":true,"native_status":status,"snapshot_matches":matches,
            "stdout_bytes":stdout})
    };
    let mut record = json!({
        "state":"complete","desktop_closed":true,
        "same_held_inputs":{"reduced_primary":true,"desktop":true,"stdio_endpoints":true,"creation_job":true},
        "baseline":settled(0x80604, 41, 0, true, 1161),
        "detached":settled(0x8060c, 42, 0, true, 1161),
        "new_console":settled(0x80614, 43, 0xc000_0142, false, 0),
    });
    assert_eq!(
        classify_reduced_console_pair(&record),
        Some("new-console-allocation-reproduces-fixture-startup"),
    );
    record["new_console"] = settled(0x80614, 43, 0, true, 1161);
    assert_eq!(
        classify_reduced_console_pair(&record),
        Some("fixture-baseline-did-not-reproduce"),
    );
    record["new_console"] = settled(0x80614, 43, 0xc000_0142, false, 7);
    assert_eq!(classify_reduced_console_pair(&record), Some("inconclusive"));
    record.as_object_mut().unwrap().remove("new_console");
    assert_eq!(classify_reduced_console_pair(&record), None);
}

#[test]
fn reduced_startup_keeps_cleanup_exit_separate_from_authenticated_product_status() {
    use memcordon_ci::windows_consumer_readiness::{
        ReducedStartupFrontend, validate_reduced_startup_settlement,
    };
    use memcordon_core::result_v3::RuntimeExecutionV3;

    let mut result = current_fixture::completed_loader_failure();
    let (terminal, delivery, authority) = settled_application_receipt(&mut result);
    result.outcome.wrapper_status = 125;
    let original = ReducedStartupFrontend::OriginalCallback {
        observed_status: None,
        cleanup_status: Some(1),
    };
    assert_eq!(
        serde_json::to_value(original).unwrap(),
        serde_json::json!({
            "source":"original-callback","observed_status":null,"cleanup_status":1,
        })
    );
    let validate = |result: &_, frontend| {
        validate_reduced_startup_settlement(result, &terminal, &delivery, &authority, frontend)
    };
    validate(&result, original).unwrap();
    assert!(
        validate(
            &result,
            ReducedStartupFrontend::OriginalCallback {
                observed_status: Some(1),
                cleanup_status: Some(125),
            }
        )
        .is_err()
    );
    assert!(
        validate(
            &result,
            ReducedStartupFrontend::Comparison {
                observed_status: None
            }
        )
        .is_err()
    );
    validate(
        &result,
        ReducedStartupFrontend::Comparison {
            observed_status: Some(125),
        },
    )
    .unwrap();

    let mut mismatch = result.clone();
    let RuntimeExecutionV3::WindowsSealed { native, .. } = &mut mismatch.runtime else {
        unreachable!()
    };
    native.initial_target_token_matches_caller = false;
    assert!(validate(&mismatch, original).is_err());

    let mut unassociated = result.clone();
    let RuntimeExecutionV3::WindowsSealed { native, .. } = &mut unassociated.runtime else {
        unreachable!()
    };
    native.frontend_provider_association = None;
    assert!(validate(&unassociated, original).is_err());

    let mut wrong_birth = result.clone();
    let RuntimeExecutionV3::WindowsSealed { native, .. } = &mut wrong_birth.runtime else {
        unreachable!()
    };
    native.target_identity.as_mut().unwrap().creation_time_100ns += 1;
    assert!(validate(&wrong_birth, original).is_err());

    let mut mismatch = result;
    let RuntimeExecutionV3::WindowsSealed { native, .. } = &mut mismatch.runtime else {
        unreachable!()
    };
    native.retirement.as_mut().unwrap().job_identity = "cd".repeat(32);
    assert!(validate(&mismatch, original).is_err());
}

#[test]
fn reduced_startup_phase_preserves_zero_coverage_without_disclosing_control_inputs() {
    use memcordon_ci::windows_consumer_readiness::reduced_startup_phase;
    use memcordon_core::{
        ProcessObservationCoverageV1, ProcessObservationPolicyV1,
        ProcessObservationUnavailableReasonV1, WindowsLoaderQualificationOutcomeV2,
        WindowsLoaderReadyEvidenceV1, WindowsProcessObservationV2, WindowsSealedEvidenceV3,
    };
    use serde_json::json;

    let mut observation = WindowsProcessObservationV2::unavailable(
        ProcessObservationUnavailableReasonV1::LegacyObservationUnavailable,
    );
    observation.coverage = ProcessObservationCoverageV1::Sampled {
        policy: ProcessObservationPolicyV1::SERVICE,
        counters: Default::default(),
        omissions: Default::default(),
        sample: Default::default(),
    };
    let mut native = WindowsSealedEvidenceV3 {
        target_released: true,
        process_observation: Some(Box::new(observation)),
        loader_qualification: Some(WindowsLoaderQualificationOutcomeV2::Ready(
            WindowsLoaderReadyEvidenceV1 {
                schema_version: 1,
                launch_plan_sha256: "digest-canary".into(),
                launch_plan_json: Some("session-and-path-canary".into()),
                elapsed_millis: 15,
            },
        )),
        service_identity: "service-identity-canary".into(),
        ..Default::default()
    };
    let phase = reduced_startup_phase(&native);
    assert_eq!(
        phase,
        json!({
            "state": "associated",
            "desktop_loader_control": "ready",
            "target_released": true,
            "process_observation": {
                "state": "sampling-configured",
                "polls_attempted": 0,
                "snapshots_obtained": 0,
                "counter_saturated": false,
            },
            "fixture_entry": "unknown",
            "failing_initializer": "unknown",
            "acceptance_authority": false,
        }),
    );
    let mut largest = phase.clone();
    largest["process_observation"]["polls_attempted"] = json!(u64::MAX);
    largest["process_observation"]["snapshots_obtained"] = json!(u64::MAX);
    assert!(serde_json::to_vec(&largest).unwrap().len() < 1024);

    native.loader_qualification = None;
    native.process_observation = None;
    let absent = reduced_startup_phase(&native);
    assert_eq!(absent["desktop_loader_control"], "unavailable");
    assert_eq!(
        absent["process_observation"],
        json!({"state": "unavailable"})
    );
}

#[test]
fn reduced_startup_phase_survives_comparison_failure_only_with_original_settlement() {
    use memcordon_ci::windows_consumer_readiness::retain_original_startup_observation;
    use serde_json::json;

    let comparison_error = json!({"state": "unavailable", "diagnostic_only": true});
    let phase = json!({"state": "associated", "acceptance_authority": false});
    let anchors = json!({"original_settlement": {"target": {"process_id": 37,
        "creation_time_100ns": 51}}});
    let retained = retain_original_startup_observation(
        Some(comparison_error.clone()),
        Some(anchors.clone()),
        Some(phase.clone()),
    )
    .unwrap();
    assert_eq!(retained["state"], comparison_error["state"]);
    assert_eq!(retained["original_case_argv_path"], anchors);
    assert_eq!(retained["original_startup_phase"], phase);

    for unassociated in [None, Some(json!({"original_settlement": null}))] {
        let unavailable = retain_original_startup_observation(
            Some(comparison_error.clone()),
            unassociated,
            Some(phase.clone()),
        )
        .unwrap();
        assert_eq!(
            unavailable["original_startup_phase"],
            json!({"state": "unavailable"})
        );
    }
    assert!(retain_original_startup_observation(None, None, Some(phase)).is_none());
}

#[test]
fn execution_evidence_requires_the_original_held_root_birth_not_only_reported_pid() {
    use memcordon_ci::windows_consumer_readiness::{bind_execution_root, current_native};
    use memcordon_ci::windows_listener_wait::Identity;
    let result = current_fixture::completed_loader_failure();
    let reported = current_native(&result)
        .unwrap()
        .target_identity
        .as_ref()
        .unwrap();
    let held = Identity {
        pid: reported.process_id,
        birth: reported.creation_time_100ns.into(),
    };
    let joined = bind_execution_root(&result, held).unwrap();
    assert_eq!(joined.pid, held.pid);
    assert_eq!(u128::from(joined.birth), held.birth);
    for invalid in [
        Identity {
            pid: held.pid + 1,
            ..held
        },
        Identity {
            birth: held.birth + 1,
            ..held
        },
        Identity { pid: 0, ..held },
        Identity { birth: 0, ..held },
        Identity {
            birth: u128::from(u64::MAX) + 1,
            ..held
        },
    ] {
        assert!(bind_execution_root(&result, invalid).is_err());
    }
}

#[test]
fn readiness_schedule_preserves_every_case_and_places_prepared_core_first() {
    use memcordon_ci::windows_consumer_readiness::{CaseKey, readiness_execution_order};
    use memcordon_ci::windows_readiness_policy::{RequirementClass, requirement_class};
    let mut keys: Vec<_> = positive_keys().into_iter().collect();
    keys.reverse();
    let order = readiness_execution_order(&keys).unwrap();
    assert_eq!(order.len(), 63);
    let classes: Vec<_> = order
        .iter()
        .map(|index| requirement_class(&keys[*index]).unwrap())
        .collect();
    assert!(
        classes[..53]
            .iter()
            .all(|class| *class == RequirementClass::CorePositive)
    );
    assert!(
        classes[53..]
            .iter()
            .all(|class| *class == RequirementClass::ContextualWorkload)
    );
    let toolchain_scenarios: Vec<_> = order
        .iter()
        .map(|index| &keys[*index])
        .filter(|case| case.family == "W-TOOLCHAIN")
        .map(|case| case.scenario.as_str())
        .collect();
    assert_eq!(
        toolchain_scenarios,
        ["ordinary", "restricted", "group-privilege-reduced"]
    );
    let mut missing = keys.clone();
    missing.pop();
    assert!(readiness_execution_order(&missing).is_err());
    let mut duplicate = keys.clone();
    duplicate.push(keys[0].clone());
    assert!(readiness_execution_order(&duplicate).is_err());
    keys[0] = CaseKey {
        family: "unknown".into(),
        scenario: "ordinary".into(),
    };
    assert!(readiness_execution_order(&keys).is_err());
}

#[test]
fn prefix_frontend_keeps_actual_nonzero_status_and_requires_bound_native_settlement() {
    use memcordon_ci::windows_consumer_readiness::{
        BoundPrefixExit, CaseInput, CaseKey, FrontendExit, TokenObservation, current_association,
        current_native, validate_listener_prefix_frontend,
    };
    use memcordon_ci::windows_listener_wait::{ApplicationEnd, Identity};
    let mut result = current_fixture::completed_loader_failure();
    result.outcome.native_termination =
        Some(memcordon_core::ChildTermination::WindowsStatus { status: 2 });
    result.outcome.wrapper_status = 2;
    result.validate().unwrap();
    let target = current_native(&result)
        .unwrap()
        .target_identity
        .as_ref()
        .unwrap();
    let ended = ApplicationEnd {
        identity: Identity {
            pid: target.process_id,
            birth: target.creation_time_100ns.into(),
        },
        status: 2,
    };
    let expected = current_association(&result).unwrap().clone();
    let (_, mut input) = matched_clock_input();
    input.case = Case::Joint;
    input.matched_control = Some(descriptor::matched::Binding {
        scope: descriptor::matched::Scope::JointListenerPrefix,
        lane: descriptor::matched::Lane::Installed,
        pair_sha256: [1; 32],
        input_sha256: [2; 32],
    });
    input.winsock_registry = Some(descriptor::winsock_registry::Declaration {
        version: descriptor::winsock_registry::VERSION,
        view: descriptor::winsock_registry::View::Native,
        sha256: [3; 32],
    });
    input.start_transport = descriptor::StartTransport::ControllerStdin {
        version: descriptor::controller_start::REGISTRY_VERSION,
    };
    input.validate().unwrap();
    let token = TokenObservation {
        user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0],
        restricted: true,
        integrity_rid: 8192,
        elevated: false,
        restricting_sids: Vec::new(),
    };
    let case = CaseInput {
        key: CaseKey {
            family: "W-MATCHED-OWNED".into(),
            scenario: "restricted".into(),
        },
        descriptor: input,
        descriptor_path: std::env::temp_dir().join("prefix-input.json"),
        workload_request: std::env::temp_dir().join("prefix-request.json"),
        expected_token: token.clone(),
    };
    let mut transcript = Vec::new();
    for (sequence, (stage, value)) in [
        ("started", case.descriptor.challenge.clone()),
        ("token-envelope", serde_json::to_vec(&token).unwrap()),
        ("sentinel-handles-excluded", 1u32.to_le_bytes().to_vec()),
        ("controller-released", case.descriptor.challenge.clone()),
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = serde_json::to_vec(&serde_json::json!({"sequence":sequence,"stage":stage,"pid":ended.identity.pid,"ordinal":null,"value":value})).unwrap();
        transcript.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        transcript.extend_from_slice(&bytes);
    }
    let observed = || BoundPrefixExit {
        frontend: FrontendExit {
            status: 2,
            original_pid: Some(41),
        },
        target: ended,
    };
    let bytes = serde_json::to_vec(&result).unwrap();
    validate_listener_prefix_frontend(
        &case,
        &bytes,
        b"",
        b"actual original fixture refusal",
        &transcript,
        observed(),
        &expected,
    )
    .unwrap();
    let mut wrong_status = observed();
    wrong_status.target.status = 3;
    assert!(
        validate_listener_prefix_frontend(
            &case,
            &bytes,
            b"",
            b"",
            &transcript,
            wrong_status,
            &expected
        )
        .is_err()
    );
    let mut wrong_owner = observed();
    wrong_owner.target.identity.pid += 1;
    assert!(
        validate_listener_prefix_frontend(
            &case,
            &bytes,
            b"",
            b"",
            &transcript,
            wrong_owner,
            &expected
        )
        .is_err()
    );
    let mut unscoped = case;
    unscoped.descriptor.matched_control = None;
    assert!(
        validate_listener_prefix_frontend(
            &unscoped,
            &bytes,
            b"",
            b"",
            &transcript,
            observed(),
            &expected
        )
        .is_err()
    );
}

#[test]
fn owned_file_scope_requires_complete_positive_operations() {
    use memcordon_ci::windows_consumer_readiness::{
        descriptor::matched::{Comparison, ComparisonOutcome, NativeStatusDomain, Scope},
        matched_owned_positive,
    };
    for scope in [Scope::BinaryFiles, Scope::Envelope] {
        for (outcome, positive) in [
            (ComparisonOutcome::ScopeSuccess, true),
            (ComparisonOutcome::SameObservedFailure, false),
            (ComparisonOutcome::DifferentOutcome, false),
        ] {
            assert_eq!(
                matched_owned_positive(&Comparison {
                    outcome,
                    scope,
                    native_status_domain: NativeStatusDomain::Win32
                }),
                positive
            );
        }
    }
}

#[test]
fn natural_frontend_settlement_preserves_the_exact_failed_application_and_retirement_checks() {
    use memcordon_ci::windows_consumer_readiness::{
        current_association, current_native, validate_ended_application_settlement,
    };
    use memcordon_ci::windows_listener_wait::{ApplicationEnd, Identity};
    let result = current_fixture::completed_loader_failure();
    let target = current_native(&result)
        .unwrap()
        .target_identity
        .as_ref()
        .unwrap();
    let ended = ApplicationEnd {
        identity: Identity {
            pid: target.process_id,
            birth: target.creation_time_100ns.into(),
        },
        status: 0xC0000142,
    };
    let association = current_association(&result).unwrap().clone();
    let bytes = serde_json::to_vec(&result).unwrap();
    validate_ended_application_settlement(&bytes, 125, ended, &association).unwrap();
    assert!(check_positive_barrier_result(&bytes, &association.provider).is_err());
    assert!(validate_ended_application_settlement(&bytes, 2, ended, &association).is_err());
    assert!(
        validate_ended_application_settlement(
            &bytes,
            125,
            ApplicationEnd { status: 2, ..ended },
            &association
        )
        .is_err()
    );
    assert!(
        validate_ended_application_settlement(
            &bytes,
            125,
            ApplicationEnd {
                identity: Identity {
                    birth: ended.identity.birth + 1,
                    ..ended.identity
                },
                ..ended
            },
            &association
        )
        .is_err()
    );
    let mut other = association.clone();
    other.request_sha256 = memcordon_core::hash_bytes(b"different request");
    assert!(validate_ended_application_settlement(&bytes, 125, ended, &other).is_err());
    assert!(
        validate_ended_application_settlement(
            &serde_json::to_vec(&current_fixture::launch_failure()).unwrap(),
            125,
            ended,
            &association
        )
        .is_err()
    );
    for field in ["retirement", "ack"] {
        let mut incomplete = result.clone();
        let memcordon_core::result_v3::RuntimeExecutionV3::WindowsSealed { native, .. } =
            &mut incomplete.runtime
        else {
            panic!("native fixture")
        };
        match field {
            "retirement" => native.guardian_reaped = false,
            "ack" => {
                native
                    .frontend_delivery
                    .as_mut()
                    .unwrap()
                    .acknowledgement_observed = false
            }
            _ => unreachable!(),
        }
        assert!(
            validate_ended_application_settlement(
                &serde_json::to_vec(&incomplete).unwrap(),
                125,
                ended,
                &association
            )
            .is_err(),
            "{field}"
        );
    }
}

#[test]
fn fileio_capture_keeps_restricted_joint_and_only_adds_ordinary_provider_joint() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseKey, loader_fileio_requested, loader_fileio_retention,
    };
    use memcordon_platform::windows_fileio_record::RetentionMode;
    for (family, scenario, case, experiment, expected) in [
        ("W-JOINT", "restricted", Case::Joint, false, true),
        ("W-JOINT", "restricted", Case::Joint, true, true),
        ("W-JOINT", "ordinary", Case::Joint, true, true),
        ("W-JOINT", "ordinary", Case::Joint, false, false),
        ("W-JOINT", "ordinary", Case::Toolchain, true, false),
        ("W-JOINT", "ordinary", Case::Churn, true, false),
        ("W-JOINT", "restricted", Case::Toolchain, true, false),
        ("W-OTHER", "ordinary", Case::Joint, true, false),
        ("W-OTHER", "restricted", Case::Joint, false, false),
        ("W-JOINT", "future-experiment", Case::Joint, true, false),
    ] {
        let key = CaseKey {
            family: family.into(),
            scenario: scenario.into(),
        };
        assert_eq!(
            loader_fileio_requested(&key, case, experiment),
            expected,
            "{family}/{scenario}/{case:?}/experiment={experiment}"
        );
        let expected_mode =
            if (family, scenario, case, experiment) == ("W-JOINT", "ordinary", Case::Joint, true) {
                RetentionMode::RollingCompleted
            } else {
                RetentionMode::Prefix
            };
        assert_eq!(
            loader_fileio_retention(&key, case, experiment),
            expected_mode
        );
    }
}

#[test]
fn provider_facts_follow_physical_producer_roots_and_ignore_writable_decoys() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseKey, ProviderExperimentRecord as Record, controller_case_directory,
        retain_provider_experiment_facts,
    };
    use std::{collections::BTreeSet, fs};

    let temporary = tempfile::tempdir().unwrap();
    let controller = temporary.path().join("controller");
    let key = CaseKey {
        family: "W-JOINT".into(),
        scenario: "ordinary".into(),
    };
    // These are the actual execute report parent and descriptor output layouts.
    let native = controller.join("W-JOINT/ordinary");
    let fixture = controller.join("candidate-outputs/W-JOINT/ordinary");
    fs::create_dir_all(&native).unwrap();
    fs::create_dir_all(&fixture).unwrap();
    assert_eq!(controller_case_directory(&controller, &key), native);
    let mut leaves = BTreeSet::new();
    for record in Record::ALL {
        assert!(leaves.insert(record.leaf()));
        let (producer, decoy, expected) = match record {
            Record::OriginalListenerObservation
            | Record::OriginalPeerSpawnObservation
            | Record::NativeListener
            | Record::NativeTcpPeer
            | Record::LoaderFileIo
            | Record::CallbackFailure
            | Record::CallbackStdout
            | Record::CallbackStderr
            | Record::FailedFrontend
            | Record::FailedTerminalObservation
            | Record::GuardianQuery
            | Record::GuardianStdout
            | Record::GuardianStderr => (&native, &fixture, b"controller".as_slice()),
            _ => (&fixture, &native, b"fixture".as_slice()),
        };
        fs::write(decoy.join(record.leaf()), b"wrong trust domain").unwrap();
        let selected = record.source_path(&controller, &key, &fixture);
        assert_eq!(selected.parent().unwrap(), producer);
        let expected_leaf = match record {
            Record::OriginalListenerObservation => "result.original-listener-observation.json",
            Record::OriginalPeerSpawnObservation => "result.original-peer-spawn-observation.json",
            _ => record.leaf(),
        };
        assert_eq!(selected.file_name().unwrap(), expected_leaf);
        fs::write(producer.join(expected_leaf), expected).unwrap();
        assert_eq!(fs::read(selected).unwrap(), expected);
    }
    assert!(leaves.contains("winsock-startup-trace.json"));
    assert!(leaves.contains("peer-winsock-startup-trace.json"));
    assert!(leaves.contains("listener-native-file-requests.json"));
    assert!(leaves.contains("peer-listener-native-file-requests.json"));
    assert!(leaves.contains("peer-spawn-call-trace.json"));
    assert!(leaves.contains("tcp-peer-stdout.json"));
    assert!(leaves.contains("tcp-peer-stdout.bin"));
    assert!(leaves.contains("result.loader-fileio.json"));
    assert!(leaves.contains("result.callback-failure.json"));
    assert!(leaves.contains("result.failed-frontend.json"));
    assert!(leaves.contains("result.failed-terminal-observation.json"));
    assert!(leaves.contains("result.guardian-query.stderr.bin"));

    let original_stderr = vec![b'x'; 4984];
    fs::write(native.join("result.stderr.bin"), &original_stderr).unwrap();
    fs::write(native.join("result.stdout.bin"), vec![0; 64 * 1024]).unwrap();
    fs::write(
        native.join("result.guardian-query.stderr.bin"),
        vec![0; 64 * 1024 + 1],
    )
    .unwrap();
    fs::remove_file(native.join("result.guardian-query.stdout.bin")).unwrap();
    fs::write(fixture.join("tcp-peer-stdout.bin"), vec![1; 64 * 1024 + 1]).unwrap();
    let facts = temporary.path().join("facts");
    let mut copied = Vec::new();
    retain_provider_experiment_facts(
        &controller,
        &key,
        &fixture,
        &facts,
        |source, destination, maximum| {
            let bytes = fs::read(source)?;
            assert!(bytes.len() as u64 <= maximum);
            copied.push(source.to_owned());
            fs::write(destination, &bytes)?;
            Ok(bytes)
        },
        |path, bytes| {
            fs::write(path, bytes)?;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        fs::read(facts.join("result.stderr.bin")).unwrap(),
        original_stderr
    );
    assert_eq!(
        fs::metadata(facts.join("result.stdout.bin")).unwrap().len(),
        64 * 1024
    );
    assert!(!facts.join("result.guardian-query.stderr.bin").exists());
    assert!(!facts.join("result.guardian-query.stdout.bin").exists());
    assert!(!copied.contains(&native.join("result.guardian-query.stderr.bin")));
    let index_bytes = fs::read(facts.join("controller-capture-retention.json")).unwrap();
    assert!(index_bytes.len() <= 8 * 1024);
    let index: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
    let captures = index["captures"].as_array().unwrap();
    assert_eq!(captures.len(), 9);
    assert_eq!(index["acceptance_authority"], false);
    for record in [Record::FailedFrontend, Record::FailedTerminalObservation] {
        let retained = fs::read(facts.join(record.leaf())).unwrap();
        assert_eq!(retained, b"controller");
        let row = captures
            .iter()
            .find(|row| row["leaf"] == record.leaf())
            .unwrap();
        assert_eq!(row["file_copy_complete"], true);
        assert_eq!(row["acceptance_authority"], false);
        assert_eq!(
            row["retained_sha256"],
            memcordon_ci::windows_causal_acceptance::sha256(&retained)
        );
    }
    assert!(!facts.join("tcp-peer-stdout.bin").exists());
    assert!(!copied.contains(&fixture.join("tcp-peer-stdout.bin")));
    for (leaf, state) in [
        ("result.stderr.bin", "copied"),
        ("result.stdout.bin", "copied"),
        ("result.failed-frontend.json", "copied"),
        ("result.failed-terminal-observation.json", "copied"),
        ("result.guardian-query.stderr.bin", "oversize-not-copied"),
        ("result.guardian-query.stdout.bin", "not-present"),
        ("tcp-peer-stdout.bin", "oversize-not-copied"),
    ] {
        assert_eq!(
            captures.iter().find(|row| row["leaf"] == leaf).unwrap()["state"],
            state
        );
    }
}

#[test]
fn controller_capture_metadata_distinguishes_complete_files_oversize_and_producer_unknown() {
    use memcordon_ci::windows_consumer_readiness::ProviderExperimentRecord as Record;
    let captures = [
        Record::CallbackFailure,
        Record::CallbackStdout,
        Record::CallbackStderr,
        Record::FailedFrontend,
        Record::FailedTerminalObservation,
        Record::GuardianQuery,
        Record::GuardianStdout,
        Record::GuardianStderr,
        Record::PeerStdout,
    ];
    let original_stderr = vec![b'x'; 4984];
    let mut index = Vec::new();
    for record in captures {
        assert_eq!(record.capture_ceiling(), Some(64 * 1024));
        let copied =
            record.capture_retention(Some(original_stderr.len() as u64), Some(&original_stderr));
        assert_eq!(copied["state"], "copied");
        assert_eq!(copied["retained_bytes"], original_stderr.len());
        assert_eq!(copied["file_copy_complete"], true);
        assert_eq!(copied["retained_sha256"].as_str().unwrap().len(), 64);
        assert!(copied["producer_capture_complete"].is_null());
        assert_eq!(copied["acceptance_authority"], false);
        let limit = vec![0; 64 * 1024];
        assert_eq!(
            record.capture_retention(Some(limit.len() as u64), Some(&limit))["file_copy_complete"],
            true
        );
        let oversized = record.capture_retention(Some(64 * 1024 + 1), None);
        assert_eq!(oversized["state"], "oversize-not-copied");
        assert_eq!(oversized["file_copy_complete"], false);
        assert!(oversized["retained_sha256"].is_null());
        assert!(oversized["retained_bytes"].is_null());
        let oversized_bytes = vec![0; 64 * 1024 + 1];
        let rejected_copy =
            record.capture_retention(Some(oversized_bytes.len() as u64), Some(&oversized_bytes));
        assert!(rejected_copy["retained_sha256"].is_null());
        assert!(rejected_copy["retained_bytes"].is_null());
        index.push(oversized);
        let absent = record.capture_retention(None, None);
        assert_eq!(absent["state"], "not-present");
        assert!(!absent["file_copy_complete"].as_bool().unwrap());
        let changed = record.capture_retention(Some(1), Some(&original_stderr));
        assert_eq!(changed["state"], "not-completely-copied");
    }
    assert!(serde_json::to_vec(&index).unwrap().len() < 8 * 1024);
}

#[test]
fn completed_released_native_failure_cannot_wait_for_a_positive_fixture() {
    let result = current_fixture::completed_loader_failure();
    let provider = result.provider.clone().unwrap();
    let bytes = serde_json::to_vec(&result).unwrap();
    let failure = check_positive_barrier_result(&bytes, &provider)
        .unwrap_err()
        .to_string();
    assert!(failure.contains("wrapper-status=125"));
    assert!(failure.contains("outcome=Completed"));
    assert!(failure.contains("windows-status=3221225794 (0xC0000142)"));
    assert!(failure.contains("release=Released"));
    assert!(failure.contains("no original provider failure observed"));
    let mut foreign = provider;
    foreign.generation = memcordon_core::BoundedText::new("foreign-generation").unwrap();
    assert!(
        check_positive_barrier_result(&bytes, &foreign)
            .unwrap_err()
            .to_string()
            .contains("provider binding")
    );
}

#[test]
fn completed_restricted_launch_failure_cannot_wait_for_a_positive_fixture() {
    let result = current_fixture::launch_failure();
    let bytes = serde_json::to_vec(&result).unwrap();
    let provider = result.provider.as_ref().unwrap();
    let failure = check_positive_barrier_result(&bytes, provider)
        .unwrap_err()
        .to_string();
    assert!(failure.contains("positive fixture launch already failed"));
    assert!(failure.contains("MCSPAWN-FAILED"));
    assert!(failure.contains("0xC0000142"));
    assert!(failure.contains("wrapper-status=125"));
    let mut foreign = provider.clone();
    foreign.generation = memcordon_core::BoundedText::new("foreign-generation").unwrap();
    assert!(
        check_positive_barrier_result(&bytes, &foreign)
            .unwrap_err()
            .to_string()
            .contains("provider binding")
    );
    assert!(check_positive_barrier_result(&bytes[..bytes.len() / 2], provider).is_err());
}

#[test]
fn released_loader_event_context_requires_exact_failure_and_retirement() {
    use memcordon_ci::windows_consumer_readiness::released_target_loader_event_candidate;
    let result = current_fixture::completed_loader_failure();
    assert!(released_target_loader_event_candidate(&result));
    let refusal = current_fixture::launch_failure();
    assert!(!released_target_loader_event_candidate(&refusal));
    let mut missing_retirement = result.clone();
    let memcordon_core::result_v3::RuntimeExecutionV3::WindowsSealed { native, .. } =
        &mut missing_retirement.runtime
    else {
        panic!("current native fixture absent");
    };
    native.guardian_reaped = false;
    assert!(!released_target_loader_event_candidate(&missing_retirement));
    let mut cleanup_error = result.clone();
    cleanup_error.cleanup.state = memcordon_core::execution_facts::CleanupStateV1::Incomplete;
    assert!(!released_target_loader_event_candidate(&cleanup_error));
    let mut different_status = result;
    different_status.outcome.wrapper_status = 0;
    assert!(!released_target_loader_event_candidate(&different_status));
    different_status.outcome.wrapper_status = 125;
    different_status.outcome.native_termination =
        Some(memcordon_core::ChildTermination::WindowsStatus { status: 1 });
    assert!(!released_target_loader_event_candidate(&different_status));
}

#[test]
fn unsupported_format_header_cannot_satisfy_current_barrier() {
    let provider = current_fixture::completed_loader_failure()
        .provider
        .unwrap();
    assert!(
        check_positive_barrier_result(br#"{"format":"unsupported","revision":99}"#, &provider)
            .is_err()
    );
}

fn descriptor() -> Descriptor {
    let root = std::env::temp_dir().join("memcordon-readiness-input-oracle");
    let inputs = root.join("locked-inputs");
    let rustc = inputs.join("toolchain").join("bin").join("rustc.exe");
    let linker = inputs
        .join("toolchain")
        .join("lib")
        .join("rustlib")
        .join("x86_64-pc-windows-msvc")
        .join("bin")
        .join("rust-lld.exe");
    Descriptor {
        matched_control: None,
        format: "memcordon.fixture-workload".into(),
        revision: descriptor::DESCRIPTOR_REVISION,
        case: Case::Churn,
        transcript: root.join("events.bin"),
        output_root: root.clone(),
        challenge: vec![0, 255, 128, 1],
        stdout: Vec::new(),
        stderr: Vec::new(),
        arguments: Vec::new(),
        application_status: 0,
        churn_creations: CHURN_CREATIONS,
        churn_live: CHURN_LIVE,
        denied_write_paths: Vec::new(),
        sentinel_handles: Vec::new(),
        descendant_gate: None,
        start_gate: Some("Local\\memcordon-readiness-test-start".into()),
        start_transport: descriptor::StartTransport::NamedEvent,
        control_clock: None,
        winsock_registry: None,
        provider_input_experiment: false,
        provider_input_paths: Vec::new(),
        provider_input_binding: None,
        gate_access_diagnostic: None,
        gate_precondition: None,
        completion_gate: None,
        cohort_gate: Some("Local\\memcordon-readiness-test-cohort".into()),
        generation_gate: Some("Local\\memcordon-readiness-test-generation".into()),
        toolchain: Some(Toolchain {
            native_work_cutoff_ticks: 1,
            native_work_frequency: 1,
            linker_mode: descriptor::LinkerMode::BundledLldLink,
            input_root: inputs.clone(),
            controller_input_root: None,
            compiler_import_siblings: Vec::new(),
            rustc: rustc.clone(),
            native_linker: linker.clone(),
            selected_images: descriptor::project_toolchain_images([rustc, linker].into_iter().map(
                |path| {
                    (
                        path,
                        String::from(memcordon_core::DiagnosticSha256::from_bytes([7; 32])),
                    )
                },
            ))
            .unwrap(),
            native_library_directories: ["msvc-lib", "sdk-ucrt", "sdk-um"]
                .into_iter()
                .map(|name| inputs.join(name))
                .collect(),
            library_source: root.join("library.rs"),
            test_source: root.join("tests.rs"),
            child_source: root.join("child.rs"),
            dll_source: root.join("dll.rs"),
            loader_source: root.join("loader.rs"),
            target: "x86_64-pc-windows-msvc".into(),
        }),
    }
}

fn invocation_fixture() -> (
    serde_json::Value,
    memcordon_ci::windows_consumer_readiness::InvocationReadbackExpectation,
) {
    use memcordon_ci::windows_consumer_readiness::{
        InvocationCwdIdentity, InvocationReadbackExpectation, invocation_environment,
    };
    let environment = invocation_environment(&[memcordon_core::WindowsEnvironmentEntryV1 {
        name: "SystemRoot".encode_utf16().collect(),
        value: "C:\\Windows".encode_utf16().collect(),
    }])
    .unwrap();
    let expected = InvocationReadbackExpectation {
        root: memcordon_core::execution_facts::NativeProcessV2 { pid: 10, birth: 20 },
        descriptor_sha256: [1; 32],
        challenge_sha256: [2; 32],
        token_sha256: [3; 32],
        environment,
        cwd_identity: InvocationCwdIdentity {
            volume_serial: 7,
            file_index: 42,
            attributes: 0x10,
        },
        work_cutoff_qpc: 100,
        qpc_frequency: 1000,
    };
    let wire = serde_json::json!({"format":"memcordon.windows-invocation-readback","revision":1,
        "pid":10,"birth":20,"descriptor_sha256":expected.descriptor_sha256,
        "challenge_sha256":expected.challenge_sha256,"token_sha256":expected.token_sha256,
        "environment_sha256":expected.environment.sha256,"environment_bytes":expected.environment.bytes,
        "environment_entries":expected.environment.entries,"cwd_utf16":"C:\\model".encode_utf16().collect::<Vec<_>>(),
        "cwd_identity":{"volume_serial":7,"file_index":42,"attributes":0x10},
        "started_qpc":10,"finished_qpc":20,"cutoff_qpc":100,"qpc_frequency":1000});
    (wire, expected)
}

#[test]
fn invocation_environment_uses_exact_native_utf16_including_empty_values_and_drive_entries() {
    use memcordon_ci::windows_consumer_readiness::invocation_environment;
    use memcordon_core::WindowsEnvironmentEntryV1 as Entry;
    let entries = [
        Entry {
            name: vec![u16::from(b'A')],
            value: vec![0x96ea, 0xd800],
        },
        Entry {
            name: "=C:".encode_utf16().collect(),
            value: "C:\\native".encode_utf16().collect(),
        },
        Entry {
            name: vec![u16::from(b'B')],
            value: Vec::new(),
        },
    ];
    let actual = invocation_environment(&entries).unwrap();
    let block = memcordon_core::encode_windows_environment_block(&entries).unwrap();
    let bytes = block
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    assert_eq!(
        actual.sha256,
        descriptor::controller_start::descriptor_digest(&bytes)
    );
    assert_eq!(actual.bytes, bytes.len());
    assert_eq!(actual.entries, 3);
    let mut reordered = entries.to_vec();
    reordered.reverse();
    assert_eq!(invocation_environment(&reordered).unwrap(), actual);
    let empty = invocation_environment(&[]).unwrap();
    assert_eq!(empty.bytes, 4);
    assert_eq!(empty.entries, 0);
    let many = (0..129)
        .map(|index| Entry {
            name: format!("N{index}").encode_utf16().collect(),
            value: Vec::new(),
        })
        .collect::<Vec<_>>();
    assert_eq!(invocation_environment(&many).unwrap().entries, 129);
    for invalid in [
        vec![Entry {
            name: Vec::new(),
            value: Vec::new(),
        }],
        vec![Entry {
            name: vec![0],
            value: Vec::new(),
        }],
        vec![Entry {
            name: vec![u16::from(b'A')],
            value: vec![0],
        }],
        vec![Entry {
            name: "=invalid".encode_utf16().collect(),
            value: Vec::new(),
        }],
        vec![
            Entry {
                name: vec![u16::from(b'A')],
                value: Vec::new(),
            },
            Entry {
                name: vec![u16::from(b'a')],
                value: Vec::new(),
            },
        ],
        vec![Entry {
            name: vec![u16::from(b'A')],
            value: vec![1; 32767],
        }],
    ] {
        assert!(invocation_environment(&invalid).is_err());
    }
}

#[test]
fn actual_invocation_readback_joins_root_digests_environment_and_native_cwd_identity() {
    use memcordon_ci::windows_consumer_readiness::validate_invocation_readback;
    let (wire, expected) = invocation_fixture();
    let bytes = serde_json::to_vec(&wire).unwrap();
    validate_invocation_readback(&bytes, &expected).unwrap();
    for field in [
        "pid",
        "birth",
        "descriptor_sha256",
        "challenge_sha256",
        "token_sha256",
        "environment_sha256",
        "environment_bytes",
        "environment_entries",
        "volume",
        "file",
        "reparse",
        "not_directory",
        "zero_file",
        "cwd_nul",
        "cwd_empty",
        "cwd_oversize",
        "started",
        "backwards",
        "late",
        "cutoff",
        "frequency",
    ] {
        let mut altered = wire.clone();
        match field {
            "pid" | "birth" => altered[field] = 99.into(),
            "descriptor_sha256" | "challenge_sha256" | "token_sha256" | "environment_sha256" => {
                altered[field] = serde_json::to_value([99u8; 32]).unwrap()
            }
            "environment_bytes" | "environment_entries" => altered[field] = 99.into(),
            "volume" => altered["cwd_identity"]["volume_serial"] = 99.into(),
            "file" => altered["cwd_identity"]["file_index"] = 99.into(),
            "reparse" => altered["cwd_identity"]["attributes"] = 0x410.into(),
            "not_directory" => altered["cwd_identity"]["attributes"] = 0x20.into(),
            "zero_file" => altered["cwd_identity"]["file_index"] = 0.into(),
            "cwd_nul" => altered["cwd_utf16"] = serde_json::json!([1, 0, 2]),
            "cwd_empty" => altered["cwd_utf16"] = serde_json::json!([]),
            "cwd_oversize" => {
                altered["cwd_utf16"] = serde_json::to_value(vec![1u16; 32769]).unwrap()
            }
            "started" => altered["started_qpc"] = 0.into(),
            "backwards" => altered["finished_qpc"] = 9.into(),
            "late" => altered["finished_qpc"] = 100.into(),
            "cutoff" => altered["cutoff_qpc"] = 101.into(),
            "frequency" => altered["qpc_frequency"] = 1001.into(),
            _ => unreachable!(),
        }
        assert!(
            validate_invocation_readback(&serde_json::to_vec(&altered).unwrap(), &expected)
                .is_err(),
            "{field}"
        );
    }
    // Spelling and unrelated observed attributes are retained facts, not a
    // reason to rewrite native paths or reject the same held directory object.
    let mut alias = wire;
    alias["cwd_utf16"] =
        serde_json::to_value("c:\\MODEL".encode_utf16().collect::<Vec<_>>()).unwrap();
    alias["cwd_identity"]["attributes"] = 0x30.into();
    validate_invocation_readback(&serde_json::to_vec(&alias).unwrap(), &expected).unwrap();
}

#[test]
fn invocation_readback_requires_closed_complete_redacted_and_bounded_wire() {
    use memcordon_ci::windows_consumer_readiness::{
        MAX_INVOCATION_READBACK_BYTES, validate_invocation_readback,
    };
    let (wire, expected) = invocation_fixture();
    for field in [
        "format",
        "revision",
        "token_sha256",
        "raw_environment",
        "cwd_identity",
    ] {
        let mut altered = wire.clone();
        match field {
            "format" => altered[field] = "matched-control-input".into(),
            "revision" => altered[field] = 0.into(),
            "token_sha256" => {
                altered.as_object_mut().unwrap().remove(field);
            }
            "raw_environment" => altered[field] = serde_json::json!([]),
            "cwd_identity" => altered[field]["extra"] = true.into(),
            _ => unreachable!(),
        }
        assert!(
            validate_invocation_readback(&serde_json::to_vec(&altered).unwrap(), &expected)
                .is_err(),
            "{field}"
        );
    }
    let bytes = serde_json::to_vec(&wire).unwrap();
    assert!(validate_invocation_readback(&bytes[..bytes.len() - 1], &expected).is_err());
    assert!(
        validate_invocation_readback(&vec![b' '; MAX_INVOCATION_READBACK_BYTES + 1], &expected)
            .is_err()
    );
    let mut duplicate = String::from_utf8(bytes).unwrap();
    duplicate.insert_str(1, "\"pid\":10,");
    assert!(validate_invocation_readback(duplicate.as_bytes(), &expected).is_err());
}

#[test]
fn invocation_readback_uses_the_original_bound_envelope_clock_without_rebinding() {
    use memcordon_ci::windows_consumer_readiness::bind_invocation_clock;
    let mut input = descriptor();
    input.case = Case::Envelope;
    input.toolchain = None;
    input.cohort_gate = None;
    input.generation_gate = None;
    input.validate().unwrap();
    assert!(Descriptor::parse(&serde_json::to_vec(&input).unwrap()).is_err());
    let clock = descriptor::ControlClock {
        revision: 1,
        work_cutoff_qpc: 100,
        qpc_frequency: 1000,
    };
    bind_invocation_clock(&mut input, clock.clone()).unwrap();
    let parsed = Descriptor::parse(&serde_json::to_vec(&input).unwrap()).unwrap();
    assert_eq!(parsed.control_clock, Some(clock.clone()));
    assert!(bind_invocation_clock(&mut input, clock.clone()).is_err());
    for field in ["revision", "cutoff", "frequency", "case", "transport"] {
        let mut draft = input.clone();
        draft.control_clock = None;
        let mut invalid = clock.clone();
        match field {
            "revision" => invalid.revision = 0,
            "cutoff" => invalid.work_cutoff_qpc = 0,
            "frequency" => invalid.qpc_frequency = 0,
            "case" => draft.case = Case::ApplicationExit,
            "transport" => {
                draft.start_transport = descriptor::StartTransport::ControllerStdin {
                    version: descriptor::controller_start::VERSION,
                }
            }
            _ => unreachable!(),
        }
        assert!(
            bind_invocation_clock(&mut draft, invalid).is_err(),
            "{field}"
        );
    }
}

fn capacity_base() -> memcordon_ci::windows_consumer_readiness::CaseInput {
    use memcordon_ci::windows_consumer_readiness::{CaseInput, CaseKey, TokenObservation};
    let mut descriptor = descriptor();
    descriptor.case = Case::Joint;
    descriptor.cohort_gate = None;
    descriptor.generation_gate = None;
    CaseInput {
        key: CaseKey {
            family: "W-JOINT".into(),
            scenario: "ordinary".into(),
        },
        descriptor_path: descriptor.output_root.join("input.json"),
        workload_request: descriptor.output_root.join("workload.json"),
        descriptor,
        expected_token: TokenObservation {
            user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0],
            restricted: false,
            integrity_rid: 8192,
            elevated: false,
            restricting_sids: Vec::new(),
        },
    }
}

#[test]
fn capacity_preparation_preserves_original_joint_and_uses_distinct_finite_ownership() {
    use memcordon_ci::windows_consumer_readiness::{
        needs_descriptor_toolchain_observer, needs_registry_input, positive_keys,
        prepare_capacity_completion, validate_descriptor,
    };
    let base = capacity_base();
    let original = serde_json::to_vec(&base).unwrap();
    validate_descriptor(&base.key, &base.descriptor).unwrap();
    for key in memcordon_ci::windows_readiness_capacity::required_keys() {
        let prepared = prepare_capacity_completion(&base, &key).unwrap();
        assert_eq!(serde_json::to_vec(&base).unwrap(), original);
        assert_eq!(prepared.key, key);
        assert_eq!(prepared.descriptor.case, Case::CapacityCompletion);
        assert_ne!(
            prepared.descriptor.cohort_gate,
            prepared.descriptor.start_gate
        );
        assert!(prepared.descriptor.cohort_gate.is_some());
        assert!(prepared.descriptor.toolchain.is_none());
        assert!(prepared.descriptor.winsock_registry.is_none());
        assert!(prepared.descriptor.generation_gate.is_none());
        assert!(prepared.descriptor.completion_gate.is_none());
        assert!(prepared.descriptor.stdout.is_empty() && prepared.descriptor.stderr.is_empty());
        assert!(!needs_registry_input(&key, prepared.descriptor.case));
        assert!(!needs_descriptor_toolchain_observer(&prepared.descriptor).unwrap());
        assert!(!positive_keys().contains(&key));
        assert!(validate_descriptor(&base.key, &prepared.descriptor).is_err());
        assert!(validate_descriptor(&key, &base.descriptor).is_err());
    }
}

#[test]
fn capacity_preparation_rejects_invalid_source_and_cannot_smuggle_a_catalogue_replacement() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseInput, CaseKey, prepare_capacity_completion,
    };
    let key = memcordon_ci::windows_readiness_capacity::required_keys().remove(0);
    let mutations: &[fn(&mut CaseInput)] = &[
        |b| b.key.scenario = "restricted".into(),
        |b| b.descriptor.case = Case::HeldDemand,
        |b| b.descriptor.toolchain = None,
        |b| b.descriptor.start_gate = None,
        |b| b.descriptor.provider_input_experiment = true,
    ];
    for mutate in mutations {
        let mut base = capacity_base();
        mutate(&mut base);
        assert!(prepare_capacity_completion(&base, &key).is_err());
    }
    for wrong in [
        CaseKey {
            family: "W-JOINT".into(),
            scenario: "ordinary".into(),
        },
        CaseKey {
            family: "W-CAPACITY".into(),
            scenario: "unknown".into(),
        },
    ] {
        assert!(prepare_capacity_completion(&capacity_base(), &wrong).is_err());
    }
}

#[test]
fn capacity_assessment_requires_natural_status_empty_streams_and_completed_owned_child() {
    use memcordon_ci::windows_consumer_readiness::{
        FrontendExit, assess, current_association, current_native, prepare_capacity_completion,
    };
    use memcordon_core::ChildTermination;
    let key = memcordon_ci::windows_readiness_capacity::required_keys().remove(0);
    let case = prepare_capacity_completion(&capacity_base(), &key).unwrap();
    let mut result = current_fixture::completed_loader_failure();
    result.outcome.wrapper_status = 0;
    result.outcome.native_termination = Some(ChildTermination::WindowsStatus { status: 0 });
    result.validate().unwrap();
    let root = current_native(&result)
        .unwrap()
        .target_identity
        .as_ref()
        .unwrap()
        .process_id;
    let mut transcript = Vec::new();
    for (index, (stage, ordinal, value)) in [
        ("started", None, case.descriptor.challenge.clone()),
        (
            "native-argv-observed",
            None,
            serde_json::to_vec(
                &serde_json::json!({"encoding":"windows_utf16","values":Vec::<Vec<u16>>::new()}),
            )
            .unwrap(),
        ),
        (
            "sentinel-handles-excluded",
            None,
            0u32.to_le_bytes().to_vec(),
        ),
        (
            "token-envelope",
            None,
            serde_json::to_vec(&case.expected_token).unwrap(),
        ),
        (
            "controller-released",
            None,
            case.descriptor.challenge.clone(),
        ),
        (
            "capacity-child-created",
            Some(0),
            serde_json::to_vec(&memcordon_core::WindowsProcessIdentityV1 {
                process_id: root + 1,
                creation_time_100ns: 21,
            })
            .unwrap(),
        ),
        ("capacity-child-completed", Some(0), Vec::new()),
        ("finished", None, case.descriptor.challenge.clone()),
    ]
    .into_iter()
    .enumerate()
    {
        let frame = serde_json::to_vec(&serde_json::json!({"sequence":index,"stage":stage,"pid":root,"ordinal":ordinal,"value":value})).unwrap();
        transcript.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        transcript.extend(frame);
    }
    let association = current_association(&result).unwrap().clone();
    let bytes = serde_json::to_vec(&result).unwrap();
    let assess_case = |bytes: &[u8], stdout: &[u8], stderr: &[u8], status| {
        assess(
            &case,
            bytes,
            stdout,
            stderr,
            &transcript,
            FrontendExit {
                status,
                original_pid: Some(root + 100),
            },
            &association,
        )
    };
    assess_case(&bytes, &[], &[], 0).unwrap();
    assert!(assess_case(&bytes, &[1], &[], 0).is_err());
    assert!(assess_case(&bytes, &[], &[1], 0).is_err());
    assert!(assess_case(&bytes, &[], &[], 2).is_err());
    result.outcome.wrapper_status = 2;
    result.outcome.native_termination = Some(ChildTermination::WindowsStatus { status: 2 });
    assert!(assess_case(&serde_json::to_vec(&result).unwrap(), &[], &[], 2).is_err());
}

fn matched_clock_input() -> (descriptor::matched_plan::Plan, Descriptor) {
    use descriptor::{
        matched::{Binding, Lane, Scope},
        matched_plan::{Directory, DirectoryRole, Plan},
    };
    let mut input = descriptor();
    let root = input.output_root.clone();
    input.case = Case::BinaryFiles;
    input.output_root = root.join("installed");
    input.transcript = input.output_root.join("fixture-events.bin");
    input.toolchain = None;
    input.cohort_gate = None;
    input.generation_gate = None;
    input.start_transport = descriptor::StartTransport::ControllerStdin {
        version: descriptor::controller_start::VERSION,
    };
    let clock = descriptor::ControlClock {
        revision: 1,
        work_cutoff_qpc: 1000,
        qpc_frequency: 100,
    };
    input.control_clock = Some(clock.clone());
    input.matched_control = Some(Binding {
        pair_sha256: [1; 32],
        lane: Lane::Installed,
        scope: Scope::BinaryFiles,
        input_sha256: [0; 32],
    });
    let mut plan = Plan {
        provider: None,
        revision: 1,
        pair_sha256: [1; 32],
        input_sha256: [0; 32],
        scope: Scope::BinaryFiles,
        restricted: false,
        fixture_sha256: memcordon_core::hash_bytes(b"fixture").into(),
        cli_sha256: memcordon_core::hash_bytes(b"cli").into(),
        direct_descriptor: root.join("direct-input.json"),
        installed_descriptor: root.join("installed-input.json"),
        cwd: root.clone(),
        work_clock: clock,
        cleanup_cutoff_qpc: 2000,
        record: root.join("broker.json"),
        environment: vec![memcordon_core::WindowsEnvironmentEntryV1 {
            name: "SystemRoot".encode_utf16().collect(),
            value: "C:\\Windows".encode_utf16().collect(),
        }],
        directories: [
            (DirectoryRole::Cwd, root.clone()),
            (DirectoryRole::DirectOutput, root.join("direct")),
            (DirectoryRole::InstalledOutput, input.output_root.clone()),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (role, path))| Directory {
            role,
            path,
            volume_serial: 1,
            file_index: index as u64 + 1,
            attributes: 0x10,
            security_information: 23,
            security_bytes: 80,
            security_sha256: [8; 32],
        })
        .collect(),
    };
    let direct = plan.direct_descriptor_for(&input).unwrap();
    plan.input_sha256 = plan.input_digest(&direct).unwrap();
    input.matched_control.as_mut().unwrap().input_sha256 = plan.input_sha256;
    plan.validate(&plan.direct_descriptor_for(&input).unwrap(), &input)
        .unwrap();
    (plan, input)
}

#[test]
fn owned_matched_gate_preparation_preserves_original_clock_without_second_projection() {
    use memcordon_ci::windows_consumer_readiness::{GateClock, prepare_gate_clock};
    let (plan, mut input) = matched_clock_input();
    let original = serde_json::to_vec(&input.control_clock).unwrap();
    let projected = std::cell::Cell::new(false);
    let observed = std::cell::Cell::new(0);
    let mut hypothetical = plan.work_clock.clone();
    hypothetical.work_cutoff_qpc += 1;
    let selection = GateClock::ExistingMatched(&plan);
    selection.validate_selection(&input).unwrap();
    prepare_gate_clock(
        &mut input,
        selection,
        std::time::Instant::now() + std::time::Duration::from_secs(10),
        || {
            projected.set(true);
            Ok(hypothetical)
        },
        || {
            observed.set(observed.get() + 1);
            Ok((500, 100))
        },
    )
    .unwrap();
    assert!(
        !projected.get(),
        "matched preparation must not sample a second projection"
    );
    assert_eq!(observed.get(), 1);
    assert_eq!(serde_json::to_vec(&input.control_clock).unwrap(), original);
    let direct = plan.direct_descriptor_for(&input).unwrap();
    plan.validate(&direct, &input).unwrap();
    assert_eq!(direct.control_clock, Some(plan.work_clock.clone()));
}

#[test]
fn matched_gate_preparation_rejects_clock_drift_missing_owner_and_expired_original_limits() {
    use memcordon_ci::windows_consumer_readiness::{GateClock, prepare_gate_clock};
    use std::time::{Duration, Instant};
    let (plan, input) = matched_clock_input();
    for field in [
        "missing",
        "tick",
        "revision",
        "frequency",
        "lane",
        "pair",
        "digest",
        "protected",
    ] {
        let mut changed = input.clone();
        match field {
            "missing" => changed.control_clock = None,
            "tick" => changed.control_clock.as_mut().unwrap().work_cutoff_qpc += 1,
            "revision" => changed.control_clock.as_mut().unwrap().revision += 1,
            "frequency" => changed.control_clock.as_mut().unwrap().qpc_frequency += 1,
            "lane" => {
                changed.matched_control.as_mut().unwrap().lane = descriptor::matched::Lane::Direct
            }
            "pair" => changed.matched_control.as_mut().unwrap().pair_sha256[0] ^= 1,
            "digest" => changed.matched_control.as_mut().unwrap().input_sha256[0] ^= 1,
            "protected" => changed
                .denied_write_paths
                .push(changed.output_root.join("unexpected")),
            _ => unreachable!(),
        }
        assert!(
            prepare_gate_clock(
                &mut changed,
                GateClock::ExistingMatched(&plan),
                Instant::now() + Duration::from_secs(10),
                || panic!("invalid owned input cannot project"),
                || panic!("invalid owned input cannot observe")
            )
            .is_err(),
            "{field}"
        );
    }
    for (now, frequency) in [(1000, 100), (1001, 100), (0, 100), (500, 101)] {
        let mut changed = input.clone();
        assert!(
            prepare_gate_clock(
                &mut changed,
                GateClock::ExistingMatched(&plan),
                Instant::now() + Duration::from_secs(10),
                || panic!("owned clock cannot project"),
                || Ok((now, frequency))
            )
            .is_err()
        );
        assert_eq!(changed.control_clock, input.control_clock);
    }
    let mut changed = input.clone();
    assert!(
        prepare_gate_clock(
            &mut changed,
            GateClock::ExistingMatched(&plan),
            Instant::now(),
            || panic!("expired cutoff cannot project"),
            || panic!("expired cutoff cannot query")
        )
        .is_err()
    );
    assert!(
        prepare_gate_clock(
            &mut changed,
            GateClock::PrepareFromDeadline,
            Instant::now() + Duration::from_secs(10),
            || panic!("serialized matched input has no clock owner"),
            || panic!("serialized matched input has no clock owner")
        )
        .is_err()
    );
}

#[test]
fn ordinary_gate_preparation_keeps_its_original_projection_and_named_event_policy() {
    use memcordon_ci::windows_consumer_readiness::{GateClock, prepare_gate_clock};
    let mut input = descriptor();
    input.case = Case::Envelope;
    input.toolchain = None;
    input.cohort_gate = None;
    input.generation_gate = None;
    input.start_transport = descriptor::StartTransport::ControllerStdin {
        version: descriptor::controller_start::VERSION,
    };
    let original = descriptor::ControlClock {
        revision: 1,
        work_cutoff_qpc: 2000,
        qpc_frequency: 100,
    };
    let projected = std::cell::Cell::new(0);
    prepare_gate_clock(
        &mut input,
        GateClock::PrepareFromDeadline,
        std::time::Instant::now() + std::time::Duration::from_secs(10),
        || {
            projected.set(projected.get() + 1);
            Ok(original.clone())
        },
        || panic!("ordinary preparation uses its existing projection"),
    )
    .unwrap();
    assert_eq!(projected.get(), 1);
    assert_eq!(input.control_clock, Some(original));
    input.validate().unwrap();
    input.start_transport = descriptor::StartTransport::NamedEvent;
    prepare_gate_clock(
        &mut input,
        GateClock::PrepareFromDeadline,
        std::time::Instant::now() + std::time::Duration::from_secs(10),
        || panic!("named event has no protocol clock"),
        || panic!("named event has no protocol clock"),
    )
    .unwrap();
    assert!(input.control_clock.is_none());
    input.validate().unwrap();
}

fn experiment_descriptor() -> Descriptor {
    let mut value = descriptor();
    value.case = Case::Joint;
    value.cohort_gate = None;
    value.generation_gate = None;
    value.start_transport = descriptor::StartTransport::ControllerStdin {
        version: descriptor::controller_start::PRIVATE_VERSION,
    };
    value.control_clock = Some(descriptor::ControlClock {
        revision: 1,
        work_cutoff_qpc: 1000,
        qpc_frequency: 10,
    });
    value.winsock_registry = Some(descriptor::winsock_registry::Declaration {
        version: descriptor::winsock_registry::VERSION,
        view: descriptor::winsock_registry::View::Native,
        sha256: [3; 32],
    });
    let parent = value.output_root.with_file_name("private-fixture-inputs");
    let fixture = parent.join("fixture.exe");
    let local = parent.join("fixture.exe.local");
    let directory = |path, index| descriptor::PrivateFixtureAncestor {
        path,
        volume_serial: 7,
        file_index: index,
        attributes: 0x10,
    };
    let ancestors = fixture
        .ancestors()
        .skip(1)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .enumerate()
        .map(|(index, path)| directory(path.to_owned(), index as u64 + 1))
        .collect();
    let output_ancestors = value
        .output_root
        .ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .enumerate()
        .map(|(index, path)| directory(path.to_owned(), 200 + index as u64))
        .collect();
    value.provider_input_experiment = true;
    value.provider_input_paths = vec![fixture.clone(), local.join("provider.dll")];
    value.provider_input_binding = Some(descriptor::PrivateFixtureBinding {
        revision: 2,
        fixture,
        volume_serial: 7,
        file_index: 42,
        attributes: 0x20,
        links: 1,
        bytes: 1000,
        sha256: "ab".repeat(32),
        native_path_utf16: r"\Device\Volume\private-fixture-inputs\fixture.exe"
            .encode_utf16()
            .collect(),
        ancestors,
        local_input: memcordon_platform::windows_private_fixture_binding::DotLocalInput::Directory(
            directory(local, 100),
        ),
        output_ancestors,
    });
    value
}

fn provider_root_clone_plan(
    file_layout: bool,
) -> (Descriptor, descriptor::matched_plan::Plan, Descriptor) {
    use descriptor::{
        matched::{Binding, Lane, Scope},
        matched_plan::{ProviderControl, ProviderInput},
    };
    use memcordon_platform::windows_private_fixture_binding::{
        DotLocalInput, PrivateFixtureAncestor, PrivateFixtureFile,
    };
    use sha2::Digest;
    use std::collections::{BTreeMap, BTreeSet};
    let (mut plan, installed_output) = matched_clock_input();
    let mut original = experiment_descriptor();
    original.output_root = installed_output.output_root;
    original.transcript = original.output_root.join("fixture-events.bin");
    original.control_clock = Some(plan.work_clock.clone());
    original.denied_write_paths = vec![
        plan.cwd.join("driver-parent/denied.bin"),
        plan.cwd.join("provider-parent/denied.bin"),
    ];
    original.stdout = vec![0, 255, 128];
    original.stderr = vec![128, 0, 255];
    let direct_output = plan.directories[1].path.clone();
    let binding = original.provider_input_binding.as_mut().unwrap();
    let mut paths = BTreeSet::new();
    for path in binding
        .fixture
        .ancestors()
        .skip(1)
        .chain(direct_output.ancestors())
        .chain(original.output_root.ancestors())
    {
        paths.insert(path.to_owned());
    }
    let identities: BTreeMap<_, _> = paths
        .into_iter()
        .enumerate()
        .map(|(index, path)| (path, index as u64 + 100))
        .collect();
    let chain = |path: &std::path::Path| {
        path.ancestors()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|path| PrivateFixtureAncestor {
                path: path.to_owned(),
                volume_serial: 7,
                file_index: identities[path],
                attributes: 0x10,
            })
            .collect::<Vec<_>>()
    };
    binding.ancestors = chain(binding.fixture.parent().unwrap());
    binding.output_ancestors = chain(&original.output_root);
    let local_path = binding.fixture.with_extension("exe.local");
    let provider_path = if file_layout {
        binding.fixture.parent().unwrap().join("provider.dll")
    } else {
        local_path.join("provider.dll")
    };
    binding.local_input = if file_layout {
        binding.revision = 3;
        DotLocalInput::File(PrivateFixtureFile {
            path: local_path.clone(),
            volume_serial: 7,
            file_index: 10_000,
            attributes: 0x20,
            links: 1,
            bytes: 0,
            sha256: hex::encode(sha2::Sha256::digest([])),
            native_path_utf16: r"\Device\Volume\private-fixture-inputs\fixture.exe.local"
                .encode_utf16()
                .collect(),
        })
    } else {
        DotLocalInput::Directory(PrivateFixtureAncestor {
            path: local_path.clone(),
            volume_serial: 7,
            file_index: 10_000,
            attributes: 0x10,
        })
    };
    original.provider_input_paths = vec![binding.fixture.clone()];
    if file_layout {
        original.provider_input_paths.push(local_path);
    }
    original.provider_input_paths.push(provider_path.clone());
    original.start_transport = descriptor::StartTransport::ControllerStdin {
        version: if file_layout {
            descriptor::controller_start::PRIVATE_FILE_VERSION
        } else {
            descriptor::controller_start::PRIVATE_VERSION
        },
    };
    plan.scope = Scope::ProviderListenerSelection;
    plan.restricted = true;
    plan.fixture_sha256 = binding.sha256.clone();
    let mut direct_binding = binding.clone();
    direct_binding.output_ancestors = chain(&direct_output);
    plan.provider = Some(ProviderControl {
        direct: direct_binding,
        installed: binding.clone(),
        paths: original.provider_input_paths.clone(),
        providers: vec![ProviderInput {
            path: provider_path,
            original_path: r"C:\Windows\provider.dll".encode_utf16().collect(),
            private_native_path: if file_layout {
                r"\Device\Volume\private-fixture-inputs\provider.dll"
            } else {
                r"\Device\Volume\private-fixture-inputs\fixture.exe.local\provider.dll"
            }
            .encode_utf16()
            .collect(),
            volume_serial: 7,
            file_index: 20_000,
            bytes: 4096,
            sha256: "cd".repeat(32),
        }],
    });
    for directory in &mut plan.directories {
        directory.volume_serial = 7;
        directory.file_index = identities[&directory.path];
    }
    original.validate().unwrap();
    let mut reduced =
        memcordon_ci::windows_consumer_readiness::prepare_provider_root_descriptor(&original)
            .unwrap();
    reduced.matched_control = Some(Binding {
        pair_sha256: plan.pair_sha256,
        lane: Lane::Installed,
        scope: plan.scope,
        input_sha256: plan.input_sha256,
    });
    let direct = plan.direct_descriptor_for(&reduced).unwrap();
    plan.input_sha256 = plan.input_digest(&direct).unwrap();
    reduced.matched_control.as_mut().unwrap().input_sha256 = plan.input_sha256;
    (original, plan, reduced)
}

#[test]
fn provider_root_clone_clears_original_probes_before_both_private_plan_derivations() {
    for file_layout in [false, true] {
        let (original, plan, installed) = provider_root_clone_plan(file_layout);
        let bytes = serde_json::to_vec(&original).unwrap();
        let cloned =
            memcordon_ci::windows_consumer_readiness::prepare_provider_root_descriptor(&original)
                .unwrap();
        assert_eq!(serde_json::to_vec(&original).unwrap(), bytes);
        assert_eq!(original.denied_write_paths.len(), 2);
        assert_eq!(original.stdout, [0, 255, 128]);
        assert_eq!(original.stderr, [128, 0, 255]);
        assert!(
            cloned.denied_write_paths.is_empty()
                && cloned.stdout.is_empty()
                && cloned.stderr.is_empty()
        );
        let direct = plan.direct_descriptor_for(&installed).unwrap();
        assert!(direct.denied_write_paths.is_empty() && installed.denied_write_paths.is_empty());
        assert_eq!(plan.input_digest(&direct).unwrap(), plan.input_sha256);
        assert_eq!(
            direct.start_transport,
            descriptor::StartTransport::ControllerStdin {
                version: if file_layout {
                    descriptor::controller_start::PRIVATE_FILE_VERSION
                } else {
                    descriptor::controller_start::PRIVATE_VERSION
                }
            }
        );
        plan.validate(&direct, &installed).unwrap();
        Descriptor::parse(&serde_json::to_vec(&direct).unwrap()).unwrap();
        Descriptor::parse(&serde_json::to_vec(&installed).unwrap()).unwrap();
        let mut forged = installed.clone();
        forged.denied_write_paths = original.denied_write_paths.clone();
        assert!(
            plan.direct_descriptor_for(&forged).is_err(),
            "unchanged strict plan rejects injected protected operations"
        );
        let mut wrong = original.clone();
        wrong.case = Case::Envelope;
        assert!(
            memcordon_ci::windows_consumer_readiness::prepare_provider_root_descriptor(&wrong)
                .is_err()
        );
        assert!(
            memcordon_ci::windows_consumer_readiness::prepare_provider_root_descriptor(&installed)
                .is_err()
        );
    }
}

#[test]
fn provider_root_reduction_does_not_relax_restricted_envelope_protected_roles() {
    use descriptor::{
        matched::Scope,
        matched_plan::{Directory, DirectoryRole},
    };
    let (mut plan, mut installed) = matched_clock_input();
    plan.scope = Scope::Envelope;
    plan.restricted = true;
    installed.case = Case::Envelope;
    installed.matched_control.as_mut().unwrap().scope = plan.scope;
    for (index, role, name) in [
        (4, DirectoryRole::DriverParent, "protected-driver"),
        (5, DirectoryRole::ProviderParent, "protected-provider"),
    ] {
        let parent = plan.cwd.join(name);
        installed.denied_write_paths.push(parent.join("denied.bin"));
        plan.directories.push(Directory {
            role,
            path: parent,
            volume_serial: 1,
            file_index: index,
            attributes: 0x10,
            security_information: 23,
            security_bytes: 80,
            security_sha256: [8; 32],
        });
    }
    let direct = plan.direct_descriptor_for(&installed).unwrap();
    plan.input_sha256 = plan.input_digest(&direct).unwrap();
    installed.matched_control.as_mut().unwrap().input_sha256 = plan.input_sha256;
    let direct = plan.direct_descriptor_for(&installed).unwrap();
    plan.validate(&direct, &installed).unwrap();
    assert_eq!(direct.denied_write_paths.len(), 2);
    assert_eq!(installed.denied_write_paths.len(), 2);
    for keep in [0, 1] {
        let mut missing = installed.clone();
        missing.denied_write_paths.truncate(keep);
        assert!(plan.direct_descriptor_for(&missing).is_err());
    }
}

#[test]
fn fixture_binding_is_experiment_only_and_part_of_the_original_bounded_descriptor() {
    let valid = experiment_descriptor();
    assert!(
        memcordon_ci::windows_consumer_readiness::needs_descriptor_toolchain_observer(&valid)
            .unwrap()
    );
    let mut root = valid.clone();
    root.matched_control = Some(descriptor::matched::Binding {
        pair_sha256: [1; 32],
        lane: descriptor::matched::Lane::Installed,
        scope: descriptor::matched::Scope::ProviderListenerSelection,
        input_sha256: [2; 32],
    });
    root.toolchain = None;
    assert!(
        !memcordon_ci::windows_consumer_readiness::needs_descriptor_toolchain_observer(&root)
            .unwrap()
    );
    let mut missing_root_binding = root.clone();
    missing_root_binding.provider_input_binding = None;
    assert!(
        memcordon_ci::windows_consumer_readiness::needs_descriptor_toolchain_observer(
            &missing_root_binding
        )
        .is_err()
    );
    root.matched_control = None;
    assert!(
        memcordon_ci::windows_consumer_readiness::needs_descriptor_toolchain_observer(&root)
            .is_err()
    );
    let bytes = serde_json::to_vec(&valid).unwrap();
    let parsed = Descriptor::parse(&bytes).unwrap();
    assert_eq!(parsed.provider_input_binding, valid.provider_input_binding);
    let mut legacy = valid.clone();
    legacy.start_transport = descriptor::StartTransport::ControllerStdin {
        version: descriptor::controller_start::REGISTRY_VERSION,
    };
    assert!(Descriptor::parse(&serde_json::to_vec(&legacy).unwrap()).is_err());
    let ordinary = serde_json::to_value(descriptor()).unwrap();
    assert!(ordinary.get("provider_input_binding").is_none());
    let mut missing = valid.clone();
    missing.provider_input_binding = None;
    assert!(Descriptor::parse(&serde_json::to_vec(&missing).unwrap()).is_err());
    let mut unexpected = valid.clone();
    unexpected.provider_input_experiment = false;
    assert!(Descriptor::parse(&serde_json::to_vec(&unexpected).unwrap()).is_err());
    let mut changed = valid.clone();
    changed.provider_input_paths.swap(0, 1);
    assert!(Descriptor::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
    let mut oversized = valid;
    oversized.arguments = vec!["x".repeat(4096); 64];
    assert!(Descriptor::parse(&serde_json::to_vec(&oversized).unwrap()).is_err());

    use memcordon_platform::windows_private_fixture_binding::{DotLocalInput, PrivateFixtureFile};
    use sha2::Digest;
    let mut file = experiment_descriptor();
    let binding = file.provider_input_binding.as_mut().unwrap();
    let DotLocalInput::Directory(local) = &binding.local_input else {
        unreachable!()
    };
    let marker = PrivateFixtureFile {
        path: local.path.clone(),
        volume_serial: local.volume_serial,
        file_index: local.file_index,
        attributes: 0x20,
        links: 1,
        bytes: 0,
        sha256: hex::encode(sha2::Sha256::digest([])),
        native_path_utf16: r"\Device\Volume\private-fixture-inputs\fixture.exe.local"
            .encode_utf16()
            .collect(),
    };
    file.provider_input_paths = vec![
        binding.fixture.clone(),
        marker.path.clone(),
        binding.fixture.parent().unwrap().join("provider.dll"),
    ];
    binding.revision = 3;
    binding.local_input = DotLocalInput::File(marker);
    file.start_transport = descriptor::StartTransport::ControllerStdin {
        version: descriptor::controller_start::PRIVATE_FILE_VERSION,
    };
    let bytes = serde_json::to_vec(&file).unwrap();
    let parsed = Descriptor::parse(&bytes).unwrap();
    assert_eq!(parsed.provider_input_binding, file.provider_input_binding);
    let digest = descriptor::controller_start::descriptor_digest(&bytes);
    Descriptor::parse_authenticated_peer(
        &bytes,
        digest,
        &file.challenge,
        &file.output_root,
        file.control_clock.as_ref().unwrap(),
    )
    .unwrap();
    let mut downgraded = file.clone();
    downgraded.start_transport = descriptor::StartTransport::ControllerStdin {
        version: descriptor::controller_start::PRIVATE_VERSION,
    };
    assert!(Descriptor::parse(&serde_json::to_vec(&downgraded).unwrap()).is_err());
    let mut mixed = file;
    mixed.provider_input_binding.as_mut().unwrap().revision = 2;
    assert!(Descriptor::parse(&serde_json::to_vec(&mixed).unwrap()).is_err());
}

#[test]
fn peer_rehashes_exact_original_bytes_and_rejects_forwarded_context_substitution() {
    let input = experiment_descriptor();
    let bytes = serde_json::to_vec(&input).unwrap();
    let digest = descriptor::controller_start::descriptor_digest(&bytes);
    let clock = input.control_clock.as_ref().unwrap();
    let (parsed, fresh) = Descriptor::parse_authenticated_peer(
        &bytes,
        digest,
        &input.challenge,
        &input.output_root,
        clock,
    )
    .unwrap();
    assert_eq!(
        fresh,
        descriptor::controller_start::descriptor_digest(&bytes)
    );
    assert_eq!(parsed.provider_input_binding, input.provider_input_binding);
    assert_eq!(parsed.provider_input_paths, input.provider_input_paths);
    // Even identical parsed content must match the original exact bytes.
    let mut whitespace = bytes.clone();
    whitespace.push(b'\n');
    assert!(Descriptor::parse(&whitespace).is_ok());
    assert!(
        Descriptor::parse_authenticated_peer(
            &whitespace,
            digest,
            &input.challenge,
            &input.output_root,
            clock
        )
        .is_err()
    );
    let mut changed = input.clone();
    changed.provider_input_binding.as_mut().unwrap().file_index += 1;
    let forged_bytes = serde_json::to_vec(&changed).unwrap();
    let forged_digest = descriptor::controller_start::descriptor_digest(&forged_bytes);
    // A forged envelope can be internally consistent. It is still not the
    // descriptor authenticated by the controller's original root START.
    Descriptor::parse_authenticated_peer(
        &forged_bytes,
        forged_digest,
        &input.challenge,
        &input.output_root,
        clock,
    )
    .unwrap();
    let authentic_binding = descriptor::controller_start::Binding {
        challenge: input.challenge.clone(),
        descriptor_sha256: digest,
        pid: 77,
        birth: 88,
    };
    let registry = descriptor::controller_start::Capability {
        version: 1,
        handle: 0x320,
        manifest_sha256: input.winsock_registry.as_ref().unwrap().sha256,
    };
    let mut wire = Vec::new();
    descriptor::controller_start::Sender::with_registry(registry, false)
        .send(
            &mut wire,
            &authentic_binding,
            descriptor::controller_start::Phase::Start,
            || Ok(()),
        )
        .unwrap();
    let mut expected_forged = authentic_binding.clone();
    expected_forged.descriptor_sha256 = forged_digest;
    let mut receiver =
        descriptor::controller_start::Receiver::with_registry(registry.manifest_sha256, false);
    assert!(
        receiver
            .receive(
                &mut std::io::Cursor::new(&wire),
                &expected_forged,
                || Ok(())
            )
            .is_err()
    );
    assert!(receiver.registry_capability().is_none());
    let mut actual_receiver =
        descriptor::controller_start::Receiver::with_registry(registry.manifest_sha256, false);
    actual_receiver
        .receive(&mut std::io::Cursor::new(&wire), &authentic_binding, || {
            Ok(())
        })
        .unwrap();
    assert!(actual_receiver.registry_capability().is_some());
    assert!(
        Descriptor::parse_authenticated_peer(
            &forged_bytes,
            digest,
            &input.challenge,
            &input.output_root,
            clock
        )
        .is_err()
    );
    let mut wrong_clock = clock.clone();
    wrong_clock.work_cutoff_qpc += 1;
    for (challenge, output, clock) in [
        (
            &b"other challenge"[..],
            input.output_root.clone(),
            clock.clone(),
        ),
        (
            input.challenge.as_slice(),
            input.output_root.join("other"),
            clock.clone(),
        ),
        (
            input.challenge.as_slice(),
            input.output_root.clone(),
            wrong_clock,
        ),
    ] {
        assert!(
            Descriptor::parse_authenticated_peer(&bytes, digest, challenge, &output, &clock)
                .is_err()
        );
    }
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    assert!(
        Descriptor::parse_authenticated_peer(
            &bytes,
            wrong_digest,
            &input.challenge,
            &input.output_root,
            clock
        )
        .is_err()
    );
    let oversized = vec![b' '; descriptor::MAX_DESCRIPTOR_BYTES + 1];
    assert!(
        Descriptor::parse_authenticated_peer(
            &oversized,
            digest,
            &input.challenge,
            &input.output_root,
            clock
        )
        .is_err()
    );
}

#[test]
fn restricted_envelopes_select_framed_start_and_wire_requires_original_clock() {
    use descriptor::StartTransport;
    use memcordon_ci::windows_consumer_readiness::{
        CaseKey, TokenObservation, expected_start_transport, validate_descriptor,
    };
    let mut input = descriptor();
    input.case = Case::Envelope;
    input.toolchain = None;
    input.cohort_gate = None;
    input.generation_gate = None;
    for (family, scenario) in [
        ("W-ENVELOPE", "restricted"),
        ("W-BINDING", "restricted-token-preserved"),
    ] {
        let key = CaseKey {
            family: family.into(),
            scenario: scenario.into(),
        };
        input.start_transport = expected_start_transport(&key);
        assert_eq!(
            input.start_transport,
            StartTransport::ControllerStdin {
                version: descriptor::controller_start::VERSION
            }
        );
        validate_descriptor(&key, &input).unwrap(); // Declared plan, before clock preparation.
        assert!(Descriptor::parse(&serde_json::to_vec(&input).unwrap()).is_err());
        input.gate_precondition = Some(descriptor::gate_precondition::Input {
            revision: 1,
            work_cutoff_qpc: 999,
            qpc_frequency: 10,
            expected_token: TokenObservation {
                user_sid: vec![1],
                restricted: true,
                integrity_rid: 12288,
                elevated: true,
                restricting_sids: vec![vec![2]],
            },
        });
        input.control_clock = Some(descriptor::ControlClock {
            revision: 1,
            work_cutoff_qpc: 999,
            qpc_frequency: 10,
        });
        let bytes = serde_json::to_vec(&input).unwrap();
        Descriptor::parse(&bytes).unwrap();
        for (field, value) in [
            ("version", serde_json::json!(99)),
            ("transport", serde_json::json!("unknown")),
        ] {
            let mut value_descriptor = serde_json::to_value(&input).unwrap();
            value_descriptor["start_transport"][field] = value;
            assert!(Descriptor::parse(&serde_json::to_vec(&value_descriptor).unwrap()).is_err());
        }
        let text = String::from_utf8(bytes).unwrap();
        let duplicated = text.replacen(
            "\"start_transport\":",
            "\"start_transport\":{\"transport\":\"named-event\"},\"start_transport\":",
            1,
        );
        assert!(Descriptor::parse(duplicated.as_bytes()).is_err());
        let mut wrong = input.clone();
        wrong.start_transport = StartTransport::NamedEvent;
        assert!(validate_descriptor(&key, &wrong).is_err());
        input.gate_precondition = None;
        input.control_clock = None;
    }
    for (family, scenario) in [
        ("W-ENVELOPE", "ordinary"),
        ("C-IO", "empty-input"),
        ("W-BINDING", "ordinary"),
    ] {
        assert_eq!(
            expected_start_transport(&CaseKey {
                family: family.into(),
                scenario: scenario.into()
            }),
            StartTransport::NamedEvent
        );
    }
    let key = CaseKey {
        family: "W-ENVELOPE".into(),
        scenario: "restricted".into(),
    };
    input.stdout = vec![0; descriptor::MAX_STREAM_BYTES];
    input.stderr = vec![0; descriptor::MAX_STREAM_BYTES];
    input.arguments = vec!["R".repeat(4096); 16];
    assert!(input.validate().is_err());
    assert!(serde_json::to_vec(&input).unwrap().len() > descriptor::MAX_DESCRIPTOR_BYTES);
    assert!(validate_descriptor(&key, &input).is_err());
}

#[test]
fn compiler_creation_uses_the_exact_frozen_measured_executable_inventory() {
    let mut input = descriptor();
    input.validate().unwrap();
    let toolchain = input.toolchain.as_mut().unwrap();
    let root = toolchain.rustc.parent().unwrap().to_owned();
    let helper = root.join("compiler-helper.exe");
    let helper_digest = String::from(memcordon_core::DiagnosticSha256::from_bytes([9; 32]));
    let mut measured: Vec<_> = toolchain
        .selected_images
        .iter()
        .map(|image| (image.path.clone(), image.sha256.clone()))
        .collect();
    measured.push((helper.clone(), helper_digest.clone()));
    measured.push((root.join("library.rs"), helper_digest.clone()));
    let frozen = descriptor::project_toolchain_images(measured).unwrap();
    toolchain.selected_images = frozen.clone();
    validate_toolchain_inventory(toolchain, &frozen).unwrap();
    assert!(toolchain.admits_created_image(&helper, &helper_digest));
    let changed_digest = String::from(memcordon_core::DiagnosticSha256::from_bytes([10; 32]));
    assert!(!toolchain.admits_created_image(&helper, &changed_digest));
    assert!(!toolchain.admits_created_image(&root.join("foreign.exe"), &helper_digest));
    let mut omitted = frozen.clone();
    omitted.retain(|image| image.path != helper);
    assert!(validate_toolchain_inventory(toolchain, &omitted).is_err());
    let mut rehashed = frozen.clone();
    rehashed
        .iter_mut()
        .find(|image| image.path == helper)
        .unwrap()
        .sha256 = changed_digest;
    assert!(validate_toolchain_inventory(toolchain, &rehashed).is_err());
    let valid = toolchain.clone();
    for malformed in [
        Vec::new(),
        vec![frozen[0].clone(), frozen[0].clone()],
        frozen
            .iter()
            .filter(|image| image.path != valid.rustc)
            .cloned()
            .collect(),
        frozen
            .iter()
            .filter(|image| image.path != valid.native_linker)
            .cloned()
            .collect(),
    ] {
        toolchain.selected_images = malformed;
        assert!(toolchain.validate_selected_images().is_err());
    }
    toolchain.selected_images = frozen;
    toolchain.selected_images[0].sha256 = "invalid".into();
    assert!(toolchain.validate_selected_images().is_err());
    let overflow = (0..=descriptor::MAX_TOOLCHAIN_IMAGES).map(|index| {
        (
            root.join(index.to_string()).with_extension("exe"),
            helper_digest.clone(),
        )
    });
    assert!(descriptor::project_toolchain_images(overflow).is_err());
    assert!(
        descriptor::project_toolchain_images([(
            root.join("..").join("foreign.exe"),
            helper_digest.clone()
        ),])
        .is_err()
    );
}

#[test]
fn restricted_joint_keeps_native_compiler_observation_with_a_separate_control_clock() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseKey, expected_start_transport, needs_toolchain_observer, validate_descriptor,
    };
    let mut input = descriptor();
    input.case = Case::Joint;
    input.cohort_gate = None;
    input.generation_gate = None;
    let key = CaseKey {
        family: "W-JOINT".into(),
        scenario: "restricted".into(),
    };
    input.start_transport = expected_start_transport(&key);
    input.control_clock = Some(descriptor::ControlClock {
        revision: 1,
        work_cutoff_qpc: 999,
        qpc_frequency: 10,
    });
    assert!(input.gate_precondition.is_none());
    validate_descriptor(&key, &input).unwrap();
    let parsed = Descriptor::parse(&serde_json::to_vec(&input).unwrap()).unwrap();
    assert!(needs_toolchain_observer(parsed.case));
    assert!(
        memcordon_ci::windows_consumer_readiness::needs_descriptor_toolchain_observer(&parsed)
            .unwrap()
    );
    assert!(parsed.gate_precondition.is_none());
    for (field, value) in [
        ("revision", 2),
        ("work_cutoff_qpc", 0),
        ("qpc_frequency", 0),
    ] {
        let mut invalid = serde_json::to_value(&input).unwrap();
        invalid["control_clock"][field] = value.into();
        assert!(Descriptor::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    let mut missing = input.clone();
    missing.control_clock = None;
    assert!(Descriptor::parse(&serde_json::to_vec(&missing).unwrap()).is_err());
    let mut diagnostic = input.clone();
    diagnostic.gate_precondition = Some(descriptor::gate_precondition::Input {
        revision: 1,
        work_cutoff_qpc: 999,
        qpc_frequency: 10,
        expected_token: memcordon_ci::windows_consumer_readiness::TokenObservation {
            user_sid: vec![1],
            restricted: true,
            integrity_rid: 12288,
            elevated: true,
            restricting_sids: vec![vec![2]],
        },
    });
    assert!(Descriptor::parse(&serde_json::to_vec(&diagnostic).unwrap()).is_err());
    for case in [Case::Toolchain, Case::Joint, Case::Churn] {
        assert!(needs_toolchain_observer(case));
    }
    for case in [Case::Envelope, Case::EndpointMismatch, Case::EmptyInput] {
        assert!(!needs_toolchain_observer(case));
    }
    for (family, scenario) in [
        ("W-JOINT", "ordinary"),
        ("W-CHURN", "restricted"),
        ("W-JOINT", "endpoint-mismatch"),
    ] {
        assert_eq!(
            expected_start_transport(&CaseKey {
                family: family.into(),
                scenario: scenario.into()
            }),
            descriptor::StartTransport::NamedEvent
        );
    }
    let mut named = input.clone();
    named.start_transport = descriptor::StartTransport::NamedEvent;
    assert!(named.validate().is_err()); // A stdin clock is not another named authority.
}

#[test]
fn reduced_compiler_toolchain_keeps_its_sentinel_under_authenticated_stdin() {
    use descriptor::{StartTransport, ToolchainInputRoot, controller_start};
    use memcordon_ci::windows_consumer_readiness::{
        CaseKey, expected_start_transport, needs_descriptor_toolchain_observer, validate_descriptor,
    };
    let key = CaseKey {
        family: "W-TOOLCHAIN".into(),
        scenario: "group-privilege-reduced".into(),
    };
    let ordinary = CaseKey {
        family: key.family.clone(),
        scenario: "ordinary".into(),
    };
    let restricted = CaseKey {
        family: key.family.clone(),
        scenario: "restricted".into(),
    };
    let stdin = StartTransport::ControllerStdin {
        version: controller_start::VERSION,
    };
    assert_eq!(expected_start_transport(&key), stdin);
    assert_eq!(expected_start_transport(&restricted), stdin);
    assert_eq!(
        expected_start_transport(&ordinary),
        StartTransport::NamedEvent
    );

    let mut input = descriptor();
    input.case = Case::Toolchain;
    input.cohort_gate = None;
    input.generation_gate = None;
    let sentinel = input
        .output_root
        .parent()
        .unwrap()
        .join(descriptor::gate_precondition::REDUCED_COMPILER_SENTINEL);
    input.denied_write_paths = vec![sentinel.clone()];
    assert!(input.validate().is_err());

    input.start_transport = stdin;
    validate_descriptor(&key, &input).unwrap();
    assert!(Descriptor::parse(&serde_json::to_vec(&input).unwrap()).is_err());
    input.control_clock = Some(descriptor::ControlClock {
        revision: 1,
        work_cutoff_qpc: 999,
        qpc_frequency: 10,
    });
    let parsed = Descriptor::parse(&serde_json::to_vec(&input).unwrap()).unwrap();
    assert_eq!(parsed.reduced_compiler_sentinel(), Some(sentinel.as_path()));
    assert!(needs_descriptor_toolchain_observer(&parsed).unwrap());
    assert!(validate_descriptor(&restricted, &parsed).is_err());

    let mut omitted = parsed.clone();
    omitted.denied_write_paths.clear();
    assert!(validate_descriptor(&key, &omitted).is_err());
    let mut replaced = parsed.clone();
    replaced.denied_write_paths[0] = sentinel.with_file_name("other.bin");
    assert!(replaced.validate().is_err());
    input.toolchain.as_mut().unwrap().controller_input_root = Some(ToolchainInputRoot {
        volume_serial: 2,
        file_index: 3,
    });
    assert!(input.validate().is_err());
}

#[test]
fn restricted_standalone_toolchain_requires_bound_stdin_start_and_observer_release() {
    use descriptor::StartTransport;
    use descriptor::controller_start::{Binding, Phase, Receiver, Sender};
    use memcordon_ci::windows_consumer_readiness::{
        CaseKey, expected_start_transport, needs_descriptor_toolchain_observer,
        standalone_toolchain_ended_transcript, standalone_toolchain_observer_ready,
        validate_descriptor,
    };
    let mut key = CaseKey {
        family: "W-TOOLCHAIN".into(),
        scenario: "restricted".into(),
    };
    let mut input = descriptor();
    input.case = Case::Toolchain;
    input.cohort_gate = None;
    input.generation_gate = None;
    assert!(validate_descriptor(&key, &input).is_err());
    input.start_transport = expected_start_transport(&key);
    assert_eq!(
        input.start_transport,
        StartTransport::ControllerStdin {
            version: descriptor::controller_start::VERSION,
        }
    );
    assert!(Descriptor::parse(&serde_json::to_vec(&input).unwrap()).is_err());
    input.control_clock = Some(descriptor::ControlClock {
        revision: 1,
        work_cutoff_qpc: 999,
        qpc_frequency: 10,
    });
    let bytes = serde_json::to_vec(&input).unwrap();
    validate_descriptor(&key, &input).unwrap();
    assert!(needs_descriptor_toolchain_observer(&Descriptor::parse(&bytes).unwrap()).unwrap());
    let controller_root = descriptor::ToolchainInputRoot {
        volume_serial: 123,
        file_index: 456,
    };
    let mut scoped = input.clone();
    scoped.toolchain.as_mut().unwrap().controller_input_root = Some(controller_root);
    validate_descriptor(&key, &scoped).unwrap();
    let scoped_bytes = serde_json::to_vec(&scoped).unwrap();
    assert_eq!(
        Descriptor::parse(&scoped_bytes)
            .unwrap()
            .toolchain
            .unwrap()
            .controller_input_root,
        Some(controller_root)
    );
    key.scenario = "ordinary".into();
    assert!(validate_descriptor(&key, &input).is_err());
    assert!(validate_descriptor(&key, &scoped).is_err());
    assert_eq!(expected_start_transport(&key), StartTransport::NamedEvent);
    scoped.start_transport = StartTransport::NamedEvent;
    scoped.control_clock = None;
    assert!(scoped.validate().is_err());
    input.start_transport = StartTransport::NamedEvent;
    input.control_clock = None;
    validate_descriptor(&key, &input).unwrap();

    let binding = Binding {
        challenge: input.challenge,
        descriptor_sha256: descriptor::controller_start::descriptor_digest(&bytes),
        pid: 123,
        birth: 456,
    };
    let event = |sequence, stage, pid, value: &[u8]| {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "sequence":sequence,"stage":stage,"pid":pid,"ordinal":null,"value":value,
        }))
        .unwrap();
        let mut frame = u32::try_from(bytes.len()).unwrap().to_le_bytes().to_vec();
        frame.extend(bytes);
        frame
    };
    let start_event = event(0, "controller-released", binding.pid, &binding.challenge);
    let mut transcript = start_event.clone();
    assert!(!standalone_toolchain_observer_ready(&transcript, &binding, None).unwrap());
    let mut bad = transcript.clone();
    bad.extend(event(
        1,
        "toolchain-ready-for-native-observer",
        binding.pid + 1,
        &binding.challenge,
    ));
    assert!(standalone_toolchain_observer_ready(&bad, &binding, None).is_err());
    transcript.extend(event(
        1,
        "toolchain-ready-for-native-observer",
        binding.pid,
        &binding.challenge,
    ));
    assert!(
        !standalone_toolchain_observer_ready(&transcript[..transcript.len() - 1], &binding, None)
            .unwrap()
    );
    assert!(standalone_toolchain_observer_ready(&transcript, &binding, None).unwrap());
    assert!(
        standalone_toolchain_observer_ready(&transcript, &binding, Some(controller_root)).is_err()
    );
    transcript.extend(event(
        2,
        "toolchain-ready-for-native-observer",
        binding.pid,
        &binding.challenge,
    ));
    assert!(standalone_toolchain_observer_ready(&transcript, &binding, None).is_err());
    let scoped_binding = Binding {
        challenge: binding.challenge.clone(),
        descriptor_sha256: descriptor::controller_start::descriptor_digest(&scoped_bytes),
        pid: binding.pid,
        birth: binding.birth,
    };
    let bound_event = |value: &descriptor::ToolchainRootReady| {
        let mut transcript = start_event.clone();
        transcript.extend(event(
            1,
            "toolchain-ready-for-native-observer",
            binding.pid,
            &serde_json::to_vec(value).unwrap(),
        ));
        transcript
    };
    let ready = descriptor::ToolchainRootReady::from_start(controller_root, &scoped_binding);
    let ready_bytes = serde_json::to_vec(&ready).unwrap();
    let ended_frames = [
        event(0, "started", binding.pid, &binding.challenge),
        event(1, "native-argv-observed", binding.pid, b"argv"),
        event(2, "sentinel-handles-excluded", binding.pid, &[0; 4]),
        event(3, "token-envelope", binding.pid, b"token"),
        event(4, "controller-released", binding.pid, &binding.challenge),
        event(
            5,
            "toolchain-ready-for-native-observer",
            binding.pid,
            &ready_bytes,
        ),
    ];
    let ended = ended_frames.concat();
    let validate_end = |bytes: &[u8]| {
        standalone_toolchain_ended_transcript(bytes, &scoped_binding, controller_root)
    };
    assert!(validate_end(&ended).unwrap());
    assert!(validate_end(&ended[..ended.len() - 1]).is_err());
    assert!(!validate_end(&ended_frames[..5].concat()).unwrap());
    let mut changed = ended_frames.clone();
    changed[0] = event(0, "started", binding.pid, b"other challenge");
    assert!(!validate_end(&changed.concat()).unwrap());
    changed[0] = ended_frames[0].clone();
    changed[3] = event(3, "token-envelope", binding.pid + 1, b"token");
    assert!(!validate_end(&changed.concat()).unwrap());
    let mut completed = ended.clone();
    completed.extend(event(
        6,
        "toolchain-test-child-dll-complete",
        binding.pid,
        &binding.challenge,
    ));
    assert!(!validate_end(&completed).unwrap());
    let mut duplicate = ended;
    duplicate.extend(event(
        6,
        "toolchain-ready-for-native-observer",
        binding.pid,
        &ready_bytes,
    ));
    assert!(!validate_end(&duplicate).unwrap());
    let transcript = bound_event(&ready);
    assert!(
        standalone_toolchain_observer_ready(&transcript, &scoped_binding, Some(controller_root))
            .unwrap()
    );
    assert!(
        standalone_toolchain_observer_ready(&transcript, &binding, Some(controller_root)).is_err()
    );
    assert!(standalone_toolchain_observer_ready(&transcript, &binding, None).is_err());
    let mismatches: [fn(&mut descriptor::ToolchainRootReady); 6] = [
        |proof| proof.input_root.volume_serial ^= 1,
        |proof| proof.input_root.file_index ^= 1,
        |proof| proof.descriptor_sha256[0] ^= 1,
        |proof| proof.challenge_sha256[0] ^= 1,
        |proof| proof.pid ^= 1,
        |proof| proof.birth ^= 1,
    ];
    for mismatch in mismatches {
        let mut proof =
            descriptor::ToolchainRootReady::from_start(controller_root, &scoped_binding);
        mismatch(&mut proof);
        let mut changed = ended_frames.clone();
        changed[5] = event(
            5,
            "toolchain-ready-for-native-observer",
            binding.pid,
            &serde_json::to_vec(&proof).unwrap(),
        );
        assert!(validate_end(&changed.concat()).is_err());
        assert!(
            standalone_toolchain_observer_ready(
                &bound_event(&proof),
                &scoped_binding,
                Some(controller_root)
            )
            .is_err()
        );
    }

    let mut sender = Sender::joint();
    let mut start = Vec::new();
    sender
        .send(&mut start, &binding, Phase::Start, || Ok(()))
        .unwrap();
    assert!(!sender.completed());
    let mut release = Vec::new();
    sender
        .send(
            &mut release,
            &binding,
            Phase::ToolchainObserverRelease,
            || Ok(()),
        )
        .unwrap();
    assert!(sender.completed());
    for (frame, expected) in [(release.as_slice(), true), (&[][..], false)] {
        let mut receiver = Receiver::joint();
        receiver
            .receive(&mut std::io::Cursor::new(&start), &binding, || Ok(()))
            .unwrap();
        assert_eq!(
            receiver
                .receive_phase(
                    &mut std::io::Cursor::new(frame),
                    &binding,
                    Phase::ToolchainObserverRelease,
                    || Ok(())
                )
                .is_ok(),
            expected
        );
    }
}

#[test]
fn explicit_listener_prefix_omits_compiler_observation_without_relaxing_joint_inputs() {
    use memcordon_ci::windows_consumer_readiness::needs_descriptor_toolchain_observer;
    let (_, mut input) = matched_clock_input();
    input.case = Case::Joint;
    input.matched_control.as_mut().unwrap().scope = descriptor::matched::Scope::JointListenerPrefix;
    input.winsock_registry = Some(descriptor::winsock_registry::Declaration {
        version: descriptor::winsock_registry::VERSION,
        view: descriptor::winsock_registry::View::Native,
        sha256: [3; 32],
    });
    input.start_transport = descriptor::StartTransport::ControllerStdin {
        version: descriptor::controller_start::REGISTRY_VERSION,
    };
    input.toolchain = None;
    assert!(!needs_descriptor_toolchain_observer(&input).unwrap());
    let mut malformed = input.clone();
    malformed.control_clock = None;
    assert!(needs_descriptor_toolchain_observer(&malformed).is_err());
    for case in [Case::Toolchain, Case::Joint, Case::Churn] {
        let mut ordinary = descriptor();
        ordinary.case = case;
        assert!(needs_descriptor_toolchain_observer(&ordinary).unwrap());
        ordinary.toolchain = None;
        assert!(needs_descriptor_toolchain_observer(&ordinary).is_err());
    }
}

#[test]
fn explicit_native_registry_dependency_requires_bound_version_three_joint_control() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseKey, expected_start_transport, fixture_parameters, needs_registry_input,
        validate_descriptor,
    };
    let rows = [
        (Case::Joint, "C-IO", "empty-message"),
        (Case::Joint, "W-IO", "empty-message"),
        (Case::Joint, "W-JOINT", "ordinary"),
        (Case::Joint, "W-JOINT", "restricted"),
        (Case::EndpointMismatch, "W-JOINT", "endpoint-mismatch"),
        (Case::Churn, "W-CHURN", "natural-4096-three-generations"),
    ];
    let eligible = positive_keys()
        .into_iter()
        .filter(|key| needs_registry_input(key, fixture_parameters(key).unwrap().case))
        .collect::<std::collections::BTreeSet<_>>();
    let intended = rows
        .iter()
        .map(|(_, family, scenario)| CaseKey {
            family: (*family).into(),
            scenario: (*scenario).into(),
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(eligible, intended);
    for (case, family, scenario) in rows {
        let mut input = descriptor();
        input.case = case;
        if case != Case::Churn {
            input.cohort_gate = None;
            input.generation_gate = None;
        }
        let key = CaseKey {
            family: family.into(),
            scenario: scenario.into(),
        };
        input.start_transport = expected_start_transport(&key);
        validate_descriptor(&key, &input).unwrap(); // Original unprepared plan.
        assert!(needs_registry_input(&key, case));
        input.start_transport = descriptor::StartTransport::ControllerStdin {
            version: descriptor::controller_start::REGISTRY_VERSION,
        };
        input.winsock_registry = Some(descriptor::winsock_registry::Declaration {
            version: descriptor::winsock_registry::VERSION,
            view: descriptor::winsock_registry::View::Native,
            sha256: [42; 32],
        });
        validate_descriptor(&key, &input).unwrap(); // Explicit prepared plan.
        assert!(Descriptor::parse(&serde_json::to_vec(&input).unwrap()).is_err());
        input.control_clock = Some(descriptor::ControlClock {
            revision: 1,
            work_cutoff_qpc: 999,
            qpc_frequency: 10,
        });
        validate_descriptor(&key, &input).unwrap();
        Descriptor::parse(&serde_json::to_vec(&input).unwrap()).unwrap();
        let foreign = CaseKey {
            family: "W-BINDING".into(),
            scenario: "restricted-token-preserved".into(),
        };
        assert!(validate_descriptor(&foreign, &input).is_err());
        for (family, scenario, claimed) in [
            ("W-JOINT", "not-in-the-positive-catalog", Case::Joint),
            ("W-CHURN", "not-in-the-positive-catalog", Case::Churn),
        ] {
            let unknown = CaseKey {
                family: family.into(),
                scenario: scenario.into(),
            };
            assert!(!needs_registry_input(&unknown, claimed));
            assert!(validate_descriptor(&unknown, &input).is_err());
        }
        for other in [Case::Joint, Case::EndpointMismatch, Case::Churn] {
            if other == case {
                continue;
            }
            let mut substituted = input.clone();
            substituted.case = other;
            if other == Case::Churn {
                let churn = descriptor();
                substituted.cohort_gate = churn.cohort_gate;
                substituted.generation_gate = churn.generation_gate;
            } else {
                substituted.cohort_gate = None;
                substituted.generation_gate = None;
            }
            // Wire has no case key: a structurally valid registry kind is not
            // sufficient for admission under a different catalog key.
            Descriptor::parse(&serde_json::to_vec(&substituted).unwrap()).unwrap();
            assert!(!needs_registry_input(&key, other));
            assert!(validate_descriptor(&key, &substituted).is_err());
        }
        for mutation in 0..4 {
            let mut bad = input.clone();
            match mutation {
                0 => bad.start_transport = descriptor::StartTransport::NamedEvent,
                1 => {
                    bad.start_transport = descriptor::StartTransport::ControllerStdin {
                        version: descriptor::controller_start::VERSION,
                    }
                }
                2 => bad.winsock_registry.as_mut().unwrap().version = 3,
                3 => bad.case = Case::Envelope,
                _ => unreachable!(),
            }
            assert!(validate_descriptor(&key, &bad).is_err());
            assert!(Descriptor::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
    }
}

#[test]
fn separate_loader_command_selects_only_the_restricted_envelope_route() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseInput, CaseKey, TokenObservation, installed_support_loader_command,
        support_loader_command,
    };
    let root = std::env::temp_dir().join("support-loader-argv-oracle");
    let mut descriptor = descriptor();
    descriptor.case = Case::Envelope;
    let mut case = CaseInput {
        key: CaseKey {
            family: "W-ENVELOPE".into(),
            scenario: "restricted".into(),
        },
        descriptor,
        descriptor_path: root.join("input.json"),
        workload_request: root.join("request.json"),
        expected_token: TokenObservation {
            user_sid: vec![1],
            restricted: true,
            integrity_rid: 12288,
            elevated: true,
            restricting_sids: vec![vec![2]],
        },
    };
    case.descriptor.gate_precondition = Some(
        memcordon_ci::windows_consumer_readiness::descriptor::gate_precondition::Input {
            revision: 1,
            expected_token: case.expected_token.clone(),
            work_cutoff_qpc: 1,
            qpc_frequency: 1,
        },
    );
    let controlled = memcordon_ci::windows_consumer_readiness::public_command(
        &root.join("measured-cli.exe"),
        &root.join("measured-wrapper.exe"),
        &root,
        &root.join("result.json"),
        &case,
    )
    .unwrap()
    .materialize()
    .unwrap();
    let controlled_args: Vec<_> = controlled
        .get_args()
        .map(std::ffi::OsStr::to_owned)
        .collect();
    assert!(controlled_args.starts_with(&[
        "consumer-readiness-windows".into(),
        "system-restricted-gate-control-frontend".into(),
        case.descriptor_path.clone().into_os_string(),
        root.join("measured-cli.exe").into_os_string(),
    ]));
    let build = |case: &CaseInput, installed: bool| {
        let builder = if installed {
            installed_support_loader_command
        } else {
            support_loader_command
        };
        builder(
            &root.join("measured-cli.exe"),
            &root.join("measured-wrapper.exe"),
            &root,
            &root.join("result.json"),
            case,
            &root.join("selection.json"),
            &root.join("observation.json"),
        )
    };
    let command = build(&case, false).unwrap().materialize().unwrap();
    let args: Vec<_> = command.get_args().map(std::ffi::OsStr::to_owned).collect();
    assert_eq!(command.get_program(), root.join("measured-wrapper.exe"));
    assert!(args.starts_with(&[
        "consumer-readiness-windows".into(),
        "restricted-frontend".into(),
        root.join("measured-cli.exe").into_os_string(),
        "__windows-loader-diagnostic".into(),
        root.join("selection.json").into_os_string(),
        root.join("observation.json").into_os_string()
    ]));
    assert!(!args.iter().any(|arg| arg == "__windows-certification"));
    let installed = build(&case, true).unwrap().materialize().unwrap();
    assert_eq!(installed.get_program(), command.get_program());
    assert_eq!(installed.get_current_dir(), command.get_current_dir());
    let installed_args: Vec<_> = installed
        .get_args()
        .map(std::ffi::OsStr::to_owned)
        .collect();
    let mut expected_installed = args.clone();
    let route = expected_installed
        .iter_mut()
        .find(|arg| *arg == "restricted-frontend")
        .unwrap();
    *route = "system-restricted-frontend".into();
    assert_eq!(installed_args, expected_installed);
    assert!(installed_args.ends_with(&[
        root.join("measured-wrapper.exe").into_os_string(),
        "consumer-readiness-windows".into(),
        case.descriptor_path.clone().into_os_string()
    ]));
    for field in ["scenario", "restricted", "workload", "arguments"] {
        let original = case.clone();
        match field {
            "scenario" => case.key.scenario = "ordinary".into(),
            "restricted" => case.expected_token.restricted = false,
            "workload" => case.descriptor.case = Case::Churn,
            "arguments" => case.descriptor.arguments.push("foreign".into()),
            _ => unreachable!(),
        }
        for installed in [false, true] {
            assert!(
                build(&case, installed).is_err(),
                "accepted {field}, installed={installed}"
            );
        }
        case = original;
    }
}

#[test]
fn workload_cannot_narrow_churn_or_hide_invalid_native_argv() {
    let valid = descriptor();
    valid.validate().unwrap();
    let mut missing_toolchain = valid.clone();
    missing_toolchain.toolchain = None;
    assert!(missing_toolchain.validate().is_err());
    let mut missing_cutoff = valid.clone();
    missing_cutoff
        .toolchain
        .as_mut()
        .unwrap()
        .native_work_cutoff_ticks = 0;
    assert!(missing_cutoff.validate().is_err());
    let mut insufficient = valid.clone();
    insufficient.churn_creations = 4095;
    assert!(insufficient.validate().is_err());
    let mut excessive_live = valid.clone();
    excessive_live.churn_live = 64;
    assert!(excessive_live.validate().is_err());
    let mut missing_barrier = valid.clone();
    missing_barrier.cohort_gate = None;
    assert!(missing_barrier.validate().is_err());
    let mut native_nul = valid.clone();
    native_nul.arguments.push("before\0after".into());
    assert!(native_nul.validate().is_err());
    let mut traversal = valid;
    traversal.output_root = traversal.output_root.join("..");
    assert!(traversal.validate().is_err());
}

#[test]
fn fixture_descriptor_rejects_duplicate_and_unknown_fields() {
    let bytes = serde_json::to_string(&descriptor()).unwrap();
    let duplicate = bytes.replacen('{', "{\"revision\":1,", 1);
    assert!(serde_json::from_str::<Descriptor>(&duplicate).is_err());
    let unknown = bytes.replacen('{', "{\"pretend_success\":true,", 1);
    assert!(serde_json::from_str::<Descriptor>(&unknown).is_err());
}

#[test]
fn production_fixture_vectors_fit_the_private_wire_bound_and_round_trip_exactly() {
    use memcordon_ci::windows_consumer_readiness::{fixture_parameters, validate_descriptor};
    let mut full_stream_cases = 0;
    let mut backpressure_cases = 0;
    for key in positive_keys() {
        let parameters = fixture_parameters(&key).unwrap();
        let mut input = descriptor();
        input.case = parameters.case;
        input.stdout = parameters.stdout;
        input.stderr = parameters.stderr;
        input.arguments = parameters.arguments;
        input.application_status = parameters.application_status;
        input.start_transport =
            memcordon_ci::windows_consumer_readiness::expected_start_transport(&key);
        if matches!(
            input.start_transport,
            descriptor::StartTransport::ControllerStdin { .. }
        ) || input.case == Case::Envelope
        {
            input.control_clock = Some(descriptor::ControlClock {
                revision: 1,
                work_cutoff_qpc: 999,
                qpc_frequency: 10,
            });
        }
        if matches!(
            (key.family.as_str(), key.scenario.as_str()),
            ("W-ENVELOPE", "restricted") | ("W-BINDING", "restricted-token-preserved")
        ) {
            input.gate_precondition = Some(descriptor::gate_precondition::Input {
                revision: 1,
                work_cutoff_qpc: 999,
                qpc_frequency: 10,
                expected_token: memcordon_ci::windows_consumer_readiness::TokenObservation {
                    user_sid: vec![1],
                    restricted: true,
                    integrity_rid: 12288,
                    elevated: true,
                    restricting_sids: vec![vec![2]],
                },
            });
        }
        if matches!(input.case, Case::RootFirst | Case::IntermediateFirst) {
            input.descendant_gate = Some("Local\\memcordon-readiness-portable-descendant".into());
        }
        if (key.family.as_str(), key.scenario.as_str())
            == ("W-TOOLCHAIN", "group-privilege-reduced")
        {
            input.denied_write_paths = vec![
                input
                    .output_root
                    .parent()
                    .unwrap()
                    .join(descriptor::gate_precondition::REDUCED_COMPILER_SENTINEL),
            ];
        }
        validate_descriptor(&key, &input).unwrap();
        let bytes = serde_json::to_vec(&input).unwrap();
        assert!(bytes.len() <= descriptor::MAX_DESCRIPTOR_BYTES, "{key:?}");
        let parsed = Descriptor::parse(&bytes).unwrap();
        assert_eq!(parsed.stdout, input.stdout, "{key:?}");
        assert_eq!(parsed.stderr, input.stderr, "{key:?}");
        assert_eq!(parsed.arguments, input.arguments, "{key:?}");
        assert_eq!(parsed.application_status, input.application_status);
        if (key.family == "C-IO" && key.scenario == "bounded-large-output")
            || (key.family == "W-RETIREMENT" && key.scenario == "output-backpressure")
        {
            assert_eq!(parsed.stdout.len(), descriptor::MAX_STREAM_BYTES);
            assert_eq!(parsed.stderr.len(), descriptor::MAX_STREAM_BYTES);
            assert_ne!(parsed.stdout, parsed.stderr);
            full_stream_cases += 1;
        }
        if key.family == "W-IO" && key.scenario == "backpressure-separated-streams" {
            assert_eq!(parsed.stdout.len(), 8192);
            assert_eq!(parsed.stderr.len(), 8192);
            assert_ne!(parsed.stdout, parsed.stderr);
            backpressure_cases += 1;
        }
    }
    assert_eq!(full_stream_cases, 2);
    assert_eq!(backpressure_cases, 1);
}

#[test]
fn compact_stream_codec_preserves_binary_empty_and_maximum_bytes() {
    for bytes in [
        Vec::new(),
        vec![0, 255, 128, 1],
        (0..=255).collect(),
        vec![255; descriptor::MAX_STREAM_BYTES],
    ] {
        let mut input = descriptor();
        input.stdout = bytes.clone();
        input.stderr = bytes.clone();
        let wire = serde_json::to_vec(&input).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        assert!(json["stdout_base64"].is_string());
        assert!(json.get("stdout").is_none());
        let parsed = Descriptor::parse(&wire).unwrap();
        assert_eq!(parsed.stdout, bytes);
        assert_eq!(parsed.stderr, bytes);
    }
}

#[test]
fn stream_encoding_rejects_noncanonical_and_over_limit_input_before_admission() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let valid = serde_json::to_value(descriptor()).unwrap();
    for field in ["stdout_base64", "stderr_base64"] {
        for encoded in [
            "@AAA", "Zg", "Zg=", "Zg===", "Zh==", "Zm9=", "AAAA\n", "====", "A===",
        ] {
            let mut changed = valid.clone();
            changed[field] = encoded.into();
            assert!(
                serde_json::from_value::<Descriptor>(changed).is_err(),
                "{field}: {encoded:?}"
            );
        }
        let mut changed = valid.clone();
        changed[field] = STANDARD
            .encode(vec![0; descriptor::MAX_STREAM_BYTES + 1])
            .into();
        assert!(serde_json::from_value::<Descriptor>(changed).is_err());
    }
    for stdout in [true, false] {
        let mut input = descriptor();
        if stdout {
            input.stdout.resize(descriptor::MAX_STREAM_BYTES + 1, 0);
        } else {
            input.stderr.resize(descriptor::MAX_STREAM_BYTES + 1, 0);
        }
        assert!(serde_json::to_vec(&input).is_err());
        assert!(input.validate().is_err());
    }
    let mut old = valid.clone();
    old["revision"] = 1.into();
    assert!(Descriptor::parse(&serde_json::to_vec(&old).unwrap()).is_err());
    let mut unknown = valid;
    unknown["stdout"] = serde_json::json!([]);
    assert!(serde_json::from_value::<Descriptor>(unknown).is_err());
    let wire = serde_json::to_string(&descriptor()).unwrap();
    let duplicate = format!(
        "{{\"stdout_base64\":\"\",{}",
        wire.strip_prefix('{').unwrap()
    );
    assert!(Descriptor::parse(duplicate.as_bytes()).is_err());
}

#[test]
fn compact_streams_do_not_relax_the_aggregate_descriptor_bound() {
    use memcordon_ci::windows_consumer_readiness::{CaseKey, validate_descriptor};
    let mut input = descriptor();
    input.arguments = vec!["x".repeat(4096); 16];
    let wire = serde_json::to_vec(&input).unwrap();
    assert!(wire.len() > descriptor::MAX_DESCRIPTOR_BYTES);
    assert!(Descriptor::parse(&wire).is_err());
    assert!(input.validate().is_err());
    let key = CaseKey {
        family: "C-IO".into(),
        scenario: "bounded-large-output".into(),
    };
    let error = validate_descriptor(&key, &input).unwrap_err().to_string();
    assert!(error.contains("C-IO/bounded-large-output"));
    assert!(error.contains(&format!("encoded-bytes={}", wire.len())));
    assert!(error.contains(&format!("limit={}", descriptor::MAX_DESCRIPTOR_BYTES)));
}

// Portable metadata fixtures exercise report consistency, not native execution.
fn complete_case_assessments() -> Vec<CaseAssessment> {
    let measured = "a".repeat(64);
    positive_keys()
        .into_iter()
        .enumerate()
        .map(|(index, key)| CaseAssessment {
            revision: CASE_ASSESSMENT_REVISION,
            key,
            contract: {
                use memcordon_ci::windows_readiness_policy::*;
                use memcordon_core::execution_facts::{
                    NativeProcessV2, ProviderAttemptAssociationV1,
                };
                use memcordon_core::{BoundedText, DiagnosticSha256, PublicProviderBindingV1};
                let digest = DiagnosticSha256::from_bytes([0xaa; 32]);
                CaseContract {
                    intrinsic: IntrinsicContract::Validated,
                    comparison: ComparisonStatus::NotMeasured,
                    execution: ExecutionDisposition::Completed,
                    evidence: Some(ExecutionEvidence {
                        association: ProviderAttemptAssociationV1 {
                            provider: PublicProviderBindingV1 {
                                generation: BoundedText::new("fixture").unwrap(),
                                source_commit: BoundedText::new(&"ab".repeat(20)).unwrap(),
                                runtime_manifest_sha256: digest.clone(),
                            },
                            attempt_id: DiagnosticSha256::from_bytes([index as u8 + 1; 32]),
                            request_sha256: DiagnosticSha256::from_bytes([0xbb; 32]),
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
                        terminal_observation_sha256: digest,
                    }),
                }
            },
            behavior: Ok(()),
            collection: Ok(()),
            retirement: Ok(()),
            descriptor_sha256: measured.clone(),
            result_sha256: Some(measured.clone()),
            stdout_sha256: Some(measured.clone()),
            stderr_sha256: Some(measured.clone()),
            transcript_sha256: Some(measured.clone()),
            request_sha256: Some(measured.clone()),
            provider_request_sha256: Some("bb".repeat(32)),
            terminal_observation_sha256: Some(measured.clone()),
        })
        .collect()
}

#[test]
fn required_windows_rows_and_terminal_custody_cannot_be_omitted() {
    let suite = SuiteInput {
        format: "memcordon.windows-readiness-input".into(),
        revision: 2,
        cases: Vec::new(),
    };
    assert!(validate_suite(&suite).is_err());
    let mut records = complete_case_assessments();
    assert!(accepted(&records));
    records[0].terminal_observation_sha256 = None;
    assert!(!accepted(&records));
    records[0].terminal_observation_sha256 = Some("a".repeat(64));
    records.pop();
    assert!(!accepted(&records));
}

#[test]
fn provider_provisioning_accepts_only_its_requested_full_joint_row() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseInput, CaseKey, TokenObservation, expected_start_transport, fixture_parameters,
        provider_joint_input,
    };
    for scenario in ["ordinary", "restricted"] {
        let key = CaseKey {
            family: "W-JOINT".into(),
            scenario: scenario.into(),
        };
        let expected = fixture_parameters(&key).unwrap();
        let mut descriptor = descriptor();
        descriptor.case = expected.case;
        descriptor.start_transport = expected_start_transport(&key);
        descriptor.stdout = expected.stdout;
        descriptor.stderr = expected.stderr;
        descriptor.arguments = expected.arguments;
        descriptor.application_status = expected.application_status;
        descriptor.cohort_gate = None;
        descriptor.generation_gate = None;
        if scenario == "restricted" {
            descriptor.denied_write_paths = ["driver", "provider"]
                .map(|name| descriptor.output_root.join(name))
                .to_vec();
        }
        let case = CaseInput {
            descriptor_path: descriptor.output_root.join("input.json"),
            workload_request: descriptor.output_root.join("request.json"),
            descriptor,
            key: key.clone(),
            expected_token: TokenObservation {
                user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
                restricted: scenario == "restricted",
                integrity_rid: 8192,
                elevated: false,
                restricting_sids: if scenario == "restricted" {
                    vec![vec![1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]]
                } else {
                    Vec::new()
                },
            },
        };
        let suite = SuiteInput {
            format: "memcordon.windows-readiness-input".into(),
            revision: 2,
            cases: vec![case.clone()],
        };
        assert_eq!(
            provider_joint_input(suite.clone(), scenario).unwrap().key,
            key
        );
        assert!(validate_suite(&suite).is_err());
        assert!(provider_joint_input(suite.clone(), "endpoint-mismatch").is_err());
        let mut invalid = suite.clone();
        invalid.cases.push(case.clone());
        assert!(provider_joint_input(invalid, scenario).is_err());
        let mut invalid = suite.clone();
        invalid.cases[0].descriptor.toolchain = None;
        assert!(provider_joint_input(invalid, scenario).is_err());
        let mut invalid = suite;
        invalid.cases[0].expected_token.restricted = scenario != "restricted";
        assert!(provider_joint_input(invalid, scenario).is_err());
    }
}

#[test]
fn later_finalization_failure_invalidates_the_row_without_erasing_measured_outcome() {
    use memcordon_ci::CiError;
    use memcordon_ci::windows_consumer_readiness::finalize_case_attempt;
    use memcordon_ci::windows_readiness_policy::{
        CaseContract, ExecutionDisposition, IntrinsicContract,
    };
    let mut rows = complete_case_assessments();
    let evidence = rows[0].contract.evidence.clone();
    let measured_hash = rows[0].result_sha256.clone();
    let error = finalize_case_attempt(
        &mut rows[0],
        Err(CiError::Message(
            "owned registry finalization failed".into(),
        )),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("owned registry finalization failed")
    );
    assert_eq!(rows[0].contract.intrinsic, IntrinsicContract::Invalid);
    assert_eq!(rows[0].contract.execution, ExecutionDisposition::Completed);
    assert_eq!(rows[0].contract.evidence, evidence);
    assert_eq!(rows[0].result_sha256, measured_hash);
    assert!(rows[0].behavior.is_err());
    assert!(!accepted(&rows));

    rows[1].contract = CaseContract::not_run();
    let untouched = rows[1].contract.clone();
    rows[0].contract.execution = ExecutionDisposition::OriginalListenerRefusal {
        raw_os_error: 12345,
    };
    let primary = CiError::LaneFailures {
        primary: Box::new(CiError::Message("actual execution failure".into())),
        secondary: Box::new(CiError::Message("actual cleanup failure".into())),
    };
    let error = finalize_case_attempt(&mut rows[0], Err(primary)).unwrap_err();
    assert!(matches!(error, CiError::LaneFailures { .. }));
    assert_eq!(
        rows[0].contract.execution,
        ExecutionDisposition::OriginalListenerRefusal {
            raw_os_error: 12345
        }
    );
    assert_eq!(rows[1].contract, untouched);
    assert_eq!(rows[1].contract.execution, ExecutionDisposition::NotRun);

    finalize_case_attempt(
        &mut rows[1],
        Err(CiError::Message(
            "setup failed before a validated observation".into(),
        )),
    )
    .unwrap_err();
    assert_eq!(rows[1].contract.intrinsic, IntrinsicContract::Invalid);
    assert_eq!(
        rows[1].contract.execution,
        ExecutionDisposition::Unvalidated
    );
}

#[derive(Debug)]
struct RegistryLifetimeModel {
    owner: u64,
    live: bool,
    sealed: bool,
    work_live: bool,
    cleanup_live: bool,
    recipient_debt: usize,
    retirements: usize,
    cleanup_attempts: usize,
}

impl RegistryLifetimeModel {
    fn new() -> Self {
        Self {
            owner: 41,
            live: true,
            sealed: true,
            work_live: true,
            cleanup_live: true,
            recipient_debt: 0,
            retirements: 0,
            cleanup_attempts: 0,
        }
    }

    fn verify_owned(&self, expected: u64) -> memcordon_ci::Result<()> {
        if !self.work_live || !self.live || !self.sealed || self.owner != expected {
            return Err(memcordon_ci::CiError::Message(
                "original registry owner or seal unavailable".into(),
            ));
        }
        Ok(())
    }

    fn retire(&mut self) -> memcordon_ci::Result<()> {
        self.cleanup_attempts += 1;
        if self.recipient_debt != 0 {
            return Err(memcordon_ci::CiError::Message(
                "original registry recipient remains unproved".into(),
            ));
        }
        if self.retirements != 0 {
            return Ok(());
        }
        if !self.cleanup_live || !self.live || self.owner != 41 {
            return Err(memcordon_ci::CiError::Message(
                "original held cleanup owner or cleanup budget invalid".into(),
            ));
        }
        self.live = false;
        self.retirements += 1;
        Ok(())
    }

    fn finish(
        &mut self,
        owner: u64,
        lifetime: memcordon_ci::windows_consumer_readiness::RegistryProjectionLifetime,
    ) -> memcordon_ci::Result<()> {
        // Use the actual production choice between work-phase verification
        // and cleanup-budget retirement. This is not native registry evidence.
        lifetime.finish_execution(
            self,
            |projection| projection.verify_owned(owner),
            |projection| projection.retire(),
        )
    }
}

#[test]
fn borrowed_registry_survives_sequential_root_and_joint_until_its_original_owner_retires() {
    use memcordon_ci::windows_consumer_readiness::RegistryProjectionLifetime::ExperimentBorrowed;
    let mut projection = RegistryLifetimeModel::new();
    for _lane in ["root-control", "original-joint"] {
        projection.verify_owned(41).unwrap();
        projection.recipient_debt += 1;
        assert!(projection.retire().is_err());
        projection.recipient_debt -= 1;
        projection.finish(41, ExperimentBorrowed).unwrap();
        projection.verify_owned(41).unwrap();
        assert_eq!(projection.retirements, 0);
    }
    projection.retire().unwrap();
    assert_eq!(projection.retirements, 1);
    assert!(!projection.live);
    projection.retire().unwrap();
    assert_eq!(projection.retirements, 1);
}

#[test]
fn execution_owned_registry_cleanup_outlives_work_validation_without_masking_cleanup_errors() {
    use memcordon_ci::windows_consumer_readiness::RegistryProjectionLifetime::{
        ExecutionOwned, ExperimentBorrowed,
    };
    for failed_work in ["expired", "invalid-seal"] {
        let mut projection = RegistryLifetimeModel::new();
        if failed_work == "expired" {
            projection.work_live = false;
        } else {
            projection.sealed = false;
        }
        assert!(projection.verify_owned(41).is_err());
        assert!(projection.finish(41, ExperimentBorrowed).is_err());
        assert_eq!(projection.cleanup_attempts, 0);
        projection.finish(41, ExecutionOwned).unwrap();
        assert_eq!(projection.cleanup_attempts, 1);
        assert_eq!(projection.retirements, 1);
        assert!(!projection.live);
    }
    for cleanup_failure in ["expired-cleanup", "wrong-owner", "recipient-debt"] {
        let mut projection = RegistryLifetimeModel::new();
        projection.work_live = false;
        match cleanup_failure {
            "expired-cleanup" => projection.cleanup_live = false,
            "wrong-owner" => projection.owner = 42,
            "recipient-debt" => projection.recipient_debt = 1,
            _ => unreachable!(),
        }
        assert!(
            projection.finish(41, ExecutionOwned).is_err(),
            "{cleanup_failure}"
        );
        assert_eq!(projection.cleanup_attempts, 1);
        assert_eq!(projection.retirements, 0);
        assert!(projection.live);
    }
}

#[test]
fn execution_owned_registry_still_retires_for_ordinary_and_matched_owners() {
    use memcordon_ci::windows_consumer_readiness::RegistryProjectionLifetime::ExecutionOwned;
    for _owner in ["ordinary-execution", "matched-execution"] {
        let mut projection = RegistryLifetimeModel::new();
        projection.recipient_debt = 1;
        assert!(projection.finish(41, ExecutionOwned).is_err());
        assert!(projection.live);
        assert_eq!(projection.retirements, 0);
        projection.recipient_debt = 0;
        projection.finish(41, ExecutionOwned).unwrap();
        assert!(!projection.live);
        assert_eq!(projection.retirements, 1);
    }
}

#[test]
fn borrowing_never_repairs_deleted_unsealed_wrong_owner_or_new_recipient_debt() {
    use memcordon_ci::windows_consumer_readiness::RegistryProjectionLifetime::{
        ExecutionOwned, ExperimentBorrowed,
    };
    for fault in ["deleted", "unsealed", "wrong-owner"] {
        let mut projection = RegistryLifetimeModel::new();
        match fault {
            "deleted" => projection.live = false,
            "unsealed" => projection.sealed = false,
            "wrong-owner" => projection.owner += 1,
            _ => unreachable!(),
        }
        assert!(
            projection.finish(41, ExperimentBorrowed).is_err(),
            "{fault}"
        );
        assert_eq!(projection.retirements, 0);
    }
    let mut projection = RegistryLifetimeModel::new();
    projection.finish(41, ExperimentBorrowed).unwrap();
    projection.recipient_debt = 1;
    projection.finish(41, ExperimentBorrowed).unwrap();
    assert_eq!(projection.recipient_debt, 1);
    assert!(projection.finish(41, ExecutionOwned).is_err());
    assert!(projection.live);
    assert_eq!(projection.retirements, 0);
    projection.recipient_debt = 0;
    projection.retire().unwrap();
    assert_eq!(projection.retirements, 1);
}
#[test]
fn provider_scenario_settlement_keeps_every_independent_failure_fatal() {
    use memcordon_ci::windows_consumer_readiness::settle_provider_scenario;
    for obligation in [
        "original operation",
        "collection",
        "retirement",
        "mutation denial",
        "custody",
        "retention",
        "namespace cleanup",
        "publication",
    ] {
        let error =
            settle_provider_scenario(None, Err(memcordon_ci::CiError::Message(obligation.into())))
                .unwrap_err()
                .to_string();
        assert!(error.contains(obligation));
    }
    assert!(
        settle_provider_scenario(None, Ok(()))
            .unwrap_err()
            .to_string()
            .contains("selection absent")
    );
}

#[test]
fn held_gate_projection_retains_only_bounded_metadata_and_drops_legacy_secrets() {
    use memcordon_ci::windows_consumer_readiness::redacted_toolchain_held_gate_observation as project;
    let digest = memcordon_ci::windows_causal_acceptance::sha256(b"descriptor");
    let secret = "CAPABILITY_CANARY_name_token_sid_descriptor";
    let mut security = serde_json::json!({"state":"observed","value":{
        "descriptor_sha256":digest,"descriptor_length":20,"revision":1,"control":32768,
        "dacl_present":false,"dacl_null":false,"acl_revision":null,"acl_bytes":null,
        "declared_ace_count":null,"unused_acl_bytes":null,"aces":[],
        "requested_name_utf16":secret,"descriptor_bytes_hex":secret,"owner_sid_hex":secret,
        "group_sid_hex":secret,"token":secret,"handle":secret}});
    let unavailable = serde_json::json!({"state":"unavailable","kind":"PermissionDenied","raw_os_error":5,"detail":secret});
    let output = project(&security, &unavailable);
    assert_eq!(output["same_held_event_security"]["state"], "observed");
    assert_eq!(
        output["same_held_event_security"]["value"]["descriptor_sha256"],
        digest
    );
    assert_eq!(output["same_held_event_mandatory_label"]["raw_os_error"], 5);
    assert_eq!(
        output["same_held_event_mandatory_label"]["kind"],
        "PermissionDenied"
    );
    let mut untrusted = unavailable.clone();
    untrusted["kind"] = serde_json::json!(secret);
    let output = project(&security, &untrusted);
    assert_eq!(output["same_held_event_mandatory_label"]["kind"], "Unknown");
    assert!(!output.to_string().contains(secret));
    let legacy = serde_json::json!({"format":"memcordon.windows-controller-gate-diagnostic",
        "requested_name_utf16":secret,"requested_sddl":secret,"controller":secret});
    assert_eq!(
        project(&legacy, &legacy)["same_held_event_security"]["state"],
        "unavailable"
    );
    security["value"]["descriptor_sha256"] = serde_json::json!(secret);
    assert_eq!(
        project(&security, &unavailable)["same_held_event_security"]["state"],
        "unavailable"
    );
    security["value"]["descriptor_sha256"] = serde_json::json!(digest);
    security["value"]["descriptor_length"] = serde_json::json!(64 * 1024 + 1);
    assert_eq!(
        project(&security, &unavailable)["same_held_event_security"]["state"],
        "unavailable"
    );
    let mut acl = serde_json::json!({"state":"observed","value":{
        "descriptor_sha256":digest,"descriptor_length":36,"revision":1,"control":32772,
        "dacl_present":true,"dacl_null":false,"acl_revision":2,"acl_bytes":16,
        "declared_ace_count":1,"unused_acl_bytes":0,"aces":[{
            "ordinal":0,"native_type":0,"flags":0,"bytes":8,
            "raw_u32_at_offset_four":1048576,"sha256":digest,"sid_hex":secret}]}});
    let mut label = serde_json::json!({"state":"observed","value":{
        "descriptor_sha256":digest,"descriptor_length":48,"control":32784,"information":16,
        "sacl_present":true,"sacl_null":false,"descriptor_bytes_hex":secret,
        "label":{"flags":0,"mask":1,"sid_revision":1,"identifier_authority":16,
            "subauthorities":[12288],"sid_hex":secret}}});
    let output = project(&acl, &label);
    assert_eq!(
        output["same_held_event_security"]["value"]["aces"][0]["raw_u32_at_offset_four"],
        1048576
    );
    assert_eq!(
        output["same_held_event_mandatory_label"]["value"]["label"]["integrity_level"],
        12288
    );
    assert!(!output.to_string().contains(secret));
    acl["value"]["declared_ace_count"] = serde_json::json!(2);
    assert_eq!(
        project(&acl, &label)["same_held_event_security"]["state"],
        "unavailable"
    );
    acl["value"]["declared_ace_count"] = serde_json::json!(1);
    acl["value"]["aces"][0]["ordinal"] = serde_json::json!(1);
    assert_eq!(
        project(&acl, &label)["same_held_event_security"]["state"],
        "unavailable"
    );
    label["value"].as_object_mut().unwrap().remove("label");
    assert_eq!(
        project(&acl, &label)["same_held_event_mandatory_label"]["state"],
        "unavailable"
    );
    label["value"]["label"] = serde_json::Value::Null;
    label["value"]["descriptor_length"] = serde_json::json!(20);
    assert_eq!(
        project(&acl, &label)["same_held_event_mandatory_label"]["state"],
        "unavailable"
    );
    label["value"]["descriptor_length"] = serde_json::json!(28);
    assert_eq!(
        project(&acl, &label)["same_held_event_mandatory_label"]["state"],
        "observed"
    );
}

#[test]
fn toolchain_summary_exports_reported_scalars_without_capability_payloads_or_prefix_hashes() {
    use memcordon_ci::windows_consumer_readiness::redacted_toolchain_failure_summary as summarize;
    let secret = "SECRET_CHALLENGE_NONCE_TOKEN_DESCRIPTOR";
    let callback = serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.windows-positive-callback-failure","revision":1,
        "observed_status":null,"termination":1,"capture_complete":true,"cleanup":{"Ok":null},
        "error":secret,"product_context":{"raw":secret},"peer_stdout":secret}))
    .unwrap();
    let stderr = format!("memcordon-test-fixture: operation=OpenEventW-controller-wait; access=0x100000; kind=PermissionDenied; raw-os-error=Some(5); wait-status=None; failure-only-effective-token={secret}\n").into_bytes();
    let output = summarize(|leaf| {
        Ok(match leaf {
            "result.callback-failure.json" => Some(callback.clone()),
            "result.stderr.bin" => Some(stderr.clone()),
            "result.guardian-query.stdout.bin" => Some(secret.as_bytes().to_vec()),
            _ => None,
        })
    });
    assert!(!output.to_string().contains(secret));
    assert_eq!(output["sources"][0]["observation"]["termination"], 1);
    assert_eq!(output["sources"][1]["observation"]["raw_os_error"], 5);
    assert_eq!(
        output["sources"][1]["observation"]["diagnostic_reported"],
        true
    );
    assert_eq!(
        output["sources"][1]["sha256"],
        memcordon_ci::windows_causal_acceptance::sha256(&stderr)
    );
    assert_eq!(output["sources"][6]["state"], "unavailable");
    assert!(output["sources"][6].get("sha256").is_none());
    for invalid in [
        b"{\"format\":\"a\",\"format\":\"b\"}".to_vec(),
        vec![b'x'; 64 * 1024 + 1],
    ] {
        let output = summarize(|_| Ok(Some(invalid.clone())));
        assert!(
            output["sources"]
                .as_array()
                .unwrap()
                .iter()
                .all(|source| source["state"] == "unavailable" && source.get("sha256").is_none())
        );
    }
    let duplicate_line = [stderr.clone(), stderr].concat();
    let output = summarize(|leaf| {
        Ok(match leaf {
            "result.callback-failure.json" => Some(callback.clone()),
            "result.stderr.bin" => Some(duplicate_line.clone()),
            _ => None,
        })
    });
    assert_eq!(output["sources"][1]["state"], "unavailable");
    assert!(output["sources"][1].get("sha256").is_none());
    let valid: serde_json::Value = serde_json::from_slice(&callback).unwrap();
    for field in ["observed_status", "termination"] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        let bytes = serde_json::to_vec(&missing).unwrap();
        let output = summarize(|_| Ok(Some(bytes.clone())));
        assert_eq!(output["sources"][0]["state"], "unavailable");
        assert!(output["sources"][0].get("sha256").is_none());
    }
    let mut conflicting = valid.clone();
    conflicting["observed_status"] = serde_json::json!(2);
    let mut incomplete = valid.clone();
    incomplete["capture_complete"] = serde_json::json!(false);
    let mut malformed_cleanup = valid.clone();
    malformed_cleanup["cleanup"] = serde_json::json!({"Err":null});
    let duplicate_known = String::from_utf8(callback)
        .unwrap()
        .replace(
            "\"capture_complete\":true",
            "\"capture_complete\":true,\"capture_complete\":false",
        )
        .into_bytes();
    for bytes in [
        serde_json::to_vec(&conflicting).unwrap(),
        serde_json::to_vec(&incomplete).unwrap(),
        serde_json::to_vec(&malformed_cleanup).unwrap(),
        duplicate_known,
    ] {
        let output = summarize(|_| Ok(Some(bytes.clone())));
        assert_eq!(output["sources"][0]["state"], "unavailable");
        assert!(output["sources"][0].get("sha256").is_none());
    }
}

#[test]
fn toolchain_stderr_projects_only_one_complete_bounded_fixture_stage() {
    use memcordon_ci::windows_consumer_readiness::redacted_toolchain_failure_summary as summarize;
    let project = |stderr: &str, capture_complete: bool| {
        let callback = serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.windows-positive-callback-failure","revision":1,
            "observed_status":null,"termination":1,"capture_complete":capture_complete,
            "cleanup":{"Ok":null}
        }))
        .unwrap();
        summarize(|leaf| {
            Ok(match leaf {
                "result.callback-failure.json" => Some(callback.clone()),
                "result.stderr.bin" => Some(stderr.as_bytes().to_vec()),
                _ => None,
            })
        })["sources"][1]
            .clone()
    };
    let marker = |operation, role, code| {
        format!(
            "memcordon-test-fixture: toolchain-failure-v1; operation={operation}; source-role={role}; raw-os-error={code}; end\n"
        )
    };
    const SECRET: &str = "DO_NOT_PROJECT_ORIGINAL_PATH_AND_ERROR_DETAIL";
    for (operation, role, code, expected) in [
        ("observer-frame-read", "none", "127", serde_json::json!(127)),
        (
            "observer-deadline-settle",
            "none",
            "none",
            serde_json::Value::Null,
        ),
        ("copy-source", "library", "-127", serde_json::json!(-127)),
    ] {
        let stderr = format!("{}{SECRET}\n", marker(operation, role, code));
        let source = project(&stderr, true);
        assert_eq!(source["observation"]["operation"], operation);
        assert_eq!(
            source["observation"]["source_role"].as_str(),
            (role != "none").then_some(role)
        );
        assert_eq!(source["observation"]["raw_os_error"], expected);
        assert_eq!(source["observation"]["acceptance_authority"], false);
        assert_eq!(
            source["sha256"],
            memcordon_ci::windows_causal_acceptance::sha256(stderr.as_bytes())
        );
        assert!(!source.to_string().contains(SECRET));
        assert!(project(&stderr, false).get("observation").is_none());
    }
    let valid = marker("observer-frame-read", "none", "127");
    let compiler_marker = |stage, role| {
        format!(
            "memcordon-test-fixture: toolchain-failure-v2; operation=compile-library; source-role=none; compiler-operation={stage}; resource-role={role}; raw-os-error=5; end\n"
        )
    };
    for (stage, role) in [
        ("directory-open", "outside-input-root"),
        ("directory-named-metadata", "input-root"),
        ("linker-read", "linker"),
        ("compiler-spawn", "compiler"),
        ("checkpoint-publish", "fixture"),
        ("child-retirement", "compiler"),
    ] {
        let stderr = format!("{}{SECRET}\n", compiler_marker(stage, role));
        let source = project(&stderr, true);
        assert_eq!(source["observation"]["operation"], "compile-library");
        assert!(source["observation"]["source_role"].is_null());
        assert_eq!(source["observation"]["compiler_operation"], stage);
        assert_eq!(source["observation"]["resource_role"], role);
        assert_eq!(source["observation"]["raw_os_error"], 5);
        assert_eq!(source["observation"]["acceptance_authority"], false);
        assert!(!source.to_string().contains(SECRET));
        assert!(project(&stderr, false).get("observation").is_none());
    }
    let compiler = compiler_marker("compiler-spawn", "compiler");
    for invalid in [
        valid.clone(),
        format!("{valid}{SECRET}"),
        format!("{SECRET}\n{valid}{SECRET}\n"),
        format!("{valid}{valid}{SECRET}\n"),
        format!("{valid}memcordon-test-fixture: unrelated fixture diagnostic\n"),
        format!("{}{SECRET}\n", marker("copy-source", "none", "127")),
        format!(
            "{}{SECRET}\n",
            marker("observer-deadline-arm", "library", "127")
        ),
        format!("{}{SECRET}\n", marker("unknown", "none", "127")),
        format!(
            "{}{SECRET}\n",
            marker("compile-library", "none", "2147483648")
        ),
        format!("{valid}{SECRET}\n").replace("; end\n", "; extra\n"),
        format!("{compiler}{SECRET}"),
        format!("{compiler}{valid}{SECRET}\n"),
        format!(
            "{}{SECRET}\n",
            compiler_marker("directory-open", "compiler")
        ),
        format!(
            "{}{SECRET}\n",
            compiler_marker("compiler-spawn", "outside-input-root")
        ),
        format!("{}{SECRET}\n", compiler_marker("unknown-stage", "fixture")),
        format!("{}{SECRET}\n", compiler_marker("directory-open", SECRET)),
        format!("{compiler}{SECRET}\n").replace("source-role=none", "source-role=library"),
        format!("{compiler}{SECRET}\n")
            .replace("operation=compile-library", "operation=copy-source"),
    ] {
        let source = project(&invalid, true);
        assert_eq!(source["state"], "unavailable", "{invalid}");
        assert!(source.get("observation").is_none());
        assert!(source.get("sha256").is_none());
    }
}

#[test]
fn original_compiler_loads_require_complete_bound_original_child_and_selected_identity() {
    use memcordon_ci::windows_consumer_readiness::{
        redacted_original_compiler_loads as project,
        redacted_toolchain_failure_summary as summarize,
    };
    use memcordon_core::{DiagnosticSha256, WindowsProcessIdentityV1};
    use serde_json::json;
    let callback = serde_json::to_vec(&json!({
        "format":"memcordon.windows-positive-callback-failure","revision":1,
        "observed_status":null,"termination":1,"capture_complete":true,"cleanup":{"Ok":null}
    }))
    .unwrap();
    let stderr = b"memcordon-test-fixture: toolchain-failure-v2; operation=compile-library; source-role=none; compiler-operation=child-status; resource-role=compiler; raw-os-error=none; end\noriginal detail\n";
    let summary = summarize(|leaf| {
        Ok(match leaf {
            "result.callback-failure.json" => Some(callback.clone()),
            "result.stderr.bin" => Some(stderr.to_vec()),
            _ => None,
        })
    });
    let compiler = "a1".repeat(32);
    let root = WindowsProcessIdentityV1 {
        process_id: 12,
        creation_time_100ns: 30,
    };
    let child = WindowsProcessIdentityV1 {
        process_id: 14,
        creation_time_100ns: 33,
    };
    let selected = [descriptor::CompilerImportSibling {
        staged_sha256: DiagnosticSha256::from_bytes([3; 32]),
        volume_serial: 7,
        file_index: 23,
        byte_length: 100,
        last_write_100ns: 20,
    }];
    let challenge = [7, 19, 21];
    for (identity, length, write_time, expected) in [
        ((7, 23), 100, 20, Some(true)),
        ((8, 23), 100, 20, None),
        ((7, 24), 100, 20, None),
        ((7, 23), 101, 20, Some(false)),
        ((7, 23), 100, 21, Some(false)),
    ] {
        assert_eq!(
            selected[0].observed_metadata_matches(identity, length, write_time),
            expected
        );
    }
    let code = 0xc000_0135u32;
    let receipt = json!({
        "format":"memcordon.windows-fixture-owned-child-retired", "revision":1,
        "role":"readiness.rlib", "challenge":challenge,
        "parent":root, "child":child, "image_sha256":compiler,
        "compiler_inputs":{"private":"must-not-project"},
        "held_from_process_creation":true,"held_live_before_wait":true,
        "native_parent_edge_observed":true,"native_wait_completed":true,
        "native_status":code as i32,
        "original_compiler_loads": {
            "compiler_stderr_bytes":0,
            "loads":{"matched_staged_sha256":[selected[0].staged_sha256],
                "bounded_events":2,"unavailable_file_identity":1,"events_after_bound":0}
        }
    });
    let ack = json!({
        "format":"memcordon.windows-toolchain-creation-ack","revision":1,"challenge":challenge,
        "descendant":{
            "format":"memcordon.windows-native-toolchain-descendant","revision":1,"ordinal":1,
            "root_pid":root.process_id,"pid":child.process_id,"birth":child.creation_time_100ns,
            "parent_pid":root.process_id,"parent_birth":root.creation_time_100ns,
            "image_sha256":compiler,"native_parent_edge_observed":true,"parent_and_child_held_live":true
        }
    });
    let observe_with_ack =
        |summary: &serde_json::Value, receipt: &serde_json::Value, ack: &serde_json::Value| {
            project(
                summary,
                &serde_json::to_vec(receipt).unwrap(),
                &challenge,
                &root,
                &compiler,
                &selected,
                |actual| (actual == &child).then(|| (code, serde_json::to_vec(ack).unwrap())),
            )
        };
    let observe = |summary: &serde_json::Value, receipt: &serde_json::Value| {
        observe_with_ack(summary, receipt, &ack)
    };
    let result = observe(&summary, &receipt).unwrap();
    assert_eq!(result["native_child_status"], code);
    assert_eq!(
        result["matched_staged_sha256"],
        json!([selected[0].staged_sha256])
    );
    assert_eq!(result["event_metadata_incomplete"], true);
    assert_eq!(result["unobserved_loads"], "unknown");
    assert_eq!(result["acceptance_authority"], false);
    assert!(!result.to_string().contains("must-not-project"));
    let mut other_image = ack.clone();
    other_image["descendant"]["image_sha256"] = json!("ff".repeat(32));
    assert!(observe_with_ack(&summary, &receipt, &other_image).is_none());
    for (field, value) in [
        ("challenge", json!([7, 19, 22])),
        ("role", json!("tests.exe")),
        ("native_status", json!(-5)),
        ("image_sha256", json!("ff".repeat(32))),
        (
            "child",
            json!({"process_id":child.process_id,"creation_time_100ns":child.creation_time_100ns + 1}),
        ),
        ("native_wait_completed", json!(false)),
    ] {
        let mut wrong = receipt.clone();
        wrong[field] = value;
        assert!(observe(&summary, &wrong).is_none(), "{field}");
    }
    let mut wrong = receipt.clone();
    wrong["original_compiler_loads"]["loads"]["matched_staged_sha256"] = json!(["ff".repeat(32)]);
    assert!(observe(&summary, &wrong).is_none());
    wrong = receipt.clone();
    wrong["original_compiler_loads"]["loads"]["events_after_bound"] = json!(1);
    assert!(observe(&summary, &wrong).is_none());
    let mut incomplete = summary.clone();
    incomplete["sources"][1]["state"] = json!("unavailable");
    assert!(observe(&incomplete, &receipt).is_none());
}

#[test]
fn installed_positive_suite_and_other_callers_scope_the_original_guardian_release_wait() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseKey, GuardianReleaseWaitScope, expected_start_transport, positive_keys,
    };
    for (family, scenario, expected) in [
        ("W-IO", "empty-message", true),
        ("C-STATUS", "deadline", true),
        ("W-TOOLCHAIN", "restricted", true),
        ("C-STATUS", "memory", false),
        ("W-STATUS", "deadline", false),
        ("W-IO", "empty-stdout-stderr", false),
        ("W-TOOLCHAIN", "ordinary", false),
        ("W-TOOLCHAIN", "deadline", false),
        ("W-JOINT", "restricted", false),
    ] {
        assert_eq!(
            GuardianReleaseWaitScope::ExistingCaseSelection.waits_for_original_release(&CaseKey {
                family: family.into(),
                scenario: scenario.into()
            }),
            expected
        );
    }
    for key in positive_keys() {
        assert!(GuardianReleaseWaitScope::MandatoryPositiveSuite.waits_for_original_release(&key));
    }
    let joint = CaseKey {
        family: "W-JOINT".into(),
        scenario: "restricted".into(),
    };
    let ordinary_toolchain = CaseKey {
        family: "W-TOOLCHAIN".into(),
        scenario: "ordinary".into(),
    };
    assert!(matches!(
        expected_start_transport(&joint),
        descriptor::StartTransport::ControllerStdin { .. }
    ));
    assert_eq!(
        expected_start_transport(&ordinary_toolchain),
        descriptor::StartTransport::NamedEvent
    );
    for key in [joint, ordinary_toolchain] {
        assert!(GuardianReleaseWaitScope::MandatoryPositiveSuite.waits_for_original_release(&key));
        assert!(!GuardianReleaseWaitScope::ExistingCaseSelection.waits_for_original_release(&key));
    }
}

#[test]
fn compiler_spawn_routes_expose_only_bound_returned_facts() {
    use memcordon_ci::windows_consumer_readiness::{
        redacted_compiler_spawn_routes as project, redacted_toolchain_failure_summary as summarize,
    };
    use serde_json::json;
    let binding = descriptor::controller_start::Binding {
        challenge: vec![3, 2, 1],
        descriptor_sha256: [4; 32],
        pid: 8,
        birth: 23,
    };
    let clock = (100, 10);
    let callback = serde_json::to_vec(&json!({
        "format":"memcordon.windows-positive-callback-failure","revision":1,
        "observed_status":null,"termination":1,"capture_complete":true,"cleanup":{"Ok":null}
    }))
    .unwrap();
    let witness = json!({
        "pid":binding.pid,"birth":binding.birth,"descriptor_sha256":binding.descriptor_sha256,
        "challenge_sha256":descriptor::controller_start::descriptor_digest(&binding.challenge),
        "cutoff_qpc":clock.0,"frequency":clock.1,"raw_os_error":5,
        "routes":{"covered":["NtCreateNamedPipeFile","CreateProcessW"],"returns":[
            {"api":"NtCreateNamedPipeFile","failed":false,"ntstatus":0,"win32_error":null},
            {"api":"CreateProcessW","failed":true,"ntstatus":null,"win32_error":5},
        ]}
    });
    let observe = |value: &serde_json::Value, with_duplicate: bool| {
        let mut stderr = format!(
            "memcordon-test-fixture: toolchain-failure-v2; operation=compile-library; source-role=none; compiler-operation=compiler-spawn; resource-role=compiler; raw-os-error=5; end\nprivate original text\ncompiler-spawn-routes-v1 {value}\n"
        );
        if with_duplicate {
            stderr.push_str(&format!("compiler-spawn-routes-v1 {value}\n"));
        }
        let summary = summarize(|leaf| {
            Ok(match leaf {
                "result.callback-failure.json" => Some(callback.clone()),
                "result.stderr.bin" => Some(stderr.as_bytes().to_vec()),
                _ => None,
            })
        });
        project(&summary, stderr.as_bytes(), &binding, clock.0, clock.1)
    };
    let observed = observe(&witness, false).unwrap();
    assert_eq!(observed["routes"]["returns"], witness["routes"]["returns"]);
    assert_eq!(observed["global_route_coverage"], false);
    assert_eq!(observed["denied_object_proved"], false);
    assert_eq!(observed["acceptance_authority"], false);
    assert!(!observed.to_string().contains("private original"));
    assert!(observe(&witness, true).is_none());
    for (field, other) in [
        ("birth", json!(0)),
        ("descriptor_sha256", json!(vec![7; 32])),
        ("cutoff_qpc", json!(101)),
        ("raw_os_error", json!(127)),
        ("routes", serde_json::Value::Null),
    ] {
        let mut changed = witness.clone();
        changed[field] = other;
        assert!(observe(&changed, false).is_none(), "{field}");
    }
    let mut wrong_route = witness.clone();
    wrong_route["routes"]["returns"][1]["api"] = json!("CreateProcessInternalW");
    assert!(observe(&wrong_route, false).is_none());
    let mut wrong_domain = witness.clone();
    wrong_domain["routes"]["returns"][1]["ntstatus"] = json!(-5);
    assert!(observe(&wrong_domain, false).is_none());
    let mut raw_name = witness;
    raw_name["routes"]["returns"][1]["path"] = json!("a private path");
    assert!(observe(&raw_name, false).is_none());
}

#[test]
fn compiler_no_debug_comparison_is_bound_and_has_no_acceptance_authority() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseKey, redacted_compiler_no_debug_comparison as project,
        redacted_toolchain_failure_summary as summarize,
    };
    use serde_json::json;
    let key = CaseKey {
        family: "W-TOOLCHAIN".into(),
        scenario: "restricted".into(),
    };
    let binding = descriptor::controller_start::Binding {
        challenge: vec![3, 2, 1],
        descriptor_sha256: [4; 32],
        pid: 8,
        birth: 23,
    };
    let clock = (100, 10);
    let callback = serde_json::to_vec(&json!({
        "format":"memcordon.windows-positive-callback-failure","revision":1,
        "observed_status":null,"termination":1,"capture_complete":true,"cleanup":{"Ok":null},
    }))
    .unwrap();
    let compiler = "12".repeat(32);
    let linker = "34".repeat(32);
    let base = json!({
        "pid":binding.pid,"birth":binding.birth,"descriptor_sha256":binding.descriptor_sha256,
        "challenge_sha256":descriptor::controller_start::descriptor_digest(&binding.challenge),
        "cutoff_qpc":clock.0,"frequency":clock.1,
    });
    let mut original = base.clone();
    original["raw_os_error"] = json!(5);
    original["routes"] = json!({"covered":["CreateProcessW"],"returns":[
        {"api":"CreateProcessW","failed":true,"ntstatus":null,"win32_error":5},
    ]});
    let mut witness = base;
    witness.as_object_mut().unwrap().extend(
        json!({
            "compiler_sha256":compiler,"linker_sha256":linker,"role":"readiness.rlib",
            "original_ordinal":1,"original_flags":1,"comparison_ordinal":2,"comparison_flags":0,
            "original_native_flags":1025,
            "outcome":{"state":"spawn-error","raw_os_error":5,
                "returned":{"state":"failure","win32_error":5,"native_flags":1024}},
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let observe = |original: &serde_json::Value, marker: &str, suffix: &str, same_digest: bool| {
        let stderr = format!(
            "memcordon-test-fixture: toolchain-failure-v2; operation=compile-library; source-role=none; compiler-operation=compiler-spawn; resource-role=compiler; raw-os-error=5; end\ncompiler-spawn-routes-v1 {original}\n; \ncompiler-no-debug-comparison-v1 {marker}\n{suffix}"
        );
        let summary = summarize(|leaf| {
            Ok(match leaf {
                "result.callback-failure.json" => Some(callback.clone()),
                "result.stderr.bin" => Some(stderr.as_bytes().to_vec()),
                _ => None,
            })
        });
        let mut changed = stderr.into_bytes();
        if !same_digest {
            changed.push(b'\n');
        }
        project(
            &summary,
            &changed,
            &key,
            &binding,
            clock,
            (&compiler, &linker),
        )
    };
    let both = observe(&original, &witness.to_string(), "", true).unwrap();
    assert_eq!(both["state"], "both-create-process-access-denied");
    assert_eq!(both["acceptance_authority"], false);
    assert_eq!(both["original"]["raw_os_error"], 5);
    let mut wrong_flags = witness.clone();
    wrong_flags["outcome"]["returned"]["native_flags"] = json!(2048);
    assert_eq!(
        observe(&original, &wrong_flags.to_string(), "", true).unwrap()["state"],
        "inconclusive",
    );
    assert!(
        observe(
            &original,
            &witness.to_string(),
            "compiler-no-debug-comparison-v1\n",
            true
        )
        .is_none()
    );
    assert!(observe(&original, "{", "", true).is_none());
    assert!(observe(&original, &witness.to_string(), "", false).is_none());

    for (field, value) in [
        ("birth", json!(24)),
        ("frequency", json!(9)),
        ("compiler_sha256", json!("56".repeat(32))),
        ("linker_sha256", json!("78".repeat(32))),
        ("comparison_flags", json!(1)),
    ] {
        let mut other = witness.clone();
        other[field] = value;
        assert!(
            observe(&original, &other.to_string(), "", true).is_none(),
            "{field}"
        );
    }
    let mut no_create_process = original.clone();
    no_create_process["routes"] = json!({"covered":["CreateFileW"],"returns":[
        {"api":"CreateFileW","failed":true,"ntstatus":null,"win32_error":5},
    ]});
    assert!(observe(&no_create_process, &witness.to_string(), "", true).is_none());

    witness["outcome"] = json!({
        "state":"child-complete","returned":{"state":"success","win32_error":null,
            "native_flags":1024,"process_id":34},
        "identity":{"process_id":34,"creation_time_100ns":25},
        "retired":true,"native_status":1,"operation_failed":false,"cleanup_failed":false,
    });
    let child = observe(&original, &witness.to_string(), "", true).unwrap();
    assert_eq!(child["state"], "no-debug-child-verified");
    assert_eq!(child["comparison"]["outcome"]["native_status"], 1);
    witness["outcome"]["retired"] = json!(false);
    assert!(observe(&original, &witness.to_string(), "", true).is_none());
    witness["outcome"] = json!({
        "state":"child-incomplete","returned":{"state":"success","win32_error":null,
            "native_flags":1024,"process_id":34},
        "identity":null,"retired":false,"native_status":null,
        "operation_failed":true,"cleanup_failed":true,
    });
    let incomplete = observe(&original, &witness.to_string(), "", true).unwrap();
    assert_eq!(incomplete["state"], "inconclusive");
    assert_eq!(incomplete["comparison"]["outcome"]["cleanup_failed"], true);
    witness["outcome"]["cleanup_failed"] = json!(false);
    assert!(observe(&original, &witness.to_string(), "", true).is_none());
}

#[test]
fn direct_compiler_baseline_requires_a_unique_witness_and_matching_native_return() {
    use memcordon_ci::windows_consumer_readiness::{
        compiler_pre_creation_marker, direct_x64_compiler_disposition,
    };
    use serde_json::json;
    let hash = "ab".repeat(32);
    let marker = format!("compiler-pre-creation-v1 {hash}\n");
    assert_eq!(
        compiler_pre_creation_marker(marker.as_bytes()),
        Some(Ok(hash.as_str()))
    );
    assert!(compiler_pre_creation_marker(marker.repeat(2).as_bytes()).is_none());
    assert!(compiler_pre_creation_marker(marker.to_uppercase().as_bytes()).is_none());
    let failure = b"compiler-pre-creation-v1 unavailable source-read\n";
    assert_eq!(
        compiler_pre_creation_marker(failure),
        Some(Err("source-read"))
    );
    assert!(
        compiler_pre_creation_marker(b"compiler-pre-creation-v1 unavailable local/path\n")
            .is_none()
    );
    assert!(
        compiler_pre_creation_marker([marker.as_bytes(), failure].concat().as_slice()).is_none()
    );
    let mut refusal = json!({
        "state":"spawn-error","raw_os_error":5,
        "returned_create_process":{"native_flags":1025,"win32_error":5,"pid":null},
    });
    assert_eq!(
        direct_x64_compiler_disposition(&refusal, 1025),
        "direct-create-process-access-denied"
    );
    assert_eq!(
        direct_x64_compiler_disposition(&refusal, 1024),
        "inconclusive"
    );
    refusal["raw_os_error"] = json!(87);
    assert_eq!(
        direct_x64_compiler_disposition(&refusal, 1025),
        "inconclusive"
    );
    let mut retired = json!({
        "state":"retired","child_pid":41,"native_status":0xc0000135_u32,
        "returned_create_process":{"native_flags":1025,"win32_error":null,"pid":41},
    });
    assert_eq!(
        direct_x64_compiler_disposition(&retired, 1025),
        "direct-child-retired"
    );
    retired["returned_create_process"]["pid"] = json!(42);
    assert_eq!(
        direct_x64_compiler_disposition(&retired, 1025),
        "inconclusive"
    );
}

#[test]
fn exact_x64_compiler_refusal_requires_the_original_and_direct_settlements() {
    use memcordon_ci::windows_consumer_readiness::matches_settled_x64_compiler_refusal;
    use serde_json::json;
    let stderr = "12".repeat(32);
    let proof = json!({
        "sources":[null, {"state":"complete","sha256":stderr}],
        "compiler_no_debug_comparison":{
            "state":"both-create-process-access-denied","stderr_sha256":stderr,
            "compiler_sha256":"compiler","linker_sha256":"linker",
            "original":{"rust":"error","raw_os_error":5,"returned_create_process":{
                "state":"failure","native_flags":1025,"win32_error":5,
            }},
            "comparison":{"rust":"error","outcome":{"state":"spawn-error","raw_os_error":5,
                "returned":{"state":"failure","native_flags":1024,"win32_error":5}}},
        },
        "original_final_settlement":{"terminal_settled":true,"retirement_verified":true},
        "direct_restricted_baseline":{"state":"direct-create-process-access-denied",
            "scratch_retired":true,"diagnostic_job_empty_verified":true,
            "installed_original":{"stderr_sha256":stderr,"native_flags":1025},
            "evidence":{"original_witness_sha256":"ab".repeat(32),
                "compiler_sha256":"compiler","linker_sha256":"linker",
                "outcome":{"state":"spawn-error","raw_os_error":5,
                    "returned_create_process":{"native_flags":1025,"win32_error":5,"pid":null}}},
        },
    });
    assert!(matches_settled_x64_compiler_refusal(&proof, &stderr));
    assert!(!matches_settled_x64_compiler_refusal(&proof, "other"));
    for (path, invalid) in [
        ("/original_final_settlement/terminal_settled", json!(false)),
        (
            "/original_final_settlement/retirement_verified",
            json!(false),
        ),
        ("/direct_restricted_baseline/scratch_retired", json!(false)),
        (
            "/direct_restricted_baseline/diagnostic_job_empty_verified",
            json!(false),
        ),
        (
            "/direct_restricted_baseline/evidence/original_witness_sha256",
            json!(null),
        ),
        (
            "/direct_restricted_baseline/evidence/outcome/returned_create_process/pid",
            json!(42),
        ),
        (
            "/direct_restricted_baseline/evidence/outcome/returned_create_process/native_flags",
            json!(1024),
        ),
        (
            "/compiler_no_debug_comparison/comparison/outcome/raw_os_error",
            json!(87),
        ),
    ] {
        let mut invalid_proof = proof.clone();
        *invalid_proof.pointer_mut(path).unwrap() = invalid;
        assert!(
            !matches_settled_x64_compiler_refusal(&invalid_proof, &stderr),
            "{path}"
        );
    }
}
#[test]
fn reduced_compiler_receipt_binds_token_challenge_and_both_access_results() {
    use descriptor::gate_precondition::sha256;
    use memcordon_ci::windows_consumer_readiness::validate_reduced_compiler_probes;
    let challenge = b"case challenge";
    let token = serde_json::json!({
        "user_sid":[1,1,0,0,0,0,0,5,21,0,0,0],"restricted":false,
        "integrity_rid":12288,"elevated":false,"restricting_sids":[],
    });
    let token_bytes = serde_json::to_vec(&token).unwrap();
    let authority = serde_json::json!({
        "token": token, "authentication_id":[10,0], "session_id":1,
        "primary":true, "administrators_attributes":16,
        "groups":[{"sid":descriptor::gate_precondition::COMPILER_ADMINISTRATORS_SID,"attributes":16}],
        "privileges":[{"luid":[23,0],"attributes":3}],"traversal_luid":[23,0],
    });
    let mut enabled_admin = authority.clone();
    enabled_admin["administrators_attributes"] = serde_json::json!(4);
    enabled_admin["groups"][0]["attributes"] = serde_json::json!(4);
    let valid = serde_json::json!({
        "challenge_sha256":sha256(challenge),"effective_token_sha256":sha256(&token_bytes),
        "protected":{"volume_serial":11,"file_index":12},
        "protected_write_win32":5,"output_write_verified":true,"authority":authority,
    });
    assert!(
        validate_reduced_compiler_probes(
            &serde_json::to_vec(&valid).unwrap(),
            challenge,
            &token_bytes
        )
        .is_ok()
    );
    for (field, different) in [
        ("challenge_sha256", serde_json::json!(sha256(b"other case"))),
        (
            "effective_token_sha256",
            serde_json::json!(sha256(b"ordinary token")),
        ),
        (
            "protected",
            serde_json::json!({"volume_serial":11,"file_index":0}),
        ),
        ("protected_write_win32", serde_json::json!(32)),
        ("output_write_verified", serde_json::json!(false)),
        ("authority", enabled_admin),
    ] {
        let mut receipt = valid.clone();
        receipt[field] = different;
        assert!(
            validate_reduced_compiler_probes(
                &serde_json::to_vec(&receipt).unwrap(),
                challenge,
                &token_bytes
            )
            .is_err()
        );
    }
}

#[test]
fn original_argv_path_does_not_identify_the_writer_or_prove_entry() {
    use memcordon_ci::windows_consumer_readiness::original_argv_path_observation as observe;
    let expected = br#"{"encoding":"windows_utf16","values":[]}"#;
    let matching = observe(true, &[], || Ok(Some(expected.to_vec())));
    assert_eq!(
        matching["state"],
        "matching-bytes-at-previously-vacant-path"
    );
    let unverified = observe(false, &[], || panic!("must not credit a preexisting path"));
    assert_eq!(unverified["state"], "prelaunch-vacancy-unverified");
    let missing = observe(true, &[], || Ok(None));
    assert_eq!(missing["state"], "absent");
    let wrong = observe(true, &["other".into()], || Ok(Some(expected.to_vec())));
    assert_eq!(wrong["state"], "different-bytes");
    let malformed = observe(true, &[], || Ok(Some(b"{".to_vec())));
    assert_eq!(malformed["state"], "malformed-json");
    let unreadable = observe(true, &[], || Err(std::io::Error::other("unavailable")));
    assert_eq!(
        unreadable["state"],
        "unreadable-or-not-bounded-regular-file"
    );
    for result in [matching, unverified, missing, wrong, malformed, unreadable] {
        assert_eq!(result["writer_identity"], "unverified");
        assert_eq!(result["fixture_entry"], "unknown");
        assert_eq!(result["failing_initializer"], "unknown");
        assert_eq!(result["acceptance_authority"], false);
    }
}

#[test]
fn original_argv_observation_survives_missing_or_failed_comparison() {
    use memcordon_ci::windows_consumer_readiness::retain_original_argv_observation as retain;
    use serde_json::json;
    for comparison in [
        None,
        Some(json!({"state":"unavailable"})),
        Some(json!({"state":"same-native-startup-status"})),
    ] {
        let observation = json!({"path_observation":{"fixture_entry":"unknown"}});
        let report = retain(comparison.clone(), Some(observation.clone())).unwrap();
        assert_eq!(report["original_case_argv_path"], observation);
        assert_eq!(retain(comparison.clone(), None), comparison);
    }
}
