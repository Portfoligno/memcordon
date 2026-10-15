use memcordon_ci::{consumer_readiness_ledger::SourceIdentity, support_loader_producer::*};
use memcordon_core::*;
use serde_json::Value;
use sha2::Digest;

fn source() -> SourceIdentity {
    SourceIdentity {
        run_id: "measured-diagnostic-run".into(),
        source_commit: "ab".repeat(20),
        source_tree_sha256: "cd".repeat(32),
        version: "0.5.8-dev".into(),
    }
}

#[test]
fn separate_operation_cutoffs_never_renew_expired_work_or_cleanup() {
    let deadline = DiagnosticDeadline::at(
        source(),
        "aarch64-pc-windows-msvc".into(),
        "ef".repeat(32),
        1000,
    )
    .unwrap();
    let origin = std::time::Instant::now();
    let (work, cleanup) = deadline.remaining_at(origin, 1000).unwrap();
    assert_eq!(work.duration_since(origin), PREPARATION + BOOTSTRAP_WORK);
    assert_eq!(cleanup.duration_since(work), BOOTSTRAP_CLEANUP);
    assert!(
        deadline
            .remaining_at(origin, deadline.work_deadline_unix_millis)
            .is_err()
    );
    let (expired, remaining) = deadline
        .remaining_cleanup_at(origin, deadline.work_deadline_unix_millis)
        .unwrap();
    assert_eq!(expired, origin);
    assert_eq!(remaining.duration_since(origin), BOOTSTRAP_CLEANUP);
    assert!(
        deadline
            .remaining_cleanup_at(origin, deadline.cleanup_deadline_unix_millis)
            .is_err()
    );
    let mut forged = deadline.clone();
    forged.work_deadline_unix_millis += 1;
    assert!(forged.remaining_at(origin, 1000).is_err());
    assert!(deadline.remaining_at(origin, 999).is_err());
}

fn find_rejection(value: &Value) -> Option<Value> {
    if let Some(object) = value.as_object() {
        if object.contains_key("loader_qualification") && object.contains_key("disposition") {
            return Some(value.clone());
        }
        return object.values().find_map(find_rejection);
    }
    value
        .as_array()
        .and_then(|values| values.iter().find_map(find_rejection))
}

fn observation() -> (
    FrontendObservation,
    WindowsLoaderDiagnosticSelectionV1,
    PublicProviderBindingV1,
) {
    let result: Value = serde_json::from_slice(include_bytes!(
        "fixtures/windows_restricted_launch_failure.json"
    ))
    .unwrap();
    let mut rejection: WindowsProviderRejectionV2 =
        serde_json::from_value(find_rejection(&result).unwrap()).unwrap();
    let provider = rejection
        .provider_failure
        .as_ref()
        .unwrap()
        .provider_binding
        .clone();
    rejection.provider_failure = None;
    let Some(WindowsLoaderQualificationOutcomeV2::Failed(failure)) =
        &mut rejection.loader_qualification
    else {
        panic!("actual fixture loader refusal required")
    };
    let plan: Value = serde_json::from_str(failure.launch_plan_json.as_ref().unwrap()).unwrap();
    let selection = WindowsLoaderDiagnosticSelectionV1 {
        kind: WindowsLoaderDiagnosticKindV1::OriginalRestrictedBootstrap,
        challenge: "12".repeat(32),
        support_bootstrap_sha256: plan["executable_sha256"].as_str().unwrap().into(),
        producer_deadline_sha256: "34".repeat(32),
        work_deadline_unix_ms: 100,
        cleanup_deadline_unix_ms: 200,
    };
    failure.support_debug_observation = Some(Box::new(WindowsLoaderDebugObservationV1 {
        process: WindowsProcessIdentityV1 {
            process_id: 7,
            creation_time_100ns: 134364933085222517,
        },
        creator_thread_id: 11,
        challenge: selection.challenge.clone(),
        executable_sha256: selection.support_bootstrap_sha256.clone(),
        launch_plan_sha256: failure.launch_plan_sha256.clone().unwrap(),
        events: vec![],
        omitted_events: 0,
        detached: false,
        exit_event_continued: true,
    }));
    assert!(rejection.is_consistent());
    let launch:WindowsLaunchRequestV1=serde_json::from_value(serde_json::json!({"restart_attempt":0,"schema_version":3,
        "expected_provider_binding":provider,"workload_contract":null,"loader_diagnostic":selection,
        "nonce":"separate-original-attempt","command":{"program":[120],"arguments":[]},"environment":[],"current_directory":[67,58,92],
        "policy":{"memory_limit_bytes":null,"absolute_deadline_millis":null,"lifetime":"command","poll_interval_millis":10,
        "signal_grace_millis":10,"command_exit_grace_millis":10,"limit_grace_millis":10}})).unwrap();
    let caller = WindowsProcessIdentityV1 {
        process_id: 13,
        creation_time_100ns: 134364933085222519,
    };
    let request = hex::encode(sha2::Sha256::digest(serde_json::to_vec(&launch).unwrap()));
    let mut hash = sha2::Sha256::new();
    hash.update(launch.nonce.as_bytes());
    hash.update(caller.process_id.to_le_bytes());
    hash.update(caller.creation_time_100ns.to_le_bytes());
    hash.update(request.as_bytes());
    let attempt = hex::encode(hash.finalize());
    let response = WindowsProviderResponseV3::Reject {
        schema_version: 3,
        attempt_id: attempt.clone(),
        nonce: launch.nonce.clone(),
        request_sha256: request.clone(),
        rejection,
    };
    (
        FrontendObservation {
            selection: selection.clone(),
            launch: Some(launch),
            caller: Some(caller),
            attempt_id: Some(attempt),
            request_sha256: Some(request),
            authenticated_provider_frames: vec![serde_json::to_vec(&response).unwrap()],
            capture_failure: None,
        },
        selection,
        provider,
    )
}

#[test]
fn candidate_trace_retains_raw_birth_and_refuses_foreign_or_authorizing_frames() {
    let (valid, selection, provider) = observation();
    let result = validate_frontend(&valid, &selection, &provider).unwrap();
    assert_eq!(result["diagnostic_only"], true);
    assert_eq!(result["certification_authority"], false);
    assert!(result["terminal_receipt"].is_null());
    let mut frame: WindowsProviderResponseV3 =
        serde_json::from_slice(&valid.authenticated_provider_frames[0]).unwrap();
    let before = frame.terminal_authority_json().unwrap();
    if let WindowsProviderResponseV3::Reject { rejection, .. } = &mut frame {
        let Some(WindowsLoaderQualificationOutcomeV2::Failed(failure)) =
            &mut rejection.loader_qualification
        else {
            unreachable!()
        };
        assert_eq!(
            failure
                .support_debug_observation
                .as_ref()
                .unwrap()
                .process
                .creation_time_100ns,
            134364933085222517
        );
        failure.support_debug_observation = None;
    }
    assert_eq!(before, frame.terminal_authority_json().unwrap());
    for mutation in [
        "challenge",
        "request",
        "birth",
        "capture",
        "missing",
        "authorized",
        "frame-count",
        "frame-bytes",
        "malformed",
    ] {
        let mut changed = valid.clone();
        match mutation {
            "challenge" => changed.selection.challenge = "56".repeat(32),
            "request" => changed.request_sha256 = Some("56".repeat(32)),
            "birth" => changed.caller.as_mut().unwrap().creation_time_100ns += 1,
            "capture" => changed.capture_failure = Some("bounded omitted frame".into()),
            "missing" => changed.authenticated_provider_frames.clear(),
            "frame-count" => changed.authenticated_provider_frames = vec![Vec::new(); 17],
            "frame-bytes" => {
                changed.authenticated_provider_frames = vec![vec![b' '; 1024 * 1024 + 1]]
            }
            "malformed" => changed.authenticated_provider_frames = vec![b"{".to_vec()],
            "authorized" => changed.authenticated_provider_frames.push(
                serde_json::to_vec(&WindowsProviderResponseV3::TargetAuthorized {
                    schema_version: 3,
                    attempt_id: valid.attempt_id.clone().unwrap(),
                    nonce: valid.launch.as_ref().unwrap().nonce.clone(),
                    request_sha256: valid.request_sha256.clone().unwrap(),
                    child_pid: 17,
                    control_site: None,
                })
                .unwrap(),
            ),
            _ => unreachable!(),
        }
        assert!(
            validate_frontend(&changed, &selection, &provider).is_err(),
            "accepted {mutation}"
        );
    }
}
