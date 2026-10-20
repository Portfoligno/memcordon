use memcordon_ci::{consumer_readiness_ledger::SourceIdentity, support_loader_producer::*};
use memcordon_core::result_v1::{AuthorizationV1, CleanupStateV1, LaunchStateV1};
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
fn installed_selection_clamps_original_lease_and_rejects_expiration_or_bad_identity() {
    let challenge = [7; 32];
    let image = "ab".repeat(32);
    let binding = "cd".repeat(32);
    let selected =
        installed_selection(&challenge, &image, &binding, 1_000, 100_000, 200_000).unwrap();
    assert_eq!(selected.work_deadline_unix_ms, 31_000);
    assert_eq!(selected.cleanup_deadline_unix_ms, 61_000);
    assert_eq!(selected.challenge, hex::encode(challenge));
    assert_eq!(selected.support_bootstrap_sha256, image);
    assert_eq!(selected.producer_deadline_sha256, binding);
    let short = installed_selection(&challenge, &image, &binding, 1_000, 2_000, 3_000).unwrap();
    assert_eq!(
        (short.work_deadline_unix_ms, short.cleanup_deadline_unix_ms),
        (2_000, 3_000)
    );
    for (now, work, cleanup) in [
        (2_000, 2_000, 3_000),
        (3_000, 2_000, 3_000),
        (1_000, 3_000, 2_000),
        (u64::MAX - 1, u64::MAX - 1, u64::MAX),
    ] {
        assert!(installed_selection(&challenge, &image, &binding, now, work, cleanup).is_err());
    }
    for (challenge, image, binding) in [
        (&[0; 32][..], image.as_str(), binding.as_str()),
        (&[7; 31][..], image.as_str(), binding.as_str()),
        (&challenge[..], "invalid", binding.as_str()),
        (&challenge[..], image.as_str(), "invalid"),
    ] {
        assert!(installed_selection(challenge, image, binding, 1_000, 2_000, 3_000).is_err());
    }
}

#[test]
fn installed_trigger_requires_exact_provider_and_settled_original_loader_refusal() {
    let original = ResultV1::parse(include_bytes!(
        "fixtures/windows_restricted_launch_failure.json"
    ))
    .unwrap();
    let provider = original
        .provider_association
        .as_ref()
        .unwrap()
        .provider
        .clone();
    assert!(installed_trigger(&original, &provider).unwrap());
    let mut foreign = provider.clone();
    foreign.generation = BoundedText::new("foreign").unwrap();
    assert!(installed_trigger(&original, &foreign).is_err());
    let mut unbound = original.clone();
    unbound.provider_association = None;
    assert!(installed_trigger(&unbound, &provider).is_err());
    for mutation in [
        "authorized",
        "created",
        "cleanup",
        "no-error",
        "other-error",
        "no-operational",
        "foreign-attempt",
        "no-loader",
        "loader-cleanup",
        "other-loader",
        "other-role",
    ] {
        let mut changed = original.clone();
        match mutation {
            "authorized" => changed.authorization = AuthorizationV1::Granted,
            "created" => changed.launch.state = LaunchStateV1::ReleaseIssued,
            "cleanup" => changed.cleanup.state = CleanupStateV1::Unknown,
            "no-error" => changed.attempts.last_mut().unwrap().error = None,
            "other-error" => {
                changed
                    .attempts
                    .last_mut()
                    .unwrap()
                    .error
                    .as_mut()
                    .unwrap()
                    .code = "OTHER".into()
            }
            "no-operational" => changed.attempts.last_mut().unwrap().operational_failure = None,
            "foreign-attempt" => {
                changed
                    .attempts
                    .last_mut()
                    .unwrap()
                    .operational_failure
                    .as_mut()
                    .unwrap()
                    .provider_association
                    .as_mut()
                    .unwrap()
                    .attempt_id = DiagnosticSha256::from_bytes([0xef; 32])
            }
            other => {
                let rejection = changed
                    .attempts
                    .last_mut()
                    .unwrap()
                    .operational_failure
                    .as_mut()
                    .unwrap()
                    .windows_rejection
                    .as_mut()
                    .unwrap();
                if other == "no-loader" {
                    rejection.loader_qualification = None;
                } else {
                    let Some(WindowsLoaderQualificationOutcomeV2::Failed(loader)) =
                        rejection.loader_qualification.as_mut()
                    else {
                        panic!("fixture loader failure")
                    };
                    match other {
                        "loader-cleanup" => {
                            loader.cleanup.status = WindowsLoaderCleanupStatusV1::Failed
                        }
                        "other-loader" => loader.stable_code = "other".into(),
                        "other-role" => loader.detail = "bootstrap_role=other".into(),
                        _ => unreachable!(),
                    }
                }
            }
        }
        assert!(
            !installed_trigger(&changed, &provider).unwrap(),
            "{mutation}"
        );
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
        console_comparison: None,
        process: WindowsProcessIdentityV1 {
            process_id: 7,
            creation_time_100ns: 134364933085222517,
        },
        creator_thread_id: 11,
        challenge: selection.challenge.clone(),
        executable_sha256: selection.support_bootstrap_sha256.clone(),
        launch_plan_sha256: failure.launch_plan_sha256.clone().unwrap(),
        events: vec![
            WindowsLoaderDebugEventV1 {
                image_path_source: None,
                code: 3,
                process_id: 7,
                thread_id: 11,
                exception_code: None,
                first_chance: None,
                address: Some(0x10000),
                native_exit_code: None,
                image_path: Some(
                    String::from_utf16(
                        &serde_json::from_value::<Vec<u16>>(plan["executable_path_utf16"].clone())
                            .unwrap(),
                    )
                    .unwrap(),
                ),
                image_path_error: None,
                continuation: 0x10002,
                continuation_error: None,
            },
            WindowsLoaderDebugEventV1 {
                image_path_source: None,
                code: 5,
                process_id: 7,
                thread_id: 11,
                exception_code: None,
                first_chance: None,
                address: None,
                native_exit_code: Some(0xc0000142),
                image_path: None,
                image_path_error: None,
                continuation: 0x10002,
                continuation_error: None,
            },
        ],
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
    let retired = retirement(&response, &provider);
    (
        FrontendObservation {
            selection: selection.clone(),
            launch: Some(launch),
            caller: Some(caller),
            attempt_id: Some(attempt),
            request_sha256: Some(request),
            authenticated_provider_frames: vec![
                serde_json::to_vec(&response).unwrap(),
                serde_json::to_vec(&WindowsProviderResponseV3::TerminalRetiredV2(retired)).unwrap(),
            ],
            capture_failure: None,
        },
        selection,
        provider,
    )
}

fn retirement(
    response: &WindowsProviderResponseV3,
    provider: &PublicProviderBindingV1,
) -> WindowsTerminalRetiredV2 {
    let WindowsProviderResponseV3::Reject {
        attempt_id,
        nonce,
        request_sha256,
        ..
    } = response
    else {
        panic!("preauthorization refusal required")
    };
    let terminal = hex::encode(sha2::Sha256::digest(
        response.terminal_authority_json().unwrap().as_bytes(),
    ));
    let proof = WindowsPreauthorizationRetirementProofV1 {
        schema_version: 1,
        attempt_id: attempt_id.clone(),
        nonce: nonce.clone(),
        request_sha256: request_sha256.clone(),
        provider_generation: provider.generation.as_str().to_owned(),
        original_boot_id: "modeled-original-boot".into(),
        launch_incarnation: "modeled-launch".into(),
        job_identity: "78".repeat(32),
        terminal_response_sha256: terminal.clone(),
        target_identity: None,
        guardian_identity: Some(WindowsProcessIdentityV1 {
            process_id: 19,
            creation_time_100ns: 134364933085222520,
        }),
        worker_identity: Some(WindowsProcessIdentityV1 {
            process_id: 23,
            creation_time_100ns: 134364933085222521,
        }),
        worker_thread_identity: Some(WindowsWorkerThreadIdentityV1 {
            thread_id: 29,
            creation_time_100ns: 134364933085222522,
        }),
        frozen_owner_manifest_sha256: None,
        target_created: false,
        authorization_unix_millis: None,
        resume_attempted: false,
        target_released: false,
        cleanup_state: WindowsDurableCleanupStateV1 {
            termination_requested: true,
            active_processes_zero: true,
            guardian_reaped: true,
            final_handles_closed: true,
        },
        recorded_target_and_guardian_extinct: true,
    };
    assert!(proof.is_consistent());
    let retired = WindowsTerminalRetiredV2 {
        schema_version: 2,
        attempt_id: attempt_id.clone(),
        nonce: nonce.clone(),
        request_sha256: request_sha256.clone(),
        terminal_response_sha256: terminal,
        disposition: WindowsAttemptTerminalDispositionV1::PreauthorizationAbort,
        provider_generation: provider.generation.as_str().to_owned(),
        original_boot_id: proof.original_boot_id.clone(),
        launch_incarnation: proof.launch_incarnation.clone(),
        job_identity: proof.job_identity.clone(),
        owner_manifest_sha256: String::new(),
        retirement_proof_sha256: proof.canonical_sha256().unwrap(),
        preauthorization_retirement_proof: Some(proof),
        ledger_generation: "90".repeat(32),
        completion: WindowsRetirementLedgerCompletionV1::RetirementComplete,
    };
    assert!(retired.is_consistent_for(
        attempt_id,
        nonce,
        request_sha256,
        &retired.terminal_response_sha256
    ));
    retired
}

#[test]
fn candidate_trace_retains_raw_birth_and_refuses_foreign_or_authorizing_frames() {
    let (valid, selection, provider) = observation();
    let result = validate_frontend(&valid, &selection, &provider).unwrap();
    assert_eq!(result["diagnostic_only"], true);
    assert_eq!(result["certification_authority"], false);
    require_complete_debug_capture(&result).unwrap();
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

#[test]
fn diagnostic_retirement_requires_exact_preauthorization_proof_and_protocol_order() {
    let (valid, selection, provider) = observation();
    require_complete_debug_capture(&validate_frontend(&valid, &selection, &provider).unwrap())
        .unwrap();
    let launch = valid.launch.as_ref().unwrap();
    let mut transport = valid.clone();
    let streams = vec![
        WindowsRemoteStreamV1 {
            role: WindowsStreamRoleV1::Stdin,
            remote_handle: 4,
        },
        WindowsRemoteStreamV1 {
            role: WindowsStreamRoleV1::Stdout,
            remote_handle: 8,
        },
        WindowsRemoteStreamV1 {
            role: WindowsStreamRoleV1::Stderr,
            remote_handle: 12,
        },
    ];
    validate_windows_stream_manifest(&streams).unwrap();
    transport.authenticated_provider_frames.insert(
        0,
        serde_json::to_vec(&WindowsProviderResponseV3::StreamsPrepared {
            schema_version: 3,
            attempt_id: valid.attempt_id.clone().unwrap(),
            nonce: launch.nonce.clone(),
            request_sha256: valid.request_sha256.clone().unwrap(),
            streams,
            relay_retired_event_handle: 16,
        })
        .unwrap(),
    );
    transport.authenticated_provider_frames.insert(
        1,
        serde_json::to_vec(&WindowsProviderResponseV3::RelaysAbort {
            schema_version: 3,
            attempt_id: valid.attempt_id.clone().unwrap(),
            nonce: launch.nonce.clone(),
            request_sha256: valid.request_sha256.clone().unwrap(),
        })
        .unwrap(),
    );
    require_complete_debug_capture(&validate_frontend(&transport, &selection, &provider).unwrap())
        .unwrap();
    for mutation in [
        "missing",
        "no-refusal",
        "reordered",
        "duplicate",
        "duplicate-refusal",
        "after-retirement",
        "attempt",
        "nonce",
        "request",
        "terminal",
        "provider",
        "posttarget",
        "proof-digest",
        "proof-cleanup",
        "missing-proof",
        "legacy-retirement",
        "unmodeled-frame",
    ] {
        let mut changed = valid.clone();
        let mut frame: WindowsProviderResponseV3 =
            serde_json::from_slice(&changed.authenticated_provider_frames[1]).unwrap();
        let WindowsProviderResponseV3::TerminalRetiredV2(retired) = &mut frame else {
            unreachable!()
        };
        match mutation {
            "missing" => {
                changed.authenticated_provider_frames.pop();
            }
            "no-refusal" => {
                changed.authenticated_provider_frames.remove(0);
            }
            "reordered" => changed.authenticated_provider_frames.swap(0, 1),
            "duplicate" => changed
                .authenticated_provider_frames
                .push(changed.authenticated_provider_frames[1].clone()),
            "duplicate-refusal" => changed
                .authenticated_provider_frames
                .insert(1, changed.authenticated_provider_frames[0].clone()),
            "after-retirement" => changed.authenticated_provider_frames.push(
                serde_json::to_vec(&WindowsProviderResponseV3::RelaysAbort {
                    schema_version: 3,
                    attempt_id: retired.attempt_id.clone(),
                    nonce: retired.nonce.clone(),
                    request_sha256: retired.request_sha256.clone(),
                })
                .unwrap(),
            ),
            "attempt" => retired.attempt_id = "a1".repeat(32),
            "nonce" => retired.nonce = "foreign-nonce".into(),
            "request" => retired.request_sha256 = "a2".repeat(32),
            "terminal" => retired.terminal_response_sha256 = "a3".repeat(32),
            "provider" => {
                retired.provider_generation = "foreign-provider".into();
                let proof = retired.preauthorization_retirement_proof.as_mut().unwrap();
                proof.provider_generation = retired.provider_generation.clone();
                retired.retirement_proof_sha256 = proof.canonical_sha256().unwrap();
                assert!(retired.is_consistent_for(
                    &retired.attempt_id,
                    &retired.nonce,
                    &retired.request_sha256,
                    &retired.terminal_response_sha256
                ));
            }
            "posttarget" => {
                retired.disposition = WindowsAttemptTerminalDispositionV1::Posttarget;
                retired.preauthorization_retirement_proof = None;
                retired.owner_manifest_sha256 = "a4".repeat(32);
            }
            "proof-digest" => retired.retirement_proof_sha256 = "a5".repeat(32),
            "proof-cleanup" => {
                let proof = retired.preauthorization_retirement_proof.as_mut().unwrap();
                proof.cleanup_state.active_processes_zero = false;
                retired.retirement_proof_sha256 = proof.canonical_sha256().unwrap();
            }
            "missing-proof" => retired.preauthorization_retirement_proof = None,
            "legacy-retirement" => {
                changed.authenticated_provider_frames[1] = serde_json::to_vec(
                    &WindowsProviderResponseV3::TerminalRetired(WindowsTerminalRetiredV1 {
                        schema_version: 1,
                        attempt_id: retired.attempt_id.clone(),
                        nonce: retired.nonce.clone(),
                        request_sha256: retired.request_sha256.clone(),
                        terminal_response_sha256: retired.terminal_response_sha256.clone(),
                        disposition: WindowsAttemptTerminalDispositionV1::PreauthorizationAbort,
                    }),
                )
                .unwrap()
            }
            "unmodeled-frame" => changed.authenticated_provider_frames.insert(
                0,
                serde_json::to_vec(
                    &WindowsProviderResponseV3::recovery_attempt_unavailable(
                        &retired.attempt_id,
                        "challenge",
                        "unavailable",
                        false,
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            _ => unreachable!(),
        }
        if [
            "attempt",
            "nonce",
            "request",
            "terminal",
            "provider",
            "posttarget",
            "proof-digest",
            "proof-cleanup",
            "missing-proof",
        ]
        .contains(&mutation)
        {
            changed.authenticated_provider_frames[1] = serde_json::to_vec(&frame).unwrap();
        }
        assert!(
            validate_frontend(&changed, &selection, &provider).is_err(),
            "accepted {mutation}"
        );
    }
}

#[test]
fn resume_refusal_with_cleanup_events_is_not_a_completed_loader_capture() {
    let (mut observed, selection, provider) = observation();
    let mut response: WindowsProviderResponseV3 =
        serde_json::from_slice(&observed.authenticated_provider_frames[0]).unwrap();
    let WindowsProviderResponseV3::Reject { rejection, .. } = &mut response else {
        unreachable!()
    };
    let Some(WindowsLoaderQualificationOutcomeV2::Failed(failure)) =
        &mut rejection.loader_qualification
    else {
        unreachable!()
    };
    failure.stage = WindowsLoaderQualificationStageV2::Resume;
    failure.stable_code = "loader-control-resume".into();
    failure.native_status = None;
    let trace = failure.support_debug_observation.as_ref().unwrap();
    assert_eq!(trace.events.first().unwrap().code, 3);
    assert_eq!(trace.events.last().unwrap().code, 5);
    assert!(trace.exit_event_continued);
    assert!(!trace.detached);
    let retired = retirement(&response, &provider);
    observed.authenticated_provider_frames = vec![
        serde_json::to_vec(&response).unwrap(),
        serde_json::to_vec(&WindowsProviderResponseV3::TerminalRetiredV2(retired)).unwrap(),
    ];
    let refusal = validate_frontend(&observed, &selection, &provider).unwrap();
    assert_eq!(refusal["certification_authority"], false);
    assert_eq!(refusal["debug_capture_complete"], false);
    assert!(require_complete_debug_capture(&refusal).is_err());
}

#[test]
fn bound_refusal_with_missing_or_incomplete_debug_evidence_never_claims_capture() {
    let (valid, selection, provider) = observation();
    for mutation in [
        "empty",
        "omitted",
        "detached",
        "exit-uncontinued",
        "wrong-create-pid",
        "missing-create",
        "missing-exit",
        "wrong-exit-pid",
        "missing-exit-status",
        "failed-continuation",
        "wrong-continuation",
        "zero-process-birth",
        "zero-creator-thread",
        "zero-event-thread",
    ] {
        let mut changed = valid.clone();
        let mut response: WindowsProviderResponseV3 =
            serde_json::from_slice(&changed.authenticated_provider_frames[0]).unwrap();
        let WindowsProviderResponseV3::Reject { rejection, .. } = &mut response else {
            unreachable!()
        };
        let Some(WindowsLoaderQualificationOutcomeV2::Failed(failure)) =
            &mut rejection.loader_qualification
        else {
            unreachable!()
        };
        let trace = failure.support_debug_observation.as_mut().unwrap();
        match mutation {
            "empty" => {
                trace.events.clear();
                trace.detached = true;
                trace.exit_event_continued = false;
            }
            "omitted" => trace.omitted_events = 1,
            "detached" => trace.detached = true,
            "exit-uncontinued" => trace.exit_event_continued = false,
            "wrong-create-pid" => trace.events[0].process_id += 1,
            "missing-create" => {
                trace.events.remove(0);
            }
            "missing-exit" => {
                trace.events.pop();
            }
            "wrong-exit-pid" => trace.events.last_mut().unwrap().process_id += 1,
            "missing-exit-status" => trace.events.last_mut().unwrap().native_exit_code = None,
            "failed-continuation" => trace.events[0].continuation_error = Some(5),
            "wrong-continuation" => trace.events[0].continuation = 0x80010001,
            "zero-process-birth" => trace.process.creation_time_100ns = 0,
            "zero-creator-thread" => trace.creator_thread_id = 0,
            "zero-event-thread" => trace.events[0].thread_id = 0,
            _ => unreachable!(),
        }
        changed.authenticated_provider_frames[0] = serde_json::to_vec(&response).unwrap();
        if ["zero-process-birth", "zero-creator-thread"].contains(&mutation) {
            // Existing typed rejection consistency rejects absent native
            // identity before the separate capture-completeness classifier.
            assert!(
                validate_frontend(&changed, &selection, &provider).is_err(),
                "accepted {mutation}"
            );
            continue;
        }
        // These incomplete diagnostics preserve typed refusal consistency and
        // immutable terminal authority, but cannot claim complete capture.
        let refusal = validate_frontend(&changed, &selection, &provider).unwrap();
        assert_eq!(refusal["certification_authority"], false);
        assert_eq!(refusal["debug_capture_complete"], false);
        assert!(
            require_complete_debug_capture(&refusal).is_err(),
            "accepted {mutation}"
        );
    }
}

#[test]
fn console_comparison_requires_complete_same_session_0142_baseline_retirement() {
    let (observed, _, _) = observation();
    let response: memcordon_core::WindowsProviderResponseV3 =
        serde_json::from_slice(&observed.authenticated_provider_frames[0]).unwrap();
    let memcordon_core::WindowsProviderResponseV3::Reject { rejection, .. } = response else {
        panic!("fixture refusal")
    };
    let Some(memcordon_core::WindowsLoaderQualificationOutcomeV2::Failed(mut baseline)) =
        rejection.loader_qualification
    else {
        panic!("fixture loader refusal")
    };
    baseline.stable_code = "loader-control-pipe-accept".into();
    assert!(baseline.admits_detached_console_comparison());
    for dimension in 0..8 {
        let mut invalid = baseline.clone();
        match dimension {
            0 => invalid.cleanup.status = memcordon_core::WindowsLoaderCleanupStatusV1::Failed,
            1 => invalid.stage = memcordon_core::WindowsLoaderQualificationStageV2::Resume,
            2 => {
                invalid
                    .support_debug_observation
                    .as_mut()
                    .unwrap()
                    .omitted_events = 1
            }
            3 => invalid.support_debug_observation.as_mut().unwrap().detached = true,
            4 => {
                invalid
                    .support_debug_observation
                    .as_mut()
                    .unwrap()
                    .exit_event_continued = false
            }
            5 => {
                invalid
                    .support_debug_observation
                    .as_mut()
                    .unwrap()
                    .events
                    .last_mut()
                    .unwrap()
                    .native_exit_code = Some(126)
            }
            6 => {
                invalid.support_debug_observation.as_mut().unwrap().events[0].continuation_error =
                    Some(5)
            }
            _ => invalid
                .support_debug_observation
                .as_mut()
                .unwrap()
                .events
                .clear(),
        }
        assert!(!invalid.admits_detached_console_comparison());
    }
}

#[test]
fn console_comparison_collector_requires_bound_inputs_capture_and_retirement() {
    use memcordon_ci::support_loader_producer::validate_console_comparison;
    use memcordon_core::{
        WindowsLoaderConsoleComparisonOutcomeV1, WindowsLoaderConsoleComparisonV1,
    };
    let (observed, mut selected, _) = observation();
    let response: memcordon_core::WindowsProviderResponseV3 =
        serde_json::from_slice(&observed.authenticated_provider_frames[0]).unwrap();
    let unchanged_response = response.clone();
    let memcordon_core::WindowsProviderResponseV3::Reject { rejection, .. } = response else {
        panic!("fixture refusal")
    };
    let Some(memcordon_core::WindowsLoaderQualificationOutcomeV2::Failed(failure)) =
        rejection.loader_qualification
    else {
        panic!("fixture loader refusal")
    };
    let plan_json = failure.launch_plan_json.as_ref().unwrap();
    let plan: memcordon_windows_launch_core::ProductionLoaderPlanV1 =
        serde_json::from_str(plan_json).unwrap();
    let descriptor = memcordon_windows_launch_core::SupportDetachedConsolePlanV1::new(
        plan.clone(),
        plan.launch_plan_sha256().into(),
        selected.challenge.clone(),
    )
    .unwrap();
    let json = serde_json::to_string(&descriptor).unwrap();
    let mut baseline = *failure.support_debug_observation.unwrap();
    let mut variant = baseline.clone();
    variant.process.process_id += 1;
    variant.process.creation_time_100ns += 1;
    variant.launch_plan_sha256 = descriptor.diagnostic_plan_sha256().into();
    for event in &mut variant.events {
        event.process_id = variant.process.process_id;
    }
    // The altered policy reached handshake, then the existing mandatory
    // diagnostic Job cleanup terminates it with the real bootstrap status.
    variant.events.last_mut().unwrap().native_exit_code = Some(0xed140000);
    baseline.console_comparison = Some(Box::new(WindowsLoaderConsoleComparisonV1 {
        schema_version: 1,
        baseline_plan_sha256: baseline.launch_plan_sha256.clone(),
        actual_creation_flags: descriptor.actual_creation_flags(),
        diagnostic_plan_json_sha256: Some(hex::encode(sha2::Sha256::digest(json.as_bytes()))),
        diagnostic_plan_json: Some(json),
        outcome: WindowsLoaderConsoleComparisonOutcomeV1::ReachedHandshake,
        cleanup: memcordon_core::WindowsLoaderCleanupOutcomeV1 {
            status: memcordon_core::WindowsLoaderCleanupStatusV1::Complete,
            stable_code: None,
        },
        debug_observation: Some(Box::new(variant)),
    }));
    selected.kind =
        memcordon_core::WindowsLoaderDiagnosticKindV1::OriginalRestrictedBootstrapConsoleComparison;
    let mut with_diagnostic = unchanged_response.clone();
    if let memcordon_core::WindowsProviderResponseV3::Reject { rejection, .. } =
        &mut with_diagnostic
        && let Some(memcordon_core::WindowsLoaderQualificationOutcomeV2::Failed(failure)) =
            &mut rejection.loader_qualification
    {
        failure.support_debug_observation = Some(Box::new(baseline.clone()));
    }
    assert_eq!(
        unchanged_response.terminal_authority_json().unwrap(),
        with_diagnostic.terminal_authority_json().unwrap()
    );
    let result = validate_console_comparison(&baseline, &selected, Some(plan_json)).unwrap();
    assert_eq!(result["available"], true);
    assert_eq!(result["reached_handshake"], true);
    assert_eq!(result["certification_authority"], false);
    let mut no_retirement = baseline.clone();
    no_retirement
        .console_comparison
        .as_mut()
        .unwrap()
        .cleanup
        .status = memcordon_core::WindowsLoaderCleanupStatusV1::Failed;
    no_retirement
        .console_comparison
        .as_mut()
        .unwrap()
        .cleanup
        .stable_code = Some("original-owner-retained".into());
    let result = validate_console_comparison(&no_retirement, &selected, Some(plan_json)).unwrap();
    assert_eq!(result["available"], false);
    assert_eq!(result["reached_handshake"], false);
    let mut incomplete = baseline.clone();
    incomplete
        .console_comparison
        .as_mut()
        .unwrap()
        .debug_observation
        .as_mut()
        .unwrap()
        .omitted_events = 1;
    assert_eq!(
        validate_console_comparison(&incomplete, &selected, Some(plan_json)).unwrap()["available"],
        false
    );
    let mut foreign = selected.clone();
    foreign.challenge = "98".repeat(32);
    assert!(validate_console_comparison(&baseline, &foreign, Some(plan_json)).is_err());
    let mut flags = baseline.clone();
    flags
        .console_comparison
        .as_mut()
        .unwrap()
        .actual_creation_flags = 0x80404;
    assert!(validate_console_comparison(&flags, &selected, Some(plan_json)).is_err());
    let mut trace = baseline.clone();
    trace
        .console_comparison
        .as_mut()
        .unwrap()
        .debug_observation
        .as_mut()
        .unwrap()
        .launch_plan_sha256 = "12".repeat(32);
    assert!(validate_console_comparison(&trace, &selected, Some(plan_json)).is_err());
    selected.kind = memcordon_core::WindowsLoaderDiagnosticKindV1::OriginalRestrictedBootstrap;
    assert!(validate_console_comparison(&baseline, &selected, Some(plan_json)).is_err());
}

#[test]
fn consoleless_comparison_is_inapplicable_without_diagnostic_authority() {
    use memcordon_ci::support_loader_producer::validate_console_comparison;
    use memcordon_core::{
        WindowsLoaderConsoleComparisonOutcomeV1 as Outcome, WindowsLoaderConsoleComparisonV1,
    };
    use memcordon_windows_launch_core::{
        ProductionLoaderPlanInputV1, ProductionLoaderPlanV1, build_package_loader_plan_v2,
    };
    let (observed, mut selected, _) = observation();
    let response: memcordon_core::WindowsProviderResponseV3 =
        serde_json::from_slice(&observed.authenticated_provider_frames[0]).unwrap();
    let memcordon_core::WindowsProviderResponseV3::Reject { rejection, .. } = response else {
        panic!("fixture refusal")
    };
    let Some(memcordon_core::WindowsLoaderQualificationOutcomeV2::Failed(failure)) =
        rejection.loader_qualification
    else {
        panic!("fixture failure")
    };
    let legacy_json = failure.launch_plan_json.unwrap();
    let legacy: ProductionLoaderPlanV1 = serde_json::from_str(&legacy_json).unwrap();
    let plan = build_package_loader_plan_v2(ProductionLoaderPlanInputV1 {
        executable_path_utf16: legacy.executable_path_utf16().to_vec(),
        executable_sha256: legacy.executable_sha256().into(),
        command_line_sha256: legacy.command_line_sha256().into(),
        environment: legacy.environment().clone(),
        current_directory_sha256: legacy.current_directory_sha256().into(),
        desktop: legacy.desktop().clone(),
        process_security_descriptor_sddl: legacy.process_security_descriptor_sddl().into(),
        thread_security_descriptor_sddl: legacy.thread_security_descriptor_sddl().into(),
        job_security_descriptor_sddl: legacy.job_security_descriptor_sddl().into(),
        loader_ready_pipe_security_descriptor_sddl: legacy
            .loader_ready_pipe_security_descriptor_sddl()
            .into(),
        target_token: legacy.target_token().clone(),
        inherited_handles: legacy.inherited_handles().clone(),
        job_at_creation: legacy.job_at_creation(),
    })
    .unwrap();
    let json = serde_json::to_string(&plan).unwrap();
    let mut baseline = *failure.support_debug_observation.unwrap();
    baseline.launch_plan_sha256 = plan.launch_plan_sha256().into();
    baseline.console_comparison = Some(Box::new(WindowsLoaderConsoleComparisonV1 {
        schema_version: 1,
        baseline_plan_sha256: baseline.launch_plan_sha256.clone(),
        actual_creation_flags: 0,
        diagnostic_plan_json_sha256: None,
        diagnostic_plan_json: None,
        outcome: Outcome::NotApplicable {
            baseline_schema_version: 2,
        },
        cleanup: memcordon_core::WindowsLoaderCleanupOutcomeV1 {
            status: memcordon_core::WindowsLoaderCleanupStatusV1::NotStarted,
            stable_code: None,
        },
        debug_observation: None,
    }));
    selected.kind =
        memcordon_core::WindowsLoaderDiagnosticKindV1::OriginalRestrictedBootstrapConsoleComparison;
    let result = validate_console_comparison(&baseline, &selected, Some(&json)).unwrap();
    assert_eq!(result["applicable"], false);
    assert_eq!(result["certification_authority"], false);
    assert_ne!(result["available"], true);
    assert_ne!(result["reached_handshake"], true);
    assert!(validate_console_comparison(&baseline, &selected, Some(&legacy_json)).is_err());
    assert!(validate_console_comparison(&baseline, &selected, None).is_err());
    for dimension in 0..6 {
        let mut changed = baseline.clone();
        let comparison = changed.console_comparison.as_mut().unwrap();
        match dimension {
            0 => comparison.baseline_plan_sha256 = "cd".repeat(32),
            1 => {
                comparison.outcome = Outcome::NotApplicable {
                    baseline_schema_version: 1,
                }
            }
            2 => comparison.cleanup.status = memcordon_core::WindowsLoaderCleanupStatusV1::Complete,
            3 => comparison.debug_observation = Some(Box::new(baseline.clone())),
            4 => comparison.diagnostic_plan_json = Some(legacy_json.clone()),
            _ => comparison.actual_creation_flags = legacy.creation_flags(),
        }
        assert!(
            validate_console_comparison(&changed, &selected, Some(&json)).is_err(),
            "dimension {dimension}"
        );
    }
}
