#[path = "../../../crates/memcordon-core/tests/support/windows_frontend_guardian.rs"]
mod support;
use memcordon_ci::windows_readiness_components::{
    ControlServiceRetirement, control_retirement_matches, control_service_loss_observation,
    control_service_recovery_authority,
};
use memcordon_core::*;

fn fixture() -> (
    WindowsProviderResponseV3,
    WindowsTerminalDeliveryEvidenceV1,
    WindowsGuardianAttemptObservation,
    WindowsControlWorkerSiteV1,
    ControlServiceRetirement,
) {
    let (mut rejection, live, _, _) = support::fixture();
    let failure = rejection.provider_failure.as_ref().unwrap();
    let mut journal = WindowsCausalDiagnosticsV1::default();
    let OriginalFailureV1::Observed { event } = &failure.original else {
        panic!("original guardian failure required")
    };
    journal.observe(event.clone()).unwrap();
    let mut secondary = failure.secondary.as_slice()[0].clone();
    secondary.sequence = 0;
    secondary.safe_detail = SafeDiagnosticDetailV1::InjectedWindowsFault {
        fault: WindowsSealedFault::ControlServiceKilledAfterAuthorization,
    };
    journal.observe(secondary).unwrap();
    rejection.provider_failure = Some(
        ProviderFailureDiagnosticV1::from_journal(
            failure.provider_binding.clone(),
            &String::from(failure.attempt_id.clone()),
            &String::from(failure.request_sha256.clone()),
            &journal,
        )
        .unwrap(),
    );
    let cause = rejection.guardian_causal_receipt.as_mut().unwrap();
    let Some(WindowsGuardianCleanupTriggerV1::FrontendLost {
        frontend,
        native_exit_status,
    }) = &mut cause.cleanup_trigger
    else {
        panic!("frontend loss required")
    };
    *native_exit_status = 125;
    let frontend = frontend.clone();
    cause.integrity_sha256 = cause.canonical_sha256().unwrap();
    assert!(rejection.is_consistent());
    let terminal = rejection.terminal_receipt().unwrap();
    terminal.validate_for_attempt().unwrap();
    let site = WindowsControlWorkerSiteV1 {
        format: "memcordon.windows-component-control-worker-site".into(),
        revision: 1,
        attempt_id: terminal.attempt_id.clone(),
        nonce: terminal.nonce.clone(),
        request_sha256: terminal.request_sha256.clone(),
        fault: WindowsSealedFault::ControlServiceKilledAfterAuthorization,
        process: WindowsProcessIdentityV1 {
            process_id: 1984,
            creation_time_100ns: 134371124486562207,
        },
        thread: WindowsWorkerThreadIdentityV1 {
            thread_id: 3720,
            creation_time_100ns: 134371125094626803,
        },
        target_pid: live.live_target_identity.as_ref().unwrap().process_id,
        target_authorization_observed: true,
    };
    let facts = ControlServiceRetirement {
        process: site.process.clone(),
        thread: site.thread,
        process_status: Some(0xc000013a),
        thread_status: 0xc000013a,
        frontend,
        frontend_status: 125,
    };
    let response = WindowsProviderResponseV3::Reject {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        attempt_id: terminal.attempt_id.clone(),
        nonce: terminal.nonce.clone(),
        request_sha256: terminal.request_sha256.clone(),
        rejection,
    };
    let delivery = delivery(&response);
    (response, delivery, live, site, facts)
}

fn delivery(response: &WindowsProviderResponseV3) -> WindowsTerminalDeliveryEvidenceV1 {
    let WindowsProviderResponseV3::Reject {
        attempt_id,
        nonce,
        request_sha256,
        ..
    } = response
    else {
        panic!("rejection required")
    };
    WindowsTerminalDeliveryEvidenceV1 {
        schema_version: 1,
        attempt_id: attempt_id.clone(),
        nonce: nonce.clone(),
        request_sha256: request_sha256.clone(),
        authority_sha256: memcordon_ci::windows_causal_acceptance::sha256(
            response.terminal_authority_json().unwrap().as_bytes(),
        ),
        retired_sha256: "ab".repeat(32),
        retired_confirmed: true,
    }
}

#[test]
fn exact_service_loss_guardian_chain_requires_original_native_witness_and_ack() {
    let (response, ack, live, site, facts) = fixture();
    let witness = control_service_loss_observation(&site, &facts, &live).unwrap();
    assert!(control_service_recovery_authority(
        &response, &ack, &live, &witness
    ));
    let pending = WindowsProviderResponseV3::RecoveryAttemptUnavailable {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        attempt_id: site.attempt_id.clone(),
        challenge: "authenticated-but-pending".into(),
        detail: "exact recovery authority remains retained pending checked closure".into(),
    };
    assert!(!control_service_recovery_authority(
        &pending, &ack, &live, &witness
    ));
    for field in ["retired", "authority", "nonce", "attempt", "request"] {
        let mut changed = ack.clone();
        match field {
            "retired" => changed.retired_confirmed = false,
            "authority" => changed.authority_sha256 = "99".repeat(32),
            "nonce" => changed.nonce = "99".repeat(32),
            "attempt" => changed.attempt_id = "99".repeat(32),
            "request" => changed.request_sha256 = "99".repeat(32),
            _ => unreachable!(),
        }
        assert!(
            !control_service_recovery_authority(&response, &changed, &live, &witness),
            "accepted {field}"
        );
    }
}

#[test]
fn missing_or_mismatched_native_service_retirement_cannot_mint_witness() {
    for mutation in 0..15 {
        let (_, _, live, mut site, mut facts) = fixture();
        match mutation {
            0 => facts.process.process_id += 1,
            1 => facts.process.creation_time_100ns += 1,
            2 => facts.thread.thread_id += 1,
            3 => facts.thread.creation_time_100ns += 1,
            4 => facts.process_status = None,
            5 => facts.process_status = Some(0),
            6 => facts.thread_status = 0,
            7 => facts.frontend_status = 0xc000013a,
            8 => site.fault = WindowsSealedFault::ControlWorkerKilledAfterAuthorization,
            9 => site.target_authorization_observed = false,
            10 => site.nonce = "99".repeat(32),
            11 => site.target_pid += 1,
            12 => site.request_sha256 = "99".repeat(32),
            13 => site.attempt_id = "99".repeat(32),
            14 => facts.thread_status = 125,
            _ => unreachable!(),
        }
        assert!(
            control_service_loss_observation(&site, &facts, &live).is_none(),
            "accepted {mutation}"
        );
    }
    assert!(control_retirement_matches(
        WindowsSealedFault::ControlWorkerKilledAfterAuthorization,
        0,
        false,
        None
    ));
    assert!(!control_retirement_matches(
        WindowsSealedFault::ControlWorkerKilledAfterAuthorization,
        0,
        true,
        Some(0)
    ));
}

#[test]
fn guardian_frontend_and_live_associations_are_exact() {
    let (response, ack, live, site, mut facts) = fixture();
    facts.frontend.creation_time_100ns += 1;
    let witness = control_service_loss_observation(&site, &facts, &live).unwrap();
    assert!(!control_service_recovery_authority(
        &response, &ack, &live, &witness
    ));
    for pointer in [
        "/association/provider/source_commit",
        "/association/attempt_id",
        "/association/request_sha256",
        "/live_nonce",
        "/live_target_identity/creation_time_100ns",
        "/guardian_identity/creation_time_100ns",
        "/worker_process_identity/creation_time_100ns",
    ] {
        let (response, ack, live, site, facts) = fixture();
        let witness = control_service_loss_observation(&site, &facts, &live).unwrap();
        let mut changed = serde_json::to_value(&live).unwrap();
        let value = changed.pointer_mut(pointer).unwrap();
        *value = if value.is_number() {
            serde_json::json!(1)
        } else {
            serde_json::json!("99".repeat(if pointer.ends_with("source_commit") {
                20
            } else {
                32
            }))
        };
        let changed = serde_json::from_value(changed).unwrap();
        assert!(
            !control_service_recovery_authority(&response, &ack, &changed, &witness),
            "accepted {pointer}"
        );
    }
}

#[test]
fn forged_missing_secondary_or_nonmonitor_terminal_never_substitutes() {
    for mutation in 0..9 {
        let (mut response, _, live, site, facts) = fixture();
        let witness = control_service_loss_observation(&site, &facts, &live).unwrap();
        let WindowsProviderResponseV3::Reject { rejection, .. } = &mut response else {
            unreachable!()
        };
        match mutation {
            0 => rejection.guardian_causal_receipt = None,
            1 => {
                rejection
                    .guardian_causal_receipt
                    .as_mut()
                    .unwrap()
                    .integrity_sha256 = "99".repeat(32)
            }
            2 => {
                let cause = rejection.guardian_causal_receipt.as_mut().unwrap();
                cause.cleanup_trigger = Some(WindowsGuardianCleanupTriggerV1::WorkerLost);
                cause.integrity_sha256 = cause.canonical_sha256().unwrap();
            }
            3 | 4 | 5 | 8 => {
                let failure = rejection.provider_failure.as_ref().unwrap();
                let OriginalFailureV1::Observed { event } = &failure.original else {
                    unreachable!()
                };
                let mut journal = WindowsCausalDiagnosticsV1::default();
                if mutation == 5 {
                    journal
                        .observe(failure.secondary.as_slice()[0].clone())
                        .unwrap();
                }
                journal.observe(event.clone()).unwrap();
                if mutation == 4 || mutation == 8 {
                    let mut secondary = failure.secondary.as_slice()[0].clone();
                    if mutation == 4 {
                        secondary.safe_detail = SafeDiagnosticDetailV1::InjectedWindowsFault {
                            fault: WindowsSealedFault::FrontendDisconnectedAfterAuthorization,
                        };
                    } else {
                        secondary.native_code = Some(NativeFailureCodeV1::Win32(5));
                    }
                    journal.observe(secondary).unwrap();
                }
                rejection.provider_failure = Some(
                    ProviderFailureDiagnosticV1::from_journal(
                        failure.provider_binding.clone(),
                        &String::from(failure.attempt_id.clone()),
                        &String::from(failure.request_sha256.clone()),
                        &journal,
                    )
                    .unwrap(),
                );
            }
            6 | 7 => {
                let WindowsProviderRejectionDispositionV2::PostauthorizationFailure { receipt } =
                    &mut rejection.disposition
                else {
                    unreachable!()
                };
                if mutation == 6 {
                    let WindowsTerminalPayloadV2::Execution { outcome, .. } = &mut receipt.payload
                    else {
                        unreachable!()
                    };
                    *outcome = RunOutcome::Exited {
                        child: ChildTermination::ExitCode { code: 0 },
                        peak: None,
                        cleanup: outcome.cleanup().clone(),
                    };
                } else {
                    receipt.schema_version = 0;
                }
            }
            _ => unreachable!(),
        }
        let ack = delivery(&response);
        assert!(
            !control_service_recovery_authority(&response, &ack, &live, &witness),
            "accepted {mutation}"
        );
    }
}
