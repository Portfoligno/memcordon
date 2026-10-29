#[path = "../../../crates/memcordon-core/tests/support/windows_current_frontend_guardian.rs"]
mod support;
use memcordon_ci::windows_readiness_components::{
    frontend_guardian_injection_authority, frontend_kill_observation,
};
use memcordon_core::*;

fn accepts(
    rejection: &WindowsProviderRejectionV3,
    live: &WindowsGuardianAttemptObservation,
    action: &serde_json::Value,
) -> bool {
    let identity: WindowsProcessIdentityV1 =
        serde_json::from_value(action["process"].clone()).unwrap();
    let Some(killed) = frontend_kill_observation(action, &identity, 0xc000013a) else {
        return false;
    };
    frontend_guardian_injection_authority(
        rejection,
        WindowsSealedFault::FrontendKilledAfterAuthorization,
        &live.association.provider,
        &String::from(live.association.attempt_id.clone()),
        &String::from(live.association.request_sha256.clone()),
        live,
        &killed,
    )
}

#[test]
fn precise_guardian_first_frontend_kill_requires_complete_bound_cause() {
    let (rejection, live, action, _) = support::fixture();
    assert!(accepts(&rejection, &live, &action));
    let mut missing = rejection.clone();
    missing.guardian_causal_receipt = None;
    assert!(!accepts(&missing, &live, &action));
    for trigger in [
        None,
        Some(WindowsGuardianCleanupTriggerV1::WorkerLost),
        Some(WindowsGuardianCleanupTriggerV1::ServiceStopped),
        Some(WindowsGuardianCleanupTriggerV1::FrontendIdentityUnavailable),
    ] {
        let mut changed = rejection.clone();
        let cause = changed.guardian_causal_receipt.as_mut().unwrap();
        cause.cleanup_trigger = trigger;
        cause.integrity_sha256 = cause.canonical_sha256().unwrap();
        assert!(!accepts(&changed, &live, &action));
    }
    for field in [
        "frontend", "guardian", "worker", "status", "digest", "attempt", "manifest",
    ] {
        let mut changed = rejection.clone();
        let cause = changed.guardian_causal_receipt.as_mut().unwrap();
        match field {
            "frontend" => {
                if let Some(WindowsGuardianCleanupTriggerV1::FrontendLost { frontend, .. }) =
                    &mut cause.cleanup_trigger
                {
                    frontend.creation_time_100ns += 1;
                }
            }
            "guardian" => cause.guardian_identity.creation_time_100ns += 1,
            "worker" => cause.worker_identity.creation_time_100ns += 1,
            "status" => {
                if let Some(WindowsGuardianCleanupTriggerV1::FrontendLost {
                    native_exit_status,
                    ..
                }) = &mut cause.cleanup_trigger
                {
                    *native_exit_status = 1;
                }
            }
            "digest" => cause.integrity_sha256 = "99".repeat(32),
            "attempt" => cause.attempt_id = "99".repeat(32),
            "manifest" => cause.owner_manifest_sha256 = "99".repeat(32),
            _ => unreachable!(),
        }
        if field != "digest" {
            cause.integrity_sha256 = cause.canonical_sha256().unwrap();
        }
        assert!(!accepts(&changed, &live, &action), "accepted {field}");
    }
    for field in [
        "requested_exit_status",
        "controller_release_observed",
        "target_authorization_observed",
    ] {
        let mut changed = action.clone();
        changed[field] = serde_json::Value::Null;
        assert!(!accepts(&rejection, &live, &changed));
    }
    let mut changed = rejection.clone();
    let diagnostic = changed.provider_failure.as_mut().unwrap();
    let mut journal = WindowsCausalDiagnosticsV1::default();
    let OriginalFailureV1::Observed { event } = diagnostic.original.clone() else {
        unreachable!()
    };
    journal
        .observe(diagnostic.secondary.as_slice()[0].clone())
        .unwrap();
    journal.observe(event).unwrap();
    *diagnostic = ProviderFailureDiagnosticV1::from_journal(
        diagnostic.provider_binding.clone(),
        &String::from(diagnostic.attempt_id.clone()),
        &String::from(diagnostic.request_sha256.clone()),
        &journal,
    )
    .unwrap();
    assert!(!accepts(&changed, &live, &action));
}

#[test]
fn optional_causal_projection_never_changes_ack_authority() {
    let (rejection, _, _, _) = support::fixture();
    let terminal = rejection.terminal_receipt().unwrap();
    let mut response = WindowsProviderResponseV4::Reject {
        schema_version: WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,
        attempt_id: terminal.attempt_id.clone(),
        nonce: terminal.nonce.clone(),
        request_sha256: terminal.request_sha256.clone(),
        rejection,
    };
    let before = response.terminal_authority_json().unwrap();
    let WindowsProviderResponseV4::Reject { rejection, .. } = &mut response else {
        unreachable!()
    };
    rejection.guardian_causal_receipt = None;
    assert_eq!(response.terminal_authority_json().unwrap(), before);
}

fn disconnect_fixture() -> (
    WindowsProviderRejectionV3,
    WindowsGuardianAttemptObservation,
    serde_json::Value,
    WindowsProcessIdentityV1,
) {
    let (mut rejection, live, mut action, _) = support::fixture();
    let diagnostic = rejection.provider_failure.as_ref().unwrap();
    let mut journal = WindowsCausalDiagnosticsV1::default();
    let OriginalFailureV1::Observed { event } = &diagnostic.original else {
        panic!("actual original guardian cause required")
    };
    journal.observe(event.clone()).unwrap();
    let mut secondary = diagnostic.secondary.as_slice()[0].clone();
    secondary.sequence = 0;
    secondary.safe_detail = SafeDiagnosticDetailV1::InjectedWindowsFault {
        fault: WindowsSealedFault::FrontendDisconnectedAfterAuthorization,
    };
    journal.observe(secondary).unwrap();
    rejection.provider_failure = Some(
        ProviderFailureDiagnosticV1::from_journal(
            diagnostic.provider_binding.clone(),
            &String::from(diagnostic.attempt_id.clone()),
            &String::from(diagnostic.request_sha256.clone()),
            &journal,
        )
        .unwrap(),
    );
    let guardian = rejection.guardian_causal_receipt.as_mut().unwrap();
    let Some(WindowsGuardianCleanupTriggerV1::FrontendLost {
        native_exit_status, ..
    }) = &mut guardian.cleanup_trigger
    else {
        panic!("actual frontend-loss trigger required")
    };
    *native_exit_status = 125;
    guardian.integrity_sha256 = guardian.canonical_sha256().unwrap();
    action["kind"] = "disconnect-public-channel".into();
    action["requested_exit_status"] = serde_json::Value::Null;
    let held = serde_json::from_value(action["process"].clone()).unwrap();
    assert!(rejection.is_consistent());
    rejection
        .terminal_receipt()
        .unwrap()
        .validate_for_attempt()
        .unwrap();
    (rejection, live, action, held)
}

fn accepts_disconnect(
    rejection: &WindowsProviderRejectionV3,
    live: &WindowsGuardianAttemptObservation,
    action: &serde_json::Value,
    held: &WindowsProcessIdentityV1,
) -> bool {
    let Some(disconnected) =
        memcordon_ci::windows_readiness_components::frontend_disconnect_observation(
            action, held, 125,
        )
    else {
        return false;
    };
    frontend_guardian_injection_authority(
        rejection,
        WindowsSealedFault::FrontendDisconnectedAfterAuthorization,
        &live.association.provider,
        &String::from(live.association.attempt_id.clone()),
        &String::from(live.association.request_sha256.clone()),
        live,
        &disconnected,
    )
}

#[test]
fn guardian_first_disconnect_requires_its_own_actual_frontend_loss_witness() {
    let (rejection, live, action, held) = disconnect_fixture();
    assert!(accepts_disconnect(&rejection, &live, &action, &held));
    let witness = memcordon_ci::windows_readiness_components::frontend_disconnect_observation(
        &action, &held, 125,
    )
    .unwrap();
    for selected in [
        WindowsSealedFault::FrontendKilledAfterAuthorization,
        WindowsSealedFault::AllJobOwnersClosedAfterAuthorization,
        WindowsSealedFault::GuardianKilledAfterAuthorization,
    ] {
        assert!(!frontend_guardian_injection_authority(
            &rejection,
            selected,
            &live.association.provider,
            &String::from(live.association.attempt_id.clone()),
            &String::from(live.association.request_sha256.clone()),
            &live,
            &witness,
        ));
    }
    let (_, _, killed_action, _) = support::fixture();
    let killed = frontend_kill_observation(&killed_action, &held, 0xc000013a).unwrap();
    assert!(!frontend_guardian_injection_authority(
        &rejection,
        WindowsSealedFault::FrontendDisconnectedAfterAuthorization,
        &live.association.provider,
        &String::from(live.association.attempt_id.clone()),
        &String::from(live.association.request_sha256.clone()),
        &live,
        &killed,
    ));
}

#[test]
fn disconnect_witness_rejects_unbound_actions_status_and_incomplete_release() {
    let (_, _, action, held) = disconnect_fixture();
    let observe = memcordon_ci::windows_readiness_components::frontend_disconnect_observation;
    for status in [0, 1, 0xc000013a] {
        assert!(observe(&action, &held, status).is_none());
    }
    for (field, value) in [
        ("format", serde_json::json!("unrelated-action")),
        ("revision", serde_json::json!(2)),
        ("kind", serde_json::json!("exit-process")),
        ("target_authorization_observed", serde_json::json!(false)),
        ("controller_release_observed", serde_json::json!(false)),
        ("requested_exit_status", serde_json::json!(125)),
    ] {
        let mut changed = action.clone();
        changed[field] = value;
        assert!(observe(&changed, &held, 125).is_none(), "accepted {field}");
    }
    let mut absent = action.clone();
    absent
        .as_object_mut()
        .unwrap()
        .remove("requested_exit_status");
    assert!(observe(&absent, &held, 125).is_none());
    let mut foreign = held.clone();
    foreign.creation_time_100ns += 1;
    assert!(observe(&action, &foreign, 125).is_none());
    foreign = held.clone();
    foreign.process_id += 1;
    assert!(observe(&action, &foreign, 125).is_none());
}

#[test]
fn disconnected_guardian_receipt_requires_original_attempt_root_and_exact_cause() {
    let (rejection, live, action, held) = disconnect_fixture();
    for (pointer, value) in [
        (
            "/association/provider/source_commit",
            serde_json::json!("99".repeat(20)),
        ),
        (
            "/association/attempt_id",
            serde_json::json!("99".repeat(32)),
        ),
        (
            "/association/request_sha256",
            serde_json::json!("99".repeat(32)),
        ),
        ("/live_nonce", serde_json::json!("99".repeat(32))),
        (
            "/live_target_identity/creation_time_100ns",
            serde_json::json!(1),
        ),
        (
            "/guardian_identity/creation_time_100ns",
            serde_json::json!(1),
        ),
        (
            "/worker_process_identity/creation_time_100ns",
            serde_json::json!(1),
        ),
    ] {
        let mut changed = serde_json::to_value(&live).unwrap();
        *changed.pointer_mut(pointer).unwrap() = value;
        let changed = serde_json::from_value(changed).unwrap();
        assert!(
            !accepts_disconnect(&rejection, &changed, &action, &held),
            "accepted {pointer}"
        );
    }
    let mut missing = rejection.clone();
    missing.guardian_causal_receipt = None;
    assert!(!accepts_disconnect(&missing, &live, &action, &held));
    let mut wrong_trigger = rejection.clone();
    let guardian = wrong_trigger.guardian_causal_receipt.as_mut().unwrap();
    guardian.cleanup_trigger = Some(WindowsGuardianCleanupTriggerV1::WorkerLost);
    guardian.integrity_sha256 = guardian.canonical_sha256().unwrap();
    assert!(!accepts_disconnect(&wrong_trigger, &live, &action, &held));
    let (wrong_fault, _, _, _) = support::fixture();
    assert!(!accepts_disconnect(&wrong_fault, &live, &action, &held));
    let mut natural = rejection.clone();
    let WindowsProviderRejectionDispositionV3::PostauthorizationFailure { receipt } =
        &mut natural.disposition
    else {
        panic!("actual original postauthorization receipt required")
    };
    let WindowsTerminalPayloadV3::Execution { outcome, .. } = &mut receipt.payload else {
        panic!("actual original execution receipt required")
    };
    *outcome = RunOutcome::Exited {
        child: ChildTermination::ExitCode { code: 0 },
        peak: None,
        cleanup: outcome.cleanup().clone(),
    };
    assert!(!accepts_disconnect(&natural, &live, &action, &held));
    let mut invalid_receipt = rejection.clone();
    let WindowsProviderRejectionDispositionV3::PostauthorizationFailure { receipt } =
        &mut invalid_receipt.disposition
    else {
        panic!("actual original postauthorization receipt required")
    };
    receipt.schema_version = 0;
    assert!(!accepts_disconnect(&invalid_receipt, &live, &action, &held));
}
