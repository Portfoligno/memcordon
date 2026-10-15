#[path = "../../../crates/memcordon-core/tests/support/windows_frontend_guardian.rs"]
mod support;
use memcordon_ci::windows_readiness_components::{
    frontend_guardian_injection_authority, frontend_kill_observation,
};
use memcordon_core::*;

fn accepts(
    rejection: &WindowsProviderRejectionV2,
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
    let mut response = WindowsProviderResponseV3::Reject {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        attempt_id: terminal.attempt_id.clone(),
        nonce: terminal.nonce.clone(),
        request_sha256: terminal.request_sha256.clone(),
        rejection,
    };
    let before = response.terminal_authority_json().unwrap();
    let WindowsProviderResponseV3::Reject { rejection, .. } = &mut response else {
        unreachable!()
    };
    rejection.guardian_causal_receipt = None;
    assert_eq!(response.terminal_authority_json().unwrap(), before);
}
