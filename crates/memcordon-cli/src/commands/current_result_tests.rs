use super::*;
use memcordon::invocation::{Invocation, route};
use memcordon_core::execution_facts::ProviderAttemptAssociationV1;
use memcordon_core::{
    DiagnosticSha256, WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION, WindowsFrontendDeliveryV3,
    WindowsProviderResponseV4, WindowsTerminalPayloadV3,
};
use sha2::{Digest, Sha256};
use std::time::Duration;

#[path = "../../../memcordon-core/tests/support/windows_current_postauthorization.rs"]
mod terminal_fixture;

#[test]
fn windows_guardian_loss_result_requires_the_original_frontend_acknowledgment() {
    let Invocation::Execute(args) = route(&["--sealed".into(), "receipt-fixture-target".into()])
        .expect("valid fixture invocation")
    else {
        panic!("expected execution");
    };
    let command = CommandSpec::new("receipt-fixture-target");
    let policy = Policy::default().with_boundary(BoundaryRequirement::Sealed);
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
        ..BackendCapabilityReport::default()
    };
    let resolution = Resolution {
        report: unresolved_report(&args.policy, &args.budgets),
        policy: policy.clone(),
        backend: backend.clone(),
        restart: RestartPolicy::Never,
    };
    let request = SupervisorRequest {
        policy,
        restart: RestartPolicy::Never,
        command: command.clone(),
        memcordon_executable: None,
        #[cfg(target_os = "linux")]
        workload_frontend: None,
        resolved_backend: Some(backend),
    };
    let rejection = terminal_fixture::rejection();
    let terminal = rejection.terminal_receipt().unwrap();
    let projection = rejection.provider_failure.clone().unwrap();
    let WindowsTerminalPayloadV3::Execution {
        child_pid,
        authorization_offset_millis,
        outcome,
        ..
    } = &terminal.payload
    else {
        panic!("expected postauthorization execution");
    };
    let response = WindowsProviderResponseV4::Reject {
        schema_version: WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,
        attempt_id: terminal.attempt_id.clone(),
        nonce: terminal.nonce.clone(),
        request_sha256: terminal.request_sha256.clone(),
        rejection: rejection.clone(),
    };
    let authority = response.terminal_authority_json().unwrap();
    let acknowledged = WindowsFrontendDeliveryV3 {
        attempt_id: terminal.attempt_id.clone(),
        nonce: terminal.nonce.clone(),
        request_sha256: terminal.request_sha256.clone(),
        terminal_sha256: DiagnosticSha256::from_bytes(Sha256::digest(authority).into()).into(),
        retired_sha256: "42".repeat(32),
        terminal_validated: true,
        acknowledgement_observed: true,
    };
    let mut unacknowledged = acknowledged.clone();
    unacknowledged.acknowledgement_observed = false;
    let mut wrong_terminal = acknowledged.clone();
    wrong_terminal.terminal_sha256 = "43".repeat(32);
    let mut wrong_nonce = acknowledged.clone();
    wrong_nonce.nonce = "other-attempt-nonce".into();
    for (delivery, expected) in [
        (None, None),
        (Some(unacknowledged), None),
        (Some(wrong_terminal), None),
        (Some(wrong_nonce), None),
        (Some(acknowledged.clone()), Some(&acknowledged)),
    ] {
        let mut error = Error::new(
            ErrorCategory::Setup,
            "MCSEALED-PROVIDER-REJECTION",
            &rejection.detail,
        )
        .with_boundary_setup_failure(memcordon_core::BoundarySetupFailure {
            requested: BoundaryRequirement::Sealed,
            mechanism: Some("windows-job-object-v2".into()),
            phase: rejection.phase,
            target_created: rejection.target_created,
            target_released: rejection.target_released,
            cleanup_attempted: rejection.cleanup_attempted,
            restart_safety: rejection.restart_safety.clone(),
        })
        .with_windows_provider_rejection_v3(rejection.clone());
        error.provider_association = Some(Box::new(ProviderAttemptAssociationV1 {
            provider: projection.provider_binding.clone(),
            attempt_id: projection.attempt_id.clone(),
            request_sha256: projection.request_sha256.clone(),
        }));
        error.provider_failure = Some(Box::new(projection.clone()));
        error.target_pid = Some(*child_pid);
        error.authorization_offset = Some(Duration::from_millis(*authorization_offset_millis));
        error.cleanup = outcome.cleanup().clone();
        error.windows_frontend_delivery = delivery;
        let direct = failure(&args, &command, &resolution.report, &error, 125).unwrap();
        let supervised =
            memcordon_platform::test_support::supervise_failed_attempt(request.clone(), error)
                .unwrap();
        let supervised = success(&args, &command, &resolution, &supervised).unwrap();
        for report in [direct, supervised] {
            assert_eq!(report.release, ReleaseKnowledgeV3::Released);
            assert_eq!(report.outcome.kind, OutcomeKindV1::ProviderFailure);
            assert_eq!(report.outcome.wrapper_status, 125);
            assert_eq!(report.provider_failure.as_ref(), Some(&projection));
            assert_eq!(report.windows_rejection.as_deref(), Some(&rejection));
            let RuntimeExecutionV3::WindowsSealed { native, .. } = &report.runtime else {
                panic!("native retirement should still be present");
            };
            assert_eq!(
                native.retirement.as_deref(),
                Some(&terminal.retirement_proof)
            );
            assert_eq!(native.frontend_delivery.as_ref(), expected);
            assert_eq!(
                report.cleanup.state,
                if expected.is_some() {
                    CleanupStateV1::Complete
                } else {
                    CleanupStateV1::Incomplete
                }
            );
            assert_eq!(
                report
                    .cleanup
                    .obligations
                    .as_slice()
                    .iter()
                    .filter(|obligation| !obligation.settled)
                    .map(|obligation| obligation.resource)
                    .collect::<Vec<_>>(),
                if expected.is_some() {
                    Vec::new()
                } else {
                    vec![CleanupResourceV3::Record]
                }
            );
        }
    }
}
