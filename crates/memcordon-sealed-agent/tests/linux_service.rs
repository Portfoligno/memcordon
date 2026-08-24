#![cfg(all(target_os = "linux", feature = "test-support"))]

use memcordon_sealed_agent::linux::qualification::QualificationReceipt;
use memcordon_sealed_agent::protocol::{Frame, MessageKind};
use memcordon_sealed_agent::rejection::{RejectionPhaseV1, RejectionV1};

fn qualification() -> QualificationReceipt {
    QualificationReceipt {
        schema_version: 2,
        mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
        provider_identity: "memcordon-sealed-agent-v2".to_owned(),
        control_service_identity: "memcordon-sealed-agent.service:v2".to_owned(),
        launcher_service_identity: "memcordon-sealed-launcher.service:v2".to_owned(),
        receipt_digest: "0".repeat(64),
        unified_cgroup_v2: true,
        private_cgroup_subtree: true,
        clone3: true,
        clone3_into_cgroup: true,
        pid_namespace: true,
        mount_namespace: true,
        cgroup_namespace: true,
        pidfd: true,
        close_range: true,
        guardian_outside_boundary: true,
        target_gated: true,
        assignment_verified: true,
        inherited_descriptors_verified: true,
        spawn_error_reporting_verified: true,
        frontend_loss_authority_verified: true,
        cgroup_kill: true,
        workload_empty: true,
        helpers_reaped: true,
        boundary_retired: true,
        recovery_complete: true,
        split_control_and_launcher_services: true,
        launcher_no_new_privs_disabled: true,
        caller_mount_namespace_reproduction_verified: true,
        caller_no_new_privs_reproduction_verified: true,
        caller_capability_bounding_set_reproduction_verified: true,
        initial_provider_capabilities_absent: true,
        credential_transition_disposition: "preserve-caller-envelope".to_owned(),
        setid_transition_certification_digest: "1".repeat(64),
        sudo_transition_certification_digest: "2".repeat(64),
        post_transition_cgroup_membership_verified: true,
        post_transition_pid_namespace_verified: true,
        post_transition_cleanup_verified: true,
        recursive_provider_request_rejected: true,
    }
}

#[test]
fn probe_returns_the_cached_startup_qualification_without_requalifying() {
    let request = Frame {
        kind: MessageKind::Probe,
        nonce: [7; 16],
        attempt_id: [0; 16],
        payload: Vec::new(),
    };
    let qualification = qualification();

    let response = memcordon_sealed_agent::linux::service::cached_probe_response_for_test(
        &request,
        0,
        &qualification,
    );

    assert_eq!(response.kind, MessageKind::ProbeReceipt);
    assert_eq!(response.nonce, request.nonce);
    assert_eq!(response.attempt_id, request.attempt_id);
    assert_eq!(response.payload, qualification.render().into_bytes());
}

#[test]
fn probe_with_descriptors_receives_a_typed_rejection() {
    let request = Frame {
        kind: MessageKind::Probe,
        nonce: [9; 16],
        attempt_id: [0; 16],
        payload: Vec::new(),
    };

    let response = memcordon_sealed_agent::linux::service::cached_probe_response_for_test(
        &request,
        1,
        &qualification(),
    );

    assert_eq!(response.kind, MessageKind::Rejected);
    assert_eq!(response.nonce, request.nonce);
    let rejection: RejectionV1 =
        serde_json::from_slice(&response.payload).expect("rejection must be typed JSON");
    rejection.validate().expect("rejection must validate");
    assert_eq!(rejection.schema_version, 1);
    assert_eq!(rejection.code, "MCSEALED-PROVIDER-REJECTION");
    assert_eq!(rejection.phase, RejectionPhaseV1::RequestValidation);
    assert!(rejection.detail.contains("must not carry descriptors"));
    assert!(!rejection.target_created);
    assert!(!rejection.cleanup.attempted);
}

#[test]
fn peer_authorization_requires_root_or_exact_access_group() {
    let authorized = memcordon_sealed_agent::linux::service::peer_is_authorized_for_test;
    assert!(authorized(0, 0, &[], 81));
    assert!(authorized(1000, 81, &[], 81));
    assert!(authorized(1000, 1000, &[7, 81, 90], 81));
    assert!(!authorized(1000, 1000, &[7, 80, 90], 81));
    assert!(!authorized(1000, 1000, &[], 81));
}
