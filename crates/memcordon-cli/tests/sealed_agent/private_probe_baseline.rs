#![cfg(target_os = "linux")]

use crate::linux::launch::{ExecFailureClass, TargetExecStatus, TerminalFacts};
use crate::linux::private_probe_baseline::{
    BaselineTerminalProjectionV1, terminal_facts_digest, verify_baseline_terminal,
};
use memcordon_core::workload_evidence::AttemptPolicyEnforcementV1;

// These are validator-only inputs, never native completion or host evidence.
fn test_terminal() -> TerminalFacts {
    TerminalFacts {
        policy_enforcement: AttemptPolicyEnforcementV1::LegacyUnspecified,
        child_status: Some(0),
        policy_revoked: false,
        exec_status: TargetExecStatus::Succeeded,
        spawn_error_reported: true,
        target_pid: 1234,
        authorization_offset_millis: 7,
        cgroup_empty: true,
        init_reaped: true,
        guardian_reaped: true,
        boundary_retired: true,
        assignment_verified: true,
        namespaces_verified: true,
        target_initial_credentials_verified: true,
        initial_provider_capabilities_absent: true,
        caller_envelope_digest: "a".repeat(64),
        caller_no_new_privs: false,
        target_no_new_privs_matched: true,
        caller_capability_bounding_set_digest: "b".repeat(64),
        target_capability_bounding_set_matched: true,
        caller_mount_namespace_digest: "c".repeat(64),
        target_mount_context_derived_from_caller: true,
        boundary_independent_of_credentials: true,
        descriptors_verified: true,
        writable_ancestor_cgroup_denied: true,
        parent_namespace_handles_denied: true,
        recursive_provider_request_denied: true,
        guardian_ready_before_authorization: true,
        frontend_loss_authority_verified: true,
        cgroup_kill_invoked: true,
        memory_limit_exceeded: false,
        deadline_exceeded: false,
    }
}

#[test]
fn baseline_terminal_rejects_exec_failure_and_unretired_boundary() {
    let mut facts = test_terminal();
    assert!(verify_baseline_terminal(&facts).is_ok());
    facts.exec_status = TargetExecStatus::Failed {
        class: ExecFailureClass::NotFound,
        os_code: libc::ENOENT,
    };
    assert!(verify_baseline_terminal(&facts).is_err());
    facts = test_terminal();
    facts.boundary_retired = false;
    assert!(verify_baseline_terminal(&facts).is_err());
    facts = test_terminal();
    facts.guardian_reaped = false;
    assert!(verify_baseline_terminal(&facts).is_err());
}

#[test]
fn baseline_terminal_digest_binds_attempt_and_observed_pid() {
    let facts = test_terminal();
    let first = terminal_facts_digest([1; 16], &facts);
    let projection = BaselineTerminalProjectionV1::from_verified_facts([1; 16], &facts).unwrap();
    assert_eq!(projection.validate_and_digest().unwrap(), first);
    assert_ne!(first, terminal_facts_digest([2; 16], &facts));
    let mut changed = test_terminal();
    changed.target_pid += 1;
    assert_ne!(first, terminal_facts_digest([1; 16], &changed));
    changed = test_terminal();
    changed.guardian_reaped = false;
    assert_ne!(first, terminal_facts_digest([1; 16], &changed));
}

#[test]
fn baseline_projection_roundtrip_preserves_all_verified_terminal_facts() {
    let facts = test_terminal();
    let projection = BaselineTerminalProjectionV1::from_verified_facts([7; 16], &facts).unwrap();
    let bytes = serde_json::to_vec(&projection).unwrap();
    let decoded: BaselineTerminalProjectionV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, projection);
    assert_eq!(
        decoded.validate_and_digest().unwrap(),
        terminal_facts_digest([7; 16], &facts)
    );

    let mut changed = decoded.clone();
    changed.attempt = [8; 16];
    assert_ne!(
        changed.validate_and_digest().unwrap(),
        decoded.validate_and_digest().unwrap()
    );
    changed = decoded.clone();
    changed.guardian_reaped = false;
    assert!(changed.validate_and_digest().is_err());
    changed = decoded.clone();
    changed.caller_envelope_digest = "wrong".into();
    assert!(changed.validate_and_digest().is_err());

    let mut with_extra: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    with_extra["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<BaselineTerminalProjectionV1>(with_extra).is_err());
}
