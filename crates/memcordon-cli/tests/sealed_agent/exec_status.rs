#![cfg(all(target_os = "linux", feature = "test-support"))]

use std::io::Write;

use crate::linux::launch::{
    ExecFailureClass, TargetExecStatus, TerminalFacts, control_socketpair_for_test,
    exec_armed_record_for_test, exec_failure_record_for_test, receive_exec_status_for_test,
};

fn terminal(exec_status: TargetExecStatus, child_status: i32) -> TerminalFacts {
    TerminalFacts {
        child_status,
        exec_status,
        spawn_error_reported: true,
        target_pid: 41,
        authorization_offset_millis: 7,
        cgroup_empty: true,
        init_reaped: true,
        guardian_reaped: true,
        boundary_retired: true,
        assignment_verified: true,
        namespaces_verified: true,
        target_initial_credentials_verified: true,
        initial_provider_capabilities_absent: true,
        caller_envelope_digest: "0".repeat(64),
        caller_no_new_privs: false,
        target_no_new_privs_matched: true,
        caller_capability_bounding_set_digest: "1".repeat(64),
        target_capability_bounding_set_matched: true,
        caller_mount_namespace_digest: "2".repeat(64),
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
fn close_on_exec_eof_is_distinct_from_native_exit_126_or_127() {
    for child_status in [126, 127] {
        let (mut target, mut provider) = control_socketpair_for_test().unwrap();
        target.write_all(&exec_armed_record_for_test()).unwrap();
        drop(target);
        assert_eq!(
            receive_exec_status_for_test(&mut provider).unwrap(),
            TargetExecStatus::Succeeded
        );
        let payload = crate::linux::service::terminal_payload_for_test(&terminal(
            TargetExecStatus::Succeeded,
            child_status,
        ));
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(&payload)
            .expect("producer terminal receipt must be accepted by the platform consumer");
        let text = std::str::from_utf8(&payload).unwrap();
        assert!(text.lines().any(|line| line == "exec-status=success"));
        assert!(text.lines().any(|line| line == "exec-os-code=none"));
        assert!(
            text.lines()
                .any(|line| line == format!("status={child_status}"))
        );
    }
}

#[test]
fn native_exec_errors_are_bounded_and_classified_before_terminal_receipt() {
    for (os_code, class, status_name, child_status) in [
        (libc::ENOENT, ExecFailureClass::NotFound, "not-found", 127),
        (
            libc::EACCES,
            ExecFailureClass::NotExecutable,
            "not-executable",
            126,
        ),
    ] {
        let (mut target, mut provider) = control_socketpair_for_test().unwrap();
        target.write_all(&exec_armed_record_for_test()).unwrap();
        target
            .write_all(&exec_failure_record_for_test(os_code))
            .unwrap();
        drop(target);
        let status = receive_exec_status_for_test(&mut provider).unwrap();
        assert_eq!(status, TargetExecStatus::Failed { class, os_code });
        let payload =
            crate::linux::service::terminal_payload_for_test(&terminal(status, child_status));
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(&payload)
            .expect("producer terminal receipt must be accepted by the platform consumer");
        let text = std::str::from_utf8(&payload).unwrap();
        assert!(
            text.lines()
                .any(|line| line == format!("exec-status={status_name}"))
        );
        assert!(
            text.lines()
                .any(|line| line == format!("exec-os-code={os_code}"))
        );
    }
}

#[test]
fn malformed_trailing_or_unarmed_exec_status_fails_closed() {
    let (target, mut provider) = control_socketpair_for_test().unwrap();
    drop(target);
    assert!(
        receive_exec_status_for_test(&mut provider)
            .unwrap_err()
            .contains("before armed record")
    );

    let (mut target, mut provider) = control_socketpair_for_test().unwrap();
    target.write_all(&exec_armed_record_for_test()).unwrap();
    target.write_all(&[1, 2, 3]).unwrap();
    drop(target);
    assert!(
        receive_exec_status_for_test(&mut provider)
            .unwrap_err()
            .contains("length mismatch")
    );

    let (mut target, mut provider) = control_socketpair_for_test().unwrap();
    target.write_all(&exec_armed_record_for_test()).unwrap();
    target
        .write_all(&exec_failure_record_for_test(libc::ENOENT))
        .unwrap();
    target
        .write_all(&exec_failure_record_for_test(libc::ENOENT))
        .unwrap();
    drop(target);
    assert!(
        receive_exec_status_for_test(&mut provider)
            .unwrap_err()
            .contains("trailing record")
    );
}
