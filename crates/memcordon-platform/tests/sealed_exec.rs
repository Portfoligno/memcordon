#![cfg(target_os = "linux")]

use memcordon_core::{ErrorCategory, InitialSpawnFailure};

fn terminal(status: i32, exec_status: &str, os_code: &str) -> Vec<u8> {
    format!(
        "status={status}\nexec-status={exec_status}\nexec-os-code={os_code}\nspawn-error-reported=true\ntarget-pid=71\nauthorization-offset-millis=9\nmemory-limit-exceeded=false\ndeadline-exceeded=false\nassignment-verified=true\nnamespaces-verified=true\ncredentials-verified=true\ncapabilities-empty=true\ndescriptors-verified=true\ncgroup-view-denied=true\nguardian-ready-before-authorization=true\nfrontend-loss-authority-verified=true\ncgroup-kill-invoked=true\ncgroup-empty=true\ninit-reaped=true\nguardian-reaped=true\nboundary-retired=true\n"
    )
    .into_bytes()
}

#[test]
fn genuine_native_exit_126_and_127_are_not_spawn_failures() {
    for status in [126, 127] {
        let error = memcordon_platform::test_support::sealed_terminal_spawn_error(&terminal(
            status, "success", "none",
        ))
        .unwrap();
        assert!(error.is_none());
    }
}

#[test]
fn enoent_and_eacces_retain_typed_authenticated_spawn_provenance() {
    for (os_code, status, exec_status, code, initial) in [
        (
            libc::ENOENT,
            127,
            "not-found",
            "MCSPAWN-NOT-FOUND",
            InitialSpawnFailure::NotFound,
        ),
        (
            libc::EACCES,
            126,
            "not-executable",
            "MCSPAWN-NOT-EXECUTABLE",
            InitialSpawnFailure::NotExecutable,
        ),
    ] {
        let error = memcordon_platform::test_support::sealed_terminal_spawn_error(&terminal(
            status,
            exec_status,
            &os_code.to_string(),
        ))
        .unwrap()
        .expect("typed exec failure must become a categorized error");
        assert_eq!(error.category, ErrorCategory::Spawn);
        assert_eq!(error.code, code);
        assert_eq!(error.os_code, Some(os_code));
        assert_eq!(error.initial_spawn_failure, Some(initial));
        assert_eq!(error.launch_phase, Some("target-spawn-failed"));
        assert!(error.target_released);
        assert_eq!(error.target_pid, Some(71));
        assert!(error.authorization_offset.is_some());
        assert!(error.cgroup_verified_before_release);
        assert!(error.guardian_ready_before_release);
        assert!(!error.workload_may_be_alive);
        let rejection = error
            .provider_rejection
            .expect("authenticated terminal provenance must remain in the report");
        assert_eq!(rejection.code, code);
        assert_eq!(rejection.os_code, Some(os_code));
        assert!(rejection.target_created);
        assert!(rejection.target_released);
        assert!(rejection.restart_safety.sealed_boundary_retired);
    }
}

#[test]
fn terminal_spawn_provenance_is_strict_and_fail_closed() {
    let mismatch = terminal(126, "not-found", &libc::ENOENT.to_string());
    assert!(
        memcordon_platform::test_support::sealed_terminal_spawn_error(&mismatch)
            .unwrap_err()
            .contains("child status")
    );

    let wrong_class = terminal(126, "not-executable", &libc::ENOENT.to_string());
    assert!(
        memcordon_platform::test_support::sealed_terminal_spawn_error(&wrong_class)
            .unwrap_err()
            .contains("classification mismatch")
    );

    let mut duplicate = terminal(0, "success", "none");
    duplicate.extend_from_slice(b"status=0\n");
    assert!(
        memcordon_platform::test_support::sealed_terminal_spawn_error(&duplicate)
            .unwrap_err()
            .contains("duplicate")
    );

    let omitted_proof = String::from_utf8(terminal(0, "success", "none"))
        .unwrap()
        .replace("spawn-error-reported=true", "spawn-error-reported=false");
    assert!(
        memcordon_platform::test_support::sealed_terminal_spawn_error(omitted_proof.as_bytes())
            .unwrap_err()
            .contains("omitted verified")
    );
}
