#![cfg(target_os = "linux")]

use memcordon_core::{ErrorCategory, InitialSpawnFailure};

#[test]
fn exact_channel_pairing_refuses_both_version_directions_before_authorization() {
    assert!(
        memcordon_platform::test_support::sealed_provider_pairing_is_exact(
            "0.5.2",
            "0.5.2",
            "Cargo CLI",
            "Cargo provider",
        )
        .is_ok()
    );
    for (cli_version, provider_version, cli_channel, provider_channel) in [
        ("0.5.2", "0.5.1", "Cargo CLI", "native provider"),
        ("0.5.1", "0.5.2", "native CLI", "Cargo provider"),
        ("0.5.2", "0.5.1", "native CLI", "native provider"),
        ("0.5.1", "0.5.2", "Cargo CLI", "Cargo provider"),
    ] {
        let error = memcordon_platform::test_support::sealed_provider_pairing_is_exact(
            cli_version,
            provider_version,
            cli_channel,
            provider_channel,
        )
        .expect_err("a cross-version provider must be refused");
        assert!(error.contains(cli_version));
        assert!(error.contains(provider_version));
        assert!(error.contains(cli_channel));
        assert!(error.contains(provider_channel));
        assert!(error.contains("before target authorization"));
        assert!(error.contains("package upgrade"));
    }
}

#[test]
fn missing_provider_names_both_installation_channels_and_companion() {
    let diagnostic = memcordon_platform::test_support::sealed_provider_installation_diagnostic();
    for required in [
        "sealed provider is not installed or reachable",
        "provider endpoint unavailable",
        "Cargo installation:",
        "memcordon-sealed-agent package install",
        "Native archive:",
        "included beside this executable",
    ] {
        assert!(
            diagnostic.contains(required),
            "missing-provider diagnostic omitted {required}"
        );
    }
}

fn terminal(status: i32, exec_status: &str, os_code: &str) -> Vec<u8> {
    const CALLER_ENVELOPE_DIGEST: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";
    const CALLER_CAPABILITY_BOUNDING_SET_DIGEST: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const CALLER_MOUNT_NAMESPACE_DIGEST: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    format!(
        concat!(
            "schema-version=2\n",
            "mechanism=linux-pid-namespace-cgroup-v2\n",
            "status={status}\n",
            "exec-status={exec_status}\n",
            "exec-os-code={os_code}\n",
            "spawn-error-reported=true\n",
            "target-pid=71\n",
            "authorization-offset-millis=9\n",
            "memory-limit-exceeded=false\n",
            "deadline-exceeded=false\n",
            "assignment-verified=true\n",
            "namespaces-verified=true\n",
            "target-initial-credentials-verified=true\n",
            "initial-provider-capabilities-absent=true\n",
            "caller-envelope-digest={caller_envelope_digest}\n",
            "caller-no-new-privs=false\n",
            "target-no-new-privs-matched=true\n",
            "caller-capability-bounding-set-digest={caller_capability_bounding_set_digest}\n",
            "target-capability-bounding-set-matched=true\n",
            "caller-mount-namespace-digest={caller_mount_namespace_digest}\n",
            "target-mount-context-derived-from-caller=true\n",
            "credential-transition-disposition=preserve-caller-envelope\n",
            "boundary-independent-of-credentials=true\n",
            "descriptors-verified=true\n",
            "writable-ancestor-cgroup-denied=true\n",
            "parent-namespace-handles-denied=true\n",
            "recursive-provider-request-denied=true\n",
            "guardian-ready-before-authorization=true\n",
            "frontend-loss-authority-verified=true\n",
            "cgroup-kill-invoked=true\n",
            "cgroup-empty=true\n",
            "init-reaped=true\n",
            "guardian-reaped=true\n",
            "boundary-retired=true\n",
        ),
        status = status,
        exec_status = exec_status,
        os_code = os_code,
        caller_envelope_digest = CALLER_ENVELOPE_DIGEST,
        caller_capability_bounding_set_digest = CALLER_CAPABILITY_BOUNDING_SET_DIGEST,
        caller_mount_namespace_digest = CALLER_MOUNT_NAMESPACE_DIGEST,
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
fn request_validation_rejection_is_typed_and_unknown_phases_fail_closed() {
    let payload = br#"{
        "schema_version": 1,
        "code": "MCSEALED-PACKAGE-LEASE",
        "phase": "request-validation",
        "detail": "stable package lease is unavailable",
        "os_code": 30,
        "target_created": false,
        "target_released": false,
        "cleanup": {
            "attempted": false,
            "direct_child_reaped": false,
            "workload_empty": null,
            "helpers_reaped": false,
            "containment_removed": false,
            "sealed_boundary_retired": false,
            "errors": []
        }
    }"#;
    let rejection = memcordon_platform::test_support::sealed_rejection_v1(payload)
        .expect("request-validation must be part of the strict provider vocabulary");
    assert_eq!(rejection.code, "MCSEALED-PACKAGE-LEASE");
    assert_eq!(
        rejection.phase,
        memcordon_core::BoundarySetupPhase::RequestValidation
    );
    assert_eq!(rejection.detail, "stable package lease is unavailable");
    assert_eq!(rejection.os_code, Some(30));
    assert!(!rejection.target_created);
    assert!(!rejection.target_released);
    assert!(!rejection.cleanup_attempted);
    assert_eq!(
        rejection.restart_safety,
        memcordon_core::RestartSafetyProof::default()
    );

    let unknown = String::from_utf8(payload.to_vec())
        .unwrap()
        .replace("request-validation", "future-request-validation");
    assert!(
        memcordon_platform::test_support::sealed_rejection_v1(unknown.as_bytes())
            .unwrap_err()
            .contains("unknown variant")
    );
}

#[test]
fn terminal_spawn_provenance_is_strict_and_fail_closed() {
    let missing_schema = String::from_utf8(terminal(0, "success", "none"))
        .unwrap()
        .replace("schema-version=2\n", "");
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(missing_schema.as_bytes())
            .unwrap_err()
            .contains("schema-version missing")
    );

    let wrong_schema = String::from_utf8(terminal(0, "success", "none"))
        .unwrap()
        .replace("schema-version=2", "schema-version=1");
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(wrong_schema.as_bytes())
            .unwrap_err()
            .contains("incompatible")
    );

    let missing_mechanism = String::from_utf8(terminal(0, "success", "none"))
        .unwrap()
        .replace("mechanism=linux-pid-namespace-cgroup-v2\n", "");
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(missing_mechanism.as_bytes())
            .unwrap_err()
            .contains("mechanism missing")
    );

    let wrong_mechanism = String::from_utf8(terminal(0, "success", "none"))
        .unwrap()
        .replace(
            "mechanism=linux-pid-namespace-cgroup-v2",
            "mechanism=legacy-credential-boundary",
        );
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(wrong_mechanism.as_bytes())
            .unwrap_err()
            .contains("incompatible")
    );

    let mut obsolete_v1_field = terminal(0, "success", "none");
    obsolete_v1_field.extend_from_slice(b"credentials-verified=true\n");
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(&obsolete_v1_field)
            .unwrap_err()
            .contains("unknown fields")
    );

    let mut unknown_field = terminal(0, "success", "none");
    unknown_field.extend_from_slice(b"unexpected-proof=true\n");
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(&unknown_field)
            .unwrap_err()
            .contains("unknown fields")
    );

    let invalid_digest = String::from_utf8(terminal(0, "success", "none"))
        .unwrap()
        .replace(
            "caller-envelope-digest=0000000000000000000000000000000000000000000000000000000000000000",
            "caller-envelope-digest=not-a-sha256-digest",
        );
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(invalid_digest.as_bytes())
            .unwrap_err()
            .contains("digest is invalid")
    );

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

    let mut not_newline_terminated = terminal(0, "success", "none");
    assert_eq!(not_newline_terminated.pop(), Some(b'\n'));
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(&not_newline_terminated)
            .unwrap_err()
            .contains("not newline terminated")
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
