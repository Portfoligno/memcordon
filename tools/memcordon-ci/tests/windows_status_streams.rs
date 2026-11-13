use memcordon_ci::windows_status_streams::validate;
use memcordon_core::execution_facts::OutcomeKindV1;

#[test]
fn controlled_statuses_require_exact_summary_then_bound_native_child_diagnostic() {
    for (status, kind, label) in [
        (123, OutcomeKindV1::Completed, "child exited"),
        (124, OutcomeKindV1::Completed, "child exited"),
        (125, OutcomeKindV1::Completed, "child exited"),
        (123, OutcomeKindV1::Deadline, "deadline exceeded"),
        (
            124,
            OutcomeKindV1::ConfirmedMemoryLimit,
            "memory limit exceeded",
        ),
    ] {
        let stderr = format!(
            "memcordon: {label} {status}; backend windows-job-object; attempts 1; restarts 0\nnative-frontend phase=inner-child-exited child-pid=42 exit-code={status} exit-code-hex=0x{status:08x} restricted=false system-environment=true\n"
        );
        validate(b"", stderr.as_bytes(), status, kind, Some(42), false).unwrap();
        assert!(validate(b"", stderr.as_bytes(), status, kind, Some(43), false).is_err());
        assert!(validate(b"", stderr.as_bytes(), status, kind, Some(42), true).is_err());
        assert!(
            validate(
                b"workload",
                stderr.as_bytes(),
                status,
                kind,
                Some(42),
                false
            )
            .is_err()
        );
        assert!(validate(b"", b"", status, kind, Some(42), false).is_err());
        assert!(validate(b"", stderr.as_bytes(), status, kind, None, false).is_err());
        for invalid in [
            format!("extra\n{stderr}"),
            format!("{stderr}extra\n"),
            format!("{stderr}{stderr}"),
            stderr.replace("system-environment=true", "system-environment=false"),
            stderr.replace("exit-code-hex=0x", "exit-code-hex=0X"),
            stderr.trim_end().to_owned(),
        ] {
            assert!(validate(b"", invalid.as_bytes(), status, kind, Some(42), false).is_err());
        }
    }
}

#[test]
fn ordinary_nonzero_status_has_only_native_diagnostic_and_zero_has_no_wrapper_bytes() {
    let stderr = b"native-frontend phase=inner-child-exited child-pid=42 exit-code=17 exit-code-hex=0x00000011 restricted=false system-environment=true\n";
    validate(b"", stderr, 17, OutcomeKindV1::Completed, Some(42), false).unwrap();
    assert!(validate(b"", stderr, 0, OutcomeKindV1::Completed, Some(42), false).is_err());
    validate(b"", b"", 0, OutcomeKindV1::Completed, None, true).unwrap();
    assert!(
        validate(
            b"",
            b"unrecognized stderr",
            0,
            OutcomeKindV1::Completed,
            None,
            true
        )
        .is_err()
    );
}
