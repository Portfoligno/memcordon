use memcordon_readiness_verifier::{current::windows::validate_package_command, sha256};
use serde_json::json;

#[test]
fn actual_failed_package_wait_is_distinct_from_success_or_incomplete_capture() {
    use memcordon_readiness_verifier::current::windows::validate_failed_package_command;
    let program = r"C:\selected\memcordon-sealed-agent.exe";
    let directory = r"C:\owned\interrupted";
    let image = sha256(b"selected current agent");
    let invocation = json!({"format":"memcordon.windows-package-invocation","revision":1,"operation":"upgrade","program_utf16":program.encode_utf16().collect::<Vec<_>>(),"argv_utf16":["package".encode_utf16().collect::<Vec<_>>(),"upgrade".encode_utf16().collect::<Vec<_>>()],"cwd_utf16":directory.encode_utf16().collect::<Vec<_>>(),"image_sha256":image,"budget_millis":90000});
    let capture = json!({"format":"memcordon.package-operation-capture","revision":1,"operation":"upgrade","operation_complete":true,"streams_available":true,"stdout_reader_finished":true,"stderr_reader_finished":true,"observed_exit_code":125,"failure":"package upgrade failed: Some(125)"});
    validate_failed_package_command(&invocation, &capture, "upgrade", program, directory, &image)
        .unwrap();
    assert!(
        validate_package_command(&invocation, &capture, "upgrade", program, directory, &image)
            .is_err()
    );
    for (field, value) in [
        ("observed_exit_code", json!(0)),
        ("failure", json!(null)),
        ("operation_complete", json!(false)),
        ("stderr_reader_finished", json!(false)),
    ] {
        let mut changed = capture.clone();
        changed[field] = value;
        assert!(
            validate_failed_package_command(
                &invocation,
                &changed,
                "upgrade",
                program,
                directory,
                &image
            )
            .is_err()
        );
    }
    assert!(
        validate_failed_package_command(
            &invocation,
            &capture,
            "install",
            program,
            directory,
            &image
        )
        .is_err()
    );
}

#[test]
fn package_native_wait_and_selected_command_cannot_be_relabelled_or_partially_captured() {
    let program = r"C:\selected\memcordon-sealed-agent.exe";
    let directory = r"C:\owned\fresh";
    let image = sha256(b"actual selected agent");
    for operation in ["install", "verify", "upgrade", "uninstall"] {
        let invocation = json!({"format":"memcordon.windows-package-invocation","revision":1,"operation":operation,"program_utf16":program.encode_utf16().collect::<Vec<_>>(),"argv_utf16":["package".encode_utf16().collect::<Vec<_>>(),operation.encode_utf16().collect::<Vec<_>>()],"cwd_utf16":directory.encode_utf16().collect::<Vec<_>>(),"image_sha256":image,"budget_millis":120000});
        let capture = json!({"format":"memcordon.package-operation-capture","revision":1,"operation":operation,"operation_complete":true,"streams_available":true,"stdout_reader_finished":true,"stderr_reader_finished":true,"observed_exit_code":0,"failure":null});
        validate_package_command(&invocation, &capture, operation, program, directory, &image)
            .unwrap();
        for field in [
            "operation_complete",
            "streams_available",
            "stdout_reader_finished",
            "stderr_reader_finished",
        ] {
            let mut changed = capture.clone();
            changed[field] = json!(false);
            assert!(
                validate_package_command(
                    &invocation,
                    &changed,
                    operation,
                    program,
                    directory,
                    &image
                )
                .is_err()
            );
        }
        for (field, value) in [
            ("observed_exit_code", json!(1)),
            ("operation", json!("launch")),
            ("failure", json!("native wait failed")),
        ] {
            let mut changed = capture.clone();
            changed[field] = value;
            assert!(
                validate_package_command(
                    &invocation,
                    &changed,
                    operation,
                    program,
                    directory,
                    &image
                )
                .is_err()
            );
        }
        for (field, value) in [
            ("image_sha256", json!(sha256(b"other agent"))),
            ("budget_millis", json!(120001)),
            (
                "argv_utf16",
                json!(["package".encode_utf16().collect::<Vec<_>>()]),
            ),
        ] {
            let mut changed = invocation.clone();
            changed[field] = value;
            assert!(
                validate_package_command(&changed, &capture, operation, program, directory, &image)
                    .is_err()
            );
        }
    }
}
