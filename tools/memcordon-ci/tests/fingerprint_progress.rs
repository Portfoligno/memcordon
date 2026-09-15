use memcordon_ci::build_context::environment::progress::phase;

#[test]
fn phase_preserves_operation_value_error_and_invocation_count() {
    let mut calls = 0;
    let result: Result<Vec<u8>, Vec<u8>> = phase("successful fixture", || {
        calls += 1;
        Ok(b"native bytes\n".to_vec())
    });
    assert_eq!(result.unwrap(), b"native bytes\n");
    let result: Result<Vec<u8>, Vec<u8>> = phase("failed fixture", || {
        calls += 1;
        Err(b"original error\n".to_vec())
    });
    assert_eq!(result.unwrap_err(), b"original error\n");
    assert_eq!(calls, 2);
}

#[test]
fn native_phase_diagnostics_leave_stdout_protocol_unchanged() {
    use std::fs;
    use std::path::Path;
    use std::process::Command;
    use std::time::Duration;

    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("phase_fixture.rs");
    let executable = temporary.path().join("phase_fixture.exe");
    let environment = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ci-build-environment.rs")
        .canonicalize()
        .unwrap();
    let declaration = format!("#[allow(dead_code)]\n#[path = {environment:?}]\nmod environment;\n");
    let body = r#"fn main() {
    let success: Result<(), &str> = environment::progress::phase("success fixture", || Ok(()));
    assert!(success.is_ok());
    let failure: Result<(), &str> = environment::progress::phase("failure fixture", || Err("original failure"));
    assert_eq!(failure.unwrap_err(), "original failure");
    println!("native-protocol");
}
"#;
    fs::write(&source, [declaration.as_bytes(), body.as_bytes()].concat()).unwrap();
    let mut compile = Command::new("rustup");
    compile
        .args(["run", "1.97.1", "rustc", "--edition=2021"])
        .arg(&source)
        .arg("-o")
        .arg(&executable);
    let compiled =
        memcordon_testkit::run_with_deadline(&mut compile, Duration::from_secs(20)).unwrap();
    assert!(
        compiled.status.success(),
        "fixture compilation failed: {:?}",
        compiled.stderr
    );
    let mut command = Command::new(&executable);
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(5),
        8192,
    )
    .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"native-protocol\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    let lines: Vec<_> = stderr.lines().collect();
    assert_eq!(lines.len(), 4, "{stderr}");
    assert_eq!(lines[0], "[native fingerprint] start success fixture");
    assert_eq!(lines[2], "[native fingerprint] start failure fixture");
    for (line, prefix) in [
        (
            lines[1],
            "[native fingerprint] complete success fixture elapsed_ms=",
        ),
        (
            lines[3],
            "[native fingerprint] failed failure fixture elapsed_ms=",
        ),
    ] {
        assert!(
            line.strip_prefix(prefix).unwrap().parse::<u128>().is_ok(),
            "{line}"
        );
    }
}
