use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

#[test]
fn cargo_provider_cli_accepts_exactly_five_identity_arguments() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let expected_digest = "ab".repeat(32);
    let mut correct = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"))
        .arg("--cargo-plugin")
        .arg("oidc")
        .arg("3")
        .arg("memcordon-core")
        .arg("0.5.2")
        .arg(&expected_digest)
        .current_dir(&root)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("provider CLI should spawn");
    drop(
        correct
            .stdin
            .take()
            .expect("provider stdin should be piped"),
    );
    let output = correct
        .wait_with_output()
        .expect("provider CLI should finish");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Cargo credential provider received no request"),
        "five identity values should reach the provider protocol, not Clap: {stderr}"
    );
    assert!(!stderr.contains("Usage:"));

    for arguments in [
        vec!["oidc"],
        vec!["oidc", "3"],
        vec!["oidc", "3", "memcordon-core"],
        vec!["oidc", "3", "memcordon-core", "0.5.2"],
        vec!["memcordon-core"],
        vec!["memcordon-core", "0.5.2"],
        vec!["memcordon-core", "0.5.2", expected_digest.as_str(), "extra"],
        vec![
            "oidc",
            "3",
            "memcordon-core",
            "0.5.2",
            expected_digest.as_str(),
            "extra",
        ],
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"))
            .arg("--cargo-plugin")
            .args(&arguments)
            .current_dir(&root)
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("provider CLI should spawn");
        if let Some(mut stdin) = command.stdin.take() {
            let _ = stdin.write_all(b"\n");
        }
        let output = command
            .wait_with_output()
            .expect("provider CLI should finish");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Usage:"),
            "incorrect provider arity should fail argument parsing: {arguments:?} => {stderr}"
        );
    }

    let mut unknown_origin = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"))
        .arg("--cargo-plugin")
        .arg("token-first")
        .arg("3")
        .arg("memcordon-core")
        .arg("0.5.2")
        .arg(&expected_digest)
        .current_dir(&root)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("provider CLI should spawn");
    drop(
        unknown_origin
            .stdin
            .take()
            .expect("provider stdin should be piped"),
    );
    let output = unknown_origin
        .wait_with_output()
        .expect("provider CLI should finish");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown credential-provider origin"),
        "a closed provider origin vocabulary must reject unknown values: {stderr}"
    );
}
