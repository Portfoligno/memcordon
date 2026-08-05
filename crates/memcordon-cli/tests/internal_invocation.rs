use std::process::Command;

#[test]
fn hidden_routes_require_exact_safe_shapes() {
    for arguments in [
        vec!["__launcher"],
        vec!["__launcher", "-1", "4", "--", "target"],
        vec!["__launcher", "3", "4", "target"],
        vec!["__guardian", "3", "0"],
        vec!["__guardian", "3", "41", "trailing"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
            .args(arguments)
            .output()
            .expect("malformed hidden invocation should run");
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("MCCLI-INTERNAL-PROTOCOL"),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let help = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .arg("--help")
        .output()
        .expect("help should run");
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert!(
        !stdout.contains("__launcher") && !stdout.contains("__guardian"),
        "hidden routes must not appear in public help: {stdout}"
    );
}
