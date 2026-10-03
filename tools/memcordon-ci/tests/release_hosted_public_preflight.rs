use std::process::Command;

#[test]
fn retired_public_preflight_has_no_ci_executable_route() {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"))
        .arg("release-hosted-public-preflight")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("unrecognized subcommand")
    );
}
