use std::process::Command;

/// The CLI rejects release-hosted-cache-activation during argument parsing.
#[test]
fn retired_cache_activation_is_not_an_executable_route() {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"))
        .arg("release-hosted-cache-activation")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("unrecognized subcommand")
    );
}
