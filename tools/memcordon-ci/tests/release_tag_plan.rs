use std::process::Command;

/// The CLI rejects unsupported tag-plan commands during argument parsing.
#[test]
fn retired_ci_tag_plan_is_not_an_executable_route() {
    let executable = env!("CARGO_BIN_EXE_memcordon-ci");
    for command in [
        "release-tag-plan",
        "release-tag-prepare",
        "release-tag-create",
    ] {
        let output = Command::new(executable).arg(command).output().unwrap();
        assert!(
            !output.status.success(),
            "retired command accepted: {command}"
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("unrecognized subcommand"),
            "unexpected retired-command rejection for {command}: {stderr}"
        );
    }
}
