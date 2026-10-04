use std::process::Command;

/// Hosted job, registration, and collection command names are rejected during CLI parsing.
#[test]
fn retired_hosted_job_commands_are_not_executable_routes() {
    let executable = env!("CARGO_BIN_EXE_memcordon-ci");
    for command in [
        "release-hosted-job",
        "release-hosted-register",
        "release-hosted-cache-register",
        "release-hosted-cache-collect",
    ] {
        let output = Command::new(executable).arg(command).output().unwrap();
        assert!(
            !output.status.success(),
            "retired command accepted: {command}"
        );
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("unrecognized subcommand"),
            "retired command was not rejected at parsing: {command}"
        );
    }
}
