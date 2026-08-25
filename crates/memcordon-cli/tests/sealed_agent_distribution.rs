use std::process::Command;

fn agent(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_memcordon-sealed-agent"))
        .args(arguments)
        .output()
        .expect("sealed agent should run")
}

#[test]
fn companion_version_and_help_are_administrative_and_exact() {
    let version = agent(&["--version"]);
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).expect("version output should be UTF-8"),
        format!("memcordon-sealed-agent {}\n", env!("CARGO_PKG_VERSION"))
    );

    let help = agent(&["--help"]);
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).expect("help should be UTF-8");
    for command in [
        "package inspect [--json]",
        "package verify [--json]",
        "package install [--ephemeral-ci]",
        "package upgrade [--ephemeral-ci]",
        "package uninstall [--ephemeral-ci]",
    ] {
        assert!(help.contains(command), "agent help omits {command}");
    }
    assert!(!help.contains("launch-broker"));
    assert!(!help.contains("\n  memcordon-sealed-agent serve"));
}

#[test]
fn package_inspection_is_credential_free_and_machine_readable() {
    let output = agent(&["package", "inspect", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let inspection: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("inspection should be JSON");
    assert_eq!(inspection["schema_version"], 2);
    assert_eq!(inspection["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(inspection["provider_protocol"], 2);
    assert_eq!(inspection["mechanism"], "linux-pid-namespace-cgroup-v2");
    assert_eq!(inspection["platform"], "linux-systemd");
    assert_eq!(
        inspection["execution_report_schema"],
        memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION
    );
    assert_eq!(
        inspection["plan_report_schema"],
        memcordon_core::PLAN_REPORT_SCHEMA_VERSION
    );
    assert_eq!(
        inspection["doctor_report_schema"],
        memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION
    );
    assert_eq!(inspection["compiled_metadata_valid"], true);
    for field in [
        "executable_sha256",
        "control_service_sha256",
        "control_socket_sha256",
        "launcher_service_sha256",
        "launcher_socket_sha256",
        "tmpfiles_sha256",
    ] {
        let value = inspection[field]
            .as_str()
            .expect("digest should be a string");
        assert!(!value.is_empty());
        assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
