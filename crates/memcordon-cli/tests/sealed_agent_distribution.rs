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
    assert_eq!(inspection["schema_version"], 3);
    assert_eq!(inspection["version"], env!("CARGO_PKG_VERSION"));
    #[cfg(target_os = "windows")]
    {
        assert_eq!(
            inspection["provider_protocol"],
            memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION
        );
        assert_eq!(inspection["mechanism"], "windows-job-object-v2");
        assert_eq!(inspection["platform"], "windows-service");
    }
    #[cfg(not(target_os = "windows"))]
    {
        assert_eq!(inspection["provider_protocol"], 2);
        assert_eq!(inspection["mechanism"], "linux-pid-namespace-cgroup-v2");
        assert_eq!(inspection["platform"], "linux-systemd");
    }
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
    #[cfg(target_os = "windows")]
    let digest_fields = [
        "executable_sha256",
        "control_service_config_sha256",
        "launcher_service_config_sha256",
        "session_broker_service_config_sha256",
        "guardian_slot_config_sha256",
        "control_pipe_security_sha256",
        "launcher_pipe_security_sha256",
        "session_broker_service_security_sha256",
        "session_broker_pipe_security_sha256",
        "guardian_pipe_security_contract_sha256",
        "install_directory_security_sha256",
        "state_directory_security_sha256",
    ];
    #[cfg(not(target_os = "windows"))]
    let digest_fields = [
        "executable_sha256",
        "control_service_sha256",
        "control_socket_sha256",
        "launcher_service_sha256",
        "launcher_socket_sha256",
        "tmpfiles_sha256",
    ];
    for field in digest_fields {
        let value = inspection[field]
            .as_str()
            .expect("digest should be a string");
        assert!(!value.is_empty());
        assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
