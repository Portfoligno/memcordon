use std::process::Command;

// A sibling spawn can inherit a writable fixture descriptor until exec closes
// it, even when the copying thread has already closed its own descriptor.
// Keep executable materialization and every spawn in this test binary in one
// lifecycle domain instead of retrying ETXTBSY or weakening inspection checks.
static EXECUTABLE_LIFECYCLE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn agent(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_memcordon-sealed-agent"))
        .args(arguments)
        .output()
        .expect("sealed agent should run")
}

#[test]
fn windows_companions_have_safe_exact_version_contracts() {
    let _lifecycle = EXECUTABLE_LIFECYCLE.lock().unwrap();
    for (component, executable) in [
        (
            "memcordon-target-desktop-bootstrap",
            env!("CARGO_BIN_EXE_memcordon-target-desktop-bootstrap"),
        ),
        (
            "memcordon-session-broker",
            env!("CARGO_BIN_EXE_memcordon-session-broker"),
        ),
    ] {
        let version = Command::new(executable)
            .arg("--version")
            .output()
            .unwrap_or_else(|error| panic!("{component} should run: {error}"));
        assert!(
            version.status.success(),
            "{}",
            String::from_utf8_lossy(&version.stderr)
        );
        assert_eq!(
            String::from_utf8(version.stdout).expect("version output should be UTF-8"),
            format!("{component} {}\n", env!("CARGO_PKG_VERSION")),
            "{component} version contract differs"
        );
    }
}

#[test]
fn companion_version_and_help_are_administrative_and_exact() {
    let _lifecycle = EXECUTABLE_LIFECYCLE.lock().unwrap();
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
        "memcordon-sealed-agent serve",
        "memcordon-sealed-agent launch-broker",
        "memcordon-sealed-agent probe",
        "package <install|upgrade|inspect|verify|uninstall> [--json]",
    ] {
        assert!(help.contains(command), "agent help omits {command}");
    }
    assert!(!help.contains("--ephemeral-ci"));
    assert!(!help.contains("--archive-certificate"));
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
#[test]
fn package_inspection_is_unavailable_without_a_native_provider_package() {
    let _lifecycle = EXECUTABLE_LIFECYCLE.lock().unwrap();
    let output = agent(&["package", "inspect", "--json"]);
    assert_eq!(output.status.code(), Some(125));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "retired release command is unavailable"
    );
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[test]
fn package_inspection_is_credential_free_and_machine_readable() {
    let _lifecycle = EXECUTABLE_LIFECYCLE.lock().unwrap();
    let output = agent(&["package", "inspect", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let inspection: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("inspection should be JSON");
    assert_eq!(inspection["format"], "memcordon.agent-package-inspection");
    assert_eq!(inspection["revision"], 1);
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
        assert_eq!(inspection["provider_protocol"], 3);
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

#[cfg(target_os = "linux")]
#[test]
fn bare_inspection_does_not_infer_package_custody_from_a_hard_linked_build() {
    let _lifecycle = EXECUTABLE_LIFECYCLE.lock().unwrap();
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("memcordon-sealed-agent");
    std::fs::copy(env!("CARGO_BIN_EXE_memcordon-sealed-agent"), &executable).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::hard_link(&executable, directory.path().join("cargo-output-link")).unwrap();
    let output = Command::new(&executable)
        .args(["package", "inspect", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let inspection: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(inspection["format"], "memcordon.agent-package-inspection");
    assert_eq!(inspection["revision"], 1);
    assert_eq!(inspection["compiled_metadata_valid"], true);

    let manifest = directory.path().join("runtime-manifest.json");
    std::fs::write(&manifest, b"{}\n").unwrap();
    std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o644)).unwrap();
    let output = Command::new(&executable)
        .args(["package", "inspect", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let with_manifest: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(with_manifest, inspection);
    assert!(with_manifest.get("installed_artifacts_valid").is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn bare_inspection_does_not_claim_source_custody_from_modes_or_sibling_links() {
    let _lifecycle = EXECUTABLE_LIFECYCLE.lock().unwrap();
    use std::os::unix::fs::{PermissionsExt, symlink};

    for unsafe_executable_mode in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("memcordon-sealed-agent");
        std::fs::copy(env!("CARGO_BIN_EXE_memcordon-sealed-agent"), &executable).unwrap();
        let mode = if unsafe_executable_mode { 0o775 } else { 0o755 };
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(mode)).unwrap();
        let manifest = directory.path().join("runtime-manifest.json");
        if unsafe_executable_mode {
            std::fs::write(&manifest, b"{}\n").unwrap();
            std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o644)).unwrap();
        } else {
            symlink(directory.path().join("absent-manifest-target"), &manifest).unwrap();
        }
        let output = Command::new(&executable)
            .args(["package", "inspect", "--json"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let inspection: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(inspection["format"], "memcordon.agent-package-inspection");
        assert_eq!(inspection["compiled_metadata_valid"], true);
        assert!(inspection.get("installed_artifacts_valid").is_none());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn bare_inspection_does_not_consume_a_sibling_invalid_manifest() {
    let _lifecycle = EXECUTABLE_LIFECYCLE.lock().unwrap();
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("memcordon-sealed-agent");
    std::fs::copy(env!("CARGO_BIN_EXE_memcordon-sealed-agent"), &executable).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let manifest = directory.path().join("runtime-manifest.json");
    std::fs::write(&manifest, b"{}\n").unwrap();
    std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o644)).unwrap();
    let output = Command::new(&executable)
        .args(["package", "inspect", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let inspection: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(inspection["format"], "memcordon.agent-package-inspection");
    assert_eq!(inspection["compiled_metadata_valid"], true);
    assert!(inspection.get("installed_artifacts_valid").is_none());
}
