use super::*;
use std::cell::Cell;
use std::io::{BufRead, BufReader, Cursor};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

fn package_inspection_fixture() -> serde_json::Value {
    let digest = sha256_bytes(b"package-inspection-fixture");
    serde_json::json!({
        "schema_version": 4,
        "version": "1.2.3",
        "source_commit": "source-commit",
        "executable_sha256": digest,
        "provider_protocol": 2,
        "mechanism": "linux-pid-namespace-cgroup-v2",
        "platform": "linux-systemd",
        "execution_report_schema": memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
        "plan_report_schema": memcordon_core::PLAN_REPORT_SCHEMA_VERSION,
        "doctor_report_schema": memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION,
        "control_service_sha256": digest,
        "control_socket_sha256": digest,
        "launcher_service_sha256": digest,
        "launcher_socket_sha256": digest,
        "tmpfiles_sha256": digest,
        "compiled_metadata_valid": true
    })
}

fn windows_package_inspection_fixture() -> serde_json::Value {
    let digest = sha256_bytes(b"windows-package-inspection-fixture");
    let digest = digest.as_str();
    let mut inspection = serde_json::Map::new();
    for field in [
        "executable_sha256",
        "control_service_config_sha256",
        "launcher_service_config_sha256",
        "session_broker_service_config_sha256",
        "guardian_slot_config_sha256",
        "target_desktop_bootstrap_sha256",
        "target_desktop_bootstrap_loader_contract_sha256",
        "session_broker_sha256",
        "control_pipe_security_sha256",
        "launcher_pipe_security_sha256",
        "session_broker_service_security_sha256",
        "session_broker_pipe_security_sha256",
        "guardian_pipe_security_contract_sha256",
        "install_directory_security_sha256",
        "state_directory_security_sha256",
    ] {
        inspection.insert(field.to_owned(), serde_json::json!(digest));
    }
    for (field, value) in [
        ("schema_version", serde_json::json!(4)),
        ("version", serde_json::json!("1.2.3")),
        ("source_commit", serde_json::json!("source-commit")),
        ("provider_protocol", serde_json::json!(1)),
        ("mechanism", serde_json::json!("windows-job-object-v2")),
        ("platform", serde_json::json!("windows-service")),
        (
            "execution_report_schema",
            serde_json::json!(memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION),
        ),
        (
            "plan_report_schema",
            serde_json::json!(memcordon_core::PLAN_REPORT_SCHEMA_VERSION),
        ),
        (
            "doctor_report_schema",
            serde_json::json!(memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION),
        ),
        (
            "control_service_name",
            serde_json::json!("MemCordonSealedControl"),
        ),
        (
            "launcher_service_name",
            serde_json::json!("MemCordonSealedLauncher"),
        ),
        (
            "session_broker_service_name",
            serde_json::json!("MemCordonSealedSessionBroker"),
        ),
        (
            "guardian_slot_count",
            serde_json::json!(memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT),
        ),
        (
            "control_pipe",
            serde_json::json!(memcordon_core::WINDOWS_CONTROL_PIPE),
        ),
        (
            "launcher_pipe",
            serde_json::json!(memcordon_core::WINDOWS_LAUNCHER_PIPE),
        ),
        (
            "session_broker_pipe",
            serde_json::json!(memcordon_core::WINDOWS_SESSION_BROKER_PIPE),
        ),
        (
            "guardian_pipe_prefix",
            serde_json::json!(memcordon_core::WINDOWS_GUARDIAN_PIPE_PREFIX),
        ),
        (
            "binary_install_path",
            serde_json::json!("C:\\Program Files\\MemCordon\\memcordon-sealed-agent.exe"),
        ),
        (
            "target_desktop_bootstrap_install_path",
            serde_json::json!(
                "C:\\Program Files\\MemCordon\\memcordon-target-desktop-bootstrap.exe"
            ),
        ),
        (
            "target_desktop_bootstrap_runtime",
            serde_json::json!("static-vc-runtime-os-ucrt"),
        ),
        (
            "target_desktop_bootstrap_normal_imports",
            serde_json::json!(["KERNEL32.dll"]),
        ),
        (
            "target_desktop_bootstrap_delayed_imports",
            serde_json::json!([]),
        ),
        (
            "session_broker_install_path",
            serde_json::json!("C:\\Program Files\\MemCordon\\memcordon-session-broker.exe"),
        ),
        (
            "state_root",
            serde_json::json!("C:\\ProgramData\\MemCordon\\Sealed"),
        ),
        ("control_service_sid_type", serde_json::json!("restricted")),
        ("launcher_service_sid_type", serde_json::json!("restricted")),
        (
            "session_broker_service_sid_type",
            serde_json::json!("unrestricted"),
        ),
        (
            "guardian_slot_service_sid_type",
            serde_json::json!("restricted"),
        ),
        (
            "control_required_privileges",
            serde_json::json!(memcordon_core::WINDOWS_CONTROL_REQUIRED_PRIVILEGES),
        ),
        (
            "launcher_required_privileges",
            serde_json::json!(memcordon_core::WINDOWS_LAUNCHER_REQUIRED_PRIVILEGES),
        ),
        (
            "session_broker_required_privileges",
            serde_json::json!(memcordon_core::WINDOWS_SESSION_BROKER_REQUIRED_PRIVILEGES),
        ),
        ("guardian_slot_required_privileges", serde_json::json!([])),
        ("compiled_metadata_valid", serde_json::json!(true)),
    ] {
        inspection.insert(field.to_owned(), value);
    }
    serde_json::Value::Object(inspection)
}

fn frontend_cli() -> &'static Path {
    if cfg!(windows) {
        Path::new(r"C:\opt\release\memcordon.exe")
    } else {
        Path::new("/opt/release/memcordon")
    }
}

#[test]
fn windows_native_build_inventory_catches_a_missing_companion() {
    let (temporary, release) = release_fixture();
    let target = release
        .assets
        .target
        .iter()
        .find(|target| target.id == "windows-x64")
        .expect("release policy should contain the Windows x64 target");
    let inventory = built_executable_inventory(temporary.path(), target);
    let configured = inventory
        .iter()
        .map(|artifact| artifact.component.binary.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        configured,
        [
            "memcordon",
            "memcordon-sealed-agent",
            "memcordon-target-desktop-bootstrap",
            "memcordon-session-broker",
        ],
        "the configured Windows executable inventory must map to built artifacts in order"
    );

    for artifact in &inventory {
        let parent = artifact
            .path
            .parent()
            .expect("built executable should have a parent directory");
        fs::create_dir_all(parent).expect("native release directory should be created");
        fs::write(&artifact.path, b"native executable").expect("native executable should write");
    }
    let bootstrap = inventory
        .iter()
        .find(|artifact| artifact.component.role == RuntimeComponentRole::DesktopBootstrap)
        .expect("Windows release inventory should contain the desktop bootstrap");
    fs::remove_file(&bootstrap.path)
        .expect("missing-companion fixture should remove the bootstrap");

    let error = require_built_executable_inventory(temporary.path(), target)
        .expect_err("a missing configured companion must fail native staging");
    let message = error.to_string();
    assert!(
        message.contains(
            "configured native executable was not built: memcordon-target-desktop-bootstrap"
        ) && message.ends_with("memcordon-target-desktop-bootstrap.exe)"),
        "missing-companion diagnostic should identify the exact configured artifact: {message}"
    );

    fs::write(&bootstrap.path, b"native executable").expect("native bootstrap should be restored");
    let complete = require_built_executable_inventory(temporary.path(), target)
        .expect("every configured executable should validate");
    assert_eq!(
        complete.len(),
        4,
        "the exact configured Windows companion inventory should be required"
    );
}

#[test]
fn archive_member_inventory_identity_uses_archive_slashes_not_host_separators() {
    let top = "memcordon-v1.2.3-x86_64-pc-windows-msvc";
    let relative = "bin/memcordon.exe";
    let host_path = PathBuf::from(top).join(relative);
    let member = format!("{top}/{relative}");
    assert_eq!(
        archive_member_inventory_name(&host_path).expect("archive member name should canonicalize"),
        member,
        "release inventory hashes must use archive paths, not host path formatting"
    );
}

#[test]
fn native_report_identity_diagnostics_identify_exact_fields_and_values() {
    let identity = ReleaseIdentity {
        tag: "1.2.3".to_owned(),
        version: Version::parse("1.2.3").expect("version should parse"),
        commit: "0123456789abcdef".to_owned(),
        changelog_section: String::new(),
        source_date: "2025-01-01T00:00:00Z".to_owned(),
    };
    let component = RuntimeComponentRecord {
        id: "cli".to_owned(),
        path: "bin/memcordon.exe".to_owned(),
        role: RuntimeComponentRole::PublicCli,
        size: 7,
        mode: 0o755,
        sha256: "00".repeat(32),
    };
    let asset = AssetRecord {
        name: "memcordon-v1.2.3-x86_64-pc-windows-msvc.zip".to_owned(),
        target: "x86_64-pc-windows-msvc".to_owned(),
        size: 10,
        sha256: "01".repeat(32),
        runtime_manifest_sha256: "02".repeat(32),
        components: vec![component.clone()],
    };
    let report = NativeAssetReport {
        schema_version: 2,
        tag: identity.tag.clone(),
        source_commit: identity.commit.clone(),
        asset: asset.clone(),
        archive_member_inventory_sha256: "assembler-inventory".to_owned(),
        smoke: NativeSmokeReport {
            cli_version: true,
            doctor: true,
            agent_version: Some(true),
            agent_inspection: Some(true),
            provider_install: Some(true),
            provider_verify: Some(true),
            provider_qualification: Some(true),
            sealed_execution: Some(true),
            provider_uninstall: Some(true),
        },
    };

    require_native_report_identity(
        "windows-x64",
        &report,
        &asset,
        &identity,
        "assembler-inventory",
        Some(true),
    )
    .expect("matching native report should validate");

    let mut producer_report = report.clone();
    producer_report.archive_member_inventory_sha256 = "windows-producer-inventory".to_owned();
    let error = require_native_report_identity(
        "windows-x64",
        &producer_report,
        &asset,
        &identity,
        "assembler-inventory",
        Some(true),
    )
    .expect_err("native report mismatch should fail");
    let message = error.to_string();
    assert!(
        message.contains(
            "field=archive_member_inventory_sha256 expected=\"assembler-inventory\" actual=\"windows-producer-inventory\""
        ),
        "native report diagnostics should expose every exact field and both values: {message}"
    );
}

#[test]
fn windows_runtime_manifest_uses_shared_qualification_schema() {
    let (_temporary, release) = release_fixture();
    let target = release
        .assets
        .target
        .iter()
        .find(|target| target.rust_target == "x86_64-pc-windows-msvc")
        .expect("release policy should contain the Windows x64 target");
    let identity = ReleaseIdentity {
        tag: "1.2.3".to_owned(),
        version: Version::parse("1.2.3").expect("version should parse"),
        commit: "0123456789abcdef".to_owned(),
        changelog_section: "notes".to_owned(),
        source_date: "2025-01-01T00:00:00Z".to_owned(),
    };
    let manifest = runtime_manifest(&identity, target, Vec::new());
    let SealedRuntimeV1::Included {
        qualification_schema,
        ..
    } = manifest.sealed
    else {
        panic!("Windows release target should include its sealed provider");
    };
    assert_eq!(
        qualification_schema,
        memcordon_core::WINDOWS_QUALIFICATION_SCHEMA_VERSION
    );
}

#[test]
fn package_inspection_binds_version_source_commit_and_sha256_fields() {
    let canonical = package_inspection_fixture();
    validate_agent_package_inspection(
        &serde_json::to_vec(&canonical).unwrap(),
        "1.2.3",
        "source-commit",
    )
    .expect("canonical package inspection should validate");

    let mut wrong_commit = canonical.clone();
    wrong_commit["source_commit"] = serde_json::json!("different-commit");
    assert!(
        validate_agent_package_inspection(
            &serde_json::to_vec(&wrong_commit).unwrap(),
            "1.2.3",
            "source-commit",
        )
        .is_err()
    );

    let mut invalid_digest = canonical.clone();
    invalid_digest["executable_sha256"] = serde_json::json!("not-a-sha256");
    assert!(
        validate_agent_package_inspection(
            &serde_json::to_vec(&invalid_digest).unwrap(),
            "1.2.3",
            "source-commit",
        )
        .is_err()
    );

    let mut unknown_field = canonical;
    unknown_field["future_field"] = serde_json::json!(true);
    assert!(
        validate_agent_package_inspection(
            &serde_json::to_vec(&unknown_field).unwrap(),
            "1.2.3",
            "source-commit",
        )
        .is_err()
    );
}

#[test]
fn windows_package_inspection_requires_complete_session_broker_privileges() {
    let canonical = windows_package_inspection_fixture();
    assert_eq!(
        canonical["session_broker_required_privileges"],
        serde_json::json!([
            "SeAssignPrimaryTokenPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeImpersonatePrivilege",
            "SeSecurityPrivilege",
            "SeTcbPrivilege",
        ])
    );
    validate_agent_package_inspection(
        &serde_json::to_vec(&canonical).unwrap(),
        "1.2.3",
        "source-commit",
    )
    .expect("canonical Windows package inspection should validate");

    let mut stale_validator_identity = canonical;
    stale_validator_identity["session_broker_required_privileges"] = serde_json::json!([
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeTcbPrivilege",
    ]);
    let error = validate_agent_package_inspection(
        &serde_json::to_vec(&stale_validator_identity).unwrap(),
        "1.2.3",
        "source-commit",
    )
    .expect_err("the stale session-broker privilege identity should fail");
    assert!(
        error
            .to_string()
            .contains("sealed agent package inspection differs from the release identity")
    );
}

#[test]
fn windows_package_inspection_binds_bootstrap_runtime_contract() {
    let mut canonical = windows_package_inspection_fixture();
    canonical["target_desktop_bootstrap_normal_imports"] =
        serde_json::json!(["API-MS-WIN-CRT-RUNTIME-L1-1-0.dll"]);
    validate_agent_package_inspection(
        &serde_json::to_vec(&canonical).unwrap(),
        "1.2.3",
        "source-commit",
    )
    .expect("OS-provided UCRT API sets must remain valid bootstrap imports");

    let mut redistributable = canonical;
    redistributable["target_desktop_bootstrap_normal_imports"] =
        serde_json::json!(["VCRUNTIME140.dll"]);
    assert!(
        validate_agent_package_inspection(
            &serde_json::to_vec(&redistributable).unwrap(),
            "1.2.3",
            "source-commit",
        )
        .is_err()
    );

    let mut runtime = windows_package_inspection_fixture();
    runtime["target_desktop_bootstrap_runtime"] = serde_json::json!("full-crt-static");
    assert!(
        validate_agent_package_inspection(
            &serde_json::to_vec(&runtime).unwrap(),
            "1.2.3",
            "source-commit",
        )
        .is_err()
    );
}

#[test]
fn provider_uninstall_proof_rejects_every_residual_path() {
    let temporary = TempDir::new().expect("temporary directory should exist");
    let artifact = temporary.path().join("installed-agent");
    let endpoint = temporary.path().join("sealed-agent.sock");
    let state = temporary.path().join("state");
    fs::write(&artifact, b"agent").expect("artifact should write");
    fs::write(&endpoint, b"endpoint").expect("endpoint should write");
    fs::create_dir(&state).expect("state directory should exist");
    for residual in [&artifact, &endpoint, &state] {
        assert!(verify_absent_paths([residual.as_path()]).is_err());
    }
    fs::remove_file(&artifact).unwrap();
    fs::remove_file(&endpoint).unwrap();
    fs::remove_dir(&state).unwrap();
    verify_absent_paths([artifact.as_path(), endpoint.as_path(), state.as_path()])
        .expect("complete uninstall inventory should be absent");
}

#[test]
fn provider_uninstall_proof_accepts_an_already_absent_inventory() {
    let temporary = TempDir::new().expect("temporary directory should exist");
    let artifact = temporary.path().join("installed-agent");
    let endpoint = temporary.path().join("sealed-agent.sock");
    let state = temporary.path().join("state");
    verify_absent_paths([artifact.as_path(), endpoint.as_path(), state.as_path()])
        .expect("an already removed provider must converge successfully");
}

#[test]
fn linux_provider_absence_inventory_is_exact() {
    assert_eq!(
        LINUX_PROVIDER_ABSENCE_PATHS,
        [
            "/usr/libexec/memcordon-sealed-agent",
            "/usr/lib/systemd/system/memcordon-sealed-agent.service",
            "/usr/lib/systemd/system/memcordon-sealed-agent.socket",
            "/usr/lib/systemd/system/memcordon-sealed-launcher.service",
            "/usr/lib/systemd/system/memcordon-sealed-launcher.socket",
            "/usr/lib/tmpfiles.d/memcordon.conf",
            "/run/memcordon/sealed-agent.sock",
            "/run/memcordon/sealed-launcher.sock",
            "/run/memcordon/sealed-package.lock",
            "/run/memcordon",
            "/var/lib/memcordon/sealed",
            "/sys/fs/cgroup/memcordon-sealed",
        ]
    );
}

#[test]
fn linux_provider_frontend_doctor_and_execution_use_authorized_nonroot_argv() {
    let identity = FrontendIdentity {
        username: "runner".to_owned(),
        uid: 1001,
        provider_gid: 998,
    };
    let cli = frontend_cli();
    assert!(
        cli.is_absolute(),
        "the frontend fixture must remain absolute on every test host"
    );
    let doctor =
        linux_provider_frontend_arguments(&identity, cli, LinuxProviderFrontendStage::Doctor)
            .expect("doctor transition should use structured argv");
    let execution = linux_provider_frontend_arguments(
        &identity,
        cli,
        LinuxProviderFrontendStage::SealedExecution,
    )
    .expect("sealed execution transition should use structured argv");
    let expected_transition = [
        "--non-interactive",
        "--",
        "/usr/bin/setpriv",
        "--reuid",
        "1001",
        "--regid",
        "998",
        "--clear-groups",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--no-new-privs",
        "--",
    ]
    .map(OsString::from);
    assert_eq!(
        doctor,
        [
            expected_transition.as_slice(),
            &[cli.as_os_str().to_os_string()],
            &["doctor", "--require", "sealed"].map(OsString::from),
        ]
        .concat()
    );
    assert_eq!(
        execution,
        [
            expected_transition.as_slice(),
            &[cli.as_os_str().to_os_string()],
            &["--sealed", "--", "/usr/bin/true"].map(OsString::from),
        ]
        .concat()
    );
}

#[test]
#[cfg(unix)]
fn provider_uninstall_proof_does_not_mask_inaccessible_state() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let temporary = TempDir::new().expect("temporary directory should exist");
    let directory = temporary.path().join("inaccessible-state");
    let state = directory.join("state");
    fs::create_dir_all(&state).expect("state directory should exist");
    let previous = fs::metadata(&directory)
        .expect("state directory metadata should exist")
        .permissions();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o000))
        .expect("state directory permissions should change");
    let result = verify_absent_paths([state.as_path()]);
    fs::set_permissions(&directory, previous)
        .expect("state directory permissions should be restored");
    let identity = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .expect("frontend identity should be observable");
    assert!(identity.status.success(), "id -u must succeed");
    if identity.stdout == b"0\n" {
        result.expect("root observes the directory without a permission failure");
        return;
    }
    let error = result.expect_err("an inaccessible state path is not proof of absence");
    assert!(
        error.to_string().contains("state proof failed"),
        "permission evidence must remain explicit: {error}"
    );
}

#[test]
fn canonical_source_tree_resolves_relocated_manifest_readme() {
    let temporary = TempDir::new().expect("temporary workspace should exist");
    let root = temporary.path();
    let package_root = root.join("crates/example");
    let manifest = b"[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2024\"\nreadme = \"../../docs/package-readme.md\"\n";
    let readme = b"# Example package\n";
    let source = b"pub fn example() {}\n";
    fs::create_dir_all(package_root.join("src")).expect("package source directory should exist");
    fs::create_dir_all(root.join("docs")).expect("documentation directory should exist");
    fs::write(
        root.join("Cargo.toml"),
        b"[workspace]\nmembers = [\"crates/example\"]\nresolver = \"2\"\n",
    )
    .expect("workspace manifest should write");
    fs::write(package_root.join("Cargo.toml"), manifest).expect("package manifest should write");
    fs::write(root.join("docs/package-readme.md"), readme)
        .expect("external package README should write");
    fs::write(package_root.join("src/lib.rs"), source).expect("package source should write");

    let inventory = "Cargo.toml\nCargo.toml.orig\npackage-readme.md\nsrc/lib.rs\n";
    let actual = canonical_source_tree(root, "example", inventory)
        .expect("relocated package README should resolve to its manifest source");
    let expected_members = BTreeMap::from([
        ("Cargo.toml.orig".to_owned(), manifest.as_slice()),
        ("package-readme.md".to_owned(), readme.as_slice()),
        ("src/lib.rs".to_owned(), source.as_slice()),
    ]);
    let mut expected = Sha256::new();
    for (path, bytes) in expected_members {
        expected.update(path.as_bytes());
        expected.update([0]);
        expected.update(0o644_u32.to_le_bytes());
        expected.update((bytes.len() as u64).to_le_bytes());
        expected.update(bytes);
    }
    assert_eq!(actual, hex::encode(expected.finalize()));

    let missing = canonical_source_tree(root, "example", "unrelated.md\n")
        .expect_err("unrelated inventory paths must not use workspace-root files");
    assert_eq!(
        missing.to_string(),
        "Cargo package inventory source is missing: \"unrelated.md\""
    );

    fs::remove_file(root.join("docs/package-readme.md"))
        .expect("external package README should be removable");
    let missing_readme = relocated_manifest_source(
        &package_root,
        Path::new("package-readme.md"),
        [("README", Some(Path::new("../../docs/package-readme.md")))],
    )
    .expect_err("missing declared README source must fail closed");
    assert_eq!(
        missing_readme.to_string(),
        "package README source is missing: \"../../docs/package-readme.md\""
    );
}

enum MockResponse {
    Json(u16, serde_json::Value),
    Ndjson(u16, Vec<serde_json::Value>),
    Bytes(u16, Vec<u8>),
    Truncated(Vec<u8>, usize),
    LoseResponse,
}

struct MockServer {
    root: String,
    requests: Arc<Mutex<Vec<String>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl MockServer {
    fn scripted(responses: Vec<MockResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock listener should bind");
        let root = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("mock listener should have an address")
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&requests);
        let thread = std::thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("mock request should arrive");
                let request = read_request(&mut stream);
                observed.lock().expect("request log lock").push(request);
                match response {
                    MockResponse::Json(status, value) => {
                        write_response(
                            &mut stream,
                            status,
                            "application/json",
                            &serde_json::to_vec(&value).expect("mock JSON should serialize"),
                        );
                    }
                    MockResponse::Ndjson(status, values) => {
                        let mut body = Vec::new();
                        for value in values {
                            body.extend(
                                serde_json::to_vec(&value)
                                    .expect("mock NDJSON record should serialize"),
                            );
                            body.push(b'\n');
                        }
                        write_response(&mut stream, status, "application/x-ndjson", &body);
                    }
                    MockResponse::Bytes(status, bytes) => {
                        write_response(&mut stream, status, "application/octet-stream", &bytes);
                    }
                    MockResponse::Truncated(bytes, declared_length) => {
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\n"
                        )
                        .expect("truncated mock headers should write");
                        stream
                            .write_all(&bytes)
                            .expect("truncated mock body should write");
                    }
                    MockResponse::LoseResponse => {}
                }
            }
        });
        Self {
            root,
            requests,
            thread: Some(thread),
        }
    }

    fn finish(mut self) -> Vec<String> {
        self.thread
            .take()
            .expect("mock thread should exist")
            .join()
            .expect("mock thread should finish");
        Arc::try_unwrap(self.requests)
            .expect("request log should have one owner")
            .into_inner()
            .expect("request log lock")
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut reader = BufReader::new(stream);
    let mut first = String::new();
    reader
        .read_line(&mut first)
        .expect("request line should be readable");
    let mut request = first;
    let mut content_length = 0_usize;
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("request header should be readable");
        if line == "\r\n" || line.is_empty() {
            break;
        }
        request.push_str(&line);
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = value.trim().parse().expect("content length should parse");
        }
    }
    let mut body = vec![0_u8; content_length];
    reader
        .read_exact(&mut body)
        .expect("request body should be readable");
    request.push_str(&String::from_utf8_lossy(&body));
    request
}

fn write_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        404 => "Not Found",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Mock",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .expect("mock headers should write");
    stream.write_all(body).expect("mock body should write");
}

fn request_json_body(request: &str) -> serde_json::Value {
    let start = request
        .find('{')
        .expect("JSON request should contain an object body");
    serde_json::from_str(&request[start..]).expect("request JSON should parse")
}

fn release_fixture() -> (TempDir, config::Release) {
    let temporary = TempDir::new().expect("temporary repository should exist");
    let root = temporary.path();
    write_canonical_publication_fixture(root);
    fs::create_dir_all(root.join("ci")).expect("CI directory should exist");
    fs::write(
        root.join("ci/release.toml"),
        include_bytes!("../../../../ci/release.toml"),
    )
    .expect("release config should be copied");
    let release = config::release(root).expect("release config should parse");
    let output = root.join(&release.assets.output_directory);
    fs::create_dir_all(&output).expect("release output should exist");
    let manifest = ReleaseManifest {
        schema_version: config::RELEASE_SCHEMA_VERSION,
        project: "memcordon".to_owned(),
        tag: "1.2.3".to_owned(),
        version: "1.2.3".to_owned(),
        source_commit: "0123456789abcdef".to_owned(),
        workflow_commit: "0123456789abcdef".to_owned(),
        workflow_ref: "Portfoligno/memcordon/.github/workflows/release.yml@refs/tags/1.2.3"
            .to_owned(),
        workflow_sha256: "00".repeat(32),
        action_revisions: BTreeMap::new(),
        prerelease: false,
        rust_toolchain: "1.85.0".to_owned(),
        assets: Vec::new(),
        crates: release
            .publish_packages
            .iter()
            .map(|name| CrateRecord {
                name: name.clone(),
                version: "1.2.3".to_owned(),
                archive_sha256: "ab".repeat(32),
                canonical_tree_sha256: "cd".repeat(32),
                canonical_identity_sha256: "ef".repeat(32),
                vcs_commit: "0123456789abcdef".to_owned(),
            })
            .collect(),
        certification: BTreeMap::new(),
        source_date: "2025-01-01T00:00:00Z".to_owned(),
    };
    write_json(&output.join(&release.assets.manifest), &manifest).expect("manifest should write");
    fs::write(output.join(&release.assets.notes), "notes\n").expect("notes should write");
    (temporary, release)
}

fn write_canonical_publication_fixture(root: &Path) {
    fn dependency_directory(dependency: &str) -> &str {
        match dependency {
            "memcordon-core" => "core",
            "memcordon-platform" => "platform",
            "memcordon-windows-launch-core" => "launch",
            "memcordon" => "cli",
            _ => panic!("unexpected fixture publication dependency"),
        }
    }

    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"core\", \"platform\", \"launch\", \"cli\"]\nresolver = \"2\"\n",
    )
    .expect("fixture workspace should write");
    let packages = [
        ("core", "memcordon-core", Vec::new()),
        (
            "platform",
            "memcordon-platform",
            Vec::from(["memcordon-core"]),
        ),
        (
            "launch",
            "memcordon-windows-launch-core",
            Vec::from(["memcordon-core", "memcordon-platform"]),
        ),
        (
            "cli",
            "memcordon",
            Vec::from([
                "memcordon-core",
                "memcordon-platform",
                "memcordon-windows-launch-core",
            ]),
        ),
    ];
    for (directory, name, dependencies) in packages {
        let package_root = root.join(directory);
        fs::create_dir_all(package_root.join("src")).expect("fixture package should exist");
        let mut manifest = format!(
            "[package]\nname = \"{name}\"\nversion = \"0.5.2\"\npublish = [\"crates-io\"]\n"
        );
        if !dependencies.is_empty() {
            manifest.push_str("[dependencies]\n");
            for dependency in dependencies {
                let dependency_directory = dependency_directory(dependency);
                manifest.push_str(&format!(
                    "{dependency} = {{ path = \"../{dependency_directory}\", version = \"=0.5.2\" }}\n"
                ));
            }
        }
        fs::write(package_root.join("Cargo.toml"), manifest)
            .expect("fixture package manifest should write");
        fs::write(package_root.join("src/lib.rs"), "")
            .expect("fixture package source should write");
    }
}

fn provenance_fixture() -> (TempDir, config::Release, ReleaseIdentity) {
    let (temporary, release) = release_fixture();
    let root = temporary.path();
    fs::create_dir_all(root.join(".github/workflows")).expect("workflow directory should exist");
    fs::write(
        root.join("ci/policy.toml"),
        include_bytes!("../../../../ci/policy.toml"),
    )
    .expect("policy should be copied");
    fs::write(
        root.join("ci/toolchains.toml"),
        include_bytes!("../../../../ci/toolchains.toml"),
    )
    .expect("toolchain policy should be copied");
    fs::write(
        root.join(".github/action-pins.toml"),
        include_bytes!("../../../../.github/action-pins.toml"),
    )
    .expect("action pins should be copied");
    let identity = ReleaseIdentity {
        tag: "1.2.3".to_owned(),
        version: Version::parse("1.2.3").expect("version should parse"),
        commit: "0123456789abcdef".to_owned(),
        changelog_section: "notes".to_owned(),
        source_date: "2025-01-01T00:00:00Z".to_owned(),
    };
    (temporary, release, identity)
}

#[test]
fn release_event_payloads_stay_credential_neutral_and_closed() {
    let dispatch: WorkflowEvent =
        serde_json::from_str(r#"{"inputs":{"tag":"0.2.0"},"repository":{"private":false}}"#)
            .expect("steady-state dispatch payload should parse");
    assert_eq!(
        dispatch.inputs.as_ref().expect("dispatch inputs").tag,
        "0.2.0"
    );
    for payload in [
        r#"{"inputs":{"tag":"0.1.0","registry_auth":"stored-token"}}"#,
        r#"{"inputs":{"tag":"0.1.0","registry_auth":"oidc-fallback"}}"#,
        r#"{"inputs":{"tag":"0.1.0","registry_auth":"unknown"}}"#,
        r#"{"inputs":{"tag":"0.1.0","extra":"forbidden"}}"#,
    ] {
        assert!(
            serde_json::from_str::<WorkflowEvent>(payload).is_err(),
            "credential-choice payloads must no longer parse: {payload}"
        );
    }
}

#[test]
fn publication_slot_requires_a_nonempty_source_agnostic_token() {
    assert!(require_registry_token(None).is_err());
    assert!(require_registry_token(Some(OsStr::new(""))).is_err());
    require_registry_token(Some(OsStr::new("opaque-test-capability")))
        .expect("any nonempty credential source is accepted");
}

#[test]
fn only_the_exact_trusted_publishing_new_crate_rejection_is_recoverable() {
    let exact = format!(
        "error: failed to publish to registry\n\ncaused by:\n  the remote server responded with an error (status 403 Forbidden): {TRUSTED_PUBLISHING_NEW_CRATE_MARKER}\n"
    );
    assert_eq!(
        classify_oidc_failure(&exact, "example-crate"),
        OidcFailureClass::TrustedPublishingNewCrate
    );
    let existing_crate = format!(
        "error: failed to publish to registry\n\ncaused by:\n  the remote server responded with an error (status 403 Forbidden): {ACCESS_TOKEN_CRATE_REJECTION_MARKER}example-crate`\n"
    );
    assert_eq!(
        classify_oidc_failure(&existing_crate, "example-crate"),
        OidcFailureClass::TrustedPublishingExistingCrate
    );
    for near_miss in [
        "",
        "error: failed to publish to registry",
        "the remote server responded with an error (status 403 Forbidden)",
        "Trusted Publishing tokens do not support creating new crates",
        "trusted publishing tokens do not support creating new crates. publish the crate manually, first",
        "error: unauthorized (status 401 Unauthorized)",
        ACCESS_TOKEN_CRATE_REJECTION_MARKER,
        "The provided access token is not valid for crate `other-crate`",
        "The provided access token is not valid for crate `example-crate",
    ] {
        assert_eq!(
            classify_oidc_failure(near_miss, "example-crate"),
            OidcFailureClass::Other,
            "near-miss diagnostics must fail closed: {near_miss}"
        );
    }
    let conflicting_diagnostics = format!(
        "{ACCESS_TOKEN_CRATE_REJECTION_MARKER}other-crate`\n{TRUSTED_PUBLISHING_NEW_CRATE_MARKER}\n"
    );
    assert_eq!(
        classify_oidc_failure(&conflicting_diagnostics, "example-crate"),
        OidcFailureClass::Other,
        "an existing-crate rejection must disqualify a mixed diagnostic transcript"
    );
}

#[test]
fn publication_evidence_redacts_and_binds_cargo_diagnostics() {
    let credential = "opaque-test-capability";
    let stderr = format!("publishing failed for token {credential} exactly once");
    let observed = ObservedOutput {
        status: std::process::ExitStatus::default(),
        stdout: b"    Packaged memcordon-core".to_vec(),
        stderr: stderr.into_bytes(),
        elapsed: Duration::from_millis(1),
    };
    let diagnostics = cargo_diagnostics(Some(&observed), None, credential).expect("diagnostics");
    assert!(!diagnostics.stderr.contains(credential));
    assert!(diagnostics.stderr.contains("[redacted]"));
    assert_eq!(diagnostics.stderr_sha256, sha256_text(&diagnostics.stderr));
    assert_eq!(diagnostics.stdout_sha256, sha256_text(&diagnostics.stdout));

    let oversized = ObservedOutput {
        stdout: vec![0_u8; MAXIMUM_CARGO_DIAGNOSTIC_BYTES + 1],
        ..observed
    };
    assert!(cargo_diagnostics(Some(&oversized), None, credential).is_err());

    let invalid_utf8 = ObservedOutput {
        stderr: vec![0xff],
        ..diagnostics_placeholder()
    };
    assert!(cargo_diagnostics(Some(&invalid_utf8), None, credential).is_err());
}

fn diagnostics_placeholder() -> ObservedOutput {
    ObservedOutput {
        status: std::process::ExitStatus::default(),
        stdout: Vec::new(),
        stderr: Vec::new(),
        elapsed: Duration::from_millis(1),
    }
}

#[test]
fn live_cargo_output_is_redacted_before_relay_and_failure_reporting() {
    let credential = "opaque-test-capability";
    let observed = ObservedOutput {
        status: std::process::ExitStatus::default(),
        stdout: format!("publishing with {credential}\n").into_bytes(),
        stderr: format!("registry rejected token {credential}\n").into_bytes(),
        elapsed: Duration::from_millis(1),
    };
    let (relay_stdout, relay_stderr) = redacted_console_output(&observed, credential);
    assert!(!relay_stdout.contains(credential));
    assert!(!relay_stderr.contains(credential));
    assert_eq!(relay_stdout.matches("[redacted]").count(), 1);
    assert_eq!(relay_stderr.matches("[redacted]").count(), 1);

    let observed_failure = CargoPublicationAttempt {
        observed: Some(observed),
        process_error: None,
    };
    let failure_text = publication_failure(&observed_failure, credential).to_string();
    assert!(!failure_text.contains(credential));

    let process_failure = CargoPublicationAttempt {
        observed: None,
        process_error: Some(format!("spawn failed after using {credential}")),
    };
    let failure_text = publication_failure(&process_failure, credential).to_string();
    assert!(!failure_text.contains(credential));
}

#[test]
fn one_new_crate_token_attempt_is_evidence_bounded() {
    let base = PublicationSlotEvidence {
        schema_version: PUBLICATION_EVIDENCE_SCHEMA_VERSION,
        publication_slot: NonZeroUsize::new(3).expect("slot is nonzero"),
        release: ReleaseBinding {
            tag: "0.5.2".to_owned(),
            source_commit: "source".to_owned(),
            workflow_commit: "workflow".to_owned(),
        },
        run: PublicationRunIdentity {
            run_id: "123".to_owned(),
            run_attempt: "1".to_owned(),
        },
        crate_binding: CrateBinding {
            name: "example".to_owned(),
            version: "0.5.2".to_owned(),
            archive_sha256: "ab".repeat(32),
        },
        records: vec![
            publication_record(
                CredentialOrigin::Oidc,
                PublicationOutcome::OidcRejectedNewCrate,
                PublicNameState::Absent,
                None,
            ),
            publication_record(
                CredentialOrigin::Oidc,
                PublicationOutcome::NewCrateAuthorized,
                PublicNameState::Absent,
                None,
            ),
        ],
    };
    assert!(evidence_authorizes_token_provider(&base));
    assert!(evidence_allows_new_token_attempt(&base));

    let existing_crate_rejection = PublicationSlotEvidence {
        records: vec![publication_record(
            CredentialOrigin::Oidc,
            PublicationOutcome::OidcRejectedExistingCrate,
            PublicNameState::Present,
            None,
        )],
        ..base.clone()
    };
    assert!(!evidence_authorizes_token_provider(
        &existing_crate_rejection
    ));

    let with_token_record = |outcome: PublicationOutcome| PublicationSlotEvidence {
        records: base
            .records
            .iter()
            .cloned()
            .chain(std::iter::once(publication_record(
                CredentialOrigin::NewCrateToken,
                outcome,
                PublicNameState::Absent,
                None,
            )))
            .collect(),
        ..base.clone()
    };
    let in_flight = with_token_record(PublicationOutcome::TokenAttemptStarted);
    assert!(evidence_authorizes_token_provider(&in_flight));
    assert!(!evidence_allows_new_token_attempt(&in_flight));
    for terminal in [
        PublicationOutcome::TokenPubliclyAccepted,
        PublicationOutcome::TokenRejected,
    ] {
        let terminal = with_token_record(terminal);
        assert!(!evidence_authorizes_token_provider(&terminal));
        assert!(!evidence_allows_new_token_attempt(&terminal));
    }
}

#[test]
fn slot_evidence_serialization_is_credential_free_and_closed() {
    let evidence = PublicationSlotEvidence {
        schema_version: PUBLICATION_EVIDENCE_SCHEMA_VERSION,
        publication_slot: NonZeroUsize::new(3).expect("slot is nonzero"),
        release: ReleaseBinding {
            tag: "0.5.2".to_owned(),
            source_commit: "source".to_owned(),
            workflow_commit: "workflow".to_owned(),
        },
        run: PublicationRunIdentity {
            run_id: "123".to_owned(),
            run_attempt: "1".to_owned(),
        },
        crate_binding: CrateBinding {
            name: "example".to_owned(),
            version: "0.5.2".to_owned(),
            archive_sha256: "ab".repeat(32),
        },
        records: vec![publication_record(
            CredentialOrigin::Oidc,
            PublicationOutcome::OidcRejectedNewCrate,
            PublicNameState::Absent,
            None,
        )],
    };
    let bytes = serde_json::to_vec(&evidence).expect("evidence should serialize");
    let text = std::str::from_utf8(&bytes).expect("evidence should be UTF-8");
    for forbidden in ["token", "credential_value", "CARGO_REGISTRIES"] {
        assert!(!text.contains(forbidden), "evidence leaked {forbidden}");
    }
    assert!(
        serde_json::from_str::<PublicationSlotEvidence>(
            r#"{
            "schema_version": 1,
            "publication_slot": 3,
            "release": {"tag":"0.5.2","source_commit":"s","workflow_commit":"w"},
            "run": {"run_id":"1","run_attempt":"1"},
            "crate_binding": {"name":"n","version":"1","archive_sha256":"a"},
            "records": [],
            "extra": true
        }"#
        )
        .is_err()
    );
}

#[test]
fn dynamic_release_identity_accepts_only_one_agreeing_version() {
    let stable = Version::new(9, 8, 7);
    validate_dynamic_release_identity(
        stable.to_string().as_str(),
        stable.to_string().as_str(),
        &stable,
    )
    .expect("a stable release is accepted when every identity agrees");

    let prerelease = Version::parse("9.8.7-rc.1").unwrap();
    validate_dynamic_release_identity(
        prerelease.to_string().as_str(),
        prerelease.to_string().as_str(),
        &prerelease,
    )
    .expect("a normal prerelease is accepted when every identity agrees");

    let different = Version::new(9, 8, 8);
    assert!(
        validate_dynamic_release_identity(
            stable.to_string().as_str(),
            different.to_string().as_str(),
            &stable,
        )
        .is_err(),
        "a manifest-only version change must not authorize publication"
    );
    assert!(
        validate_dynamic_release_identity(
            stable.to_string().as_str(),
            stable.to_string().as_str(),
            &different,
        )
        .is_err(),
        "a workspace-only version change must not authorize publication"
    );
    let development = Version::parse("9.8.7-dev").unwrap();
    assert!(
        validate_dynamic_release_identity(
            development.to_string().as_str(),
            development.to_string().as_str(),
            &development,
        )
        .is_err(),
        "development versions remain ineligible as immutable releases"
    );
    assert!(
        validate_dynamic_release_identity("not-semver", stable.to_string().as_str(), &stable)
            .is_err(),
        "a malformed tag must fail closed"
    );
    assert!(
        validate_dynamic_release_identity(stable.to_string().as_str(), "not-semver", &stable,)
            .is_err(),
        "a malformed manifest version must fail closed"
    );
}

#[test]
fn fallback_policy_rejects_tags_after_the_dynamic_release_bound() {
    let release = Version::parse("9.8.7-rc.1").expect("release version should parse");
    let inventory =
        b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\trefs/tags/9.8.6\n\
        0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\trefs/tags/9.8.7-rc.1\n";
    validate_fallback_remote_tags(inventory, &release)
        .expect("earlier tags and the exact dynamic release are eligible");
    let later =
        b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\trefs/tags/9.8.8\n";
    assert!(validate_fallback_remote_tags(later, &release).is_err());
}

#[test]
fn credential_provider_binds_origin_slot_and_artifact_identity() {
    let (temporary, release) = release_fixture();
    let manifest_path = temporary
        .path()
        .join(&release.assets.output_directory)
        .join(&release.assets.manifest);
    let manifest: ReleaseManifest =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest should read"))
            .expect("manifest should parse");
    let record = manifest
        .crates
        .first()
        .expect("release fixture should contain the core crate")
        .clone();
    let slot = NonZeroUsize::new(1).expect("slot is nonzero");
    let run = PublicationRunIdentity {
        run_id: "1234567890".to_owned(),
        run_attempt: "1".to_owned(),
    };
    let arguments = serde_json::json!([
        "oidc",
        "1",
        record.name.clone(),
        record.version.clone(),
        record.archive_sha256.clone(),
    ]);
    let read_message = serde_json::json!({
        "v": 1,
        "registry": {
            "index-url": "sparse+https://index.crates.io/",
            "name": "crates-io",
            "headers": ["WWW-Authenticate: Cargo login_url=https://crates.io/me"],
        },
        "kind": "get",
        "operation": "read",
        "args": arguments.clone(),
    });
    let read_request: CredentialRequest = serde_json::from_value(read_message.clone())
        .expect("Cargo read request without publish fields should parse");
    validate_credential_request(temporary.path(), &read_request)
        .expect("bound read request should pass");

    let mut read_output = Vec::new();
    let mut read_wire = serde_json::to_vec(&read_message).expect("read request should encode");
    read_wire.push(b'\n');
    cargo_credential_provider_io(
        temporary.path(),
        Cursor::new(read_wire),
        &mut read_output,
        || Some("opaque-test-capability".to_owned()),
        || Ok(run.clone()),
    )
    .expect("Cargo read transcript should complete");
    let read_lines: Vec<serde_json::Value> = read_output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("provider output should be JSON"))
        .collect();
    assert_eq!(read_lines[0], serde_json::json!({ "v": [1] }));
    assert_eq!(read_lines[1]["Ok"]["kind"], "get");
    assert_eq!(read_lines[1]["Ok"]["cache"], "never");
    assert_eq!(read_lines[1]["Ok"]["operation_independent"], false);
    assert_eq!(read_lines[1]["Ok"]["token"], "opaque-test-capability");

    let publish_message = serde_json::json!({
        "v": 1,
        "registry": {
            "index-url": "sparse+https://index.crates.io/",
            "name": "crates-io",
        },
        "kind": "get",
        "operation": "publish",
        "name": record.name.clone(),
        "vers": record.version.clone(),
        "cksum": record.archive_sha256.clone(),
        "args": arguments.clone(),
    });
    let publish_request: CredentialRequest = serde_json::from_value(publish_message.clone())
        .expect("Cargo publish request should parse");
    validate_credential_request(temporary.path(), &publish_request)
        .expect("exact publish request should pass");
    let accepted = credential_response(
        temporary.path(),
        Ok(publish_request.clone()),
        || Some("opaque-test-capability".to_owned()),
        || Ok(run.clone()),
    );
    assert_eq!(accepted["Ok"]["kind"], "get");
    assert_eq!(accepted["Ok"]["cache"], "never");
    assert_eq!(accepted["Ok"]["operation_independent"], false);
    assert_eq!(accepted["Ok"]["token"], "opaque-test-capability");
    let missing = credential_response(
        temporary.path(),
        Ok(publish_request.clone()),
        || None,
        || Ok(run.clone()),
    );
    assert_eq!(missing["Err"]["kind"], "other");

    let mut missing_args = read_message.clone();
    missing_args
        .as_object_mut()
        .expect("request should be an object")
        .remove("args");
    let missing_args = serde_json::from_value::<CredentialRequest>(missing_args)
        .expect("Cargo request may omit empty args");
    let missing_args = credential_response(
        temporary.path(),
        Ok(missing_args),
        || Some("opaque-test-capability".to_owned()),
        || Ok(run.clone()),
    );
    assert_eq!(missing_args["Err"]["kind"], "other");
    assert_eq!(
        missing_args["Err"]["message"],
        "Cargo credential provider configuration identity is invalid"
    );

    let unsupported: CredentialRequest = serde_json::from_value(serde_json::json!({
        "v": 1,
        "registry": {
            "index-url": "sparse+https://index.crates.io/",
            "name": "crates-io",
        },
        "kind": "get",
        "operation": "yank",
        "args": arguments,
    }))
    .expect("unsupported Cargo operation should still parse");
    let unsupported = credential_response(
        temporary.path(),
        Ok(unsupported),
        || Some("opaque-test-capability".to_owned()),
        || Ok(run.clone()),
    );
    assert_eq!(unsupported["Err"]["kind"], "operation-not-supported");

    let malformed = credential_response(
        temporary.path(),
        serde_json::from_str::<CredentialRequest>("not JSON"),
        || Some("opaque-test-capability".to_owned()),
        || Ok(run.clone()),
    );
    assert_eq!(malformed["Err"]["kind"], "other");
    assert_eq!(
        malformed["Err"]["message"],
        "Cargo credential request is malformed"
    );

    let cargo_config =
        cargo_publish_config(temporary.path(), &record, CredentialOrigin::Oidc, slot)
            .expect("isolated Cargo configuration should be prepared");
    let provider_config = fs::read_to_string(cargo_config).expect("config should read");
    assert!(!provider_config.contains("opaque-test-capability"));
    let provider_config: toml::Value =
        toml::from_str(&provider_config).expect("config should parse");
    let provider = provider_config["registry"]["credential-provider"]
        .as_array()
        .expect("provider should be an argv array");
    assert_eq!(provider.len(), 6);
    assert_eq!(provider[1].as_str(), Some("oidc"));
    assert_eq!(provider[2].as_str(), Some("1"));
    assert_eq!(provider[3].as_str(), Some(record.name.as_str()));
    assert_eq!(provider[4].as_str(), Some(record.version.as_str()));
    assert_eq!(provider[5].as_str(), Some(record.archive_sha256.as_str()));

    let mut wrong_checksum = publish_request.clone();
    let CredentialAction::Get {
        operation: CredentialOperation::Publish { cksum, .. },
    } = &mut wrong_checksum.action
    else {
        panic!("publish request should retain its operation");
    };
    *cksum = "00".repeat(32);
    assert!(validate_credential_request(temporary.path(), &wrong_checksum).is_err());
    let mut wrong_argv = publish_request;
    wrong_argv.args = vec![
        "oidc".to_owned(),
        "2".to_owned(),
        record.name.clone(),
        record.version.clone(),
        record.archive_sha256.clone(),
    ];
    let error = validate_credential_request(temporary.path(), &wrong_argv)
        .expect_err("Cargo request arguments must select the configured slot");
    assert!(error.to_string().contains("selected publication slot"));

    let token_arguments = serde_json::json!([
        "new-crate-token",
        "1",
        record.name.clone(),
        record.version.clone(),
        record.archive_sha256.clone(),
    ]);
    let mut token_read_message = read_message.clone();
    token_read_message
        .as_object_mut()
        .expect("request should be an object")
        .insert("args".to_owned(), token_arguments.clone());
    let token_read: CredentialRequest = serde_json::from_value(token_read_message.clone())
        .expect("token-origin read request should parse");
    let read_invoked = Cell::new(false);
    let unauthorized_read = credential_response(
        temporary.path(),
        Ok(token_read.clone()),
        || {
            read_invoked.set(true);
            Some("new-crate-capability".to_owned())
        },
        || Ok(run.clone()),
    );
    assert_eq!(unauthorized_read["Err"]["kind"], "other");
    assert!(!read_invoked.get());

    let mut foreign_origin = token_read.clone();
    foreign_origin.args[0] = "token-first".to_owned();
    let foreign_origin = credential_response(
        temporary.path(),
        Ok(foreign_origin),
        || {
            read_invoked.set(true);
            Some("new-crate-capability".to_owned())
        },
        || Ok(run.clone()),
    );
    assert_eq!(foreign_origin["Err"]["kind"], "other");
    assert_eq!(
        foreign_origin["Err"]["message"],
        "unknown credential-provider origin in Cargo request args: token-first"
    );
    assert!(!read_invoked.get());

    let mut foreign_registry_message = token_read_message.clone();
    foreign_registry_message
        .as_object_mut()
        .expect("request should be an object")
        .insert(
            "registry".to_owned(),
            serde_json::json!({
                "index-url": "sparse+https://private.example/index/",
                "name": "private",
            }),
        );
    let foreign_registry: CredentialRequest = serde_json::from_value(foreign_registry_message)
        .expect("a foreign-registry read request should parse");
    let foreign_registry = credential_response(
        temporary.path(),
        Ok(foreign_registry),
        || {
            read_invoked.set(true);
            Some("new-crate-capability".to_owned())
        },
        || Ok(run.clone()),
    );
    assert_eq!(foreign_registry["Err"]["kind"], "other");
    assert_eq!(
        foreign_registry["Err"]["message"],
        "Cargo credential request identity is invalid"
    );
    assert!(!read_invoked.get());

    let mut token_publish_message = publish_message.clone();
    token_publish_message
        .as_object_mut()
        .expect("request should be an object")
        .insert("args".to_owned(), token_arguments);
    let token_publish: CredentialRequest = serde_json::from_value(token_publish_message)
        .expect("token-origin publish request should parse");
    let publish_invoked = Cell::new(false);
    let unauthorized = credential_response(
        temporary.path(),
        Ok(token_publish.clone()),
        || {
            publish_invoked.set(true);
            Some("new-crate-capability".to_owned())
        },
        || Ok(run.clone()),
    );
    assert_eq!(unauthorized["Err"]["kind"], "other");
    assert!(!publish_invoked.get());

    let release_binding = ReleaseBinding::from_manifest(&manifest);
    let crate_binding = CrateBinding::from_record(&record);
    establish_slot_evidence(
        temporary.path(),
        slot,
        &release_binding,
        &run,
        &crate_binding,
    )
    .expect("evidence should be established");
    append_publication_record(
        temporary.path(),
        &release,
        slot,
        publication_record(
            CredentialOrigin::Oidc,
            PublicationOutcome::OidcRejectedNewCrate,
            PublicNameState::Absent,
            None,
        ),
    )
    .expect("rejection evidence should append");
    let still_unauthorized = credential_response(
        temporary.path(),
        Ok(token_publish.clone()),
        || {
            publish_invoked.set(true);
            Some("new-crate-capability".to_owned())
        },
        || Ok(run.clone()),
    );
    assert_eq!(still_unauthorized["Err"]["kind"], "other");
    assert!(!publish_invoked.get());

    append_publication_record(
        temporary.path(),
        &release,
        slot,
        publication_record(
            CredentialOrigin::Oidc,
            PublicationOutcome::NewCrateAuthorized,
            PublicNameState::Absent,
            None,
        ),
    )
    .expect("authorization evidence should append");
    let evidence_before_read =
        fs::read(slot_evidence_path(temporary.path(), slot)).expect("evidence should read");
    let mut fallback_read_wire =
        serde_json::to_vec(&token_read_message).expect("fallback read request should encode");
    fallback_read_wire.push(b'\n');
    let mut fallback_read_output = Vec::new();
    cargo_credential_provider_io(
        temporary.path(),
        Cursor::new(fallback_read_wire),
        &mut fallback_read_output,
        || {
            read_invoked.set(true);
            Some("new-crate-capability".to_owned())
        },
        || Ok(run.clone()),
    )
    .expect("fallback index-read transcript should complete");
    let fallback_read_lines: Vec<serde_json::Value> = fallback_read_output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("provider output should be JSON"))
        .collect();
    assert_eq!(fallback_read_lines[0], serde_json::json!({ "v": [1] }));
    assert_eq!(fallback_read_lines[1]["Ok"]["kind"], "get");
    assert_eq!(fallback_read_lines[1]["Ok"]["cache"], "never");
    assert_eq!(fallback_read_lines[1]["Ok"]["operation_independent"], false);
    assert_eq!(
        fallback_read_lines[1]["Ok"]["token"],
        "new-crate-capability"
    );
    assert!(read_invoked.get());
    let evidence_after_read =
        fs::read(slot_evidence_path(temporary.path(), slot)).expect("evidence should read");
    assert_eq!(
        evidence_after_read, evidence_before_read,
        "a registry read must not consume the one publication attempt"
    );

    let authorized = credential_response(
        temporary.path(),
        Ok(token_publish.clone()),
        || {
            publish_invoked.set(true);
            Some("new-crate-capability".to_owned())
        },
        || Ok(run.clone()),
    );
    assert_eq!(authorized["Ok"]["token"], "new-crate-capability");
    assert!(publish_invoked.get());
    let evidence_after_publish =
        load_slot_evidence(temporary.path(), slot).expect("publication evidence should read");
    assert_eq!(
        evidence_after_publish
            .records
            .iter()
            .filter(|record| record.outcome == PublicationOutcome::TokenAttemptStarted)
            .count(),
        1,
        "only the publish request should record the actual attempt"
    );
    assert!(!evidence_allows_new_token_attempt(&evidence_after_publish));
    let duplicate_invoked = Cell::new(false);
    let duplicate_publish = credential_response(
        temporary.path(),
        Ok(token_publish.clone()),
        || {
            duplicate_invoked.set(true);
            Some("new-crate-capability".to_owned())
        },
        || Ok(run.clone()),
    );
    assert_eq!(duplicate_publish["Err"]["kind"], "other");
    assert!(!duplicate_invoked.get());

    append_publication_record(
        temporary.path(),
        &release,
        slot,
        publication_record(
            CredentialOrigin::NewCrateToken,
            PublicationOutcome::TokenRejected,
            PublicNameState::Absent,
            None,
        ),
    )
    .expect("terminal token evidence should append");
    let retry_invoked = Cell::new(false);
    let forbidden_retry = credential_response(
        temporary.path(),
        Ok(token_publish),
        || {
            retry_invoked.set(true);
            Some("new-crate-capability".to_owned())
        },
        || Ok(run.clone()),
    );
    assert_eq!(forbidden_retry["Err"]["kind"], "other");
    assert!(
        !retry_invoked.get(),
        "a prior terminal token attempt must forbid every further token read"
    );

    let evidence_text = fs::read_to_string(slot_evidence_path(temporary.path(), slot))
        .expect("slot evidence should read");
    assert!(!evidence_text.contains("new-crate-capability"));
    assert!(!evidence_text.contains("opaque-test-capability"));
    let aggregate_text = fs::read_to_string(aggregate_evidence_path(temporary.path()))
        .expect("aggregate evidence should read");
    assert!(!aggregate_text.contains("new-crate-capability"));
}

#[test]
fn publication_cursor_selects_only_the_first_absent_configured_crate() {
    let packages: Vec<String> = [
        "memcordon-core",
        "memcordon-platform",
        "memcordon-windows-launch-core",
        "memcordon",
    ]
    .map(str::to_owned)
    .to_vec();
    let slot = |value: usize| NonZeroUsize::new(value).expect("slot is nonzero");
    assert_eq!(
        resolve_first_absent_slot(&packages, None, slot(1))
            .expect("a complete registry is idempotent"),
        None
    );
    assert_eq!(
        resolve_first_absent_slot(&packages, Some("memcordon-platform"), slot(2))
            .expect("the exact first-absent slot is selected"),
        Some(1)
    );
    assert!(resolve_first_absent_slot(&packages, Some("memcordon-platform"), slot(1)).is_err());
    assert!(resolve_first_absent_slot(&packages, Some("memcordon-platform"), slot(3)).is_err());
    assert!(resolve_first_absent_slot(&packages, Some("memcordon"), slot(5)).is_err());
}

#[test]
fn immutable_publication_report_has_no_credential_origin() {
    let report = PublicationReport {
        schema_version: 2,
        manifest_sha256: "digest".to_owned(),
        github_release_id: 7,
        source_commit: "commit".to_owned(),
        workflow_commit: "workflow".to_owned(),
        prerelease: false,
        assets: Vec::new(),
        crates: Vec::new(),
    };
    let bytes = serde_json::to_vec(&report).expect("report should serialize");
    let text = std::str::from_utf8(&bytes).expect("report should be UTF-8");
    for forbidden in ["token", "credential", "registry_auth"] {
        assert!(!text.contains(forbidden));
    }
}

fn remote(draft: bool) -> serde_json::Value {
    serde_json::json!({
        "id": 41,
        "tag_name": "1.2.3",
        "target_commitish": "0123456789abcdef",
        "prerelease": false,
        "draft": draft,
        "assets": [],
    })
}

fn sparse_record(name: &str, version: &str, yanked: bool) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "vers": version,
        "cksum": "published",
        "yanked": yanked,
    })
}

fn verifier_crate_record(archive_sha256: &str) -> CrateRecord {
    CrateRecord {
        name: "example".to_owned(),
        version: "1.2.3".to_owned(),
        archive_sha256: archive_sha256.to_owned(),
        canonical_tree_sha256: "tree-digest".to_owned(),
        canonical_identity_sha256: "identity-digest".to_owned(),
        vcs_commit: "0123456789abcdef".to_owned(),
    }
}

fn remote_asset(path: &Path, id: u64) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "name": path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("asset name should be UTF-8"),
        "size": fs::metadata(path).expect("asset metadata").len(),
        "digest": format!("sha256:{}", sha256_file(path).expect("asset digest")),
        "url": "unused",
    })
}

fn write_crate(path: &Path, manifest: &str, commit: &str, reverse: bool) {
    let file = File::create(path).expect("crate archive should be created");
    let encoder = GzEncoder::new(file, Compression::best());
    let mut archive = tar::Builder::new(encoder);
    let vcs = serde_json::to_vec(&serde_json::json!({
        "git": {"sha1": commit},
        "path_in_vcs": "crates/example",
        "dirty": false,
    }))
    .expect("VCS JSON should serialize");
    let mut entries = vec![
        ("example-1.2.3/Cargo.toml", manifest.as_bytes().to_vec()),
        ("example-1.2.3/.cargo_vcs_info.json", vcs),
        (
            "example-1.2.3/src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n".to_vec(),
        ),
    ];
    if reverse {
        entries.reverse();
    }
    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive
            .append_data(&mut header, name, bytes.as_slice())
            .expect("archive member should append");
    }
    archive.finish().expect("archive should finish");
    archive
        .into_inner()
        .expect("encoder should be returned")
        .finish()
        .expect("gzip should finish");
}

#[test]
fn mock_github_fresh_release_creates_one_draft() {
    let calls = Cell::new(0);
    let created = existing_or_create(None, || {
        calls.set(calls.get() + 1);
        Ok(remote(true))
    })
    .expect("fresh release should create");
    assert_eq!(calls.get(), 1);
    assert_eq!(
        classify_remote_release(&created, "1.2.3", "0123456789abcdef", false)
            .expect("created draft should classify"),
        RemoteReleaseState::Draft(41)
    );
}

#[test]
fn mock_github_exact_existing_draft_is_not_created_again() {
    let calls = Cell::new(0);
    let existing = existing_or_create(Some(remote(true)), || {
        calls.set(calls.get() + 1);
        Ok(remote(true))
    })
    .expect("existing draft should reconcile");
    assert_eq!(calls.get(), 0);
    assert_eq!(
        classify_remote_release(&existing, "1.2.3", "0123456789abcdef", false)
            .expect("draft should classify"),
        RemoteReleaseState::Draft(41)
    );
}

#[test]
fn mock_github_exact_published_release_is_immutable_and_reconciled() {
    let calls = Cell::new(0);
    let existing = existing_or_create(Some(remote(false)), || {
        calls.set(calls.get() + 1);
        Ok(remote(true))
    })
    .expect("published release should reconcile");
    assert_eq!(calls.get(), 0);
    assert_eq!(
        classify_remote_release(&existing, "1.2.3", "0123456789abcdef", false)
            .expect("published release should classify"),
        RemoteReleaseState::Published(41)
    );
}

#[test]
fn mock_github_partial_rerun_reuses_existing_state() {
    let calls = Cell::new(0);
    let _ = existing_or_create(Some(remote(true)), || {
        calls.set(calls.get() + 1);
        Ok(remote(true))
    })
    .expect("partial rerun should resume");
    assert_eq!(calls.get(), 0);
}

#[test]
fn mock_github_identity_conflict_hard_fails() {
    let mut conflicting = remote(true);
    conflicting["target_commitish"] = serde_json::json!("different");
    assert!(classify_remote_release(&conflicting, "1.2.3", "0123456789abcdef", false).is_err());
}

#[test]
fn deterministic_crate_identity_ignores_archive_input_order() {
    let temporary = TempDir::new().expect("temporary directory should exist");
    let first = temporary.path().join("first.crate");
    let second = temporary.path().join("second.crate");
    let manifest =
        "[package]\nname = \"example\"\nversion = \"1.2.3\"\n\n[dependencies]\nserde = \"1\"\n";
    write_crate(&first, manifest, "0123456789abcdef", false);
    write_crate(&second, manifest, "0123456789abcdef", true);
    assert_eq!(
        canonical_crate_identity(&first).expect("first identity"),
        canonical_crate_identity(&second).expect("second identity")
    );
}

#[test]
fn crate_archive_hashes_render_nested_host_paths_with_archive_separators() {
    let nested = PathBuf::from("src").join("lib.rs");
    let archive_path = PathBuf::from("example-1.2.3").join(nested);
    assert_eq!(
        archive_member_path(&archive_path).expect("nested member path should normalize"),
        "src/lib.rs"
    );
}

#[test]
fn crate_archive_tree_and_identity_use_archive_member_bytes() {
    let temporary = TempDir::new().expect("temporary directory should exist");
    let archive = temporary.path().join("example.crate");
    let manifest =
        "[package]\nname = \"example\"\nversion = \"1.2.3\"\n\n[dependencies]\nserde = \"1\"\n";
    let source = b"pub fn value() -> u8 { 1 }\n";
    write_crate(&archive, manifest, "0123456789abcdef", false);

    let mut tree = Sha256::new();
    tree.update(b"src/lib.rs");
    tree.update([0]);
    tree.update(0o644_u32.to_le_bytes());
    tree.update((source.len() as u64).to_le_bytes());
    tree.update(source);
    assert_eq!(
        canonical_crate_tree(&archive).expect("archive tree should canonicalize"),
        hex::encode(tree.finalize())
    );

    let manifest_value: toml::Value = toml::from_str(manifest).expect("manifest should parse");
    let normalized_manifest =
        toml::to_string(&manifest_value).expect("normalized manifest should serialize");
    let vcs = serde_json::json!({
        "git": {"sha1": "0123456789abcdef"},
        "path_in_vcs": "crates/example",
        "dirty": false,
    });
    let normalized_vcs = serde_json::to_vec(&vcs).expect("normalized provenance should serialize");
    let identity_members = BTreeMap::from([
        (
            ".cargo_vcs_info.json".to_owned(),
            (0o644_u32, normalized_vcs),
        ),
        (
            "Cargo.toml".to_owned(),
            (0o644_u32, normalized_manifest.into_bytes()),
        ),
        ("src/lib.rs".to_owned(), (0o644_u32, source.to_vec())),
    ]);
    let mut identity = Sha256::new();
    for (path, (mode, bytes)) in identity_members {
        identity.update(path.as_bytes());
        identity.update([0]);
        identity.update(mode.to_le_bytes());
        identity.update((bytes.len() as u64).to_le_bytes());
        identity.update(bytes);
    }
    assert_eq!(
        canonical_crate_identity(&archive)
            .expect("archive identity should canonicalize")
            .sha256,
        hex::encode(identity.finalize())
    );
}

#[test]
fn crate_archive_hashing_cannot_render_host_dependent_paths() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("release.rs"),
    )
    .expect("release source should be readable from the test");
    let forbidden = ["path.to_string_lossy()", "as_bytes()"].join("");
    assert!(
        !source.contains(&forbidden),
        "crate member paths must be encoded as archive-format strings before hashing"
    );
}

#[test]
fn mock_registry_same_version_manifest_or_provenance_conflict_hard_fails() {
    let temporary = TempDir::new().expect("temporary directory should exist");
    let expected = temporary.path().join("expected.crate");
    let dependency_conflict = temporary.path().join("dependency-conflict.crate");
    let provenance_conflict = temporary.path().join("provenance-conflict.crate");
    write_crate(
        &expected,
        "[package]\nname = \"example\"\nversion = \"1.2.3\"\n\n[dependencies]\nserde = \"1\"\n",
        "0123456789abcdef",
        false,
    );
    write_crate(
        &dependency_conflict,
        "[package]\nname = \"example\"\nversion = \"1.2.3\"\n\n[dependencies]\nserde = \"2\"\n",
        "0123456789abcdef",
        false,
    );
    write_crate(
        &provenance_conflict,
        "[package]\nname = \"example\"\nversion = \"1.2.3\"\n\n[dependencies]\nserde = \"1\"\n",
        "fedcba9876543210",
        false,
    );
    let identity = canonical_crate_identity(&expected).expect("expected identity");
    assert_ne!(
        identity.sha256,
        canonical_crate_identity(&dependency_conflict)
            .expect("dependency identity")
            .sha256
    );
    assert_ne!(
        identity.sha256,
        canonical_crate_identity(&provenance_conflict)
            .expect("provenance identity")
            .sha256
    );
}

#[test]
fn archive_inspection_rejects_traversal() {
    assert!(safe_archive_path(Path::new("../escape")).is_err());
    assert!(safe_archive_path(Path::new("/absolute")).is_err());
    assert_eq!(
        safe_archive_path(Path::new("root/bin")).expect("safe path"),
        PathBuf::from("root/bin")
    );
}

#[test]
fn archive_member_read_diagnostics_identify_operation_member_and_path() {
    let temporary = TempDir::new().expect("temporary extraction root should exist");
    let relative = Path::new("top/CHANGELOG.md");
    let expected_path = temporary.path().join(relative);
    let error = read_archive_member(
        temporary.path(),
        "top/CHANGELOG.md",
        relative,
        "document validation",
    )
    .expect_err("missing archive member read should fail");
    let message = error.to_string();
    assert!(
        message.contains("operation=document validation")
            && message.contains("member=\"top/CHANGELOG.md\"")
            && message.contains(format!("path={expected_path:?}").as_str()),
        "archive member diagnostics should identify the exact operation and path: {message}"
    );
}

#[test]
fn canonical_archive_members_read_through_their_extracted_paths_once() {
    let temporary = TempDir::new().expect("temporary release root should exist");
    let root = temporary.path();
    let component = config::AssetExecutable {
        package: "memcordon".to_owned(),
        binary: "memcordon".to_owned(),
        archive_path: "bin/memcordon".to_owned(),
        mode: 0o755,
        role: RuntimeComponentRole::PublicCli,
    };
    let mut target = AssetTarget {
        id: "release-fixture".to_owned(),
        rust_target: "x86_64-unknown-linux-gnu".to_owned(),
        archive: "tar-gz".to_owned(),
        executable: vec![component],
        sealed: SealedAssetPolicy::NotApplicable,
    };
    for relative in NATIVE_ARCHIVE_STATIC_PATHS {
        let source = root.join(Path::new(*relative));
        fs::create_dir_all(source.parent().expect("static member parent should exist"))
            .expect("static member parent should exist");
        fs::write(&source, b"fixture\n").expect("static member fixture should write");
    }
    let identity = ReleaseIdentity {
        tag: "1.2.3".to_owned(),
        version: Version::parse("1.2.3").expect("version should parse"),
        commit: "0123456789abcdef".to_owned(),
        changelog_section: String::new(),
        source_date: "2025-01-01T00:00:00Z".to_owned(),
    };
    for archive_kind in ["tar-gz", "zip"] {
        target.archive = archive_kind.to_owned();
        let executable = built_executable_path(root, &target, &target.executable[0]);
        fs::create_dir_all(executable.parent().expect("executable parent should exist"))
            .expect("executable parent should exist");
        fs::write(&executable, b"cli fixture\n").expect("executable fixture should write");
        let built = build_archive(root, &identity, &target)
            .expect("synthetic release archive fixture should build");
        let inspection = inspect_extract_and_smoke(root, &built.path, &target, &identity, false)
            .unwrap_or_else(|error| {
                panic!("{archive_kind} archive inspection should succeed: {error}")
            });
        assert_eq!(
            inspection.components.len(),
            1,
            "{archive_kind} archive should retain its public CLI component"
        );
        assert!(
            !inspection.archive_member_inventory_sha256.is_empty(),
            "{archive_kind} archive should produce a member inventory digest"
        );
    }
}

#[test]
fn deterministic_conflict_is_not_retried() {
    let wait = config::RegistryWait {
        initial_milliseconds: 1,
        maximum_milliseconds: 1,
        total_seconds: 1,
    };
    let calls = Cell::new(0);
    let result: Result<()> = retry_transient(&wait, || {
        calls.set(calls.get() + 1);
        Err(failure("immutable conflict"))
    });
    assert!(result.is_err());
    assert_eq!(calls.get(), 1);
}

#[test]
fn workflow_provenance_fetches_public_bytes_without_a_token() {
    let (temporary, release, identity) = provenance_fixture();
    let workflow = include_bytes!("../../../../.github/workflows/release.yml");
    let server = MockServer::scripted(vec![MockResponse::Bytes(200, workflow.to_vec())]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let workflow_ref = "Portfoligno/memcordon/.github/workflows/release.yml@refs/tags/1.2.3";
    let (commit, observed_ref, digest, actions) = workflow_provenance_at(
        temporary.path(),
        &identity,
        &release,
        &endpoints,
        &identity.commit,
        workflow_ref,
    )
    .expect("public workflow provenance should not need credentials");
    assert_eq!(commit, identity.commit);
    assert_eq!(observed_ref, workflow_ref);
    assert_eq!(digest, sha256_bytes(workflow));
    assert_eq!(actions.len(), 6);
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with(
        "GET /repos/Portfoligno/memcordon/contents/.github/workflows/release.yml?ref=0123456789abcdef"
    ));
    assert!(
        !requests[0].to_ascii_lowercase().contains("authorization:"),
        "public workflow provenance must not send an authorization credential"
    );
}

fn public_provenance_fixture() -> (
    TempDir,
    config::Release,
    ReleaseIdentity,
    ReleaseManifest,
    Vec<u8>,
) {
    let (temporary, release, identity) = provenance_fixture();
    // Construct canonical LF independently of the test host's checkout settings.
    let workflow = include_str!("../../../../.github/workflows/release.yml")
        .replace("\r\n", "\n")
        .into_bytes();
    let (_, mut manifest, _) = bundle_manifest(temporary.path()).expect("fixture manifest");
    manifest.workflow_sha256 = sha256_bytes(&workflow);
    manifest.action_revisions = config::action_pins(temporary.path())
        .expect("fixture pins")
        .action
        .into_iter()
        .map(|pin| (pin.name, pin.uses))
        .collect();
    (temporary, release, identity, manifest, workflow)
}

#[test]
fn public_workflow_provenance_uses_exact_commit_bytes_despite_crlf_checkout() {
    let (temporary, release, identity, manifest, workflow) = public_provenance_fixture();
    let checkout = String::from_utf8(workflow.clone())
        .expect("UTF-8 workflow")
        .replace('\n', "\r\n");
    let workflow_path = temporary.path().join(".github/workflows/release.yml");
    fs::write(&workflow_path, checkout).expect("CRLF checkout");
    assert_ne!(
        sha256_file(&workflow_path).expect("checkout digest"),
        manifest.workflow_sha256
    );
    let server = MockServer::scripted(vec![MockResponse::Bytes(200, workflow)]);
    verify_public_workflow_provenance(
        temporary.path(),
        &release,
        &manifest,
        &identity,
        &HttpEndpoints::fixed_test_server(&server.root),
    )
    .expect("canonical provenance survives checkout conversion");
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with(
        "GET /repos/Portfoligno/memcordon/contents/.github/workflows/release.yml?ref=0123456789abcdef"
    ));
    assert!(!requests[0].to_ascii_lowercase().contains("authorization:"));
}

#[test]
fn public_workflow_provenance_rejects_changed_authoritative_bytes_and_actions() {
    for mismatch in ["workflow bytes", "digest", "actions", "policy"] {
        let (temporary, release, identity, mut manifest, mut workflow) =
            public_provenance_fixture();
        let expected = match mismatch {
            "workflow bytes" => {
                // Valid YAML with equivalent meaning must still have a different identity.
                workflow.extend_from_slice(b"\n");
                "release workflow digest differs from exact-commit bytes"
            }
            "digest" => {
                manifest.workflow_sha256 = "00".repeat(32);
                "release workflow digest differs from exact-commit bytes"
            }
            "actions" => {
                manifest.action_revisions.clear();
                "release action revisions differ"
            }
            "policy" => {
                workflow = b"name: untrusted\non: push\njobs: {}\n".to_vec();
                // Even matching bytes cannot bypass policy validation.
                manifest.workflow_sha256 = sha256_bytes(&workflow);
                ""
            }
            _ => unreachable!(),
        };
        let server = MockServer::scripted(vec![MockResponse::Bytes(200, workflow)]);
        let error = verify_public_workflow_provenance(
            temporary.path(),
            &release,
            &manifest,
            &identity,
            &HttpEndpoints::fixed_test_server(&server.root),
        )
        .expect_err(mismatch);
        if !expected.is_empty() {
            assert!(error.to_string().contains(expected), "{mismatch}: {error}");
        }
        assert_eq!(server.finish().len(), 1);
    }
}

#[test]
fn public_workflow_provenance_rejects_wrong_commit_or_full_workflow_ref() {
    for mismatch in ["commit", "repository", "workflow", "tag"] {
        let (temporary, release, identity, mut manifest, _) = public_provenance_fixture();
        match mismatch {
            "commit" => manifest.workflow_commit = "different-commit".to_owned(),
            "repository" => {
                manifest.workflow_ref =
                    "other/repository/.github/workflows/release.yml@refs/tags/1.2.3".to_owned()
            }
            "workflow" => {
                manifest.workflow_ref =
                    "Portfoligno/memcordon/.github/workflows/other.yml@refs/tags/1.2.3".to_owned()
            }
            "tag" => {
                manifest.workflow_ref =
                    "Portfoligno/memcordon/.github/workflows/release.yml@refs/tags/1.2.4".to_owned()
            }
            _ => unreachable!(),
        }
        let server = MockServer::scripted(Vec::new());
        let error = verify_public_workflow_provenance(
            temporary.path(),
            &release,
            &manifest,
            &identity,
            &HttpEndpoints::fixed_test_server(&server.root),
        )
        .expect_err(mismatch);
        let expected = if mismatch == "commit" {
            "workflow provenance commit differs from source commit"
        } else {
            "GITHUB_WORKFLOW_REF is not the exact release tag"
        };
        assert!(error.to_string().contains(expected), "{mismatch}: {error}");
        assert!(server.finish().is_empty());
    }
}

#[test]
fn workflow_provenance_rejects_fetched_bytes_that_fail_policy() {
    let (temporary, release, identity) = provenance_fixture();
    let server = MockServer::scripted(vec![MockResponse::Bytes(
        200,
        b"name: untrusted\non: push\njobs: {}\n".to_vec(),
    )]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let result = workflow_provenance_at(
        temporary.path(),
        &identity,
        &release,
        &endpoints,
        &identity.commit,
        "Portfoligno/memcordon/.github/workflows/release.yml@refs/tags/1.2.3",
    );
    assert!(
        result.is_err(),
        "untrusted fetched workflow must fail closed"
    );
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn http_mock_authenticated_github_lookup_finds_draft_in_release_listing() {
    let (temporary, _) = release_fixture();
    let server = MockServer::scripted(vec![MockResponse::Json(
        200,
        serde_json::json!([remote(true)]),
    )]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let found = github_release_at(temporary.path(), Some("token"), &endpoints)
        .expect("authenticated release listing should succeed")
        .expect("authenticated release listing should include the draft");
    assert_eq!(found, remote(true));
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].starts_with("GET /repos/Portfoligno/memcordon/releases?per_page=100&page=1 ")
    );
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer token")
    );
    assert!(!requests[0].contains("/releases/tags/"));
}

#[test]
fn http_mock_authenticated_github_lookup_rejects_duplicate_tag_releases() {
    let (temporary, _) = release_fixture();
    let mut first_page: Vec<serde_json::Value> = (0..GITHUB_RELEASES_PER_PAGE - 1)
        .map(|index| {
            let mut other = remote(false);
            other["id"] = serde_json::json!(index);
            other["tag_name"] = serde_json::json!(format!("other-{index}"));
            other
        })
        .collect();
    first_page.push(remote(true));
    let mut duplicate = remote(false);
    duplicate["id"] = serde_json::json!(42);
    let server = MockServer::scripted(vec![
        MockResponse::Json(200, serde_json::Value::Array(first_page)),
        MockResponse::Json(200, serde_json::json!([duplicate])),
    ]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let result = github_release_at(temporary.path(), Some("token"), &endpoints);
    assert!(result.is_err(), "duplicate tag ownership must fail closed");
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("per_page=100&page=1"));
    assert!(requests[1].contains("per_page=100&page=2"));
}

#[test]
fn http_mock_authenticated_github_lookup_paginates_until_draft() {
    let (temporary, _) = release_fixture();
    let first_page: Vec<serde_json::Value> = (0..GITHUB_RELEASES_PER_PAGE)
        .map(|index| {
            let mut other = remote(false);
            other["id"] = serde_json::json!(index);
            other["tag_name"] = serde_json::json!(format!("other-{index}"));
            other
        })
        .collect();
    let server = MockServer::scripted(vec![
        MockResponse::Json(200, serde_json::Value::Array(first_page)),
        MockResponse::Json(200, serde_json::json!([remote(true)])),
    ]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let found = github_release_at(temporary.path(), Some("token"), &endpoints)
        .expect("paginated release listing should succeed")
        .expect("second page should contain the draft");
    assert_eq!(found, remote(true));
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("per_page=100&page=1"));
    assert!(requests[1].contains("per_page=100&page=2"));
}

#[test]
fn http_mock_authenticated_github_lookup_rejects_malformed_listing() {
    let (temporary, _) = release_fixture();
    let server = MockServer::scripted(vec![MockResponse::Json(
        200,
        serde_json::json!({"unexpected": "object"}),
    )]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let result = github_release_at(temporary.path(), Some("token"), &endpoints);
    assert!(
        result.is_err(),
        "non-array release listing must fail closed"
    );
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn http_mock_public_github_lookup_uses_published_tag_endpoint() {
    let (temporary, _) = release_fixture();
    let server = MockServer::scripted(vec![MockResponse::Json(200, remote(false))]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let found = github_release_at(temporary.path(), None, &endpoints)
        .expect("public release lookup should succeed")
        .expect("published release should exist");
    assert_eq!(found, remote(false));
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /repos/Portfoligno/memcordon/releases/tags/1.2.3 "));
    assert!(!requests[0].to_ascii_lowercase().contains("authorization:"));
}

#[test]
fn http_mock_github_response_loss_is_reconciled_and_rerun_is_idempotent() {
    let (temporary, _) = release_fixture();
    let server = MockServer::scripted(vec![
        MockResponse::Json(200, serde_json::json!([])),
        MockResponse::LoseResponse,
        MockResponse::Json(200, serde_json::json!([])),
        MockResponse::Json(200, serde_json::json!([remote(true)])),
        MockResponse::Json(200, serde_json::json!([remote(true)])),
    ]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let first = create_or_reconcile_github_draft_at(temporary.path(), "token", &endpoints)
        .expect("lost create response should reconcile by GET");
    let second = create_or_reconcile_github_draft_at(temporary.path(), "token", &endpoints)
        .expect("end-to-end rerun should reuse the draft");
    assert_eq!(first, second);
    let requests = server.finish();
    assert_eq!(requests.len(), 5);
    assert!(requests[0].starts_with("GET "));
    assert!(requests[1].starts_with("POST "));
    assert!(requests[2].starts_with("GET "));
    assert!(requests[3].starts_with("GET "));
    assert!(requests[4].starts_with("GET "));
    for request in [&requests[0], &requests[2], &requests[3], &requests[4]] {
        assert!(request.contains("/releases?per_page=100&page=1"));
        assert!(!request.contains("/releases/tags/"));
    }
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.starts_with("POST "))
            .count(),
        1,
        "an ambiguous create must never be blindly retried"
    );
}

#[test]
fn http_mock_upload_conflict_reconciles_canonical_remote_asset_once() {
    let (temporary, release) = release_fixture();
    let path = temporary.path().join("asset.bin");
    fs::write(&path, b"canonical asset\n").expect("asset should write");
    let asset = serde_json::json!({
        "id": 9,
        "name": "asset.bin",
        "size": fs::metadata(&path).expect("asset metadata").len(),
        "digest": format!("sha256:{}", sha256_file(&path).expect("asset digest")),
        "url": "unused",
    });
    let mut release_state = remote(true);
    release_state["assets"] = serde_json::json!([asset.clone()]);
    let server = MockServer::scripted(vec![
        MockResponse::Json(422, serde_json::json!({"message": "already_exists"})),
        MockResponse::Json(200, serde_json::json!([remote(true)])),
        MockResponse::Json(200, serde_json::json!([release_state])),
    ]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let reconciled = upload_or_reconcile_github_asset_at(
        temporary.path(),
        &release,
        &endpoints,
        41,
        "token",
        &path,
    )
    .expect("upload collision should reconcile canonical asset");
    assert_eq!(reconciled, asset);
    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("POST "));
    assert!(
        requests[1].starts_with("GET /repos/Portfoligno/memcordon/releases?per_page=100&page=1 ")
    );
    assert!(
        requests[2].starts_with("GET /repos/Portfoligno/memcordon/releases?per_page=100&page=1 ")
    );
}

#[test]
fn http_mock_stage_uploads_complete_static_inventory_including_certification() {
    let (temporary, release) = release_fixture();
    let output = temporary.path().join(&release.assets.output_directory);
    let certification = [
        (
            "linux-cgroup-v2",
            "certification/backend-linux-cgroup-v2.json",
        ),
        (
            "windows-job-object-v2/x86_64-pc-windows-msvc",
            "certification/windows-sealed-v2/x64-windows-cleanup.json",
        ),
        (
            "windows-job-object-v2/aarch64-pc-windows-msvc",
            "certification/windows-sealed-v2/arm64-windows-cleanup.json",
        ),
        (
            "macos-watchdog",
            "certification/backend-macos-watchdog.json",
        ),
    ];
    fs::create_dir_all(output.join("certification")).expect("certification directory should exist");
    fs::write(output.join(&release.assets.checksums), b"checksums\n")
        .expect("checksums should write");
    let native_path = output.join("memcordon-linux-x64.tar.gz");
    fs::write(&native_path, b"native archive\n").expect("native asset should write");
    let manifest_path = output.join(&release.assets.manifest);
    let mut manifest: ReleaseManifest =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest should read"))
            .expect("manifest should parse");
    manifest.assets.push(AssetRecord {
        name: "memcordon-linux-x64.tar.gz".to_owned(),
        target: "linux-x64".to_owned(),
        size: fs::metadata(&native_path)
            .expect("native asset metadata")
            .len(),
        sha256: sha256_file(&native_path).expect("native asset digest"),
        runtime_manifest_sha256: "runtime-manifest-digest".to_owned(),
        components: Vec::new(),
    });
    for (backend, relative) in certification {
        let evidence_path = output.join(relative);
        fs::create_dir_all(
            evidence_path
                .parent()
                .expect("certification evidence should have a parent"),
        )
        .expect("certification evidence directory should exist");
        fs::write(&evidence_path, format!("{backend} certified\n"))
            .expect("certification evidence should write");
        manifest.certification.insert(
            backend.to_owned(),
            CertificationRecord {
                evidence_path: relative.to_owned(),
                sha256: sha256_file(&evidence_path).expect("evidence digest"),
            },
        );
    }
    write_json(&manifest_path, &manifest).expect("manifest should update");
    let static_paths = static_asset_paths(&release, &manifest, &output)
        .expect("static asset inventory should be valid");
    let assets: Vec<serde_json::Value> = static_paths
        .iter()
        .enumerate()
        .map(|(index, path)| remote_asset(path, 100 + index as u64))
        .collect();
    let mut final_remote = remote(true);
    final_remote["assets"] = serde_json::Value::Array(assets.clone());
    let mut responses = vec![
        MockResponse::Json(200, serde_json::json!([])),
        MockResponse::Json(201, remote(true)),
    ];
    responses.extend(
        assets
            .iter()
            .cloned()
            .map(|asset| MockResponse::Json(201, asset)),
    );
    responses.push(MockResponse::Json(200, serde_json::json!([final_remote])));
    let server = MockServer::scripted(responses);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    stage_github_at(temporary.path(), "token", &endpoints)
        .expect("complete static inventory should stage");
    let requests = server.finish();
    assert_eq!(requests.len(), static_paths.len() + 3);
    let create_body = request_json_body(&requests[1]);
    assert_eq!(create_body["draft"], true);
    assert_eq!(create_body["tag_name"], "1.2.3");
    assert_eq!(create_body["target_commitish"], "0123456789abcdef");
    assert!(
        requests
            .last()
            .expect("stage should perform a final reconciliation read")
            .starts_with("GET /repos/Portfoligno/memcordon/releases?per_page=100&page=1 ",)
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| {
                request.starts_with("POST /repos/Portfoligno/memcordon/releases HTTP/")
            })
            .count(),
        1,
        "stage must create at most one draft"
    );
    for path in &static_paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("asset name should be UTF-8");
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.starts_with("POST /repos/Portfoligno/memcordon/releases/41/assets?")
                        && request.contains(&format!("name={name}"))
                })
                .count(),
            1,
            "each canonical static asset must upload exactly once"
        );
    }
}

#[test]
fn http_mock_stage_rejects_missing_asset_inventory_before_mutation() {
    let (temporary, _) = release_fixture();
    let mut malformed = remote(true);
    malformed
        .as_object_mut()
        .expect("remote release should be an object")
        .remove("assets");
    let server = MockServer::scripted(vec![MockResponse::Json(
        200,
        serde_json::json!([malformed]),
    )]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let result = stage_github_at(temporary.path(), "token", &endpoints);
    assert!(result.is_err(), "missing asset inventory must fail closed");
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET "));
    assert!(requests.iter().all(|request| !request.starts_with("POST ")));
}

#[test]
fn http_mock_idempotent_github_and_registry_reads_retry_transient_statuses() {
    let (temporary, mut release) = release_fixture();
    release.network_retry = config::RegistryWait {
        initial_milliseconds: 1,
        maximum_milliseconds: 1,
        total_seconds: 2,
    };
    let server = MockServer::scripted(vec![
        MockResponse::Json(500, serde_json::json!({"message": "retry"})),
        MockResponse::Json(200, remote(true)),
        MockResponse::Json(503, serde_json::json!({"message": "retry"})),
        MockResponse::Json(200, {
            let mut record = sparse_record("example", "1.2.3", false);
            record["cksum"] = serde_json::json!("registry-digest");
            record
        }),
        MockResponse::Bytes(503, b"retry".to_vec()),
        MockResponse::Truncated(b"partial".to_vec(), 20),
        MockResponse::Bytes(200, b"crate bytes".to_vec()),
    ]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let remote_url = format!(
        "{}/repos/{}/releases/tags/1.2.3",
        endpoints.github_api, release.repository
    );
    let github = github_json_request(&release, &endpoints, "GET", &remote_url, None, None)
        .expect("idempotent GitHub GET should retry");
    assert_eq!(github["id"], 41);
    assert_eq!(
        crate_version_state_at(&release, &endpoints, "example", "1.2.3")
            .expect("registry checksum should retry"),
        CrateVersionLookup::Present(CrateRegistryState {
            checksum: "registry-digest".to_owned(),
            yanked: false,
        })
    );
    let archive = temporary.path().join("download.crate");
    public_crate_archive_at(&release, &endpoints, "example", "1.2.3", &archive)
        .expect("registry download should retry");
    assert_eq!(
        fs::read(archive).expect("download should exist"),
        b"crate bytes"
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 7);
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
    assert!(requests[2].starts_with("GET /ex/am/example "));
    assert!(requests[3].starts_with("GET /ex/am/example "));
    assert!(requests[4].starts_with("GET /crates/example/example-1.2.3.crate "));
    assert!(requests[5].starts_with("GET /crates/example/example-1.2.3.crate "));
    assert!(requests[6].starts_with("GET /crates/example/example-1.2.3.crate "));
}

#[test]
fn sparse_index_paths_follow_cargo_shard_rules() {
    assert_eq!(
        sparse_index_path("a").expect("one-character crate path should shard"),
        "1/a"
    );
    assert_eq!(
        sparse_index_path("ab").expect("two-character crate path should shard"),
        "2/ab"
    );
    assert_eq!(
        sparse_index_path("abc").expect("three-character crate path should shard"),
        "3/a/abc"
    );
    assert_eq!(
        sparse_index_path("abcd").expect("four-character crate path should shard"),
        "ab/cd/abcd"
    );
}

#[test]
fn sparse_index_lookup_selects_the_exact_public_version() {
    let (_, mut release) = release_fixture();
    release.network_retry = config::RegistryWait {
        initial_milliseconds: 1,
        maximum_milliseconds: 1,
        total_seconds: 1,
    };
    let mut target = sparse_record("example", "1.2.3", false);
    target["cksum"] = serde_json::json!("target-digest");
    let server = MockServer::scripted(vec![MockResponse::Ndjson(
        200,
        vec![
            sparse_record("example", "1.2.2", false),
            target,
            sparse_record("example", "1.2.4", true),
        ],
    )]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    assert_eq!(
        crate_version_state_at(&release, &endpoints, "example", "1.2.3")
            .expect("exact sparse-index version should be selected"),
        CrateVersionLookup::Present(CrateRegistryState {
            checksum: "target-digest".to_owned(),
            yanked: false,
        })
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /ex/am/example "));
}

#[test]
fn public_verifier_binds_sparse_checksum_to_manifest_archive_digest() {
    let (_, mut release) = release_fixture();
    release.network_retry = config::RegistryWait {
        initial_milliseconds: 1,
        maximum_milliseconds: 1,
        total_seconds: 1,
    };
    let mut sparse_state = sparse_record("example", "1.2.3", false);
    sparse_state["cksum"] = serde_json::json!("sparse-index-digest");
    let server = MockServer::scripted(vec![MockResponse::Json(200, sparse_state)]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let result = verify_public_crate_at(
        &release,
        &endpoints,
        &verifier_crate_record("manifest-archive-digest"),
    );
    let error = match result {
        Err(error) => error,
        Ok(record) => panic!("checksum conflict must not return {record:?}"),
    };
    let message = error.to_string();
    assert!(
        message.contains("published crate archive checksum conflict for example")
            && message.contains("expected=manifest-archive-digest")
            && message.contains("observed=sparse-index-digest"),
        "checksum diagnostics should bind sparse and manifest digests: {message}"
    );
    let requests = server.finish();
    assert_eq!(
        requests.len(),
        1,
        "the archive must not download on conflict"
    );
    assert!(requests[0].starts_with("GET /ex/am/example "));
}

#[test]
fn public_verifier_rejects_yanked_input_before_archive_download() {
    let (_, mut release) = release_fixture();
    release.network_retry = config::RegistryWait {
        initial_milliseconds: 1,
        maximum_milliseconds: 1,
        total_seconds: 1,
    };
    let server = MockServer::scripted(vec![MockResponse::Json(
        200,
        sparse_record("example", "1.2.3", true),
    )]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let result = verify_public_crate_at(&release, &endpoints, &verifier_crate_record("published"));
    let error = match result {
        Err(error) => error,
        Ok(record) => panic!("yanked input must not return {record:?}"),
    };
    assert_eq!(error.to_string(), "crate version is yanked: example 1.2.3");
    let requests = server.finish();
    assert_eq!(requests.len(), 1, "a yanked archive must not download");
    assert!(requests[0].starts_with("GET /ex/am/example "));
    assert!(
        requests
            .iter()
            .all(|request| !request.starts_with("GET /crates/"))
    );
}

#[test]
fn registry_http_403_is_diagnosed_without_retry() {
    let (temporary, mut release) = release_fixture();
    release.network_retry = config::RegistryWait {
        initial_milliseconds: 1,
        maximum_milliseconds: 1,
        total_seconds: 2,
    };
    let server = MockServer::scripted(vec![
        MockResponse::Json(403, serde_json::json!({"message": "denied"})),
        MockResponse::Bytes(403, b"denied".to_vec()),
    ]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let index_error = crate_version_state_at(&release, &endpoints, "example", "1.2.3")
        .expect_err("sparse-index 403 must fail immediately");
    let archive = temporary.path().join("download.crate");
    let archive_error = public_crate_archive_at(&release, &endpoints, "example", "1.2.3", &archive)
        .expect_err("archive 403 must fail immediately");
    let index_message = index_error.to_string();
    let archive_message = archive_error.to_string();
    assert!(
        index_message.contains("sparse-index version lookup")
            && index_message.contains("/ex/am/example")
            && index_message.contains("not treated as transient"),
        "sparse-index diagnostics should identify the exact endpoint: {index_message}"
    );
    assert!(
        archive_message.contains("public crate archive download")
            && archive_message.contains("/crates/example/example-1.2.3.crate")
            && archive_message.contains("not treated as transient"),
        "archive diagnostics should identify the exact endpoint: {archive_message}"
    );
    assert_eq!(server.finish().len(), 2);
}

#[test]
fn http_mock_partial_registry_publication_selects_only_missing_versions() {
    let (_, mut release) = release_fixture();
    release.network_retry = config::RegistryWait {
        initial_milliseconds: 1,
        maximum_milliseconds: 1,
        total_seconds: 1,
    };
    let server = MockServer::scripted(vec![
        MockResponse::Json(200, sparse_record("memcordon-core", "1.2.3", false)),
        MockResponse::Json(404, serde_json::json!({"message": "missing"})),
    ]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let states = ["memcordon-core", "memcordon-platform"]
        .into_iter()
        .map(|name| {
            crate_version_state_at(&release, &endpoints, name, "1.2.3").map(|state| (name, state))
        })
        .collect::<Result<Vec<_>>>()
        .expect("partial registry state should reconcile");
    assert_eq!(
        states[0].1,
        CrateVersionLookup::Present(CrateRegistryState {
            checksum: "published".to_owned(),
            yanked: false,
        })
    );
    assert_eq!(states[1].1, CrateVersionLookup::Absent);
    assert_eq!(server.finish().len(), 2);
}

#[test]
fn http_mock_scan_selects_the_first_absent_crate_and_rejects_yanks() {
    let (temporary, mut release) = release_fixture();
    release.network_retry = config::RegistryWait {
        initial_milliseconds: 1,
        maximum_milliseconds: 1,
        total_seconds: 1,
    };
    let manifest: ReleaseManifest = serde_json::from_slice(
        &fs::read(
            temporary
                .path()
                .join(&release.assets.output_directory)
                .join(&release.assets.manifest),
        )
        .expect("fixture manifest should read"),
    )
    .expect("fixture manifest should parse");
    let public = |name: &str| MockResponse::Json(200, sparse_record(name, "1.2.3", false));
    let server = MockServer::scripted(vec![
        public("memcordon-core"),
        public("memcordon-platform"),
        MockResponse::Json(404, serde_json::json!({"message": "missing"})),
        MockResponse::Json(404, serde_json::json!({"message": "missing"})),
    ]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let scan =
        scan_registry_publication(&release, &endpoints, &manifest, &release.publish_packages)
            .expect("the first absent exact version should be selected generically");
    assert_eq!(
        scan.first_absent.as_deref(),
        Some("memcordon-windows-launch-core")
    );
    assert_eq!(scan.public_names, ["memcordon-core", "memcordon-platform"]);
    assert_eq!(server.finish().len(), 4);

    let yanked = sparse_record("memcordon-platform", "1.2.3", true);
    let server = MockServer::scripted(vec![
        public("memcordon-core"),
        MockResponse::Json(200, yanked),
    ]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    let error =
        scan_registry_publication(&release, &endpoints, &manifest, &release.publish_packages)
            .expect_err("a yanked target version must not reconcile");
    assert!(error.to_string().contains("yanked"));
    assert_eq!(server.finish().len(), 2);
}

#[test]
fn http_mock_distinguishes_existing_crate_name_from_absent_target_version() {
    let (_, mut release) = release_fixture();
    release.network_retry = config::RegistryWait {
        initial_milliseconds: 1,
        maximum_milliseconds: 1,
        total_seconds: 1,
    };
    let server = MockServer::scripted(vec![
        MockResponse::Json(200, serde_json::json!({"crate": {"id": "memcordon-core"}})),
        MockResponse::Json(404, serde_json::json!({"message": "missing version"})),
    ]);
    let endpoints = HttpEndpoints::fixed_test_server(&server.root);
    assert!(
        crate_name_exists_at(&release, &endpoints, "memcordon-core")
            .expect("existing name should be recognized")
    );
    assert_eq!(
        crate_version_state_at(&release, &endpoints, "memcordon-core", "0.1.0")
            .expect("absent target version should be recognized"),
        CrateVersionLookup::Absent
    );
    assert_eq!(server.finish().len(), 2);
}

#[test]
fn http_mock_crate_name_check_fails_closed_on_malformed_or_wrong_identity() {
    let (_, release) = release_fixture();
    for response in [
        serde_json::json!({"crate": {}}),
        serde_json::json!({"crate": {"id": "different-name"}}),
    ] {
        let server = MockServer::scripted(vec![MockResponse::Json(200, response)]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        assert!(crate_name_exists_at(&release, &endpoints, "memcordon-core").is_err());
        assert_eq!(server.finish().len(), 1);
    }
}

#[test]
fn http_mock_version_state_fails_closed_on_malformed_or_wrong_identity() {
    let (_, release) = release_fixture();
    for response in [
        serde_json::json!({"name": "memcordon-core", "vers": "1.2.3", "cksum": "published"}),
        sparse_record("different-name", "1.2.3", false),
    ] {
        let server = MockServer::scripted(vec![MockResponse::Json(200, response)]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        assert!(
            crate_version_state_at(&release, &endpoints, "memcordon-core", "1.2.3").is_err(),
            "malformed or mismatched version state must fail closed"
        );
        assert_eq!(server.finish().len(), 1);
    }
}
