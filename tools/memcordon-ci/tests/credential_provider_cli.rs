use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use memcordon_ci::command::CommandSpec;
use memcordon_ci::config;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[path = "support/standard.rs"]
mod standard_fixture;

const PROVIDER_DEADLINE: Duration = Duration::from_secs(30);
const FIXTURE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

fn provider_fixture() -> (TempDir, config::Release, Value) {
    let temporary = TempDir::new().expect("provider fixture directory should exist");
    let root = temporary.path();
    write_canonical_publication_fixture(root);
    fs::create_dir_all(root.join("ci")).expect("fixture CI directory should exist");
    fs::write(
        root.join("ci/release.toml"),
        include_str!("../../../ci/release.toml"),
    )
    .expect("release configuration should write");
    let release = config::release(root).expect("fixture release should parse");
    let output = root.join(&release.assets.output_directory);
    fs::create_dir_all(&output).expect("release output should exist");

    let checksum = "ab".repeat(32);
    let crates: Vec<Value> = release
        .publish_packages
        .iter()
        .map(|name| {
            json!({
                "name": name,
                "version": "0.5.2",
                "archive_sha256": checksum,
                "canonical_tree_sha256": "cd".repeat(32),
                "canonical_identity_sha256": "ef".repeat(32),
                "vcs_commit": FIXTURE_COMMIT,
            })
        })
        .collect();
    let mut manifest = json!({
        "schema_version": config::RELEASE_SCHEMA_VERSION,
        "certification_contract": "standard-and-sealed-v1",
        "certification_origin": {
            "source_commit": FIXTURE_COMMIT,
            "repository": "Portfoligno/memcordon",
            "run_id": 123,
            "workflow_commit": FIXTURE_COMMIT,
            "workflow_ref": "Portfoligno/memcordon/.github/workflows/release.yml@refs/tags/0.5.2"
        },
        "project": "memcordon",
        "tag": "0.5.2",
        "version": "0.5.2",
        "source_commit": FIXTURE_COMMIT,
        "workflow_commit": FIXTURE_COMMIT,
        "workflow_ref": "Portfoligno/memcordon/.github/workflows/release.yml@refs/tags/0.5.2",
        "workflow_sha256": "00".repeat(32),
        "action_revisions": {},
        "prerelease": false,
        "rust_toolchain": "stable",
        "assets": [],
        "crates": crates,
        "certification": {},
        "source_date": "2026-01-01T00:00:00Z",
    });
    write_certification_fixture(&output, &mut manifest);
    fs::write(
        output.join(&release.assets.manifest),
        serde_json::to_vec(&manifest).expect("manifest should encode"),
    )
    .expect("release manifest should write");
    (temporary, release, manifest)
}

// Synthetic transport evidence reaches the credential boundary without claiming
// that this portable test executed native certification.
fn write_certification_fixture(output: &Path, manifest: &mut Value) {
    let origin = serde_json::from_value(manifest["certification_origin"].clone()).unwrap();
    let mut records = serde_json::Map::new();
    let mut write = |key: &str, path: &str, value: Value| {
        let destination = output.join(path);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        let sha256: String = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        fs::write(destination, bytes).unwrap();
        records.insert(
            key.into(),
            json!({ "evidence_path": path, "sha256": sha256 }),
        );
    };
    for (key, path) in [
        (
            "linux-pid-namespace-cgroup-v2",
            "certification/cleanup-leak-check.json",
        ),
        (
            "windows-job-object-v2/x86_64-pc-windows-msvc",
            "certification/windows-sealed-v2/x64-windows-release-certification.json",
        ),
        (
            "windows-job-object-v2/aarch64-pc-windows-msvc",
            "certification/windows-sealed-v2/arm64-windows-release-certification.json",
        ),
        (
            "macos-watchdog",
            "certification/backend-macos-watchdog.json",
        ),
    ] {
        write(key, path, json!({}));
    }
    for name in [
        "provider-package-verification.json",
        "provider-qualification-v2.json",
        "setid-transition.json",
        "sudo-transition.json",
        "file-capability-transition.json",
        "caller-envelope.json",
        "mount-context.json",
        "fault-injection.json",
    ] {
        write(
            &format!("linux-pid-namespace-cgroup-v2/{name}"),
            &format!("certification/linux-sealed-v2/{name}"),
            json!({}),
        );
    }
    for contract in [
        memcordon_ci::standard_contract::LINUX,
        memcordon_ci::standard_contract::WINDOWS,
    ] {
        write(
            contract.manifest_key,
            contract.bundle_path,
            serde_json::to_value(standard_fixture::report(contract, &origin)).unwrap(),
        );
    }
    use memcordon_ci::workload_qualification::{QualificationArtifactV1, QualificationKind};
    for (name, target, kind) in [
        (
            "linux-profile-qualification.json",
            "x86_64-unknown-linux-gnu",
            QualificationKind::Profile,
        ),
        (
            "windows-x64-profile-qualification.json",
            "x86_64-pc-windows-msvc",
            QualificationKind::Profile,
        ),
        (
            "windows-x64-causal-diagnostics.json",
            "x86_64-pc-windows-msvc",
            QualificationKind::CausalDiagnostics,
        ),
        (
            "windows-arm64-profile-qualification.json",
            "aarch64-pc-windows-msvc",
            QualificationKind::Profile,
        ),
        (
            "windows-arm64-causal-diagnostics.json",
            "aarch64-pc-windows-msvc",
            QualificationKind::CausalDiagnostics,
        ),
    ] {
        write(
            &format!("workload/{name}"),
            &format!("certification/workload/{name}"),
            serde_json::to_value(QualificationArtifactV1::after_observed_tests(
                kind,
                target,
                &origin.source_commit,
            ))
            .unwrap(),
        );
    }
    assert_eq!(records.len(), 19);
    manifest["certification"] = Value::Object(records);
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

fn provider_exchange(root: &Path, request: &[u8]) -> (Value, Value, Output) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"));
    command
        .arg("--cargo-plugin")
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    CommandSpec::new(env!("CARGO_BIN_EXE_memcordon-ci"), root, PROVIDER_DEADLINE)
        .apply_environment(&mut command);
    let mut child = command
        .spawn()
        .expect("Cargo credential provider should spawn");
    let mut stdin = child.stdin.take().expect("provider stdin should be piped");
    stdin
        .write_all(request)
        .expect("provider request should write");
    drop(stdin);

    let stdout = child
        .stdout
        .take()
        .expect("provider stdout should be piped");
    let mut lines = BufReader::new(stdout).lines();
    let hello = lines
        .next()
        .expect("provider hello should arrive")
        .expect("provider hello should read");
    let response = lines
        .next()
        .expect("provider response should arrive")
        .expect("provider response should read");
    drop(lines);
    let output = child
        .wait_with_output()
        .expect("provider process should finish");
    assert!(
        output.status.success(),
        "provider should exit after response"
    );
    let hello: Value = serde_json::from_str(&hello).expect("hello should be JSON");
    let response: Value = serde_json::from_str(&response).expect("response should be JSON");
    (hello, response, output)
}

fn exchange_json(root: &Path, request: Value) -> (Value, Value, Output) {
    let mut wire = serde_json::to_vec(&request).expect("request should encode");
    wire.push(b'\n');
    provider_exchange(root, &wire)
}

fn crate_record(manifest: &Value) -> Value {
    manifest["crates"][0].clone()
}

fn provider_arguments(record: &Value, origin: &str) -> Value {
    json!([
        origin,
        "1",
        record["name"],
        record["version"],
        record["archive_sha256"],
    ])
}

fn publish_request(record: &Value) -> Value {
    json!({
        "v": 1,
        "registry": {
            "index-url": "sparse+https://index.crates.io/",
            "name": "crates-io",
        },
        "kind": "get",
        "operation": "publish",
        "name": record["name"],
        "vers": record["version"],
        "cksum": record["archive_sha256"],
        "args": provider_arguments(record, "oidc"),
    })
}

#[test]
fn cargo_plugin_marker_reaches_protocol_without_identity_arguments() {
    let (temporary, _, _) = provider_fixture();
    let (hello, response, output) = provider_exchange(temporary.path(), b"not JSON\n");
    assert_eq!(hello, json!({ "v": [1] }));
    assert_eq!(response["Err"]["kind"], "other");
    assert_eq!(
        response["Err"]["message"],
        "Cargo credential request is malformed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Usage:"),
        "marker must not fail in Clap: {stderr}"
    );
}

#[test]
fn cargo_plugin_marker_rejects_appended_identity_arguments() {
    let (temporary, _, manifest) = provider_fixture();
    let record = crate_record(&manifest);
    let mut child = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"))
        .arg("--cargo-plugin")
        .arg("oidc")
        .arg("1")
        .arg(record["name"].as_str().expect("crate name should be text"))
        .arg(record["version"].as_str().expect("version should be text"))
        .arg(
            record["archive_sha256"]
                .as_str()
                .expect("checksum should be text"),
        )
        .current_dir(temporary.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("provider CLI should spawn");
    drop(child.stdin.take().expect("provider stdin should be piped"));
    let output = child
        .wait_with_output()
        .expect("provider CLI should finish");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Usage:"),
        "identity values are not CLI values: {stderr}"
    );
}

#[test]
fn cargo_provider_binds_cargo_request_to_release_manifest() {
    let (temporary, _, manifest) = provider_fixture();
    let record = crate_record(&manifest);
    let request = publish_request(&record);
    let (hello, response, _) = exchange_json(temporary.path(), request.clone());
    assert_eq!(hello, json!({ "v": [1] }));
    assert_eq!(response["Err"]["kind"], "other");
    assert_eq!(
        response["Err"]["message"], "registry capability is absent",
        "an exact request should reach capability acquisition"
    );

    for (field, replacement) in [
        ("name", json!("not-the-selected-crate")),
        ("vers", json!("9.9.9")),
        ("cksum", json!("00".repeat(32))),
    ] {
        let mut mismatch = request.clone();
        mismatch
            .as_object_mut()
            .expect("publish request should be an object")
            .insert(field.to_owned(), replacement);
        let (_, response, output) = exchange_json(temporary.path(), mismatch);
        assert_eq!(response["Err"]["kind"], "other", "field: {field}");
        assert_eq!(
            response["Err"]["message"],
            "Cargo credential request differs from the selected release artifact",
            "field: {field}"
        );
        assert!(
            output.stderr.is_empty(),
            "mismatch rejection should remain in protocol: field: {field}"
        );
    }

    let configured_identity_mismatches = [
        (
            0,
            json!("token-first"),
            "unknown credential-provider origin in Cargo request args: token-first",
        ),
        (
            1,
            json!("2"),
            "Cargo credential request differs from the selected publication slot",
        ),
        (
            2,
            json!("not-the-selected-crate"),
            "Cargo credential request differs from the selected publication slot",
        ),
        (
            3,
            json!("9.9.9"),
            "Cargo credential request is absent from the release manifest",
        ),
        (
            4,
            json!("00".repeat(32)),
            "Cargo credential request differs from the selected release artifact",
        ),
    ];
    for (index, replacement, expected_error) in configured_identity_mismatches {
        let mut mismatch = publish_request(&record);
        mismatch["args"][index] = replacement;
        let (_, response, output) = exchange_json(temporary.path(), mismatch);
        assert_eq!(response["Err"]["kind"], "other", "index: {index}");
        assert_eq!(response["Err"]["message"], expected_error, "index: {index}");
        assert!(output.stderr.is_empty(), "index: {index}");
    }
}

#[test]
fn cargo_provider_rejects_wrong_and_malformed_actions() {
    let (temporary, _, manifest) = provider_fixture();
    let record = crate_record(&manifest);
    let arguments = provider_arguments(&record, "oidc");
    let login = json!({
        "v": 1,
        "registry": {
            "index-url": "sparse+https://index.crates.io/",
            "name": "crates-io",
        },
        "kind": "login",
        "args": arguments,
    });
    let (_, response, _) = exchange_json(temporary.path(), login);
    assert_eq!(response["Err"]["kind"], "operation-not-supported");

    let malformed_action = json!({
        "v": 1,
        "registry": {
            "index-url": "sparse+https://index.crates.io/",
            "name": "crates-io",
        },
        "kind": "destroy-registry",
        "args": provider_arguments(&record, "oidc"),
    });
    let (_, response, _) = exchange_json(temporary.path(), malformed_action);
    assert_eq!(response["Err"]["kind"], "other");
    assert_eq!(
        response["Err"]["message"],
        "Cargo credential request is malformed"
    );
}

#[test]
fn new_crate_fallback_cli_read_requires_a_publication_run() {
    let (temporary, _, manifest) = provider_fixture();
    let record = crate_record(&manifest);
    let request = json!({
        "v": 1,
        "registry": {
            "index-url": "sparse+https://index.crates.io/",
            "name": "crates-io",
        },
        "kind": "get",
        "operation": "read",
        "args": provider_arguments(&record, "new-crate-token"),
    });
    let (_, response, output) = exchange_json(temporary.path(), request);
    assert_eq!(response["Err"]["kind"], "other");
    assert!(response.get("Ok").is_none());
    assert!(output.stderr.is_empty());
}
