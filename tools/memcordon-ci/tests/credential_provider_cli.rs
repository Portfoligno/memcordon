use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use memcordon_ci::config;
use serde_json::{Value, json};
use tempfile::TempDir;

fn provider_fixture() -> (TempDir, config::Release, Value) {
    let temporary = TempDir::new().expect("provider fixture directory should exist");
    let root = temporary.path();
    fs::create_dir_all(root.join("ci")).expect("fixture CI directory should exist");
    fs::write(root.join("Cargo.toml"), "[workspace]\n").expect("workspace marker should write");
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
                "vcs_commit": "0123456789abcdef",
            })
        })
        .collect();
    let manifest = json!({
        "schema_version": config::RELEASE_SCHEMA_VERSION,
        "project": "memcordon",
        "tag": "0.5.2",
        "version": "0.5.2",
        "source_commit": "0123456789abcdef",
        "workflow_commit": "0123456789abcdef",
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
    fs::write(
        output.join(&release.assets.manifest),
        serde_json::to_vec(&manifest).expect("manifest should encode"),
    )
    .expect("release manifest should write");
    (temporary, release, manifest)
}

fn provider_exchange(root: &Path, request: &[u8]) -> (Value, Value, Output) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"))
        .arg("--cargo-plugin")
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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
fn new_crate_fallback_provider_forbids_registry_reads() {
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
    assert_eq!(
        response["Err"]["message"],
        "the new-crate fallback credential does not support registry reads"
    );
    assert!(output.stderr.is_empty());
}
