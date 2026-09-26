use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use memcordon_ci::build_context::ValidatedBuildContext;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn encoded(path: &Path) -> String {
    hex::encode(path.as_os_str().as_encoded_bytes())
}

// Synchronous reference for the unchanged source/native record contract.
fn serial(
    path: &Path,
    source: Option<&Path>,
    visited: &mut BTreeSet<PathBuf>,
    inputs: &mut Vec<Value>,
) {
    if let Some(root) = source {
        let relative = path.strip_prefix(root).unwrap();
        if ["fuzz/target", "fuzz/corpus", "fuzz/artifacts"]
            .iter()
            .any(|p| relative.starts_with(p))
            || relative.components().next().is_some_and(|p| {
                matches!(
                    p.as_os_str().to_str(),
                    Some(
                        "target"
                            | ".git"
                            | "ci-native-fingerprint"
                            | "ci-native-fingerprint.exe"
                            | "ci-native-fingerprint.pdb"
                    )
                )
            })
        {
            return;
        }
    }
    let metadata = fs::symlink_metadata(path).unwrap();
    let identity = if metadata.file_type().is_symlink() {
        path.to_path_buf()
    } else {
        path.canonicalize().unwrap()
    };
    if !visited.insert(identity.clone()) {
        return;
    }
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    };
    #[cfg(not(unix))]
    let mode = u32::from(metadata.permissions().readonly());
    let (kind, digest) = if metadata.file_type().is_symlink() {
        let target = fs::read_link(path).unwrap();
        let resolved = path.canonicalize().unwrap();
        if source.is_none() {
            serial(&resolved, source, visited, inputs);
        }
        (
            "symlink",
            serde_json::to_string(&[encoded(&target), encoded(&resolved)]).unwrap(),
        )
    } else if metadata.is_dir() {
        let mut children = fs::read_dir(&identity)
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            serial(&child.path(), source, visited, inputs);
        }
        ("directory", String::new())
    } else {
        (
            "file",
            hex::encode(Sha256::digest(fs::read(&identity).unwrap())),
        )
    };
    inputs.push(json!({"path":encoded(&identity), "mode":mode, "kind":kind, "digest":digest}));
}

fn context(
    root: &Path,
    required: &[PathBuf],
    discovered: &[PathBuf],
    inputs: Vec<Value>,
) -> ValidatedBuildContext {
    let temporary = tempfile::tempdir().unwrap();
    let cargo_home = temporary.path().join("cargo-home");
    fs::create_dir(&cargo_home).unwrap();
    let value = json!({"schema_version":4, "profile":"stable", "root":root,
        "environment":[[encoded(Path::new("CARGO_HOME")), encoded(&cargo_home)]],
        "toolchains":{"stable":root}, "input_roots":required, "discovery_roots":discovered,
        "inputs":inputs, "worker":{}});
    let path = temporary.path().join("context.json");
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    // Audit needs no toolchain execution and the empty source home may disappear.
    ValidatedBuildContext::read(&path).unwrap()
}

fn reconfigure(
    context: &ValidatedBuildContext,
    update: impl FnOnce(&mut Value),
) -> Result<ValidatedBuildContext, memcordon_ci::CiError> {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("context.json");
    let mut value = serde_json::to_value(context).unwrap();
    update(&mut value);
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    ValidatedBuildContext::read(&path)
}

fn configured_root() -> tempfile::TempDir {
    let temporary = tempfile::tempdir().unwrap();
    fs::create_dir(temporary.path().join("ci")).unwrap();
    fs::write(
        temporary.path().join("ci/toolchains.toml"),
        "stable = \"stable-test\"\nmsrv = \"msrv-test\"\nmiri = \"nightly-test\"\n",
    )
    .unwrap();
    fs::write(
        temporary.path().join("ci/tools.toml"),
        "cargo_audit = \"0.22.2\"\ncargo_deny = \"0.20.2\"\ncargo_fuzz = \"0.13.2\"\n",
    )
    .unwrap();
    temporary
}

#[test]
fn prepared_profile_labels_require_measured_tools_and_configured_toolchains() {
    use memcordon_ci::bootstrap_profile::BootstrapProfile;
    let temporary = configured_root();
    let root = temporary.path().canonicalize().unwrap();
    let mut records = Vec::new();
    serial(&root, Some(&root), &mut BTreeSet::new(), &mut records);
    records.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    let original = context(&root, &[], &[], records);
    let prepared = reconfigure(&original, |value| {
        value["profile"] = json!("supply-chain");
        value["toolchains"] = json!({"stable-test":root});
    })
    .unwrap();
    assert!(
        prepared
            .require_profile(BootstrapProfile::SupplyChain)
            .unwrap_err()
            .to_string()
            .contains("required prepared executable missing: cargo-audit")
    );
    let missing_stable = reconfigure(&prepared, |value| {
        value["toolchains"] = json!({"msrv-test":root})
    })
    .unwrap();
    assert!(
        missing_stable
            .require_profile(BootstrapProfile::Stable)
            .unwrap_err()
            .to_string()
            .contains("required prepared toolchain missing: stable-test")
    );
    let fuzz_without_nightly =
        reconfigure(&prepared, |value| value["profile"] = json!("fuzz")).unwrap();
    assert!(
        fuzz_without_nightly
            .require_profile(BootstrapProfile::Fuzz)
            .unwrap_err()
            .to_string()
            .contains("required prepared toolchain missing: nightly-test")
    );
    assert!(
        prepared
            .require_profile(BootstrapProfile::Fuzz)
            .unwrap_err()
            .to_string()
            .contains("does not satisfy")
    );
    for version in [0, 1, 2, 3, 5] {
        assert!(reconfigure(&prepared, |value| value["schema_version"] = json!(version)).is_err());
    }
}

#[test]
fn restored_tool_bytes_must_match_the_prepared_supply_chain_context() {
    use memcordon_ci::bootstrap_profile::BootstrapProfile;
    let temporary = configured_root();
    let root = temporary.path().canonicalize().unwrap();
    let tools = root.join("target/ci-tools/bin");
    fs::create_dir_all(&tools).unwrap();
    let paths: Vec<_> = ["cargo-audit", "cargo-deny"]
        .iter()
        .map(|name| tools.join(format!("{name}{}", std::env::consts::EXE_SUFFIX)))
        .collect();
    let fixture = root.join("target/tool.rs");
    fs::write(
        &fixture,
        r#"fn main() {
        let path = std::env::current_exe().unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();
        let version = if name.starts_with("cargo-audit") { "0.22.2" } else { "0.20.2" };
        println!("{name} {version}");
    }
    "#,
    )
    .unwrap();
    let mut command = std::process::Command::new("rustup");
    command
        .args(["run", "1.97.1", "rustc", "--edition=2021"])
        .arg(&fixture)
        .arg("-o")
        .arg(&paths[0]);
    let output =
        memcordon_testkit::run_with_deadline(&mut command, std::time::Duration::from_secs(30))
            .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::copy(&paths[0], &paths[1]).unwrap();
    let original_bytes = fs::read(&paths[0]).unwrap();
    let mut records = Vec::new();
    serial(&root, Some(&root), &mut BTreeSet::new(), &mut records);
    serial(&tools, None, &mut BTreeSet::new(), &mut records);
    records.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    let original = context(&root, &[tools], &[], records);
    let prepared = reconfigure(&original, |value| {
        value["profile"] = json!("supply-chain");
        value["toolchains"] = json!({"stable-test":root});
    })
    .unwrap();
    prepared
        .verify_prepared_suite_inputs(BootstrapProfile::SupplyChain)
        .unwrap();
    for path in &paths {
        fs::write(path, b"restored executable bytes\n").unwrap();
        assert!(
            prepared
                .verify_prepared_suite_inputs(BootstrapProfile::SupplyChain)
                .unwrap_err()
                .to_string()
                .contains("managed build inputs changed")
        );
        fs::write(path, &original_bytes).unwrap();
        prepared
            .verify_prepared_suite_inputs(BootstrapProfile::SupplyChain)
            .unwrap();
    }
}

#[test]
fn parallel_domains_match_serial_records_and_retain_equal_paths() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    for path in [
        "src",
        "target",
        ".git",
        "fuzz/target",
        "fuzz/corpus",
        "fuzz/artifacts",
    ] {
        fs::create_dir_all(root.join(path)).unwrap();
        fs::write(root.join(path).join("bytes"), path).unwrap();
    }
    fs::write(root.join("src/file"), b"source bytes\n").unwrap();
    fs::write(root.join("ci-native-fingerprint"), b"excluded\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink("file", root.join("src/alias")).unwrap();
        // Exclusion precedes filesystem admission, so excluded dangling links
        // and source links to directories never create extra recursive records.
        symlink("missing", root.join("ci-native-fingerprint.exe")).unwrap();
        symlink("src", root.join("source-alias")).unwrap();
        symlink(".", root.join("source-cycle")).unwrap();
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStringExt;
            fs::write(
                root.join(std::ffi::OsString::from_vec(vec![b'n', 0xff])),
                [],
            )
            .unwrap();
        }
    }
    let required = vec![root.join("src"), root.join("target")];
    let discovered = vec![root.join("src")];
    let mut inputs = Vec::new();
    serial(&root, Some(&root), &mut BTreeSet::new(), &mut inputs);
    let mut visited = BTreeSet::new();
    for native in required.iter().chain(&discovered) {
        serial(native, None, &mut visited, &mut inputs);
    }
    inputs.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    assert_eq!(
        inputs
            .iter()
            .filter(|input| input["path"] == encoded(&root.join("src/file")))
            .count(),
        2
    );
    let context = context(&root, &required, &discovered, inputs);
    for _ in 0..4 {
        context.audit().unwrap();
    }
    fs::write(root.join("target/bytes"), b"native change\n").unwrap();
    assert!(
        context
            .audit()
            .unwrap_err()
            .to_string()
            .contains("managed build inputs changed")
    );
}

#[cfg(unix)]
#[test]
fn source_failure_wins_and_native_domain_is_still_settled() {
    use std::os::unix::fs::symlink;
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("outside"), b"bytes\n").unwrap();
    symlink(outside.path().join("outside"), root.join("escape")).unwrap();
    let context = context(
        &root,
        &[root.join("missing-native")],
        &[],
        vec![json!({
        "path":encoded(&root),"kind":"directory","mode":0,"digest":""})],
    );
    for _ in 0..4 {
        let error = context.audit().unwrap_err().to_string();
        assert!(
            error.contains("source symlink escapes declared root"),
            "{error}"
        );
        assert!(!error.contains("missing-native"), "{error}");
    }
}

#[cfg(unix)]
#[test]
fn explicit_discovery_root_is_validated_even_after_an_inaccessible_alias_was_visited() {
    use std::os::unix::fs::PermissionsExt;
    let source = tempfile::tempdir().unwrap();
    let root = source.path().canonicalize().unwrap();
    let native = tempfile::tempdir().unwrap();
    let native_root = native.path().canonicalize().unwrap();
    let denied = native_root.join("denied");
    fs::create_dir(&denied).unwrap();
    fs::write(denied.join("header"), b"bytes\n").unwrap();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0)).unwrap();
    if fs::read_dir(&denied).is_ok() {
        // An elevated test principal cannot produce the search-denial fixture.
        fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    let prepared = context(
        &root,
        &[],
        &[native_root, denied.clone()],
        vec![json!({
        "path":encoded(&root),"kind":"directory","mode":0,"digest":""})],
    );
    let result = prepared.audit();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
    let error = result.unwrap_err().to_string();
    assert!(error.contains("reading required native root"), "{error}");
}
