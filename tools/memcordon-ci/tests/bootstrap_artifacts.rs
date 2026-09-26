use std::fs;
use std::path::Path;
use std::process::Command;

fn status(root: &Path) -> Vec<u8> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
        .output()
        .expect("inspect bootstrap fixture checkout");
    assert!(output.status.success(), "{output:?}");
    output.stdout
}

#[test]
fn bootstrap_artifacts_do_not_hide_unrelated_checkout_changes() {
    let fixture = tempfile::tempdir().expect("bootstrap fixture");
    let root = fixture.path();
    let output = Command::new("git")
        .current_dir(root)
        .args(["init", "--quiet"])
        .output()
        .expect("initialize bootstrap fixture");
    assert!(output.status.success(), "{output:?}");
    fs::write(
        root.join(".gitignore"),
        include_bytes!("../../../.gitignore"),
    )
    .expect("install repository artifact rules");
    let baseline = status(root);
    assert_eq!(baseline, b"?? .gitignore\0");

    for artifact in [
        "ci-native-fingerprint",
        "ci-native-fingerprint.exe",
        "ci-native-fingerprint.pdb",
    ] {
        fs::write(root.join(artifact), b"compiled bootstrap").expect("bootstrap artifact");
    }
    assert_eq!(status(root), baseline);

    fs::create_dir(root.join("nested")).expect("nested source directory");
    for unrelated in [
        "unrelated.exe",
        "unrelated.pdb",
        "nested/ci-native-fingerprint.exe",
        "nested/ci-native-fingerprint.pdb",
    ] {
        fs::write(root.join(unrelated), b"unrelated content").expect("unrelated file");
    }
    assert_eq!(
        status(root),
        b"?? .gitignore\0?? nested/ci-native-fingerprint.exe\0?? nested/ci-native-fingerprint.pdb\0?? unrelated.exe\0?? unrelated.pdb\0"
    );
}

#[test]
fn bootstrap_pdb_is_an_output_only_at_the_source_root() {
    use memcordon_ci::build_context::{BuildInputSnapshot, ValidatedBuildContext};
    use sha2::{Digest, Sha256};
    use std::ffi::OsStr;

    let fixture = tempfile::tempdir().unwrap();
    let base = fixture.path().canonicalize().unwrap();
    let root = base.join("source");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("nested")).unwrap();
    let cargo = base.join("cargo-fixture");
    fs::write(&cargo, b"fixture tool").unwrap();
    let encode = |value: &OsStr| hex::encode(value.as_encoded_bytes());
    let input = |path: &Path, kind: &str, digest: String| {
        let metadata = path.metadata().unwrap();
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode()
        };
        #[cfg(windows)]
        let mode = u32::from(metadata.permissions().readonly());
        serde_json::json!({"path": encode(path.as_os_str()), "kind": kind, "mode": mode, "digest": digest})
    };
    // Explicit expected source entries exercise the full profile's Source scope.
    // BuildInputSnapshot::capture intentionally has no output exclusions.
    let mut inputs = vec![
        input(&root, "directory", String::new()),
        input(&root.join("nested"), "directory", String::new()),
        input(&cargo, "file", hex::encode(Sha256::digest(b"fixture tool"))),
    ];
    inputs.sort_by_key(|input| input["path"].as_str().unwrap().to_owned());
    let manifest = base.join("context.json");
    fs::write(&manifest, serde_json::to_vec(&serde_json::json!({
        "schema_version": 4, "profile": "stable", "root": root,
        "environment": [[encode(OsStr::new("CARGO_HOME")), encode(base.join("cargo-home").as_os_str())]],
        "toolchains": {"1.97.1": cargo},
        "input_roots": [cargo], "discovery_roots": [],
        "inputs": inputs, "worker": {}
    })).unwrap()).unwrap();
    let source = ValidatedBuildContext::read(&manifest).unwrap();
    source.audit().unwrap();
    let pdb = root.join("ci-native-fingerprint.pdb");
    fs::write(&pdb, b"bootstrap symbols").unwrap();
    source.audit().unwrap();

    // The same name is still fully measured in a declared native input tree.
    let native = BuildInputSnapshot::capture_native_tree(&root).unwrap();
    fs::write(&pdb, b"changed bootstrap symbols").unwrap();
    assert!(native.audit().is_err());
    source.audit().unwrap();

    let nested = root.join("nested/ci-native-fingerprint.pdb");
    fs::write(&nested, b"nested symbols").unwrap();
    assert!(source.audit().is_err());
}
