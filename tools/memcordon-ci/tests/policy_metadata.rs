use memcordon_ci::{
    build_context::{BuildInputSnapshot, ValidatedBuildContext, environment},
    policy::workspace_metadata_command,
};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

fn recipe(root: &Path) {
    fs::create_dir(root.join("ci")).unwrap();
    fs::write(
        root.join("ci/toolchains.toml"),
        "stable = \"1.97.1\"\nmsrv = \"1.85.0\"\nmiri = \"nightly-2026-07-31\"\n",
    )
    .unwrap();
}

fn expected_arguments() -> [&'static str; 6] {
    [
        "metadata",
        "--format-version",
        "1",
        "--no-deps",
        "--locked",
        "--offline",
    ]
}

#[test]
fn metadata_materializes_as_measured_cargo_with_closed_environment() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    recipe(&root);
    let bin = root.join("measured sysroot/bin");
    fs::create_dir_all(&bin).unwrap();
    let cargo = bin.join(if cfg!(windows) { "cargo.exe" } else { "cargo" });
    fs::write(&cargo, b"fixture tool\n").unwrap();
    let command_root = environment::command_path(&root).unwrap();
    let command_bin = environment::command_path(&bin).unwrap();
    let encode = |value: &OsStr| hex::encode(value.as_encoded_bytes());
    let manifest = root.join("context.json");
    fs::write(&manifest, serde_json::to_vec(&serde_json::json!({
        "schema_version": 4,
        "profile": "stable",
        "root": root,
        "environment": [[encode(OsStr::new("PATH")), encode(command_root.as_os_str())]],
        "toolchains": {"1.97.1": cargo},
        "input_roots": [bin], "discovery_roots": [],
        "inputs": [{"path": encode(cargo.as_os_str()), "kind": "file", "mode": 0, "digest": "fixture"}],
        "worker": {}
    })).unwrap()).unwrap();
    let context = ValidatedBuildContext::read(&manifest).unwrap();
    let spec = workspace_metadata_command(&root).unwrap();
    let command = spec.materialize(Some(&context)).unwrap();
    assert_eq!(
        command.get_program(),
        environment::paths::command_program(&cargo).unwrap()
    );
    assert_eq!(command.get_args().collect::<Vec<_>>(), expected_arguments());
    let env: std::collections::BTreeMap<_, _> = command.get_envs().collect();
    assert_eq!(
        env.get(OsStr::new("RUSTUP_TOOLCHAIN")),
        Some(&Some(OsStr::new("1.97.1")))
    );
    assert_eq!(
        env.get(OsStr::new("CARGO_NET_OFFLINE")),
        Some(&Some(OsStr::new("true")))
    );
    assert_eq!(
        env.get(OsStr::new("RUSTC")).unwrap().unwrap(),
        command_bin.join(if cfg!(windows) { "rustc.exe" } else { "rustc" })
    );
    assert_eq!(
        env.get(OsStr::new("RUSTDOC")).unwrap().unwrap(),
        command_bin.join(if cfg!(windows) {
            "rustdoc.exe"
        } else {
            "rustdoc"
        })
    );
    let paths: Vec<_> =
        std::env::split_paths(env.get(OsStr::new("PATH")).unwrap().unwrap()).collect();
    assert_eq!(paths, [command_bin, command_root.clone()]);
    assert_eq!(command.get_current_dir(), Some(command_root.as_path()));
    assert_eq!(
        env.values().filter(|value| value.is_some()).count(),
        5,
        "ambient variables must not enter managed metadata"
    );
}

#[test]
fn standalone_metadata_uses_explicit_pin_and_leaves_tiny_offline_workspace_unchanged() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    recipe(&root);
    fs::create_dir(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    fs::write(root.join("Cargo.toml"), "[package]\nname = \"metadata-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n[workspace]\n").unwrap();
    fs::write(
        root.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"metadata-fixture\"\nversion = \"0.0.0\"\n",
    )
    .unwrap();
    fs::write(root.join("rust-toolchain.toml"), "[toolchain]\nchannel = \"uninstalled-policy-override\"\ncomponents = [\"nonexistent-component\"]\n").unwrap();
    let before = BuildInputSnapshot::capture(&root).unwrap();
    let spec = workspace_metadata_command(&root).unwrap();
    let command = spec.materialize(None).unwrap();
    assert_eq!(command.get_program(), "rustup");
    let expected: Vec<_> = ["run", "1.97.1", "cargo"]
        .into_iter()
        .chain(expected_arguments())
        .collect();
    assert_eq!(command.get_args().collect::<Vec<_>>(), expected);
    let metadata = memcordon_ci::policy::workspace_metadata(&root).unwrap();
    assert_eq!(metadata.packages.len(), 1);
    assert_eq!(metadata.packages[0].name.as_str(), "metadata-fixture");
    assert_eq!(
        PathBuf::from(metadata.workspace_root.as_str())
            .canonicalize()
            .unwrap(),
        root
    );
    assert!(
        metadata.resolve.is_none(),
        "no-deps metadata must retain its contract"
    );
    before.audit().unwrap();
}
