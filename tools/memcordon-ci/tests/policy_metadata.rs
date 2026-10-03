use memcordon_ci::policy::workspace_metadata_command;
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
fn standalone_metadata_uses_explicit_pin_and_leaves_tiny_offline_workspace_unchanged() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    recipe(&root);
    fs::create_dir(root.join("src")).unwrap();
    let files = [
        ("src/lib.rs", "pub fn fixture() {}\n"),
        (
            "Cargo.toml",
            "[package]\nname = \"metadata-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n[workspace]\n",
        ),
        (
            "Cargo.lock",
            "version = 4\n\n[[package]]\nname = \"metadata-fixture\"\nversion = \"0.0.0\"\n",
        ),
        (
            "rust-toolchain.toml",
            "[toolchain]\nchannel = \"uninstalled-policy-override\"\ncomponents = [\"nonexistent-component\"]\n",
        ),
    ];
    for (path, bytes) in files {
        fs::write(root.join(path), bytes).unwrap();
    }
    let command = workspace_metadata_command(&root)
        .unwrap()
        .materialize()
        .unwrap();
    assert_eq!(command.get_program(), "rustup");
    let expected: Vec<_> = ["run", "1.97.1", "cargo"]
        .into_iter()
        .chain(expected_arguments())
        .collect();
    assert_eq!(command.get_args().collect::<Vec<_>>(), expected);
    assert_eq!(command.get_current_dir(), Some(root.as_path()));
    let metadata = memcordon_ci::policy::workspace_metadata(&root).unwrap();
    assert_eq!(metadata.packages.len(), 1);
    assert_eq!(metadata.packages[0].name.as_str(), "metadata-fixture");
    assert_eq!(
        PathBuf::from(metadata.workspace_root.as_str())
            .canonicalize()
            .unwrap(),
        root
    );
    assert!(metadata.resolve.is_none());
    for (path, bytes) in files {
        assert_eq!(fs::read(root.join(path)).unwrap(), bytes.as_bytes());
    }
}
