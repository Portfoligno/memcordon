use memcordon_ci::{
    build_context::{ValidatedBuildContext, environment},
    command::PackageOutput,
};
use std::{ffi::OsStr, fs, path::Path};

#[test]
fn package_producer_and_consumer_share_explicit_target_under_closed_environment() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let bin = root.join("measured bin");
    fs::create_dir(&bin).unwrap();
    let cargo = bin.join(if cfg!(windows) { "cargo.exe" } else { "cargo" });
    fs::write(&cargo, "fixture\n").unwrap();
    let encode = |value: &OsStr| hex::encode(value.as_encoded_bytes());
    let manifest = root.join("context.json");
    fs::write(&manifest, serde_json::to_vec(&serde_json::json!({
        "schema_version": 3, "root": root,
        "environment": [[encode(OsStr::new("PATH")), encode(bin.as_os_str())]],
        "toolchains": {"1.97.1": cargo}, "input_roots": [bin], "discovery_roots": [],
        "inputs": [{"path": encode(cargo.as_os_str()), "kind": "file", "mode": 0, "digest": "fixture"}], "worker": {}
    })).unwrap()).unwrap();
    let context = ValidatedBuildContext::read(&manifest).unwrap();
    let absolute = temporary.path().join("absolute output with spaces");
    for target in [
        None,
        Some(Path::new("target/channel output")),
        Some(Path::new("target/ci/windows-sealed-cargo/build")),
        Some(absolute.as_path()),
    ] {
        let output = PackageOutput::new(&root, target).unwrap();
        let expected = target.map_or_else(
            || root.join("target"),
            |path| {
                if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    root.join(path)
                }
            },
        );
        let expected = environment::paths::command_output_path(&expected).unwrap();
        assert_eq!(output.archive_directory(), expected.join("package"));
        let command = output
            .command(
                &root,
                "1.97.1",
                &["fixture-one".into(), "fixture-two".into()],
            )
            .materialize(Some(&context))
            .unwrap();
        assert_eq!(
            command.get_program(),
            environment::paths::command_program(&cargo).unwrap()
        );
        let args = command.get_args().collect::<Vec<_>>();
        let index = args.iter().position(|arg| *arg == "--target-dir").unwrap();
        assert_eq!(args[index + 1], expected);
        assert!(args.contains(&OsStr::new("--locked")));
        assert!(args.contains(&OsStr::new("--no-verify")));
        assert_eq!(args.iter().filter(|arg| **arg == "--package").count(), 2);
        assert!(!command.get_envs().any(|(key, _)| key == "CARGO_TARGET_DIR"));
        assert_eq!(
            command.get_current_dir(),
            Some(environment::command_path(&root).unwrap().as_path())
        );
    }
}
