use std::ffi::OsStr;
use std::process::Command;

#[test]
fn explicit_toolchain_invocations_preserve_native_argv_without_a_context() {
    use memcordon_ci::command::CommandSpec;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let rustup = root.join("tool path/rustup");
    let tool = root.join("tool path/cargo-fuzz");
    let deadline = std::time::Duration::from_secs(1);
    let cargo = CommandSpec::cargo(&rustup, root, "nightly", deadline)
        .args(["test", "argument with spaces"])
        .materialize(None)
        .unwrap();
    assert_eq!(cargo.get_program(), rustup);
    assert_eq!(
        cargo.get_args().collect::<Vec<_>>(),
        ["run", "nightly", "cargo", "test", "argument with spaces"]
    );
    let fuzz = CommandSpec::toolchain_program(&rustup, root, "nightly", &tool, deadline)
        .args(["fuzz", "build"])
        .materialize(None)
        .unwrap();
    assert_eq!(
        fuzz.get_args().collect::<Vec<_>>(),
        [
            OsStr::new("run"),
            OsStr::new("nightly"),
            tool.as_os_str(),
            OsStr::new("fuzz"),
            OsStr::new("build")
        ]
    );
}

#[cfg(unix)]
#[test]
fn absolute_rustup_and_fuzz_use_closed_toolchain_context_but_workloads_keep_their_environment() {
    use memcordon_ci::{build_context::ValidatedBuildContext, command::CommandSpec};
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let bin = root.join("sysroot/bin");
    fs::create_dir_all(&bin).unwrap();
    let cargo = bin.join("cargo");
    std::os::unix::fs::symlink("/usr/bin/env", &cargo).unwrap();
    let fuzz = root.join("target/ci-tools/bin/cargo-fuzz");
    fs::create_dir_all(fuzz.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink("/usr/bin/env", &fuzz).unwrap();
    let hex = |value: &OsStr| {
        value
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let manifest = root.join("context.json");
    fs::write(&manifest, serde_json::to_vec(&serde_json::json!({
        "schema_version": 2, "root": root,
        "environment": [[hex(OsStr::new("PATH")), hex(OsStr::new("/usr/bin"))]],
        "toolchains": {"nightly": cargo}, "input_roots": [root],
        "inputs": [{"path": hex(cargo.as_os_str()), "kind": "file", "mode": 0, "digest": "fixture"}],
        "worker": {}
    })).unwrap()).unwrap();
    let context = ValidatedBuildContext::read(&manifest).unwrap();
    let deadline = std::time::Duration::from_secs(1);
    for spec in [
        CommandSpec::cargo(root.join("absolute/rustup"), &root, "nightly", deadline),
        CommandSpec::toolchain_program("rustup", &root, "nightly", &fuzz, deadline),
    ] {
        let mut command = spec.materialize(Some(&context)).unwrap();
        assert_eq!(command.get_current_dir(), Some(root.as_path()));
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "native recorder failed: status {:?}, stderr {:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let output = String::from_utf8(output.stdout).unwrap();
        let environment: std::collections::BTreeMap<_, _> = output
            .lines()
            .map(|line| line.split_once('=').unwrap())
            .collect();
        assert_eq!(environment.get("RUSTUP_TOOLCHAIN"), Some(&"nightly"));
        assert_eq!(environment.get("CARGO_NET_OFFLINE"), Some(&"true"));
        assert_eq!(
            environment.get("RUSTC").copied(),
            bin.join("rustc").to_str()
        );
        assert_eq!(
            environment.get("RUSTDOC").copied(),
            bin.join("rustdoc").to_str()
        );
        assert_eq!(
            std::env::split_paths(environment.get("PATH").unwrap()).next(),
            Some(bin.clone())
        );
        assert_eq!(
            environment.len(),
            5,
            "ambient variables must not reach a managed compiler"
        );
    }
    let workload = CommandSpec::new("workload", &root, deadline)
        .arg("payload")
        .materialize(Some(&context))
        .unwrap();
    assert_eq!(workload.get_program(), "workload");
    assert_eq!(workload.get_args().collect::<Vec<_>>(), ["payload"]);
    assert!(
        workload
            .get_envs()
            .all(|(key, _)| key == "CARGO_REGISTRY_TOKEN"
                || key == "CARGO_REGISTRIES_CRATES_IO_TOKEN")
    );
}

#[test]
fn subprocesses_expose_exactly_one_selected_cargo_capability_interface() {
    for inherit_crates_io_token in [false, true] {
        let mut spec = memcordon_ci::command::CommandSpec::new(
            "memcordon-ci-command-policy-fixture",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
            std::time::Duration::from_secs(1),
        );
        if inherit_crates_io_token {
            spec = spec.inherit_crates_io_registry_token();
        }
        let mut command = Command::new("memcordon-ci-command-policy-fixture");
        spec.apply_environment(&mut command);
        let environment_state = |name: &str| {
            command
                .get_envs()
                .find(|(key, _)| *key == OsStr::new(name))
                .map(|(_, value)| value)
        };
        assert_eq!(
            environment_state("CARGO_REGISTRY_TOKEN"),
            Some(None),
            "the legacy singular-token interface must always be removed"
        );
        assert_eq!(
            environment_state("CARGO_REGISTRIES_CRATES_IO_TOKEN"),
            if inherit_crates_io_token {
                None
            } else {
                Some(None)
            },
            "the standard crates.io variable must follow the selected capability only"
        );
    }
}
