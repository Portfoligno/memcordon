use memcordon_ci::command::CommandSpec;
use std::ffi::OsStr;
use std::process::Command;
use std::time::Duration;

#[test]
fn private_native_command_explicitly_removes_actions_token() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let command = CommandSpec::new(
        "/usr/libexec/memcordon-sealed-agent",
        root,
        Duration::from_secs(1),
    )
    .args(["package", "inspect", "--json"])
    .materialize()
    .unwrap();
    for credential in [
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
    ] {
        assert_eq!(
            command
                .get_envs()
                .find(|(name, _)| *name == OsStr::new(credential)),
            Some((OsStr::new(credential), None))
        );
    }
}

#[test]
fn workspace_metadata_removes_registry_credentials() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    std::fs::create_dir(root.join("ci")).unwrap();
    std::fs::write(
        root.join("ci/toolchains.toml"),
        include_bytes!("../../../ci/toolchains.toml"),
    )
    .unwrap();
    let command = memcordon_ci::policy::workspace_metadata_command(root)
        .unwrap()
        .materialize()
        .unwrap();
    for credential in ["CARGO_REGISTRY_TOKEN", "CARGO_REGISTRIES_CRATES_IO_TOKEN"] {
        assert_eq!(
            command
                .get_envs()
                .find(|(name, _)| *name == OsStr::new(credential)),
            Some((OsStr::new(credential), None))
        );
    }
}

#[test]
fn explicit_toolchain_invocations_preserve_native_argv() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let rustup = root.join("tool path/rustup");
    let tool = root.join("tool path/cargo-fuzz");
    let deadline = Duration::from_secs(1);
    let cargo = CommandSpec::cargo(&rustup, root, "nightly", deadline)
        .args(["test", "argument with spaces"])
        .materialize()
        .unwrap();
    assert_eq!(cargo.get_program(), rustup);
    assert_eq!(
        cargo.get_args().collect::<Vec<_>>(),
        ["run", "nightly", "cargo", "test", "argument with spaces"]
    );
    let fuzz = CommandSpec::toolchain_program(&rustup, root, "nightly", &tool, deadline)
        .args(["fuzz", "build"])
        .materialize()
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

#[test]
fn supply_chain_tools_preserve_selected_pin_and_workloads_use_native_argv() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (spec, basename) in memcordon_ci::command::supply_chain_commands(root, "nightly")
        .into_iter()
        .zip(["cargo-audit", "cargo-deny"])
    {
        let command = spec.materialize().unwrap();
        assert_eq!(command.get_program(), "rustup");
        let arguments = command.get_args().collect::<Vec<_>>();
        assert_eq!(&arguments[..2], ["run", "nightly"]);
        assert_eq!(
            std::path::Path::new(arguments[2]).file_stem(),
            Some(OsStr::new(basename))
        );
        assert_eq!(command.get_current_dir(), Some(root));
    }
    let workload = CommandSpec::new("workload", root, Duration::from_secs(1))
        .arg("payload with spaces")
        .materialize()
        .unwrap();
    assert_eq!(workload.get_program(), "workload");
    assert_eq!(
        workload.get_args().collect::<Vec<_>>(),
        ["payload with spaces"]
    );
    assert!(!workload.get_envs().any(|(_, value)| value.is_some()));
}

#[test]
fn subprocesses_unconditionally_exclude_registry_and_actions_credentials() {
    let spec = CommandSpec::new(
        "memcordon-ci-command-policy-fixture",
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
        Duration::from_secs(1),
    );
    let mut command = Command::new("memcordon-ci-command-policy-fixture");
    spec.apply_environment(&mut command);
    let environment_state = |name: &str| {
        command
            .get_envs()
            .find(|(key, _)| *key == OsStr::new(name))
            .map(|(_, value)| value)
    };
    for credential in [
        "CARGO_REGISTRY_TOKEN",
        "CARGO_REGISTRIES_CRATES_IO_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
    ] {
        assert_eq!(
            environment_state(credential),
            Some(None),
            "{credential} must be excluded"
        );
    }
}
