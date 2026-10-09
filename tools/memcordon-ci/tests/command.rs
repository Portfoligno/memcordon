use memcordon_ci::command::CommandSpec;
use std::ffi::OsStr;
use std::process::Command;
use std::time::Duration;

#[test]
fn command_excerpts_preserve_each_middle_libtest_failure_for_lf_and_crlf() {
    let limit = 64 * 1024;
    let failure = "failures:\n\n---- actual_asset_loss stdout ----\nthread 'actual_asset_loss' panicked at release_rehearsal_loss.rs:387:\nactual first failure observation\n\nfailures:\n    actual_asset_loss\n\ntest result: FAILED. 0 passed; 1 failed\n";
    let later = b"failures:\n\n---- another_case stdout ----\nsecond failure observation\n\nfailures:\n    another_case\n\ntest result: FAILED. 0 passed; 1 failed\n";
    for failure in [failure.to_owned(), failure.replace('\n', "\r\n")] {
        assert_eq!(
            memcordon_ci::command::bounded_excerpt(failure.as_bytes()),
            failure
        );
        let beginning = b"first successful target\n";
        let terminal = b"last successful target: test result: ok. 2 passed\n";
        let mut bytes = beginning.to_vec();
        bytes.extend(vec![b'x'; limit]);
        bytes.push(b'\n');
        bytes.extend_from_slice(failure.as_bytes());
        bytes.extend(vec![b'y'; limit]);
        bytes.push(b'\n');
        bytes.extend_from_slice(later);
        bytes.extend(vec![b'z'; limit]);
        bytes.extend_from_slice(terminal);
        let excerpt = memcordon_ci::command::bounded_excerpt(&bytes);
        assert!(excerpt.len() <= limit);
        assert!(excerpt.starts_with(std::str::from_utf8(beginning).unwrap()));
        assert!(excerpt.ends_with(std::str::from_utf8(terminal).unwrap()));
        assert!(excerpt.contains(&failure));
        assert!(excerpt.contains("second failure observation"));
        assert!(excerpt.contains("libtest failure sections"));
    }
}

#[test]
fn command_excerpts_bound_large_failure_sections_and_lossy_decoding() {
    let limit = 64 * 1024;
    let beginning = b"first successful target\n";
    let terminal = "last successful target: 終了🙂\n";
    for padding in ["🙂".repeat(limit).into_bytes(), vec![0xff; limit * 2]] {
        let mut bytes = beginning.to_vec();
        bytes.extend(vec![b'x'; limit]);
        bytes.extend_from_slice(b"\nfailures:\n\n---- large_case stdout ----\nthread panicked at actual_source.rs:42:\n");
        bytes.extend(padding);
        bytes.extend_from_slice(
            b"\nfailures:\n    large_case\n\ntest result: FAILED. 0 passed; 1 failed\n",
        );
        bytes.extend(vec![b'y'; limit]);
        bytes.extend_from_slice(terminal.as_bytes());
        let excerpt = memcordon_ci::command::bounded_excerpt(&bytes);
        assert!(excerpt.len() <= limit);
        assert!(excerpt.starts_with(std::str::from_utf8(beginning).unwrap()));
        assert!(excerpt.ends_with(terminal));
        assert!(excerpt.contains("thread panicked at actual_source.rs:42"));
        assert!(excerpt.contains("test result: FAILED. 0 passed; 1 failed"));
        assert!(excerpt.contains(" [excerpt truncated] "));
    }
}

#[test]
fn command_excerpts_ignore_incidental_failure_headings_and_reset_after_success() {
    let limit = 64 * 1024;
    for incidental in [
        "failures:\nincidental output\ntest result: ok. 1 passed\n",
        "failures:\nunterminated output\n",
        "failures: incidental inline heading\ntest result: FAILED. 1 failed\n",
        "failures:\nincidental output\ntest result: FAILEDNESS.\n",
    ] {
        let mut bytes = vec![b'x'; limit];
        bytes.push(b'\n');
        bytes.extend_from_slice(incidental.as_bytes());
        bytes.extend(vec![b'y'; limit]);
        let excerpt = memcordon_ci::command::bounded_excerpt(&bytes);
        assert!(excerpt.len() <= limit);
        assert!(!excerpt.contains("libtest failure sections"));
    }

    let mut bytes = vec![b'x'; limit];
    bytes.extend_from_slice(
        b"\nfailures:\nincidental successful output\ntest result: ok. 1 passed\n",
    );
    bytes.extend(vec![b'y'; limit]);
    bytes.extend_from_slice(b"\nfailures:\nactual later failure\ntest result: FAILED. 1 failed\n");
    bytes.extend(vec![b'z'; limit]);
    let excerpt = memcordon_ci::command::bounded_excerpt(&bytes);
    assert!(excerpt.len() <= limit);
    assert!(excerpt.contains("actual later failure"));
    assert!(!excerpt.contains("incidental successful output"));
}

#[test]
fn command_excerpts_preserve_terminal_failures_within_the_existing_bound() {
    let limit = 64 * 1024;
    let beginning = b"beginning of subprocess output\n";
    let terminal = b"\nerror: test failed, to rerun pass --test actual_terminal_failure";
    let mut bytes = beginning.to_vec();
    bytes.extend(vec![b'x'; limit * 2]);
    bytes.extend_from_slice(terminal);
    let excerpt = memcordon_ci::command::bounded_excerpt(&bytes);
    assert_eq!(excerpt.len(), limit);
    assert!(excerpt.starts_with(std::str::from_utf8(beginning).unwrap()));
    assert!(excerpt.ends_with(std::str::from_utf8(terminal).unwrap()));
    assert!(excerpt.contains(" [excerpt truncated] "));

    for length in [0, limit / 2, limit] {
        let complete = vec![b'x'; length];
        assert_eq!(
            memcordon_ci::command::bounded_excerpt(&complete).as_bytes(),
            complete
        );
    }
    let overflowing = vec![b'x'; limit + 1];
    assert!(memcordon_ci::command::bounded_excerpt(&overflowing).len() <= limit);
    assert!(memcordon_ci::command::bounded_excerpt(&overflowing).contains("[excerpt truncated]"));
}

#[test]
fn command_excerpts_bound_unicode_and_lossy_utf8_without_losing_the_tail() {
    let limit = 64 * 1024;
    let terminal = "\nactual terminal failure: 終了🙂";
    for mut bytes in [
        "🙂".repeat(limit).into_bytes(),
        vec![0xff; limit * 2],
        vec![0xff; limit / 2],
    ] {
        bytes.extend_from_slice(terminal.as_bytes());
        let excerpt = memcordon_ci::command::bounded_excerpt(&bytes);
        assert!(excerpt.len() <= limit);
        assert!(excerpt.ends_with(terminal));
        assert!(excerpt.contains("[excerpt truncated]"));
    }
    let short = "short output: 終了🙂";
    assert_eq!(
        memcordon_ci::command::bounded_excerpt(short.as_bytes()),
        short
    );
}

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
