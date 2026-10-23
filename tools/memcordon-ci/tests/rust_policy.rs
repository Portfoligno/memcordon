use std::path::Path;

use memcordon_ci::policy::validate_rust_policy_bytes;

const OWNED_COMPILER_PROTOCOL: &str = r#"
impl CommandSpec {
    fn materialize(&self) {
        self.apply_environment(&mut command);
        #[cfg(unix)]
        if let Some(owner) = &self.compiler_owner {
            let protocol = owner.admit()?;
            command.env_remove("MAKEFLAGS").env_remove("MFLAGS")
                .env_remove("CARGO_BUILD_JOBS")
                .env("CARGO_MAKEFLAGS", protocol.makeflags());
        }
    }
}
"#;

#[test]
fn owned_compiler_protocol_requires_the_complete_materialization_boundary() {
    let boundary = Path::new("tools/memcordon-ci/src/command.rs");
    validate_rust_policy_bytes(boundary, OWNED_COMPILER_PROTOCOL.as_bytes()).unwrap();
    for path in [
        "tools/memcordon-ci/src/compiler_pool.rs",
        "tools/memcordon-ci/src/command_other.rs",
        "tools/memcordon-ci/tests/compiler_pool.rs",
        "crates/example/src/lib.rs",
    ] {
        assert!(
            validate_rust_policy_bytes(Path::new(path), OWNED_COMPILER_PROTOCOL.as_bytes())
                .is_err()
        );
    }
    for (before, after) in [
        ("CommandSpec", "OtherCommand"),
        ("impl CommandSpec", "#[cfg(any())] impl CommandSpec"),
        ("fn materialize", "#[cfg(any())] fn materialize"),
        ("fn materialize", "fn another_function"),
        ("#[cfg(unix)]", ""),
        ("#[cfg(unix)]", "#[cfg(any())]"),
        ("#[cfg(unix)]", "#[cfg(windows)]"),
        ("#[cfg(unix)]", "#[cfg_attr(unix, cfg(any()))]"),
        ("#[cfg(unix)]", "#[cfg(unix)] #[cfg(any())]"),
        ("self.apply_environment(&mut command);", ""),
        ("&self.compiler_owner", "&self.other_owner"),
        ("owner.admit()?", "arbitrary_protocol()"),
        ("owner.admit()?", "other.admit()?"),
        ("protocol.makeflags()", "\"arbitrary flags\""),
        ("protocol.makeflags()", "unvalidated"),
        ("protocol.makeflags()", "other.makeflags()"),
        ("protocol.makeflags()", "protocol.makeflags(extra)"),
        ("protocol.makeflags()", "protocol.makeflags::<Other>()"),
        ("\"CARGO_MAKEFLAGS\"", "\"MAKEFLAGS\""),
        ("\"CARGO_MAKEFLAGS\"", "dynamic_key"),
        ("\"MFLAGS\"", "\"GH_TOKEN\""),
        (".env_remove(\"MFLAGS\")", ""),
        ("command.env_remove", "other.env_remove"),
        (
            "let protocol = owner.admit()?;",
            "let protocol = owner.admit()?; let protocol = arbitrary;",
        ),
    ] {
        let changed = OWNED_COMPILER_PROTOCOL.replace(before, after);
        assert_ne!(changed, OWNED_COMPILER_PROTOCOL);
        assert!(
            validate_rust_policy_bytes(boundary, changed.as_bytes()).is_err(),
            "accepted {before} -> {after}"
        );
    }
}

#[test]
fn owned_compiler_protocol_accounts_for_all_mutations_and_keeps_credentials_restricted() {
    let boundary = Path::new("tools/memcordon-ci/src/command.rs");
    for changed in [
        OWNED_COMPILER_PROTOCOL.replace(
            "self.apply_environment(&mut command);",
            "self.apply_environment(&mut command); self.apply_environment(&mut command);",
        ),
        OWNED_COMPILER_PROTOCOL.replace(
            "        }\n    }\n}",
            "        }\n        self.apply_environment(&mut command);\n    }\n}",
        ),
        OWNED_COMPILER_PROTOCOL.replace(
            "        }\n    }\n}",
            "        }\n        self.apply_environment(&mut other);\n    }\n}",
        ),
        OWNED_COMPILER_PROTOCOL.replace(
            "        }\n    }\n}",
            "        }\n        command.env_remove(\"CARGO_MAKEFLAGS\");\n    }\n}",
        ),
        OWNED_COMPILER_PROTOCOL.replace(
            "        }\n    }\n}",
            "        }\n        command.env_remove(dynamic_key);\n    }\n}",
        ),
    ] {
        assert_ne!(changed, OWNED_COMPILER_PROTOCOL);
        assert!(
            validate_rust_policy_bytes(boundary, changed.as_bytes()).is_err(),
            "accepted repeated sanitation after protocol admission"
        );
    }
    for extra in [
        "command.env(\"CARGO_MAKEFLAGS\", protocol.makeflags());",
        "command.env(\"CUSTOM_CI_VALUE\", \"value\");",
        "command.envs([(\"CARGO_MAKEFLAGS\", \"value\")]);",
        "command.env_clear();",
        "command.env_remove(\"MAKEFLAGS\");",
        "std::env::set_var(\"CARGO_MAKEFLAGS\", \"value\");",
    ] {
        let changed = [OWNED_COMPILER_PROTOCOL, "fn extra() {", extra, "}"].join("\n");
        assert!(
            validate_rust_policy_bytes(boundary, changed.as_bytes()).is_err(),
            "accepted extra mutation: {extra}"
        );
    }
    let duplicate = [OWNED_COMPILER_PROTOCOL, OWNED_COMPILER_PROTOCOL].join("\n");
    assert!(validate_rust_policy_bytes(boundary, duplicate.as_bytes()).is_err());
    for path in [
        "tools/memcordon-ci/src/compiler_pool.rs",
        "crates/example/src/lib.rs",
    ] {
        assert!(
            validate_rust_policy_bytes(
                Path::new(path),
                b"fn extra() { command.env_remove(\"GH_TOKEN\"); }"
            )
            .is_err()
        );
    }
}

#[test]
fn actual_compiler_protocol_sources_satisfy_policy() {
    validate_rust_policy_bytes(
        Path::new("tools/memcordon-ci/src/command.rs"),
        include_bytes!("../src/command.rs"),
    )
    .unwrap();
    validate_rust_policy_bytes(
        Path::new("tools/memcordon-ci/src/compiler_pool.rs"),
        include_bytes!("../src/compiler_pool.rs"),
    )
    .unwrap();
    // repository_policy_checks_all_lightweight_phases below exercises the
    // complete gate used by preparation, including these same source files.
}

#[test]
fn owned_protocol_cannot_be_overwritten_through_direct_command_calls() {
    let boundary = Path::new("tools/memcordon-ci/src/command.rs");
    for call in [
        "Self::apply_environment(self, &mut command);",
        "CommandSpec::apply_environment(self, &mut command);",
        "Command::env_remove(&mut command, dynamic_key);",
        "std::process::Command::env_remove(&mut command, \"CARGO_MAKEFLAGS\");",
        "Command::env(&mut command, \"CARGO_MAKEFLAGS\", \"arbitrary\");",
        "Command::envs(&mut command, [(\"CARGO_MAKEFLAGS\", \"arbitrary\")]);",
        "Command::env_clear(&mut command);",
    ] {
        let replacement = ["        }", call, "    }", "}"].join("\n");
        let changed = OWNED_COMPILER_PROTOCOL.replace("        }\n    }\n}", &replacement);
        assert_ne!(changed, OWNED_COMPILER_PROTOCOL);
        assert!(
            validate_rust_policy_bytes(boundary, changed.as_bytes()).is_err(),
            "accepted direct overwrite: {call}"
        );
    }
}

#[test]
fn repository_policy_checks_all_lightweight_phases() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    memcordon_ci::policy::run(root).unwrap();
}

#[test]
fn repository_rust_sources_satisfy_policy_without_first_error_masking() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let tracked = std::process::Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(tracked.status.success());
    let mut files = std::collections::BTreeSet::new();
    for name in tracked
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let relative = std::path::PathBuf::from(std::str::from_utf8(name).unwrap());
        if relative
            .extension()
            .is_some_and(|extension| extension == "rs")
        {
            files.insert(relative);
        }
    }
    for base in [
        "tools/memcordon-ci",
        "crates/memcordon-testkit",
        "crates/memcordon-cli/src/bin",
        "crates/memcordon-cli/tests",
        "crates/memcordon-platform/src",
    ] {
        for entry in walkdir::WalkDir::new(root.join(base)) {
            let entry = entry.unwrap();
            if entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "rs")
            {
                files.insert(entry.path().strip_prefix(root).unwrap().to_path_buf());
            }
        }
    }
    let failures: Vec<_> = files
        .iter()
        .filter_map(|relative| {
            let bytes = match std::fs::read(root.join(relative)) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
                Err(error) => panic!("read tracked Rust source {relative:?}: {error}"),
            };
            validate_rust_policy_bytes(relative, &bytes)
                .err()
                .map(|error| error.to_string())
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn neutral_execution_identity_does_not_exempt_pre_exec() {
    let path = Path::new(
        "crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/execution_identity.rs",
    );
    let native = b"fn run(command: &mut std::process::Command, uid: u32, gid: u32) { command.gid(gid).uid(uid); }";
    validate_rust_policy_bytes(path, native).unwrap();
    let hook =
        b"fn run(command: &mut std::process::Command) { unsafe { command.pre_exec(|| Ok(())); } }";
    assert!(validate_rust_policy_bytes(path, hook).is_err());
    validate_rust_policy_bytes(
        path,
        include_bytes!("../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/execution_identity.rs"),
    )
    .unwrap();
}

#[test]
fn process_test_boundary_has_one_shared_native_setup_hook() {
    struct Hooks(usize);
    impl<'ast> syn::visit::Visit<'ast> for Hooks {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "pre_exec" {
                self.0 += 1;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let source = include_bytes!("../../../crates/memcordon-platform/src/test_support.rs");
    validate_rust_policy_bytes(
        Path::new("crates/memcordon-platform/src/test_support.rs"),
        source,
    )
    .unwrap();
    let file = syn::parse_file(std::str::from_utf8(source).unwrap()).unwrap();
    let mut hooks = Hooks(0);
    syn::visit::Visit::visit_file(&mut hooks, &file);
    assert_eq!(hooks.0, 1);
}

#[test]
fn private_sealed_forks_have_exact_reviewed_source_boundaries() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = Path::new("crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux");
    let fork = b"fn run() { unsafe { libc::fork(); } }";
    for name in ["private_guardian.rs", "private_namespace_init.rs"] {
        let relative = directory.join(name);
        validate_rust_policy_bytes(&relative, fork).unwrap();
        let bytes = std::fs::read(root.join(&relative)).unwrap();
        validate_rust_policy_bytes(&relative, &bytes)
            .unwrap_or_else(|error| panic!("reviewed source {relative:?}: {error}"));
    }
    for name in ["private_unreviewed.rs", "private_guardian_copy.rs"] {
        assert!(validate_rust_policy_bytes(&directory.join(name), fork).is_err());
    }
}

#[test]
fn deadline_helpers_preserve_typed_spawning_and_environment_boundaries() {
    for (path, source) in [
        (
            "tools/memcordon-deadline-oracle/src/native.rs",
            include_str!("../../memcordon-deadline-oracle/src/native.rs"),
        ),
        (
            "crates/memcordon-cli/src/commands/result_delivery.rs",
            include_str!("../../../crates/memcordon-cli/src/commands/result_delivery.rs"),
        ),
        (
            "crates/memcordon-platform/src/macos_envelope.rs",
            include_str!("../../../crates/memcordon-platform/src/macos_envelope.rs"),
        ),
    ] {
        validate_rust_policy_bytes(Path::new(path), source.as_bytes())
            .expect("native helper policy");
    }
}

#[test]
fn native_install_fixture_only_may_override_standard_path() {
    let fixture = Path::new("crates/memcordon-cli/tests/macos_remediation.rs");
    let path = b"fn run(command: &mut std::process::Command) { command.env(\"PATH\", \"/usr/bin:/bin\"); }";
    validate_rust_policy_bytes(fixture, path).unwrap();
    assert!(validate_rust_policy_bytes(Path::new("crates/example/src/lib.rs"), path).is_err());
    let custom = b"fn run(command: &mut std::process::Command) { command.env(\"MEMCORDON_FAULT\", \"ready\"); }";
    assert!(validate_rust_policy_bytes(fixture, custom).is_err());
    let dynamic =
        b"fn run(command: &mut std::process::Command, key: &str) { command.env(key, \"value\"); }";
    assert!(validate_rust_policy_bytes(fixture, dynamic).is_err());
}

#[test]
fn installed_joint_compiler_only_may_select_standard_toolchain_environment() {
    let fixture = Path::new("crates/memcordon-cli/src/bin/consumer_readiness_linux/mod.rs");
    let compiler = br#"fn run(command: &mut std::process::Command) {
        command.env_clear().env("CARGO_HOME", "/owned/cargo-home")
            .env("RUSTC", "/owned/rustc").env("TMPDIR", "/owned/tmp");
    }"#;
    validate_rust_policy_bytes(fixture, compiler).unwrap();
    assert!(validate_rust_policy_bytes(Path::new("crates/example/src/lib.rs"), compiler).is_err());
    for source in [
        br#"fn run(command: &mut std::process::Command) { command.env("MEMCORDON_FAULT", "ready"); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command, key: &str) { command.env(key, "value"); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.envs([("RUSTC", "/owned/rustc")]); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.env("PATH", "/unowned/bin"); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.env("CARGO_HOME", "/owned/cargo-home").env("RUSTC", "/owned/rustc").env("TMPDIR", "/owned/tmp"); }"#.as_slice(),
    ] {
        assert!(validate_rust_policy_bytes(fixture, source).is_err());
    }
}

#[test]
fn isolated_cargo_boundary_only_may_select_standard_cargo_home() {
    let boundary = Path::new("tools/memcordon-ci/src/command.rs");
    let standard = br#"fn run(command: &mut std::process::Command) { command.env("CARGO_HOME", "/owned/cargo-home"); }"#;
    validate_rust_policy_bytes(boundary, standard).unwrap();
    assert!(validate_rust_policy_bytes(Path::new("crates/example/src/lib.rs"), standard).is_err());
    let miri =
        br#"fn run(command: &mut std::process::Command) { command.env("MIRI_SYSROOT", root); }"#;
    validate_rust_policy_bytes(boundary, miri).unwrap();
    assert!(validate_rust_policy_bytes(Path::new("crates/example/src/lib.rs"), miri).is_err());
    for source in [
        br#"fn run(command: &mut std::process::Command) { command.env("CUSTOM_CI_FLAG", "value"); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.env("RUSTC", "/unowned/rustc"); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command, key: &str) { command.env(key, "value"); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.envs([("CARGO_HOME", "/owned/cargo-home")]); }"#.as_slice(),
    ] {
        assert!(validate_rust_policy_bytes(boundary, source).is_err());
    }
}

#[test]
fn reviewed_download_fixtures_preserve_isolated_home_and_output_boundaries() {
    let fixtures = [
        (
            "tools/memcordon-ci/tests/cache_download_families.rs",
            include_str!("cache_download_families.rs"),
        ),
        (
            "tools/memcordon-ci/tests/cache_snapshot_transport.rs",
            include_str!("cache_snapshot_transport.rs"),
        ),
        (
            "tools/memcordon-ci/tests/tool_download_roundtrip.rs",
            include_str!("tool_download_roundtrip.rs"),
        ),
    ];
    let standard = br#"fn run(command: &mut std::process::Command) { command.env("CARGO_HOME", home).env("GITHUB_OUTPUT", output); }"#;
    for (relative, actual) in fixtures {
        let path = Path::new(relative);
        validate_rust_policy_bytes(path, actual.as_bytes()).unwrap();
        validate_rust_policy_bytes(path, standard).unwrap();
        for forbidden in [
            br#"fn run(command: &mut std::process::Command) { command.env("CUSTOM_CI_FLAG", "value"); }"#.as_slice(),
            br#"fn run(command: &mut std::process::Command, key: &str) { command.env(key, "value"); }"#.as_slice(),
            br#"fn run(command: &mut std::process::Command) { command.envs([("CARGO_HOME", home)]); }"#.as_slice(),
            br#"fn run(command: &mut std::process::Command) { command.env_clear().env("CARGO_HOME", home); }"#.as_slice(),
            br#"fn run(command: &mut std::process::Command) { command.env_remove("CARGO_HOME"); }"#.as_slice(),
            br#"fn run(command: &mut std::process::Command) { command.env("PATH", "/unowned/bin"); }"#.as_slice(),
            br#"fn run(command: &mut std::process::Command) { command.env("RUSTC", "/unowned/rustc"); }"#.as_slice(),
            br#"fn run(command: &mut std::process::Command) { command.env("CARGO_HOME", home).env("CUSTOM_CI_FLAG", "value"); }"#.as_slice(),
        ] {
            assert!(
                validate_rust_policy_bytes(path, forbidden).is_err(),
                "{relative} accepted unreviewed environment source: {}",
                String::from_utf8_lossy(forbidden)
            );
        }
    }
    for relative in [
        "tools/memcordon-ci/tests/unreviewed_download_fixture.rs",
        "tools/memcordon-ci/src/download_cache.rs",
        "crates/example/src/lib.rs",
    ] {
        assert!(validate_rust_policy_bytes(Path::new(relative), standard).is_err());
    }
}

#[test]
fn offline_download_permission_is_exact_in_path_key_and_value() {
    let fixture = Path::new("tools/memcordon-ci/tests/tool_download_roundtrip.rs");
    let offline = br#"fn run(command: &mut std::process::Command) { command.env("CARGO_NET_OFFLINE", "true"); }"#;
    validate_rust_policy_bytes(fixture, offline).unwrap();
    let combined = br#"fn run(command: &mut std::process::Command) { command.env("CARGO_HOME", home).env("CARGO_NET_OFFLINE", "true").env("GITHUB_OUTPUT", output); }"#;
    validate_rust_policy_bytes(fixture, combined).unwrap();
    for relative in [
        "tools/memcordon-ci/tests/cache_download_families.rs",
        "tools/memcordon-ci/tests/cache_snapshot_transport.rs",
        "tools/memcordon-ci/tests/unreviewed_download_fixture.rs",
        "tools/memcordon-ci/src/command.rs",
    ] {
        assert!(validate_rust_policy_bytes(Path::new(relative), offline).is_err());
    }
    for forbidden in [
        br#"fn run(command: &mut std::process::Command) { command.env("CARGO_NET_OFFLINE", "false"); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.env("CARGO_NET_OFFLINE", "1"); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.env("CARGO_NET_OFFLINE", value); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command, key: &str) { command.env(key, "true"); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.envs([("CARGO_NET_OFFLINE", "true")]); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.env("CUSTOM_CI_OFFLINE", "true"); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.env("CARGO_NET_OFFLINE", "true").env("CARGO_NET_OFFLINE", "false"); }"#.as_slice(),
    ] {
        assert!(
            validate_rust_policy_bytes(fixture, forbidden).is_err(),
            "offline fixture accepted unreviewed source: {}",
            String::from_utf8_lossy(forbidden)
        );
    }
}

#[test]
fn driver_fixture_environment_is_exact_in_path_key_value_and_count() {
    let fixture = Path::new("tools/memcordon-ci/tests/driver_cache.rs");
    let actual = include_str!("driver_cache.rs");
    validate_rust_policy_bytes(fixture, actual.as_bytes()).unwrap();
    for changed in [
        actual.replace("\"GITHUB_EVENT_NAME\", event", "\"GITHUB_EVENT_NAME\", \"push\""),
        actual.replace("refs/heads/test", "refs/tags/test"),
        actual.replace("\"GITHUB_OUTPUT\", &outputs", "\"GITHUB_OUTPUT\", \"unowned-output\""),
        actual.replace("join(\"cargo-home\")", "join(\"unowned-home\")"),
        actual.replace("\"GITHUB_REF\"", "\"CUSTOM_CI_REF\""),
        actual.replace(".env(\"GITHUB_REF\", \"refs/heads/test\")", ""),
        [actual, r#"fn extra(command: &mut Command) { command.env("GITHUB_REF", "refs/heads/test"); }"#].join("\n"),
        [actual, r#"fn extra(command: &mut Command) { command.env("CUSTOM_CI_FLAG", "value"); }"#].join("\n"),
        [actual, r#"fn extra(command: &mut Command, key: &str) { command.env(key, "value"); }"#].join("\n"),
        [actual, r#"fn extra(command: &mut Command) { command.envs([("GITHUB_REF", "refs/heads/test")]); }"#].join("\n"),
        [actual, r#"fn extra(command: &mut Command) { command.env_clear(); }"#].join("\n"),
        [actual, r#"fn extra(command: &mut Command) { command.env_remove("GITHUB_REF"); }"#].join("\n"),
    ] {
        assert_ne!(changed, actual, "mutation must change the real fixture");
        assert!(validate_rust_policy_bytes(fixture, changed.as_bytes()).is_err());
    }
    for path in [
        "tools/memcordon-ci/tests/unreviewed_driver_cache.rs",
        "tools/memcordon-ci/tests/cache_download_families.rs",
        "tools/memcordon-ci/src/driver_cache.rs",
    ] {
        assert!(validate_rust_policy_bytes(Path::new(path), actual.as_bytes()).is_err());
    }
}

#[test]
fn cargo_fuzz_budget_is_reviewed_only_at_the_owned_command_boundary() {
    let boundary = Path::new("tools/memcordon-ci/src/command.rs");
    let actual = include_str!("../src/command.rs");
    validate_rust_policy_bytes(boundary, actual.as_bytes()).unwrap();
    let standard = br#"fn run(command: &mut std::process::Command) { command.env("CARGO_BUILD_JOBS", group.compiler_jobs().to_string()); }"#;
    validate_rust_policy_bytes(boundary, standard).unwrap();
    assert!(validate_rust_policy_bytes(Path::new("crates/example/src/lib.rs"), standard).is_err());
    for source in [
        br#"fn run(command: &mut std::process::Command) { command.env("CARGO_BUILD_JOBS", "99"); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.env("MIRI_SYSROOT", "/arbitrary"); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.env("MIRI_SYSROOT", arbitrary); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.env("CARGO_BUILD_JOBS", arbitrary.to_string()); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.env("CUSTOM_CI_JOBS", group.compiler_jobs().to_string()); }"#.as_slice(),
        br#"fn run(command: &mut std::process::Command) { command.env("CARGO_BUILD_JOBS", group.compiler_jobs().to_string()).env("CARGO_BUILD_JOBS", group.compiler_jobs().to_string()); }"#.as_slice(),
    ] {
        assert!(validate_rust_policy_bytes(boundary, source).is_err());
    }
}

#[test]
fn mixed_release_helpers_use_the_reviewed_descriptor_inheritance_boundary() {
    let fixture = Path::new("crates/memcordon-cli/tests/sealed_agent/native_mixed_release.rs");
    validate_rust_policy_bytes(
        fixture,
        include_bytes!("../../../crates/memcordon-cli/tests/sealed_agent/native_mixed_release.rs"),
    )
    .unwrap();
    let direct = br#"fn run(command: &mut std::process::Command) { unsafe { command.pre_exec(|| Ok(())); } }"#;
    assert!(validate_rust_policy_bytes(fixture, direct).is_err());
}

#[test]
fn unrelated_exec_method_is_not_rejected_by_name() {
    let source = b"struct Example; impl Example { fn exec(&self) {} } fn use_it(value: &Example) { value.exec(); }";
    validate_rust_policy_bytes(Path::new("crates/example/src/lib.rs"), source)
        .expect("an unrelated typed exec method should remain valid");
}

#[test]
fn subprocess_environment_is_confined_to_the_sealed_exec_boundary() {
    let source = b"fn run(command: &mut std::process::Command) { command.env(\"A\", \"B\"); }";
    validate_rust_policy_bytes(
        Path::new("crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/launch.rs"),
        source,
    )
    .expect("the exact sealed exec boundary may restore the requested environment");
    assert!(validate_rust_policy_bytes(Path::new("crates/example/src/lib.rs"), source).is_err());
}

#[test]
fn delivery_evidence_uses_the_reviewed_process_boundary_without_new_authority() {
    let fixture = Path::new("crates/memcordon-cli/tests/support/delivery_evidence.rs");
    validate_rust_policy_bytes(
        fixture,
        include_bytes!("../../../crates/memcordon-cli/tests/support/delivery_evidence.rs"),
    )
    .expect("delivery evidence must use the existing reviewed process boundary");
    let forbidden = br#"
        #[cfg(all(target_os = "macos", feature = "test-fixtures"))]
        fn attach(command: &mut std::process::Command) {
            unsafe { command.pre_exec(|| Ok(())); }
        }
    "#;
    let error = validate_rust_policy_bytes(fixture, forbidden)
        .unwrap_err()
        .to_string();
    assert!(error.contains("pre_exec is allowed only"), "{error}");
    validate_rust_policy_bytes(
        Path::new("crates/memcordon-platform/src/test_support.rs"),
        forbidden,
    )
    .expect("the one reviewed process boundary retains its existing authority");
}

#[test]
fn inspector_retirement_control_has_no_new_pre_exec_authority() {
    let fixture =
        Path::new("crates/memcordon-platform/tests/support/macos_inspector_retirement.rs");
    validate_rust_policy_bytes(
        fixture,
        include_bytes!(
            "../../../crates/memcordon-platform/tests/support/macos_inspector_retirement.rs"
        ),
    )
    .expect("the real inspector retirement control must satisfy the process policy");
    let previous_hook = br#"
        fn configure(command: &mut std::process::Command) {
            unsafe {
                command.pre_exec(|| {
                    if libc::setpgid(0, 0) == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                });
            }
        }
    "#;
    let error = validate_rust_policy_bytes(fixture, previous_hook)
        .unwrap_err()
        .to_string();
    assert!(error.contains("pre_exec is allowed only"), "{error}");
}

#[test]
fn pre_exec_and_raw_fork_are_confined_to_exact_reviewed_boundaries() {
    let pre_exec =
        b"fn run(command: &mut std::process::Command) { unsafe { command.pre_exec(|| Ok(())); } }";
    assert!(validate_rust_policy_bytes(Path::new("crates/example/src/lib.rs"), pre_exec).is_err());
    let fork = b"fn run() { unsafe { libc::fork(); } }";
    assert!(validate_rust_policy_bytes(Path::new("crates/example/src/lib.rs"), fork).is_err());
    assert!(
        validate_rust_policy_bytes(Path::new("crates/memcordon-platform/src/guardian.rs"), fork,)
            .is_err()
    );
    for reviewed in [
        "crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/launch.rs",
        "crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/launcher.rs",
        "crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/namespace.rs",
        "crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/service.rs",
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture.rs",
        "crates/memcordon-cli/tests/sealed_agent/linux_faults.rs",
        "crates/memcordon-cli/tests/sealed_agent/linux_sealed.rs",
        "crates/memcordon-cli/tests/sealed_agent/launcher_activation.rs",
    ] {
        validate_rust_policy_bytes(Path::new(reviewed), fork)
            .expect("an exact reviewed sealed-provider boundary may fork");
    }
    assert!(
        validate_rust_policy_bytes(
            Path::new("crates/memcordon-cli/tests/sealed_agent/support/sealed_faults.rs"),
            fork,
        )
        .is_err(),
        "the fault harness must use the staged argv-spawned frontend helper",
    );
    assert!(
        validate_rust_policy_bytes(
            Path::new("crates/memcordon-cli/tests/sealed_agent/support/mod.rs"),
            fork,
        )
        .is_err(),
        "the generic shared support module must not retain raw-fork authority",
    );
    assert!(
        validate_rust_policy_bytes(
            Path::new("crates/memcordon-cli/tests/sealed_agent/launcher_activation_copy.rs"),
            fork,
        )
        .is_err(),
        "raw-fork authority must remain confined to the exact activation test path",
    );
    assert!(
        validate_rust_policy_bytes(
            Path::new("crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/qualification.rs"),
            fork,
        )
        .is_err()
    );
}

#[test]
fn only_the_macos_watchdog_may_resolve_the_current_executable() {
    let current_exe = b"fn run() { let _ = std::env::current_exe(); }";
    validate_rust_policy_bytes(
        Path::new("crates/memcordon-platform/src/macos_watchdog.rs"),
        current_exe,
    )
    .expect("reviewed macOS watchdog may resolve its installed executable");
    assert!(
        validate_rust_policy_bytes(
            Path::new("crates/memcordon-platform/src/linux_cgroup.rs"),
            current_exe,
        )
        .is_err()
    );
    let proc_self_exe = b"fn run() { let _ = \"/proc/self/exe\"; }";
    assert!(
        validate_rust_policy_bytes(
            Path::new("crates/memcordon-platform/src/macos_watchdog.rs"),
            proc_self_exe,
        )
        .is_err()
    );
}

#[test]
fn sealed_identity_transition_obeys_the_semantic_subprocess_policy() {
    validate_rust_policy_bytes(
        Path::new("tools/memcordon-ci/src/sealed_identity.rs"),
        include_bytes!("../src/sealed_identity.rs"),
    )
    .expect("the native setpriv argv builder must remain shell- and environment-free");
}

#[test]
fn retired_context_and_source_proof_paths_have_no_environment_exemption() {
    let source = br#"fn run(command: &mut std::process::Command) { command.env("RUSTC", "/pinned/rustc"); }"#;
    let removed = br#"fn generated_fixture_child(command: &mut std::process::Command) { command.env_remove("RUSTC"); }"#;
    for path in [
        "tools/ci-native-fingerprint.rs",
        "tools/memcordon-ci/src/build_context.rs",
        "tools/memcordon-ci/src/release_source.rs",
        "tools/memcordon-ci/tests/build_context.rs",
    ] {
        assert!(validate_rust_policy_bytes(Path::new(path), source).is_err());
        assert!(validate_rust_policy_bytes(Path::new(path), removed).is_err());
    }
    let credential =
        br#"fn remove(command: &mut std::process::Command) { command.env_remove("GH_TOKEN"); }"#;
    validate_rust_policy_bytes(Path::new("tools/memcordon-ci/src/command.rs"), credential).unwrap();
    assert!(
        validate_rust_policy_bytes(Path::new("tools/memcordon-ci/src/release.rs"), credential)
            .is_err()
    );
}
