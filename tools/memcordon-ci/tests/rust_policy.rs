use std::path::Path;

use memcordon_ci::policy::validate_rust_policy_bytes;

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
