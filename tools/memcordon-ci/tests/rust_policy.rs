use std::path::Path;

use memcordon_ci::policy::validate_rust_policy_bytes;

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
        Path::new("crates/memcordon-sealed-agent/src/linux/launch.rs"),
        source,
    )
    .expect("the exact sealed exec boundary may restore the requested environment");
    assert!(validate_rust_policy_bytes(Path::new("crates/example/src/lib.rs"), source).is_err());
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
        "crates/memcordon-sealed-agent/src/linux/launch.rs",
        "crates/memcordon-sealed-agent/src/linux/service.rs",
        "crates/memcordon-sealed-agent/src/bin/memcordon-sealed-test-fixture.rs",
        "crates/memcordon-sealed-agent/tests/linux_faults.rs",
        "crates/memcordon-sealed-agent/tests/linux_sealed.rs",
    ] {
        validate_rust_policy_bytes(Path::new(reviewed), fork)
            .expect("an exact reviewed sealed-provider boundary may fork");
    }
    assert!(
        validate_rust_policy_bytes(
            Path::new("crates/memcordon-sealed-agent/tests/support/sealed_faults.rs"),
            fork,
        )
        .is_err(),
        "the fault harness must use the staged argv-spawned frontend helper",
    );
    assert!(
        validate_rust_policy_bytes(
            Path::new("crates/memcordon-sealed-agent/tests/support/mod.rs"),
            fork,
        )
        .is_err(),
        "the generic shared support module must not retain raw-fork authority",
    );
    assert!(
        validate_rust_policy_bytes(
            Path::new("crates/memcordon-sealed-agent/src/linux/qualification.rs"),
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
