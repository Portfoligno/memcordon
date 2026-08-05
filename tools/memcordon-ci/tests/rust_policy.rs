use std::path::Path;

use memcordon_ci::policy::validate_rust_policy_bytes;

#[test]
fn unrelated_exec_method_is_not_rejected_by_name() {
    let source = b"struct Example; impl Example { fn exec(&self) {} } fn use_it(value: &Example) { value.exec(); }";
    validate_rust_policy_bytes(Path::new("crates/example/src/lib.rs"), source)
        .expect("an unrelated typed exec method should remain valid");
}

#[test]
fn pre_exec_is_test_only_and_raw_fork_is_forbidden_everywhere() {
    let pre_exec =
        b"fn run(command: &mut std::process::Command) { unsafe { command.pre_exec(|| Ok(())); } }";
    assert!(validate_rust_policy_bytes(Path::new("crates/example/src/lib.rs"), pre_exec).is_err());
    let fork = b"fn run() { unsafe { libc::fork(); } }";
    assert!(validate_rust_policy_bytes(Path::new("crates/example/src/lib.rs"), fork).is_err());
    assert!(
        validate_rust_policy_bytes(Path::new("crates/memcordon-platform/src/guardian.rs"), fork,)
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
