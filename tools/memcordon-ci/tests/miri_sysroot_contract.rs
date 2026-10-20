use memcordon_ci::{command::CommandSpec, miri_cache};
use std::{path::Path, time::Duration};

#[test]
fn absent_managed_identity_keeps_required_native_work_admitted() {
    use memcordon_ci::{failure_mode::FailureMode, preparation::with_operation};
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    std::fs::create_dir(root.join("ci")).unwrap();
    // Missing native compiler inputs keep optional discovery unavailable.
    let pins = include_str!("../../../ci/toolchains.toml")
        .replace("nightly-2026-07-31", "nightly-2026-07-30");
    std::fs::write(root.join("ci/toolchains.toml"), pins).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let required_started = std::cell::Cell::new(false);
    with_operation(FailureMode::CollectAll, deadline, || {
        miri_cache::context(root)?;
        with_operation(FailureMode::CollectAll, deadline, || {
            required_started.set(true);
            Ok(())
        })
    })
    .unwrap();
    assert!(required_started.get());
    std::fs::write(root.join("ci/toolchains.toml"), "miri = 5\n").unwrap();
    assert!(
        miri_cache::identity(root).is_err(),
        "invalid inputs remain errors"
    );
}

#[test]
fn generated_sysroot_is_a_standard_child_setting() {
    let spec = CommandSpec::new("rustup", Path::new("."), Duration::from_secs(1))
        .miri_sysroot(Path::new("owned-sysroot"));
    let mut child = std::process::Command::new("rustup");
    spec.apply_environment(&mut child);
    assert!(child.get_envs().any(|(name, value)| name == "MIRI_SYSROOT"
        && value == Some(std::ffi::OsStr::new("owned-sysroot"))));
}

#[test]
fn managed_sysroot_has_no_host_or_nightly_rollout_gate() {
    let source = include_str!("../src/miri_cache.rs");
    assert!(!source.contains("VALIDATED_MIRI_SETUP"));
    assert!(!source.contains("native_setup_validated"));
    assert!(source.contains("MIRI_SYSROOT"));
    assert!(!miri_cache::ready_in_invocation());
}
