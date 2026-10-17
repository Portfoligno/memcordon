use memcordon_ci::{command::CommandSpec, miri_cache};
use std::{path::Path, time::Duration};

#[test]
fn absent_managed_identity_keeps_required_native_work_admitted() {
    use memcordon_ci::{failure_mode::FailureMode, preparation::with_operation};
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    std::fs::create_dir(root.join("ci")).unwrap();
    // No host has native cache acceptance for this fixture pin. Identity must
    // stop before native queries or Miri setup, independently of ambient env.
    let pins = include_str!("../../../ci/toolchains.toml")
        .replace("nightly-2026-07-31", "nightly-2026-07-30");
    std::fs::write(root.join("ci/toolchains.toml"), pins).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let required_started = std::cell::Cell::new(false);
    with_operation(FailureMode::CollectAll, deadline, || {
        let identity = with_operation(FailureMode::CollectAll, deadline, || {
            miri_cache::identity(root)
        })?;
        assert!(identity.is_none());
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
fn unrun_native_setup_acceptance_cannot_be_replaced_by_cached_readiness() {
    assert!(miri_cache::native_setup_validated(
        "aarch64-apple-darwin",
        "nightly-2026-07-31"
    ));
    for target in ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"] {
        assert!(!miri_cache::native_setup_validated(
            target,
            "nightly-2026-07-31"
        ));
    }
    for target in [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
    ] {
        assert!(!miri_cache::native_setup_validated(
            target,
            "unvalidated-nightly"
        ));
    }
}
