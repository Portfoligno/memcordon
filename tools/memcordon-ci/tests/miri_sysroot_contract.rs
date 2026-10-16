use memcordon_ci::{command::CommandSpec, miri_cache};
use std::{path::Path, time::Duration};

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
