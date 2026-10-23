use memcordon_ci::command::CommandSpec;
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
