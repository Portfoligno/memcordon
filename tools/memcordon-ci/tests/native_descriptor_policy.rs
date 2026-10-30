use std::path::Path;

use memcordon_ci::policy::validate_rust_policy_bytes;

const PATH: &str = "tools/memcordon-ci/src/release/linux_current_phase_gate.rs";
const SOURCE: &str = include_str!("../src/release/linux_current_phase_gate.rs");

#[test]
fn retained_descriptor_boundary_accepts_only_the_reviewed_source_and_path() {
    validate_rust_policy_bytes(Path::new(PATH), SOURCE.as_bytes()).unwrap();
    let formatted = SOURCE.replace(
        "command.pre_exec(move || {",
        "command . pre_exec ( move || { /* non-operational comment */",
    );
    assert_ne!(formatted, SOURCE);
    validate_rust_policy_bytes(Path::new(PATH), formatted.as_bytes()).unwrap();
    for path in [
        "tools/memcordon-ci/src/release/other_phase_gate.rs",
        "crates/example/src/lib.rs",
    ] {
        assert!(validate_rust_policy_bytes(Path::new(path), SOURCE.as_bytes()).is_err());
    }
}

#[test]
fn retained_descriptor_boundary_rejects_changes_to_every_native_operation() {
    for (before, after) in [
        ("source: &File", "source: &OtherFile"),
        (
            "pub(crate) fn configure_extra_descriptor",
            "fn configure_extra_descriptor",
        ),
        (
            "pub(crate) fn configure_extra_descriptor",
            "#[cfg(any())] pub(crate) fn configure_extra_descriptor",
        ),
        (
            "fcntl_dupfd_cloexec(source, 129)",
            "fcntl_dupfd_cloexec(source, 130)",
        ),
        (
            "fcntl_dupfd_cloexec(source, 129)",
            "fcntl_dupfd_cloexec(other, 129)",
        ),
        (".map_err(std::io::Error::from)?", ".unwrap()"),
        ("pre_exec(move ||", "pre_exec(||"),
        ("libc::fcntl(128, libc::F_GETFD) >= 0", "false"),
        ("libc::F_GETFD", "libc::F_GETFL"),
        ("libc::EEXIST", "libc::EBADF"),
        (
            "error.raw_os_error() != Some(libc::EBADF)",
            "error.raw_os_error() == Some(libc::EBADF)",
        ),
        (
            "libc::dup2(held.as_raw_fd(), 128)",
            "libc::dup2(source.as_raw_fd(), 128)",
        ),
        (
            "libc::dup2(held.as_raw_fd(), 128)",
            "libc::dup2(held.as_raw_fd(), 127)",
        ),
        ("return Err(error);", "return Ok(());"),
        (
            "command.pre_exec(move || {",
            "command.pre_exec(move || { arbitrary();",
        ),
        (
            "command.pre_exec(move || {",
            "command.pre_exec(move || { command.env(\"CUSTOM_CI\", \"value\");",
        ),
        (
            "command.pre_exec(move || {",
            "command.pre_exec(move || { std::process::Command::new(\"child\").spawn()?;",
        ),
        (
            "command.pre_exec(move || {",
            "command.pre_exec(move || { let held = arbitrary();",
        ),
    ] {
        let changed = SOURCE.replace(before, after);
        assert_ne!(changed, SOURCE, "missing mutation source: {before}");
        assert!(
            validate_rust_policy_bytes(Path::new(PATH), changed.as_bytes()).is_err(),
            "accepted {before} -> {after}"
        );
    }
}

#[test]
fn retained_descriptor_boundary_does_not_cover_an_additional_callback() {
    let changed = [
        SOURCE,
        "fn extra(command: &mut std::process::Command) { unsafe { command.pre_exec(|| Ok(())); } }",
    ]
    .join("\n");
    assert!(validate_rust_policy_bytes(Path::new(PATH), changed.as_bytes()).is_err());
}

#[test]
fn retained_descriptor_recognition_keeps_independent_file_checks() {
    for extra in [
        "fn extra(command: &mut std::process::Command) { command.env(\"CUSTOM_CI\", \"value\"); }",
        "fn extra() { unsafe { libc::fork(); } }",
        "fn extra() { std::process::Command::new(\"sh\").args([\"-c\", \"true\"]).spawn(); }",
    ] {
        let changed = [SOURCE, extra].join("\n");
        assert!(
            validate_rust_policy_bytes(Path::new(PATH), changed.as_bytes()).is_err(),
            "accepted additional forbidden operation: {extra}"
        );
    }
}
