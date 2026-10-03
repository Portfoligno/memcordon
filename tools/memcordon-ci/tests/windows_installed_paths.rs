use std::{path::Path, path::PathBuf, time::Duration};

use memcordon_ci::{
    command::CommandSpec, config, windows_installed_cases::installed_public_command,
};

#[test]
fn installed_public_paths_reach_selected_fixture_and_intended_report_under_changed_cwd() {
    let current = std::env::current_dir().unwrap();
    let owner = if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        // Relative paths require a shared volume; the Windows system temp may
        // be on a different drive from the driver cwd.
        tempfile::tempdir_in(&current).unwrap()
    };
    let payload = owner.path().join("selected payload");
    let reports = owner.path().join("cases/windows-installed");
    std::fs::create_dir(&payload).unwrap();
    std::fs::create_dir_all(&reports).unwrap();
    let fixture = owner.path().join("selected fixture input");
    let bytes = b"selected installed fixture bytes\xff";
    std::fs::write(&fixture, bytes).unwrap();
    let executable = payload.join(if cfg!(windows) { "cli.exe" } else { "cli" });
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let compiler = CommandSpec::toolchain_program(
        "rustup",
        owner.path(),
        &config::toolchains(root).unwrap().stable,
        "rustc",
        Duration::from_secs(30),
    )
    .arg(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/installed_windows_path_child.rs"),
    )
    .args(["--edition", "2024", "-o"])
    .arg(&executable)
    .output_quiet()
    .unwrap();
    assert!(compiler.status.success(), "{compiler:?}");

    // Preserve this multithreaded test's cwd while supplying driver-relative paths.
    let common = current
        .ancestors()
        .find(|ancestor| owner.path().starts_with(ancestor))
        .unwrap();
    let mut relative = PathBuf::new();
    for _ in current.strip_prefix(common).unwrap().components() {
        relative.push("..");
    }
    relative.push(owner.path().strip_prefix(common).unwrap());
    let directory = relative.join("cases/windows-installed");
    let program = relative
        .join("selected payload")
        .join(executable.file_name().unwrap());
    let spec = installed_public_command(
        &program,
        &relative.join("selected fixture input"),
        &directory,
        &directory.join("smoke-before.json"),
        "exit",
    )
    .unwrap()
    .args(["--code", "0"]);
    let mut command = spec.materialize().unwrap();
    assert!(Path::new(command.get_program()).is_absolute());
    assert!(command.get_current_dir().unwrap().is_absolute());
    assert_ne!(current, command.get_current_dir().unwrap());
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(5),
        16 * 1024,
    )
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read(reports.join("smoke-before.json")).unwrap(),
        bytes
    );
    assert!(
        !reports
            .join("cases/windows-installed/smoke-before.json")
            .exists()
    );
    assert!(!payload.join("smoke-before.json").exists());
}
