#[path = "../src/stress_package_plan.rs"]
mod stress_package_plan;

#[test]
fn compilation_and_execution_share_inputs_but_not_the_runtime_budget() {
    let target = std::path::Path::new("target/cache with spaces");
    let [(mut compile, build_budget), (execute, runtime_budget)] =
        stress_package_plan::package_phases("memcordon-ci", target);
    assert_eq!(compile.pop(), Some(std::ffi::OsString::from("--no-run")));
    assert_eq!(compile, execute);
    assert_eq!(execute[2], target.as_os_str());
    assert_eq!(execute[4], "memcordon-ci");
    assert_eq!(runtime_budget, std::time::Duration::from_secs(900));
    assert_eq!(build_budget, std::time::Duration::from_secs(35 * 60));
    assert!(execute.iter().any(|argument| argument == "--locked"));
    assert!(execute.iter().any(|argument| argument == "--release"));
    assert!(execute.iter().any(|argument| argument == "--all-targets"));
    assert!(execute.iter().any(|argument| argument == "--all-features"));
}

#[test]
fn original_listener_diagnostic_is_serial_release_only_for_the_windows_cli_package() {
    use std::{ffi::OsString, path::Path, time::Duration};
    let target = Path::new("target/shared release cache with spaces");
    let before = stress_package_plan::package_phases("memcordon", target);
    let (arguments, ceiling) =
        stress_package_plan::original_listener_diagnostic("memcordon", target, true).unwrap();
    assert_eq!(
        arguments,
        [
            "test",
            "--target-dir",
            target.to_str().unwrap(),
            "--package",
            "memcordon",
            "--test",
            "original_listener_result",
            "--all-features",
            "--locked",
            "--release",
            "--",
            "--test-threads=1",
            "--nocapture"
        ]
        .map(OsString::from)
    );
    assert_eq!(ceiling, before[1].1);
    assert_eq!(ceiling, Duration::from_secs(900));
    assert_eq!(
        stress_package_plan::package_phases("memcordon", target),
        before
    );
    for (package, windows) in [
        ("memcordon", false),
        ("memcordon-ci", true),
        ("memcordon-platform", true),
        ("memcordon-core", true),
        ("memcordon-extra", true),
    ] {
        assert!(
            stress_package_plan::original_listener_diagnostic(package, target, windows).is_none()
        );
    }
}
