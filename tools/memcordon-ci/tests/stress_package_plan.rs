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
