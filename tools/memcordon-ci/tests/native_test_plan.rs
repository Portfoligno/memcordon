use std::time::Duration;

use memcordon_ci::native_test_plan::commands;

#[test]
fn native_build_and_execution_have_independent_deadlines_and_matching_targets() {
    let release = commands(true);
    assert_eq!(release.len(), 2);
    assert_eq!(
        release[0].deadline,
        Duration::from_secs(if cfg!(windows) { 40 * 60 } else { 25 * 60 })
    );
    assert_eq!(release[1].deadline, Duration::from_secs(15 * 60));
    assert_eq!(release[0].arguments.last(), Some(&"--no-run"));
    let build_inputs: Vec<_> = release[0]
        .arguments
        .iter()
        .copied()
        .filter(|arg| *arg != "--no-run")
        .collect();
    let execution_inputs: Vec<_> = release[1]
        .arguments
        .iter()
        .copied()
        .filter(|arg| *arg != "--no-fail-fast")
        .collect();
    assert_eq!(build_inputs, execution_inputs);
    assert!(!release[0].arguments.contains(&"--no-fail-fast"));
    assert_eq!(release[1].arguments.last(), Some(&"--no-fail-fast"));
    assert!(release[1].arguments.contains(&"--release"));
    assert!(release[1].arguments.contains(&"--workspace"));
    assert!(release[1].arguments.contains(&"--all-targets"));
    assert!(release[1].arguments.contains(&"--all-features"));
    assert!(release[1].arguments.contains(&"--locked"));

    let ordinary = commands(false);
    assert_eq!(ordinary.len(), 2);
    assert_eq!(ordinary[0].deadline, Duration::from_secs(25 * 60));
    assert_eq!(ordinary[1].deadline, Duration::from_secs(15 * 60));
    assert_eq!(ordinary[0].arguments.last(), Some(&"--no-run"));
    assert!(!ordinary[0].arguments.contains(&"--no-fail-fast"));
    assert!(!ordinary[0].arguments.contains(&"--release"));
    assert!(!ordinary[1].arguments.contains(&"--release"));
    assert_eq!(ordinary[1].arguments.last(), Some(&"--no-fail-fast"));
    let ordinary_build_inputs: Vec<_> = ordinary[0]
        .arguments
        .iter()
        .copied()
        .filter(|arg| *arg != "--no-run")
        .collect();
    let ordinary_execution_inputs: Vec<_> = ordinary[1]
        .arguments
        .iter()
        .copied()
        .filter(|arg| *arg != "--no-fail-fast")
        .collect();
    assert_eq!(ordinary_build_inputs, ordinary_execution_inputs);
    for command in [&ordinary[1], &release[1]] {
        assert_eq!(
            command
                .arguments
                .iter()
                .filter(|arg| **arg == "--no-fail-fast")
                .count(),
            1
        );
        assert!(!command.arguments.contains(&"--ignored"));
        assert!(!command.arguments.contains(&"--exclude"));
    }
}
