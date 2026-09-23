use std::time::Duration;

use memcordon_ci::native_test_plan::commands;

#[test]
fn release_build_and_execution_have_independent_deadlines_and_matching_targets() {
    let release = commands(true);
    assert_eq!(release.len(), 2);
    assert_eq!(release[0].deadline, Duration::from_secs(25 * 60));
    assert_eq!(release[1].deadline, Duration::from_secs(15 * 60));
    assert_eq!(release[0].arguments.last(), Some(&"--no-run"));
    assert_eq!(
        &release[0].arguments[..release[0].arguments.len() - 1],
        release[1].arguments
    );
    assert!(release[1].arguments.contains(&"--release"));
    assert!(release[1].arguments.contains(&"--workspace"));
    assert!(release[1].arguments.contains(&"--all-targets"));
    assert!(release[1].arguments.contains(&"--all-features"));
    assert!(release[1].arguments.contains(&"--locked"));

    let ordinary = commands(false);
    assert_eq!(ordinary.len(), 1);
    assert_eq!(ordinary[0].deadline, Duration::from_secs(15 * 60));
    assert!(!ordinary[0].arguments.contains(&"--release"));
    assert!(!ordinary[0].arguments.contains(&"--no-run"));
}
