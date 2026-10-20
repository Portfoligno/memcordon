use std::time::Duration;

use memcordon_ci::{
    failure_mode::FailureMode,
    native_test_plan::{
        NativePlatform, build_allocation, commands, commands_for_platform, commands_with_failure,
    },
    performance_plan::Layout,
};

#[test]
fn broader_native_compilation_receives_remaining_bounded_workers() {
    for (available, layout, native_jobs) in [
        (0, Layout::Serial, 1),
        (1, Layout::Serial, 1),
        (2, Layout::Parallel, 1),
        (3, Layout::Parallel, 2),
        (4, Layout::Parallel, 3),
        (8, Layout::Parallel, 3),
        (usize::MAX, Layout::Parallel, 3),
    ] {
        let allocation = build_allocation(available);
        assert_eq!(allocation.layout, layout);
        assert_eq!(allocation.product_jobs, 1);
        assert_eq!(allocation.native_jobs, native_jobs);
        if allocation.layout == Layout::Parallel {
            assert!(allocation.product_jobs + allocation.native_jobs <= available.min(4));
        }
    }
}

#[test]
fn native_build_and_execution_have_independent_deadlines_and_matching_targets() {
    let release = commands(true);
    assert_eq!(release.len(), 2);
    assert_eq!(
        release[0].deadline,
        Duration::from_secs(if cfg!(windows) {
            60 * 60
        } else if cfg!(target_os = "macos") {
            40 * 60
        } else {
            25 * 60
        })
    );
    let execution_deadline = Duration::from_secs(
        if cfg!(any(windows, target_os = "macos")) {
            30
        } else {
            15
        } * 60,
    );
    assert_eq!(release[1].deadline, execution_deadline);
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
    assert!(!release[1].arguments.contains(&"--no-fail-fast"));
    assert!(release[1].arguments.contains(&"--release"));
    assert!(release[1].arguments.contains(&"--workspace"));
    assert!(release[1].arguments.contains(&"--all-targets"));
    assert!(release[1].arguments.contains(&"--all-features"));
    assert!(release[1].arguments.contains(&"--locked"));

    let ordinary = commands(false);
    assert_eq!(ordinary.len(), 2);
    assert_eq!(ordinary[0].deadline, Duration::from_secs(25 * 60));
    assert_eq!(ordinary[1].deadline, execution_deadline);
    assert_eq!(ordinary[0].arguments.last(), Some(&"--no-run"));
    assert!(!ordinary[0].arguments.contains(&"--no-fail-fast"));
    assert!(!ordinary[0].arguments.contains(&"--release"));
    assert!(!ordinary[1].arguments.contains(&"--release"));
    assert!(!ordinary[1].arguments.contains(&"--no-fail-fast"));
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
            0
        );
        assert!(!command.arguments.contains(&"--ignored"));
        assert!(!command.arguments.contains(&"--exclude"));
    }
}

#[test]
fn explicit_collect_all_only_changes_cargo_execution_policy() {
    for release in [false, true] {
        let stop = commands(release);
        let collect = commands_with_failure(release, FailureMode::CollectAll);
        assert_eq!(stop[0], collect[0]);
        let mut expected = stop[1].arguments.clone();
        expected.push("--no-fail-fast");
        assert_eq!(collect[1].arguments, expected);
        assert_eq!(stop[1].deadline, collect[1].deadline);
    }
}

#[test]
fn cold_platform_build_allowances_preserve_the_complete_execution_graph() {
    for (platform, release_minutes) in [
        (NativePlatform::Windows, 60),
        (NativePlatform::MacOs, 40),
        (NativePlatform::Other, 25),
    ] {
        for release in [false, true] {
            for mode in [FailureMode::StopAfterFailure, FailureMode::CollectAll] {
                let plan = commands_for_platform(release, mode, platform);
                assert_eq!(
                    plan[0].deadline,
                    Duration::from_secs(if release { release_minutes } else { 25 } * 60)
                );
                let execution_minutes = if platform != NativePlatform::Other {
                    30
                } else {
                    15
                };
                assert_eq!(
                    plan[1].deadline,
                    Duration::from_secs(execution_minutes * 60)
                );
                let build_inputs: Vec<_> = plan[0]
                    .arguments
                    .iter()
                    .copied()
                    .filter(|arg| *arg != "--no-run")
                    .collect();
                let execution_inputs: Vec<_> = plan[1]
                    .arguments
                    .iter()
                    .copied()
                    .filter(|arg| *arg != "--no-fail-fast")
                    .collect();
                assert_eq!(build_inputs, execution_inputs);
                for required in ["--workspace", "--all-targets", "--all-features", "--locked"] {
                    assert!(plan[0].arguments.contains(&required));
                }
                assert!(!plan[0].arguments.contains(&"--exclude"));
                assert!(!plan[1].arguments.contains(&"--ignored"));
            }
        }
    }
}

#[test]
fn platform_execution_headroom_is_finite_and_preserves_every_phase_input() {
    for release in [false, true] {
        for mode in [FailureMode::StopAfterFailure, FailureMode::CollectAll] {
            let windows = commands_for_platform(release, mode, NativePlatform::Windows);
            for platform in [NativePlatform::MacOs, NativePlatform::Other] {
                let other = commands_for_platform(release, mode, platform);
                assert_eq!(windows.len(), 2);
                assert_eq!(windows[0].arguments, other[0].arguments);
                assert_eq!(windows[1].arguments, other[1].arguments);
                // Explicit headroom above progressing 900s Windows and Mac
                // runs, not a claim of measured complete-suite runtime.
                assert_eq!(
                    windows[1].deadline,
                    other[1].deadline
                        * if platform == NativePlatform::Other {
                            2
                        } else {
                            1
                        }
                );
                let total = other[0].deadline.checked_add(other[1].deadline).unwrap();
                let total_minutes = match (platform, release) {
                    (NativePlatform::MacOs, true) => 70,
                    (NativePlatform::MacOs, false) => 55,
                    (NativePlatform::Other, _) => 40,
                    _ => unreachable!(),
                };
                assert_eq!(total, Duration::from_secs(total_minutes * 60));
            }
            assert_eq!(windows[1].deadline, Duration::from_secs(30 * 60));
            let total = windows[0]
                .deadline
                .checked_add(windows[1].deadline)
                .unwrap();
            assert_eq!(
                total,
                Duration::from_secs(if release { 90 } else { 55 } * 60)
            );
            assert!(windows[1].deadline < total);
            assert_eq!(
                windows[0]
                    .arguments
                    .iter()
                    .filter(|arg| **arg == "--no-run")
                    .count(),
                1
            );
            assert!(!windows[1].arguments.contains(&"--no-run"));
            for forbidden in ["--ignored", "--exclude", "--skip"] {
                assert!(!windows[0].arguments.contains(&forbidden));
                assert!(!windows[1].arguments.contains(&forbidden));
            }
        }
    }
}
