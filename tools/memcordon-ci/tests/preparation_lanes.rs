use memcordon_ci::{
    CiError,
    command::CommandSpec,
    performance_plan::Layout,
    preparation::{complete_lanes, complete_lanes_with_failure, observed, remaining},
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[test]
fn nested_default_inherits_collect_all_and_original_deadline() {
    use memcordon_ci::{
        failure_mode::FailureMode,
        preparation::{active_group, with_operation},
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    let called = std::sync::atomic::AtomicBool::new(false);
    let result = with_operation(FailureMode::CollectAll, deadline, || {
        assert!(with_operation(FailureMode::StopAfterFailure, deadline, || Ok(())).is_err());
        assert!(
            complete_lanes_with_failure(
                Layout::Serial,
                FailureMode::StopAfterFailure,
                || Ok(()),
                || Ok(())
            )
            .is_err()
        );
        complete_lanes(
            Layout::Serial,
            || {
                let root = active_group().unwrap();
                assert_eq!(root.mode(), FailureMode::CollectAll);
                assert_eq!(root.deadline(), deadline);
                memcordon_ci::preparation::with_nested_operation(
                    deadline + Duration::from_secs(60),
                    || {
                        assert_eq!(active_group().unwrap().deadline(), deadline);
                        Err(CiError::Message("nested required failure".into()))
                    },
                )
            },
            || {
                called.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        )
    });
    assert!(result.is_err());
    assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    assert!(active_group().is_none());
}

#[test]
fn operation_restores_thread_local_owner_after_panic() {
    use memcordon_ci::{
        failure_mode::FailureMode,
        preparation::{active_group, with_operation},
    };
    let result: memcordon_ci::Result<()> = with_operation(
        FailureMode::CollectAll,
        Instant::now() + Duration::from_secs(20),
        || panic!("owner panic"),
    );
    assert!(result.is_err());
    assert!(active_group().is_none());
}

#[test]
fn nested_parallel_lanes_reuse_the_current_thread() {
    complete_lanes(
        Layout::Parallel,
        || {
            let owner = std::thread::current().id();
            complete_lanes(
                Layout::Parallel,
                || {
                    assert_eq!(std::thread::current().id(), owner);
                    Ok(())
                },
                || {
                    assert_eq!(std::thread::current().id(), owner);
                    Ok(())
                },
            )
        },
        || Ok(()),
    )
    .unwrap();
}

#[test]
fn nested_cargo_arguments_cannot_exceed_the_parent_lane_allocation() {
    complete_lanes(
        Layout::Parallel,
        || {
            let inherited = memcordon_ci::preparation::active_group()
                .unwrap()
                .compiler_jobs();
            complete_lanes(
                Layout::Parallel,
                || {
                    for jobs in [
                        vec!["--jobs", "99"],
                        vec!["--jobs=99"],
                        vec!["-j99"],
                        vec![],
                    ] {
                        let command = memcordon_ci::command::rustup_cargo(
                            std::path::Path::new("."),
                            "stable",
                            ["check"],
                            Duration::from_secs(20),
                        )
                        .args(jobs)
                        .materialize()?;
                        let arguments: Vec<_> = command.get_args().collect();
                        let position = arguments
                            .iter()
                            .position(|argument| *argument == "--jobs")
                            .unwrap();
                        assert_eq!(
                            arguments[position + 1],
                            std::ffi::OsStr::new(&inherited.to_string())
                        );
                    }
                    let fuzz = CommandSpec::toolchain_program(
                        "rustup",
                        std::path::Path::new("."),
                        "stable",
                        std::path::Path::new("cargo-fuzz"),
                        Duration::from_secs(20),
                    )
                    .args(["build", "target"])
                    .materialize()?;
                    let jobs = fuzz
                        .get_envs()
                        .find(|(key, _)| *key == "CARGO_BUILD_JOBS")
                        .unwrap()
                        .1
                        .unwrap();
                    assert_eq!(jobs, std::ffi::OsStr::new(&inherited.to_string()));
                    Ok(())
                },
                || Ok(()),
            )
        },
        || Ok(()),
    )
    .unwrap();
}

#[test]
fn later_collect_all_pair_selects_its_own_first_observed_failure() {
    use memcordon_ci::{
        failure_mode::FailureMode,
        preparation::{active_group, with_operation},
    };
    with_operation(
        FailureMode::CollectAll,
        Instant::now() + Duration::from_secs(20),
        || {
            assert!(
                complete_lanes(
                    Layout::Parallel,
                    || { Err(CiError::Message("earlier pair first lane".into())) },
                    || Ok(())
                )
                .is_err()
            );
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let error = complete_lanes(
                Layout::Parallel,
                move || {
                    receiver.recv_timeout(Duration::from_secs(5)).unwrap();
                    Err(CiError::Message("later pair slower first lane".into()))
                },
                || {
                    active_group().unwrap().request_after_failure();
                    sender.send(()).unwrap();
                    Err(CiError::Message(
                        "later pair first observed second lane".into(),
                    ))
                },
            )
            .unwrap_err();
            let CiError::LaneFailures { primary, .. } = error else {
                panic!("both required errors retained");
            };
            assert!(primary.to_string().contains("first observed second lane"));
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn stateful_phase_finishes_cleanup_then_withholds_the_next_command() {
    use memcordon_ci::command::PeerStopPolicy;
    let root = tempfile::tempdir().unwrap();
    let path = root.path();
    complete_lanes(
        Layout::Parallel,
        || {
            CommandSpec::new(
                std::env::current_exe().unwrap(),
                path,
                Duration::from_secs(20),
            )
            .args([
                "--ignored",
                "--exact",
                "stateful_phase_child",
                "--nocapture",
            ])
            .peer_stop_policy(PeerStopPolicy::FinishOwnedPhase)
            .run()?;
            assert!(path.join("phase-cleaned").exists());
            let error = CommandSpec::new(
                std::env::current_exe().unwrap(),
                path,
                Duration::from_secs(20),
            )
            .arg("--list")
            .run()
            .unwrap_err();
            assert!(matches!(error, CiError::NotStartedAfterFailure));
            Ok(())
        },
        || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !path.join("phase-ready").exists() {
                assert!(Instant::now() < deadline);
                std::thread::yield_now();
            }
            memcordon_ci::preparation::active_group()
                .unwrap()
                .request_after_failure();
            std::fs::write(path.join("phase-release"), b"release\n")?;
            Err(CiError::Message("peer required failure".into()))
        },
    )
    .unwrap_err();
    assert!(path.join("phase-cleaned").exists());
}

#[test]
#[ignore = "stateful native cleanup fixture"]
fn stateful_phase_child() {
    let path = std::env::current_dir().unwrap();
    std::fs::write(path.join("phase-ready"), b"ready\n").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.join("phase-release").exists() {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    std::fs::write(path.join("phase-cleaned"), b"cleaned\n").unwrap();
}

#[test]
fn collect_all_settles_both_owners_after_failure_or_panic() {
    for layout in [Layout::Serial, Layout::Parallel] {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let first = Arc::clone(&observed);
        let second = Arc::clone(&observed);
        let error = complete_lanes_with_failure(
            layout,
            memcordon_ci::failure_mode::FailureMode::CollectAll,
            move || {
                first.lock().unwrap().push("first");
                Err(CiError::Message("first failure".into()))
            },
            move || {
                second.lock().unwrap().push("second");
                Err(CiError::Message("second failure".into()))
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("first failure") && error.contains("second failure"));
        let mut completed = observed.lock().unwrap().clone();
        completed.sort();
        assert_eq!(completed, ["first", "second"]);
        let done = Arc::new(Mutex::new(false));
        let second = Arc::clone(&done);
        assert!(
            complete_lanes_with_failure(
                layout,
                memcordon_ci::failure_mode::FailureMode::CollectAll,
                || panic!("actual injected owner failure"),
                move || {
                    *second.lock().unwrap() = true;
                    Ok(())
                }
            )
            .is_err()
        );
        assert!(*done.lock().unwrap());
    }
}

#[test]
fn default_serial_failure_does_not_admit_second_lane() {
    let called = std::sync::atomic::AtomicBool::new(false);
    let error = complete_lanes(
        Layout::Serial,
        || Err(CiError::Message("first cause".into())),
        || {
            called.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("first cause"));
    assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn second_failure_remains_primary_after_admitted_first_owner_settles() {
    let (entered, admission) = std::sync::mpsc::sync_channel(1);
    let deadline = Instant::now() + Duration::from_secs(2);
    let settled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let first_settled = Arc::clone(&settled);
    let error = complete_lanes(
        Layout::Parallel,
        move || {
            let group = memcordon_ci::preparation::active_group().unwrap();
            entered.send(()).unwrap();
            while group.may_start() {
                assert!(
                    Instant::now() < deadline,
                    "admitted owner did not observe stop"
                );
                std::thread::yield_now();
            }
            first_settled.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        },
        move || {
            admission
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap();
            Err(CiError::Message("fast second failure".into()))
        },
    )
    .unwrap_err();
    // The sole real failure has an exact primary cause; collect-all above
    // separately retains both real errors without scheduler-order assumptions.
    assert!(matches!(error, CiError::Message(cause) if cause == "fast second failure"));
    assert!(settled.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn original_group_deadline_caps_each_command_without_renewal() {
    let end = Instant::now() + Duration::from_secs(2);
    assert!(remaining(end, Duration::from_secs(30)).unwrap() <= Duration::from_secs(2));
    assert!(remaining(Instant::now(), Duration::from_secs(30)).is_err());
}

#[test]
fn invalid_cache_version_probe_can_rebuild_without_stopping_the_group() {
    let root = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();
    complete_lanes(
        Layout::Serial,
        || {
            let output = CommandSpec::new(&executable, root.path(), Duration::from_secs(20))
                .args([
                    "--ignored",
                    "--exact",
                    "failing_operation_child",
                    "--nocapture",
                ])
                .defer_group_failure()
                .output_quiet()?;
            assert!(!output.status.success());
            CommandSpec::new(&executable, root.path(), Duration::from_secs(20))
                .arg("--list")
                .run()
                .map(|_| ())
        },
        || Ok(()),
    )
    .unwrap();
}

#[test]
fn auxiliary_setup_never_renews_an_expired_supply_deadline() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("ci")).unwrap();
    for (name, bytes) in [
        (
            "toolchains.toml",
            include_str!("../../../ci/toolchains.toml"),
        ),
        ("tools.toml", include_str!("../../../ci/tools.toml")),
        (
            "performance.toml",
            include_str!("../../../ci/performance.toml"),
        ),
    ] {
        std::fs::write(root.path().join("ci").join(name), bytes).unwrap();
    }
    let error = memcordon_ci::preparation::ensure_auxiliary_tool_until(
        root.path(),
        memcordon_ci::bootstrap_profile::BootstrapProfile::SupplyChain,
        "cargo-audit",
        "0.0.0",
        Instant::now(),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("original operation group deadline expired"),
        "{error}"
    );
}

#[test]
fn failed_operation_exposes_child_diagnostics_even_when_collection_fails() {
    #[cfg(unix)]
    let root = tempfile::Builder::new()
        .prefix("memcordon-operation-fixture-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let root = tempfile::Builder::new()
        .prefix("memcordon-operation-fixture-")
        .tempdir()
        .unwrap();
    let executable = std::env::current_exe().unwrap();
    for directory in [root.path().to_path_buf(), root.path().join("absent")] {
        let command = CommandSpec::new(&executable, root.path(), Duration::from_secs(20)).args([
            "--ignored",
            "--exact",
            "failing_operation_child",
            "--nocapture",
        ]);
        let error = observed(command, &directory, "diagnostic-fixture")
            .unwrap_err()
            .to_string();
        assert!(error.contains("operation diagnostic-fixture failed"));
        assert!(error.contains("captured stdout diagnostic"));
        assert!(error.contains("captured stderr diagnostic"));
        if directory == root.path() {
            let stdout =
                std::fs::read_to_string(directory.join("diagnostic-fixture.stdout.bin")).unwrap();
            let stderr =
                std::fs::read_to_string(directory.join("diagnostic-fixture.stderr.bin")).unwrap();
            assert!(stdout.contains("captured stdout diagnostic"));
            assert!(stderr.contains("captured stderr diagnostic"));
        } else {
            assert!(error.contains("stdout collection=Err"));
            assert!(error.contains("stderr collection=Err"));
        }
    }
}

#[test]
#[ignore = "explicit subprocess fixture for failure diagnostics"]
fn failing_operation_child() {
    println!("captured stdout diagnostic");
    eprintln!("captured stderr diagnostic");
    panic!("deliberate child failure");
}
