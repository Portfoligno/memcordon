use super::*;

fn selected() -> BuildSourceIdentity {
    BuildSourceIdentity::Working {
        version: semver::Version::new(0, 1, 0),
        commit: "abcdef".into(),
    }
}

fn association() -> Association {
    Association {
        run: "run".into(),
        job: "native".into(),
        attempt: "1".into(),
        checkout: "/checkout".into(),
    }
}

fn record() -> NativeBudget {
    NativeBudget {
        revision: 1,
        source: selected(),
        target: "host".into(),
        association: association(),
        domain: "boot-one".into(),
        started: 1000,
        work_cutoff: 1000 + WORK_MILLIS,
        cleanup_cutoff: 1000 + CLEANUP_MILLIS,
        wall_started: 10_000,
    }
}

#[test]
fn cache_and_action_time_reduce_original_interval_and_wall_rollback_never_renews_it() {
    let record = record();
    let now = ClockReading {
        domain: "boot-one".into(),
        millis: 1000 + 70 * 60 * 1000,
    };
    let remaining = |wall| {
        record.remaining(
            &selected(),
            "host",
            &association(),
            &now,
            WallWindow {
                started: 10_000,
                cutoff: 10_000 + WORK_MILLIS,
                now: wall,
            },
            false,
        )
    };
    assert_eq!(
        remaining(10_000 + 70 * 60 * 1000).unwrap(),
        Duration::from_secs(70 * 60)
    );
    assert_eq!(remaining(9_000).unwrap(), Duration::from_secs(70 * 60));
    assert_eq!(
        remaining(10_000 + 100 * 60 * 1000).unwrap(),
        Duration::from_secs(40 * 60)
    );
    assert!(remaining(10_000 + WORK_MILLIS).is_err());
}

#[test]
fn resume_rejects_source_target_job_attempt_domain_regression_and_contradictory_cutoffs() {
    let now = ClockReading {
        domain: "boot-one".into(),
        millis: 1001,
    };
    let check = |record: &NativeBudget,
                 source: &BuildSourceIdentity,
                 target: &str,
                 job: &Association,
                 clock: &ClockReading| {
        record.remaining(
            source,
            target,
            job,
            clock,
            WallWindow {
                started: 10_000,
                cutoff: 10_000 + WORK_MILLIS,
                now: 10_001,
            },
            false,
        )
    };
    assert!(check(&record(), &selected(), "host", &association(), &now).is_ok());
    let mut changed = selected();
    if let BuildSourceIdentity::Working { commit, .. } = &mut changed {
        commit.push('0');
    }
    assert!(check(&record(), &changed, "host", &association(), &now).is_err());
    assert!(check(&record(), &selected(), "other", &association(), &now).is_err());
    for field in ["run", "job", "attempt", "checkout"] {
        let mut job = association();
        match field {
            "run" => job.run.push('2'),
            "job" => job.job.push('2'),
            "attempt" => job.attempt.push('2'),
            _ => job.checkout.push('2'),
        }
        assert!(check(&record(), &selected(), "host", &job, &now).is_err());
    }
    for clock in [
        ClockReading {
            domain: "boot-two".into(),
            millis: 1001,
        },
        ClockReading {
            domain: "boot-one".into(),
            millis: 999,
        },
    ] {
        assert!(check(&record(), &selected(), "host", &association(), &clock).is_err());
    }
    let mut invalid = record();
    invalid.cleanup_cutoff += 1;
    assert!(check(&invalid, &selected(), "host", &association(), &now).is_err());
    let expired = ClockReading {
        domain: "boot-one".into(),
        millis: 1000 + WORK_MILLIS,
    };
    assert!(check(&record(), &selected(), "host", &association(), &expired).is_err());
    assert_eq!(
        record()
            .remaining(
                &selected(),
                "host",
                &association(),
                &expired,
                WallWindow {
                    started: 10_000,
                    cutoff: 10_000 + CLEANUP_MILLIS,
                    now: 10_000 + WORK_MILLIS
                },
                true
            )
            .unwrap(),
        Duration::from_secs(15 * 60)
    );
}

#[test]
fn native_counter_and_real_file_handoff_resume_without_serializing_instant() {
    let before = clock_reading().unwrap();
    let after = clock_reading().unwrap();
    assert_eq!(before.domain, after.domain);
    assert!(after.millis >= before.millis);
    let root = tempfile::tempdir().unwrap();
    assert!(
        resume(
            root.path(),
            &selected(),
            "host",
            10_000,
            10_000 + WORK_MILLIS,
            10_001,
            false
        )
        .is_err()
    );
    begin(root.path(), &selected(), "host", 10_000).unwrap();
    let deadline = resume(
        root.path(),
        &selected(),
        "host",
        10_000,
        10_000 + WORK_MILLIS,
        10_001,
        false,
    )
    .unwrap();
    assert!(deadline > Instant::now());
    assert!(deadline <= Instant::now() + Duration::from_millis(WORK_MILLIS));
    assert!(begin(root.path(), &selected(), "host", 10_000).is_err());
    fs::remove_file(root.path().join(RECORD)).unwrap();
    assert!(
        resume(
            root.path(),
            &selected(),
            "host",
            10_000,
            10_000 + WORK_MILLIS,
            10_001,
            false
        )
        .is_err()
    );
    assert!(!root.path().join(RECORD).exists());
}

#[cfg(unix)]
#[test]
fn native_handoff_refuses_symlinked_parent_and_record() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("target")).unwrap();
    assert!(begin(root.path(), &selected(), "host", 10_000).is_err());
    assert!(!outside.path().join("ci-session").exists());
}
