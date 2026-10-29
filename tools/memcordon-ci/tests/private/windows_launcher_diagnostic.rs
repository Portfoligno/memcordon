use super::*;
use crate::ci_operation_time::ClockReading;
use crate::readiness_identity::SourceIdentity;
use crate::windows_owned_guardian::{
    LauncherServiceQueryError, LauncherServiceQueryStage, LauncherServiceStatus,
};
use memcordon_core::{
    PublicProviderBindingV1, WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_BYTES,
    WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_MAX_AGE_MILLIS, WindowsLauncherStartupDiagnosticV1,
    WindowsLauncherStartupReasonV1, WindowsLauncherStartupStageV1, WindowsProcessIdentityV1,
};

fn binding() -> Binding {
    let commit = "ab".repeat(20);
    Binding {
        owner_sha256: "cd".repeat(32),
        identity: SourceIdentity {
            run_id: "39146715998".into(),
            source_commit: commit.clone(),
            source_tree_sha256: "ef".repeat(32),
            version: "0.5.8-dev".into(),
        },
        job: "native-windows-arm64".into(),
        run_attempt: 1,
        provider: serde_json::from_value(serde_json::json!({
            "generation":format!("0.5.8-dev:{commit}"),
            "source_commit":commit,
            "runtime_manifest_sha256":"12".repeat(32),
        }))
        .unwrap(),
        work_unix_millis: 2_000_000,
        cleanup_unix_millis: 3_000_000,
        clock_domain: "windows-gettickcount64:42".into(),
        minimum_tick: 1_000,
    }
}

fn clock(millis: u64) -> ClockReading {
    ClockReading {
        domain: "windows-gettickcount64:42".into(),
        millis,
    }
}

fn reported_service(state: u32) -> LauncherServiceStatus {
    LauncherServiceStatus {
        service_type: 16,
        current_state: state,
        controls_accepted: 1,
        win32_exit_code: 1067,
        service_specific_exit_code: 0,
        checkpoint: 3,
        wait_hint: 1_000,
        process_id: 410,
        service_flags: 0,
    }
}

#[test]
fn launcher_scm_snapshot_retains_reported_fields_without_process_or_listener_authority() {
    let selected = binding();
    let epoch = Epoch::acquire(selected.clone(), clock(1_000)).unwrap();
    for state in 1..=7 {
        let status = reported_service(state);
        let snapshot = launcher_service_snapshot(
            &epoch,
            &selected,
            &clock(1_100),
            &clock(1_101),
            Ok(status.clone()),
        )
        .unwrap();
        assert_eq!(
            snapshot["query_result"]["Ok"],
            serde_json::to_value(status).unwrap()
        );
        assert_eq!(snapshot["owner_sha256"], selected.owner_sha256);
        assert_eq!(
            snapshot["pid_field_defined_for_reported_state"],
            matches!(state, 4..=7)
        );
        assert_eq!(
            snapshot["reported_state_source"],
            "most-recently-reported-to-scm-may-lag"
        );
        assert_eq!(snapshot["process_join"], "unavailable");
        assert_eq!(snapshot["listener_join"], "unavailable");
        assert_eq!(snapshot["diagnostic_only"], true);
        assert_eq!(snapshot["certification_authority"], false);
    }
}

#[test]
fn launcher_scm_query_failures_remain_failures_without_invented_status() {
    let selected = binding();
    let epoch = Epoch::acquire(selected.clone(), clock(1_000)).unwrap();
    for stage in [
        LauncherServiceQueryStage::ScmOpen,
        LauncherServiceQueryStage::ServiceOpen,
        LauncherServiceQueryStage::StatusQuery,
    ] {
        for win32_error in [None, Some(5)] {
            let failure = LauncherServiceQueryError { stage, win32_error };
            let snapshot = launcher_service_snapshot(
                &epoch,
                &selected,
                &clock(1_100),
                &clock(1_101),
                Err(failure.clone()),
            )
            .unwrap();
            assert_eq!(
                snapshot["query_result"]["Err"],
                serde_json::to_value(failure).unwrap()
            );
            assert!(snapshot["query_result"].get("Ok").is_none());
            assert!(snapshot["pid_field_defined_for_reported_state"].is_null());
            assert_eq!(snapshot["process_join"], "unavailable");
            assert_eq!(snapshot["listener_join"], "unavailable");
        }
    }
}

#[test]
fn launcher_scm_snapshot_rejects_foreign_owner_and_clock_reassociation() {
    let selected = binding();
    let epoch = Epoch::acquire(selected.clone(), clock(1_000)).unwrap();
    let mut foreign = Vec::new();
    let mut changed = selected.clone();
    changed.owner_sha256 = "98".repeat(32);
    foreign.push(changed);
    let mut changed = selected.clone();
    changed.identity.source_commit = "76".repeat(20);
    foreign.push(changed);
    let mut changed = selected.clone();
    changed.job.push_str("-foreign");
    foreign.push(changed);
    let mut changed = selected.clone();
    changed.run_attempt += 1;
    foreign.push(changed);
    let mut changed = selected.clone();
    changed.cleanup_unix_millis += 1;
    foreign.push(changed);
    for changed in foreign {
        assert!(
            launcher_service_snapshot(
                &epoch,
                &changed,
                &clock(1_100),
                &clock(1_101),
                Ok(reported_service(4))
            )
            .is_err()
        );
    }
    for (before, after) in [
        (clock(999), clock(1_100)),
        (clock(1_101), clock(1_100)),
        (
            ClockReading {
                domain: "windows-gettickcount64:43".into(),
                millis: 1_100,
            },
            clock(1_101),
        ),
        (
            clock(1_100),
            ClockReading {
                domain: "windows-gettickcount64:43".into(),
                millis: 1_101,
            },
        ),
    ] {
        assert!(
            launcher_service_snapshot(&epoch, &selected, &before, &after, Ok(reported_service(4)))
                .is_err()
        );
    }
}

fn record(provider: PublicProviderBindingV1, tick: u64) -> WindowsLauncherStartupDiagnosticV1 {
    WindowsLauncherStartupDiagnosticV1 {
        schema_version: 1,
        provider,
        startup_process: WindowsProcessIdentityV1 {
            process_id: 410,
            creation_time_100ns: 810,
        },
        boot_identity: "42".into(),
        recorded_tick_millis: tick,
        service_exit: 0x4d43_0202,
        stage: WindowsLauncherStartupStageV1::OwnedAdmission,
        reason: WindowsLauncherStartupReasonV1::UnjoinedAdmission,
        native_code: None,
    }
}

#[test]
fn original_owner_without_diagnostic_clock_keeps_exact_serialization_and_hash() {
    let (directory, _, config, _) = crate::release::installed_loader_support::tests::fixture();
    let mut selected = binding();
    selected.identity.source_commit = config.source_commit.clone();
    selected.identity.version = config.version.clone();
    let owner = WindowsOriginalOwner {
        format: "memcordon.consumer-readiness.windows-original-owner".into(),
        revision: 1,
        identity: selected.identity,
        job: selected.job,
        run_attempt: selected.run_attempt,
        config,
        removal: crate::windows_readiness_adapter::WindowsRemovalPlan {
            binary_root: directory.path().join("installed"),
            state_root: directory.path().join("state"),
            diagnostics_root: directory.path().join("diagnostics"),
        },
        original_work_unix_millis: selected.work_unix_millis,
        original_cleanup_unix_millis: selected.cleanup_unix_millis,
        diagnostic_clock: None,
    };
    let original_bytes = serde_json::to_vec(&owner).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();
    assert!(value.get("diagnostic_clock").is_none());
    let original_hash = crate::release::artifacts::checksum(&original_bytes);
    let mut decoded: WindowsOriginalOwner = serde_json::from_slice(&original_bytes).unwrap();
    assert!(decoded.diagnostic_clock.is_none());
    assert!(launcher_diagnostic_binding(&decoded).is_err());
    let roundtrip = serde_json::to_vec(&decoded).unwrap();
    assert_eq!(roundtrip, original_bytes);
    assert_eq!(
        crate::release::artifacts::checksum(&roundtrip),
        original_hash
    );

    decoded.diagnostic_clock = Some(WindowsDiagnosticClock {
        domain: "windows-gettickcount64:42".into(),
        millis: 1_000,
    });
    let bound_bytes = serde_json::to_vec(&decoded).unwrap();
    assert_ne!(
        crate::release::artifacts::checksum(&bound_bytes),
        original_hash
    );
    let bound: WindowsOriginalOwner = serde_json::from_slice(&bound_bytes).unwrap();
    let joined = launcher_diagnostic_binding(&bound).unwrap();
    assert_eq!(
        joined.owner_sha256,
        crate::release::artifacts::checksum(&bound_bytes)
    );
    assert_eq!(joined.clock_domain, "windows-gettickcount64:42");
    assert_eq!(joined.minimum_tick, 1_000);
    let retained_clock = bound.diagnostic_clock.unwrap();
    assert_eq!(retained_clock.domain, "windows-gettickcount64:42");
    assert_eq!(retained_clock.millis, 1_000);
}

#[test]
fn original_launcher_record_is_only_uncorroborated_episode_evidence() {
    let expected = binding();
    let epoch = Epoch::acquire(expected.clone(), clock(1_000)).unwrap();
    let original = record(expected.provider.clone(), 1_500);
    let bytes = original.to_bounded_json().unwrap();
    let Observation::Uncorroborated(observed) =
        classify(&epoch, &expected, &clock(2_000), &bytes).unwrap()
    else {
        panic!("bound startup record must remain available only as uncorroborated evidence")
    };
    assert_eq!(observed, original);
    assert_eq!(epoch.binding.work_unix_millis, expected.work_unix_millis);
    assert_eq!(
        epoch.binding.cleanup_unix_millis,
        expected.cleanup_unix_millis
    );
    assert_eq!(epoch.minimum_tick, 1_000);
    // Same process birth and service exit here are record content, not an
    // independently observed SCM/process join or successful recovery authority.
    let boundary = clock(1_500 + WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_MAX_AGE_MILLIS);
    assert!(matches!(
        classify(&epoch, &expected, &boundary, &bytes).unwrap(),
        Observation::Uncorroborated(_)
    ));
}

#[test]
fn original_launcher_epoch_rejects_foreign_owner_source_job_cutoffs_and_clock() {
    let expected = binding();
    let epoch = Epoch::acquire(expected.clone(), clock(1_000)).unwrap();
    let bytes = record(expected.provider.clone(), 1_500)
        .to_bounded_json()
        .unwrap();
    for mutation in [
        "owner",
        "run",
        "commit",
        "tree",
        "version",
        "job",
        "attempt",
        "provider",
        "work",
        "cleanup",
        "clock-domain",
        "clock-tick",
    ] {
        let mut foreign = expected.clone();
        match mutation {
            "owner" => foreign.owner_sha256 = "23".repeat(32),
            "run" => foreign.identity.run_id = "39146715999".into(),
            "commit" => foreign.identity.source_commit = "34".repeat(20),
            "tree" => foreign.identity.source_tree_sha256 = "45".repeat(32),
            "version" => foreign.identity.version = "0.5.9-dev".into(),
            "job" => foreign.job = "native-windows-x64".into(),
            "attempt" => foreign.run_attempt += 1,
            "provider" => foreign.provider = binding_with_foreign_provider(),
            "work" => foreign.work_unix_millis += 1,
            "cleanup" => foreign.cleanup_unix_millis += 1,
            "clock-domain" => foreign.clock_domain = "windows-gettickcount64:43".into(),
            "clock-tick" => foreign.minimum_tick += 1,
            _ => unreachable!(),
        }
        assert!(
            classify(&epoch, &foreign, &clock(2_000), &bytes).is_err(),
            "accepted foreign {mutation}"
        );
    }
    for mutation in [
        "format",
        "revision",
        "domain",
        "lowered-epoch",
        "advanced-epoch",
        "future-epoch",
    ] {
        let mut changed = epoch.clone();
        match mutation {
            "format" => changed.format = "foreign".into(),
            "revision" => changed.revision += 1,
            "domain" => changed.clock_domain = "windows-gettickcount64:43".into(),
            "lowered-epoch" => changed.minimum_tick = 999,
            "advanced-epoch" => changed.minimum_tick = 1_001,
            "future-epoch" => changed.minimum_tick = 2_001,
            _ => unreachable!(),
        }
        assert!(
            classify(&changed, &expected, &clock(2_000), &bytes).is_err(),
            "accepted epoch {mutation}"
        );
    }
    assert!(classify(&epoch, &expected, &clock(999), &bytes).is_err());
    let foreign_boot = ClockReading {
        domain: "windows-gettickcount64:43".into(),
        millis: 2_000,
    };
    assert!(classify(&epoch, &expected, &foreign_boot, &bytes).is_err());
    assert!(Epoch::acquire(expected.clone(), clock(1_001)).is_err());
    let mut invalid = expected.clone();
    invalid.run_attempt = 0;
    assert!(Epoch::acquire(invalid, clock(1_000)).is_err());
    let mut oversized = expected.clone();
    oversized.job = "x".repeat(EPOCH_BYTES + 1);
    assert!(Epoch::acquire(oversized, clock(1_000)).is_err());
    assert!(
        Epoch::acquire(
            expected,
            ClockReading {
                domain: "linux-clock-boottime:42".into(),
                millis: 1_000
            }
        )
        .is_err()
    );
}

fn binding_with_foreign_provider() -> PublicProviderBindingV1 {
    let commit = "56".repeat(20);
    serde_json::from_value(serde_json::json!({
        "generation":format!("0.5.8-dev:{commit}"),
        "source_commit":commit,
        "runtime_manifest_sha256":"67".repeat(32),
    }))
    .unwrap()
}

#[test]
fn original_launcher_record_bounds_schema_provider_and_time_never_grant_authority() {
    let expected = binding();
    let epoch = Epoch::acquire(expected.clone(), clock(1_000)).unwrap();
    let valid = record(expected.provider.clone(), 1_500);
    let bytes = valid.to_bounded_json().unwrap();
    for mutation in [
        "provider",
        "boot",
        "before-episode",
        "future",
        "schema",
        "process",
        "stage-exit",
        "unknown-field",
        "duplicate-field",
        "malformed",
        "oversize",
    ] {
        let mut value = serde_json::to_value(&valid).unwrap();
        match mutation {
            "provider" => {
                value["provider"] = serde_json::to_value(binding_with_foreign_provider()).unwrap()
            }
            "boot" => value["boot_identity"] = "43".into(),
            "before-episode" => value["recorded_tick_millis"] = 999.into(),
            "future" => value["recorded_tick_millis"] = 2_001.into(),
            "schema" => value["schema_version"] = 2.into(),
            "process" => value["startup_process"]["process_id"] = 0.into(),
            "stage-exit" => value["service_exit"] = 1.into(),
            "unknown-field" => value["authority"] = true.into(),
            _ => (),
        }
        let mutated = match mutation {
            "duplicate-field" => {
                let json = String::from_utf8(bytes.clone()).unwrap();
                format!("{{\"schema_version\":1,{}", &json[1..]).into_bytes()
            }
            "malformed" => b"not a startup record".to_vec(),
            "oversize" => vec![b' '; WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_BYTES + 1],
            _ => serde_json::to_vec(&value).unwrap(),
        };
        let observed = classify(&epoch, &expected, &clock(2_000), &mutated).unwrap();
        assert!(
            matches!(observed, Observation::Unavailable(_)),
            "accepted {mutation}"
        );
    }
    let stale = clock(1_500 + WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_MAX_AGE_MILLIS + 1);
    assert!(matches!(
        classify(&epoch, &expected, &stale, &bytes).unwrap(),
        Observation::Unavailable(_)
    ));
}
