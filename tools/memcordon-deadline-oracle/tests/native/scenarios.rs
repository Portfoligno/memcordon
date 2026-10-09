use super::super::*;

#[test]
fn fault_injection_is_not_preempted_by_an_unrelated_work_deadline() {
    let executable = Path::new("memcordon with spaces");
    let report = Path::new("execution.json");
    let marker = Path::new("target-identity.json");
    let budgets = [
        Some("+250ms"),
        Some("+3s"),
        Some("+0ms"),
        Some("+3s"),
        None,
        Some("+3s"),
    ];
    for (spec, budget) in SCENARIOS.iter().copied().zip(budgets) {
        let command = scenario_command(executable, spec, report, marker).unwrap();
        assert_eq!(command.get_program(), std::env::current_exe().unwrap());
        let mut expected = vec![
            OsString::from("--session-exec-confirmed"),
            executable.into(),
        ];
        expected.extend(budget.into_iter().map(OsString::from));
        expected.extend([OsString::from("--summary"), OsString::from("--report")]);
        expected.push(report.into());
        expected.push("--".into());
        expected.push(std::env::current_exe().unwrap().into_os_string());
        expected.extend([
            OsString::from("--fixture"),
            OsString::from(spec.fixture.argument()),
        ]);
        expected.push(marker.into());
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            expected,
            "{}",
            spec.name
        );
    }
}

#[test]
fn successful_teardown_never_promotes_failed_retirement() {
    let mut observation = Observation::new(SCENARIOS[0]);
    observation.teardown_complete = true;
    observation.scenario_exercised = true;
    observation.finish();
    assert!(!observation.pre_intervention_retirement_confirmed);
    assert!(!observation.independently_confirmed_cleanup);
    assert!(!observation.passed);
}

#[test]
fn native_marker_parent_evidence_rejects_another_real_session_identity() {
    let actual = ProcessObservation {
        identity: ProcessIdentity {
            pid: 42,
            birth_seconds: 1,
            birth_microseconds: 2,
        },
        state: 2,
        parent_pid: 41,
        process_group: 40,
        session_id: 40,
    };
    assert!(marker_observation_matches(actual, actual, 40));
    let forged_parent = ProcessObservation {
        parent_pid: 40,
        ..actual
    };
    assert!(
        !marker_observation_matches(forged_parent, actual, 40),
        "real frontend cannot masquerade as the target's guardian"
    );
    let reused = ProcessObservation {
        identity: ProcessIdentity {
            birth_microseconds: 3,
            ..actual.identity
        },
        ..actual
    };
    assert!(!marker_observation_matches(actual, reused, 40));
}

#[test]
fn stopped_checkpoint_follows_marker_and_budget_even_when_launch_is_delayed() {
    let spec = SCENARIOS
        .iter()
        .find(|spec| spec.name == "frontend-stopped")
        .copied()
        .unwrap();
    assert_eq!(
        stopped_checkpoint_after_marker(1_620_000_000, spec).unwrap(),
        5_120_000_000
    );
    assert!(stopped_checkpoint_after_marker(u64::MAX, spec).is_err());
}

#[test]
fn stopped_session_launcher_preserves_scope_until_native_confirmation() {
    let (mut owner, marker, directory) = super::cleanup::launch("children");
    let boundary = Instant::now() + Duration::from_secs(3);
    while Instant::now() < boundary {
        if NativeProcessApi
            .observation(owner.session_id)
            .unwrap()
            .is_some_and(|native| {
                native.session_id == owner.session_id && native.state == libc::SSTOP
            })
        {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        !marker.exists(),
        "fixture must not exec before native scope confirmation"
    );
    let native = NativeProcessApi
        .observation(owner.session_id)
        .unwrap()
        .unwrap();
    assert_eq!(native.session_id, owner.session_id);
    assert_eq!(native.state, libc::SSTOP);
    owner
        .confirm_session(clock().unwrap() + 1_000_000_000)
        .unwrap();
    assert!(owner.session_confirmed);
    assert!(owner.teardown().0);
    fs::remove_dir_all(directory).unwrap();
}
