#[path = "../src/bin/memcordon-sealed-agent/windows/service_startup_render.rs"]
mod render;

#[test]
fn only_launcher_dispatches_one_read_with_original_exit_and_pre_start_tick() {
    for name in [
        memcordon_core::WINDOWS_CONTROL_SERVICE_NAME,
        "other-service",
    ] {
        let suffix = render::launcher_failure_suffix(name, 0x4d43_0202, Some(123), |_, _| {
            panic!("another role must not invoke the launcher reader")
        });
        assert!(suffix.is_empty());
    }
    let mut calls = Vec::new();
    let suffix = render::launcher_failure_suffix(
        memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME,
        0x4d43_0202,
        Some(123),
        |exit, minimum| {
            calls.push((exit, minimum));
            Ok(Some(
                "stage=record-authentication reason=invalid-record".into(),
            ))
        },
    );
    assert_eq!(calls, [(0x4d43_0202, 123)]);
    assert!(suffix.contains("diagnostic_status=available"));
    assert!(suffix.contains("stage=record-authentication reason=invalid-record"));
    assert_eq!(
        render::launcher_startup_stage(0x4d43_0202),
        Some("state-recovery")
    );
    assert_eq!(render::launcher_startup_stage(1066), None);
}

#[test]
fn absent_rejected_and_missing_freshness_remain_distinct_from_available() {
    for minimum in [None, Some(0)] {
        let suffix = render::launcher_failure_suffix(
            memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME,
            0x4d43_0202,
            minimum,
            |_, _| panic!("missing freshness must never permit an unbounded read"),
        );
        assert!(suffix.contains("diagnostic_status=freshness-unavailable"));
    }
    let absent = render::launcher_failure_suffix(
        memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME,
        0x4d43_0202,
        Some(123),
        |_, _| Ok(None),
    );
    assert!(absent.contains("diagnostic_status=absent"));
    let rejected = render::launcher_failure_suffix(
        memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME,
        0x4d43_0202,
        Some(123),
        |_, _| Err("provider/boot/exit/freshness binding rejected".into()),
    );
    assert!(rejected.contains("diagnostic_status=rejected-or-read-error"));
    assert!(rejected.contains("provider/boot/exit/freshness binding rejected"));
}

#[test]
fn supplementary_detail_is_bounded_escaped_and_never_replaces_primary_scm_failure() {
    let primary = "role=windows-service operation=state-convergence service=MemCordonSealedLauncher expected_state=4 last_state=1 win32_exit=1066 service_exit=1296237058";
    for diagnostic in [
        Ok(Some(
            "head\n\t".to_owned() + &"界".repeat(5000) + "terminal-reason",
        )),
        Err("read-error\n\t".to_owned() + &"x".repeat(10000) + "last-reason"),
    ] {
        let suffix = render::launcher_failure_suffix(
            memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME,
            0x4d43_0202,
            Some(123),
            |_, _| diagnostic,
        );
        let error = format!("{primary}{suffix}");
        assert!(error.starts_with(primary));
        assert!(error.contains("diagnostic omitted"));
        assert!(error.contains("terminal-reason") || error.contains("last-reason"));
        assert!(error.contains("\\n") && error.contains("\\t"));
        assert!(!error.contains('\n') && !error.contains('\t'));
        assert!(error.len() < 4600);
    }
}
