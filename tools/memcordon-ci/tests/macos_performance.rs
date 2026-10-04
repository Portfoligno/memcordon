use memcordon_ci::{
    macos_performance::{MacosPhaseReport, validate_phase},
    native_results::{NativeTestOutcome, NativeTestReport, NativeTestResult},
};

fn phase(phase: &str) -> MacosPhaseReport {
    let names = if phase == "native" {
        memcordon_ci::native_acceptance_catalogue::MACOS_LIFECYCLE_SCENARIOS
            .iter()
            .chain(memcordon_ci::native_acceptance_catalogue::MACOS_REMEDIATION_SCENARIOS)
            .copied()
            .collect::<Vec<_>>()
    } else {
        vec![
            "installed_package_execution_probe_and_deadline",
            "installed_package_typed_external_consumer",
        ]
    };
    MacosPhaseReport {
        format: "memcordon.macos-executed-phase".into(),
        revision: 1,
        host_os: "macos".into(),
        host_arch: "aarch64".into(),
        phase: phase.into(),
        native: NativeTestReport {
            schema_version: 1,
            backend: "macos-watchdog".into(),
            source_commit: "a".repeat(40),
            tests_run: names.len(),
            tests_skipped: 0,
            tests: names
                .into_iter()
                .map(|name| NativeTestResult {
                    name: name.into(),
                    result: NativeTestOutcome::Passed,
                })
                .collect(),
        },
    }
}

#[test]
fn exact_selected_phase_rejects_architecture_source_and_missing_coverage() {
    for kind in ["native", "acceptance"] {
        let report = phase(kind);
        let commit = "a".repeat(40);
        validate_phase(&report, &commit, "aarch64", kind).unwrap();
        assert!(validate_phase(&report, &commit, "x86_64", kind).is_err());
        assert!(validate_phase(&report, &"b".repeat(40), "aarch64", kind).is_err());
        assert!(validate_phase(&report, &commit, "aarch64", "combined").is_err());
        let mut value = phase(kind);
        value.native.tests.pop();
        assert!(validate_phase(&value, &commit, "aarch64", kind).is_err());
        let mut value = phase(kind);
        value.native.tests[0].result = NativeTestOutcome::Skipped;
        assert!(validate_phase(&value, &commit, "aarch64", kind).is_err());
        let mut value = phase(kind);
        value.native.tests_skipped = 1;
        assert!(validate_phase(&value, &commit, "aarch64", kind).is_err());
        let mut value = phase(kind);
        value.revision = 2;
        assert!(validate_phase(&value, &commit, "aarch64", kind).is_err());
    }
}
