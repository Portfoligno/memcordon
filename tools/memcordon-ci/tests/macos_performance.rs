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

fn write_phase(root: &std::path::Path, kind: &str, value: &MacosPhaseReport) {
    let filename = match kind {
        "native" => "release-macos-native.json",
        "acceptance" => "release-macos-acceptance.json",
        _ => unreachable!(),
    };
    std::fs::write(
        root.join("target/ci/reports").join(filename),
        serde_json::to_vec(value).unwrap(),
    )
    .unwrap();
}

#[test]
fn local_completion_rejects_missing_stale_malformed_or_incomplete_phase_reports() {
    use memcordon_ci::macos_performance::{clear_local_phases, validate_local_completed};
    let temporary = tempfile::tempdir_in("/tmp").unwrap();
    let root = temporary.path();
    let reports = root.join("target/ci/reports");
    std::fs::create_dir_all(&reports).unwrap();
    let commit = "a".repeat(40);
    assert!(validate_local_completed(root, &commit, "aarch64").is_err());
    for kind in ["native", "acceptance"] {
        write_phase(root, kind, &phase(kind));
    }
    validate_local_completed(root, &commit, "aarch64").unwrap();
    assert!(validate_local_completed(root, &"b".repeat(40), "aarch64").is_err());
    assert!(validate_local_completed(root, &commit, "x86_64").is_err());
    for kind in ["native", "acceptance"] {
        for mutation in ["missing-case", "skip", "wrong-phase", "wrong-os", "failed"] {
            let mut report = phase(kind);
            match mutation {
                "missing-case" => {
                    report.native.tests.pop();
                }
                "skip" => report.native.tests_skipped = 1,
                "wrong-phase" => report.phase = "combined".into(),
                "wrong-os" => report.host_os = "linux".into(),
                "failed" => report.native.tests[0].result = NativeTestOutcome::Failed,
                _ => unreachable!(),
            }
            write_phase(root, kind, &report);
            assert!(
                validate_local_completed(root, &commit, "aarch64").is_err(),
                "{kind}: {mutation}"
            );
            write_phase(root, kind, &phase(kind));
        }
    }
    let native = reports.join("release-macos-native.json");
    for malformed in [
        b"{}".as_slice(),
        b"{\"revision\":1,\"revision\":1}",
        b"not json",
    ] {
        std::fs::write(&native, malformed).unwrap();
        assert!(validate_local_completed(root, &commit, "aarch64").is_err());
    }
    write_phase(root, "native", &phase("native"));
    std::fs::File::create(&native)
        .unwrap()
        .set_len(memcordon_ci::native_results::MAX_REPORT_BYTES + 1)
        .unwrap();
    assert!(validate_local_completed(root, &commit, "aarch64").is_err());
    std::fs::remove_file(&native).unwrap();
    std::fs::create_dir(&native).unwrap();
    assert!(validate_local_completed(root, &commit, "aarch64").is_err());
    assert!(
        clear_local_phases(root).is_err(),
        "a diagnostic directory is not recursively removed"
    );
    std::fs::remove_dir(&native).unwrap();
    #[cfg(unix)]
    {
        let outside = root.join("outside.json");
        std::fs::write(&outside, serde_json::to_vec(&phase("native")).unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside, &native).unwrap();
        assert!(validate_local_completed(root, &commit, "aarch64").is_err());
        clear_local_phases(root).unwrap();
        assert!(outside.is_file());
        write_phase(root, "acceptance", &phase("acceptance"));
    }
    write_phase(root, "native", &phase("native"));
    let unrelated = reports.join("unrelated.json");
    std::fs::write(&unrelated, b"preserve\n").unwrap();
    clear_local_phases(root).unwrap();
    clear_local_phases(root).unwrap();
    assert!(unrelated.is_file());
    assert!(
        validate_local_completed(root, &commit, "aarch64").is_err(),
        "old success may not survive current execution reset"
    );
    write_phase(root, "native", &phase("native"));
    assert!(
        validate_local_completed(root, &commit, "aarch64").is_err(),
        "current acceptance report required"
    );
}

#[test]
fn complete_suite_resets_then_executes_then_validates_before_reporting_completion() {
    let source = include_str!("../src/suites.rs");
    let wrapper = source
        .split_once("pub fn release_macos(root:")
        .unwrap()
        .1
        .split_once("pub(crate) struct SuiteOptions")
        .unwrap()
        .0;
    let reset = wrapper.find("clear_local_phases(root)?").unwrap();
    let native = wrapper.find("release_macos_native(root, stable)?").unwrap();
    let acceptance = wrapper
        .find("release_macos_acceptance(root, stable)?")
        .unwrap();
    let validate = wrapper.find("validate_local_completed(").unwrap();
    let complete = wrapper.find("write_macos_report(").unwrap();
    assert!(reset < native && native < acceptance && acceptance < validate && validate < complete);
    assert!(wrapper.contains("std::env::consts::ARCH"));
    assert!(wrapper.contains("git(root, [\"rev-parse\", \"HEAD\"])?"));
}
