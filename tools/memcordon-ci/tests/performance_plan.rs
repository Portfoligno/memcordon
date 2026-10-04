use memcordon_ci::performance_plan::{
    Experiment, Layout, PerformancePlan, Sample, Selection, StressPhaseObservation, Warmth,
    validate_stress_results,
};
use std::path::Path;

fn measurements(parallel: u64) -> Experiment {
    let mut samples = Vec::new();
    for category in [Warmth::Cold, Warmth::Warm] {
        for (layout, duration) in [(Layout::Serial, 1000), (Layout::Parallel, parallel)] {
            for ordinal in 0..5 {
                samples.push(Sample {
                    category,
                    layout,
                    end_to_end_ms: duration + ordinal,
                    queue_ms: 10,
                    bootstrap_ms: 20,
                    duplicated_bootstrap_ms: 0,
                    lost_incremental_reuse_ms: 0,
                    coverage: vec!["packages".into(), "lifecycle-4096".into()],
                    timeouts: 0,
                    cleanup_failures: 0,
                });
            }
        }
    }
    Experiment {
        available_categories: vec![Warmth::Cold, Warmth::Warm],
        samples,
    }
}

fn phases() -> Vec<StressPhaseObservation> {
    let ordinals = (0..memcordon_ci::stress::PACKAGES.len()).collect::<Vec<_>>();
    vec![
        StressPhaseObservation {
            schema_version: 1,
            source_revision: "source".into(),
            platform: "linux".into(),
            architecture: "x86_64".into(),
            suite: "packages".into(),
            target_path: "target/ci/stress".into(),
            planned_package_ordinals: ordinals.clone(),
            attempted_package_ordinals: ordinals.clone(),
            completed_package_ordinals: ordinals,
            planned_iterations: 0,
            executed_iterations: 0,
            seed: None,
            elapsed_millis: 1,
            disposition: "passed".into(),
            detail: serde_json::Value::Null,
        },
        StressPhaseObservation {
            schema_version: 1,
            source_revision: "source".into(),
            platform: "linux".into(),
            architecture: "x86_64".into(),
            suite: "lifecycle".into(),
            target_path: "target/ci/stress".into(),
            planned_package_ordinals: vec![],
            attempted_package_ordinals: vec![],
            completed_package_ordinals: vec![],
            planned_iterations: 4096,
            executed_iterations: 4096,
            seed: Some(42),
            elapsed_millis: 1,
            disposition: "passed".into(),
            detail: serde_json::Value::Null,
        },
    ]
}

#[test]
fn aggregation_requires_actual_complete_unique_source_bound_phases() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let plan = PerformancePlan::read(&root).unwrap();
    validate_stress_results(&plan, "linux-x64", "source", &phases()).unwrap();
    for case in [
        "omission",
        "duplicate-phase",
        "duplicate-ordinal",
        "attempt",
        "iteration",
        "source",
        "root",
        "unavailable-false-pass",
    ] {
        let mut reports = phases();
        match case {
            "omission" => {
                reports.pop();
            }
            "duplicate-phase" => reports[1] = reports[0].clone(),
            "duplicate-ordinal" => reports[0].completed_package_ordinals.push(0),
            "attempt" => {
                reports[0].attempted_package_ordinals.pop();
            }
            "iteration" => reports[1].executed_iterations -= 1,
            "source" => reports[1].source_revision = "other".into(),
            "root" => reports[1].target_path = "target/ci/stress-packages".into(),
            "unavailable-false-pass" => reports[1].executed_iterations = 0,
            _ => unreachable!(),
        }
        assert!(
            validate_stress_results(&plan, "linux-x64", "source", &reports).is_err(),
            "{case}"
        );
    }
    let mut unavailable = phases();
    unavailable[1].executed_iterations = 0;
    unavailable[1].disposition = "unavailable-on-linux".into();
    validate_stress_results(&plan, "linux-x64", "source", &unavailable).unwrap();
}

#[test]
fn split_selection_requires_distinct_actual_phase_roots() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut plan = PerformancePlan::read(&root).unwrap();
    let selection = plan
        .stress
        .iter_mut()
        .find(|item| item.platform == "linux-x64")
        .unwrap();
    selection.selected = Layout::Parallel;
    selection.experiment = Some(measurements(800));
    assert_eq!(plan.stress_cells(Layout::Parallel).unwrap().len(), 1);
    let mut reports = phases();
    assert!(validate_stress_results(&plan, "linux-x64", "source", &reports).is_err());
    reports[0].target_path = "target/ci/stress-packages".into();
    reports[1].target_path = "target/ci/stress-lifecycle".into();
    validate_stress_results(&plan, "linux-x64", "source", &reports).unwrap();
    reports[1].target_path = reports[0].target_path.clone();
    assert!(validate_stress_results(&plan, "linux-x64", "source", &reports).is_err());
}

#[test]
fn serial_remains_default_until_comparable_queue_inclusive_improvement() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let plan = PerformancePlan::read(&root).unwrap();
    assert_eq!(plan.stress_cells(Layout::Serial).unwrap().len(), 5);
    assert!(plan.stress_cells(Layout::Parallel).unwrap().is_empty());
    assert!(
        Selection {
            selected: Layout::Parallel,
            experiment: None
        }
        .validate()
        .is_err()
    );
    assert!(measurements(899).supports_parallel().unwrap());
    assert!(!measurements(950).supports_parallel().unwrap());
}

#[test]
fn parallel_cannot_hide_tail_cleanup_timeout_or_coverage_regressions() {
    for case in [
        "tail",
        "cleanup",
        "timeout",
        "coverage",
        "cardinality",
        "category",
    ] {
        let mut experiment = measurements(800);
        let index = experiment
            .samples
            .iter()
            .position(|sample| sample.layout == Layout::Parallel)
            .unwrap();
        match case {
            "tail" => experiment.samples[index].end_to_end_ms = 2000,
            "cleanup" => experiment.samples[index].cleanup_failures = 1,
            "timeout" => experiment.samples[index].timeouts = 1,
            "coverage" => {
                experiment.samples[index].coverage.pop();
            }
            "cardinality" => {
                experiment.samples.pop();
            }
            "category" => experiment.available_categories.push(Warmth::Cold),
            _ => unreachable!(),
        }
        assert!(
            !experiment.supports_parallel().unwrap_or(false),
            "case={case}"
        );
        assert!(
            Selection {
                selected: Layout::Parallel,
                experiment: Some(experiment)
            }
            .validate()
            .is_err()
        );
    }
}

#[test]
fn platform_omissions_duplicates_and_unknown_fields_are_rejected() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let plan = PerformancePlan::read(&root).unwrap();
    let mut missing = plan.clone();
    missing.stress.pop();
    assert!(missing.validate().is_err());
    let mut duplicate = plan.clone();
    duplicate.stress[1].platform = duplicate.stress[0].platform.clone();
    assert!(duplicate.validate().is_err());
    let mut unknown = serde_json::to_value(plan).unwrap();
    unknown["certificate"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<PerformancePlan>(unknown).is_err());
}
