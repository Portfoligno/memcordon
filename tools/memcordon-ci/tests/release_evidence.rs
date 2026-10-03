//! Bounded native report collection, identity checks, and rejection regressions.
use memcordon_ci::native_results::{MAX_REPORT_BYTES, NativeReportSpec, collect_native_results};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use tempfile::TempDir;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const SCENARIOS: &[&str] = &[
    "ordinary_status_and_reaping",
    "memory_limit_and_descendant_cleanup",
];
const SPECS: &[NativeReportSpec<'_>] = &[
    NativeReportSpec {
        artifact_directory: "native-linux",
        report_name: "linux.json",
        backend: "linux-cgroup-v2",
        scenario_names: SCENARIOS,
    },
    NativeReportSpec {
        artifact_directory: "native-windows",
        report_name: "windows.json",
        backend: "windows-job-object",
        scenario_names: SCENARIOS,
    },
    NativeReportSpec {
        artifact_directory: "native-macos",
        report_name: "macos.json",
        backend: "macos-watchdog",
        scenario_names: SCENARIOS,
    },
];
fn report(backend: &str) -> Value {
    json!({ "schema_version": 1, "backend": backend, "source_commit": COMMIT,
        "tests": SCENARIOS.iter().map(|name| json!({"name": name, "result": "passed"})).collect::<Vec<_>>(),
        "tests_run": SCENARIOS.len(), "tests_skipped": 0 })
}
fn write_report(path: &Path, value: &Value) {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}
fn fixture() -> TempDir {
    let temporary = tempfile::tempdir().unwrap();
    for spec in SPECS {
        write_report(
            &temporary
                .path()
                .join("input")
                .join(spec.artifact_directory)
                .join(spec.report_name),
            &report(spec.backend),
        );
    }
    temporary
}

#[test]
fn valid_reports_are_copied_and_digest_bound() {
    let temporary = fixture();
    let input = temporary.path().join("input");
    let output = temporary.path().join("output");
    let records = collect_native_results(&input, &output, COMMIT, SPECS).unwrap();
    assert_eq!(records.len(), SPECS.len());
    for spec in SPECS {
        let record = &records[spec.backend];
        assert_eq!(record.evidence_path, spec.report_name);
        let evidence = fs::read(output.join(&record.evidence_path)).unwrap();
        assert_eq!(
            evidence,
            fs::read(input.join(spec.artifact_directory).join(spec.report_name)).unwrap()
        );
        assert_eq!(record.sha256, hex::encode(Sha256::digest(evidence)));
    }
}

#[test]
fn hard_report_contract_mutations_fail_closed() {
    type Mutation = (&'static str, fn(&mut Value));
    let cases: &[Mutation] = &[
        ("schema", |report| report["schema_version"] = json!(2)),
        ("backend", |report| report["backend"] = json!("other")),
        ("commit", |report| report["source_commit"] = json!("wrong")),
        ("count", |report| report["tests_run"] = json!(1)),
        ("empty", |report| {
            report["tests"] = json!([]);
            report["tests_run"] = json!(0);
        }),
        ("skips", |report| report["tests_skipped"] = json!(1)),
        ("failed", |report| {
            report["tests"][0]["result"] = json!("failed")
        }),
        ("skipped", |report| {
            report["tests"][0]["result"] = json!("skipped")
        }),
        ("order", |report| {
            report["tests"].as_array_mut().unwrap().swap(0, 1)
        }),
        ("duplicate", |report| {
            report["tests"][1] = report["tests"][0].clone()
        }),
        ("unknown", |report| report["unexpected"] = json!(true)),
    ];
    for (name, mutate) in cases {
        let temporary = fixture();
        let input = temporary.path().join("input");
        let mut invalid = report(SPECS[0].backend);
        mutate(&mut invalid);
        write_report(
            &input
                .join(SPECS[0].artifact_directory)
                .join(SPECS[0].report_name),
            &invalid,
        );
        assert!(
            collect_native_results(&input, &temporary.path().join("output"), COMMIT, SPECS)
                .is_err(),
            "{name}"
        );
    }
}

#[test]
fn artifact_path_cardinality_and_size_fail_closed() {
    let temporary = fixture();
    let input = temporary.path().join("input");
    let output = temporary.path().join("output");
    fs::create_dir(input.join("unexpected")).unwrap();
    assert!(collect_native_results(&input, &output, COMMIT, SPECS).is_err());
    fs::remove_dir(input.join("unexpected")).unwrap();
    write_report(
        &input.join("duplicate/linux.json"),
        &report(SPECS[0].backend),
    );
    assert!(collect_native_results(&input, &output, COMMIT, SPECS).is_err());
    fs::remove_dir_all(input.join("duplicate")).unwrap();
    fs::write(
        input
            .join(SPECS[0].artifact_directory)
            .join(SPECS[0].report_name),
        vec![b' '; usize::try_from(MAX_REPORT_BYTES).unwrap() + 1],
    )
    .unwrap();
    assert!(collect_native_results(&input, &output, COMMIT, SPECS).is_err());
    assert!(collect_native_results(&input, &output, COMMIT, &[]).is_err());
}
