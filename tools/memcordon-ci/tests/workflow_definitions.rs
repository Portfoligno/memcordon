use memcordon_ci::{config, policy, workflow_definitions};
use serde_yaml::Value;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const SELECTION_ID: &str = "${{ needs.select.outputs.selection-artifact-id }}";

#[test]
fn native_storage_baseline_is_uploaded_before_heavy_work_without_admission_authority() {
    for document in sources("ci.yml") {
        let sequence = steps(&document, "native");
        let find = |id: &str| {
            let matches = sequence
                .iter()
                .enumerate()
                .filter(|(_, step)| step["id"] == id)
                .collect::<Vec<_>>();
            assert_eq!(matches.len(), 1, "expected one {id}");
            matches[0]
        };
        let (checkpoint_index, checkpoint) = find("native-storage-checkpoint");
        let (upload_index, upload) = find("native-storage-retain");
        let (compile_index, _) = find("native-compile");
        for restore in [
            "native-compile-request-native-tests-complete-restore",
            "native-compile-request-native-tests-partial-restore",
        ] {
            assert!(
                find(restore).0 < checkpoint_index,
                "baseline must observe restored capacity"
            );
        }
        assert_eq!(upload_index, checkpoint_index + 1);
        assert_eq!(compile_index, upload_index + 1);
        assert_eq!(checkpoint["if"], "!cancelled() && runner.os == 'Linux'");
        assert_eq!(
            upload["if"],
            "!cancelled() && runner.os == 'Linux' && steps.native-storage-checkpoint.outcome == 'success'"
        );
        for step in [checkpoint, upload] {
            assert_eq!(step["continue-on-error"], true);
            assert!(step["env"].is_null());
        }
        assert_eq!(
            checkpoint["run"],
            "./target/ci-runtime/current/memcordon-ci ci storage-checkpoint"
        );
        assert_eq!(checkpoint["timeout-minutes"].as_u64(), Some(1));
        assert!(checkpoint["uses"].is_null());
        assert_eq!(upload["uses"], "./.github/actions/upload-artifact");
        assert!(upload["run"].is_null());
        assert_eq!(upload["timeout-minutes"].as_u64(), Some(2));
        assert_eq!(
            upload["with"]["path"],
            "target/ci/reports/storage/native-before-compile.json"
        );
        assert_eq!(upload["with"]["if-no-files-found"], "ignore");
        assert_eq!(upload["with"]["retention-days"].as_u64(), Some(7));
        assert_eq!(
            upload["with"]["name"],
            "native-storage-${{ github.job }}-${{ runner.arch }}-${{ strategy.job-index }}-${{ github.run_id }}-${{ github.run_attempt }}"
        );
        let mut ids = BTreeSet::new();
        for step in sequence {
            if let Some(id) = step["id"].as_str() {
                assert!(ids.insert(id), "duplicate native step: {id}");
            }
        }
    }
}

#[test]
fn backend_original_failure_carriers_precede_the_full_installed_artifact() {
    for document in sources("backend-certification.yml") {
        for job in ["windows-installed-x64", "windows-installed-arm64"] {
            let steps = document["jobs"][job]["steps"].as_sequence().unwrap();
            let selected: Vec<_> = steps
                .iter()
                .enumerate()
                .filter(|(_, step)| step["name"] == "Retain original Winsock failure carriers")
                .collect();
            assert_eq!(selected.len(), 1);
            let (index, step) = selected[0];
            assert_eq!(step["if"], "!cancelled() && failure()");
            assert_eq!(step["continue-on-error"], true);
            assert_eq!(step["timeout-minutes"].as_u64(), Some(2));
            assert_eq!(step["uses"], "./.github/actions/upload-artifact");
            assert_eq!(step["with"]["if-no-files-found"], "ignore");
            let paths: Vec<_> = step["with"]["path"].as_str().unwrap().lines().collect();
            let expected = expected_listener_carriers(
                "target/ci/windows-installed/${{ matrix.channel }}/cases",
            );
            assert_eq!(paths, expected);
            let full = &steps[index + 1];
            assert_eq!(full["with"]["path"], "target/ci/windows-installed");
            assert_eq!(full["timeout-minutes"].as_u64(), Some(6));
        }
    }
}

fn expected_listener_carriers(prefix: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for case in ["C-IO/empty-message", "W-JOINT/restricted"] {
        for name in [
            "result.callback-failure.json",
            "result.failed-frontend.json",
            "result.failed-terminal-observation.json",
            "result.stderr.bin",
            "result.winsock-startup-trace.json",
            "result.listener-call-trace.json",
            "result.listener-native-file-requests.json",
            "result.peer-spawn-call-trace.json",
        ] {
            paths.push(format!("{prefix}/windows-installed/{case}/{name}"));
        }
    }
    paths.push(format!(
        "{prefix}/windows-installed/W-JOINT/restricted/result.loader-fileio.json"
    ));
    paths.push(format!(
        "{prefix}/windows-installed/fixture-manifest-inventory.json"
    ));
    for name in [
        "result.guardian-query.json",
        "result.guardian-query.stdout.bin",
        "result.guardian-query.stderr.bin",
        "result.callback-failure.json",
        "result.stderr.bin",
    ] {
        paths.push(format!(
            "{prefix}/windows-installed/C-IO/native-argv/{name}"
        ));
    }
    for name in [
        "package-uninstall.stdout.bin",
        "package-uninstall.stderr.bin",
        "package-uninstall.capture.json",
        "package-uninstall.invocation.json",
        "recovery.stdout.bin",
        "recovery.stderr.bin",
    ] {
        paths.push(format!("{prefix}/windows-installed/{name}"));
    }
    paths
}

#[test]
fn release_finite_listener_carriers_precede_general_retention_in_all_windows_deliveries() {
    for document in sources("release.yml") {
        let mut consumers = BTreeSet::new();
        for (name, job) in document["jobs"].as_mapping().unwrap() {
            let name = name.as_str().unwrap();
            let Some(steps) = job["steps"].as_sequence() else {
                continue;
            };
            let carriers = steps
                .iter()
                .enumerate()
                .filter(|(_, step)| step["name"] == "Retain original listener failure carriers")
                .collect::<Vec<_>>();
            if carriers.is_empty() {
                continue;
            }
            assert_eq!(carriers.len(), 1);
            consumers.insert(name.to_owned());
            assert!(name.starts_with("candidate-windows-") || name.starts_with("public-windows-"));
            let (index, step) = carriers[0];
            assert_eq!(steps[index - 1]["id"], "installed-test");
            assert_eq!(steps[index - 1]["timeout-minutes"].as_u64(), Some(160));
            assert_eq!(step["if"], "!cancelled() && failure()");
            assert_eq!(step["continue-on-error"], true);
            assert_eq!(step["timeout-minutes"].as_u64(), Some(2));
            assert_eq!(step["uses"], "./.github/actions/upload-artifact");
            assert_eq!(step["with"]["if-no-files-found"], "ignore");
            let paths = step["with"]["path"]
                .as_str()
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert_eq!(
                paths,
                expected_listener_carriers("target/ci/reports/installed/raw")
            );
            let general = steps
                .iter()
                .position(|step| step["name"] == "Retain bounded installed diagnostics")
                .unwrap();
            assert!(index < general);
            for (other, step) in steps.iter().enumerate() {
                if matches!(
                    step["with"]["path"].as_str(),
                    Some(".release/installed-results" | "target/ci/reports/installed")
                ) {
                    assert!(index < other);
                }
            }
        }
        assert_eq!(
            consumers,
            [
                "candidate-windows-x64-native",
                "candidate-windows-x64-cargo",
                "candidate-windows-arm64-native",
                "candidate-windows-arm64-cargo",
                "public-windows-x64-native",
                "public-windows-x64-cargo",
                "public-windows-arm64-native",
                "public-windows-arm64-cargo"
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
    }
}

#[test]
fn every_release_selection_consumer_has_an_adjacent_fatal_exact_retry() {
    for document in sources("release.yml") {
        let mut consumers = BTreeSet::new();
        for (name, job) in document["jobs"].as_mapping().unwrap() {
            let Some(steps) = job["steps"].as_sequence() else {
                continue;
            };
            let selected: Vec<_> = steps
                .iter()
                .enumerate()
                .filter(|(_, step)| step["with"]["artifact-ids"] == SELECTION_ID)
                .collect();
            if selected.is_empty() {
                continue;
            }
            assert!(consumers.insert(name.as_str().unwrap().to_owned()));
            assert_eq!(selected.len(), 2, "{name:?}");
            let (first_index, first) = selected[0];
            let (retry_index, retry) = selected[1];
            assert_eq!(retry_index, first_index + 1, "{name:?}");
            assert_eq!(first["id"], "selection-download");
            assert_eq!(retry["id"], "selection-download-retry");
            assert_eq!(first["continue-on-error"], true);
            assert!(first["if"].is_null());
            assert!(retry["continue-on-error"].is_null());
            assert_eq!(
                retry["if"],
                "${{ !cancelled() && steps.selection-download.outcome == 'failure' }}"
            );
            for attempt in [first, retry] {
                assert_eq!(
                    attempt["uses"],
                    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
                );
                assert_eq!(attempt["timeout-minutes"].as_u64(), Some(3));
                assert_eq!(attempt["with"]["path"], ".release");
                assert_eq!(attempt["with"]["merge-multiple"], true);
                assert_eq!(attempt["with"]["digest-mismatch"], "error");
                assert_eq!(attempt["with"].as_mapping().unwrap().len(), 4);
            }
            assert_eq!(first["with"], retry["with"]);
            assert_eq!(
                first["timeout-minutes"].as_u64().unwrap()
                    + retry["timeout-minutes"].as_u64().unwrap(),
                6
            );
            let mut ids = BTreeSet::new();
            for step in steps {
                if let Some(id) = step["id"].as_str() {
                    assert!(ids.insert(id), "duplicate id in {name:?}: {id}");
                }
            }
        }
        assert_eq!(consumers.len(), 52);
        assert!(consumers.contains("native-macos-x64-shard-1"));
        assert!(consumers.contains("fuzz-setup"));
    }
}

#[test]
fn selection_retry_contract_rejects_missing_optional_or_unbound_attempts() {
    let baseline = workflow_definitions::definition("release.yml").unwrap();
    workflow_definitions::validate_semantics(&baseline).unwrap();
    for job in ["native-macos-x64-shard-1", "fuzz-setup", "assemble-payload"] {
        let initial = steps(&baseline, job)
            .iter()
            .position(|step| step["id"] == "selection-download")
            .unwrap();
        for mutation in [
            "missing-retry",
            "both-absent",
            "optional-retry",
            "wrong-condition",
            "cancelled-retry",
            "timeout",
            "digest",
            "artifact",
            "separated",
        ] {
            let mut changed = baseline.clone();
            let selected = changed["jobs"][job]["steps"].as_sequence_mut().unwrap();
            match mutation {
                "missing-retry" => {
                    selected.remove(initial + 1);
                }
                "both-absent" => {
                    selected.drain(initial..initial + 2);
                }
                "optional-retry" => selected[initial + 1]["continue-on-error"] = true.into(),
                "wrong-condition" => {
                    selected[initial + 1]["if"] =
                        "${{ !cancelled() && steps.selection-download.conclusion == 'failure' }}"
                            .into()
                }
                "cancelled-retry" => {
                    selected[initial + 1]["if"] =
                        "${{ always() && steps.selection-download.outcome == 'failure' }}".into()
                }
                "timeout" => selected[initial]["timeout-minutes"] = 4.into(),
                "digest" => {
                    selected[initial]["with"]["digest-mismatch"] = "warn".into();
                    selected[initial + 1]["with"]["digest-mismatch"] = "warn".into();
                }
                "artifact" => {
                    selected[initial + 1]["with"]["artifact-ids"] =
                        "${{ needs.other.outputs.artifact-id }}".into()
                }
                "separated" => {
                    let retry = selected.remove(initial + 1);
                    selected.push(retry);
                }
                _ => unreachable!(),
            }
            assert!(
                workflow_definitions::validate_semantics(&changed).is_err(),
                "{job}/{mutation}"
            );
        }
    }
}
fn sources(file: &str) -> [Value; 2] {
    [
        workflow_definitions::definition(file).unwrap(),
        serde_yaml::from_slice(
            &std::fs::read(root().join(".github/workflows").join(file)).unwrap(),
        )
        .unwrap(),
    ]
}
fn steps<'a>(document: &'a Value, job: &str) -> &'a Vec<Value> {
    document["jobs"][job]["steps"].as_sequence().unwrap()
}
fn recipes(document: &Value) -> BTreeSet<String> {
    document["jobs"]
        .as_mapping()
        .unwrap()
        .values()
        .filter_map(|job| job["steps"].as_sequence())
        .flatten()
        .filter_map(|step| step["run"].as_str())
        .filter_map(|run| {
            run.split_once(" ci segment ")
                .map(|(_, name)| name.to_owned())
        })
        .collect()
}

#[test]
fn publication_source_producer_really_compiles_before_adoption() {
    let document = workflow_definitions::definition("release.yml").unwrap();
    let steps = document["jobs"]["select"]["steps"].as_sequence().unwrap();
    let compile = steps
        .iter()
        .position(|s| {
            s["run"].as_str().is_some_and(|r| {
                r.contains("cargo build --locked --release ")
                    && r.contains("--target-dir target/ci-driver-cold")
                    && r.ends_with("--bin memcordon-ci")
            })
        })
        .unwrap();
    let adoption = steps
        .iter()
        .position(|s| {
            s["run"]
                .as_str()
                .is_some_and(|r| r.ends_with(" ci driver-adopt-cold"))
        })
        .unwrap();
    assert!(compile < adoption);
    let mut changed = document.clone();
    changed["jobs"]["select"]["steps"]
        .as_sequence_mut()
        .unwrap()
        .remove(compile);
    let root = root();
    assert!(
        policy::validate_workflow_bytes(
            &root,
            Path::new(".github/workflows/release.yml"),
            serde_yaml::to_string(&changed).unwrap().as_bytes(),
            &config::policy(&root).unwrap()
        )
        .is_err()
    );
}

#[test]
fn generated_content_matches_all_checked_in_workflows() {
    workflow_definitions::run(&root(), false).unwrap();
    for file in workflow_definitions::FILES {
        let bytes = std::fs::read(root().join(".github/workflows").join(file)).unwrap();
        assert!(bytes.ends_with(b"\n"));
        assert!(bytes.starts_with(b"# Generated by memcordon-ci ci workflows --write."));
    }
}

#[test]
fn workflow_checks_accept_crlf_and_writes_restore_canonical_lf() {
    let fixture = tempfile::tempdir().unwrap();
    let workflows = fixture.path().join(".github/workflows");
    std::fs::create_dir_all(&workflows).unwrap();
    workflow_definitions::run(fixture.path(), true).unwrap();
    for file in workflow_definitions::FILES {
        let path = workflows.join(file);
        let canonical = std::fs::read_to_string(&path).unwrap();
        assert!(canonical.ends_with('\n') && !canonical.contains('\r'));
        std::fs::write(path, canonical.replace('\n', "\r\n")).unwrap();
    }
    workflow_definitions::run(fixture.path(), false).unwrap();
    // Checking must leave the checkout's line endings alone.
    for file in workflow_definitions::FILES {
        let content = std::fs::read_to_string(workflows.join(file)).unwrap();
        assert!(content.ends_with("\r\n"));
    }

    let path = workflows.join("ci.yml");
    let crlf = std::fs::read_to_string(&path).unwrap();
    for changed in [
        crlf.replacen("# Generated", "# Changed", 1),
        crlf.replacen("\r\n", " \r\n", 1),
        crlf.strip_suffix("\r\n").unwrap().to_owned(),
        crlf.replacen("\r\n", "\r\r\n", 1),
        crlf.replace("\r\n", "\r"),
    ] {
        std::fs::write(&path, changed).unwrap();
        let error = workflow_definitions::run(fixture.path(), false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("generated workflow drift: ci.yml")
        );
    }

    workflow_definitions::run(fixture.path(), true).unwrap();
    workflow_definitions::run(fixture.path(), false).unwrap();
    for file in workflow_definitions::FILES {
        let bytes = std::fs::read(workflows.join(file)).unwrap();
        assert!(bytes.ends_with(b"\n") && !bytes.contains(&b'\r'));
    }
}

#[test]
fn compact_action_aliases_preserve_complete_workflow_data_and_consumer_guards() {
    for file in workflow_definitions::FILES {
        let rendered = workflow_definitions::render(file).unwrap();
        assert!(rendered.len() <= 500 * 1024, "{file} exceeds size budget");
        assert!(rendered.contains("uses: &action_"));
        assert!(rendered.contains("uses: *action_"));
        let parsed: Value = serde_yaml::from_str(&rendered).unwrap();
        assert_eq!(parsed, workflow_definitions::definition(file).unwrap());
        if file == "release.yml" {
            for (name, job) in parsed["jobs"].as_mapping().unwrap() {
                if name.as_str().unwrap().starts_with("installed-macos-") {
                    for row in job["strategy"]["matrix"]["include"].as_sequence().unwrap() {
                        assert!(row["producer-job"].is_null());
                    }
                }
            }
        }
    }
}

#[test]
fn direct_release_tests_require_all_channels_shards_and_rehearsal() {
    let baseline = workflow_definitions::definition("release.yml").unwrap();
    for missing in [
        "candidate-linux-x64-native",
        "candidate-windows-arm64-cargo",
        "installed-macos-arm64-cargo",
        "native-macos-x64-shard-3",
        "native-components-linux-x64",
        "native-components-windows-arm64",
        "rehearse",
    ] {
        let mut changed = baseline.clone();
        changed["jobs"]["assemble"]["needs"]
            .as_sequence_mut()
            .unwrap()
            .retain(|name| name.as_str() != Some(missing));
        assert!(
            workflow_definitions::validate_semantics(&changed).is_err(),
            "missing direct dependency {missing}"
        );
    }
    let mut changed = baseline.clone();
    changed["jobs"]["public-linux-x64-native"]["if"] = Value::String(
        "needs.publish.result == 'success' && needs.recovery-publish.result == 'success'".into(),
    );
    assert!(workflow_definitions::validate_semantics(&changed).is_err());
    for owner in ["publish", "recovery-publish"] {
        let mut changed = baseline.clone();
        changed["jobs"][owner]["if"] = Value::String("always()".into());
        assert!(workflow_definitions::validate_semantics(&changed).is_err());
    }
}

#[test]
fn budgets_use_maximum_branch_and_reject_platform_overflow() {
    use workflow_definitions::budget::JobBudget;
    assert_eq!(
        JobBudget {
            production: 100,
            serial_cache: 20,
            cold_driver: 61,
            warm_driver: Some(87)
        }
        .minutes()
        .unwrap(),
        212
    );
    assert!(
        JobBudget {
            production: 300,
            serial_cache: 1,
            cold_driver: 61,
            warm_driver: None
        }
        .minutes()
        .unwrap_err()
        .to_string()
        .contains("BudgetExceedsPlatformLimit")
    );
    assert!(
        JobBudget {
            production: u64::MAX,
            serial_cache: 1,
            cold_driver: 0,
            warm_driver: None
        }
        .minutes()
        .is_err()
    );
    for file in workflow_definitions::FILES {
        let document = workflow_definitions::definition(file).unwrap();
        for job in document["jobs"].as_mapping().unwrap().values() {
            assert!(job["timeout-minutes"].as_u64().unwrap() <= 360);
        }
    }
}

#[test]
fn fuzz_split_binds_actual_immutable_artifact_and_source() {
    let document = workflow_definitions::definition("deep-ci.yml").unwrap();
    for (mutation, expected) in [
        ("artifact", "exact same-run immutable setup ID"),
        ("dependency", "performance-plan edges"),
        ("probe", "protocol probe"),
        ("checkout", "same exact source checkout"),
        ("admission-missing", "failure must fail selected shards"),
        ("admission-optional", "failure must fail selected shards"),
    ] {
        let mut changed = document.clone();
        match mutation {
            "admission-missing" => {
                changed["jobs"]["fuzz"]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .remove(0);
            }
            "admission-optional" => {
                changed["jobs"]["fuzz"]["steps"][0]["continue-on-error"] = true.into()
            }
            "artifact" => {
                changed["jobs"]["fuzz"]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|s| s["id"] == "fuzz-setup-download")
                    .unwrap()["with"]["artifact-ids"] = "latest".into()
            }
            "dependency" => {
                changed["jobs"]["fuzz"]["needs"] =
                    serde_yaml::from_str("[performance-plan]").unwrap()
            }
            "probe" => changed["jobs"]["fuzz"]["steps"]
                .as_sequence_mut()
                .unwrap()
                .retain(|s| {
                    !s["run"]
                        .as_str()
                        .is_some_and(|r| r.ends_with(" ci driver-image-probe"))
                }),
            "checkout" => {
                let checkout = changed["jobs"]["fuzz-setup"]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|step| {
                        step["uses"]
                            .as_str()
                            .is_some_and(|uses| uses.starts_with("actions/checkout@"))
                    })
                    .unwrap();
                checkout["with"]["ref"] = "main".into();
            }
            _ => unreachable!(),
        }
        let error = workflow_definitions::validate_semantics(&changed)
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{mutation}: {error}");
    }
}

#[test]
fn actual_event_unions_native_matrix_and_shard_inventory_survive_rendering() {
    for document in sources("ci.yml") {
        let events = document["on"]
            .as_mapping()
            .unwrap()
            .keys()
            .map(|k| k.as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            events,
            BTreeSet::from(["push", "pull_request", "merge_group", "workflow_dispatch"])
        );
        let rows = document["jobs"]["native"]["strategy"]["matrix"]["include"]
            .as_sequence()
            .unwrap();
        let hosts = rows
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            hosts,
            BTreeSet::from([
                "linux-x64",
                "linux-arm64",
                "macos-x64",
                "macos-arm64",
                "windows-x64",
                "windows-arm64"
            ])
        );
        let actual = recipes(&document);
        for required in [
            "policy",
            "quality-compiler",
            "quality-documentation",
            "msrv",
            "supply-audit",
            "supply-deny",
            "native-compile",
            "native-execute",
            "macos-deadline",
        ] {
            let executed = actual.contains(required)
                || (required == "policy"
                    && steps(&document, "policy").iter().any(|step| {
                        step["run"]
                            .as_str()
                            .is_some_and(|run| run.ends_with("--feedback repository-policy"))
                    }));
            assert!(executed, "missing {required}");
        }
    }
    for file in ["deep-ci.yml", "release.yml"] {
        for document in sources(file) {
            let actual = recipes(&document);
            for family in [
                "miri-quarter-",
                "fuzz-compile-quarter-",
                "fuzz-execute-quarter-",
            ] {
                for quarter in ["one", "two", "three", "four"] {
                    assert!(
                        actual.contains(&format!("{family}{quarter}")),
                        "{file}: missing {family}{quarter}"
                    );
                }
            }
            assert!(
                !actual
                    .iter()
                    .any(|recipe| recipe.ends_with("-first") || recipe.ends_with("-second")),
                "old half-shard inventory returned"
            );
        }
    }
    for document in sources("backend-certification.yml") {
        let actual = recipes(&document);
        for required in [
            "backend-macos-watchdog",
            "release-macos-native",
            "release-macos-acceptance",
            "backend-linux-private-prepare",
            "backend-linux-private-runtime",
            "backend-linux-cgroup",
            "backend-windows-job",
        ] {
            assert!(
                actual.contains(required),
                "missing optional native work: {required}"
            );
        }
        assert_eq!(
            document["jobs"]["windows-installed-x64"]["needs"],
            "windows-payload-x64"
        );
    }
}

fn visit_strings(value: &Value, f: &mut impl FnMut(&str)) {
    match value {
        Value::String(text) => f(text),
        Value::Mapping(fields) => {
            for (_, v) in fields {
                visit_strings(v, f);
            }
        }
        Value::Sequence(items) => {
            for v in items {
                visit_strings(v, f);
            }
        }
        _ => (),
    }
}

#[test]
fn actual_steps_have_no_dangling_references_or_command_environment_bridge() {
    for file in workflow_definitions::FILES {
        for document in sources(file) {
            assert_eq!(document["permissions"]["contents"], "read");
            for (job_name, job) in document["jobs"].as_mapping().unwrap() {
                let Some(sequence) = job["steps"].as_sequence() else {
                    continue;
                };
                let ids = sequence
                    .iter()
                    .filter_map(|step| step["id"].as_str())
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    ids.len(),
                    sequence.iter().filter(|s| s["id"].is_string()).count(),
                    "duplicate id: {file}/{job_name:?}"
                );
                visit_strings(job, &mut |text| {
                    for tail in text.split("steps.").skip(1) {
                        let reference = tail.split('.').next().unwrap();
                        assert!(
                            ids.contains(reference),
                            "{file}/{job_name:?}: dangling steps.{reference}"
                        );
                    }
                    assert!(!text.contains("toJSON(steps)") && !text.contains("CI_STEPS"));
                });
                for step in sequence {
                    if let Some(command) = step["run"].as_str() {
                        assert!(!command.contains("${{") && !command.contains('\n'));
                        assert!(!step["shell"].is_string());
                        if command.contains(" ci segment ") {
                            assert!(
                                step["continue-on-error"].is_null(),
                                "required work became optional"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn publishers_and_rehearsal_require_exact_tools_and_rehearsal_graph() {
    for document in sources("release.yml") {
        for name in [
            "publish",
            "recovery-publish",
            "rehearse",
            "recovery-rehearse",
        ] {
            let sequence = steps(&document, name);
            assert!(sequence.iter().all(|step| {
                !step["run"].as_str().is_some_and(|run| {
                    run.contains("ci-runtime") || run.contains("driver-bootstrap")
                })
            }));
        }
        assert!(
            document["jobs"]["publish"]["needs"]
                .as_sequence()
                .unwrap()
                .iter()
                .any(|need| need == "rehearse")
        );
        assert!(
            document["jobs"]["recovery-publish"]["needs"]
                .as_sequence()
                .unwrap()
                .iter()
                .any(|need| need == "recovery-rehearse")
        );
        let select = steps(&document, "select");
        assert!(
            select
                .iter()
                .any(|s| s["run"]
                    .as_str()
                    .is_some_and(|run| run.contains(
                        "cargo build --locked --release --target-dir target/ci-driver-cold"
                    ) && run.ends_with("--bin memcordon-ci"))),
            "publication tool producer must actually compile current source"
        );
    }
}

#[test]
fn required_work_and_environment_boundaries_are_enforced() {
    let root = root();
    let configuration = config::policy(&root).unwrap();
    for file in workflow_definitions::FILES {
        let relative = Path::new(".github/workflows").join(file);
        let document = workflow_definitions::definition(file).unwrap();
        policy::validate_workflow_bytes(
            &root,
            &relative,
            serde_yaml::to_string(&document).unwrap().as_bytes(),
            &configuration,
        )
        .unwrap();
        let (job_name, index) = document["jobs"]
            .as_mapping()
            .unwrap()
            .iter()
            .find_map(|(name, job)| {
                job["steps"]
                    .as_sequence()?
                    .iter()
                    .position(|step| {
                        step["run"]
                            .as_str()
                            .is_some_and(|run| run.contains(" ci segment "))
                    })
                    .map(|index| (name.as_str().unwrap().to_owned(), index))
            })
            .unwrap();
        for mutation in ["environment", "required-optional"] {
            let mut changed = document.clone();
            let work = &mut changed["jobs"][&job_name]["steps"][index];
            match mutation {
                "environment" => {
                    work["env"] = serde_yaml::from_str("CI_STEPS: '${{ toJSON(steps) }}'").unwrap();
                }
                "required-optional" => work["continue-on-error"] = true.into(),
                _ => unreachable!(),
            }
            let error = workflow_definitions::validate_semantics(&changed)
                .unwrap_err()
                .to_string();
            let expected = match mutation {
                "environment" => "environment bridge",
                "required-optional" => "required work became optional",
                _ => unreachable!(),
            };
            assert!(
                error.contains(expected),
                "{file}/{mutation}: wrong semantic reason: {error}"
            );
        }
    }
}
