use memcordon_ci::policy;
use serde_yaml::Value;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn check(document: &Value) -> memcordon_ci::Result<()> {
    policy::validate_workflow_bytes(
        &root(),
        Path::new(".github/workflows/release.yml"),
        serde_yaml::to_string(document)?.as_bytes(),
        &memcordon_ci::config::policy(&root())?,
    )
}

fn unique_step(steps: &[Value], role: &str, predicate: impl Fn(&Value) -> bool) -> usize {
    let matches: Vec<_> = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| predicate(step))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(matches.len(), 1, "{role} must identify exactly one step");
    matches[0]
}

fn earliest_toolchain_consumer(steps: &[Value]) -> usize {
    steps
        .iter()
        .position(|step| {
            step["run"].as_str().is_some_and(|run| {
                run.starts_with("rustup run ") || run.starts_with("./.release/tool/memcordon-ci ")
            })
        })
        .expect("required metadata or compilation consumer")
}

// Independent parsed-graph contract: never ask the authoring helper to certify itself.
fn logical_acquisition(
    steps: &[Value],
    command: &str,
    before: usize,
) -> Result<std::ops::Range<usize>, String> {
    let matching: Vec<_> = steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| (step["run"].as_str() == Some(command)).then_some(index))
        .collect();
    if matching.len() != 3 {
        return Err("exactly three pinned acquisition attempts required".into());
    }
    let start = matching[0];
    if matching != [start, start + 1, start + 2] || start + 2 >= before {
        return Err("complete adjacent acquisition must precede earliest consumer".into());
    }
    let group = &steps[start..start + 3];
    let mut ids = std::collections::BTreeSet::new();
    let mut total = 0;
    for (index, step) in group.iter().enumerate() {
        let id = step["id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or("missing acquisition id")?;
        if !ids.insert(id)
            || steps
                .iter()
                .filter(|step| step["id"].as_str() == Some(id))
                .count()
                != 1
        {
            return Err("duplicate acquisition id".into());
        }
        for field in ["env", "working-directory", "shell"] {
            if !step[field].is_null() {
                return Err(format!("unexpected acquisition context: {field}"));
            }
        }
        if index == 0 {
            if !step["if"].is_null() {
                return Err("initial acquisition must be unconditional".into());
            }
        } else {
            let previous = group[index - 1]["id"]
                .as_str()
                .ok_or("missing predecessor id")?;
            let guard = format!("${{{{ !cancelled() && steps.{previous}.outcome == 'failure' }}}}");
            if step["if"].as_str() != Some(&guard) {
                return Err("acquisition retry guard differs".into());
            }
        }
        if (index < 2 && step["continue-on-error"] != true)
            || (index == 2 && !step["continue-on-error"].is_null())
        {
            return Err("only first two attempts may be optional".into());
        }
        let minutes = step["timeout-minutes"]
            .as_u64()
            .ok_or("missing attempt timeout")?;
        if minutes != 5 {
            return Err("acquisition attempt must retain five-minute allowance".into());
        }
        total += minutes;
    }
    if total != 15 {
        return Err("acquisition configured total must remain fifteen minutes".into());
    }
    Ok(start..start + 3)
}

#[test]
fn logical_toolchain_acquisition_rejects_each_unsafe_shape_before_any_consumer() {
    let workflow: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    for (job, command) in [
        (
            "assemble-payload",
            "rustup toolchain install 1.97.1 --profile minimal",
        ),
        (
            "source-checks",
            "rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt",
        ),
    ] {
        let baseline = workflow["jobs"][job]["steps"].as_sequence().unwrap();
        let group =
            logical_acquisition(baseline, command, earliest_toolchain_consumer(baseline)).unwrap();
        for case in [
            "remove-first",
            "remove-second",
            "remove-third",
            "remove-all",
            "duplicate",
            "separate",
            "pin",
            "components",
            "context",
            "all-context",
            "optional-final",
            "conditional-first",
            "conclusion",
            "predecessor",
            "cancel",
            "timeout",
            "duplicate-id",
            "late-member",
            "late-group",
        ] {
            let mut changed = baseline.clone();
            let start = group.start;
            match case {
                "remove-first" => {
                    changed.remove(start);
                }
                "remove-second" => {
                    changed.remove(start + 1);
                }
                "remove-third" => {
                    changed.remove(start + 2);
                }
                "remove-all" => {
                    changed.drain(group.clone());
                }
                "duplicate" => {
                    changed.insert(start, changed[start].clone());
                }
                "separate" => {
                    changed.insert(
                        start + 1,
                        serde_yaml::from_str("run: echo unrelated").unwrap(),
                    );
                }
                "pin" => changed[start + 1]["run"] = command.replace("1.97.1", "1.97.0").into(),
                "components" => {
                    changed[start + 1]["run"] = format!("{command} --component rust-src").into()
                }
                "context" => changed[start + 1]["working-directory"] = "elsewhere".into(),
                "all-context" => {
                    for step in &mut changed[group.clone()] {
                        step["working-directory"] = "elsewhere".into();
                    }
                }
                "optional-final" => changed[start + 2]["continue-on-error"] = true.into(),
                "conditional-first" => changed[start]["if"] = false.into(),
                "conclusion" => {
                    let guard = changed[start + 1]["if"]
                        .as_str()
                        .unwrap()
                        .replace(".outcome", ".conclusion");
                    changed[start + 1]["if"] = guard.into();
                }
                "predecessor" => {
                    changed[start + 2]["if"] =
                        "${{ !cancelled() && steps.unknown.outcome == 'failure' }}".into()
                }
                "cancel" => {
                    let guard = changed[start + 1]["if"]
                        .as_str()
                        .unwrap()
                        .replace("!cancelled() && ", "");
                    changed[start + 1]["if"] = guard.into();
                }
                "timeout" => changed[start + 2]["timeout-minutes"] = 6.into(),
                "duplicate-id" => changed[start + 2]["id"] = changed[start]["id"].clone(),
                "late-member" => {
                    let member = changed.remove(start + 2);
                    let consumer = earliest_toolchain_consumer(&changed);
                    changed.insert(consumer + 1, member);
                }
                "late-group" => {
                    let members: Vec<_> = changed.drain(group.clone()).collect();
                    let consumer = earliest_toolchain_consumer(&changed);
                    changed.splice(consumer + 1..consumer + 1, members);
                }
                _ => unreachable!(),
            }
            assert!(
                logical_acquisition(&changed, command, earliest_toolchain_consumer(&changed))
                    .is_err(),
                "{job}/{case}"
            );
        }
    }
}

#[test]
fn release_assembly_provisions_selected_metadata_toolchain_before_rechecking_source() {
    let workflow: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    check(&workflow).unwrap();
    let steps = workflow["jobs"]["assemble-payload"]["steps"]
        .as_sequence()
        .unwrap();
    let assembly = unique_step(steps, "early assembly", |step| {
        step["run"].as_str()
            == Some(
                "./.release/tool/memcordon-ci release assemble --build-source .release/build-source.json --runtime-components --destination .release/assembled",
            )
    });
    let stable = memcordon_ci::config::toolchains(&root()).unwrap().stable;
    let acquisition = logical_acquisition(
        steps,
        &format!("rustup toolchain install {stable} --profile minimal"),
        earliest_toolchain_consumer(steps),
    )
    .unwrap();
    assert!(acquisition.end <= assembly);
    for target in [
        "linux-x64",
        "linux-arm64",
        "macos-x64",
        "macos-arm64",
        "windows-x64",
        "windows-arm64",
    ] {
        let path = format!(".release/targets/{target}");
        let download = unique_step(steps, &path, |step| {
            step["with"]["path"].as_str() == Some(&path)
        });
        assert!(download < assembly);
        assert_eq!(
            steps[download]["with"]["artifact-ids"],
            format!("${{{{ needs.native-{target}.outputs.artifact-id }}}}")
        );
        assert_eq!(steps[download]["with"]["digest-mismatch"], "error");
    }
    let final_steps = workflow["jobs"]["assemble"]["steps"].as_sequence().unwrap();
    let finalize = unique_step(final_steps, "final handoff", |step| {
        step["run"].as_str()
            == Some(
                "./.release/tool/memcordon-ci release finalize-preparation --build-source .release/build-source.json --input .release/assembled --publisher-archive .release/tool/memcordon-publication-tool.tar.gz --destination .release/final",
            )
    });
    let input = unique_step(final_steps, "assembled input", |step| {
        step["with"]["path"] == ".release/assembled"
    });
    assert!(input < finalize);
    assert_eq!(
        final_steps[input]["with"]["artifact-ids"],
        "${{ needs.assemble-payload.outputs.assembled-artifact-id }}"
    );
    assert!(final_steps.iter().all(|step| {
        step["run"]
            .as_str()
            .is_none_or(|run| !run.contains("cargo ") && !run.contains(" release assemble "))
    }));
}

#[test]
fn windows_release_jobs_configure_lf_before_checkout() {
    let workflow: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    for (name, job) in workflow["jobs"].as_mapping().unwrap() {
        let name = name.as_str().unwrap();
        if !name.starts_with("native-windows-")
            && !name.starts_with("native-components-windows-")
            && !name.starts_with("candidate-windows-")
            && !name.starts_with("public-windows-")
        {
            continue;
        }
        let steps = job["steps"].as_sequence().unwrap();
        let checkout = steps
            .iter()
            .position(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|action| action.starts_with("actions/checkout@"))
            })
            .unwrap();
        assert!(
            steps[..checkout].iter().any(|step| {
                step["run"].as_str() == Some("git config --global core.autocrlf false")
                    && step["if"].is_null()
                    && step["continue-on-error"].is_null()
            }),
            "{name} must establish LF checkout before source materialization"
        );
    }
}

#[test]
fn public_installed_jobs_require_local_tests_and_the_selected_writer() {
    let baseline: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    check(&baseline).unwrap();
    for job in ["public-linux-x64-native", "public-windows-arm64-cargo"] {
        let mut changed = baseline.clone();
        let steps = changed["jobs"][job]["steps"].as_sequence_mut().unwrap();
        let test = unique_step(steps, "direct installed test", |step| {
            step["id"] == "installed-test"
        });
        assert!(
            steps[test]["run"]
                .as_str()
                .unwrap()
                .contains(" release test-installed --delivery public-")
        );
        assert!(steps[test]["continue-on-error"].is_null());
        steps[test]["continue-on-error"] = true.into();
        assert!(check(&changed).is_err());
        let mut changed = baseline.clone();
        changed["jobs"][job]["if"] = "always()".into();
        assert!(check(&changed).is_err());
    }
}

#[test]
fn release_quality_installs_required_components_before_running_the_suite() {
    let workflow: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    let steps = workflow["jobs"]["source-checks"]["steps"]
        .as_sequence()
        .unwrap();
    check(&workflow).unwrap();
    let quality = unique_step(steps, "quality compilation", |step| {
        step["run"].as_str()
            == Some("./.release/tool/memcordon-ci ci segment release-quality-compiler")
    });
    let acquisition = logical_acquisition(
        steps,
        "rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt",
        earliest_toolchain_consumer(steps),
    )
    .unwrap();
    assert!(acquisition.end <= quality);
}

#[test]
fn source_component_failures_are_required_local_job_failures() {
    let baseline: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    check(&baseline).unwrap();
    for host in ["linux-x64", "linux-arm64", "windows-x64", "windows-arm64"] {
        let job = format!("native-components-{host}");
        let mut absent = baseline.clone();
        absent["jobs"]
            .as_mapping_mut()
            .unwrap()
            .remove(job.as_str());
        assert!(check(&absent).is_err(), "missing {job}");
        let mut changed = baseline.clone();
        let steps = changed["jobs"][&job]["steps"].as_sequence_mut().unwrap();
        let test = unique_step(steps, "native components", |step| {
            step["run"]
                .as_str()
                .is_some_and(|command| command.contains(" release test-components "))
        });
        assert!(steps[test]["continue-on-error"].is_null());
        steps[test]["continue-on-error"] = true.into();
        assert!(check(&changed).is_err());
        let producer = format!("native-{host}");
        assert!(
            baseline["jobs"][&job]["needs"]
                .as_sequence()
                .unwrap()
                .contains(&Value::String(producer))
        );
        for consumer in ["assemble-payload", "assemble"] {
            assert!(
                baseline["jobs"][consumer]["needs"]
                    .as_sequence()
                    .unwrap()
                    .contains(&Value::String(job.clone())),
                "{consumer} must require {job}"
            );
        }
        for (consumer, definition) in baseline["jobs"].as_mapping().unwrap() {
            if let Some(needs) = definition["needs"].as_sequence()
                && needs.contains(&Value::String(job.clone()))
            {
                let mut changed = baseline.clone();
                changed["jobs"][consumer]["needs"]
                    .as_sequence_mut()
                    .unwrap()
                    .retain(|need| need.as_str() != Some(job.as_str()));
                assert!(
                    check(&changed).is_err(),
                    "{consumer:?} lost required component success for {host}"
                );
            }
        }
    }
}

#[test]
fn candidate_validation_peers_require_only_their_actual_inputs() {
    let baseline: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    check(&baseline).unwrap();
    for host in ["linux-x64", "linux-arm64", "windows-x64", "windows-arm64"] {
        let native = format!("native-{host}");
        let tools = format!("test-tools-{host}");
        let components = format!("native-components-{host}");
        for missing in ["select", &native, &tools] {
            let mut changed = baseline.clone();
            changed["jobs"][&components]["needs"]
                .as_sequence_mut()
                .unwrap()
                .retain(|need| need.as_str() != Some(missing));
            assert_ne!(changed, baseline);
            assert!(check(&changed).is_err(), "{components} lost {missing}");
        }
        for channel in ["native", "cargo"] {
            let candidate = format!("candidate-{host}-{channel}");
            let needs = baseline["jobs"][&candidate]["needs"].as_sequence().unwrap();
            assert_eq!(needs.len(), 4, "{candidate} waits only for actual inputs");
            for missing in ["select", "packages", &native, &tools] {
                assert!(needs.contains(&Value::String(missing.into())));
                let mut changed = baseline.clone();
                changed["jobs"][&candidate]["needs"]
                    .as_sequence_mut()
                    .unwrap()
                    .retain(|need| need.as_str() != Some(missing));
                assert_ne!(changed, baseline);
                assert!(check(&changed).is_err(), "{candidate} lost {missing}");
            }
            let mut changed = baseline.clone();
            changed["jobs"][&candidate]["needs"]
                .as_sequence_mut()
                .unwrap()
                .push(Value::String(components.clone()));
            assert!(
                check(&changed).is_err(),
                "{candidate} regained the unrelated {components} gate"
            );
        }
    }
}

#[test]
fn release_graph_retains_six_native_consumers_and_isolated_publisher() {
    let baseline: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    check(&baseline).unwrap();
    let mut missing = baseline.clone();
    missing["jobs"]
        .as_mapping_mut()
        .unwrap()
        .remove(Value::String("native-linux-arm64".into()));
    assert!(check(&missing).is_err());
    let mut checkout = baseline.clone();
    checkout["jobs"]["publish"]["steps"].as_sequence_mut().unwrap().push(serde_yaml::from_str(
        "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\nwith:\n  persist-credentials: false\n").unwrap());
    assert!(check(&checkout).is_err());
    let mut cancel = baseline.clone();
    cancel["jobs"]["publish"]["concurrency"]["cancel-in-progress"] = Value::Bool(true);
    assert!(check(&cancel).is_err());
    let mut skip = baseline.clone();
    let steps = skip["jobs"]["candidate-linux-x64-native"]["steps"]
        .as_sequence_mut()
        .unwrap();
    let readiness = unique_step(steps, "selected installed test", |step| {
        step["id"] == "installed-test"
    });
    assert_eq!(
        steps[readiness]["run"],
        "./target/ci-runtime/current/memcordon-ci release test-installed --delivery candidate-native --target .release/target --packages .release/packages --diagnostics target/ci/reports/installed"
    );
    assert!(steps[readiness]["continue-on-error"].is_null());
    steps[readiness]["continue-on-error"] = Value::Bool(true);
    assert_ne!(
        skip, baseline,
        "readiness mutation must change the actual required owner"
    );
    assert!(check(&skip).is_err());
}

#[test]
fn assembly_and_targetlocal_dependencies_preserve_every_selected_leaf() {
    let baseline: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    check(&baseline).unwrap();
    for leaf in [
        "select",
        "packages",
        "source-checks",
        "source-docs",
        "msrv",
        "supply-chain-audit",
        "supply-chain-deny",
        "assemble-payload",
        "rehearse",
        "miri",
        "fuzz",
        "native-linux-x64",
        "native-linux-arm64",
        "native-macos-x64",
        "native-macos-arm64",
        "native-windows-x64",
        "native-windows-arm64",
        "native-components-linux-x64",
        "native-components-linux-arm64",
        "native-components-windows-x64",
        "native-components-windows-arm64",
        "candidate-linux-x64-native",
        "candidate-linux-x64-cargo",
        "candidate-linux-arm64-native",
        "candidate-linux-arm64-cargo",
        "installed-macos-x64-native",
        "installed-macos-x64-cargo",
        "installed-macos-arm64-native",
        "installed-macos-arm64-cargo",
        "candidate-windows-x64-native",
        "candidate-windows-x64-cargo",
        "candidate-windows-arm64-native",
        "candidate-windows-arm64-cargo",
    ] {
        let mut changed = baseline.clone();
        let needs = changed["jobs"]["assemble"]["needs"]
            .as_sequence_mut()
            .unwrap();
        let index = unique_step(needs, leaf, |need| need.as_str() == Some(leaf));
        needs.remove(index);
        assert_ne!(changed, baseline, "missing {leaf} mutation was empty");
        assert!(
            check(&changed).is_err(),
            "final handoff accepted missing {leaf}"
        );
    }
    for case in ["serialproducer", "wrongtarget", "partialshards"] {
        let mut changed = baseline.clone();
        match case {
            "serialproducer" => {
                changed["jobs"]["native-linux-x64"]["needs"] =
                    serde_yaml::from_str("[select, test-tools-linux-x64, packages]").unwrap()
            }
            "wrongtarget" => {
                changed["jobs"]["candidate-linux-x64-native"]["needs"] = serde_yaml::from_str(
                    "[select, packages, test-tools-linux-x64, native-linux-arm64]",
                )
                .unwrap()
            }
            "partialshards" => {
                changed["jobs"]["miri"]["strategy"]["matrix"]["shard"]
                    .as_sequence_mut()
                    .unwrap()
                    .pop();
            }
            _ => unreachable!(),
        }
        assert_ne!(changed, baseline, "{case} mutation was empty");
        assert!(check(&changed).is_err(), "{case}");
    }
    for (job, target, channel) in [
        ("installed-macos-x64-native", "macos-x64", "native"),
        ("installed-macos-x64-cargo", "macos-x64", "cargo"),
        ("installed-macos-arm64-native", "macos-arm64", "native"),
        ("installed-macos-arm64-cargo", "macos-arm64", "cargo"),
    ] {
        let matrix = baseline["jobs"][job]["strategy"]["matrix"]["include"]
            .as_sequence()
            .unwrap();
        assert_eq!(matrix.len(), 1);
        assert_eq!(matrix[0]["channel"], channel);
        assert_eq!(matrix[0]["native-job"], format!("native-{target}"));
        let steps = baseline["jobs"][job]["steps"].as_sequence().unwrap();
        let selected = unique_step(steps, "selected installed channel", |step| {
            step["id"].as_str() == Some("installed-test")
        });
        assert!(steps[selected]["continue-on-error"].is_null());
        let mut optional = baseline.clone();
        optional["jobs"][job]["steps"][selected]["continue-on-error"] = true.into();
        assert!(
            check(&optional).is_err(),
            "{job} selected installed work must still fail normally"
        );
    }
}

#[test]
fn preparation_event_prerequisite_and_immutable_routing_mutations_fail() {
    let baseline: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    check(&baseline).unwrap();
    for case in [
        "branches",
        "moving-ref",
        "lf",
        "quality-components",
        "assembly-toolchain",
        "native-budget",
        "writer-event",
        "recovery-writer-event",
        "wildcard",
        "overwrite",
        "hidden",
        "diagnostic-fatal",
    ] {
        let mut changed = baseline.clone();
        match case {
            "branches" => changed["on"]["push"]["branches"] = Value::Null,
            "moving-ref" => {
                let steps = changed["jobs"]["select"]["steps"]
                    .as_sequence_mut()
                    .unwrap();
                let checkout = unique_step(steps, "selected checkout", |step| {
                    step["uses"]
                        .as_str()
                        .is_some_and(|uses| uses.starts_with("actions/checkout@"))
                });
                assert_eq!(steps[checkout]["with"]["ref"], "${{ github.sha }}");
                steps[checkout]["with"]["ref"] = Value::String("${{ github.ref }}".into())
            }
            "lf" => {
                let steps = changed["jobs"]["native-windows-arm64"]["steps"]
                    .as_sequence_mut()
                    .unwrap();
                let configure = unique_step(steps, "Windows LF configuration", |step| {
                    step["run"] == "git config --global core.autocrlf false"
                });
                steps.remove(configure);
            }
            "quality-components" | "assembly-toolchain" => {
                let job = if case == "quality-components" {
                    "source-checks"
                } else {
                    "assemble-payload"
                };
                let command = if case == "quality-components" {
                    "rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt"
                } else {
                    "rustup toolchain install 1.97.1 --profile minimal"
                };
                let steps = changed["jobs"][job]["steps"].as_sequence_mut().unwrap();
                let install =
                    logical_acquisition(steps, command, earliest_toolchain_consumer(steps))
                        .unwrap();
                steps.drain(install);
            }
            "native-budget" => {
                changed["jobs"]["native-linux-x64"]["timeout-minutes"] = Value::Number(90.into())
            }
            "writer-event" | "recovery-writer-event" => {
                let job = if case == "writer-event" {
                    "publish"
                } else {
                    "recovery-publish"
                };
                changed["jobs"][job]["if"] = Value::String("always()".into());
            }
            "wildcard" => {
                let steps = changed["jobs"]["assemble-payload"]["steps"]
                    .as_sequence_mut()
                    .unwrap();
                let download = unique_step(steps, "immutable Linux input", |step| {
                    step["with"]["path"] == ".release/targets/linux-x64"
                });
                steps[download]["with"]["pattern"] = Value::String("native-*".into());
            }
            "overwrite" | "hidden" => {
                let step = changed["jobs"]["packages"]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|step| step["id"].as_str() == Some("payload"))
                    .unwrap();
                step["with"][if case == "overwrite" {
                    "overwrite"
                } else {
                    "include-hidden-files"
                }] = Value::Bool(case == "overwrite");
            }
            "diagnostic-fatal" => {
                let steps = changed["jobs"]["source-checks"]["steps"]
                    .as_sequence_mut()
                    .unwrap();
                let diagnostic = unique_step(steps, "bounded source diagnostics", |step| {
                    step["name"] == "Retain bounded preparation diagnostics"
                });
                assert_eq!(steps[diagnostic]["continue-on-error"], true);
                steps[diagnostic]["continue-on-error"] = Value::Bool(false);
            }
            _ => unreachable!(),
        }
        assert_ne!(changed, baseline, "mutation {case} was empty");
        assert!(check(&changed).is_err(), "mutation {case} must fail");
    }
    for target in [
        "linux-x64",
        "linux-arm64",
        "macos-x64",
        "macos-arm64",
        "windows-x64",
        "windows-arm64",
    ] {
        let mut changed = baseline.clone();
        let steps = changed["jobs"]["assemble-payload"]["steps"]
            .as_sequence_mut()
            .unwrap();
        let path = format!(".release/targets/{target}");
        let download = unique_step(steps, &path, |step| {
            step["with"]["path"].as_str() == Some(&path)
        });
        assert_eq!(
            steps[download]["with"]["artifact-ids"],
            format!("${{{{ needs.native-{target}.outputs.artifact-id }}}}")
        );
        steps[download]["with"]["artifact-ids"] =
            "${{ needs.packages.outputs.artifact-id }}".into();
        assert_ne!(changed, baseline);
        assert!(
            check(&changed).is_err(),
            "accepted wrong immutable producer for {target}"
        );
    }
    for case in [
        "assembled-route",
        "assembled-missing",
        "assembled-duplicate",
        "assembled-after-finalize",
        "assembled-optional",
        "assembled-skipped",
        "assembled-digest",
        "finalizer-rebuild",
    ] {
        let mut changed = baseline.clone();
        let steps = changed["jobs"]["assemble"]["steps"]
            .as_sequence_mut()
            .unwrap();
        if case != "finalizer-rebuild" {
            let download = unique_step(steps, "assembled input", |step| {
                step["with"]["path"] == ".release/assembled"
            });
            assert_eq!(
                steps[download]["with"]["artifact-ids"],
                "${{ needs.assemble-payload.outputs.assembled-artifact-id }}"
            );
            match case {
                "assembled-route" => {
                    steps[download]["with"]["artifact-ids"] =
                        "${{ needs.packages.outputs.artifact-id }}".into()
                }
                "assembled-missing" => {
                    steps.remove(download);
                }
                "assembled-duplicate" => steps.push(steps[download].clone()),
                "assembled-after-finalize" => {
                    let finalize = unique_step(steps, "final handoff", |step| {
                        step["run"]
                            .as_str()
                            .is_some_and(|run| run.contains(" release finalize-preparation "))
                    });
                    steps.swap(download, finalize);
                }
                "assembled-optional" => steps[download]["continue-on-error"] = true.into(),
                "assembled-skipped" => steps[download]["if"] = false.into(),
                "assembled-digest" => steps[download]["with"]["digest-mismatch"] = "warn".into(),
                _ => unreachable!(),
            }
        } else {
            steps.push(
                serde_yaml::from_str("run: rustup run 1.97.1 cargo check --locked --workspace")
                    .unwrap(),
            );
        }
        assert_ne!(changed, baseline);
        assert!(check(&changed).is_err(), "accepted {case}");
    }
}
