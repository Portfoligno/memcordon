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

#[test]
fn assessed_producers_use_one_exact_matrix_derived_job_name() {
    let workflow: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    check(&workflow).unwrap();
    for producer in [
        "native-linux-x64",
        "candidate-linux-x64-native",
        "public-linux-x64-native",
    ] {
        for mutation in [
            "missing-name",
            "static-name",
            "other-expression",
            "wrong-producer",
            "duplicate-row",
            "additional-axis",
        ] {
            let mut changed = workflow.clone();
            let job = &mut changed["jobs"][producer];
            match mutation {
                "missing-name" => {
                    job.as_mapping_mut()
                        .unwrap()
                        .remove(Value::String("name".into()));
                }
                "static-name" => job["name"] = producer.into(),
                "other-expression" => job["name"] = "${{ matrix.target }}".into(),
                "wrong-producer" => {
                    job["strategy"]["matrix"]["include"][0]["producer-job"] =
                        "unrelated-producer".into();
                }
                "duplicate-row" => {
                    let rows = job["strategy"]["matrix"]["include"]
                        .as_sequence_mut()
                        .unwrap();
                    rows.push(rows[0].clone());
                }
                "additional-axis" => {
                    job["strategy"]["matrix"]["extra"] =
                        serde_yaml::from_str("[first, second]").unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                check(&changed).is_err(),
                "{producer} accepted {mutation} in assessed job identity"
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
                "./.release/tool/memcordon-ci release assemble --build-source .release/build-source.json --consumer-readiness --destination .release/assembled",
            )
    });
    let stable = memcordon_ci::config::toolchains(&root()).unwrap().stable;
    assert!(
        steps[..assembly].iter().any(|step| {
            step["run"].as_str().is_some_and(|run| {
                run.split_whitespace().collect::<Vec<_>>()
                    == [
                        "rustup",
                        "toolchain",
                        "install",
                        stable.as_str(),
                        "--profile",
                        "minimal",
                    ]
            }) && step["if"].is_null()
                && step["continue-on-error"].is_null()
        }),
        "assembly must install the pinned Cargo toolchain before source metadata validation"
    );
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
fn public_readiness_owners_cannot_drop_cleanup_or_rewrite_original_publication_dependencies() {
    let workflow: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    check(&workflow).unwrap();
    let mut missing = workflow.clone();
    missing["jobs"]
        .as_mapping_mut()
        .unwrap()
        .remove(Value::String("public-linux-arm64-cargo".into()));
    assert!(check(&missing).is_err());
    let mut skipped = workflow.clone();
    let steps = skipped["jobs"]["public-windows-x64-native"]["steps"]
        .as_sequence_mut()
        .unwrap();
    let cleanup = unique_step(steps, "required public Windows cleanup", |step| {
        step["id"].as_str() == Some("readiness-cleanup")
    });
    assert_eq!(
        steps[cleanup]["run"].as_str(),
        Some(
            "./target/ci-driver-cold/release/consumer-readiness.exe cleanup --github-context --driver ./target/ci-runtime/current/memcordon-ci.exe --identity .release/readiness-identity.json --destination .release/readiness-cell"
        )
    );
    steps[cleanup]["if"] = Value::String("success()".into());
    assert!(check(&skipped).is_err());
    let mut fresh_candidate = workflow.clone();
    fresh_candidate["jobs"]["public-linux-x64-native"]["needs"]
        .as_sequence_mut()
        .unwrap()
        .push(Value::String("candidate-linux-x64-native".into()));
    assert!(check(&fresh_candidate).is_err());
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
    assert!(steps[..quality].iter().any(|step| {
        step["run"].as_str()
            == Some(
                "rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt",
            )
            && step["if"].is_null()
            && step["continue-on-error"].is_null()
    }));
}

#[test]
fn original_native_component_jobs_preserve_execution_cleanup_and_immutable_upload() {
    let original: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    check(&original).unwrap();
    for job in [
        "native-linux-x64",
        "native-linux-arm64",
        "native-windows-x64",
        "native-windows-arm64",
    ] {
        for mutation in 0..7 {
            let mut changed = original.clone();
            let steps = changed["jobs"][job]["steps"].as_sequence_mut().unwrap();
            match mutation {
                0 => {
                    let position = steps
                        .iter()
                        .position(|step| step["id"].as_str() == Some("native_readiness"))
                        .unwrap();
                    steps.remove(position);
                }
                1 => {
                    let cleanup = steps
                        .iter_mut()
                        .find(|step| step["id"].as_str() == Some("native_readiness_cleanup"))
                        .unwrap();
                    cleanup["if"] = Value::String("success()".into());
                }
                2 => {
                    let upload = steps
                        .iter_mut()
                        .find(|step| {
                            step["with"]["path"].as_str() == Some(".release/native-readiness")
                        })
                        .unwrap();
                    upload["with"]["overwrite"] = Value::Bool(true);
                }
                3 | 4 => {
                    let cleanup = steps
                        .iter_mut()
                        .find(|step| step["id"].as_str() == Some("native_readiness_cleanup"))
                        .unwrap();
                    cleanup["if"] = if mutation == 3 {
                        "always() && (runner.os == 'Linux' || runner.os == 'Windows')".into()
                    } else {
                        cleanup["if"]
                            .as_str()
                            .unwrap()
                            .replace(" || steps.native_readiness.outcome == 'cancelled'", "")
                            .into()
                    };
                }
                _ => {
                    let upload = steps
                        .iter_mut()
                        .find(|step| {
                            step["with"]["path"].as_str() == Some(".release/native-readiness")
                        })
                        .unwrap();
                    upload["if"] = if mutation == 5 {
                        "always() && (runner.os == 'Linux' || runner.os == 'Windows')".into()
                    } else {
                        upload["if"]
                            .as_str()
                            .unwrap()
                            .replace(" || steps.native_readiness.outcome == 'cancelled'", "")
                            .into()
                    };
                }
            }
            assert!(
                check(&changed).is_err(),
                "{job} original producer mutation {mutation}"
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
    let readiness = unique_step(steps, "selected required readiness", |step| {
        step["id"] == "readiness"
    });
    assert_eq!(
        steps[readiness]["run"],
        "./target/ci/release/consumer-readiness acquire --github-context --driver ./target/ci-runtime/current/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell"
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
                    serde_yaml::from_str("[select, readiness-tools-linux-x64, packages]").unwrap()
            }
            "wrongtarget" => {
                changed["jobs"]["candidate-linux-x64-native"]["needs"] = serde_yaml::from_str(
                    "[select, packages, readiness-tools-linux-x64, native-linux-arm64]",
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
        let saves: Vec<_> = steps
            .iter()
            .enumerate()
            .filter(|(_, step)| {
                step["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
            })
            .map(|(index, _)| index)
            .collect();
        assert!(!saves.is_empty(), "{job} cache owner must be exercised");
        let selected = unique_step(steps, "selected installed channel", |step| {
            step["id"].as_str() == Some(channel)
        });
        assert!(steps[selected]["continue-on-error"].is_null());
        for index in saves {
            assert!(
                index < selected,
                "{job} must retain its independent early transfers before installed execution"
            );
            let reference = steps[index]["with"]["key"]
                .as_str()
                .unwrap()
                .strip_prefix("${{ steps.")
                .and_then(|value| value.strip_suffix("-key }}"))
                .unwrap();
            let (owner, slot) = reference.split_once(".outputs.").unwrap();
            assert_eq!(
                steps[index]["with"]["path"],
                format!("${{{{ steps.{owner}.outputs.{slot}-path }}}}")
            );
            let producer = unique_step(steps, "actual Rust retention owner", |step| {
                step["id"].as_str() == Some(owner)
            });
            assert!(producer < index);
            let guard = format!("steps.{owner}.outputs.{slot}-save == 'true'");
            let original = steps[index]["if"].as_str().unwrap();
            let ready = format!("always() && {guard}");
            let expected = if slot.ends_with("partial") {
                ready
            } else {
                format!("{ready} && steps.{owner}-{slot}-probe.outputs.cache-hit != 'true'")
            };
            assert_eq!(
                original, expected,
                "{job} must use exactly its validated transfer owner/class"
            );
            assert!(
                !original.contains(&format!("steps.{channel}.")),
                "later independent installed work cannot gate the earlier transfer"
            );
            let mut changed = baseline.clone();
            changed["jobs"][job]["steps"][index]["if"] = original.replace(&guard, "true").into();
            assert_ne!(changed, baseline);
            assert!(
                check(&changed).is_err(),
                "{job} accepted a transfer without its actual Rust readiness decision"
            );
        }
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
        "staging-cache",
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
                    unique_step(steps, case, |step| step["run"].as_str() == Some(command));
                steps.remove(install);
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
            "staging-cache" => {
                let steps = changed["jobs"]["packages"]["steps"]
                    .as_sequence_mut()
                    .unwrap();
                let restore = unique_step(steps, "package download cache", |step| {
                    step["id"] == "workspace-fetch-request-source-restore"
                        && step["uses"]
                            .as_str()
                            .is_some_and(|uses| uses.starts_with("actions/cache/restore@"))
                });
                steps[restore]["with"]["path"] = Value::String(".release/prepared".into());
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
