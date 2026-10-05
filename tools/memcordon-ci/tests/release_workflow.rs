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

#[test]
fn release_assembly_provisions_selected_metadata_toolchain_before_rechecking_source() {
    let workflow: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    let steps = workflow["jobs"]["assemble"]["steps"].as_sequence().unwrap();
    let assembly = steps
        .iter()
        .position(|step| {
            step["run"].as_str() == Some("./.release/tool/memcordon-ci release assemble --build-source .release/build-source.json")
        })
        .unwrap();
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
}

#[test]
fn windows_release_jobs_configure_lf_before_checkout() {
    let workflow: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    for (name, job) in workflow["jobs"].as_mapping().unwrap() {
        let name = name.as_str().unwrap();
        if !name.starts_with("native-windows-") && !name.starts_with("installed-windows-") {
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
fn release_quality_installs_required_components_before_running_the_suite() {
    let workflow: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    let steps = workflow["jobs"]["source-checks"]["steps"]
        .as_sequence()
        .unwrap();
    let quality = steps
        .iter()
        .position(|step| {
            step["run"].as_str() == Some("./target/ci/release/memcordon-ci suite quality")
        })
        .unwrap();
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
    for step in skip["jobs"]["installed-linux-x64"]["steps"]
        .as_sequence_mut()
        .unwrap()
    {
        if step["run"].as_str()
            == Some(
                "./target/ci/release/memcordon-ci release installed-consumers --channel native --destination .release/installed-results/native",
            )
        {
            step["continue-on-error"] = Value::Bool(true);
        }
    }
    assert!(check(&skip).is_err());
}

#[test]
fn assembly_and_targetlocal_dependencies_preserve_every_selected_leaf() {
    let baseline: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    for case in [
        "sourcechecks",
        "miri",
        "fuzz",
        "installed",
        "serialproducer",
        "wrongtarget",
        "partialshards",
        "sharedcacheuncertain",
    ] {
        let mut changed = baseline.clone();
        match case {
            "sourcechecks" | "miri" | "fuzz" | "installed" => {
                let missing = match case {
                    "sourcechecks" => "source-checks",
                    "installed" => "installed-windows-arm64-cargo",
                    other => other,
                };
                changed["jobs"]["assemble"]["needs"]
                    .as_sequence_mut()
                    .unwrap()
                    .retain(|need| need.as_str() != Some(missing));
            }
            "serialproducer" => {
                changed["jobs"]["native-linux-x64"]["needs"] =
                    serde_yaml::from_str("[select, packages]").unwrap()
            }
            "wrongtarget" => {
                changed["jobs"]["installed-linux-x64"]["needs"] =
                    serde_yaml::from_str("[select, packages, native-linux-arm64]").unwrap()
            }
            "partialshards" => {
                changed["jobs"]["miri"]["strategy"]["matrix"]["shard"]
                    .as_sequence_mut()
                    .unwrap()
                    .pop();
            }
            "sharedcacheuncertain" => {
                for step in changed["jobs"]["installed-linux-x64"]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                {
                    if step["uses"]
                        .as_str()
                        .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
                    {
                        step["if"] = Value::String(
                            "always() && steps.native.outputs.cache-quiescent == 'true'".into(),
                        );
                    }
                }
            }
            _ => unreachable!(),
        }
        assert!(check(&changed).is_err(), "{case}");
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
                changed["jobs"]["select"]["steps"][1]["with"]["ref"] =
                    Value::String("${{ github.ref }}".into())
            }
            "lf" => {
                changed["jobs"]["native-windows-arm64"]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .remove(0);
            }
            "quality-components" | "assembly-toolchain" => {
                let job = if case == "quality-components" {
                    "source-checks"
                } else {
                    "assemble"
                };
                changed["jobs"][job]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .retain(|step| {
                        !step["run"]
                            .as_str()
                            .is_some_and(|run| run.starts_with("rustup toolchain install 1.97.1"))
                    });
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
                let step = changed["jobs"]["assemble"]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|step| {
                        step["with"]["path"].as_str() == Some(".release/targets/linux-x64")
                    })
                    .unwrap();
                step["with"]["pattern"] = Value::String("native-*".into());
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
                let step = changed["jobs"]["source-checks"]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .last_mut()
                    .unwrap();
                step["continue-on-error"] = Value::Bool(false);
            }
            "staging-cache" => {
                let step = changed["jobs"]["packages"]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|step| {
                        step["uses"]
                            .as_str()
                            .is_some_and(|uses| uses.starts_with("actions/cache/restore@"))
                    })
                    .unwrap();
                step["with"]["path"] = Value::String(".release/prepared".into());
            }
            _ => unreachable!(),
        }
        assert!(check(&changed).is_err(), "mutation {case} must fail");
    }
}
