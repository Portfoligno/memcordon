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
