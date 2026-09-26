use std::path::{Path, PathBuf};

use memcordon_ci::{config, policy};
use serde_yaml::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn fixture() -> Value {
    serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap()
}
fn validate(value: &Value) -> memcordon_ci::Result<()> {
    let root = root();
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/release.yml"),
        serde_yaml::to_string(value).unwrap().as_bytes(),
        &config::policy(&root).unwrap(),
    )
}
fn reject(change: impl FnOnce(&mut Value)) {
    let mut value = fixture();
    change(&mut value);
    assert!(
        validate(&value).is_err(),
        "mutated release contract was accepted"
    );
}
fn step<'a>(value: &'a mut Value, job: &str, id: &str) -> &'a mut Value {
    value["jobs"][job]["steps"]
        .as_sequence_mut()
        .unwrap()
        .iter_mut()
        .find(|step| step["id"].as_str() == Some(id))
        .unwrap()
}

#[test]
fn exact_release_graph_passes_and_native_union_has_one_writer_per_target() {
    validate(&fixture()).unwrap();
    for job in [
        "linux-native-x64",
        "linux-native-arm64",
        "macos-native",
        "windows-native-x64",
        "windows-native-arm64",
    ] {
        reject(|value| {
            value["jobs"]
                .as_mapping_mut()
                .unwrap()
                .remove(Value::from(job));
        });
        reject(|value| {
            value["jobs"][job]["needs"] = Value::from("preflight");
        });
        reject(|value| {
            let rows = value["jobs"][job]["strategy"]["matrix"]["include"]
                .as_sequence_mut()
                .unwrap();
            rows.push(rows[0].clone());
        });
        reject(|value| {
            value["jobs"][job]["strategy"]["matrix"]["include"][0]["runner"] =
                Value::from("ubuntu-latest");
        });
        reject(|value| {
            step(value, job, "native-target")["with"]["key"] = Value::from("wrong-target-cache");
        });
        reject(|value| {
            let uploads = value["jobs"][job]["steps"].as_sequence_mut().unwrap();
            let upload = uploads
                .iter_mut()
                .find(|step| {
                    step["with"]["name"].as_str() == Some("release-native-${{ matrix.id }}")
                })
                .unwrap();
            upload["with"]["name"] = Value::from("release-native-linux-x64");
        });
    }
    reject(|value| {
        value["jobs"]["assemble"]["needs"]
            .as_sequence_mut()
            .unwrap()
            .retain(|name| name.as_str() != Some("preflight"));
    });
    reject(|value| {
        value["jobs"]["assemble"]["needs"]
            .as_sequence_mut()
            .unwrap()
            .push(Value::from("linux-private-complete-x64"));
    });
}

#[test]
fn windows_chains_reject_cross_architecture_edges_and_development_downgrade() {
    for architecture in ["x64", "arm64"] {
        for phase in ["loader-production", "provider-lifecycle", "package-channel"] {
            let job = format!("windows-{phase}-{architecture}");
            reject(|value| {
                value["jobs"][&job]["needs"] = Value::from(if architecture == "x64" {
                    "windows-native-arm64"
                } else {
                    "windows-native-x64"
                });
            });
            reject(|value| {
                value["jobs"][&job]["needs"] =
                    serde_yaml::to_value(["windows-native-x64", "windows-native-arm64"]).unwrap();
            });
            reject(|value| {
                let suite = value["jobs"][&job]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|step| {
                        step["run"]
                            .as_str()
                            .is_some_and(|run| run.contains("--native-channel"))
                    })
                    .unwrap();
                suite["run"] = Value::from(
                    suite["run"]
                        .as_str()
                        .unwrap()
                        .replace(" --native-channel required-downloaded-archive", ""),
                );
            });
            reject(|value| {
                let download = value["jobs"][&job]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|step| {
                        step["uses"]
                            .as_str()
                            .is_some_and(|action| action.starts_with("actions/download-artifact@"))
                    })
                    .unwrap();
                download["with"]["name"] = Value::from("release-native-windows-opposite");
            });
        }
        let job = format!("windows-package-channel-{architecture}");
        reject(|value| {
            step(value, &job, "package-target")["with"]["path"] =
                Value::from("target/ci/windows-sealed-cargo");
        });
        reject(|value| {
            value["jobs"][&job]["steps"]
                .as_sequence_mut()
                .unwrap()
                .retain(|step| {
                    step["with"]["name"].as_str()
                        != Some("release-windows-provider-lifecycle-${{ matrix.id }}")
                });
        });
    }
}

#[test]
fn complete_halves_and_public_global_host_responsibilities_are_required() {
    for family in ["miri", "fuzz"] {
        reject(|value| {
            value["jobs"][family]["strategy"]["matrix"]["shard"] =
                serde_yaml::to_value(["first"]).unwrap();
        });
        reject(|value| {
            value["jobs"][family]["strategy"]["matrix"]["shard"] =
                serde_yaml::to_value(["first", "first"]).unwrap();
        });
        reject(|value| {
            step(value, family, &format!("{family}-target"))["with"]["key"] =
                Value::from("shared-unsharded-cache");
        });
        reject(|value| {
            let steps = value["jobs"][family]["steps"].as_sequence_mut().unwrap();
            let second = steps
                .iter_mut()
                .find(|step| step["if"].as_str() == Some("matrix.shard == 'second'"))
                .unwrap();
            second["run"] = Value::from(format!(
                "./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci --build-context target/ci/native-inputs.bin suite {family}-first"
            ));
        });
    }
    for job in ["verify-public-global", "verify-public-windows"] {
        reject(|value| {
            value["jobs"]
                .as_mapping_mut()
                .unwrap()
                .remove(Value::from(job));
        });
        reject(|value| {
            value["jobs"][job]["needs"] = Value::from("assemble");
        });
        reject(|value| {
            value["jobs"][job]["steps"]
                .as_sequence_mut()
                .unwrap()
                .retain(|step| {
                    step["run"]
                        .as_str()
                        .is_none_or(|run| !run.contains("release verify-public-"))
                });
        });
    }
}

#[test]
fn private_custody_chain_has_exact_producers_and_never_replaces_public_gate() {
    for architecture in ["x64", "arm64"] {
        let candidate = format!("linux-private-candidate-{architecture}");
        reject(|value| {
            value["jobs"][&candidate]["needs"]
                .as_sequence_mut()
                .unwrap()
                .retain(|name| name.as_str() != Some("preflight"));
        });
        for role in ["q", "seal", "final", "p", "complete"] {
            let job = format!("linux-private-{role}-{architecture}");
            reject(|value| {
                value["jobs"]
                    .as_mapping_mut()
                    .unwrap()
                    .remove(Value::from(job.as_str()));
            });
            reject(|value| {
                value["jobs"][&job]["needs"] = Value::from("linux-private-candidate-inputs-x64");
            });
            reject(|value| {
                value["jobs"][&job]["if"] = Value::from("always()");
            });
            reject(|value| {
                value["jobs"][&job]["permissions"]["actions"] = Value::from("none");
            });
            reject(|value| {
                let download = value["jobs"][&job]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|step| {
                        step["uses"]
                            .as_str()
                            .is_some_and(|action| action.starts_with("actions/download-artifact@"))
                    })
                    .unwrap();
                download["with"]["name"] = Value::from("release-private-final-x64");
            });
        }
        let seal = format!("linux-private-seal-{architecture}");
        reject(|value| {
            let upload = value["jobs"][&seal]["steps"]
                .as_sequence_mut()
                .unwrap()
                .iter_mut()
                .find(|step| step["uses"].as_str() == Some("./.github/actions/upload-artifact"))
                .unwrap();
            upload["with"]["name"] = Value::from("release-private-public-raw-x64");
        });
    }
}
