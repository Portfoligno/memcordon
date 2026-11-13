use memcordon_ci::{config, policy, workflow_definitions};
use std::path::{Path, PathBuf};

#[test]
fn both_architectures_select_the_installed_owner_without_retired_external_cleanup() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let configuration = config::policy(&root).unwrap();
    let workflow = workflow_definitions::definition("backend-certification.yml").unwrap();
    let mut count = 0;
    for job in ["windows-installed-x64", "windows-installed-arm64"] {
        let steps = workflow["jobs"][job]["steps"].as_sequence().unwrap();
        let upload = steps
            .iter()
            .position(|step| step["with"]["path"].as_str() == Some("target/ci/windows-installed"))
            .unwrap();
        assert_eq!(steps[upload]["if"].as_str(), Some("!cancelled()"));
        assert_eq!(
            steps[upload]["with"]["if-no-files-found"].as_str(),
            Some("error")
        );
        assert!(steps[upload]["continue-on-error"].is_null());
        assert!(steps.iter().all(|step| {
            !step["id"]
                .as_str()
                .unwrap_or("")
                .starts_with("loader-cleanup-")
                && !step["run"]
                    .as_str()
                    .unwrap_or("")
                    .contains("cleanup-installed-loader-support")
        }));
        for channel in ["native", "cargo"] {
            let execute = steps
                .iter()
                .position(|step| step["id"].as_str() == Some(channel))
                .unwrap();
            let matches: Vec<_> = steps
                .iter()
                .enumerate()
                .filter(|(_, step)| step["id"].as_str() == Some(channel))
                .collect();
            assert_eq!(matches.len(), 1);
            let (_, step) = matches[0];
            assert!(execute < upload);
            let expected = format!(
                "./target/ci-runtime/current/memcordon-ci.exe release working-windows-consumer --channel {channel} --destination target/ci/windows-installed/{channel}"
            );
            assert_eq!(step["run"].as_str(), Some(expected.as_str()));
            assert_eq!(
                step["if"].as_str(),
                Some(format!("(matrix.channel == '{channel}') && runner.os == 'Windows'").as_str())
            );
            assert_eq!(step["timeout-minutes"].as_u64(), Some(135));
            assert!(step["continue-on-error"].is_null());
            count += 1;
        }
    }
    assert_eq!(count, 4);
    let relative = Path::new(".github/workflows/backend-certification.yml");
    policy::validate_workflow_bytes(
        &root,
        relative,
        serde_yaml::to_string(&workflow).unwrap().as_bytes(),
        &configuration,
    )
    .unwrap();
    for job in ["windows-installed-x64", "windows-installed-arm64"] {
        for channel in ["native", "cargo"] {
            for mutation in [
                "missing",
                "wrong-channel",
                "wrong-destination",
                "optional",
                "lost-windows-guard",
                "upload-before-execution",
            ] {
                let mut changed = workflow.clone();
                let steps = changed["jobs"][job]["steps"].as_sequence_mut().unwrap();
                let index = steps
                    .iter()
                    .position(|step| step["id"].as_str() == Some(channel))
                    .unwrap();
                match mutation {
                    "missing" => {
                        steps.remove(index);
                    }
                    "wrong-channel" => {
                        steps[index]["run"] = serde_yaml::Value::String(
                            steps[index]["run"]
                                .as_str()
                                .unwrap()
                                .replace(&format!("--channel {channel}"), "--channel other"),
                        )
                    }
                    "wrong-destination" => {
                        steps[index]["run"] = serde_yaml::Value::String(
                            steps[index]["run"].as_str().unwrap().replace(
                                &format!("windows-installed/{channel}"),
                                "windows-installed/other",
                            ),
                        )
                    }
                    "optional" => steps[index]["continue-on-error"] = serde_yaml::Value::Bool(true),
                    "lost-windows-guard" => {
                        steps[index]["if"] =
                            serde_yaml::Value::String(format!("matrix.channel == '{channel}'"))
                    }
                    "upload-before-execution" => {
                        let upload = steps
                            .iter()
                            .position(|step| {
                                step["with"]["path"].as_str() == Some("target/ci/windows-installed")
                            })
                            .unwrap();
                        let retained = steps.remove(upload);
                        steps.insert(index, retained);
                    }
                    _ => unreachable!(),
                }
                assert_ne!(changed, workflow, "{job}/{channel}/{mutation}");
                assert!(
                    policy::validate_workflow_bytes(
                        &root,
                        relative,
                        serde_yaml::to_string(&changed).unwrap().as_bytes(),
                        &configuration
                    )
                    .is_err(),
                    "{mutation}"
                );
            }
        }
    }
}
