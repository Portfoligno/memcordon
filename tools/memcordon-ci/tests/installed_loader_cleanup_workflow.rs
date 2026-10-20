use memcordon_ci::{config, policy, workflow_definitions};
use std::path::{Path, PathBuf};

#[test]
fn both_architectures_retire_the_selected_support_lifetime_even_after_failure() {
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
        for (channel, expected) in [
            (
                "native",
                "./target/ci-runtime/current/memcordon-ci.exe release cleanup-installed-loader-support --destination target/ci/windows-installed/native",
            ),
            (
                "cargo",
                "./target/ci-runtime/current/memcordon-ci.exe release cleanup-installed-loader-support --destination target/ci/windows-installed/cargo",
            ),
        ] {
            let execute = steps
                .iter()
                .position(|step| step["id"].as_str() == Some(channel))
                .unwrap();
            let id = format!("loader-cleanup-{channel}");
            let matches: Vec<_> = steps
                .iter()
                .enumerate()
                .filter(|(_, step)| step["id"].as_str() == Some(id.as_str()))
                .collect();
            assert_eq!(matches.len(), 1);
            let (cleanup, step) = matches[0];
            assert!(execute < cleanup && cleanup < upload);
            assert_eq!(step["run"].as_str(), Some(expected));
            assert_eq!(
                step["if"].as_str(),
                Some(
                    format!("always() && matrix.channel == '{channel}' && runner.os == 'Windows'")
                        .as_str()
                )
            );
            assert_eq!(step["timeout-minutes"].as_u64(), Some(15));
            assert_ne!(step["continue-on-error"].as_bool(), Some(true));
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
    for mutation in ["missing", "success-only", "wrong-destination"] {
        let mut changed = workflow.clone();
        let steps = changed["jobs"]["windows-installed-x64"]["steps"]
            .as_sequence_mut()
            .unwrap();
        let index = steps
            .iter()
            .position(|step| step["id"].as_str() == Some("loader-cleanup-native"))
            .unwrap();
        match mutation {
            "missing" => { steps.remove(index); },
            "success-only" => steps[index]["if"] = serde_yaml::Value::String("success()".into()),
            "wrong-destination" => steps[index]["run"] = serde_yaml::Value::String("./target/ci-runtime/current/memcordon-ci.exe release cleanup-installed-loader-support --destination target/ci/windows-installed/cargo".into()),
            _ => unreachable!(),
        }
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
