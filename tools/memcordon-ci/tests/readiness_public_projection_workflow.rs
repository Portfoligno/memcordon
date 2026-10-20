use memcordon_ci::{config, policy, workflow_definitions};
use std::path::{Path, PathBuf};

#[test]
fn linux_uploads_only_finite_projection_and_windows_keeps_original_boundary() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let configuration = config::policy(&root).unwrap();
    let mut workflow = workflow_definitions::definition("release.yml").unwrap();
    let mut linux = 0;
    let mut windows = 0;
    for source in ["candidate", "public"] {
        for architecture in ["x64", "arm64"] {
            for channel in ["native", "cargo"] {
                for platform in ["linux", "windows"] {
                    let name = format!("{source}-{platform}-{architecture}-{channel}");
                    let steps = workflow["jobs"][&name]["steps"].as_sequence().unwrap();
                    let uploads: Vec<_> = steps
                        .iter()
                        .filter(|step| step["id"].as_str() == Some("readiness-upload"))
                        .collect();
                    assert_eq!(uploads.len(), 1, "{name}");
                    let seals: Vec<_> = steps
                        .iter()
                        .filter_map(|step| step["run"].as_str())
                        .filter(|run| run.contains(" seal-producer "))
                        .collect();
                    assert_eq!(seals.len(), 1, "{name}");
                    if platform == "linux" {
                        linux += 1;
                        assert_eq!(
                            uploads[0]["with"]["path"],
                            ".release/readiness-cell/producer"
                        );
                        assert!(
                            seals[0].contains("--cell .release/readiness-cell/producer/cell.json")
                        );
                        assert!(seals[0].contains(
                            "--output .release/readiness-cell/producer/producer-manifest.json"
                        ));
                        assert!(seals[0].ends_with("--acquisition-root .release/readiness-cell"));
                    } else {
                        windows += 1;
                        assert_eq!(uploads[0]["with"]["path"], ".release/readiness-cell");
                        assert!(!seals[0].contains("--acquisition-root"));
                    }
                }
            }
        }
    }
    assert_eq!((linux, windows), (8, 8));
    let relative = Path::new(".github/workflows/release.yml");
    policy::validate_workflow_bytes(
        &root,
        relative,
        serde_yaml::to_string(&workflow).unwrap().as_bytes(),
        &configuration,
    )
    .unwrap();
    let steps = workflow["jobs"]["candidate-linux-x64-native"]["steps"]
        .as_sequence_mut()
        .unwrap();
    let upload = steps
        .iter_mut()
        .find(|step| step["id"].as_str() == Some("readiness-upload"))
        .unwrap();
    upload["with"]["path"] = serde_yaml::Value::String(".release/readiness-cell".into());
    assert!(
        policy::validate_workflow_bytes(
            &root,
            relative,
            serde_yaml::to_string(&workflow).unwrap().as_bytes(),
            &configuration
        )
        .is_err()
    );
}
