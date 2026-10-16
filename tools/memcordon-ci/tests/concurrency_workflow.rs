use std::path::{Path, PathBuf};

use memcordon_ci::{config, miri_targets, policy};
use serde_yaml::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn validate(path: &str, document: &Value) -> memcordon_ci::Result<()> {
    policy::validate_workflow_bytes(
        &root(),
        Path::new(path),
        serde_yaml::to_string(document).unwrap().as_bytes(),
        &config::policy(&root()).unwrap(),
    )
}

#[test]
fn actual_metadata_has_four_complete_disjoint_nonempty_miri_quarters() {
    let metadata = policy::workspace_metadata(&root()).unwrap();
    let bytes = serde_json::to_vec(&metadata).unwrap();
    let complete = miri_targets::plan(&bytes, "memcordon-core").unwrap();
    let mut joined = Vec::new();
    for quarter in [
        miri_targets::MiriQuarter::One,
        miri_targets::MiriQuarter::Two,
        miri_targets::MiriQuarter::Three,
        miri_targets::MiriQuarter::Four,
    ] {
        let targets = miri_targets::plan_quarter(&bytes, "memcordon-core", quarter).unwrap();
        assert!(!targets.is_empty());
        assert!(targets.iter().all(|target| !joined.contains(target)));
        joined.extend(targets);
    }
    joined.sort();
    assert_eq!(joined, complete);
}

#[test]
fn full_workflows_reject_incomplete_quarters_and_unpaired_mode_branches() {
    for path in [
        ".github/workflows/release.yml",
        ".github/workflows/deep-ci.yml",
    ] {
        let original: Value =
            serde_yaml::from_slice(&std::fs::read(root().join(path)).unwrap()).unwrap();
        validate(path, &original).unwrap_or_else(|error| panic!("{path}: {error}"));
        for family in ["miri", "fuzz"] {
            let mut missing = original.clone();
            missing["jobs"][family]["strategy"]["matrix"]["shard"]
                .as_sequence_mut()
                .unwrap()
                .pop();
            assert!(validate(path, &missing).is_err());
            let mut wrong_mode = original.clone();
            wrong_mode["jobs"][family]["strategy"]["fail-fast"] =
                Value::String("${{ github.event_name != 'workflow_dispatch' }}".into());
            assert!(validate(path, &wrong_mode).is_err());
            let mut missing_branch = original.clone();
            let steps = missing_branch["jobs"][family]["steps"]
                .as_sequence_mut()
                .unwrap();
            let ordinal = steps
                .iter()
                .position(|step| {
                    step["id"]
                        .as_str()
                        .is_some_and(|id| id.ends_with("-diagnostic"))
                })
                .unwrap();
            steps.remove(ordinal);
            assert!(validate(path, &missing_branch).is_err());
        }
    }
}

#[test]
fn release_selection_cannot_reintroduce_full_workspace_fetch() {
    let path = ".github/workflows/release.yml";
    let mut document: Value =
        serde_yaml::from_slice(&std::fs::read(root().join(path)).unwrap()).unwrap();
    document["jobs"]["select"]["steps"].as_sequence_mut().unwrap().push(serde_yaml::from_str("id: workspace-fetch\nrun: ./.release/tool/memcordon-ci ci fetch-downloads --family workspace\n").unwrap());
    assert!(validate(path, &document).is_err());
}
