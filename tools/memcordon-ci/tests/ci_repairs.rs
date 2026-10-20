use memcordon_ci::workflow_definitions;
use serde_yaml::Value;
#[path = "../src/cache_guard.rs"]
mod cache_guard;

#[test]
fn source_producer_ownership_matches_event_truth_table_and_shared_writers() {
    for file in workflow_definitions::FILES {
        let document = workflow_definitions::definition(file).unwrap();
        let condition = document["jobs"]["source-seed"]["if"].as_str().unwrap();
        for (event, reference, deleted, recovery) in [
            ("push", "refs/heads/main", false, "reprepare"),
            ("push", "refs/tags/0.5.8", false, "reprepare"),
            ("push", "refs/tags/uncovered", false, "reprepare"),
            ("workflow_dispatch", "refs/heads/main", false, "reprepare"),
            (
                "workflow_dispatch",
                "refs/heads/main",
                false,
                "publication-only",
            ),
            ("workflow_dispatch", "refs/tags/0.5.8", false, "reprepare"),
            ("pull_request", "refs/heads/main", false, "reprepare"),
            ("merge_group", "refs/heads/main", false, "reprepare"),
            ("push", "refs/heads/main", true, "reprepare"),
            ("push", "refs/heads/", false, "reprepare"),
            ("push", "refs/tags/", false, "reprepare"),
            ("push", "", false, "reprepare"),
        ] {
            let branch = reference
                .strip_prefix("refs/heads/")
                .is_some_and(|name| !name.is_empty());
            let tag = reference
                .strip_prefix("refs/tags/")
                .is_some_and(|name| !name.is_empty());
            let expected = !deleted
                && match event {
                    "push" => (branch && file == "release.yml") || (tag && file == "deep-ci.yml"),
                    "workflow_dispatch" => {
                        branch && (file != "release.yml" || recovery == "reprepare")
                    }
                    _ => false,
                };
            let expression = condition
                .replace(
                    "startsWith(github.ref, 'refs/heads/')",
                    if reference.starts_with("refs/heads/") {
                        "true"
                    } else {
                        "false"
                    },
                )
                .replace(
                    "startsWith(github.ref, 'refs/tags/')",
                    if reference.starts_with("refs/tags/") {
                        "true"
                    } else {
                        "false"
                    },
                )
                .replace(
                    "github.event.deleted",
                    if deleted { "true" } else { "false" },
                );
            let actual = cache_guard::parse(&expression).unwrap().evaluate(
                &|name| match name {
                    "github.event_name" => event.into(),
                    "github.ref" => reference.into(),
                    "inputs.recovery-mode" => recovery.into(),
                    _ => panic!("unexpected owner field {name}"),
                },
                &|name| panic!("unexpected status {name}"),
            );
            assert_eq!(
                actual, expected,
                "{file} {event} {reference} deleted={deleted} recovery={recovery}"
            );
            if actual {
                assert!(memcordon_ci::segment_cache::write_event_for(
                    Some(event),
                    Some(reference)
                ));
            }
        }
    }
}

#[test]
fn public_source_producer_and_narrow_checks_reject_independent_mutations() {
    let baseline = workflow_definitions::definition("ci.yml").unwrap();
    for (field, value) in [
        ("needs", Value::String("policy".into())),
        (
            "permissions",
            serde_yaml::from_str("contents: write").unwrap(),
        ),
        ("continue-on-error", Value::Bool(false)),
        ("runs-on", Value::String("ubuntu-24.04".into())),
        ("timeout-minutes", Value::Number(360.into())),
        (
            "strategy",
            serde_yaml::from_str("matrix: {runner: [ubuntu-24.04]}").unwrap(),
        ),
    ] {
        let mut mutated = baseline.clone();
        mutated["jobs"]["source-seed"][field] = value;
        assert!(
            workflow_definitions::validate_semantics(&mutated).is_err(),
            "producer {field}"
        );
    }
    let mut wrong_paths = baseline.clone();
    wrong_paths["jobs"]["source-seed"]["steps"][3]["with"]["path"] =
        Value::String("target/ci-cargo-home".into());
    assert!(workflow_definitions::validate_semantics(&wrong_paths).is_err());
    let mut blocked = baseline.clone();
    blocked["jobs"]["policy"]["needs"] = Value::String("source-seed".into());
    assert!(workflow_definitions::validate_semantics(&blocked).is_err());
    let mut late_format = baseline.clone();
    let steps = late_format["jobs"]["quality"]["steps"]
        .as_sequence_mut()
        .unwrap();
    let index = steps
        .iter()
        .position(|step| step["id"].as_str() == Some("early-format"))
        .unwrap();
    let format = steps.remove(index);
    steps.push(format);
    assert!(workflow_definitions::validate_semantics(&late_format).is_err());
}

#[test]
fn raw_source_seed_rejects_unmodeled_registry_or_configuration() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    std::fs::write(
        root.join("Cargo.lock"),
        "version=4\n[[package]]\nname='local'\nversion='0.1.0'\n",
    )
    .unwrap();
    workflow_definitions::validate_public_source_model(root).unwrap();
    std::fs::write(root.join("Cargo.lock"),"version=4\n[[package]]\nname='remote'\nversion='0.1.0'\nsource='registry+https://private.invalid/index'\n").unwrap();
    assert!(workflow_definitions::validate_public_source_model(root).is_err());
    std::fs::write(
        root.join("Cargo.lock"),
        "version=4\n[[package]]\nname='local'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::create_dir(root.join(".cargo")).unwrap();
    std::fs::write(
        root.join(".cargo/config.toml"),
        "[source.crates-io]\nreplace-with='private'\n",
    )
    .unwrap();
    assert!(workflow_definitions::validate_public_source_model(root).is_err());
}
