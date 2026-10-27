use std::collections::BTreeSet;

use memcordon_ci::fuzz_targets::{FuzzShard, RequiredFeature, plans_sharded, targets};

#[test]
fn typed_plans_preserve_all_targets_and_only_six_ci_dependency_requirements() {
    let manifest = include_str!("../../../fuzz/Cargo.toml");
    let plans = plans_sharded(manifest, None).unwrap();
    assert_eq!(plans.len(), 52);
    assert_eq!(
        plans
            .iter()
            .map(|plan| plan.name.clone())
            .collect::<Vec<_>>(),
        targets(manifest, None).unwrap()
    );
    let ci: Vec<_> = plans
        .iter()
        .filter(|plan| !plan.required_features.is_empty())
        .map(|plan| plan.name.as_str())
        .collect();
    assert_eq!(
        ci,
        [
            "mount-context-manifest",
            "policy_parser",
            "release-asset-components",
            "runtime-manifest",
            "target-distribution",
            "workflow_parser"
        ]
    );
    let mut covered = BTreeSet::new();
    for index in 0..4 {
        let shard = memcordon_ci::target_shard::ShardSpec::new(
            index,
            std::num::NonZeroUsize::new(4).unwrap(),
        )
        .unwrap();
        for plan in plans_sharded(manifest, Some(shard)).unwrap() {
            assert_eq!(
                plans.iter().find(|original| original.name == plan.name),
                Some(&plan)
            );
            assert!(covered.insert(plan.name));
        }
    }
    assert_eq!(
        covered.into_iter().collect::<Vec<_>>(),
        targets(manifest, None).unwrap()
    );
    for plan in &plans {
        let mut build: Vec<std::ffi::OsString> =
            vec!["fuzz".into(), "build".into(), plan.name.clone().into()];
        let mut run: Vec<std::ffi::OsString> =
            vec!["fuzz".into(), "run".into(), plan.name.clone().into()];
        if ci.contains(&plan.name.as_str()) {
            assert_eq!(plan.required_features, [RequiredFeature::CiTargets]);
            build.extend(["--features".into(), "ci-targets".into()]);
            run.extend(["--features".into(), "ci-targets".into()]);
        } else {
            assert!(plan.required_features.is_empty());
        }
        run.extend([
            "--".into(),
            "-max_total_time=30".into(),
            if plan.name.starts_with("workload-") {
                "-max_len=1048576".into()
            } else {
                "-max_len=4096".into()
            },
        ]);
        assert_eq!(plan.build_arguments(), build);
        assert_eq!(plan.run_arguments(), run);
        let serialized = serde_json::to_value(plan).unwrap();
        assert_eq!(
            serialized["required_features"],
            if ci.contains(&plan.name.as_str()) {
                serde_json::json!(["ci-targets"])
            } else {
                serde_json::json!([])
            }
        );
    }
}

#[test]
fn required_features_are_explicit_closed_and_never_silently_omitted() {
    for requirements in [
        "'ci-targets'",
        "true",
        "[1]",
        "['unknown']",
        "['ci-targets','ci-targets']",
        "['ci-targets','future']",
    ] {
        let manifest = format!("[[bin]]\nname='selected'\nrequired-features={requirements}\n");
        assert!(plans_sharded(&manifest, None).is_err(), "{manifest}");
        assert!(
            targets(&manifest, None).is_err(),
            "legacy API must also reject {manifest}"
        );
    }
    for requirement in ["", "required-features=[]"] {
        let manifest = format!("[[bin]]\nname='future_ordinary'\n{requirement}\n");
        let plan = plans_sharded(&manifest, None).unwrap().remove(0);
        assert!(plan.required_features.is_empty());
        assert_eq!(
            plan.build_arguments(),
            ["fuzz", "build", "future_ordinary"].map(std::ffi::OsString::from)
        );
    }
    let plan = plans_sharded(
        "[[bin]]\nname='future_ci'\nrequired-features=['ci-targets']",
        None,
    )
    .unwrap()
    .remove(0);
    assert_eq!(plan.required_features, [RequiredFeature::CiTargets]);
    assert_eq!(
        plan.build_arguments(),
        ["fuzz", "build", "future_ci", "--features", "ci-targets"].map(std::ffi::OsString::from)
    );
}

#[test]
fn retained_probe_and_distribution_seeds_reach_valid_models_and_reject_substitution() {
    let probe_bytes = include_bytes!("../../../fuzz/corpus/windows-provider-probe/observed.json");
    memcordon_core::canonical_json::reject_duplicate_json_keys(probe_bytes).unwrap();
    let probe: memcordon_core::WindowsProviderProbeV1 =
        serde_json::from_slice(probe_bytes).unwrap();
    probe.validate().unwrap();
    let mut foreign = probe.clone();
    foreign.format = "memcordon.retired-qualification".into();
    assert!(foreign.validate().is_err());
    let mut unauthenticated = probe;
    unauthenticated.launcher_authenticated = false;
    assert!(unauthenticated.validate().is_err());

    let distribution_bytes =
        include_bytes!("../../../fuzz/corpus/target-distribution/cli-only.json");
    memcordon_core::canonical_json::reject_duplicate_json_keys(distribution_bytes).unwrap();
    let mut distribution: memcordon_ci::release::distribution::TargetDistribution =
        serde_json::from_slice(distribution_bytes).unwrap();
    distribution.validate().unwrap();
    distribution.units.push("unexpected.service".into());
    assert!(distribution.validate().is_err());
    assert!(
        memcordon_core::canonical_json::reject_duplicate_json_keys(
            br#"{"revision":1,"revision":1}"#,
        )
        .is_err()
    );
}

#[test]
fn shards_cover_current_and_future_manifest_targets_exactly_once() {
    let manifest = include_str!("../../../fuzz/Cargo.toml");
    for manifest in [
        manifest.to_owned(),
        format!(
            "{manifest}\n[[bin]]\nname = 'future_target'\npath = 'fuzz_targets/future_target.rs'\n"
        ),
    ] {
        let all = targets(&manifest, None).unwrap();
        let first = targets(&manifest, Some(FuzzShard::First)).unwrap();
        let second = targets(&manifest, Some(FuzzShard::Second)).unwrap();
        let first: BTreeSet<_> = first.into_iter().collect();
        let second: BTreeSet<_> = second.into_iter().collect();
        assert!(first.is_disjoint(&second));
        assert_eq!(first.union(&second).cloned().collect::<Vec<_>>(), all);
        assert!(first.len().abs_diff(second.len()) <= 1);
        assert_ne!(first.contains("report_json"), first.contains("schema_four"));
    }
    assert_eq!(targets(manifest, None).unwrap().len(), 52);
}

#[test]
fn malformed_or_empty_inventory_cannot_silently_lose_coverage() {
    for manifest in [
        "",
        "bin = []",
        "[[bin]]\npath='x'",
        "[[bin]]\nname=''",
        "[[bin]]\nname='a b'",
        "[[bin]]\nname='same'\n[[bin]]\nname='same'",
        "bin = [7]",
    ] {
        assert!(targets(manifest, None).is_err(), "{manifest}");
    }
    assert!(targets("[[bin]]\nname='only'", Some(FuzzShard::Second)).is_err());
}

#[test]
fn workflow_requires_complete_static_shards_and_execution() {
    let workflow = include_str!("../../../.github/workflows/deep-ci.yml");
    let yaml: serde_yaml::Value = serde_yaml::from_str(workflow).unwrap();
    let baseline = yaml["jobs"]["fuzz"].as_mapping().unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let configuration = memcordon_ci::config::policy(&root).unwrap();
    let validate = |job: &serde_yaml::Mapping| {
        let mut document = yaml.clone();
        document["jobs"]["fuzz"] = serde_yaml::Value::Mapping(job.clone());
        memcordon_ci::policy::validate_workflow_bytes(
            &root,
            std::path::Path::new(".github/workflows/deep-ci.yml"),
            serde_yaml::to_string(&document).unwrap().as_bytes(),
            &configuration,
        )
    };
    validate(baseline).unwrap();
    let reject = |job: serde_yaml::Mapping| {
        assert_ne!(
            &job, baseline,
            "mutation did not change the validated fuzz job"
        );
        assert!(
            validate(&job).is_err(),
            "accepted changed fuzz job: {job:?}"
        );
    };
    let strategy_key = serde_yaml::Value::String("strategy".into());
    assert_eq!(baseline[&strategy_key]["fail-fast"].as_bool(), Some(false));
    for value in [
        true.into(),
        "${{ github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all' }}"
            .into(),
        "${{ github.event_name == 'workflow_dispatch' }}".into(),
    ] {
        let mut job = baseline.clone();
        job.get_mut(&strategy_key).unwrap()["fail-fast"] = value;
        reject(job);
    }
    let mut job = baseline.clone();
    job.get_mut(&strategy_key)
        .unwrap()
        .as_mapping_mut()
        .unwrap()
        .remove(serde_yaml::Value::String("fail-fast".into()));
    reject(job);
    for shards in [
        vec!["quarter-one"],
        vec![
            "quarter-one",
            "quarter-one",
            "quarter-three",
            "quarter-four",
        ],
        vec!["quarter-one", "quarter-two", "quarter-three", "other"],
        vec![
            "quarter-one",
            "quarter-two",
            "quarter-three",
            "quarter-four",
            "extra",
        ],
    ] {
        let mut job = baseline.clone();
        job.get_mut(&strategy_key).unwrap()["matrix"]["shard"] =
            serde_yaml::to_value(shards).unwrap();
        reject(job);
    }
    for (name, value) in [
        ("timeout-minutes", serde_yaml::Value::Number(90.into())),
        ("if", serde_yaml::Value::Bool(false)),
        ("continue-on-error", serde_yaml::Value::Bool(true)),
    ] {
        let mut job = baseline.clone();
        job.insert(name.into(), value);
        reject(job);
    }
    let steps_key = serde_yaml::Value::String("steps".into());
    let steps = baseline[&steps_key].as_sequence().unwrap();
    let step_id = |id: &str| {
        steps
            .iter()
            .position(|step| step["id"].as_str() == Some(id))
            .unwrap()
    };
    for (index, field, from, to) in [
        (
            step_id("fuzz-two"),
            "if",
            "matrix.shard == 'quarter-two'",
            "matrix.shard == 'quarter-one'",
        ),
        (
            step_id("fuzz-two"),
            "run",
            "ci segment fuzz-execute-quarter-two",
            "ci segment fuzz-execute-quarter-one",
        ),
    ] {
        let original = steps[index][field].as_str().unwrap();
        assert!(original.contains(from));
        let mut job = baseline.clone();
        job.get_mut(&steps_key).unwrap().as_sequence_mut().unwrap()[index][field] =
            original.replace(from, to).into();
        reject(job);
    }
    for (index, step) in steps.iter().enumerate() {
        let required_work = step["run"].as_str().is_some_and(|run| {
            run.contains(" ci segment ")
                || run.ends_with(" release fuzz-setup-check")
                || run.ends_with(" release fuzz-setup-extract")
                || run.ends_with(" release fuzz-setup-validate")
                || run.ends_with(" release fuzz-current-probe")
        });
        let artifact_or_checkout = step["uses"].as_str().is_some_and(|uses| {
            uses.starts_with("actions/checkout@")
                || uses.starts_with("actions/download-artifact@")
                || uses.starts_with("actions/upload-artifact@")
        });
        if !required_work && !artifact_or_checkout {
            continue;
        }
        let mut job = baseline.clone();
        job.get_mut(&steps_key)
            .unwrap()
            .as_sequence_mut()
            .unwrap()
            .remove(index);
        reject(job);
        if step["run"].as_str().is_none() {
            continue;
        }
        let mut job = baseline.clone();
        job.get_mut(&steps_key).unwrap().as_sequence_mut().unwrap()[index]
            .as_mapping_mut()
            .unwrap()
            .insert("continue-on-error".into(), true.into());
        if step["continue-on-error"].as_bool() != Some(true) {
            reject(job);
        }
    }
    let mut job = baseline.clone();
    let driver = steps
        .iter()
        .position(|step| step["id"].as_str() == Some("fuzz-current-probe"))
        .unwrap();
    for index in [driver, step_id("fuzz-setup-extract")] {
        let mut job = baseline.clone();
        job.get_mut(&steps_key)
            .unwrap()
            .as_sequence_mut()
            .unwrap()
            .swap(step_id("shard-workspace-fetch"), index);
        reject(job);
    }
    let mut conditional_fetch = baseline.clone();
    conditional_fetch
        .get_mut(&steps_key)
        .unwrap()
        .as_sequence_mut()
        .unwrap()[step_id("shard-workspace-fetch")]["if"] = "success()".into();
    reject(conditional_fetch);
    job.get_mut(&steps_key)
        .unwrap()
        .as_sequence_mut()
        .unwrap()
        .swap(driver, step_id("fuzz-one"));
    reject(job);
}
