use std::collections::BTreeSet;

use memcordon_ci::fuzz_targets::{FuzzShard, targets};

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
fn workflow_requires_complete_static_shards_and_cache_inputs() {
    let workflow = include_str!("../../../.github/workflows/deep-ci.yml");
    let validate = |source: &str| {
        let yaml: serde_yaml::Value = serde_yaml::from_str(source).unwrap();
        memcordon_ci::policy::check_deep_fuzz_shards(yaml["jobs"]["fuzz"].as_mapping().unwrap())
    };
    validate(workflow).unwrap();
    for (from, to) in [
        (
            "shard: [quarter-one, quarter-two, quarter-three, quarter-four]",
            "shard: [quarter-one]",
        ),
        (
            "shard: [quarter-one, quarter-two, quarter-three, quarter-four]",
            "shard: [quarter-one, quarter-one, quarter-three, quarter-four]",
        ),
        (
            "matrix.shard == 'quarter-two'",
            "matrix.shard == 'quarter-one'",
        ),
        ("suite fuzz-quarter-two", "suite fuzz-quarter-one"),
        ("fail-fast: false", "fail-fast: true"),
        ("'fuzz/Cargo.lock', 'fuzz/Cargo.toml'", "'fuzz/Cargo.toml'"),
        (
            "always() && matrix.shard == 'quarter-one' && steps.fuzz-deps",
            "success() && matrix.shard == 'quarter-one' && steps.fuzz-deps",
        ),
    ] {
        assert!(workflow.contains(from));
        assert!(
            validate(&workflow.replace(from, to)).is_err(),
            "accepted {to}"
        );
    }
    let yaml: serde_yaml::Value = serde_yaml::from_str(workflow).unwrap();
    let baseline = yaml["jobs"]["fuzz"].as_mapping().unwrap();
    for (name, value) in [
        ("timeout-minutes", serde_yaml::Value::Number(90.into())),
        ("if", serde_yaml::Value::Bool(false)),
        ("continue-on-error", serde_yaml::Value::Bool(true)),
    ] {
        let mut job = baseline.clone();
        job.insert(name.into(), value);
        assert!(memcordon_ci::policy::check_deep_fuzz_shards(&job).is_err());
    }
    let steps_key = serde_yaml::Value::String("steps".into());
    let count = baseline[&steps_key].as_sequence().unwrap().len();
    for index in 0..count {
        let mut job = baseline.clone();
        job[&steps_key].as_sequence_mut().unwrap().remove(index);
        assert!(memcordon_ci::policy::check_deep_fuzz_shards(&job).is_err());
        let mut job = baseline.clone();
        job[&steps_key].as_sequence_mut().unwrap()[index]
            .as_mapping_mut()
            .unwrap()
            .insert("continue-on-error".into(), true.into());
        assert!(memcordon_ci::policy::check_deep_fuzz_shards(&job).is_err());
    }
    let mut job = baseline.clone();
    job[&steps_key].as_sequence_mut().unwrap().swap(5, 7);
    assert!(memcordon_ci::policy::check_deep_fuzz_shards(&job).is_err());
}
