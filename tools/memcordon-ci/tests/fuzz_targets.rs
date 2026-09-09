use std::collections::BTreeSet;

use memcordon_ci::fuzz_targets::{FuzzShard, targets};

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
        memcordon_ci::policy::check_fuzz_shards(yaml["jobs"]["fuzz"].as_mapping().unwrap())
    };
    validate(workflow).unwrap();
    for (from, to) in [
        ("shard: [first, second]", "shard: [first]"),
        ("shard: [first, second]", "shard: [first, first]"),
        ("matrix.shard == 'second'", "matrix.shard == 'first'"),
        ("suite fuzz-second", "suite fuzz-first"),
        ("timeout-minutes: 45", "timeout-minutes: 90"),
        ("fail-fast: false", "fail-fast: true"),
        ("${{ matrix.shard }}-nightly", "nightly"),
        ("'Cargo.toml', 'Cargo.lock', '.cargo/**'", "'Cargo.lock'"),
        (
            "always() && steps.fuzz-target",
            "success() && steps.fuzz-target",
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
        ("if", serde_yaml::Value::Bool(false)),
        ("continue-on-error", serde_yaml::Value::Bool(true)),
    ] {
        let mut job = baseline.clone();
        job.insert(name.into(), value);
        assert!(memcordon_ci::policy::check_fuzz_shards(&job).is_err());
    }
    let steps_key = serde_yaml::Value::String("steps".into());
    let count = baseline[&steps_key].as_sequence().unwrap().len();
    for index in 0..count {
        let mut job = baseline.clone();
        job[&steps_key].as_sequence_mut().unwrap().remove(index);
        assert!(memcordon_ci::policy::check_fuzz_shards(&job).is_err());
        let mut job = baseline.clone();
        job[&steps_key].as_sequence_mut().unwrap()[index]
            .as_mapping_mut()
            .unwrap()
            .insert("continue-on-error".into(), true.into());
        assert!(memcordon_ci::policy::check_fuzz_shards(&job).is_err());
    }
    let mut job = baseline.clone();
    job[&steps_key].as_sequence_mut().unwrap().swap(5, 7);
    assert!(memcordon_ci::policy::check_fuzz_shards(&job).is_err());
}
