use memcordon_ci::{
    cache::partition_compatibility,
    cache_inputs::{KeyInputs, keys},
    cache_restore::{CompiledPartition, partition_layout},
};
use std::collections::BTreeMap;

fn facts(purpose: &str, shard: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("purpose".into(), purpose.into()),
        ("shard".into(), shard.into()),
        ("rustc".into(), "compiler".into()),
        ("compiler-source-root".into(), "/same/checkout".into()),
        ("cargo-home".into(), "/same/home".into()),
        ("product-features".into(), purpose.into()),
        ("consumer-runtime-selection".into(), purpose.into()),
    ])
}

#[test]
fn actual_optimized_native_recipes_share_only_their_test_partition() {
    let release = partition_compatibility(
        "native-release",
        CompiledPartition::NativeTests,
        facts("native-release", "complete"),
    )
    .unwrap();
    for purpose in ["native-readiness", "windows-working", "private"] {
        assert_eq!(
            release,
            partition_compatibility(
                purpose,
                CompiledPartition::NativeTests,
                facts(purpose, "complete")
            )
            .unwrap()
        );
    }
    assert_ne!(
        release,
        partition_compatibility(
            "native-debug",
            CompiledPartition::NativeTests,
            facts("native-debug", "complete")
        )
        .unwrap()
    );
    for field in [
        "rustc",
        "compiler-source-root",
        "cargo-home",
        "CARGO_ENCODED_RUSTFLAGS",
        "native-linker",
    ] {
        let mut changed = facts("native-release", "complete");
        changed.insert(field.into(), "different".into());
        assert_ne!(
            release,
            partition_compatibility("native-release", CompiledPartition::NativeTests, changed)
                .unwrap()
        );
    }
    assert_ne!(
        partition_compatibility(
            "native-release",
            CompiledPartition::Product,
            facts("native-release", "complete")
        )
        .unwrap(),
        partition_compatibility(
            "native-readiness",
            CompiledPartition::Product,
            facts("native-readiness", "complete")
        )
        .unwrap()
    );
}

#[test]
fn finite_partition_layouts_keep_distinct_owned_roots() {
    for purpose in [
        "native-release",
        "native-readiness",
        "windows-working",
        "private",
    ] {
        let native =
            partition_layout(purpose, "complete", Some(CompiledPartition::NativeTests)).unwrap();
        let product =
            partition_layout(purpose, "complete", Some(CompiledPartition::Product)).unwrap();
        assert_eq!(native.revision, 6);
        assert_eq!(product.revision, 6);
        assert!(
            !native
                .directories
                .iter()
                .any(|path| product.directories.contains(path))
        );
    }
    assert!(partition_layout("quality", "complete", Some(CompiledPartition::NativeTests)).is_err());
    assert_eq!(
        partition_layout(
            "native-auxiliary",
            "complete",
            Some(CompiledPartition::AuxiliaryProfiles)
        )
        .unwrap()
        .revision,
        5
    );
}

#[test]
fn fuzz_shards_share_compatible_dependencies_but_not_exact_content() {
    let first = partition_compatibility(
        "fuzz",
        CompiledPartition::FuzzTargets,
        facts("fuzz", "first"),
    )
    .unwrap();
    let quarter = partition_compatibility(
        "fuzz",
        CompiledPartition::FuzzTargets,
        facts("fuzz", "quarter-one"),
    )
    .unwrap();
    assert_eq!(first, quarter);
    let key = |shard: &str, revision| {
        keys(&KeyInputs {
            family: "workspace".into(),
            layout_revision: revision,
            compatibility: first.clone(),
            content: BTreeMap::from([("selected-shard".into(), shard.into())]),
        })
        .unwrap()
    };
    assert_eq!(key("first", 6).1, key("quarter-one", 6).1);
    assert_ne!(key("first", 6).0, key("quarter-one", 6).0);
    assert_ne!(key("first", 4).1, key("first", 6).1);
}
