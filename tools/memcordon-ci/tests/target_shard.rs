use memcordon_ci::target_shard::ShardSpec;
use std::collections::BTreeSet;
use std::num::NonZeroUsize;

#[test]
fn every_ordinal_has_exactly_one_owner_and_balanced_complete_partition() {
    for count in 1..=8 {
        let count = NonZeroUsize::new(count).unwrap();
        assert!(ShardSpec::new(count.get(), count).is_err());
        for length in 0..=53 {
            let parts: Vec<Vec<_>> = (0..count.get())
                .map(|index| {
                    (0..length)
                        .filter(|ordinal| ShardSpec::new(index, count).unwrap().selects(*ordinal))
                        .collect()
                })
                .collect();
            let combined: BTreeSet<_> = parts.iter().flatten().copied().collect();
            assert_eq!(combined, (0..length).collect());
            assert_eq!(parts.iter().map(Vec::len).sum::<usize>(), length);
            assert!(
                parts.iter().map(Vec::len).max().unwrap()
                    - parts.iter().map(Vec::len).min().unwrap()
                    <= 1
            );
        }
    }
}

#[test]
fn real_fuzz_manifest_has_four_disjoint_complete_quarters_and_compatible_halves() {
    let manifest = include_str!("../../../fuzz/Cargo.toml");
    let complete = memcordon_ci::fuzz_targets::targets(manifest, None).unwrap();
    let quarters: Vec<_> = (0..4)
        .map(|index| {
            memcordon_ci::fuzz_targets::targets_sharded(
                manifest,
                Some(ShardSpec::new(index, NonZeroUsize::new(4).unwrap()).unwrap()),
            )
            .unwrap()
        })
        .collect();
    assert_eq!(complete.len(), 52);
    for quarter in &quarters {
        assert_eq!(quarter.len(), 13);
    }
    let mut joined: Vec<_> = quarters.into_iter().flatten().collect();
    joined.sort();
    assert_eq!(joined, complete);
    for (index, half) in [
        memcordon_ci::fuzz_targets::FuzzShard::First,
        memcordon_ci::fuzz_targets::FuzzShard::Second,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            memcordon_ci::fuzz_targets::targets(manifest, Some(half)).unwrap(),
            memcordon_ci::fuzz_targets::targets_sharded(
                manifest,
                Some(ShardSpec::new(index, NonZeroUsize::new(2).unwrap()).unwrap())
            )
            .unwrap()
        );
    }
}
