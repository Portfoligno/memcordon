use memcordon_ci::native_coverage::{Selector, Target, select};
use std::collections::BTreeSet;

#[test]
fn local_shards_are_complete_disjoint_and_keep_sibling_support() {
    let targets = vec![
        Target {
            package: "one".into(),
            selector: Selector::Lib,
        },
        Target {
            package: "two".into(),
            selector: Selector::Lib,
        },
        Target {
            package: "one".into(),
            selector: Selector::Bin("fixture".into()),
        },
        Target {
            package: "one".into(),
            selector: Selector::Test("integration".into()),
        },
        Target {
            package: "two".into(),
            selector: Selector::Test("integration".into()),
        },
        Target {
            package: "one".into(),
            selector: Selector::Example("example".into()),
        },
        Target {
            package: "one".into(),
            selector: Selector::Bench("bench".into()),
        },
    ];
    let mut union = BTreeSet::new();
    for index in 0..4 {
        let selected = select(&targets, index, 4).unwrap();
        assert_eq!(selected, select(&targets, index, 4).unwrap());
        assert_eq!(selected.support_binaries, ["fixture"]);
        assert!(!selected.selectors.is_empty());
        for selector in selected.selectors {
            assert!(union.insert(selector));
        }
    }
    assert_eq!(
        union,
        targets
            .iter()
            .map(|target| target.selector.clone())
            .collect()
    );
    assert!(select(&targets, 4, 4).is_err());
    assert!(select(&targets, 0, 0).is_err());
    assert!(select(&targets, 0, targets.len()).is_err());
}

#[test]
fn ambiguous_ordinary_output_and_repeated_targets_fail_locally() {
    let target = Target {
        package: "one".into(),
        selector: Selector::Bin("fixture".into()),
    };
    assert!(select(&[target.clone(), target.clone()], 0, 1).is_err());
    let mut other = target.clone();
    other.package = "two".into();
    assert!(select(&[target, other], 0, 1).is_err());
}
