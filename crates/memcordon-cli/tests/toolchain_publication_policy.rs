#[path = "../src/bin/consumer_readiness_windows/toolchain_publication_policy.rs"]
mod policy;

fn identity() -> policy::Identity {
    policy::Identity {
        volume: 7,
        index: 101,
        attributes: 32,
        links: 1,
        length: 811,
    }
}

#[test]
fn ownership_requires_absence_or_exact_original_handle_observation() {
    let original = identity();
    assert!(policy::destination(None, None).is_ok());
    assert!(policy::destination(Some(&original), Some(&original)).is_ok());
    // Identical diagnostic bytes or metadata cannot authorize a pre-existing
    // destination when this execution has no retained original handle.
    assert!(policy::destination(None, Some(&original)).is_err());
    assert!(policy::destination(Some(&original), None).is_err());
    for changed in [
        policy::Identity {
            index: 102,
            ..original.clone()
        },
        policy::Identity {
            volume: 8,
            ..original.clone()
        },
        policy::Identity {
            length: 812,
            ..original.clone()
        },
        policy::Identity {
            attributes: 128,
            ..original.clone()
        },
    ] {
        assert!(policy::destination(Some(&original), Some(&changed)).is_err());
    }
}

#[test]
fn matching_facts_do_not_authorize_reparse_directory_or_hardlink() {
    for attributes in [0x400, 0x10, 0x410] {
        let invalid = policy::Identity {
            attributes,
            ..identity()
        };
        assert!(policy::destination(Some(&invalid), Some(&invalid)).is_err());
    }
    for links in [0, 2, u32::MAX] {
        let invalid = policy::Identity {
            links,
            ..identity()
        };
        assert!(policy::destination(Some(&invalid), Some(&invalid)).is_err());
    }
}
