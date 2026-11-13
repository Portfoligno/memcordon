use memcordon_ci::namespace_watch_model::{self as model, Subscription};

fn parent(role: &str, name: &[u8]) -> Subscription {
    Subscription {
        watch: 7,
        role: role.into(),
        basename: Some(name.to_vec()),
    }
}

#[test]
fn optional_root_presence_and_identity_are_not_rebaselined() {
    let identity = Some((1, 2, 0, 0o40700));
    model::require_same_identity(None, None).unwrap();
    model::require_same_identity(identity, identity).unwrap();
    assert!(model::require_same_identity(None, identity).is_err());
    assert!(model::require_same_identity(identity, None).is_err());
    assert!(model::require_same_identity(identity, Some((1, 3, 0, 0o40700))).is_err());
    assert!(model::require_same_identity(identity, Some((1, 2, 1, 0o40700))).is_err());
}

#[test]
fn shared_parent_dispatches_every_exact_basename_subscription() {
    let subscriptions = [
        parent("journal", b"attempts"),
        parent("inputs", b"inputs"),
        parent("alias", b"inputs"),
    ];
    assert_eq!(
        model::classify(&subscriptions, 7, 0x100, b"inputs").unwrap(),
        ["inputs", "alias"]
    );
    assert!(
        model::classify(&subscriptions, 7, 0x100, b"inputs-other")
            .unwrap()
            .is_empty()
    );
    assert!(model::classify(&subscriptions, 8, 0x100, b"inputs").is_err());
}

#[test]
fn transient_creation_and_removal_both_remain_violations() {
    let subscriptions = [parent("journal", b"attempts")];
    let mut events = Vec::new();
    for mask in [0x100, 0x200, 0x40, 0x80] {
        events.extend(model::classify(&subscriptions, 7, mask, b"attempts").unwrap());
    }
    assert_eq!(events, ["journal"; 4]);
    model::require_same_identity(None, None).unwrap();
    assert!(!events.is_empty());
}

#[test]
fn staging_content_filter_never_hides_parent_link_or_shared_role() {
    let subscriptions = [
        parent("root-staging", b"memcordon"),
        Subscription {
            watch: 7,
            role: "root-staging".into(),
            basename: None,
        },
        Subscription {
            watch: 7,
            role: "other-content".into(),
            basename: None,
        },
    ];
    assert_eq!(
        model::classify(&subscriptions, 7, 0x100, b"memcordon").unwrap(),
        ["root-staging", "other-content"]
    );
    assert_eq!(
        model::classify(&subscriptions, 7, 0x100, b"private-root-a").unwrap(),
        ["root-staging", "other-content"]
    );
}

#[test]
fn invalidation_and_overflow_are_fatal_even_for_unrelated_names() {
    let subscriptions = [parent("root-staging", b"memcordon")];
    for mask in [0x400, 0x800, 0x2000, 0x8000, 0x4000] {
        assert!(model::classify(&subscriptions, 7, mask, b"unrelated").is_err());
    }
    assert!(model::classify(&subscriptions, 7, 1, b"memcordon").is_err());
}

#[test]
fn raw_and_relevant_event_budgets_are_independently_bounded() {
    model::check_event_bounds(model::RAW_EVENT_LIMIT, model::RELEVANT_EVENT_LIMIT).unwrap();
    assert!(model::check_event_bounds(model::RAW_EVENT_LIMIT + 1, 0).is_err());
    assert!(model::check_event_bounds(1, model::RELEVANT_EVENT_LIMIT + 1).is_err());
}
