use memcordon_ci::workflow_scope::{Scope, classify, from_event_file, matches_release_tag_filter};

#[test]
fn literal_trigger_shape_preserves_uncovered_tags_and_nonpush_requests() {
    for reference in [
        "refs/heads/main",
        "refs/heads/release/0.5.6-rc.1",
        "refs/heads/1.2.3",
        "refs/tags/1.2.3",
        "refs/tags/1.2.3-rc.1",
        "refs/tags/01.2.3",
        "refs/tags/1.2.3not-semver",
        "refs/tags/1.2.3.4",
    ] {
        assert_eq!(
            classify("push", reference, false),
            Scope::SharedPreparationPush
        );
        assert_eq!(classify("push", reference, true), Scope::DeletedRef);
        for event in [
            "workflow_dispatch",
            "pull_request",
            "merge_group",
            "future_event",
        ] {
            assert_eq!(classify(event, reference, false), Scope::Standalone);
            assert_eq!(classify(event, reference, true), Scope::Standalone);
        }
    }
    for tag in [
        "v1.2.3",
        "nightly",
        "1.2.3/nested",
        "1.2",
        "1..3",
        ".2.3",
        "1.2.x",
        "1.2.",
        "1a.2.3",
    ] {
        assert!(!matches_release_tag_filter(tag), "{tag}");
        let reference = ["refs/tags/", tag].concat();
        assert_eq!(classify("push", &reference, false), Scope::Standalone);
    }
    for reference in ["refs/heads/", "refs/tags/", "refs/other/object"] {
        assert_eq!(classify("push", reference, false), Scope::Standalone);
    }
    assert!(Scope::Standalone.standalone_common());
    assert!(!Scope::SharedPreparationPush.standalone_common());
    assert!(!Scope::DeletedRef.standalone_common());
}

#[test]
fn bounded_provider_adapter_requires_consistent_typed_push_context() {
    let directory = if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    let path = directory.path().join("event.json");
    std::fs::write(
        &path,
        br#"{"ref":"refs/heads/main","deleted":false,"unrelated":{"provider":true}}"#,
    )
    .unwrap();
    assert_eq!(
        from_event_file("push", "refs/heads/main", &path).unwrap(),
        Scope::SharedPreparationPush
    );
    assert!(from_event_file("push", "refs/heads/other", &path).is_err());
    for invalid in [
        br#"{"ref":"refs/heads/main"}"#.as_slice(),
        br#"{"ref":"refs/heads/main","deleted":"false"}"#,
        br#"{"ref":5,"deleted":false}"#,
        br#"{"ref":"refs/heads/main","deleted":false,"deleted":true}"#,
        br#"{"ref":"refs/heads/main","deleted":false,"provider":{"x":1,"x":2}}"#,
        br#"{"ref":"refs/heads/main\n","deleted":false}"#,
        b"[]",
        b"not json",
    ] {
        std::fs::write(&path, invalid).unwrap();
        assert!(from_event_file("push", "refs/heads/main", &path).is_err());
    }
    std::fs::write(&path, br#"{"ref":"refs/heads/main","deleted":true}"#).unwrap();
    assert_eq!(
        from_event_file("push", "refs/heads/main", &path).unwrap(),
        Scope::DeletedRef
    );
    std::fs::write(&path, b"{}").unwrap();
    assert_eq!(
        from_event_file("workflow_dispatch", "refs/tags/nightly", &path).unwrap(),
        Scope::Standalone
    );
    for (event, reference) in [
        ("", "refs/heads/main"),
        ("push", ""),
        ("push\n", "refs/heads/main"),
        ("push", "refs/heads/main\0"),
        ("push", "refs/heads/with space"),
    ] {
        assert!(from_event_file(event, reference, &path).is_err());
    }
    assert!(from_event_file("push", &"x".repeat(4097), &path).is_err());
    std::fs::write(&path, vec![b' '; 1_048_577]).unwrap();
    assert!(from_event_file("push", "refs/heads/main", &path).is_err());
    assert!(from_event_file("push", "refs/heads/main", &directory.path().join("missing")).is_err());
}

#[test]
fn scope_helper_has_no_process_network_or_publication_dependencies() {
    let source = include_str!("../src/workflow_scope.rs");
    for forbidden in [
        "CommandSpec",
        "std::process",
        "Command::",
        "ureq",
        "reqwest",
        "BuildSourceIdentity",
        "publish::",
        "GITHUB_TOKEN",
        "semver::",
    ] {
        assert!(!source.contains(forbidden), "{forbidden}");
    }
    let cli = include_str!("../src/main.rs");
    assert!(
        cli.contains(
            "CiCommand::WorkflowScope => memcordon_ci::workflow_scope::emit_from_github()"
        )
    );
}
