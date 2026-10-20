use super::*;

#[test]
fn ordinary_observation_path_accepts_another_configured_nightly() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    std::fs::create_dir(root.join("ci")).unwrap();
    std::fs::write(
        root.join("ci/toolchains.toml"),
        include_str!("../../../../ci/toolchains.toml")
            .replace("nightly-2026-07-31", "nightly-2026-07-30"),
    )
    .unwrap();
    let mut queries = 0;
    let identity = identity_with_query(root, |_, arguments| {
        queries += 1;
        Ok(if arguments.first() == Some(&"component") {
            b"rust-src\nmiri\n".to_vec()
        } else {
            b"actual bounded observation\n".to_vec()
        })
    })
    .unwrap();
    assert!(queries > 0);
    let (key, path) = identity.expect("ordinary observations need no nightly approval tuple");
    assert!(!key.is_empty());
    assert_eq!(
        path,
        root.canonicalize().unwrap().join("target/ci-miri-sysroot")
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    crate::preparation::with_operation(
        crate::failure_mode::FailureMode::CollectAll,
        deadline,
        || {
            let unavailable = identity_with_query(root, |_, _| {
                Err(CiError::Message("settled optional query failed".into()))
            });
            assert!(unavailable.is_err());
            assert!(crate::preparation::active_group().unwrap().may_start());
            crate::preparation::with_operation(
                crate::failure_mode::FailureMode::CollectAll,
                deadline,
                || Ok(()),
            )
        },
    )
    .unwrap();
}

#[test]
fn observed_linux_setup_facts_support_reuse_without_a_tuple_catalogue() {
    let facts = BTreeMap::from([
        ("target".into(), "x86_64-unknown-linux-gnu".into()),
        (
            "rustc".into(),
            "rustc nightly-2026-07-31 actual compiler observation".into(),
        ),
        ("miri".into(), "miri actual interpreter observation".into()),
        (
            "components".into(),
            "miri-x86_64-unknown-linux-gnu\nrust-src".into(),
        ),
        ("native-cc".into(), "gcc selected compiler".into()),
        ("ImageVersion".into(), "ordinary-ubuntu-image".into()),
    ]);
    let key = key_for_facts(facts.clone()).unwrap();
    assert!(key.starts_with("mc-"));
    assert_eq!(key, key_for_facts(facts.clone()).unwrap());
    for field in [
        "target",
        "rustc",
        "miri",
        "components",
        "native-cc",
        "ImageVersion",
    ] {
        let mut changed = facts.clone();
        changed.insert(field.into(), "different observed input".into());
        assert_ne!(key, key_for_facts(changed).unwrap(), "{field}");
    }
    let mut another_nightly = facts;
    another_nightly.insert("rustc".into(), "rustc another installed nightly".into());
    assert!(!key_for_facts(another_nightly).unwrap().is_empty());
}
