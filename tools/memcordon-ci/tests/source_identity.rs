#[test]
fn publication_requires_full_source_identity() {
    use memcordon_ci::source_identity::validate;
    for commit in [
        "unknown",
        "",
        "abcd",
        "refs/heads/main",
        "0123456789abcdef0123456789abcdef0123456g",
    ] {
        assert!(validate(commit).is_err(), "{commit}");
    }
    for commit in ["ab".repeat(20), "cd".repeat(32)] {
        validate(&commit).unwrap();
        assert!(validate(&format!("{commit}\n")).is_err());
    }
    assert!(validate(&"00".repeat(20)).is_err());
}

#[test]
fn certification_rejects_unknown_before_resolving_artifacts() {
    use memcordon_ci::certification_context::ExpectedCertificationOrigin;
    let origin = ExpectedCertificationOrigin {
        source_commit: "unknown".into(),
        repository: "owner/project".into(),
        run_id: std::num::NonZeroU64::new(1).unwrap(),
        workflow_ref: "owner/project/.github/workflows/release.yml@refs/tags/1.0.0".into(),
        workflow_commit: "ab".repeat(20),
    };
    let error = memcordon_ci::release_evidence::validate_required_certification_records(
        &std::collections::BTreeMap::new(),
        &origin,
        |_| panic!("unknown provenance must be rejected before artifact access"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("unknown is forbidden"));
}
