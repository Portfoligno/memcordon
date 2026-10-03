use memcordon_ci::release::source::{BuildSourceIdentity, SelectedSource};

#[test]
fn working_build_identity_never_becomes_publication_selection() {
    let working = BuildSourceIdentity::Working {
        version: "0.5.7-dev".parse().unwrap(),
        commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
    };
    working.validate().unwrap();
    assert!(working.require_tagged().is_err());
    let bytes = serde_json::to_vec(&working).unwrap();
    assert!(serde_json::from_slice::<SelectedSource>(&bytes).is_err());
    let roundtrip: BuildSourceIdentity = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(roundtrip, working);
    let mut unknown = serde_json::to_value(&working).unwrap();
    unknown["tag_ref"] = serde_json::json!("refs/tags/0.5.7-dev");
    assert!(serde_json::from_value::<BuildSourceIdentity>(unknown).is_err());
}

#[test]
fn tagged_build_identity_preserves_exact_release_ref_and_version_checks() {
    let source = SelectedSource {
        format: "memcordon.selected-source".into(),
        revision: 1,
        repository: "owner/repository".into(),
        tag_ref: "refs/tags/0.5.7-dev".into(),
        commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        version: "0.5.7-dev".parse().unwrap(),
    };
    let selected = BuildSourceIdentity::from(source.clone());
    assert_eq!(selected.require_tagged().unwrap(), &source);
    let mut wrong = source;
    wrong.tag_ref = "refs/tags/0.5.8-dev".into();
    assert!(BuildSourceIdentity::from(wrong).require_tagged().is_err());
    let wrong = BuildSourceIdentity::Working {
        version: "0.5.7-dev".parse().unwrap(),
        commit: "not-an-object".into(),
    };
    assert!(wrong.validate().is_err());
}
