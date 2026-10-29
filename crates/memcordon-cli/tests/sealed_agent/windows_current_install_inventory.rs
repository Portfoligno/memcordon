use crate::windows::package::require_absent_install_inventory;

#[test]
fn opaque_install_root_is_refused_without_parsing_or_mutating_its_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("occupied-image-root");
    std::fs::create_dir(&root).unwrap();
    let opaque = root.join("unrecognized-state");
    let bytes = b"\0opaque state\xff\xfe, deliberately not JSON\n";
    std::fs::write(&opaque, bytes).unwrap();
    let error =
        require_absent_install_inventory(&[("installed-image-root", root.clone())]).unwrap_err();
    assert!(error.starts_with("MCSEALED-WINDOWS-ALREADY-INSTALLED:"));
    assert_eq!(std::fs::read(&opaque).unwrap(), bytes);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
}

#[test]
fn absent_current_roots_pass_without_being_created() {
    let temporary = tempfile::tempdir().unwrap();
    let image = temporary.path().join("absent-image-root");
    let diagnostics = temporary.path().join("absent-diagnostics-root");
    require_absent_install_inventory(&[
        ("installed-image-root", image.clone()),
        ("installed-diagnostics-root", diagnostics.clone()),
    ])
    .unwrap();
    assert!(!image.exists());
    assert!(!diagnostics.exists());
}
