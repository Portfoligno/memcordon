use super::*;

#[test]
fn policy_directory_pin_allows_atomic_child_publication_and_prevents_directory_rename() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("policy");
    let renamed = temporary.path().join("renamed");
    std::fs::create_dir(&root).unwrap();
    let pin = pin_directory(&root).unwrap();
    let staged = root.join("policy-activation.pending");
    let destination = root.join("policy-activation.json");
    for bytes in [
        b"first activation\n".as_slice(),
        b"second activation\n".as_slice(),
    ] {
        std::fs::write(&staged, bytes).unwrap();
        super::super::record::replace_atomically(&staged, &destination).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), bytes);
    }
    assert!(std::fs::rename(&root, &renamed).is_err());
    assert!(root.is_dir());
    assert!(!renamed.exists());
    drop(pin);
    std::fs::rename(&root, &renamed).unwrap();
    assert_eq!(
        std::fs::read(renamed.join("policy-activation.json")).unwrap(),
        b"second activation\n"
    );
}
