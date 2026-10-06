use memcordon_ci::release::rehearsal_input::RehearsalInput;
use std::fs;

#[test]
fn exact_envelope_dispatch_rejects_both_neither_and_never_falls_back() {
    #[cfg(unix)]
    let root = tempfile::tempdir_in("/tmp").unwrap();
    #[cfg(not(unix))]
    let root = tempfile::tempdir().unwrap();
    assert!(RehearsalInput::load(root.path()).is_err());
    fs::write(root.path().join("candidate.json"), b"{}").unwrap();
    assert!(RehearsalInput::load(root.path()).is_err());
    fs::write(root.path().join("prepared.json"), b"{}").unwrap();
    assert!(RehearsalInput::load(root.path()).is_err());
    fs::remove_file(root.path().join("candidate.json")).unwrap();
    assert!(RehearsalInput::load(root.path()).is_err());
}
