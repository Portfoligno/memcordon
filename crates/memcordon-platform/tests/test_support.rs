use std::fs;

use memcordon_platform::test_support::ProcessIdentity;

#[test]
fn process_identity_publication_atomically_replaces_destination() {
    let temporary = tempfile::tempdir().expect("temporary directory should exist");
    let path = temporary.path().join("identity.pid");
    fs::write(&path, b"").expect("incomplete destination should write");

    let identity = ProcessIdentity {
        pid: 42,
        birth: 1_234_567_890,
    };
    identity
        .publish_to(&path)
        .expect("process identity should publish");

    assert_eq!(
        fs::read_to_string(&path).expect("published identity should read"),
        "42 1234567890\n"
    );
    let entries: Vec<_> = fs::read_dir(temporary.path())
        .expect("temporary directory should read")
        .collect::<Result<_, _>>()
        .expect("temporary directory entries should read");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path(), path);
}
