use memcordon_ci::CiError;

#[path = "../src/release/owned_resource_open_error.rs"]
mod owned_open;

#[test]
fn actual_initial_absence_retains_the_optional_read_error_kind() {
    let directory = tempfile::tempdir().unwrap();
    for path in [
        directory.path().join("absent-intent.json"),
        directory.path().join("unreached-recipe/intent.json"),
    ] {
        let error = std::fs::File::open(&path).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        match owned_open::open_error(&path, error) {
            CiError::Io(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound),
            error => panic!("initial absence lost its typed distinction: {error}"),
        }
    }
}

#[cfg(unix)]
#[test]
fn actual_no_follow_symlink_failure_cannot_become_optional_absence() {
    use std::os::unix::fs::{OpenOptionsExt, symlink};

    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.json");
    let substituted = directory.path().join("intent.json");
    std::fs::write(&original, b"protected resource").unwrap();
    symlink(&original, &substituted).unwrap();
    let error = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&substituted)
        .unwrap_err();
    assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
    let native_code = error.raw_os_error().unwrap();
    let CiError::Message(message) = owned_open::open_error(&substituted, error) else {
        panic!("symlink rejection became optional absence");
    };
    assert!(message.contains(&format!("{substituted:?}")));
    assert!(message.contains(&format!("os error {native_code}")));
}

#[test]
fn other_open_failures_keep_context_and_cannot_skip_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("not-a-directory");
    std::fs::write(&parent, b"regular file").unwrap();
    let path = parent.join("intent.json");
    #[cfg(unix)]
    {
        let error = std::fs::File::open(&path).unwrap_err();
        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(matches!(
            owned_open::open_error(&path, error),
            CiError::Message(_)
        ));
    }

    let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let CiError::Message(message) = owned_open::open_error(&path, denied) else {
        panic!("permission denial became optional absence");
    };
    assert!(message.contains(&format!("{path:?}")));
}
