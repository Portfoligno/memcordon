#[path = "../src/release/original_loader_publication.rs"]
mod publication;

#[test]
fn publication_preserves_exact_bytes_and_refuses_replacement() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("requested-contract.json");
    let bytes = b"{\"revision\":1}";
    publication::publish(&path, bytes).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(
        publication::publish(&path, b"replacement")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[cfg(windows)]
#[test]
fn immutable_custody_succeeds_after_publication_and_refuses_live_writer() {
    use std::{fs::OpenOptions, io::Read, os::windows::fs::OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("requested-contract.json");
    let bytes = b"{\"revision\":1}";
    publication::publish(&path, bytes).unwrap();
    let mut held = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&path)
        .unwrap();
    let mut actual = Vec::new();
    held.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, bytes);
    assert_eq!(
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap_err()
            .raw_os_error(),
        Some(32)
    );
    drop(held);

    let writer = OpenOptions::new().write(true).open(&path).unwrap();
    assert_eq!(
        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .unwrap_err()
            .raw_os_error(),
        Some(32)
    );
    drop(writer);
}
