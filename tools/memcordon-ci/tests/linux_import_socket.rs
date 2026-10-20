#![cfg(unix)]

#[path = "../src/release/linux_import_socket.rs"]
mod socket;

use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::fs::{FileTypeExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};

#[test]
fn short_held_alias_creates_real_socket_at_original_long_source() {
    let root = tempfile::Builder::new()
        .prefix("ms-")
        .tempdir_in("/tmp")
        .unwrap();
    let original = root.path().join("a".repeat(80)).join("b".repeat(80));
    std::fs::create_dir_all(&original).unwrap();
    let held = File::open(&original).unwrap();
    let leaf = OsStr::new("input-socket");
    assert!(UnixListener::bind(original.join(leaf)).is_err());
    let alias = root.path().join("a");
    symlink(&original, &alias).unwrap();
    let listener = socket::bind_via_held_alias(&held, &alias, leaf).unwrap();
    assert!(
        std::fs::symlink_metadata(original.join(leaf))
            .unwrap()
            .file_type()
            .is_socket()
    );
    let client = UnixStream::connect(alias.join(leaf)).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    drop(accepted);
    drop(client);
    drop(listener);
    assert!(
        std::fs::symlink_metadata(original.join(leaf))
            .unwrap()
            .file_type()
            .is_socket()
    );
    std::fs::remove_file(original.join(leaf)).unwrap();
}

#[test]
fn alias_must_resolve_to_exact_held_directory() {
    let root = tempfile::Builder::new()
        .prefix("ms-")
        .tempdir_in("/tmp")
        .unwrap();
    let selected = root.path().join("selected");
    let foreign = root.path().join("foreign");
    std::fs::create_dir(&selected).unwrap();
    std::fs::create_dir(&foreign).unwrap();
    let held = File::open(&selected).unwrap();
    let alias = root.path().join("a");
    symlink(&foreign, &alias).unwrap();
    assert!(socket::bind_via_held_alias(&held, &alias, OsStr::new("socket")).is_err());
    assert!(!selected.join("socket").exists());
    assert!(!foreign.join("socket").exists());
    std::fs::remove_file(&alias).unwrap();
    let ordinary = root.path().join("ordinary");
    std::fs::write(&ordinary, b"not a directory").unwrap();
    symlink(&ordinary, &alias).unwrap();
    assert!(socket::bind_via_held_alias(&held, &alias, OsStr::new("socket")).is_err());
}

#[test]
fn socket_leaf_cannot_escape_held_source_directory() {
    let root = tempfile::Builder::new()
        .prefix("ms-")
        .tempdir_in("/tmp")
        .unwrap();
    let held = File::open(root.path()).unwrap();
    for leaf in ["", ".", "..", "../escape", "nested/socket", "/absolute"] {
        assert!(socket::bind_via_held_alias(&held, root.path(), OsStr::new(leaf)).is_err());
    }
    assert!(std::fs::read_dir(root.path()).unwrap().next().is_none());
}
