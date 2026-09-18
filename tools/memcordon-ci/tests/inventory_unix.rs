#![cfg(unix)]

use memcordon_ci::build_context::BuildInputSnapshot;
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;

#[test]
fn native_inventory_keeps_output_named_directories_and_external_alias_contents() {
    let root = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    for name in ["target", "fuzz/corpus", "fuzz/artifacts"] {
        let directory = root.path().join(name);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("sdk-header"), b"original").unwrap();
    }
    let library = external.path().join("library");
    fs::write(&library, b"first library").unwrap();
    symlink(external.path(), root.path().join("external-sdk")).unwrap();
    for path in [
        root.path().join("target/sdk-header"),
        root.path().join("fuzz/corpus/sdk-header"),
        root.path().join("fuzz/artifacts/sdk-header"),
        library,
    ] {
        let before = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
        before.audit().unwrap();
        fs::write(path, b"changed admitted contents").unwrap();
        assert!(before.audit().is_err());
    }
}

#[test]
#[cfg(target_os = "linux")]
fn native_inventory_preserves_non_unicode_paths_empty_files_and_modes() {
    let root = tempfile::tempdir().unwrap();
    let name = std::ffi::OsString::from_vec(vec![b't', 0xff, b'l']);
    let file = root.path().join(&name);
    fs::write(&file, []).unwrap();
    symlink(&name, root.path().join("selected")).unwrap();
    let empty = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    empty.audit().unwrap();
    fs::write(&file, b"nonempty").unwrap();
    assert!(empty.audit().is_err());
    let contents = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    let old_mode = fs::metadata(&file).unwrap().permissions().mode();
    fs::set_permissions(&file, fs::Permissions::from_mode(old_mode ^ 0o100)).unwrap();
    assert!(contents.audit().is_err());
}

#[test]
fn native_inventory_rejects_socket_inputs_without_reading_them() {
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("unsupported.socket");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let error = BuildInputSnapshot::capture_native_tree(root.path())
        .unwrap_err()
        .to_string();
    assert!(error.contains("unsupported"), "{error}");
}

#[cfg(target_os = "linux")]
#[test]
fn native_descendant_null_device_remains_auditable() {
    let root = tempfile::tempdir().unwrap();
    let link = root.path().join("masked-resource");
    symlink("/dev/null", &link).unwrap();
    let before = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    before.audit().unwrap();
    fs::remove_file(&link).unwrap();
    fs::write(&link, []).unwrap();
    assert!(before.audit().is_err());
}
