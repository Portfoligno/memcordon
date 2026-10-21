#![cfg(unix)]
#![deny(unsafe_code, dead_code)]

#[path = "../src/release/frontend_invocation_custody.rs"]
mod custody;

use std::{
    fs::File,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    path::Path,
};

fn observe(directory: &Path) -> Result<(serde_json::Value, serde_json::Value), String> {
    let command = std::fs::symlink_metadata(directory.join("command.json"))
        .map_err(|error| error.to_string())?;
    let endpoint = std::fs::symlink_metadata(directory.join("service.sock"))
        .map_err(|error| error.to_string())?;
    Ok((
        serde_json::json!({"uid":command.uid()}),
        serde_json::json!({"device":endpoint.dev(),"inode":endpoint.ino()}),
    ))
}

fn fixture() -> (tempfile::TempDir, custody::Invocation, UnixListener) {
    let directory = tempfile::tempdir().unwrap();
    let socket = UnixListener::bind(directory.path().join("service.sock")).unwrap();
    let path = directory.path().join("command.json");
    std::fs::write(&path, b"{}").unwrap();
    let (access, endpoint) = observe(directory.path()).unwrap();
    let bytes =
        serde_json::to_vec(&serde_json::json!({"file_access":access,"endpoint_access":endpoint}))
            .unwrap();
    std::fs::write(&path, &bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    let file = File::open(&path).unwrap();
    let uid = file.metadata().unwrap().uid();
    let invocation = custody::Invocation::new(file, path, bytes, uid);
    (directory, invocation, socket)
}

#[test]
fn earned_live_proof_survives_intentional_endpoint_retirement() {
    let (directory, mut invocation, socket) = fixture();
    let expected = invocation.verified(|| observe(directory.path())).unwrap();
    invocation.seal(|| observe(directory.path())).unwrap();
    drop(socket);
    std::fs::remove_file(directory.path().join("service.sock")).unwrap();
    assert_eq!(
        invocation
            .verified(|| Err("endpoint already retired".into()))
            .unwrap(),
        expected
    );
}

#[test]
fn retained_bytes_alone_cannot_create_a_live_proof() {
    let (directory, invocation, socket) = fixture();
    drop(socket);
    std::fs::remove_file(directory.path().join("service.sock")).unwrap();
    assert!(invocation.verified(|| observe(directory.path())).is_err());
}

#[test]
fn replaced_endpoint_cannot_earn_a_live_proof() {
    let (directory, mut invocation, original) = fixture();
    std::fs::remove_file(directory.path().join("service.sock")).unwrap();
    let replacement = UnixListener::bind(directory.path().join("service.sock")).unwrap();
    assert!(invocation.seal(|| observe(directory.path())).is_err());
    drop((original, replacement));
}

#[test]
fn sealed_command_replacement_and_mutation_remain_rejected() {
    let (directory, mut invocation, _socket) = fixture();
    invocation.seal(|| observe(directory.path())).unwrap();
    let path = directory.path().join("command.json");
    let bytes = std::fs::read(&path).unwrap();
    let replacement = directory.path().join("replacement.json");
    std::fs::write(&replacement, bytes).unwrap();
    std::fs::rename(replacement, &path).unwrap();
    assert!(invocation.verified(|| observe(directory.path())).is_err());

    let (directory, mut invocation, _socket) = fixture();
    invocation.seal(|| observe(directory.path())).unwrap();
    let path = directory.path().join("command.json");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] = b'[';
    std::fs::write(&path, bytes).unwrap();
    assert!(invocation.verified(|| observe(directory.path())).is_err());
}
