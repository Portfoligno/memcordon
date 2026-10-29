#![cfg(unix)]
use memcordon_core::workload_request::PrivateRootLayoutV1;
use memcordon_platform::workload_outputs::WorkloadOutputReceiver;

fn receiver(root: &std::path::Path, bytes: &[u8]) -> WorkloadOutputReceiver {
    let layout: PrivateRootLayoutV1 = serde_json::from_value(serde_json::json!({
        "writable_roots":[{"id":"out","path":"out","byte_limit":4096,"generated_execution":false}],
        "output_files":["out/value"]
    }))
    .unwrap();
    let mut receiver = WorkloadOutputReceiver::new(&layout, Some(root)).unwrap();
    let inventory = serde_json::to_vec(&vec![memcordon_core::result_v3::WorkloadOutputFileV1 {
        path: memcordon_core::workload_request::RootRelativePath::new("out/value".into()).unwrap(),
        size: bytes.len() as u64,
        sha256: memcordon_core::hash_bytes(bytes),
    }])
    .unwrap();
    receiver.inventory(&inventory).unwrap();
    receiver
}

fn chunk(bytes: &[u8], total: u64, offset: u64) -> Vec<u8> {
    memcordon_core::workload_chunks::WorkloadOutputChunkV1 {
        file_index: 0,
        total,
        offset,
        bytes,
    }
    .encode()
    .unwrap()
}

#[test]
fn held_root_survives_path_replacement_and_commits_verified_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("destination");
    std::fs::create_dir(&root).unwrap();
    let mut receiver = receiver(&root, b"data");
    let held = temp.path().join("held");
    std::fs::rename(&root, &held).unwrap();
    std::fs::create_dir(&root).unwrap();
    receiver.chunk(&chunk(b"data", 4, 0)).unwrap();
    receiver.finish().unwrap();
    assert_eq!(std::fs::read(held.join("out/value")).unwrap(), b"data");
    assert!(!root.join("out/value").exists());
}

#[test]
fn symlink_parent_does_not_escape_and_stream_failure_is_retained() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("out")).unwrap();
    let mut receiver = receiver(root.path(), b"data");
    receiver.chunk(&chunk(b"data", 4, 0)).unwrap();
    assert!(receiver.finish().is_err());
    assert!(!outside.path().join("value").exists());
}

#[test]
fn digest_failure_and_incomplete_stream_remove_only_owned_partial_leaf() {
    let root = tempfile::tempdir().unwrap();
    let mut corrupt = receiver(root.path(), b"data");
    assert!(corrupt.chunk(&chunk(b"xxxx", 4, 0)).is_err());
    drop(corrupt);
    assert!(!root.path().join("out/value").exists());
    let mut receiver = receiver(root.path(), b"data");
    receiver.chunk(&chunk(b"da", 4, 0)).unwrap();
    std::fs::rename(
        root.path().join("out/value"),
        root.path().join("out/original"),
    )
    .unwrap();
    std::fs::write(root.path().join("out/value"), b"replacement").unwrap();
    drop(receiver);
    assert_eq!(
        std::fs::read(root.path().join("out/value")).unwrap(),
        b"replacement"
    );
}
