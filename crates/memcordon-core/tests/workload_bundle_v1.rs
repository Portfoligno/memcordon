use memcordon_core::workload_bundle::*;
use memcordon_core::workload_request::RootRelativePath;
use memcordon_core::{BoundedVec, DiagnosticSha256};
use std::io::Cursor;

fn manifest(path: &str, bytes: &[u8]) -> SnapshotManifestV1 {
    let mut entries = BoundedVec::default();
    entries
        .try_push(ImageEntryV1::Regular {
            path: RootRelativePath::new(path.into()).unwrap(),
            sha256: memcordon_core::hash_bytes(bytes),
            size: bytes.len().try_into().unwrap(),
            executable: false,
        })
        .unwrap();
    SnapshotManifestV1 {
        format: "memcordon.workload-snapshot".into(),
        revision: 1,
        target: "aarch64-unknown-linux-gnu".into(),
        entries,
        entrypoints: BoundedVec::default(),
        library_directories: BoundedVec::default(),
    }
}

#[test]
fn bounded_stream_copies_measured_bytes_and_rejects_mutation() {
    let manifest = manifest("workspace/source", b"original");
    let member = manifest.regular_members()[0];
    let mut output = Vec::new();
    stream_member(&mut Cursor::new(b"original"), &mut output, member).unwrap();
    assert_eq!(output, b"original");
    assert!(stream_member(&mut Cursor::new(b"mutated!"), &mut Vec::new(), member).is_err());
    assert!(stream_member(&mut Cursor::new(b"short"), &mut Vec::new(), member).is_err());
}

#[test]
fn loader_catalog_requires_immutable_ancestry_and_disjoint_writable_roots() {
    let mut runtime = manifest("lib/libexample.so", b"immutable");
    runtime
        .library_directories
        .try_push(RootRelativePath::new("lib".into()).unwrap())
        .unwrap();
    runtime.validate().unwrap();
    for directory in ["work", "proc/self/fd", "dev/fd"] {
        let mut changed = runtime.clone();
        changed
            .library_directories
            .try_push(RootRelativePath::new(directory.into()).unwrap())
            .unwrap();
        assert!(changed.validate().is_err());
    }
    let input = manifest("input/source", b"input");
    let layout:memcordon_core::workload_request::PrivateRootLayoutV1=serde_json::from_value(serde_json::json!({"writable_roots":[{"id":"w","path":"lib/cache","byte_limit":4096,"generated_execution":false}],"output_files":[]})).unwrap();
    assert!(validate_layout(&runtime, &input, &layout).is_err());
    let mut unknown = serde_json::to_value(&runtime).unwrap();
    unknown["startup_environment"] = serde_json::json!([]);
    assert!(SnapshotManifestV1::parse(&serde_json::to_vec(&unknown).unwrap()).is_err());
}

#[test]
fn indexed_snapshot_alias_resolution_accepts_long_chain_and_rejects_cycle() {
    let mut snapshot = manifest("file", b"contents");
    for index in 0..1024 {
        snapshot
            .entries
            .try_push(ImageEntryV1::Symlink {
                path: RootRelativePath::new(format!("alias-{index}")).unwrap(),
                target: RootRelativePath::new(if index == 0 {
                    "file".into()
                } else {
                    format!("alias-{}", index - 1)
                })
                .unwrap(),
            })
            .unwrap();
    }
    snapshot.validate().unwrap();
    let mut value = serde_json::to_value(snapshot).unwrap();
    value["entries"][1]["target"] = "alias-1023".into();
    assert!(SnapshotManifestV1::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn bundle_headers_bound_sizes_and_composition_before_content() {
    let runtime = manifest("bin/tool", b"runtime");
    let input = manifest("workspace/source", b"input");
    let mut bytes = Vec::new();
    write_bundle_headers(&mut bytes, &runtime, &input).unwrap();
    let parsed = read_bundle_headers(&mut Cursor::new(&bytes)).unwrap();
    assert_eq!(parsed, (runtime.clone(), input));
    assert!(validate_combined(&runtime, &manifest("bin/tool/child", b"bad")).is_err());
    let mut invalid = BUNDLE_MAGIC.to_vec();
    invalid.extend_from_slice(&u64::MAX.to_be_bytes());
    assert!(read_bundle_headers(&mut Cursor::new(invalid)).is_err());
    let mut oversized = runtime;
    oversized.entries = BoundedVec::default();
    oversized
        .entries
        .try_push(ImageEntryV1::Regular {
            path: RootRelativePath::new("tool".into()).unwrap(),
            sha256: DiagnosticSha256::from_bytes([0; 32]),
            size: MEMBER_BYTES + 1,
            executable: true,
        })
        .unwrap();
    assert!(oversized.validate().is_err());
}

#[test]
fn stream_chunks_preserve_role_index_and_checked_offsets() {
    use memcordon_core::workload_chunks::{CHUNK_DATA_BYTES, SnapshotRoleV1, WorkloadChunkV1};
    let chunk = WorkloadChunkV1 {
        role: SnapshotRoleV1::Input,
        member_index: 7,
        total: 10,
        offset: 4,
        bytes: b"bytes",
    };
    let encoded = chunk.encode().unwrap();
    assert_eq!(WorkloadChunkV1::decode(&encoded).unwrap(), chunk);
    let mut unknown = encoded.clone();
    unknown[0] = u8::MAX;
    assert!(WorkloadChunkV1::decode(&unknown).is_err());
    assert!(
        WorkloadChunkV1 {
            offset: u64::MAX,
            total: u64::MAX,
            ..chunk
        }
        .encode()
        .is_err()
    );
    let oversized = vec![0; CHUNK_DATA_BYTES + 1];
    assert!(
        WorkloadChunkV1 {
            role: SnapshotRoleV1::Runtime,
            member_index: 0,
            total: u64::MAX,
            offset: 0,
            bytes: &oversized
        }
        .encode()
        .is_err()
    );
}
