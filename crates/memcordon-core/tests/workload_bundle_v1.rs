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

fn search(snapshot: &mut SnapshotManifestV1, directory: &str) {
    snapshot
        .library_directories
        .try_push(RootRelativePath::new(directory.into()).unwrap())
        .unwrap();
}

#[test]
fn empty_search_is_explicit_anchored_and_roundtrips_without_fabricated_members() {
    let mut runtime = manifest(
        "toolchain/lib/rustlib/aarch64-unknown-linux-gnu/bin/gcc-ld/ld.lld",
        b"real immutable member",
    );
    let directory = "toolchain/lib/rustlib/aarch64-unknown-linux-gnu/bin/lib";
    search(&mut runtime, directory);
    search(&mut runtime, "toolchain/absent/deep/lib");
    runtime.validate().unwrap();
    let encoded = runtime.canonical_bytes().unwrap();
    assert_eq!(SnapshotManifestV1::parse(&encoded).unwrap(), runtime);
    assert_eq!(runtime.entries.as_slice().len(), 1);
    let input = manifest("input/source", b"input");
    validate_combined(&runtime, &input).unwrap();
    for writable in [
        directory.to_owned(),
        format!("{directory}/cache"),
        "toolchain/lib".into(),
    ] {
        let layout = serde_json::from_value(serde_json::json!({"writable_roots":[{"id":"w","path":writable,"byte_limit":4096,"generated_execution":false}],"output_files":[]})).unwrap();
        assert!(validate_layout(&runtime, &input, &layout).is_err());
    }
    let layout = serde_json::from_value(serde_json::json!({"writable_roots":[{"id":"w","path":"work","byte_limit":4096,"generated_execution":false}],"output_files":[]})).unwrap();
    validate_layout(&runtime, &input, &layout).unwrap();
}

#[test]
fn empty_search_rejects_unanchored_reserved_and_same_image_object_aliases() {
    let runtime = manifest("sdk/bin/tool", b"immutable");
    for directory in [
        "work",
        "work/lib",
        "sdk-other/lib",
        "proc/self/fd",
        "dev/fd",
        "sys/lib",
        "run/lib",
        "sdk/bin/tool",
        "sdk/bin/tool/lib",
    ] {
        let mut changed = runtime.clone();
        search(&mut changed, directory);
        assert!(changed.validate().is_err(), "accepted {directory}");
    }
    let mut alias = runtime;
    alias
        .entries
        .try_push(ImageEntryV1::Symlink {
            path: RootRelativePath::new("sdk/alias".into()).unwrap(),
            target: RootRelativePath::new("sdk/bin/tool".into()).unwrap(),
        })
        .unwrap();
    for directory in ["sdk/alias", "sdk/alias/lib"] {
        let mut changed = alias.clone();
        search(&mut changed, directory);
        assert!(changed.validate().is_err(), "accepted {directory}");
    }
}

#[test]
fn empty_search_rejects_cross_image_objects_and_preserves_catalogue_bound() {
    let mut runtime = manifest("sdk/bin/tool", b"runtime");
    search(&mut runtime, "sdk/bin/empty/lib");
    for collision in ["sdk/bin/empty", "sdk/bin/empty/lib"] {
        let input = manifest(collision, b"conflicting file");
        assert!(validate_combined(&runtime, &input).is_err());
        let mut input = manifest("input/target", b"input");
        input
            .entries
            .try_push(ImageEntryV1::Symlink {
                path: RootRelativePath::new(collision.into()).unwrap(),
                target: RootRelativePath::new("input/target".into()).unwrap(),
            })
            .unwrap();
        input.validate().unwrap();
        assert!(validate_combined(&runtime, &input).is_err());
        assert!(validate_combined(&input, &runtime).is_err());
    }
    let mut duplicate = runtime.clone();
    search(&mut duplicate, "sdk/bin/empty/lib");
    assert!(duplicate.validate().is_err());
    for index in runtime.library_directories.as_slice().len()..32 {
        search(&mut runtime, &format!("sdk/empty-{index}"));
    }
    runtime.validate().unwrap();
    assert!(
        runtime
            .library_directories
            .try_push(RootRelativePath::new("sdk/overflow".into()).unwrap())
            .is_err()
    );
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
