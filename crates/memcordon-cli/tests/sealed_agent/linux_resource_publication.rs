#![cfg(target_os = "linux")]
use crate::linux::workload_resources::{anonymous_charge, publish_anonymous_charge};
use std::{fs::File, io::Write, os::unix::fs::MetadataExt};

#[test]
fn interrupted_charge_write_has_no_named_partial_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let held = File::open(directory.path()).unwrap();
    let mut charge = anonymous_charge(&held).unwrap();
    assert_eq!(charge.metadata().unwrap().nlink(), 0);
    charge.write_all(&[1, 2, 3]).unwrap();
    charge.sync_all().unwrap();
    drop(charge);
    assert!(
        std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn full_charge_publication_keeps_original_inode_and_refuses_occupied_name() {
    let directory = tempfile::tempdir().unwrap();
    let held = File::open(directory.path()).unwrap();
    let mut charge = anonymous_charge(&held).unwrap();
    let original = charge.metadata().unwrap();
    publish_anonymous_charge(&held, &mut charge, c"charge", 123456).unwrap();
    let named = std::fs::metadata(directory.path().join("charge")).unwrap();
    assert_eq!((named.dev(), named.ino()), (original.dev(), original.ino()));
    assert_eq!(
        std::fs::read(directory.path().join("charge")).unwrap(),
        123456_u64.to_be_bytes()
    );
    let mut other = anonymous_charge(&held).unwrap();
    assert!(publish_anonymous_charge(&held, &mut other, c"charge", 654321).is_err());
    assert_eq!(other.metadata().unwrap().nlink(), 0);
    assert_eq!(
        std::fs::read(directory.path().join("charge")).unwrap(),
        123456_u64.to_be_bytes()
    );
}

#[test]
fn intake_budget_charges_fixed_shared_memory_and_page_rounded_small_objects() {
    use memcordon_core::{
        BoundedVec,
        workload_bundle::{ImageEntryV1, SnapshotManifestV1},
        workload_request::{RootRelativePath, WorkloadRequestV1},
    };
    let empty = SnapshotManifestV1 {
        format: "memcordon.workload-snapshot".into(),
        revision: 1,
        target: "aarch64-unknown-linux-gnu".into(),
        entries: BoundedVec::default(),
        entrypoints: BoundedVec::default(),
        library_directories: BoundedVec::default(),
    };
    let request=WorkloadRequestV1::parse(&serde_json::to_vec(&serde_json::json!({"format":"memcordon.workload-request","revision":1,"runtime":{"kind":"linux-private","profile":"linux-private-workload-v1","inputs":{"runtime_digest":"01".repeat(32),"input_digest":"02".repeat(32),"entrypoint":"tool"},"layout":{"writable_roots":[],"output_files":[]}},"requirements":[]})).unwrap()).unwrap();
    let base = crate::linux::workload_inputs::footprint(&empty, &empty, &request).unwrap();
    assert!(
        base >= 64 * 1024 * 1024,
        "fixed private shared memory was omitted"
    );
    let mut tiny = empty.clone();
    tiny.entries
        .try_push(ImageEntryV1::Regular {
            path: RootRelativePath::new("nested/tiny".into()).unwrap(),
            sha256: memcordon_core::hash_bytes(b"x"),
            size: 1,
            executable: false,
        })
        .unwrap();
    let charged = crate::linux::workload_inputs::footprint(&tiny, &empty, &request).unwrap();
    assert!(
        charged - base >= 4096,
        "small objects cannot be charged as one physical byte"
    );
    let mut overflow = serde_json::to_value(tiny).unwrap();
    overflow["entries"][0]["size"] = u64::MAX.into();
    let overflow: SnapshotManifestV1 = serde_json::from_value(overflow).unwrap();
    assert!(crate::linux::workload_inputs::footprint(&overflow, &empty, &request).is_err());
}

#[test]
fn writable_inode_and_byte_bounds_include_tiny_quotas_and_reject_overflow() {
    use crate::linux::workload_resources::{rounded_bytes, writable_inode_limit};
    assert_eq!(rounded_bytes(1, 4096).unwrap(), 4096);
    assert_eq!(rounded_bytes(4096, 4096).unwrap(), 4096);
    assert!(writable_inode_limit(1, 4096).unwrap() >= 64);
    assert!(writable_inode_limit(16 * 1024 * 1024 * 1024, 4096).unwrap() <= 65536);
    assert!(rounded_bytes(u64::MAX, 4096).is_err());
    assert!(writable_inode_limit(1, 0).is_err());
}
