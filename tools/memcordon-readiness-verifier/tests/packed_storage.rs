use memcordon_readiness_verifier::{storage::*, *};
use std::collections::{BTreeMap, BTreeSet};

#[path = "support/linux_installed_case.rs"]
mod linux_installed_case;
#[path = "support/linux_legacy_case.rs"]
mod linux_legacy_case;
#[path = "support/persisted_case.rs"]
mod persisted_case;

fn record(path: &str, bytes: &[u8]) -> Artifact {
    Artifact {
        path: path.into(),
        length: bytes.len() as u64,
        sha256: sha256(bytes),
    }
}
fn directory() -> tempfile::TempDir {
    if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
}
fn producer(artifacts: Vec<Artifact>) -> ProducerManifest {
    ProducerManifest {
        format: "memcordon.consumer-readiness.producer".into(),
        revision: 1,
        job: "candidate-linux-x64-native".into(),
        run_id: "12".into(),
        run_attempt: 1,
        source_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        source_tree_sha256: sha256(b"fixture-source-tree"),
        version: "0.5.8-dev".into(),
        manifest_sha256: sha256(b"fixture-manifest"),
        artifacts,
        products: Vec::new(),
        component_builds: Vec::new(),
        records: Vec::new(),
    }
}

#[test]
fn finite_mapping_rejects_missing_extra_recursive_and_archive_aliases() {
    let logical = vec![record("first/raw", b"same"), record("second/raw", b"same")];
    let object = record(&object_path(&sha256(b"same")).unwrap(), b"same");
    let bindings: Vec<_> = logical
        .iter()
        .map(|a| ArtifactBinding {
            logical_path: a.path.clone(),
            object_path: object.path.clone(),
        })
        .collect();
    let plan = StoragePlan::packed(
        &logical,
        std::slice::from_ref(&object),
        &bindings,
        &BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(plan.physical_artifacts().count(), 1);
    assert_eq!(
        plan.resolve("first/raw").unwrap().path,
        plan.resolve("second/raw").unwrap().path
    );
    for reserved in [
        "objects/raw",
        "producer/raw",
        "cell.json/child",
        "producer-manifest.json/child",
        "evidence.json/child",
    ] {
        let artifact = record(reserved, b"same");
        let binding = ArtifactBinding {
            logical_path: artifact.path.clone(),
            object_path: object.path.clone(),
        };
        assert!(
            StoragePlan::packed(
                &[artifact],
                std::slice::from_ref(&object),
                &[binding],
                &BTreeSet::new()
            )
            .is_err()
        );
    }
    for mutation in 0..5 {
        let mut bindings = bindings.clone();
        let mut objects = vec![object.clone()];
        match mutation {
            0 => {
                bindings.pop();
            }
            1 => bindings.push(bindings[0].clone()),
            2 => bindings[0].object_path = "second/raw".into(),
            3 => objects.push(record(&object_path(&sha256(b"extra")).unwrap(), b"extra")),
            _ => bindings[0].logical_path = "objects/sha256/foreign".into(),
        }
        assert!(StoragePlan::packed(&logical, &objects, &bindings, &BTreeSet::new()).is_err());
    }
    let archive = record("origins/producer.zip", b"same");
    let archive_alias = ArtifactBinding {
        logical_path: archive.path.clone(),
        object_path: object.path.clone(),
    };
    assert!(
        StoragePlan::packed(
            &[archive.clone()],
            &[object],
            &[archive_alias],
            &BTreeSet::from([archive.path])
        )
        .is_err()
    );
    assert!(
        StoragePlan::packed(
            &[record("parent", b"a"), record("parent/child", b"b")],
            &[],
            &[],
            &BTreeSet::new()
        )
        .is_err()
    );
}

#[test]
fn physical_budget_counts_original_archive_objects_and_metadata_at_boundary() {
    let raw = record("case/raw", b"x");
    let object = record(&object_path(&raw.sha256).unwrap(), b"x");
    let metadata = 17;
    let archive = Artifact {
        path: "original.zip".into(),
        length: MAX_PRODUCER_BYTES - object.length - metadata,
        sha256: sha256(b"original-archive"),
    };
    let plan = StoragePlan::packed(
        &[raw.clone(), archive.clone()],
        &[object.clone()],
        &[ArtifactBinding {
            logical_path: raw.path.clone(),
            object_path: object.path.clone(),
        }],
        &BTreeSet::from([archive.path]),
    )
    .unwrap();
    assert_eq!(plan.check_budget(metadata).unwrap(), MAX_PRODUCER_BYTES);
    assert!(plan.check_budget(metadata + 1).is_err());
    let local = StoragePlan::packed(
        &[raw.clone()],
        &[object.clone()],
        &[ArtifactBinding {
            logical_path: raw.path,
            object_path: object.path.clone(),
        }],
        &BTreeSet::new(),
    )
    .unwrap();
    let own_members = vec![
        ZipMember {
            name: object.path,
            length: 1,
            directory: false,
        },
        ZipMember {
            name: "cell.json".into(),
            length: 2,
            directory: false,
        },
        ZipMember {
            name: "producer-manifest.json".into(),
            length: 2,
            directory: false,
        },
    ];
    local.validate_zip(&own_members, 3).unwrap();
    assert!(
        local.validate_zip(&own_members[1..], 3).is_err(),
        "another producer's matching object cannot replace an absent own ZIP member"
    );
    let mut extra = own_members;
    extra.push(ZipMember {
        name: "undeclared/".into(),
        length: 0,
        directory: true,
    });
    assert!(local.validate_zip(&extra, 3).is_err());
}

#[test]
fn explicit_envelopes_reject_unknown_revision_fields_and_duplicate_keys() {
    let logical = record("case/raw", b"same");
    let object = record(&object_path(&logical.sha256).unwrap(), b"same");
    let packed = PackedProducerManifestV1 {
        format: "memcordon.consumer-readiness.packed-producer".into(),
        revision: 1,
        producer: producer(vec![logical.clone()]),
        objects: vec![object.clone()],
        bindings: vec![ArtifactBinding {
            logical_path: logical.path,
            object_path: object.path,
        }],
    };
    let bytes = serde_json::to_vec(&packed).unwrap();
    decode_producer(&bytes).unwrap();
    for mutate in ["revision", "unknown", "format"] {
        let mut value = serde_json::to_value(&packed).unwrap();
        value[mutate] = match mutate {
            "revision" => serde_json::json!(2),
            "unknown" => serde_json::json!(true),
            _ => serde_json::json!("future"),
        };
        assert!(decode_producer(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let text = std::str::from_utf8(&bytes).unwrap();
    let duplicate = format!("{{\"revision\":1,{}", text.strip_prefix('{').unwrap());
    assert!(decode_producer(duplicate.as_bytes()).is_err());
}

fn pack(case: &persisted_case::PersistedCase) -> (tempfile::TempDir, PackedEvidenceIndexV1) {
    let root = directory();
    let mut objects = BTreeMap::new();
    let mut bindings = Vec::new();
    let archives: BTreeSet<_> = case
        .index
        .producer_origins
        .iter()
        .map(|origin| origin.bundle_artifact.as_str())
        .collect();
    for logical in &case.index.artifacts {
        let bytes = read_artifact_bytes(case.root.path(), logical).unwrap();
        if archives.contains(logical.path.as_str()) {
            retain_artifact_bytes(root.path(), logical, &bytes, false).unwrap();
            continue;
        }
        let object = record(&object_path(&logical.sha256).unwrap(), &bytes);
        retain_artifact_bytes(
            root.path(),
            &object,
            &bytes,
            objects.contains_key(&object.path),
        )
        .unwrap();
        bindings.push(ArtifactBinding {
            logical_path: logical.path.clone(),
            object_path: object.path.clone(),
        });
        objects.insert(object.path.clone(), object);
    }
    let mut evidence = case.index.clone();
    evidence.records = vec![case.record.clone()];
    (
        root,
        PackedEvidenceIndexV1 {
            format: "memcordon.consumer-readiness.packed-evidence".into(),
            revision: 1,
            evidence,
            objects: objects.into_values().collect(),
            bindings,
        },
    )
}

#[test]
fn packed_and_direct_records_preserve_semantics_and_rehashed_source_associations() {
    let compatible = linux_legacy_case::baseline_v2();
    compatible.validate().unwrap();
    let (root, packed) = pack(&compatible);
    validate_case_document(
        &serde_json::to_vec(&packed).unwrap(),
        &compatible.record.key,
        root.path(),
    )
    .unwrap();
    let mut case = linux_legacy_case::baseline();
    case.validate().unwrap();
    let (root, packed) = pack(&case);
    let bytes = serde_json::to_vec(&packed).unwrap();
    validate_case_document(&bytes, &case.record.key, root.path()).unwrap();
    assert_eq!(
        decode_evidence(&bytes).unwrap().0.producer_origins.len(),
        case.index.producer_origins.len()
    );
    let mut direct = case.index.clone();
    direct.records = vec![case.record.clone()];
    validate_case_document(
        &serde_json::to_vec(&direct).unwrap(),
        &case.record.key,
        case.root.path(),
    )
    .unwrap();
    let origins = std::mem::take(&mut case.index.producer_origins);
    let (local_root, local) = pack(&case);
    let local_bytes = serde_json::to_vec(&local).unwrap();
    assert!(
        decode_evidence(&local_bytes)
            .unwrap()
            .0
            .producer_origins
            .is_empty(),
        "standalone packing cannot invent hosted provenance"
    );
    assert!(
        validate_case_document(&local_bytes, &case.record.key, local_root.path()).is_err(),
        "an installed producer association cannot be proven by object storage alone"
    );
    case.index.producer_origins = origins;
    case.mutate(
        "installed/installed/frozen-legacy/v1/request.json",
        |value| value["expected_epoch"]["revision"] = serde_json::json!(10),
    );
    assert!(case.validate().is_err());
    let (root, packed) = pack(&case);
    assert!(
        validate_case_document(
            &serde_json::to_vec(&packed).unwrap(),
            &case.record.key,
            root.path()
        )
        .is_err()
    );
}

#[test]
fn retained_objects_reject_late_replacement_corruption_and_filesystem_aliases() {
    let root = directory();
    let object = record(&object_path(&sha256(b"same")).unwrap(), b"same");
    retain_artifact_bytes(root.path(), &object, b"same", false).unwrap();
    assert!(retain_artifact_bytes(root.path(), &object, b"fake", true).is_err());
    let path = root.path().join(&object.path);
    std::fs::write(&path, b"fake").unwrap();
    assert!(read_artifact_bytes(root.path(), &object).is_err());
    std::fs::write(&path, b"same").unwrap();
    std::fs::hard_link(&path, root.path().join("alias")).unwrap();
    assert!(read_artifact_bytes(root.path(), &object).is_err());
}
