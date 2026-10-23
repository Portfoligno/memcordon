use memcordon_ci::release::readiness_artifact_catalog::{
    CanonicalCatalog, PackedCatalog, VerifiedCapture, preflight_unique,
};
use memcordon_readiness_verifier::{Artifact, MAX_ARTIFACT_BYTES, MAX_PRODUCER_BYTES};
use std::time::{Duration, Instant};

fn cutoff() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn packed_capture_reads_each_actual_source_before_sharing_and_rejects_changed_later_source() {
    use memcordon_readiness_verifier::{retain_artifact_bytes, sha256};
    for corrupt_second in [false, true] {
        let source = if cfg!(unix) {
            tempfile::tempdir_in("/tmp").unwrap()
        } else {
            tempfile::tempdir().unwrap()
        };
        let destination = if cfg!(unix) {
            tempfile::tempdir_in("/tmp").unwrap()
        } else {
            tempfile::tempdir().unwrap()
        };
        for name in ["first", "second"] {
            std::fs::write(source.path().join(name), b"same").unwrap();
        }
        let records: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|path| Artifact {
                path: path.into(),
                length: b"same".len() as u64,
                sha256: sha256(b"same"),
            })
            .collect();
        let mut captures = Vec::new();
        let catalog = PackedCatalog::capture(
            &records,
            0,
            cutoff(),
            |logical| {
                captures.push(logical.path.clone());
                if corrupt_second && logical.path == "second" {
                    std::fs::write(source.path().join("second"), b"fake").unwrap();
                }
                VerifiedCapture::read(source.path(), logical)
            },
            |object, bytes, existing| {
                retain_artifact_bytes(destination.path(), object, bytes, existing)
                    .map_err(memcordon_ci::CiError::Message)
            },
        );
        assert_eq!(captures, ["first", "second"]);
        if corrupt_second {
            assert!(catalog.is_err());
        } else {
            let catalog = catalog.unwrap();
            assert_eq!(catalog.objects.len(), 1);
            assert_eq!(catalog.bindings.len(), 2);
        }
    }
}
fn record(path: &str) -> Artifact {
    Artifact {
        path: path.into(),
        length: 7,
        sha256: "a".repeat(64),
    }
}

#[test]
fn shared_references_are_each_validated_but_only_unique_bytes_are_planned() {
    let shared = record("lifetime/shared.bin");
    let later = record("recipe-59/journal.bin");
    let records = vec![shared.clone(), shared, later];
    let mut validated = Vec::new();
    let catalog = CanonicalCatalog::build(&records, MAX_PRODUCER_BYTES - 14, cutoff(), |item| {
        validated.push(item.path.clone());
        Ok(())
    })
    .unwrap()
    .into_records();
    assert_eq!(validated.len(), 3);
    assert_eq!(catalog.len(), 2);
    assert!(
        catalog
            .iter()
            .any(|item| item.path == "recipe-59/journal.bin")
    );
    preflight_unique(&catalog, MAX_PRODUCER_BYTES - 14, cutoff()).unwrap();
    assert!(preflight_unique(&records, 0, cutoff()).is_err());
    let mut calls = 0;
    assert!(
        CanonicalCatalog::build(&records, 0, cutoff(), |_| {
            calls += 1;
            if calls == 2 {
                Err(memcordon_ci::CiError::Message(
                    "second held read changed".into(),
                ))
            } else {
                Ok(())
            }
        })
        .is_err()
    );
    assert_eq!(calls, 2);
}

#[test]
fn structural_conflicts_are_rejected_before_any_reader_runs() {
    for path in [
        "producer/x",
        "cell.json",
        "cell.json/child",
        "producer-manifest.json",
        "producer-manifest.json/child",
        "../x",
        "a//b",
        "a/./b",
        "a\\b",
    ] {
        assert!(
            CanonicalCatalog::build(&[record(path)], 0, cutoff(), |_| panic!(
                "reader before preflight"
            ))
            .is_err(),
            "{path}"
        );
    }
    let original = record("shared.bin");
    let mut changed = original.clone();
    changed.sha256 = "b".repeat(64);
    assert!(
        CanonicalCatalog::build(&[original, changed], 0, cutoff(), |_| panic!(
            "conflict read"
        ))
        .is_err()
    );
    assert!(
        CanonicalCatalog::build(&[record("a"), record("a/child")], 0, cutoff(), |_| panic!(
            "parent collision read"
        ))
        .is_err()
    );
}

#[test]
fn bounds_and_original_cutoff_fail_before_validation() {
    assert!(
        CanonicalCatalog::build(&[record(&"a".repeat(4097))], 0, cutoff(), |_| panic!(
            "overlong path read"
        ))
        .is_err()
    );
    let deep: Vec<_> = (0..6)
        .map(|index| {
            let mut components = vec![index.to_string(), "a".repeat(2000)];
            for _ in 0..1000 {
                components.push("x".to_owned());
            }
            record(&components.join("/"))
        })
        .collect();
    let Err(error) = CanonicalCatalog::build(&deep, 0, cutoff(), |_| {
        panic!("excess parent metadata read")
    }) else {
        panic!("excess ancestor metadata was admitted");
    };
    assert!(error.to_string().contains("parent metadata"), "{error}");
    let mut huge = record("large.bin");
    huge.length = MAX_ARTIFACT_BYTES + 1;
    assert!(CanonicalCatalog::build(&[huge], 0, cutoff(), |_| panic!("oversized read")).is_err());
    assert!(
        CanonicalCatalog::build(&[record("a")], u64::MAX, cutoff(), |_| panic!(
            "overflow read"
        ))
        .is_err()
    );
    assert!(
        CanonicalCatalog::build(&[record("a")], 0, Instant::now(), |_| panic!(
            "expired read"
        ))
        .is_err()
    );
}
