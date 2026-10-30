#![cfg(unix)]
use memcordon_ci::{
    preparation_tools::{Kind, OwnerProbeBinding, validate_owner_probe_preparation},
    release::{artifacts, source},
};
use memcordon_readiness_verifier::current::linux_owners::{
    OwnerPreparationContext, verify_owner_preparation,
};
use serde_json::{Value, json};

fn proof(kind: &str, producer: &str, target: &str, digest: &str, size: u64) -> Value {
    json!({"format":1,"inputs":{"kind":kind,"source":{"kind":"working","version":"0.5.8-dev","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"host":target,"toolchains":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","invocation":{"repository":"example/repository","workflow":"selected workflow","run":"7","attempt":"1"},"producer":producer},"files":[{"path":"target/ci-runtime/current/memcordon-ci","size":size,"sha256":digest,"executable":true}]})
}

#[test]
fn explicit_current_origins_bind_the_original_controller_without_qualifying_smoke() {
    let image = b"retained image bytes";
    let digest = artifacts::checksum(image);
    for (kind, label, producer) in [
        (Kind::Private, "private", "private-linux-prepare-arm64"),
        (Kind::Readiness, "readiness", "readiness-tools-linux-arm64"),
    ] {
        let proof = proof(
            label,
            producer,
            "aarch64-unknown-linux-gnu",
            &digest,
            image.len() as u64,
        );
        let context = OwnerProbeBinding {
            kind,
            source_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            version: "0.5.8-dev",
            host: "aarch64-unknown-linux-gnu",
            run: "7",
            image_sha256: &digest,
            image_size: image.len() as u64,
        };
        let bytes = serde_json::to_vec(&proof).unwrap();
        validate_owner_probe_preparation(&bytes, &context).unwrap();
        verify_owner_preparation(
            &proof,
            &OwnerPreparationContext {
                source_commit: context.source_commit,
                version: context.version,
                run: context.run,
                target: context.host,
                image_sha256: &digest,
                image_size: context.image_size,
            },
        )
        .unwrap();
        let wrong = OwnerProbeBinding {
            kind: if kind == Kind::Private {
                Kind::Readiness
            } else {
                Kind::Private
            },
            ..context
        };
        assert!(validate_owner_probe_preparation(&bytes, &wrong).is_err());
        assert_eq!(
            bytes,
            serde_json::to_vec(&proof).unwrap(),
            "validation must not rewrite preparation proof"
        );
    }
}

#[test]
fn mismatched_origin_source_run_and_missing_or_duplicate_controller_are_refused() {
    let digest = artifacts::checksum(b"image");
    let original = proof(
        "private",
        "private-linux-prepare-x64",
        "x86_64-unknown-linux-gnu",
        &digest,
        5,
    );
    let context = OwnerProbeBinding {
        kind: Kind::Private,
        source_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        version: "0.5.8-dev",
        host: "x86_64-unknown-linux-gnu",
        run: "7",
        image_sha256: &digest,
        image_size: 5,
    };
    let mut invalids = Vec::new();
    for (pointer, bad) in [
        ("/inputs/kind", json!("private-driver")),
        ("/inputs/producer", json!("readiness-tools-linux-x64")),
        ("/inputs/host", json!("aarch64-unknown-linux-gnu")),
        (
            "/inputs/source/commit",
            json!("cccccccccccccccccccccccccccccccccccccccc"),
        ),
        ("/inputs/source/version", json!("0.5.7-dev")),
        ("/inputs/invocation/run", json!("8")),
        (
            "/files/0/sha256",
            json!("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
        ),
        ("/files/0/size", json!(6)),
        ("/files/0/executable", json!(false)),
        ("/files/0/path", json!("other-controller")),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = bad;
        invalids.push(changed);
    }
    let mut duplicate = original.clone();
    duplicate["files"]
        .as_array_mut()
        .unwrap()
        .push(original["files"][0].clone());
    invalids.push(duplicate);
    let mut missing = original.clone();
    missing["files"] = json!([]);
    invalids.push(missing);
    for invalid in invalids {
        assert!(
            validate_owner_probe_preparation(&serde_json::to_vec(&invalid).unwrap(), &context)
                .is_err()
        );
        assert!(
            verify_owner_preparation(
                &invalid,
                &OwnerPreparationContext {
                    source_commit: context.source_commit,
                    version: context.version,
                    run: context.run,
                    target: context.host,
                    image_sha256: &digest,
                    image_size: 5
                }
            )
            .is_err()
        );
    }
}

#[test]
fn private_receipt_is_exclusive_0600_while_diagnostics_are_separate_and_readable() {
    use std::os::unix::fs::MetadataExt;
    let owner = tempfile::tempdir().unwrap();
    let receipt = owner.path().join("installed-retirement.json");
    source::write_json_new(&receipt, &json!({"actual":"retirement"})).unwrap();
    let bytes = std::fs::read(&receipt).unwrap();
    let metadata = std::fs::metadata(&receipt).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert!(source::write_json_new(&receipt, &json!({"replacement":true})).is_err());
    let diagnostic = owner.path().join("diagnostic.json");
    source::write_diagnostic_json(&diagnostic, &json!({"diagnostic_only":true})).unwrap();
    assert_eq!(std::fs::metadata(diagnostic).unwrap().mode() & 0o777, 0o644);
    assert_eq!(std::fs::read(&receipt).unwrap(), bytes);
    assert_eq!(std::fs::metadata(receipt).unwrap().mode() & 0o777, 0o600);
}
