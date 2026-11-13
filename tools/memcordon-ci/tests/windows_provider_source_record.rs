use memcordon_ci::windows_provider_source_record::{Metadata, SOURCE_BYTES};
use std::path::Path;

#[path = "../src/windows_receipt_identity.rs"]
mod receipt;

fn source(links: u32) -> Metadata {
    Metadata {
        volume_serial: 7,
        file_index: 42,
        attributes: 0x20,
        links,
        bytes: 4,
    }
}

#[test]
fn borrowed_multiple_links_never_gain_owned_receipt_authority() {
    for links in [1, 2, 10] {
        let measured = source(links);
        measured.validate().unwrap();
        let bytes = b"data";
        let hash = memcordon_ci::windows_causal_acceptance::sha256(bytes);
        measured.verify(&measured, bytes, &hash).unwrap();
        assert_eq!(
            receipt::validate(
                Path::new("owned.dll"),
                false,
                measured.attributes,
                measured.links
            )
            .is_ok(),
            links == 1
        );
    }
    // The independent private copy must establish its own strict identity.
    receipt::validate(Path::new("private.dll"), false, 0x20, 1).unwrap();
    assert!(receipt::validate(Path::new("private.dll"), false, 0x20, 2).is_err());
}

#[test]
fn source_metadata_and_measured_bytes_must_remain_coherent() {
    let measured = source(2);
    let bytes = b"data";
    let hash = memcordon_ci::windows_causal_acceptance::sha256(bytes);
    for changed in [
        Metadata {
            file_index: 43,
            ..measured.clone()
        },
        Metadata {
            volume_serial: 8,
            ..measured.clone()
        },
        Metadata {
            links: 3,
            ..measured.clone()
        },
        Metadata {
            attributes: 0x21,
            ..measured.clone()
        },
        Metadata {
            bytes: 5,
            ..measured.clone()
        },
    ] {
        assert!(measured.verify(&changed, bytes, &hash).is_err());
    }
    assert!(measured.verify(&measured, b"date", &hash).is_err());
    assert!(measured.verify(&measured, b"dat", &hash).is_err());
    assert!(measured.verify(&measured, bytes, &"0".repeat(64)).is_err());
}

#[test]
fn missing_links_wrong_type_reparse_and_size_bounds_are_refused() {
    let measured = source(2);
    for invalid in [
        Metadata {
            links: 0,
            ..measured.clone()
        },
        Metadata {
            attributes: 0x10,
            ..measured.clone()
        },
        Metadata {
            attributes: 0x420,
            ..measured.clone()
        },
        Metadata {
            bytes: 0,
            ..measured.clone()
        },
        Metadata {
            bytes: SOURCE_BYTES + 1,
            ..measured.clone()
        },
    ] {
        assert!(invalid.validate().is_err());
    }
    Metadata {
        bytes: SOURCE_BYTES,
        ..measured
    }
    .validate()
    .unwrap();
    // Existing compiler-source policy is not repurposed as provider authority.
    assert!(receipt::validate_compiler_source(Path::new("compiler.dll"), 0x400, 2).is_err());
}

#[cfg(windows)]
#[test]
fn borrowed_linked_source_publishes_independent_strict_bytes_without_overwrite() {
    use memcordon_ci::windows_native_files::{HeldProviderSource, hold_artifact};
    use std::{
        fs,
        time::{Duration, Instant},
    };
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.dll");
    let alias = directory.path().join("alias.dll");
    let destination = directory.path().join("private.dll");
    fs::write(&source, b"data").unwrap();
    fs::hard_link(&source, &alias).unwrap();
    let work = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    assert!(hold_artifact(&source, None, SOURCE_BYTES).is_err());
    let held = HeldProviderSource::hold(&source, work).unwrap();
    assert_eq!(held.metadata.links, 2);
    let copied = held.publish(&destination, work).unwrap();
    assert_eq!(copied.bytes, b"data");
    assert_ne!(
        copied.identity(&destination).unwrap(),
        (held.metadata.volume_serial, held.metadata.file_index)
    );
    assert!(held.publish(&destination, work).is_err());
    held.verify(work).unwrap();
    assert_eq!(fs::read(&source).unwrap(), b"data");
    assert_eq!(fs::read(&alias).unwrap(), b"data");
    assert_eq!(fs::read(&destination).unwrap(), b"data");
    assert!(HeldProviderSource::hold(&source, Instant::now()).is_err());
    drop(copied);
    drop(held);
}
