use memcordon_ci::private_public_abi_outer::{
    PublicAbiHelperImageV1, validate_public_abi_helper_image_v1,
};
use memcordon_core::workload_codec::hash_bytes;

// These bytes exercise the diagnostic object validator, not an ELF loader or
// an origin/installation capability. Production expected hashes come from H1.
fn image() -> (Vec<u8>, PublicAbiHelperImageV1) {
    let bytes = b"independently retained helper bytes".to_vec();
    let metadata = PublicAbiHelperImageV1 {
        device: 42,
        inode: 73,
        uid: 0,
        gid: 0,
        mode: 0o100755,
        nlink: 1,
        size: bytes.len() as u64,
        sha256: hash_bytes(&bytes),
    };
    (bytes, metadata)
}

#[test]
fn original_held_image_matches_exact_pin_and_object() {
    let (bytes, metadata) = image();
    assert_eq!(
        validate_public_abi_helper_image_v1(
            &bytes,
            &serde_json::to_vec(&metadata).unwrap(),
            &metadata.sha256
        )
        .unwrap(),
        (42, 73)
    );
}

#[test]
fn helper_bytes_or_h1_pin_substitution_is_rejected() {
    let (bytes, metadata) = image();
    let wire = serde_json::to_vec(&metadata).unwrap();
    let mut changed = bytes.clone();
    changed[0] ^= 1;
    assert!(validate_public_abi_helper_image_v1(&changed, &wire, &metadata.sha256).is_err());
    assert!(
        validate_public_abi_helper_image_v1(&bytes, &wire, &hash_bytes(b"another H1 helper"))
            .is_err()
    );
}

#[test]
fn helper_object_protection_aliases_and_malformed_metadata_are_rejected() {
    let (bytes, valid) = image();
    for metadata in [
        PublicAbiHelperImageV1 {
            uid: 1,
            ..valid.clone()
        },
        PublicAbiHelperImageV1 {
            gid: 1,
            ..valid.clone()
        },
        PublicAbiHelperImageV1 {
            mode: 0o100775,
            ..valid.clone()
        },
        PublicAbiHelperImageV1 {
            mode: 0o120755,
            ..valid.clone()
        },
        PublicAbiHelperImageV1 {
            mode: 0o100644,
            ..valid.clone()
        },
        PublicAbiHelperImageV1 {
            nlink: 2,
            ..valid.clone()
        },
        PublicAbiHelperImageV1 {
            inode: 0,
            ..valid.clone()
        },
        PublicAbiHelperImageV1 {
            size: valid.size + 1,
            ..valid.clone()
        },
    ] {
        assert!(
            validate_public_abi_helper_image_v1(
                &bytes,
                &serde_json::to_vec(&metadata).unwrap(),
                &valid.sha256
            )
            .is_err()
        );
    }
    let mut extra = serde_json::to_value(&valid).unwrap();
    extra["origin_authorized"] = serde_json::json!(true);
    assert!(
        validate_public_abi_helper_image_v1(
            &bytes,
            &serde_json::to_vec(&extra).unwrap(),
            &valid.sha256
        )
        .is_err()
    );
    assert!(
        validate_public_abi_helper_image_v1(
            &bytes,
            b"{\"device\":42,\"device\":43}",
            &valid.sha256
        )
        .is_err()
    );
}
