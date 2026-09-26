use ed25519_dalek::{Signer, SigningKey};
use memcordon_core::release_archive_trust::{
    ArchiveCertificateV1, ArchiveMemberV1, ExpectedArchiveSealV1, SignedArchiveCertificateV1,
};
use memcordon_core::release_trust::{
    DelegatedReleaseKeyV1, ReleaseSigningRoleV1, ReleaseTrustAnchorV1, ReleaseTrustPolicyV1,
    SignedReleaseTrustPolicyV1, TrustHighWaterV1,
};
use memcordon_core::workload_codec::hash_bytes;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn digest(byte: u8) -> String {
    hex(&[byte; 32])
}

#[test]
fn exact_archive_sidecar_rejects_byte_inventory_and_revocation_tamper() {
    let root = SigningKey::from_bytes(&[3; 32]);
    let release = SigningKey::from_bytes(&[7; 32]);
    let policy = ReleaseTrustPolicyV1 {
        schema_version: 1,
        policy_version: 4,
        root_key_id: "test-root".into(),
        repository_id: 101,
        repository: "example/memcordon".into(),
        workflow_path: ".github/workflows/release.yml".into(),
        workflow_revision: digest(1),
        verifier_sha256: digest(2),
        verifier_policy_sha256: digest(3),
        catalogue_sha256: digest(4),
        minimum_release_sequence: 10,
        not_before_unix: 100,
        expires_at_unix: 1000,
        delegated_keys: vec![DelegatedReleaseKeyV1 {
            key_id: "test-release".into(),
            public_key_hex: hex(release.verifying_key().as_bytes()),
            roles: vec![ReleaseSigningRoleV1::ReleaseIndex],
            not_before_unix: 100,
            expires_at_unix: 1000,
        }],
        revoked_key_ids: vec![],
        revoked_certificate_sha256: vec![],
        revoked_qualification_sha256: vec![],
        revoked_build_sha256: vec![],
    };
    let signed_policy = SignedReleaseTrustPolicyV1 {
        signature_hex: hex(&root.sign(&policy.canonical_bytes().unwrap()).to_bytes()),
        payload: policy,
    };
    let anchor = ReleaseTrustAnchorV1 {
        root_key_id: "test-root".into(),
        public_key_hex: hex(root.verifying_key().as_bytes()),
    };
    let high_water = TrustHighWaterV1 {
        policy_version: 3,
        release_sequence: 9,
        last_accepted_wall_unix: 200,
    };
    let verified_policy = signed_policy.verify(&anchor, &high_water, 300).unwrap();
    let archive = b"exact test-only A";
    let members = vec![ArchiveMemberV1 {
        path: "memcordon-v0.5.7-dev-x86_64-unknown-linux-gnu/runtime-manifest.json".into(),
        size: 2,
        mode: 0o644,
        sha256: digest(5),
    }];
    let payload = ArchiveCertificateV1 {
        schema_version: 1,
        policy_version: 4,
        key_id: "test-release".into(),
        release_sequence: 10,
        archive_sha256: String::from(hash_bytes(archive)),
        archive_size: archive.len() as u64,
        members: members.clone(),
        build_sha256: digest(6),
        manifest_sha256: digest(7),
        qualification_sha256: digest(8),
        native_certificate_sha256: digest(9),
        source_commit: "a".repeat(40),
        release_version: "0.5.7-dev".into(),
        target: "x86_64-unknown-linux-gnu".into(),
        issued_at_unix: 200,
        expires_at_unix: 900,
    };
    let signed = SignedArchiveCertificateV1 {
        signature_hex: hex(&release.sign(&payload.canonical_bytes().unwrap()).to_bytes()),
        payload,
    };
    let bytes = serde_json::to_vec(&signed).unwrap();
    fn expected<'a>(
        archive_bytes: &'a [u8],
        members: &'a [ArchiveMemberV1],
    ) -> ExpectedArchiveSealV1<'a> {
        ExpectedArchiveSealV1 {
            archive_bytes,
            members,
            build_sha256: "0606060606060606060606060606060606060606060606060606060606060606",
            manifest_sha256: "0707070707070707070707070707070707070707070707070707070707070707",
            qualification_sha256: "0808080808080808080808080808080808080808080808080808080808080808",
            native_certificate_sha256: "0909090909090909090909090909090909090909090909090909090909090909",
            source_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            release_version: "0.5.7-dev",
            target: "x86_64-unknown-linux-gnu",
            release_sequence: 10,
        }
    }
    let e = expected(archive, &members);
    assert_eq!(signed.payload.build_sha256, e.build_sha256);
    assert_eq!(signed.payload.manifest_sha256, e.manifest_sha256);
    assert_eq!(signed.payload.qualification_sha256, e.qualification_sha256);
    assert_eq!(
        signed.payload.native_certificate_sha256,
        e.native_certificate_sha256
    );
    signed
        .verify(&bytes, &verified_policy, &high_water, &e, 300)
        .unwrap();
    assert!(
        signed
            .verify(
                &bytes,
                &verified_policy,
                &high_water,
                &expected(b"changed A", &members),
                300
            )
            .is_err()
    );
    let mut forged = signed.clone();
    forged.payload.archive_size += 1;
    assert!(
        forged
            .verify(
                &serde_json::to_vec(&forged).unwrap(),
                &verified_policy,
                &high_water,
                &expected(archive, &members),
                300
            )
            .is_err()
    );
    assert!(
        signed
            .verify(
                &bytes,
                &verified_policy,
                &high_water,
                &expected(archive, &members),
                900
            )
            .is_err()
    );
    let mut revoked = signed_policy.payload.clone();
    revoked.revoked_key_ids.push("test-release".into());
    let revoked = SignedReleaseTrustPolicyV1 {
        signature_hex: hex(&root.sign(&revoked.canonical_bytes().unwrap()).to_bytes()),
        payload: revoked,
    };
    let revoked_policy = revoked.verify(&anchor, &high_water, 300).unwrap();
    assert!(
        signed
            .verify(&bytes, &revoked_policy, &high_water, &e, 300)
            .is_err()
    );
}
