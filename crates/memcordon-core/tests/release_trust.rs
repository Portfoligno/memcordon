use ed25519_dalek::{Signer, SigningKey};
use memcordon_core::release_trust::{
    DelegatedReleaseKeyV1, ExpectedNativeQualificationV1, NativeQualificationCertificateV1,
    ReleaseRollbackExceptionV1, ReleaseRootRotationV1, ReleaseSigningRoleV1, ReleaseTrustAnchorV1,
    ReleaseTrustPolicyV1, SignedNativeQualificationCertificateV1, SignedReleaseRollbackExceptionV1,
    SignedReleaseRootRotationV1, SignedReleaseTrustPolicyV1, TrustHighWaterV1,
};
use memcordon_core::workload_codec::hash_bytes;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest(byte: u8) -> String {
    hex(&[byte; 32])
}

fn fixture() -> (
    SignedReleaseTrustPolicyV1,
    SignedNativeQualificationCertificateV1,
    ReleaseTrustAnchorV1,
    Vec<u8>,
) {
    let root = SigningKey::from_bytes(&[3; 32]);
    let delegated = SigningKey::from_bytes(&[7; 32]);
    let q_bytes = b"test-only verified qualification".to_vec();
    let policy = ReleaseTrustPolicyV1 {
        schema_version: 1,
        policy_version: 4,
        root_key_id: "offline-root-1".into(),
        repository_id: 101,
        repository: "Portfoligno/memcordon".into(),
        workflow_path: ".github/workflows/release.yml".into(),
        workflow_revision: digest(1),
        verifier_sha256: digest(8),
        verifier_policy_sha256: digest(2),
        catalogue_sha256: digest(3),
        minimum_release_sequence: 10,
        not_before_unix: 100,
        expires_at_unix: 1000,
        delegated_keys: vec![DelegatedReleaseKeyV1 {
            key_id: "ci-q-1".into(),
            public_key_hex: hex(delegated.verifying_key().as_bytes()),
            roles: vec![ReleaseSigningRoleV1::NativeQ],
            not_before_unix: 100,
            expires_at_unix: 1000,
        }],
        revoked_key_ids: vec![],
        revoked_certificate_sha256: vec![],
        revoked_qualification_sha256: vec![],
        revoked_build_sha256: vec![],
    };
    let policy_signature = root.sign(&policy.canonical_bytes().unwrap());
    let signed_policy = SignedReleaseTrustPolicyV1 {
        payload: policy,
        signature_hex: hex(&policy_signature.to_bytes()),
    };
    let payload = NativeQualificationCertificateV1 {
        schema_version: 1,
        policy_version: 4,
        key_id: "ci-q-1".into(),
        release_sequence: 10,
        build_sha256: digest(4),
        build_context_sha256: digest(5),
        target: "x86_64-unknown-linux-gnu".into(),
        native_machine: "x86_64".into(),
        source_commit: "a".repeat(40),
        release_version: "0.5.7-dev".into(),
        qualification_sha256: String::from(hash_bytes(&q_bytes)),
        qualification_size: q_bytes.len() as u64,
        raw_index_sha256: digest(6),
        completed_provenance_sha256: digest(7),
        repository_id: 101,
        repository: "Portfoligno/memcordon".into(),
        workflow_path: ".github/workflows/release.yml".into(),
        workflow_revision: digest(1),
        run_id: 11,
        run_attempt: 1,
        producer_job_id: 12,
        artifact_id: 13,
        verifier_sha256: digest(8),
        verifier_source_commit: "a".repeat(40),
        verifier_policy_sha256: digest(2),
        catalogue_sha256: digest(3),
        accepted_case_set_sha256: digest(9),
        issued_at_unix: 200,
        expires_at_unix: 900,
        decision: "Complete".into(),
    };
    let signature = delegated.sign(&payload.canonical_bytes().unwrap());
    let signed_certificate = SignedNativeQualificationCertificateV1 {
        payload,
        signature_hex: hex(&signature.to_bytes()),
    };
    let anchor = ReleaseTrustAnchorV1 {
        root_key_id: "offline-root-1".into(),
        public_key_hex: hex(root.verifying_key().as_bytes()),
    };
    (signed_policy, signed_certificate, anchor, q_bytes)
}

fn expected<'a>(q_bytes: &'a [u8]) -> ExpectedNativeQualificationV1<'a> {
    ExpectedNativeQualificationV1 {
        repository_id: 101,
        repository: "Portfoligno/memcordon",
        workflow_path: ".github/workflows/release.yml",
        workflow_revision: "0101010101010101010101010101010101010101010101010101010101010101",
        target: "x86_64-unknown-linux-gnu",
        native_machine: "x86_64",
        verifier_sha256: "0808080808080808080808080808080808080808080808080808080808080808",
        source_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        release_version: "0.5.7-dev",
        build_sha256: "0404040404040404040404040404040404040404040404040404040404040404",
        build_context_sha256: "0505050505050505050505050505050505050505050505050505050505050505",
        qualification_bytes: q_bytes,
        raw_index_sha256: "0606060606060606060606060606060606060606060606060606060606060606",
        completed_provenance_sha256: "0707070707070707070707070707070707070707070707070707070707070707",
        accepted_case_set_sha256: "0909090909090909090909090909090909090909090909090909090909090909",
    }
}

#[test]
fn independently_anchored_q_round_trip_and_subject_binding() {
    let (signed_policy, signed_certificate, anchor, q_bytes) = fixture();
    assert_eq!(
        String::from(hash_bytes(
            &signed_policy.payload.canonical_bytes().unwrap()
        )),
        "9613a6f2896f01d6d1deb479a61173c2ee0543d795c9044009a937fd2125604f"
    );
    assert_eq!(
        String::from(hash_bytes(
            &signed_certificate.payload.canonical_bytes().unwrap()
        )),
        "cbd55887f59409efe072f5a04b0b9c11534f1265c2f55ed4791c5a807c3548de"
    );
    let high_water = TrustHighWaterV1 {
        policy_version: 3,
        release_sequence: 9,
        last_accepted_wall_unix: 200,
    };
    let policy_bytes = serde_json::to_vec(&signed_policy).unwrap();
    let policy = SignedReleaseTrustPolicyV1::parse(&policy_bytes)
        .unwrap()
        .verify(&anchor, &high_water, 300)
        .unwrap();
    let certificate_bytes = serde_json::to_vec(&signed_certificate).unwrap();
    let cert = SignedNativeQualificationCertificateV1::parse(&certificate_bytes).unwrap();
    assert!(
        cert.verify(&policy, &expected(&q_bytes), &high_water, 300)
            .is_ok()
    );

    let mut wrong_q = q_bytes.clone();
    wrong_q.push(0);
    assert!(
        cert.verify(&policy, &expected(&wrong_q), &high_water, 300)
            .is_err()
    );
    let mut forged = cert.clone();
    forged.payload.release_sequence += 1;
    assert!(
        forged
            .verify(&policy, &expected(&q_bytes), &high_water, 300)
            .is_err()
    );
    assert!(
        cert.verify(&policy, &expected(&q_bytes), &high_water, 900)
            .is_err()
    );
    assert!(
        cert.verify(
            &policy,
            &expected(&q_bytes),
            &TrustHighWaterV1 {
                release_sequence: 11,
                ..high_water.clone()
            },
            300
        )
        .is_err()
    );
}

#[test]
fn self_supplied_root_and_changed_policy_are_rejected() {
    let (signed_policy, signed_certificate, anchor, q_bytes) = fixture();
    let high_water = TrustHighWaterV1 {
        policy_version: 0,
        release_sequence: 0,
        last_accepted_wall_unix: 0,
    };
    let wrong_anchor = ReleaseTrustAnchorV1 {
        root_key_id: anchor.root_key_id.clone(),
        public_key_hex: hex(SigningKey::from_bytes(&[11; 32]).verifying_key().as_bytes()),
    };
    assert!(
        signed_policy
            .verify(&wrong_anchor, &high_water, 300)
            .is_err()
    );
    let mut revoked_policy = signed_policy.clone();
    revoked_policy.payload.revoked_qualification_sha256 =
        vec![signed_certificate.payload.qualification_sha256.clone()];
    assert!(revoked_policy.verify(&anchor, &high_water, 300).is_err());
    let policy = signed_policy.verify(&anchor, &high_water, 300).unwrap();
    let mut wrong_role = signed_certificate.clone();
    wrong_role.payload.key_id = "unknown-key".into();
    assert!(
        wrong_role
            .verify(&policy, &expected(&q_bytes), &high_water, 300)
            .is_err()
    );
    let mut malformed = serde_json::to_vec(&signed_certificate).unwrap();
    malformed.extend_from_slice(b" trailing");
    assert!(SignedNativeQualificationCertificateV1::parse(&malformed).is_err());
    let mut unknown: serde_json::Value =
        serde_json::from_slice(&serde_json::to_vec(&signed_certificate).unwrap()).unwrap();
    unknown["unexpected_authority"] = serde_json::json!(true);
    assert!(
        SignedNativeQualificationCertificateV1::parse(&serde_json::to_vec(&unknown).unwrap(),)
            .is_err()
    );
    let encoded = serde_json::to_string(&signed_certificate).unwrap();
    let duplicate = format!(
        "{},\"signature_hex\":\"00\"}}",
        encoded.strip_suffix('}').unwrap()
    );
    assert!(SignedNativeQualificationCertificateV1::parse(duplicate.as_bytes()).is_err());
}

#[test]
fn root_signed_revocation_and_role_limits_close_q() {
    let (mut signed_policy, signed_certificate, anchor, q_bytes) = fixture();
    let high_water = TrustHighWaterV1 {
        policy_version: 0,
        release_sequence: 0,
        last_accepted_wall_unix: 0,
    };
    signed_policy.payload.revoked_qualification_sha256 =
        vec![signed_certificate.payload.qualification_sha256.clone()];
    let root = SigningKey::from_bytes(&[3; 32]);
    signed_policy.signature_hex = hex(&root
        .sign(&signed_policy.payload.canonical_bytes().unwrap())
        .to_bytes());
    let revoked = signed_policy.verify(&anchor, &high_water, 300).unwrap();
    assert!(
        signed_certificate
            .verify(&revoked, &expected(&q_bytes), &high_water, 300)
            .is_err()
    );

    signed_policy.payload.revoked_qualification_sha256.clear();
    signed_policy.payload.delegated_keys[0].roles = vec![ReleaseSigningRoleV1::PublicP];
    signed_policy.signature_hex = hex(&root
        .sign(&signed_policy.payload.canonical_bytes().unwrap())
        .to_bytes());
    let wrong_role = signed_policy.verify(&anchor, &high_water, 300).unwrap();
    assert!(
        signed_certificate
            .verify(&wrong_role, &expected(&q_bytes), &high_water, 300)
            .is_err()
    );
}

#[test]
fn rollback_requires_exact_root_signed_build_and_q() {
    let (signed_policy, signed_certificate, anchor, q_bytes) = fixture();
    let high_water = TrustHighWaterV1 {
        policy_version: 4,
        release_sequence: 11,
        last_accepted_wall_unix: 250,
    };
    let policy = signed_policy.verify(&anchor, &high_water, 300).unwrap();
    assert!(
        signed_certificate
            .verify(&policy, &expected(&q_bytes), &high_water, 300)
            .is_err()
    );
    let root = SigningKey::from_bytes(&[3; 32]);
    let payload = ReleaseRollbackExceptionV1 {
        schema_version: 1,
        root_key_id: anchor.root_key_id.clone(),
        policy_version: 4,
        build_sha256: signed_certificate.payload.build_sha256.clone(),
        qualification_sha256: signed_certificate.payload.qualification_sha256.clone(),
        allowed_release_sequence: 10,
        issued_at_unix: 280,
        expires_at_unix: 350,
    };
    let signed = SignedReleaseRollbackExceptionV1 {
        signature_hex: hex(&root.sign(&payload.canonical_bytes().unwrap()).to_bytes()),
        payload,
    };
    let exception = signed.verify(&anchor, &policy, 300).unwrap();
    assert!(
        signed_certificate
            .verify_with_rollback(
                &policy,
                &expected(&q_bytes),
                &high_water,
                Some(&exception),
                300
            )
            .is_ok()
    );
    assert!(signed.verify(&anchor, &policy, 350).is_err());
    let mut wrong = signed;
    wrong.payload.build_sha256 = digest(42);
    assert!(wrong.verify(&anchor, &policy, 300).is_err());
}

#[test]
fn root_rotation_requires_both_keys_and_higher_policy_version() {
    let (_, _, previous, _) = fixture();
    let next_key = SigningKey::from_bytes(&[13; 32]);
    let next = ReleaseTrustAnchorV1 {
        root_key_id: "offline-root-2".into(),
        public_key_hex: hex(next_key.verifying_key().as_bytes()),
    };
    let payload = ReleaseRootRotationV1 {
        schema_version: 1,
        previous_root_key_id: previous.root_key_id.clone(),
        previous_root_public_key_hex: previous.public_key_hex.clone(),
        next_root_key_id: next.root_key_id.clone(),
        next_root_public_key_hex: next.public_key_hex.clone(),
        minimum_next_policy_version: 5,
        issued_at_unix: 250,
        expires_at_unix: 350,
    };
    let bytes = payload.canonical_bytes().unwrap();
    let signed = SignedReleaseRootRotationV1 {
        payload,
        previous_root_signature_hex: hex(&SigningKey::from_bytes(&[3; 32]).sign(&bytes).to_bytes()),
        next_root_signature_hex: hex(&next_key.sign(&bytes).to_bytes()),
    };
    assert_eq!(
        signed
            .verify(&previous, &next, 4, 300)
            .unwrap()
            .minimum_next_policy_version(),
        5
    );
    assert!(signed.verify(&previous, &next, 5, 300).is_err());
    assert!(signed.verify(&previous, &next, 4, 350).is_err());
    let mut one_signature = signed.clone();
    one_signature.next_root_signature_hex = "00".repeat(64);
    assert!(one_signature.verify(&previous, &next, 4, 300).is_err());
    let wrong_previous = ReleaseTrustAnchorV1 {
        root_key_id: previous.root_key_id,
        public_key_hex: hex(SigningKey::from_bytes(&[17; 32]).verifying_key().as_bytes()),
    };
    assert!(signed.verify(&wrong_previous, &next, 4, 300).is_err());
}
