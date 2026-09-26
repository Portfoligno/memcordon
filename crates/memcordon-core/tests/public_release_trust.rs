use ed25519_dalek::{Signer, SigningKey};
use memcordon_core::public_release_trust::{
    ExpectedPublicQualificationV1, PublicQualificationCertificateV1,
    SignedPublicQualificationCertificateV1,
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
fn public_certificate_requires_independent_archive_host_and_p_subject() {
    let root = SigningKey::from_bytes(&[3; 32]);
    let delegated = SigningKey::from_bytes(&[9; 32]);
    let p = b"test-only detached public evidence";
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
            key_id: "ci-p-1".into(),
            public_key_hex: hex(delegated.verifying_key().as_bytes()),
            roles: vec![ReleaseSigningRoleV1::PublicP],
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
    let high_water = TrustHighWaterV1 {
        policy_version: 4,
        release_sequence: 9,
        last_accepted_wall_unix: 200,
    };
    let verified_policy = signed_policy
        .verify(
            &ReleaseTrustAnchorV1 {
                root_key_id: "offline-root-1".into(),
                public_key_hex: hex(root.verifying_key().as_bytes()),
            },
            &high_water,
            300,
        )
        .unwrap();
    let payload = PublicQualificationCertificateV1 {
        schema_version: 1,
        policy_version: 4,
        key_id: "ci-p-1".into(),
        release_sequence: 10,
        build_sha256: digest(4),
        qualification_sha256: digest(5),
        qualification_certificate_sha256: digest(6),
        archive_sha256: digest(7),
        manifest_sha256: digest(10),
        host_receipt_sha256: digest(11),
        public_evidence_sha256: String::from(hash_bytes(p)),
        public_evidence_size: p.len() as u64,
        raw_index_sha256: digest(12),
        completed_provenance_sha256: digest(13),
        target: "x86_64-unknown-linux-gnu".into(),
        native_machine: "x86_64".into(),
        source_commit: "a".repeat(40),
        release_version: "0.5.7-dev".into(),
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
        accepted_case_set_sha256: digest(14),
        issued_at_unix: 200,
        expires_at_unix: 900,
        decision: "Complete".into(),
    };
    let certificate = SignedPublicQualificationCertificateV1 {
        signature_hex: hex(&delegated
            .sign(&payload.canonical_bytes().unwrap())
            .to_bytes()),
        payload,
    };
    let expected = ExpectedPublicQualificationV1 {
        release_sequence: 10,
        repository_id: 101,
        repository: "Portfoligno/memcordon",
        workflow_path: ".github/workflows/release.yml",
        workflow_revision: &digest(1),
        run_id: 11,
        run_attempt: 1,
        producer_job_id: 12,
        artifact_id: 13,
        target: "x86_64-unknown-linux-gnu",
        native_machine: "x86_64",
        source_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        release_version: "0.5.7-dev",
        verifier_sha256: &digest(8),
        verifier_source_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        build_sha256: &digest(4),
        qualification_sha256: &digest(5),
        qualification_certificate_sha256: &digest(6),
        archive_sha256: &digest(7),
        manifest_sha256: &digest(10),
        host_receipt_sha256: &digest(11),
        public_evidence_bytes: p,
        raw_index_sha256: &digest(12),
        completed_provenance_sha256: &digest(13),
        accepted_case_set_sha256: &digest(14),
    };
    assert!(
        certificate
            .verify(&verified_policy, &expected, &high_water, 300)
            .is_ok()
    );
    let mut wrong_archive = certificate.clone();
    wrong_archive.payload.archive_sha256 = digest(15);
    assert!(
        wrong_archive
            .verify(&verified_policy, &expected, &high_water, 300)
            .is_err()
    );
    let mut wrong_host = certificate.clone();
    wrong_host.payload.host_receipt_sha256 = digest(16);
    assert!(
        wrong_host
            .verify(&verified_policy, &expected, &high_water, 300)
            .is_err()
    );
    let mut wrong_p = certificate.clone();
    wrong_p.payload.public_evidence_sha256 = digest(17);
    assert!(
        wrong_p
            .verify(&verified_policy, &expected, &high_water, 300)
            .is_err()
    );
    assert!(
        certificate
            .verify(&verified_policy, &expected, &high_water, 900)
            .is_err()
    );
    use memcordon_core::public_release_trust::{
        ExpectedPublicQualificationV2, PublicQualificationCertificateV2,
        SignedPublicQualificationCertificateV2,
    };
    let extension = PublicQualificationCertificateV2 {
        schema_version: 2,
        subject: certificate.payload.clone(),
        payload_index_sha256: digest(21),
        origin_commitment_sha256: digest(22),
        custody_receipt_sha256: digest(23),
        generation_timeline_sha256: digest(24),
        qualification_certificate_file_sha256: digest(25),
        semantics_sha256: digest(26),
    };
    let cp2 = SignedPublicQualificationCertificateV2 {
        signature_hex: hex(&delegated
            .sign(&extension.canonical_bytes().unwrap())
            .to_bytes()),
        payload: extension,
    };
    let expected2 = ExpectedPublicQualificationV2 {
        subject: expected,
        payload_index_sha256: &digest(21),
        origin_commitment_sha256: &digest(22),
        custody_receipt_sha256: &digest(23),
        generation_timeline_sha256: &digest(24),
        qualification_certificate_file_sha256: &digest(25),
        semantics_sha256: &digest(26),
    };
    assert!(
        cp2.verify(&verified_policy, &expected2, &high_water, 300)
            .is_ok()
    );
    for field in 0..6 {
        let mut mutation = cp2.clone();
        match field {
            0 => mutation.payload.payload_index_sha256 = digest(27),
            1 => mutation.payload.origin_commitment_sha256 = digest(27),
            2 => mutation.payload.custody_receipt_sha256 = digest(27),
            3 => mutation.payload.generation_timeline_sha256 = digest(27),
            4 => mutation.payload.qualification_certificate_file_sha256 = digest(27),
            5 => mutation.payload.semantics_sha256 = digest(27),
            _ => unreachable!(),
        }
        // A valid delegated signature cannot override independent expected
        // physical provenance, including CQ file vs canonical payload hash.
        mutation.signature_hex = hex(&delegated
            .sign(&mutation.payload.canonical_bytes().unwrap())
            .to_bytes());
        assert!(
            mutation
                .verify(&verified_policy, &expected2, &high_water, 300)
                .is_err()
        );
    }
    let mut old_domain = cp2.clone();
    old_domain.signature_hex = certificate.signature_hex;
    assert!(
        old_domain
            .verify(&verified_policy, &expected2, &high_water, 300)
            .is_err()
    );
    assert!(
        cp2.verify(&verified_policy, &expected2, &high_water, 900)
            .is_err()
    );
    let bytes = serde_json::to_vec(&cp2).unwrap();
    assert!(SignedPublicQualificationCertificateV2::parse(&bytes).is_ok());
    let duplicate = format!(
        "{{\"signature_hex\":\"{}\",{}",
        cp2.signature_hex,
        String::from_utf8(bytes).unwrap().strip_prefix('{').unwrap()
    );
    assert!(SignedPublicQualificationCertificateV2::parse(duplicate.as_bytes()).is_err());
}
