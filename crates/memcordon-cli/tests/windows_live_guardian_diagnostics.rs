#[path = "../src/bin/memcordon-sealed-agent/windows/live_guardian_diagnostics.rs"]
mod live_guardian_diagnostics;

use live_guardian_diagnostics::AssociationRefusalPredicates;
use memcordon_core::{
    BoundedText, DiagnosticSha256, PublicProviderBindingV1, WindowsLauncherResponseV4,
    WindowsProcessIdentityV1, WindowsReadOnlyQueryFailure, WindowsReadOnlyQueryOperation,
    WindowsReadOnlyQueryPhase,
};

fn guardian() -> WindowsProcessIdentityV1 {
    WindowsProcessIdentityV1 {
        process_id: u32::MAX,
        creation_time_100ns: u64::MAX,
    }
}

#[test]
fn all_predicate_combinations_preserve_refusal_and_identify_every_failed_gate() {
    for duplicate_match in [false, true] {
        for boot_mismatch in [false, true] {
            for provider_mismatch in [false, true] {
                for target_not_released in [false, true] {
                    for resume_not_attempted in [false, true] {
                        for authorization_missing in [false, true] {
                            let predicates = AssociationRefusalPredicates {
                                duplicate_match,
                                boot_mismatch,
                                provider_mismatch,
                                target_not_released,
                                resume_not_attempted,
                                authorization_missing,
                            };
                            let facts = [
                                ("duplicate-match", duplicate_match),
                                ("boot-mismatch", boot_mismatch),
                                ("provider-mismatch", provider_mismatch),
                                ("target-not-released", target_not_released),
                                ("resume-not-attempted", resume_not_attempted),
                                ("authorization-missing", authorization_missing),
                            ];
                            let refusal = predicates.refusal(&guardian(), u64::MAX);
                            assert_eq!(refusal.is_some(), facts.iter().any(|(_, failed)| *failed));
                            if let Some(refusal) = refusal {
                                let detail = refusal.to_string();
                                for (label, failed) in facts {
                                    assert!(detail.contains(&format!("{label}={failed};")));
                                }
                                assert!(detail.contains("liveness-before-inventory=passed;"));
                                assert!(detail.ends_with("liveness-after-inventory=not-reached"));
                                assert!(detail.len() < 512);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn maximal_refusal_retains_identity_revision_and_survives_existing_failure_transport() {
    let detail = AssociationRefusalPredicates {
        duplicate_match: true,
        ..Default::default()
    }
    .refusal(&guardian(), u64::MAX)
    .unwrap()
    .to_string();
    assert!(detail.starts_with("live guardian association is ambiguous or not released;"));
    assert!(detail.contains(&format!("guardian-pid={};", u32::MAX)));
    assert!(detail.contains(&format!("guardian-birth={};", u64::MAX)));
    assert!(detail.contains(&format!("record-revision={};", u64::MAX)));
    assert!(detail.contains("diagnostic-revision=1;"));
    let failure = WindowsReadOnlyQueryFailure::new(
        WindowsReadOnlyQueryOperation::GuardianObservation,
        BoundedText::new("query-challenge").unwrap(),
        PublicProviderBindingV1 {
            generation: BoundedText::new("installed-generation").unwrap(),
            source_commit: BoundedText::new("c21430372b4c7b37982259f93aac757f605b7f35").unwrap(),
            runtime_manifest_sha256: DiagnosticSha256::from_bytes([1; 32]),
        },
        WindowsReadOnlyQueryPhase::QueryHandler,
        &detail,
    )
    .unwrap();
    assert!(!failure.detail_truncated);
    assert_eq!(failure.detail.as_str(), detail);
    let response = WindowsLauncherResponseV4::ReadOnlyQueryFailure(failure.clone());
    let encoded = serde_json::to_vec(&response).unwrap();
    assert!(encoded.len() < WindowsReadOnlyQueryFailure::MAX_FRAME_BYTES);
    let WindowsLauncherResponseV4::ReadOnlyQueryFailure(decoded) =
        serde_json::from_slice::<WindowsLauncherResponseV4>(&encoded).unwrap()
    else {
        panic!("refusal frame must remain a read-only query failure");
    };
    assert_eq!(decoded, failure);
}
