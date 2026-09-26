use memcordon_core::private_public_case_v2::FinalPublicChildIdentityV2;
use memcordon_core::private_public_policy_composite_v1::{
    PUBLIC_POLICY_SELECTOR_V1, PublicPolicyBranchEvidenceV1, PublicPolicyBranchOutcomeV1,
    PublicPolicyCompositeCaseV1,
};
use memcordon_core::private_release_branch_v1::{
    PolicyOperationBranchV1, policy_branch_challenge_v1,
};
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::{BoundedText, DiagnosticSha256};

fn digest(label: &str) -> DiagnosticSha256 {
    hash_bytes(label.as_bytes())
}

fn valid() -> PublicPolicyCompositeCaseV1 {
    let base = [7_u8; 32];
    let branches = PolicyOperationBranchV1::ALL.map(|branch| {
        let name = branch.as_str();
        let challenge = policy_branch_challenge_v1(&base, branch).unwrap();
        let ordinal = PolicyOperationBranchV1::ALL
            .iter()
            .position(|item| *item == branch)
            .unwrap() as u32;
        let outcome = match branch {
            PolicyOperationBranchV1::AcceptedControl => {
                PublicPolicyBranchOutcomeV1::AcceptedControl {
                    attempt_id: "22".repeat(16),
                    target_identity_sha256: digest("target"),
                    terminal_sha256: digest("terminal"),
                    cleanup_sha256: digest("cleanup"),
                }
            }
            PolicyOperationBranchV1::CommittedPortTamper => {
                PublicPolicyBranchOutcomeV1::FrozenPlanDenied {
                    rejection_sha256: digest("frozen-rejection"),
                }
            }
            other => PublicPolicyBranchOutcomeV1::PlanDenied {
                admission_code: match other {
                    PolicyOperationBranchV1::WrongGrant => {
                        memcordon_core::workload_registry_v2::AdmissionCodeV2::ProfileNotAuthorized
                    }
                    PolicyOperationBranchV1::WrongProfile => {
                        memcordon_core::workload_registry_v2::AdmissionCodeV2::ProfileDigestMismatch
                    }
                    PolicyOperationBranchV1::UnapprovedChangedPortPlan => {
                        memcordon_core::workload_registry_v2::AdmissionCodeV2::PlanNotApproved
                    }
                    _ => unreachable!(),
                },
                rejection_sha256: digest(&format!("rejection-{name}")),
            },
        };
        PublicPolicyBranchEvidenceV1 {
            branch,
            challenge,
            result_key: private_release_case_key_v1(
                PrivateReleaseStageV1::FinalPublic,
                PUBLIC_POLICY_SELECTOR_V1,
                &challenge,
            )
            .unwrap(),
            child: FinalPublicChildIdentityV2 {
                pid: 100 + ordinal,
                start_time_ticks: 200 + u64::from(ordinal),
                boot_identity: BoundedText::new("boot-1").unwrap(),
                uid: 1000,
                gid: 1000,
                supplementary_groups_empty: true,
                executable_sha256: digest("public-cli"),
                argv_sha256: digest(&format!("argv-{name}")),
                working_directory_sha256: digest(&format!("cwd-{name}")),
            },
            provider_record_sha256: digest(&format!("provider-{name}")),
            plan_response_sha256: digest(&format!("plan-{name}")),
            grant_decision_sha256: digest(&format!("grant-{name}")),
            kernel_capture_sha256: digest(&format!("capture-{name}")),
            report_sha256: digest(&format!("report-{name}")),
            stdio_sha256: digest(&format!("stdio-{name}")),
            raw_inventory_sha256: digest(&format!("raw-{name}")),
            outcome,
        }
    });
    PublicPolicyCompositeCaseV1 {
        schema_version: 1,
        selector: PUBLIC_POLICY_SELECTOR_V1.into(),
        base_challenge: base,
        source_commit: "a".repeat(40),
        release_version: BoundedText::new("0.5.7-dev").unwrap(),
        target: "x86_64-unknown-linux-gnu".into(),
        native_machine: "x86_64".into(),
        archive_sha256: digest("A"),
        manifest_sha256: digest("M1"),
        qualification_sha256: digest("Q"),
        active_h1_receipt_sha256: digest("H1"),
        installation_epoch: digest("E1"),
        build_context_sha256: digest("B-context"),
        release_catalogue_sha256: digest("catalogue"),
        provider_inventory_sha256: digest("provider-inventory"),
        interval_inventory_sha256: digest("interval-inventory"),
        branches,
    }
}

#[test]
fn five_actor_policy_composite_requires_derived_keys_and_distinct_observations() {
    let case = valid();
    let bytes = serde_json::to_vec(&case).unwrap();
    assert_eq!(PublicPolicyCompositeCaseV1::parse(&bytes).unwrap(), case);
    let mut changed = case.clone();
    changed.branches.swap(1, 2);
    assert!(changed.validate().is_err());
    let mut changed = case.clone();
    changed.branches[4].child.pid = changed.branches[0].child.pid;
    changed.branches[4].child.start_time_ticks = changed.branches[0].child.start_time_ticks;
    assert!(changed.validate().is_err());
    let mut changed = case.clone();
    changed.branches[3].kernel_capture_sha256 = changed.branches[2].kernel_capture_sha256.clone();
    assert!(changed.validate().is_err());
    let mut changed = case.clone();
    changed.branches[2].result_key = changed.branches[1].result_key.clone();
    assert!(changed.validate().is_err());
}

#[test]
fn policy_composite_rejects_wrong_denial_and_noncanonical_json() {
    let mut case = valid();
    case.branches[3].outcome = PublicPolicyBranchOutcomeV1::PlanDenied {
        admission_code: memcordon_core::workload_registry_v2::AdmissionCodeV2::ProfileNotAuthorized,
        rejection_sha256: digest("wrong-code"),
    };
    assert!(case.validate().is_err());
    let bytes = serde_json::to_vec(&valid()).unwrap();
    let mut padded = bytes.clone();
    padded.push(b' ');
    assert!(PublicPolicyCompositeCaseV1::parse(&padded).is_err());
    let mut extra: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    extra["untrusted"] = serde_json::json!(true);
    assert!(PublicPolicyCompositeCaseV1::parse(&serde_json::to_vec(&extra).unwrap()).is_err());
}
