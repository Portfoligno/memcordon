use std::collections::BTreeMap;
use std::io::{Cursor, Write};

use memcordon_ci::private_candidate_c_v3::{
    CandidateCaseV3, CandidateEvidenceIndexV3, CandidateRawMemberV3, parse_candidate_c_v3,
};
use memcordon_core::private_release_case_v1::{
    PrivateReleaseAllocatedOutcomeV1, PrivateReleaseAttachmentRoleV1, PrivateReleaseAttachmentV1,
    PrivateReleaseCaseResultV1, PrivateReleaseDualRetiredBranchV1, PrivateReleaseExecV1,
    PrivateReleaseInstalledBindingV1, PrivateReleaseKnowledgeV1, PrivateReleaseObservationV1,
    PrivateReleaseStageV1, REQUIRED_PRIVATE_RELEASE_SELECTORS_V1, private_release_case_key_v1,
};
use memcordon_core::workload_codec::hash_bytes;

fn raw(path: String, bytes: &[u8]) -> CandidateRawMemberV3 {
    CandidateRawMemberV3 {
        path,
        size: bytes.len() as u64,
        sha256: hash_bytes(bytes),
    }
}

fn fixture() -> (CandidateEvidenceIndexV3, BTreeMap<String, Vec<u8>>) {
    let intent = hash_bytes(b"protected-intent");
    let mut cases = Vec::new();
    let mut members = BTreeMap::new();
    for (number, selector) in REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.iter().enumerate() {
        let challenge = [number as u8 + 1; 32];
        let key = private_release_case_key_v1(
            PrivateReleaseStageV1::CandidateCapability,
            selector,
            &challenge,
        )
        .unwrap();
        let prefix = format!("candidate-c-v3/cases/{}", String::from(key.clone()));
        let attachments: [Vec<u8>; 5] =
            std::array::from_fn(|position| vec![number as u8 + 1, position as u8 + 1]);
        let inventory = PrivateReleaseAttachmentRoleV1::ALL
            .iter()
            .zip(&attachments)
            .map(|(role, bytes)| PrivateReleaseAttachmentV1 {
                role: *role,
                size: bytes.len() as u64,
                sha256: hash_bytes(bytes),
            })
            .collect();
        let digest = |name: &[u8]| hash_bytes(name);
        let observation = match *selector {
            "private_tcp::abi_alternate_entry_denied" => {
                PrivateReleaseObservationV1::AbiComposite {
                    attempt_id: hex::encode([5_u8; 16]),
                    checkpoint_sha256: digest(b"abi-checkpoint"),
                    terminal_sha256: digest(&vec![number as u8 + 1; 8]),
                    retirement_sha256: digest(&attachments[4]),
                    abi_raw: memcordon_core::private_release_case_v1::PrivateReleaseAbiRawInventoryV1::X86_64 {
                        x32_sha256: digest(&vec![number as u8 + 1; 8]),
                        i386_sha256: digest(&vec![number as u8 + 2; 8]),
                    },
                    independent_interval_sha256: digest(&vec![number as u8 + 1; 16]),
                    native_observer_sha256: digest(&attachments[3]),
                }
            }
            "private_tcp::wrong_grant_profile_and_port_rejected" => {
                PrivateReleaseObservationV1::PolicyComposite {
                    accepted_decision_sha256: digest(b"accepted-policy-decision"),
                    branch_transcript_sha256: digest(b"policy-branch-transcript"),
                    independent_interval_inventory_sha256: digest(b"five-kernel-intervals"),
                    native_observer_sha256: digest(&attachments[3]),
                }
            }
            "private_tcp::dual_attempt_namespace_isolation" => {
                PrivateReleaseObservationV1::DualAttemptsRetired {
                    first: PrivateReleaseDualRetiredBranchV1 {
                        attempt_id: hex::encode([1_u8; 16]),
                        checkpoint_sha256: digest(b"first-checkpoint"),
                        terminal_sha256: digest(b"first-terminal"),
                        retirement_sha256: digest(b"first-retirement"),
                        release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
                        exec: PrivateReleaseExecV1::Succeeded,
                    },
                    second: PrivateReleaseDualRetiredBranchV1 {
                        attempt_id: hex::encode([2_u8; 16]),
                        checkpoint_sha256: digest(b"second-checkpoint"),
                        terminal_sha256: digest(b"second-terminal"),
                        retirement_sha256: digest(b"second-retirement"),
                        release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
                        exec: PrivateReleaseExecV1::Succeeded,
                    },
                    native_observer_sha256: digest(&attachments[3]),
                }
            }
            "private_tcp::retirement_failure_blocks_reuse" => {
                PrivateReleaseObservationV1::RetirementFailureBlockedReuse {
                    attempt_id: hex::encode([3_u8; 16]),
                    checkpoint_sha256: digest(b"checkpoint"),
                    terminal_sha256: digest(b"terminal"),
                    cleanup_failure_sha256: digest(b"cleanup-failure"),
                    reuse_rejection_sha256: digest(b"reuse-rejection"),
                    release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
                    exec: PrivateReleaseExecV1::Succeeded,
                    native_observer_sha256: digest(&attachments[3]),
                }
            }
            _ => {
                let outcome = match *selector {
                    "private_tcp::authorization_uncertainty_retired" => {
                        PrivateReleaseAllocatedOutcomeV1::AuthorizationUncertain
                    }
                    "private_tcp::frontend_loss_retired" => {
                        PrivateReleaseAllocatedOutcomeV1::FrontendLost
                    }
                    "private_tcp::guardian_loss_retired" => {
                        PrivateReleaseAllocatedOutcomeV1::GuardianLost
                    }
                    _ => PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
                };
                PrivateReleaseObservationV1::AllocatedRetired {
                    outcome,
                    attempt_id: hex::encode([4_u8; 16]),
                    checkpoint_sha256: digest(b"checkpoint"),
                    terminal_sha256: digest(b"terminal"),
                    retirement_sha256: digest(b"retirement"),
                    release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
                    exec: PrivateReleaseExecV1::Succeeded,
                    native_observer_sha256: digest(&attachments[3]),
                }
            }
        };
        let result = PrivateReleaseCaseResultV1 {
            schema_version: 1,
            selector: (*selector).into(),
            challenge: hex::encode(challenge),
            target: "x86_64-unknown-linux-gnu".into(),
            native_machine: "x86_64".into(),
            installed: PrivateReleaseInstalledBindingV1::CandidateCapability {
                installation_epoch: digest(b"epoch"),
                candidate_manifest_sha256: digest(b"m0"),
                installed_inspection_sha256: digest(b"h0"),
            },
            observation,
            attachments: inventory,
        };
        result.validate().unwrap();
        let result_bytes = serde_json::to_vec(&result).unwrap();
        let result_raw = raw(format!("{prefix}/result.json"), &result_bytes);
        members.insert(result_raw.path.clone(), result_bytes);
        let mut raw_attachments = Vec::new();
        for (role, bytes) in PrivateReleaseAttachmentRoleV1::ALL.iter().zip(&attachments) {
            let item = raw(format!("{prefix}/{}", role.leaf()), bytes);
            members.insert(item.path.clone(), bytes.clone());
            raw_attachments.push(item);
        }
        let capture_bytes = vec![number as u8 + 1; 16];
        let capture = raw(
            format!(
                "{prefix}/kernel-{}.capture.bin",
                String::from(intent.clone())
            ),
            &capture_bytes,
        );
        members.insert(capture.path.clone(), capture_bytes);
        let family_names: Vec<&str> = match *selector {
            "private_tcp::abi_alternate_entry_denied" => vec![
                "request.json",
                "attempt.json",
                "x32-alternate.raw.json",
                "i386-entry.raw.json",
            ],
            "private_tcp::caller_identity_and_epoch_bound" => vec!["historical-epoch.raw.json"],
            "private_tcp::wrong_grant_profile_and_port_rejected" => vec![
                "policy-intent.v1.json",
                "policy-branches.raw.json",
                "accepted-control.request.json",
                "accepted-control.raw.json",
                "accepted-control.kernel.capture.bin",
                "wrong-grant.request.json",
                "wrong-grant.raw.json",
                "wrong-grant.kernel.capture.bin",
                "wrong-profile.request.json",
                "wrong-profile.raw.json",
                "wrong-profile.kernel.capture.bin",
                "unapproved-changed-port-plan.request.json",
                "unapproved-changed-port-plan.raw.json",
                "unapproved-changed-port-plan.kernel.capture.bin",
                "committed-port-tamper.request.json",
                "committed-port-tamper.raw.json",
                "committed-port-tamper.kernel.capture.bin",
            ],
            _ => vec![],
        };
        let family_raw = family_names
            .into_iter()
            .map(|name| {
                let value = match name {
                    "request.json" => attachments[0].clone(),
                    "i386-entry.raw.json" => vec![number as u8 + 2; 8],
                    _ => vec![number as u8 + 1; 8],
                };
                let item = raw(format!("{prefix}/family/{name}"), &value);
                members.insert(item.path.clone(), value);
                item
            })
            .collect();
        cases.push(CandidateCaseV3 {
            selector: (*selector).into(),
            result_key: key,
            result: result_raw,
            attachments: raw_attachments,
            kernel_capture: capture,
            family_raw,
        });
    }
    let index = CandidateEvidenceIndexV3 {
        schema_version: 3,
        observer_raw: Vec::new(),
        target: "x86_64-unknown-linux-gnu".into(),
        source_commit: hex::encode([3_u8; 20]),
        release_version: "0.5.7".into(),
        collector_intent_sha256: intent,
        cases,
    };
    (index, members)
}

fn zip(
    index: &CandidateEvidenceIndexV3,
    members: &BTreeMap<String, Vec<u8>>,
    extra: Option<(&str, &[u8])>,
) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer
        .start_file("candidate-c-v3/index.json", options)
        .unwrap();
    writer
        .write_all(&serde_json::to_vec(index).unwrap())
        .unwrap();
    for (path, bytes) in members {
        writer.start_file(path, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    if let Some((path, bytes)) = extra {
        writer.start_file(path, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn c_v3_preserves_dual_attempt_result_and_exact_raw_inventory() {
    let (index, members) = fixture();
    let bytes = zip(&index, &members, None);
    assert_eq!(parse_candidate_c_v3(&bytes).unwrap(), index);
    let dual = &index.cases[8];
    let parsed =
        PrivateReleaseCaseResultV1::parse(members.get(&dual.result.path).unwrap()).unwrap();
    assert!(matches!(
        parsed.observation,
        PrivateReleaseObservationV1::DualAttemptsRetired { .. }
    ));
}

#[test]
fn c_v3_rejects_swapped_raw_dual_branch_and_unlisted_member() {
    let (mut index, mut members) = fixture();
    let swapped = index.cases[8].attachments[0].path.clone();
    members.insert(swapped, b"swapped".to_vec());
    assert!(parse_candidate_c_v3(&zip(&index, &members, None)).is_err());
    let (original, members) = fixture();
    index = original;
    index.cases[8].selector = index.cases[7].selector.clone();
    assert!(parse_candidate_c_v3(&zip(&index, &members, None)).is_err());
    let (index, members) = fixture();
    assert!(
        parse_candidate_c_v3(&zip(
            &index,
            &members,
            Some(("candidate-c-v3/cases/extra.bin", b"x"))
        ))
        .is_err()
    );
    let (mut index, members) = fixture();
    index.cases[0].family_raw.clear();
    assert!(parse_candidate_c_v3(&zip(&index, &members, None)).is_err());
}

#[test]
fn c_v3_requires_every_policy_branch_raw_and_lossless_capture() {
    let (index, members) = fixture();
    let policy = index
        .cases
        .iter()
        .position(|case| case.selector == "private_tcp::wrong_grant_profile_and_port_rejected")
        .unwrap();
    assert_eq!(index.cases[policy].family_raw.len(), 17);
    for missing in 0..17 {
        let mut index = index.clone();
        let mut members = members.clone();
        let removed = index.cases[policy].family_raw.remove(missing);
        members.remove(&removed.path);
        assert!(
            parse_candidate_c_v3(&zip(&index, &members, None)).is_err(),
            "accepted policy archive without family leaf {}",
            removed.path
        );
    }
    let (index, mut members) = fixture();
    let capture = index.cases[policy]
        .family_raw
        .iter()
        .find(|raw| {
            raw.path
                .ends_with("committed-port-tamper.kernel.capture.bin")
        })
        .unwrap();
    members.insert(capture.path.clone(), b"altered-capture".to_vec());
    assert!(parse_candidate_c_v3(&zip(&index, &members, None)).is_err());
}

#[test]
fn c_v3_requires_exact_abi_request_and_both_x86_subwitnesses() {
    let (index, members) = fixture();
    let abi = index
        .cases
        .iter()
        .position(|case| case.selector == "private_tcp::abi_alternate_entry_denied")
        .unwrap();
    assert_eq!(index.cases[abi].family_raw.len(), 4);
    for missing in 0..4 {
        let mut index = index.clone();
        let mut members = members.clone();
        let removed = index.cases[abi].family_raw.remove(missing);
        members.remove(&removed.path);
        assert!(
            parse_candidate_c_v3(&zip(&index, &members, None)).is_err(),
            "accepted ABI archive without family leaf {}",
            removed.path
        );
    }
    let (mut index, mut members) = fixture();
    let i386 = index.cases[abi]
        .family_raw
        .iter_mut()
        .find(|leaf| leaf.path.ends_with("i386-entry.raw.json"))
        .unwrap();
    let changed = b"different-i386-raw".to_vec();
    i386.size = changed.len() as u64;
    i386.sha256 = hash_bytes(&changed);
    members.insert(i386.path.clone(), changed);
    assert!(parse_candidate_c_v3(&zip(&index, &members, None)).is_err());
}
