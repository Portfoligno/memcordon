#![cfg(unix)]

use std::os::unix::process::ExitStatusExt;

use memcordon_ci::private_public_case_readback::{
    ExpectedFinalPublicCaseV2, RawPublicAttachmentV2, assemble_structural_final_public_case,
    validate_structural_final_public_case,
};
use memcordon_ci::private_public_v2::ExpectedFrontendLossEvidenceV2;
use memcordon_ci::private_supervisor::{LinuxChildIdentityV1, SupervisedProcessV2};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_public_case_v2::FinalPublicCaseEvidenceV2;
use memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1;
use memcordon_core::workload_codec::hash_bytes;

fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}

#[test]
fn final_public_case_joins_exact_independent_inputs_and_raw_bytes() {
    let raw = [
        (PrivateReleaseAttachmentRoleV1::Request, b"r".as_slice()),
        (
            PrivateReleaseAttachmentRoleV1::Report,
            b"public report".as_slice(),
        ),
        (PrivateReleaseAttachmentRoleV1::Stdio, b"s".as_slice()),
        (PrivateReleaseAttachmentRoleV1::Observer, b"o".as_slice()),
        (PrivateReleaseAttachmentRoleV1::Cleanup, b"c".as_slice()),
    ];
    let selector = "private_tcp::native_tcp_bind_listen_connect";
    let source = "a".repeat(40);
    let mut value = serde_json::json!({
        "schema_version": 2,
        "selector": selector,
        "challenge": Vec::from([7_u8; 32]),
        "source_commit": source,
        "release_version": "0.5.7",
        "target": "x86_64-unknown-linux-gnu",
        "native_machine": "x86_64",
        "build_context_sha256": digest(24),
        "release_catalogue_sha256": digest(25),
        "installed": {
            "installation_epoch": digest(1),
            "archive_sha256": digest(2),
            "qualified_manifest_sha256": digest(3),
            "release_qualification_sha256": digest(4),
            "active_host_receipt_sha256": digest(5),
            "component_sha256": digest(21),
            "unit_sha256": digest(22),
            "filter_sha256": digest(23),
            "public_plan_sha256": digest(6),
            "public_grant_sha256": digest(7),
        },
        "child": {
            "pid": 42,
            "start_time_ticks": 123,
            "boot_identity": "boot-1",
            "uid": 1000,
            "gid": 1000,
            "supplementary_groups_empty": true,
            "executable_sha256": digest(10),
            "argv_sha256": digest(11),
            "working_directory_sha256": digest(12),
        },
        "observation": {
            "phase": "allocated-retired",
            "outcome": "target-completed",
            "attempt_id": "ab".repeat(16),
            "checkpoint_sha256": digest(13),
            "terminal_sha256": digest(14),
            "retirement_sha256": digest(15),
            "release_knowledge": "exec-observed",
            "exec": "succeeded",
            "native_observer_sha256": hash_bytes(b"o"),
        },
        "positive_control_terminal_sha256": null,
        "report": {
            "state": "present",
            "size": b"public report".len(),
            "sha256": hash_bytes(b"public report"),
        },
        "attachments": raw.iter().map(|(role, bytes)| serde_json::json!({
            "role": role,
            "size": bytes.len(),
            "sha256": hash_bytes(bytes),
        })).collect::<Vec<_>>(),
    });
    let bytes = serde_json::to_vec(&value).unwrap();
    let parsed = FinalPublicCaseEvidenceV2::parse(&bytes).unwrap();
    let raw_readback: Vec<_> = raw
        .iter()
        .map(|(role, bytes)| RawPublicAttachmentV2 { role: *role, bytes })
        .collect();
    let child = SupervisedProcessV2 {
        status: std::process::ExitStatus::from_raw(0),
        stdout: Vec::new(),
        stderr: Vec::new(),
        linux_child: Some(LinuxChildIdentityV1 {
            pid: 42,
            start_time_ticks: 123,
        }),
    };
    let expected = ExpectedFinalPublicCaseV2 {
        selector,
        challenge: [7; 32],
        source_commit: &source,
        release_version: "0.5.7",
        target: "x86_64-unknown-linux-gnu",
        native_machine: "x86_64",
        build_context_sha256: &digest(24),
        release_catalogue_sha256: &digest(25),
        installed: &parsed.installed,
        child: &parsed.child,
        terminal_observation: &parsed.observation,
        positive_control_terminal_sha256: None,
        frontend_loss_replacement: None,
        supervised_child: &child,
        raw_attachments: &raw_readback,
    };
    let result = validate_structural_final_public_case(&bytes, &expected).unwrap();
    assert_eq!(result.child_pid, 42);
    assert_eq!(result.child_start_time_ticks, 123);
    let (assembled, assembled_readback) = assemble_structural_final_public_case(&expected).unwrap();
    assert_eq!(assembled_readback.case_sha256, hash_bytes(&assembled));
    assert_eq!(
        FinalPublicCaseEvidenceV2::parse(&assembled).unwrap(),
        parsed
    );
    value["installed"]["archive_sha256"] = serde_json::json!(digest(30));
    assert!(
        validate_structural_final_public_case(&serde_json::to_vec(&value).unwrap(), &expected)
            .is_err()
    );
    value["installed"]["archive_sha256"] = serde_json::json!(digest(2));
    value["child"]["start_time_ticks"] = serde_json::json!(124);
    assert!(
        validate_structural_final_public_case(&serde_json::to_vec(&value).unwrap(), &expected)
            .is_err()
    );
    let mut swapped_raw: Vec<_> = raw
        .iter()
        .map(|(role, bytes)| RawPublicAttachmentV2 { role: *role, bytes })
        .collect();
    swapped_raw[0].bytes = b"other";
    let swapped = ExpectedFinalPublicCaseV2 {
        raw_attachments: &swapped_raw,
        ..expected
    };
    assert!(validate_structural_final_public_case(&bytes, &swapped).is_err());

    value["child"]["start_time_ticks"] = serde_json::json!(123);
    value["selector"] = serde_json::json!("private_tcp::frontend_loss_retired");
    value["observation"]["outcome"] = serde_json::json!("frontend-lost");
    value["report"] = serde_json::json!({
        "state": "absent-frontend-loss",
        "authenticated_terminal_sha256": digest(14),
        "supervised_transport_sha256": digest(19),
        "independent_recovery_sha256": digest(20),
    });
    value["attachments"].as_array_mut().unwrap().remove(1);
    let frontend_bytes = serde_json::to_vec(&value).unwrap();
    let frontend = FinalPublicCaseEvidenceV2::parse(&frontend_bytes).unwrap();
    let frontend_raw: Vec<_> = raw
        .iter()
        .filter(|(role, _)| *role != PrivateReleaseAttachmentRoleV1::Report)
        .map(|(role, bytes)| RawPublicAttachmentV2 { role: *role, bytes })
        .collect();
    let frontend_child = SupervisedProcessV2 {
        status: std::process::ExitStatus::from_raw(9),
        stdout: Vec::new(),
        stderr: Vec::new(),
        linux_child: child.linux_child,
    };
    let transport = digest(19);
    let recovery = digest(20);
    let replacement = ExpectedFrontendLossEvidenceV2 {
        authenticated_terminal_sha256: &digest(14),
        supervised_transport_sha256: &transport,
        independent_recovery_sha256: &recovery,
    };
    let frontend_expected = ExpectedFinalPublicCaseV2 {
        selector: "private_tcp::frontend_loss_retired",
        installed: &frontend.installed,
        child: &frontend.child,
        terminal_observation: &frontend.observation,
        frontend_loss_replacement: Some(&replacement),
        supervised_child: &frontend_child,
        raw_attachments: &frontend_raw,
        ..swapped
    };
    assert!(validate_structural_final_public_case(&frontend_bytes, &frontend_expected).is_ok());
    let (assembled_frontend, _) =
        assemble_structural_final_public_case(&frontend_expected).unwrap();
    assert_eq!(
        FinalPublicCaseEvidenceV2::parse(&assembled_frontend).unwrap(),
        frontend
    );
    let missing_replacement = ExpectedFinalPublicCaseV2 {
        frontend_loss_replacement: None,
        ..frontend_expected
    };
    assert!(validate_structural_final_public_case(&frontend_bytes, &missing_replacement).is_err());
}
