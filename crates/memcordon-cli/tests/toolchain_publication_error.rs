#[path = "../src/bin/consumer_readiness_windows/toolchain_publication_error.rs"]
mod publication;

use publication::{Context, Failure, Stage};
use std::io;

fn binding() -> serde_json::Value {
    serde_json::json!({
        "original_child":{"process_id":7388,"creation_time_100ns":134379513503576272_u64},
        "parent":{"process_id":9412,"creation_time_100ns":134379513479411609_u64},
        "selected_image_sha256":"a".repeat(64),
        "challenge":[0,255,7,42],
        "unrelated_state":"must not be projected"
    })
}

#[test]
fn context_projects_only_original_bounded_binding_and_keeps_unknown_destination_explicit() {
    use sha2::{Digest, Sha256};
    let binding = binding();
    let context = Context::new("before-debug-run", Some(false), 1, &binding);
    let encoded = context.encode(Stage::Replace).unwrap();
    let actual: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(
        actual["context"]["binding"]["original_compiler"],
        binding["original_child"]
    );
    assert_eq!(
        actual["context"]["binding"]["original_parent"],
        binding["parent"]
    );
    assert_eq!(
        actual["context"]["binding"]["selected_image_sha256"],
        binding["selected_image_sha256"]
    );
    let challenge = String::from(memcordon_core::DiagnosticSha256::from_bytes(
        Sha256::digest([0, 255, 7, 42]).into(),
    ));
    assert_eq!(actual["context"]["binding"]["challenge_sha256"], challenge);
    assert_eq!(actual["context"]["phase"], "before-debug-run");
    assert_eq!(actual["context"]["record_debug"], false);
    assert_eq!(actual["context"]["sequence"], 1);
    assert_eq!(actual["rename_flags"], 3);
    assert_eq!(
        actual["rename_api"],
        "NtSetInformationFile/FileRenameInformationEx"
    );
    assert_eq!(
        actual["destination_identity_security_sharing"],
        "unavailable"
    );
    assert_eq!(actual["diagnostic_only"], true);
    assert_eq!(actual["acceptance_authority"], false);
    assert_eq!(actual["same_parent_paths"], false);
    assert!(actual["context"]["parent_path_sha256"].is_null());
    assert!(actual["context"]["parent"].is_null());
    assert!(actual["context"]["stage_file"].is_null());
    assert_eq!(actual["context"]["readback_verified"], false);
    assert!(
        !String::from_utf8(encoded)
            .unwrap()
            .contains("must not be projected")
    );

    let phase = "\"\n🦀".repeat(10000);
    let mut malformed = binding;
    malformed["selected_image_sha256"] = "x".repeat(100000).into();
    malformed["challenge"] = serde_json::json!(vec![0; 4097]);
    malformed["original_child"]["process_id"] = u64::MAX.into();
    let bounded = Context::new(&phase, None, u64::MAX, &malformed);
    let bytes = bounded.encode(Stage::Encode).unwrap();
    assert!(bytes.len() < publication::DISPLAY_BOUND);
    let actual: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(actual["context"]["phase"].is_null());
    assert_eq!(actual["context"]["phase_bytes"], phase.len());
    let phase_digest = String::from(memcordon_core::DiagnosticSha256::from_bytes(
        Sha256::digest(phase.as_bytes()).into(),
    ));
    assert_eq!(actual["context"]["phase_sha256"], phase_digest);
    for field in [
        "original_compiler",
        "selected_image_sha256",
        "challenge_sha256",
    ] {
        assert!(actual["context"]["binding"][field].is_null(), "{field}");
    }
    assert_eq!(
        actual["context"]["binding"]["original_parent"],
        malformed["parent"]
    );
}

#[test]
fn metadata_failure_and_readback_observations_never_replace_primary_io_failure() {
    let mut context = Context::new("before-debug-run", Some(false), 1, &binding());
    context.parent = Some(publication::FileObservation {
        volume: 7,
        index: 11,
        attributes: 16,
        links: 1,
        length: 0,
    });
    context.stage_file = Some(publication::FileObservation {
        volume: 7,
        index: 12,
        attributes: 32,
        links: 1,
        length: 1024,
    });
    context.readback_verified = true;
    context.expected_destination = context.stage_file.clone();
    context.destination_before_stage = Some(publication::FileObservation {
        index: 99,
        ..context.stage_file.clone().unwrap()
    });
    context.same_parent_paths = true;
    context.parent_path_sha256 = Some("c".repeat(64));
    context.stage_observation_error = Some(publication::ObservationError {
        kind: "PermissionDenied".into(),
        native_code: Some(6),
    });
    let projected = context.failure(Stage::Replace, io::Error::from_raw_os_error(5));
    let failure = projected
        .get_ref()
        .unwrap()
        .downcast_ref::<Failure>()
        .unwrap();
    let original = std::error::Error::source(failure)
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    assert_eq!(original.raw_os_error(), Some(5));
    assert_eq!(failure.stage(), Stage::Replace);
    let actual: serde_json::Value =
        serde_json::from_slice(&failure.context().encode(Stage::Replace).unwrap()).unwrap();
    assert_eq!(
        actual["context"]["stage_observation_error"]["native_code"],
        6
    );
    assert_eq!(actual["context"]["stage_file"]["index"], 12);
    assert_eq!(actual["context"]["expected_destination"]["index"], 12);
    assert_eq!(actual["context"]["destination_before_stage"]["index"], 99);
    assert!(actual["context"]["destination_before_commit"].is_null());
    assert_eq!(actual["context"]["stage_file"]["length"], 1024);
    assert_eq!(actual["context"]["parent"]["index"], 11);
    assert_eq!(actual["context"]["readback_verified"], true);
    assert_eq!(actual["same_parent_paths"], true);
    assert_eq!(actual["context"]["parent_path_sha256"], "c".repeat(64));
    assert_eq!(
        actual["destination_identity_security_sharing"],
        "unavailable"
    );

    context.stage_observation_error.as_mut().unwrap().kind =
        "oversized-observation".repeat(publication::DISPLAY_BOUND);
    assert!(context.encode(Stage::Replace).is_err());
    let projected = context.failure(Stage::Replace, io::Error::from_raw_os_error(5));
    assert!(projected.to_string().contains("context-encoding-failed"));
    let failure = projected
        .get_ref()
        .unwrap()
        .downcast_ref::<Failure>()
        .unwrap();
    assert_eq!(
        std::error::Error::source(failure)
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(5)
    );
}

#[test]
fn every_publication_boundary_retains_its_exact_stage_and_original_native_error() {
    let context = Context::new("before-debug-run", Some(false), 1, &binding());
    for stage in [
        Stage::RetainParentOpen,
        Stage::RetainParentIdentity,
        Stage::Sequence,
        Stage::Encode,
        Stage::ParentIdentity,
        Stage::ParentOpen,
        Stage::NamedParentIdentity,
        Stage::ParentVerification,
        Stage::PendingCreate,
        Stage::PendingWrite,
        Stage::PendingFlush,
        Stage::PendingRewind,
        Stage::PendingReadback,
        Stage::PendingReadbackVerification,
        Stage::DestinationOpen,
        Stage::DestinationIdentity,
        Stage::DestinationOwnership,
        Stage::ReadbackOpen,
        Stage::RenameSourceOpen,
        Stage::SourcePreparation,
        Stage::CommitVerification,
        Stage::Replace,
        Stage::PendingIdentity,
        Stage::FinalOpen,
        Stage::FinalIdentity,
        Stage::FinalVerification,
        Stage::FinalLength,
    ] {
        let original = io::Error::from_raw_os_error(5);
        let original_kind = original.kind();
        let projected = context.failure(stage, original);
        assert_eq!(projected.kind(), original_kind);
        let failure = projected
            .get_ref()
            .unwrap()
            .downcast_ref::<Failure>()
            .unwrap();
        assert_eq!(failure.stage(), stage);
        let native = std::error::Error::source(failure)
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert_eq!(native.raw_os_error(), Some(5));
        assert_eq!(native.kind(), original_kind);
        let bytes = failure.context().encode(stage).unwrap();
        assert!(bytes.len() <= publication::DISPLAY_BOUND);
        let _: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    }
    // A semantic verification failure must not acquire a guessed Win32 code.
    let projected = context.failure(
        Stage::FinalVerification,
        io::Error::other("identity differs"),
    );
    let failure = projected
        .get_ref()
        .unwrap()
        .downcast_ref::<Failure>()
        .unwrap();
    let original = std::error::Error::source(failure)
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    assert_eq!(original.raw_os_error(), None);
    assert_eq!(original.to_string(), "identity differs");
}
