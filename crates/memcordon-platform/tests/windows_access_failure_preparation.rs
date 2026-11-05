#![cfg(feature = "test-support")]
use memcordon_platform::windows_access_failure_preparation::*;

fn before_apply() -> State {
    State {
        operation: PreparationOperation::ApplyOwnedDacl,
        progress: Milestones {
            file_created: true,
            fixed_bytes_written: true,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn native_failure_preserves_original_code_kind_source_and_bounded_facts() {
    let original = std::io::Error::from_raw_os_error(5);
    let original_kind = original.kind();
    let wrapped = before_apply().failure(original);
    let failure = wrapped
        .get_ref()
        .unwrap()
        .downcast_ref::<PreparationFailure>()
        .unwrap();
    assert_eq!(wrapped.kind(), original_kind);
    assert_eq!(failure.primary.raw_os_error(), Some(5));
    assert_eq!(failure.record.native_error, Some(5));
    assert_eq!(
        failure.record.operation,
        PreparationOperation::ApplyOwnedDacl
    );
    assert_eq!(
        std::error::Error::source(failure)
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(5)
    );
    failure.record.validate().unwrap();
    let bytes = serde_json::to_vec(&failure.record).unwrap();
    assert!(bytes.len() + 1 < RECORD_BYTES);
    assert_eq!(
        serde_json::from_slice::<Record>(&bytes).unwrap(),
        failure.record
    );
    assert_eq!(failure.record.request.owner_file_desired_access, 0x40003);
    assert_eq!(failure.record.request.security_information, 0x80000004);
    let nested = Record::from_error(&before_apply(), &wrapped);
    nested.validate().unwrap();
    assert_eq!(nested.native_error, Some(5));
    assert_eq!(nested, failure.record);
    assert_eq!(failure.primary.raw_os_error(), Some(5));
    assert_eq!(wrapped.kind(), original_kind);
}
#[test]
fn cutoff_semantic_and_code_unavailable_native_errors_are_distinct() {
    let cutoff = Record::from_error(
        &State::default(),
        &std::io::Error::new(std::io::ErrorKind::TimedOut, "original cutoff"),
    );
    cutoff.validate().unwrap();
    assert_eq!(cutoff.kind, FailureKind::Cutoff);
    assert_eq!(cutoff.native_error, None);
    let semantic = Record::from_error(
        &State {
            operation: PreparationOperation::ValidateOwnedDacl,
            ..before_apply()
        },
        &std::io::Error::other("DACL absent"),
    );
    semantic.validate().unwrap();
    assert_eq!(semantic.kind, FailureKind::Semantic);
    let native = Record::from_error(
        &State {
            operation: PreparationOperation::WriteOwnedFile,
            progress: Milestones {
                file_created: true,
                ..Default::default()
            },
            ..Default::default()
        },
        &std::io::Error::other("write unavailable"),
    );
    native.validate().unwrap();
    assert_eq!(native.kind, FailureKind::Native);
    assert_eq!(native.native_error, None);
}
#[test]
fn contradictions_unknown_operations_and_fabricated_progress_are_rejected() {
    let record = Record::from_error(&before_apply(), &std::io::Error::from_raw_os_error(5));
    let mut invalid = record;
    invalid.progress.dacl_applied = true;
    assert!(invalid.validate().is_err());
    let mut invalid = record;
    invalid.progress.file_created = false;
    assert!(invalid.validate().is_err());
    let mut invalid = record;
    invalid.kind = FailureKind::Semantic;
    assert!(invalid.validate().is_err());
    let mut invalid = record;
    invalid.request.owner_file_desired_access |= 0x20000;
    assert!(invalid.validate().is_err());
    let mut invalid = record;
    invalid.native_error = Some(0);
    assert!(invalid.validate().is_err());
    let mut wire = serde_json::to_value(record).unwrap();
    wire["operation"] = serde_json::json!("unknown-operation");
    assert!(serde_json::from_value::<Record>(wire).is_err());
    let mut wire = serde_json::to_value(record).unwrap();
    wire["raw_sid"] = serde_json::json!([1, 2]);
    assert!(serde_json::from_value::<Record>(wire).is_err());
    let impossible = Record::from_error(
        &State {
            operation: PreparationOperation::OpenCurrentThreadToken,
            ..Default::default()
        },
        &std::io::Error::from_raw_os_error(1008),
    );
    assert!(impossible.validate().is_err());
}
