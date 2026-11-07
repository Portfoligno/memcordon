#[path = "../src/bin/consumer_readiness_windows/operation_context.rs"]
mod context;

use context::{Operation, context};
use std::{error::Error, io};

#[test]
fn existing_operation_result_and_original_native_error_survive_context() {
    let value = Box::new(7);
    let address = &*value as *const i32;
    let returned = context(Operation::PeerCommandSpawn, Ok(value)).unwrap();
    assert_eq!(&*returned as *const i32, address);
    let failure = context::<()>(
        Operation::PeerCommandSpawn,
        Err(io::Error::from_raw_os_error(5)),
    )
    .unwrap_err();
    assert_eq!(failure.kind(), io::Error::from_raw_os_error(5).kind());
    assert!(
        failure
            .to_string()
            .contains("peer-command-spawn [original_native_code=Some(5)]")
    );
    let original = failure
        .get_ref()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    assert_eq!(original.raw_os_error(), Some(5));
    // A later failed operation cannot be mislabeled as the completed operation.
    assert!(!failure.to_string().contains("tcp-challenge-write"));
}

#[test]
fn finite_labels_keep_nested_typed_sources_without_claiming_native_api() {
    for operation in [
        Operation::ListenerLocalAddress,
        Operation::CompetingBind,
        Operation::TranscriptConflictingBind,
        Operation::TranscriptListenerOwned,
        Operation::ChallengeWrite,
        Operation::PeerStdoutCreate,
        Operation::PeerStdoutDuplicate,
        Operation::PeerStdoutValidate,
        Operation::CurrentExecutable,
        Operation::PeerCommandSpawn,
        Operation::TranscriptSpawnIntent,
        Operation::PendingPeerIdentity,
        Operation::TranscriptPendingAdmission,
        Operation::PeerRecipientAdmission,
        Operation::RegistryMetadataHandoff,
        Operation::PeerIdentity,
        Operation::TranscriptPeerCreated,
    ] {
        assert!(operation.label().len() <= 40);
        let inner = context::<()>(operation, Err(io::Error::from_raw_os_error(5))).unwrap_err();
        let outer = context::<()>(Operation::RegistryMetadataHandoff, Err(inner)).unwrap_err();
        let mut source: &(dyn Error + 'static) = outer.get_ref().unwrap();
        let mut found = false;
        loop {
            if source
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.raw_os_error() == Some(5))
            {
                found = true;
            }
            let Some(next) = source.source() else {
                break;
            };
            source = next;
        }
        assert!(found);
        assert!(!outer.to_string().contains("CreateProcessW"));
    }
}
