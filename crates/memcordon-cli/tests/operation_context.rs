#[path = "../src/bin/consumer_readiness_windows/operation_context.rs"]
mod context;

use context::{Operation, SourceRole, ToolchainOperation, context};
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

#[test]
fn toolchain_marker_uses_only_the_declared_stage_role_and_native_code() {
    use ToolchainOperation::*;

    for (stage, operation, role) in [
        (ObserverSession, "observer-session", "none"),
        (ObserverDeadlineArm, "observer-deadline-arm", "none"),
        (ObserverFrameRead, "observer-frame-read", "none"),
        (ObserverDeadlineSettle, "observer-deadline-settle", "none"),
        (CompilerConsole, "compiler-console", "none"),
        (CreateCompiledDirectory, "create-compiled-directory", "none"),
        (ValidateClock, "validate-clock", "none"),
        (SampleDeadline, "sample-deadline", "none"),
        (PublicationDeadline, "publication-deadline", "none"),
        (RetainPublicationParent, "retain-publication-parent", "none"),
        (CompileLibrary, "compile-library", "none"),
        (CopySource(SourceRole::Library), "copy-source", "library"),
        (CopySource(SourceRole::Tests), "copy-source", "tests"),
        (CopySource(SourceRole::Child), "copy-source", "child"),
        (CopySource(SourceRole::Dll), "copy-source", "dll"),
        (CopySource(SourceRole::Loader), "copy-source", "loader"),
    ] {
        let failure = context::<()>(
            Operation::Toolchain(stage),
            Err(io::Error::from_raw_os_error(5)),
        )
        .unwrap_err();
        let marker = format!(
            "toolchain-failure-v1; operation={operation}; source-role={role}; raw-os-error=5; end"
        );
        assert_eq!(failure.to_string().lines().next(), Some(marker.as_str()));
    }
}

#[test]
fn compiler_marker_keeps_original_operation_and_raw_code_through_secondary_failure() {
    use context::{
        CompilerDirectoryRole::*, CompilerOperation::*, compiler_context, with_secondary,
    };

    for (stage, operation, resource) in [
        (QualifySelection, "qualify-selection", "fixture"),
        (QualifyCommand, "qualify-command", "fixture"),
        (QualifyClock, "qualify-clock", "fixture"),
        (DirectoryOwnerBound, "directory-owner-bound", "fixture"),
        (
            DirectoryOpen(OutsideInputRoot),
            "directory-open",
            "outside-input-root",
        ),
        (
            DirectoryMetadata(InputRoot),
            "directory-metadata",
            "input-root",
        ),
        (
            DirectoryNamedOpen(InputAncestor),
            "directory-named-open",
            "input-ancestor",
        ),
        (
            DirectoryRetainedMetadata(NativeLibraryDirectory),
            "directory-retained-metadata",
            "native-library-directory",
        ),
        (
            DirectoryNamedMetadata(LinkerDirectory),
            "directory-named-metadata",
            "linker-directory",
        ),
        (
            DirectoryNamedIdentity(InputRoot),
            "directory-named-identity",
            "input-root",
        ),
        (LinkerOpen, "linker-open", "linker"),
        (LinkerMetadata, "linker-metadata", "linker"),
        (LinkerRead, "linker-read", "linker"),
        (LinkerMeasure, "linker-measure", "linker"),
        (LinkerNamedOpen, "linker-named-open", "linker"),
        (LinkerRetainedMetadata, "linker-retained-metadata", "linker"),
        (LinkerNamedMetadata, "linker-named-metadata", "linker"),
        (LinkerNamedIdentity, "linker-named-identity", "linker"),
        (CompilerOpen, "compiler-open", "compiler"),
        (CompilerMetadata, "compiler-metadata", "compiler"),
        (CompilerRead, "compiler-read", "compiler"),
        (ParentIdentity, "parent-identity", "fixture"),
        (CompilerSpawn, "compiler-spawn", "compiler"),
        (CaptureStart, "capture-start", "compiler"),
        (ChildRetain, "child-retain", "compiler"),
        (ChildIdentity, "child-identity", "compiler"),
        (CheckpointInitialize, "checkpoint-initialize", "fixture"),
        (CheckpointPublish, "checkpoint-publish", "fixture"),
        (DebugObservation, "debug-observation", "compiler"),
        (ChildRetirement, "child-retirement", "compiler"),
        (ChildWait, "child-wait", "compiler"),
        (CaptureReceive, "capture-receive", "compiler"),
        (RetirementReceipt, "retirement-receipt", "fixture"),
        (ChildStatus, "child-status", "compiler"),
    ] {
        let original = io::Error::from_raw_os_error(5);
        let kind = original.kind();
        let error = compiler_context::<()>(stage, Err(original)).unwrap_err();
        let secondary = with_secondary(error, "secondary-only/private-path".into());
        let error = context::<()>(
            Operation::Toolchain(ToolchainOperation::CompileLibrary),
            Err(secondary),
        )
        .unwrap_err();
        assert_eq!(error.kind(), kind);
        let rendered = error.to_string();
        assert_eq!(
            rendered.lines().next().unwrap(),
            format!(
                "toolchain-failure-v2; operation=compile-library; source-role=none; compiler-operation={operation}; resource-role={resource}; raw-os-error=5; end"
            )
        );
        assert!(
            rendered
                .lines()
                .nth(1)
                .unwrap()
                .ends_with("secondary-only/private-path")
        );
        let native =
            std::iter::successors(error.source(), |&cause| cause.source()).find_map(|cause| {
                cause
                    .downcast_ref::<io::Error>()
                    .and_then(io::Error::raw_os_error)
            });
        assert_eq!(native, Some(5));
    }
}
