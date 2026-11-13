#[path = "../src/bin/memcordon-sealed-agent/windows/launcher_startup_progress.rs"]
mod progress;

use memcordon_core::{
    WindowsLauncherStartupReasonV1 as Reason, WindowsLauncherStartupStageV1 as Stage,
};
use progress::LauncherStartupProgress;

#[test]
fn first_native_failure_keeps_its_own_operation_reason_and_code() {
    let mut progress = LauncherStartupProgress::new();
    progress.stage(Stage::QuarantineDirectory);
    progress.failure(Reason::OperationFailed, Some(5));
    progress.stage(Stage::QuarantineOpen);
    progress.failure(Reason::OperationFailed, Some(32));
    progress.stage(Stage::FinalAmbiguity);
    progress.failure(Reason::RetainedAmbiguity, None);
    assert_eq!(
        progress.observation(),
        (Stage::QuarantineDirectory, Reason::OperationFailed, Some(5))
    );
    progress.reset();
    progress.stage(Stage::WriterRegistry);
    progress.failure(Reason::UnconfirmedWriter, Some(32));
    progress.stage(Stage::QuarantineOpen);
    progress.failure(Reason::OperationFailed, Some(5));
    assert_eq!(
        progress.observation(),
        (Stage::WriterRegistry, Reason::UnconfirmedWriter, Some(32))
    );
}

#[test]
fn semantic_and_registry_failures_never_borrow_a_later_native_code() {
    for reason in [
        Reason::RetainedAmbiguity,
        Reason::WriterRegistryUnavailable,
        Reason::UnconfirmedWriter,
    ] {
        let mut progress = LauncherStartupProgress::new();
        progress.stage(Stage::WriterRegistry);
        progress.failure(reason, None);
        progress.stage(Stage::AttemptsDirectory);
        progress.failure(Reason::OperationFailed, Some(3));
        assert_eq!(
            progress.observation(),
            (Stage::WriterRegistry, reason, None)
        );
    }
}

#[test]
fn fresh_start_and_service_loop_reset_the_entire_previous_failure_tuple() {
    let mut progress = LauncherStartupProgress::new();
    progress.stage(Stage::QuarantineEntry);
    progress.failure(Reason::OperationFailed, Some(32));
    progress.reset();
    assert_eq!(
        progress.observation(),
        (Stage::ProcessProtection, Reason::OperationFailed, None)
    );
    progress.stage(Stage::ReplayDirectory);
    progress.failure(Reason::OperationFailed, Some(5));
    progress.stage(Stage::ServiceLoop);
    assert_eq!(
        progress.observation(),
        (Stage::ServiceLoop, Reason::OperationFailed, None)
    );
    progress.stage(Stage::AdmissionDirectory);
    progress.failure(Reason::OperationFailed, Some(2));
    assert_eq!(
        progress.observation(),
        (Stage::AdmissionDirectory, Reason::OperationFailed, Some(2))
    );
}
