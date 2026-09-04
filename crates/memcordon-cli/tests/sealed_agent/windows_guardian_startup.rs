use std::os::windows::io::AsRawHandle;
use std::process::{Command, Stdio};

use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, SetEvent, TerminateProcess,
};

use crate::windows::guardian::{GuardianCapabilityV1, GuardianHandleRole, GuardianStartupSubphase};

fn event(signaled: bool) -> crate::windows::pipe::OwnedHandle {
    // SAFETY: null security/name create a private manual-reset test event.
    crate::windows::pipe::OwnedHandle::new(unsafe {
        CreateEventW(std::ptr::null(), 1, i32::from(signaled), std::ptr::null())
    })
    .unwrap()
}

#[test]
fn native_guardian_wait_distinguishes_ready_live_timeout_and_wait_failure() {
    // WaitForMultipleObjects requires a real process handle rather than the
    // current-process pseudo-handle returned by GetCurrentProcess.
    let guardian =
        crate::windows::process::duplicate_owned(unsafe { GetCurrentProcess() }).unwrap();
    let ready = event(true);
    assert!(
        crate::windows::launcher_service::guardian_startup_observation_for_test(
            ready.raw(),
            guardian.raw(),
            20,
        )
        .is_ok()
    );

    let not_ready = event(false);
    let (detail, os_code) =
        crate::windows::launcher_service::guardian_startup_observation_for_test(
            not_ready.raw(),
            guardian.raw(),
            1,
        )
        .unwrap_err();
    assert!(detail.contains("outcome=guardian-live-timeout"));
    assert_eq!(os_code, None);

    let (detail, os_code) =
        crate::windows::launcher_service::guardian_startup_observation_for_test(
            std::ptr::null_mut(),
            guardian.raw(),
            20,
        )
        .unwrap_err();
    assert!(detail.contains("outcome=wait-failed"));
    assert_eq!(os_code, Some(6));
}

#[test]
fn native_guardian_wait_reports_early_exit_and_ready_then_exit() {
    let mut exited = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "windows_guardian_startup::guardian_native_exit_child_fixture",
            "--ignored",
        ])
        .spawn()
        .unwrap();
    let process = exited.as_raw_handle() as _;
    assert_eq!(exited.wait().unwrap().code(), Some(37));

    let not_ready = event(false);
    let (detail, os_code) =
        crate::windows::launcher_service::guardian_startup_observation_for_test(
            not_ready.raw(),
            process,
            20,
        )
        .unwrap_err();
    assert!(detail.contains("outcome=guardian-exited"));
    assert!(detail.contains("exit_code=37"));
    assert_eq!(os_code, None);

    let ready = event(false);
    // SAFETY: ready is a live private event owned by this test.
    assert_ne!(unsafe { SetEvent(ready.raw()) }, 0);
    let (detail, _) = crate::windows::launcher_service::guardian_startup_observation_for_test(
        ready.raw(),
        process,
        20,
    )
    .unwrap_err();
    assert!(detail.contains("outcome=ready-then-exited"));
}

#[test]
fn startup_exit_status_preserves_bounded_phase_role_and_native_code() {
    for role in [
        GuardianHandleRole::BootstrapRead,
        GuardianHandleRole::BootstrapWrite,
        GuardianHandleRole::Job,
        GuardianHandleRole::Frontend,
        GuardianHandleRole::Worker,
        GuardianHandleRole::Disarm,
        GuardianHandleRole::Ready,
        GuardianHandleRole::ServiceStop,
    ] {
        let exit_code = crate::windows::guardian::startup_exit_code_for_test(
            GuardianStartupSubphase::HandleValidation,
            Some(role),
            Some(6),
        );
        let (subphase, decoded_role, native_code) =
            crate::windows::guardian::startup_detail_for_exit_code(exit_code);
        assert_eq!(subphase, GuardianStartupSubphase::HandleValidation);
        assert_eq!(decoded_role, Some(role));
        assert_eq!(native_code, Some(6));
    }
    for subphase in [
        GuardianStartupSubphase::BootstrapChannel,
        GuardianStartupSubphase::SelfHarden,
        GuardianStartupSubphase::ProcessPolicyApply,
        GuardianStartupSubphase::ProcessPolicyReadback,
        GuardianStartupSubphase::ThreadPolicyApply,
        GuardianStartupSubphase::ThreadPolicyReadback,
        GuardianStartupSubphase::LauncherAuthentication,
        GuardianStartupSubphase::CapabilityManifest,
        GuardianStartupSubphase::LoaderContext,
    ] {
        let exit_code = crate::windows::guardian::startup_exit_code_for_test(subphase, None, None);
        let (decoded, role, native) =
            crate::windows::guardian::startup_detail_for_exit_code(exit_code);
        assert_eq!(decoded, subphase);
        assert_eq!(role, None);
        assert_eq!(native, None);
    }
}

#[test]
fn loader_context_rejects_interactive_desktops_and_malformed_handle_lists() {
    crate::windows::process::certify_guardian_loader_context_negatives().unwrap();
}

#[test]
fn guardian_slot_pool_names_are_bounded_canonical_and_non_fallback() {
    crate::windows::guardian_service::certify_slot_contract_negatives().unwrap();
    assert_eq!(memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT, 8);
    assert_eq!(
        crate::windows::security::guardian_slot_name(0).unwrap(),
        "MemCordonSealedGuardian-000"
    );
    assert!(crate::windows::security::guardian_slot_name(8).is_err());
}

fn long_lived_child() -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "windows_guardian_startup::guardian_native_wait_child_fixture",
            "--ignored",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

#[test]
#[ignore = "subprocess fixture invoked by the guardian startup contract"]
fn guardian_native_exit_child_fixture() {
    std::process::exit(37);
}

#[test]
#[ignore = "subprocess fixture invoked by the guardian startup contract"]
fn guardian_native_wait_child_fixture() {
    std::thread::park_timeout(std::time::Duration::from_secs(30));
}

#[test]
fn bootstrap_broken_pipe_preserves_typed_guardian_exit() {
    let (reader, writer) =
        crate::windows::process::guardian_bootstrap_pipe_pair_for_test().unwrap();
    let mut child = long_lived_child();
    let process = child.as_raw_handle() as _;
    let identity = crate::windows::process::process_identity(process).unwrap();
    let exit_code = crate::windows::guardian::startup_exit_code_for_test(
        GuardianStartupSubphase::ThreadPolicyApply,
        None,
        Some(5),
    );
    // SAFETY: process is the live owned child and the encoded code is the
    // production guardian startup contract exercised by this test.
    assert_ne!(unsafe { TerminateProcess(process, exit_code) }, 0);
    child.wait().unwrap();
    drop(writer);

    let error = crate::windows::process::guardian_bootstrap_frame_for_test(
        reader.raw(),
        process,
        &identity,
    )
    .unwrap_err();
    assert_eq!(
        error.outcome,
        crate::windows::process::GuardianBootstrapOutcome::ChildRejected
    );
    assert_eq!(error.subphase, GuardianStartupSubphase::ThreadPolicyApply);
    assert_eq!(error.native_code, Some(5));
    assert_eq!(error.exit_code, Some(exit_code));
}

#[test]
fn bootstrap_eof_while_guardian_is_live_is_distinct_and_bounded() {
    let (reader, writer) =
        crate::windows::process::guardian_bootstrap_pipe_pair_for_test().unwrap();
    drop(writer);
    // SAFETY: the current process pseudo-handle remains live throughout the test.
    let process = unsafe { GetCurrentProcess() };
    let identity = crate::windows::process::process_identity(process).unwrap();
    let error = crate::windows::process::guardian_bootstrap_frame_for_test(
        reader.raw(),
        process,
        &identity,
    )
    .unwrap_err();
    assert_eq!(
        error.outcome,
        crate::windows::process::GuardianBootstrapOutcome::ChannelClosedWhileLive
    );
    assert!(error.elapsed_millis < 1_000);
}

#[test]
fn structured_bootstrap_rejection_is_preserved_while_guardian_is_live() {
    let (reader, writer) =
        crate::windows::process::guardian_bootstrap_pipe_pair_for_test().unwrap();
    // SAFETY: the current process pseudo-handle remains live throughout the test.
    let process = unsafe { GetCurrentProcess() };
    let identity = crate::windows::process::process_identity(process).unwrap();
    crate::windows::pipe::write_frame(
        writer.raw(),
        &crate::windows::guardian::GuardianBootstrapMessageV1::Rejected {
            binding: None,
            subphase: GuardianStartupSubphase::ProcessPolicyReadback,
            role: None,
            native_code: Some(5),
            detail_class: "policy-attestation".to_owned(),
        },
    )
    .unwrap();
    let error = crate::windows::process::guardian_bootstrap_frame_for_test(
        reader.raw(),
        process,
        &identity,
    )
    .unwrap_err();
    assert_eq!(
        error.outcome,
        crate::windows::process::GuardianBootstrapOutcome::ChildRejected
    );
    assert_eq!(
        error.subphase,
        GuardianStartupSubphase::ProcessPolicyReadback
    );
    assert_eq!(error.native_code, Some(5));
    assert_eq!(error.detail, "policy-attestation");
}

#[test]
fn armed_bootstrap_cleanup_terminates_and_reaps_child() {
    let mut child = long_lived_child();
    let process = child.as_raw_handle() as _;
    crate::windows::process::guardian_bootstrap_cleanup_for_test(process);
    assert!(child.wait().unwrap().code().is_some());
}

#[test]
fn failed_startup_stays_boundary_created_for_recovery() {
    use memcordon_core::{WindowsAttemptStateV1, windows_attempt_transition_allowed};

    assert_eq!(
        crate::windows::launcher_service::guardian_state_after_observation_for_test(false),
        WindowsAttemptStateV1::BoundaryCreated
    );
    assert!(windows_attempt_transition_allowed(
        WindowsAttemptStateV1::BoundaryCreated,
        WindowsAttemptStateV1::Terminating,
    ));
    assert_eq!(
        crate::windows::launcher_service::guardian_state_after_observation_for_test(true),
        WindowsAttemptStateV1::GuardianReady
    );
}

#[test]
fn bootstrap_manifest_rejects_invalid_role_and_partial_transfer() {
    let contract = crate::windows::guardian::guardian_manifest_contract();
    let complete = contract
        .into_iter()
        .enumerate()
        .map(|(index, (role, access))| GuardianCapabilityV1 {
            role: role.to_owned(),
            handle: (index + 1) as u64,
            access,
        })
        .collect::<Vec<_>>();
    assert!(crate::windows::guardian::validate_manifest_for_test(&complete).is_ok());

    let mut invalid_role = complete.clone();
    invalid_role[2].role = "ready".to_owned();
    let exit = crate::windows::guardian::validate_manifest_for_test(&invalid_role).unwrap_err();
    assert_eq!(
        crate::windows::guardian::startup_detail_for_exit_code(exit).0,
        GuardianStartupSubphase::CapabilityManifest
    );

    let partial = &complete[..4];
    let exit = crate::windows::guardian::validate_manifest_for_test(partial).unwrap_err();
    assert_eq!(
        crate::windows::guardian::startup_detail_for_exit_code(exit).0,
        GuardianStartupSubphase::CapabilityManifest
    );
}

#[test]
fn bootstrap_manifest_rejects_access_and_handle_aliasing() {
    let mut manifest = crate::windows::guardian::guardian_manifest_contract()
        .into_iter()
        .enumerate()
        .map(|(index, (role, access))| GuardianCapabilityV1 {
            role: role.to_owned(),
            handle: (index + 1) as u64,
            access,
        })
        .collect::<Vec<_>>();
    manifest[0].access ^= 1;
    assert!(crate::windows::guardian::validate_manifest_for_test(&manifest).is_err());

    manifest[0].access = crate::windows::guardian::guardian_manifest_contract()[0].1;
    manifest[4].handle = manifest[0].handle;
    assert!(crate::windows::guardian::validate_manifest_for_test(&manifest).is_err());
}
