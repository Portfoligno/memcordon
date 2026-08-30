use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateMutexW, GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_LIMITED_INFORMATION, ReleaseMutex, SetEvent, WaitForSingleObject,
};

use crate::windows::process::RemoteHandleObjectIdentity;

const FIXTURE_MARKER: &str = "MCSEALED-HANDLE-FIXTURE:";
const COLLISION_SEARCH_HANDLES: usize = 2_048;

#[test]
fn target_token_capability_is_queryable_duplicable_and_noninheritable() {
    let target = crate::windows::token::restricted_current_primary()
        .expect("restricted target token should be created");
    crate::windows::process::attest_target_token_capability_for_test(target.raw())
        .expect("reduced target capability should query and mint an impersonation token");
}

#[test]
fn holder_session_error_preserves_typed_stage_and_native_code() {
    let target_session_id = 23_u32;
    let error = crate::windows::token::LauncherHolderTokenDerivationError::session_set_for_test(
        target_session_id,
        5,
    );
    let (detail, native_code) =
        crate::windows::process::holder_derivation_error_mapping_for_test(error);
    assert_eq!(native_code, Some(5));
    assert!(detail.contains("stage=session-set"));
    assert!(detail.contains("api=NtSetInformationToken"));
    assert!(detail.contains("object_role=holder-mutable"));
    assert!(detail.contains("token_type=primary"));
    assert!(detail.contains("requested_access=0x0000019b"));
    assert!(detail.contains("granted_access=0x0000019b"));
    assert!(detail.contains("target_session_id=23"));
    assert!(detail.contains("native_code=Some(5)"));
    assert!(detail.contains("nt_status=0xc0000022"));
    assert!(detail.contains("carrier_installed=true"));
    assert!(detail.contains("carrier_reverted=true"));
}

#[test]
fn holder_mutation_and_launch_masks_have_exact_kernel_readback() {
    let source = crate::windows::token::restricted_current_primary()
        .expect("restricted token should provide the holder access fixture");
    let (mutable_granted, launch_granted) =
        crate::windows::token::holder_access_mask_readback_for_test(source.raw())
            .expect("holder access masks should have native GrantedAccess evidence");
    assert_eq!(mutable_granted, 0x0000_019b);
    assert_eq!(launch_granted, 0x0000_001b);
    assert_eq!(mutable_granted & 0x0000_0180, 0x0000_0180);
    assert_eq!(launch_granted & 0x0000_0180, 0);
}

#[test]
#[ignore = "subprocess fixture invoked by the provenance test"]
fn frontend_handle_fixture() {
    let handles = (0..COLLISION_SEARCH_HANDLES)
        .map(|_| {
            // SAFETY: null security/name create a private, initially-unsignaled event.
            crate::windows::pipe::OwnedHandle::new(unsafe {
                CreateEventW(std::ptr::null(), 1, 0, std::ptr::null())
            })
            .expect("frontend fixture event should be created")
        })
        .collect::<Vec<_>>();
    let values = handles
        .iter()
        .map(|handle| (handle.raw() as usize as u64).to_string())
        .collect::<Vec<_>>()
        .join(",");
    println!("{FIXTURE_MARKER}{values}");
    std::io::stdout().flush().unwrap();

    let mut release = String::new();
    std::io::stdin().read_line(&mut release).unwrap();
}

fn spawn_frontend_fixture() -> (
    std::process::Child,
    BufReader<std::process::ChildStdout>,
    Vec<u64>,
) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "windows_handle_provenance::frontend_handle_fixture",
            "--ignored",
            "--nocapture",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("frontend fixture should start");
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    let values = loop {
        line.clear();
        assert_ne!(
            stdout.read_line(&mut line).unwrap(),
            0,
            "fixture exited early"
        );
        if let Some(values) = line.trim().strip_prefix(FIXTURE_MARKER) {
            break values
                .split(',')
                .map(|value| value.parse::<u64>().unwrap())
                .collect::<Vec<_>>();
        }
    };
    (child, stdout, values)
}

#[test]
fn cross_process_duplication_uses_frontend_namespace_even_on_numeric_collision() {
    let control_mutexes = (0..COLLISION_SEARCH_HANDLES)
        .map(|_| {
            // SAFETY: null security/name create a private, initially-signaled mutex.
            crate::windows::pipe::OwnedHandle::new(unsafe {
                CreateMutexW(std::ptr::null(), 0, std::ptr::null())
            })
            .expect("control fixture mutex should be created")
        })
        .collect::<Vec<_>>();
    let control_by_value = control_mutexes
        .iter()
        .map(|handle| (handle.raw() as usize as u64, handle.raw()))
        .collect::<BTreeMap<_, _>>();

    let (mut child, _fixture_stdout, frontend_values) = spawn_frontend_fixture();
    let (collision, control_mutex) = frontend_values
        .iter()
        .find_map(|value| control_by_value.get(value).map(|handle| (*value, *handle)))
        .expect("fixture should arrange a frontend/control numeric handle collision");

    // SAFETY: the fixture PID is live and the requested rights are the exact
    // query/duplication rights needed by the provenance test.
    let frontend_process = crate::windows::pipe::OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            child.id(),
        )
    })
    .unwrap();
    let frontend_identity = crate::windows::process::process_identity(frontend_process.raw())
        .expect("frontend identity should be pinned");
    // SAFETY: the pseudo handle always denotes this live test process.
    let control_process = unsafe { GetCurrentProcess() };
    let control_identity = crate::windows::process::process_identity(control_process).unwrap();

    // The colliding control value is a signaled mutex. Selecting it by value
    // from the wrong namespace would therefore return WAIT_OBJECT_0.
    assert_eq!(
        unsafe { WaitForSingleObject(control_mutex, 0) },
        WAIT_OBJECT_0
    );
    // SAFETY: the successful wait above acquired this mutex on the test thread.
    assert_ne!(unsafe { ReleaseMutex(control_mutex) }, 0);

    let duplicate =
        crate::windows::control_service::duplicate_authenticated_frontend_canary_for_test(
            frontend_process.raw(),
            &frontend_identity,
            collision as usize as _,
            control_process,
            &control_identity,
            1,
        )
        .expect("frontend event should duplicate into the target namespace");
    let duplicate = crate::windows::pipe::OwnedHandle::new(duplicate as usize as _).unwrap();
    crate::windows::process::verify_not_inheritable(duplicate.raw()).unwrap();
    assert_eq!(
        crate::windows::process::compare_remote_handle_object(
            frontend_process.raw(),
            collision as usize as _,
            control_mutex,
        )
        .unwrap(),
        RemoteHandleObjectIdentity::DifferentObject,
        "a valid local handle at the same numeric slot is not object identity"
    );
    assert_eq!(
        crate::windows::process::compare_remote_handle_object(
            frontend_process.raw(),
            collision as usize as _,
            duplicate.raw(),
        )
        .unwrap(),
        RemoteHandleObjectIdentity::SameObject,
        "the duplicated frontend event must compare as the same kernel object"
    );
    assert_eq!(
        crate::windows::process::compare_remote_handle_object(
            frontend_process.raw(),
            std::ptr::null_mut(),
            duplicate.raw(),
        )
        .unwrap(),
        RemoteHandleObjectIdentity::Absent,
        "an invalid remote slot must be classified as absent"
    );
    assert_eq!(
        unsafe { WaitForSingleObject(duplicate.raw(), 0) },
        WAIT_TIMEOUT
    );
    assert_ne!(unsafe { SetEvent(duplicate.raw()) }, 0);
    assert_eq!(
        unsafe { WaitForSingleObject(duplicate.raw(), 0) },
        WAIT_OBJECT_0
    );

    let error = crate::windows::control_service::duplicate_authenticated_frontend_canary_for_test(
        frontend_process.raw(),
        &frontend_identity,
        std::ptr::null_mut(),
        control_process,
        &control_identity,
        5,
    )
    .unwrap_err();
    assert!(error.starts_with("MCSEALED-WINDOWS-HANDLE-DUPLICATE:"));
    assert!(error.contains("phase=qualification-canary-to-launcher"));
    assert!(error.contains("source_role=authenticated-frontend"));
    assert!(error.contains(&format!("source_pid={}", frontend_identity.process_id)));
    assert!(error.contains("destination_role=launcher"));
    assert!(error.contains("inventory_index=5"));
    assert!(error.contains("native_code=6"));

    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
}
