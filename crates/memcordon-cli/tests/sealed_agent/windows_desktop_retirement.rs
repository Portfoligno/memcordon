use super::*;
use std::io::Read;
use std::os::windows::io::{AsRawHandle, IntoRawHandle};
use std::process::{Command, Stdio};

fn holder(
    name: &str,
) -> (
    Option<OwnedHandle>,
    Job,
    OwnedHandle,
    std::process::ChildStdout,
) {
    let job = Job::create_session_holder_fixture().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", name, "--nocapture"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    // SAFETY: both Job and child process handles remain owned and valid.
    let assigned = unsafe {
        windows_sys::Win32::System::JobObjects::AssignProcessToJobObject(
            job.handle(),
            child.as_raw_handle(),
        )
    };
    if assigned == 0 {
        let original = std::io::Error::last_os_error();
        let termination = child.kill();
        let settlement = child.wait();
        panic!(
            "fixture Job assignment failed: {original}; termination: {termination:?}; settlement: {settlement:?}"
        );
    }
    let connection = OwnedHandle::new(child.stdin.take().unwrap().into_raw_handle()).unwrap();
    let output = child.stdout.take().unwrap();
    let process = OwnedHandle::new(child.into_raw_handle()).unwrap();
    (Some(connection), job, process, output)
}

#[test]
fn checked_holder_close_releases_pipe_before_waiting_for_normal_exit() {
    let module = module_path!().split_once("::").unwrap().1;
    let name = format!("{module}::normal_holder");
    let (mut connection, mut job, mut process, mut output) = holder(&name);
    assert!(!close_desktop_holder_handles(&mut connection, &mut job, &mut process).unwrap());
    assert!(connection.is_none());
    let mut bytes = Vec::new();
    output.read_to_end(&mut bytes).unwrap();
    assert!(
        String::from_utf8(bytes)
            .unwrap()
            .contains("DESKTOP_HOLDER_RELEASE_OBSERVED")
    );
}

#[test]
fn checked_holder_close_retains_existing_job_termination_fallback() {
    let module = module_path!().split_once("::").unwrap().1;
    let name = format!("{module}::ignoring_holder");
    let (mut connection, mut job, mut process, mut output) = holder(&name);
    assert!(close_desktop_holder_handles(&mut connection, &mut job, &mut process).unwrap());
    let mut bytes = Vec::new();
    output.read_to_end(&mut bytes).unwrap();
    assert!(
        String::from_utf8(bytes)
            .unwrap()
            .contains("DESKTOP_HOLDER_IGNORING_RELEASE")
    );
}

#[test]
fn first_release_failure_is_not_replaced_by_later_settlement_failure() {
    let error = combine_desktop_retirement_error(
        Err("original close error".into()),
        "later wait error".into(),
    );
    assert!(error.starts_with("desktop holder connection release failed: original close error"));
    assert!(error.contains("later wait error"));
}

#[test]
fn failed_connection_close_remains_refusal_after_actual_holder_settlement() {
    let module = module_path!().split_once("::").unwrap().1;
    let name = format!("{module}::normal_holder");
    let (mut connection, mut job, mut process, _output) = holder(&name);
    connection.as_mut().unwrap().close_checked().unwrap();
    let error = close_desktop_holder_handles(&mut connection, &mut job, &mut process).unwrap_err();
    assert!(error.contains("retirement handle is not live"));
    assert!(
        connection.is_some(),
        "failed checked release cannot be reported as closed"
    );
    assert!(
        process.raw().is_null(),
        "independent settlement still closes the process handle"
    );
}

#[test]
fn failed_same_handle_wait_cannot_authorize_final_handle_closure() {
    let module = module_path!().split_once("::").unwrap().1;
    let name = format!("{module}::normal_holder");
    let (mut connection, mut job, mut process, _output) = holder(&name);
    // SAFETY: GetCurrentProcess returns this process's pseudo-handle.
    let current = unsafe { GetCurrentProcess() };
    let mut retained = ptr::null_mut();
    // SAFETY: retain only synchronization access to the exact owned child.
    assert_ne!(
        unsafe {
            DuplicateHandle(
                current,
                process.raw(),
                current,
                &raw mut retained,
                SYNCHRONIZE_ACCESS,
                0,
                0,
            )
        },
        0
    );
    let mut retained = OwnedHandle::new(retained).unwrap();
    process.close_checked().unwrap();
    let error = close_desktop_holder_handles(&mut connection, &mut job, &mut process).unwrap_err();
    assert!(error.contains("raw-os-error=Some(6)"), "{error}");
    assert!(
        !job.handle().is_null(),
        "no checked Job close without same-handle signal"
    );
    job.terminate(TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS)
        .unwrap();
    // SAFETY: cleanup observes the same retained child object, never a PID.
    assert_eq!(
        unsafe { WaitForSingleObject(retained.raw(), 5_000) },
        WAIT_OBJECT_0
    );
    retained.close_checked().unwrap();
    job.close_checked().unwrap();
}

#[test]
#[ignore = "real holder released by the checked owned connection"]
fn normal_holder() {
    let mut byte = [0];
    assert_eq!(std::io::stdin().read(&mut byte).unwrap(), 0);
    println!("DESKTOP_HOLDER_RELEASE_OBSERVED");
}

#[test]
#[ignore = "real holder exercising original Job termination fallback"]
fn ignoring_holder() {
    let mut byte = [0];
    assert_eq!(std::io::stdin().read(&mut byte).unwrap(), 0);
    println!("DESKTOP_HOLDER_IGNORING_RELEASE");
    loop {
        std::thread::park();
    }
}
