#![cfg(all(windows, feature = "test-support"))]

use memcordon_platform::test_support::ProcessIdentity;
use std::io::Read;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::process::{Child, Command, Stdio};
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

struct HeldChild(Child);

impl Drop for HeldChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "invoked by the bounded parent process-identity regression"]
fn process_identity_held_child() {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut byte = [0];
        let _ = sender.send(std::io::stdin().read(&mut byte));
    });
    assert_eq!(
        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("parent must release or terminate the bounded child")
            .unwrap(),
        0
    );
}

#[test]
fn exited_held_process_object_is_queryable_but_not_live() {
    let mut child = HeldChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "--ignored", "process_identity_held_child"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let identity = ProcessIdentity::for_pid(child.0.id()).unwrap();
    // SAFETY: retain the actual child process object past native termination.
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            identity.pid,
        )
    };
    assert!(!process.is_null(), "{}", std::io::Error::last_os_error());
    // SAFETY: the successful OpenProcess returned one owned handle.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    assert!(identity.still_exists().unwrap());
    assert!(
        !ProcessIdentity {
            birth: identity.birth.checked_add(1).unwrap(),
            ..identity
        }
        .still_exists()
        .unwrap()
    );

    child.0.kill().unwrap();
    // SAFETY: the exact owned handle has SYNCHRONIZE access; bound the wait.
    assert_eq!(
        unsafe { WaitForSingleObject(process.as_raw_handle(), 5_000) },
        WAIT_OBJECT_0
    );
    child.0.wait().unwrap();
    assert_eq!(ProcessIdentity::for_pid(identity.pid).unwrap(), identity);
    assert!(!identity.still_exists().unwrap());
}
