#![cfg(windows)]

#[path = "../src/windows_component_worker_wait.rs"]
mod worker_wait;

use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::time::{Duration, Instant};

#[test]
fn original_native_thread_settlement_is_observed_without_terminating_its_owner() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        GetCurrentThreadId, OpenThread, THREAD_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
    };
    let (entered, wait_entered) = std::sync::mpsc::sync_channel(1);
    let (release, wait_release) = std::sync::mpsc::sync_channel(1);
    let owner = std::thread::spawn(move || {
        // SAFETY: query the current controlled test thread's native identity.
        entered.send(unsafe { GetCurrentThreadId() }).unwrap();
        wait_release.recv_timeout(Duration::from_secs(30)).unwrap();
    });
    let id = wait_entered.recv_timeout(Duration::from_secs(5)).unwrap();
    // SAFETY: the live controlled owner is held behind its explicit release.
    let raw = unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION | 0x00100000, 0, id) };
    assert!(!raw.is_null());
    // SAFETY: successful OpenThread transfers a uniquely owned query/sync handle.
    let thread = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
    assert_eq!(
        worker_wait::wait_until(&thread, Instant::now())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(
        worker_wait::wait_until(&thread, Instant::now() + Duration::from_millis(10))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    // SAFETY: the original query/synchronization object remains held.
    assert_eq!(
        unsafe { WaitForSingleObject(thread.as_raw_handle(), 0) },
        WAIT_TIMEOUT
    );
    release.send(()).unwrap();
    assert_eq!(
        worker_wait::wait_until(&thread, Instant::now() + Duration::from_secs(5)).unwrap(),
        0
    );
    // SAFETY: this is the same original retained thread, not a reopened numeric id.
    assert_eq!(
        unsafe { WaitForSingleObject(thread.as_raw_handle(), 0) },
        WAIT_OBJECT_0
    );
    owner.join().unwrap();
}
