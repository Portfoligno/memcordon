#![cfg(windows)]
#![allow(unsafe_code)]
//! Native held-object predicates only; this does not claim qualified observer/WCT execution.
use memcordon_windows_loader_lab::helper_wait_protocol;
#[path = "../src/helper_wait_binding.rs"]
mod binding;
use helper_wait_protocol as wire;
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::mpsc,
    thread::JoinHandle,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, FILETIME, HANDLE, WAIT_OBJECT_0},
    System::Threading::{
        CreateEventW, GetCurrentProcess, GetProcessTimes, GetThreadId, GetThreadTimes,
        WaitForSingleObject,
    },
};

fn duplicate(handle: HANDLE, access: u32) -> OwnedHandle {
    let mut copied = std::ptr::null_mut();
    let process = unsafe { GetCurrentProcess() };
    assert_ne!(
        unsafe { DuplicateHandle(process, handle, process, &mut copied, access, 0, 0) },
        0
    );
    unsafe { OwnedHandle::from_raw_handle(copied) }
}
fn birth(process: bool, handle: &OwnedHandle) -> u64 {
    let (mut creation, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    let ok = if process {
        unsafe {
            GetProcessTimes(
                handle.as_raw_handle(),
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        }
    } else {
        unsafe {
            GetThreadTimes(
                handle.as_raw_handle(),
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        }
    };
    assert_ne!(ok, 0);
    (u64::from(creation.dwHighDateTime) << u32::BITS) | u64::from(creation.dwLowDateTime)
}
struct Thread {
    handle: Option<OwnedHandle>,
    worker: Option<JoinHandle<()>>,
    release: Option<mpsc::Sender<()>>,
    deadline: Instant,
}
impl Thread {
    fn new(deadline: Instant) -> Self {
        let (release, wait) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = wait.recv();
        });
        // Only duplicate the already owned thread; never open its TID.
        let mut owned = Self {
            handle: None,
            worker: Some(worker),
            release: Some(release),
            deadline,
        };
        owned.handle = Some(duplicate(
            owned.worker.as_ref().unwrap().as_raw_handle(),
            0x0010_0800,
        ));
        owned
    }
    fn handle(&self) -> &OwnedHandle {
        self.handle.as_ref().unwrap()
    }
    fn identity(&self) -> wire::Thread {
        wire::Thread {
            handle: self.handle().as_raw_handle() as usize as u64,
            tid: unsafe { GetThreadId(self.handle().as_raw_handle()) },
            birth: birth(false, self.handle()),
        }
    }
    fn finish(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if self.worker.is_some() {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            let millis = remaining.as_millis().min(u128::from(u32::MAX - 1)) as u32;
            if unsafe { WaitForSingleObject(self.worker.as_ref().unwrap().as_raw_handle(), millis) }
                != WAIT_OBJECT_0
            {
                std::process::abort();
            }
            // Native exit was observed under the original cutoff before joining.
            self.worker.take().unwrap().join().unwrap();
        }
    }
}
impl Drop for Thread {
    fn drop(&mut self) {
        self.finish();
    }
}

#[test]
fn exact_exited_original_handle_remains_distinct_from_a_remaining_live_thread() {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut exited = Thread::new(deadline);
    let live = Thread::new(deadline);
    let original = exited.identity();
    let remaining = live.identity();
    assert_eq!(
        binding::thread(
            exited.handle(),
            &original,
            std::process::id(),
            0,
            wire::BindingBoundary::BeforeQuery
        )
        .unwrap(),
        binding::ThreadState::Live
    );
    exited.finish();
    assert!(matches!(
        binding::thread(
            exited.handle(),
            &original,
            std::process::id(),
            0,
            wire::BindingBoundary::BeforeQuery
        )
        .unwrap(),
        binding::ThreadState::Exited(_)
    ));
    assert_eq!(
        binding::thread(
            live.handle(),
            &remaining,
            std::process::id(),
            1,
            wire::BindingBoundary::BeforeQuery
        )
        .unwrap(),
        binding::ThreadState::Live
    );
    let mut wrong = original;
    wrong.birth = wrong.birth.checked_add(1).unwrap();
    let failure = binding::thread(
        exited.handle(),
        &wrong,
        std::process::id(),
        0,
        wire::BindingBoundary::BeforeQuery,
    )
    .unwrap_err();
    assert_eq!(failure.reason, wire::BindingReason::IdentityMismatch);
    assert_eq!(failure.observed.birth, Some(u128::from(original.birth)));
}

#[test]
fn helper_mismatch_and_wrong_object_query_errors_remain_terminal_facts() {
    let process = duplicate(unsafe { GetCurrentProcess() }, 0x0010_1000);
    let actual = wire::Identity {
        pid: std::process::id(),
        birth: u128::from(birth(true, &process)),
    };
    binding::process(&process, actual, None, wire::BindingBoundary::BeforeQuery).unwrap();
    let wrong = wire::Identity {
        birth: u128::MAX,
        ..actual
    };
    let failure =
        binding::process(&process, wrong, None, wire::BindingBoundary::BeforeQuery).unwrap_err();
    assert_eq!(failure.reason, wire::BindingReason::IdentityMismatch);
    assert_eq!(failure.observed.birth, Some(actual.birth));
    let raw = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    assert!(!raw.is_null());
    let event = unsafe { OwnedHandle::from_raw_handle(raw) };
    let failure = binding::thread(
        &event,
        &wire::Thread {
            handle: 1,
            tid: 1,
            birth: 1,
        },
        actual.pid,
        0,
        wire::BindingBoundary::BeforeQuery,
    )
    .unwrap_err();
    assert_eq!(failure.operation, wire::BindingOperation::GetId);
    assert_eq!(failure.reason, wire::BindingReason::NativeError);
    assert!(failure.native_error.is_some());
}
