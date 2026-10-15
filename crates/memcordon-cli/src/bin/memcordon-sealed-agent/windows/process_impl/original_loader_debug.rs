//! Separate support experiment. Never enabled by an ordinary launch.
use std::{io, marker::PhantomData, rc::Rc, time::Instant};

use memcordon_core::{
    WindowsLoaderDebugEventV1, WindowsLoaderDebugObservationV1, WindowsProcessIdentityV1,
};
use windows_sys::Win32::{
    Foundation::{
        DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, ERROR_SEM_TIMEOUT, EXCEPTION_BREAKPOINT,
    },
    System::{
        Diagnostics::Debug::{
            CREATE_PROCESS_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcess,
            DebugActiveProcessStop, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
            LOAD_DLL_DEBUG_EVENT, WaitForDebugEventEx,
        },
        Threading::GetCurrentThreadId,
    },
};

use super::super::pipe::PendingTargetDesktopBootstrapAccept;
use super::{Job, OwnedHandle, TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS};

const MAX_EVENTS: usize = 64;

struct Continuation {
    pid: u32,
    tid: u32,
    disposition: i32,
    exits: bool,
    retained: Option<usize>,
}

/// Must remain on the original creator thread. Unsettled native debug ownership
/// cannot unwind into the long-lived service; the exclusive support gate is a
/// prerequisite for constructing this owner.
pub(super) struct OriginalLoaderDebug {
    observation: WindowsLoaderDebugObservationV1,
    attached: bool,
    outstanding: Option<Continuation>,
    accept: Option<PendingTargetDesktopBootstrapAccept>,
    initial_process_seen: bool,
    initial_breakpoint_seen: bool,
    _creator_thread: PhantomData<Rc<()>>,
}

impl OriginalLoaderDebug {
    pub(super) fn attach(
        original_process: windows_sys::Win32::Foundation::HANDLE,
        process: WindowsProcessIdentityV1,
        challenge: String,
        executable_sha256: String,
        launch_plan_sha256: String,
        accept: PendingTargetDesktopBootstrapAccept,
        cleanup_cutoff: Instant,
    ) -> Result<Self, String> {
        let mut owner = Self {
            observation: WindowsLoaderDebugObservationV1 {
                process,
                creator_thread_id: unsafe { GetCurrentThreadId() },
                challenge,
                executable_sha256,
                launch_plan_sha256,
                events: Vec::new(),
                omitted_events: 0,
                detached: false,
                exit_event_continued: false,
            },
            attached: false,
            outstanding: None,
            accept: Some(accept),
            initial_process_seen: false,
            initial_breakpoint_seen: false,
            _creator_thread: PhantomData,
        };
        let held = super::process_identity(original_process);
        if held.as_ref() != Ok(&owner.observation.process) {
            owner.cancel_accept(cleanup_cutoff)?;
            return Err("original held bootstrap birth differs before debug attach".into());
        }
        if unsafe { DebugActiveProcess(owner.observation.process.process_id) } == 0 {
            let error = io::Error::last_os_error().to_string();
            owner.cancel_accept(cleanup_cutoff)?;
            return Err(error);
        }
        owner.attached = true;
        Ok(owner)
    }

    fn require_creator(&self) {
        if unsafe { GetCurrentThreadId() } != self.observation.creator_thread_id {
            self.fail_stop("debug owner moved away from originating creator thread");
        }
    }

    fn fail_stop(&self, detail: &str) -> ! {
        eprintln!(
            "support-original-loader-debug incomplete: pid={} birth={} creator={} outstanding={} detail={detail}",
            self.observation.process.process_id,
            self.observation.process.creation_time_100ns,
            self.observation.creator_thread_id,
            self.outstanding.is_some(),
        );
        // Only legal inside the isolated measured support provider while both
        // package and exclusive settlement leases exclude unrelated owners.
        // Service death is NOT a child-retirement receipt.
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS,
            );
        }
        std::process::abort()
    }

    fn continue_outstanding(&mut self) -> Result<(), String> {
        let Some(event) = self.outstanding.as_ref() else {
            return Ok(());
        };
        if unsafe { ContinueDebugEvent(event.pid, event.tid, event.disposition) } == 0 {
            let error = io::Error::last_os_error();
            if let Some(index) = event.retained {
                self.observation.events[index].continuation_error = error
                    .raw_os_error()
                    .and_then(|code| u32::try_from(code).ok());
            }
            return Err(error.to_string());
        }
        if event.exits {
            self.observation.exit_event_continued = true;
            self.attached = false;
        }
        self.outstanding = None;
        Ok(())
    }

    fn poll_event(&mut self, cutoff: Instant) -> Result<(), String> {
        self.require_creator();
        self.continue_outstanding()?;
        if !self.attached {
            return Ok(());
        }
        let remaining = cutoff
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "original support debug cutoff expired".to_owned())?;
        let milliseconds = u32::try_from(remaining.as_millis().min(10)).unwrap_or(10);
        let mut event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        if unsafe { WaitForDebugEventEx(&raw mut event, milliseconds) } == 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_SEM_TIMEOUT as i32) {
                Ok(())
            } else {
                Err(error.to_string())
            };
        }
        // Successful wait itself creates the native continuation obligation.
        // Install it before any adoption, allocation, or validation can fail.
        self.outstanding = Some(Continuation {
            pid: event.dwProcessId,
            tid: event.dwThreadId,
            disposition: if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                DBG_EXCEPTION_NOT_HANDLED
            } else {
                DBG_CONTINUE
            },
            exits: event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT
                && event.dwProcessId == self.observation.process.process_id,
            retained: None,
        });
        let mut observed = WindowsLoaderDebugEventV1 {
            code: event.dwDebugEventCode,
            process_id: event.dwProcessId,
            thread_id: event.dwThreadId,
            exception_code: None,
            first_chance: None,
            address: None,
            native_exit_code: None,
            image_path: None,
            image_path_error: None,
            continuation: DBG_CONTINUE as u32,
            continuation_error: None,
        };
        // These image handles have documented independent caller ownership.
        // Close even when trace retention is full; never close the event-owned
        // process/thread handles, which Windows closes after continuation.
        let image = match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                if event.dwProcessId == self.observation.process.process_id {
                    self.initial_process_seen = true;
                }
                let created = unsafe { event.u.CreateProcessInfo };
                observed.address = Some(created.lpBaseOfImage as usize as u64);
                created.hFile
            }
            LOAD_DLL_DEBUG_EVENT => {
                let loaded = unsafe { event.u.LoadDll };
                observed.address = Some(loaded.lpBaseOfDll as usize as u64);
                loaded.hFile
            }
            EXCEPTION_DEBUG_EVENT => {
                let exception = unsafe { event.u.Exception };
                observed.exception_code = Some(exception.ExceptionRecord.ExceptionCode as u32);
                observed.first_chance = Some(exception.dwFirstChance != 0);
                observed.address = Some(exception.ExceptionRecord.ExceptionAddress as usize as u64);
                let startup = event.dwProcessId == self.observation.process.process_id
                    && self.initial_process_seen
                    && !self.initial_breakpoint_seen
                    && exception.dwFirstChance != 0
                    && exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT;
                if startup {
                    self.initial_breakpoint_seen = true;
                } else {
                    observed.continuation = DBG_EXCEPTION_NOT_HANDLED as u32;
                }
                std::ptr::null_mut()
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                observed.native_exit_code = Some(unsafe { event.u.ExitProcess.dwExitCode });
                std::ptr::null_mut()
            }
            _ => std::ptr::null_mut(),
        };
        let retained = if self.observation.events.len() < MAX_EVENTS {
            let index = self.observation.events.len();
            self.observation.events.push(observed.clone());
            Some(index)
        } else {
            self.observation.omitted_events = self.observation.omitted_events.saturating_add(1);
            None
        };
        let outstanding = self
            .outstanding
            .as_mut()
            .expect("successful wait owns event");
        outstanding.disposition = observed.continuation as i32;
        outstanding.retained = retained;
        let image =
            if image.is_null() || image == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                None
            } else {
                Some(OwnedHandle::new(image)?)
            };
        if event.dwProcessId != self.observation.process.process_id {
            return Err("debug event refers to a foreign process".to_owned());
        }
        self.continue_outstanding()?;
        if let (Some(index), Some(image)) = (retained, image) {
            // Query only the event-provided file handle, after continuation.
            // No PID/path reopen and no remote string/memory interpretation.
            let mut path = [0_u16; 512];
            let length = unsafe {
                windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW(
                    image.raw(),
                    path.as_mut_ptr(),
                    path.len() as u32,
                    0,
                )
            };
            if length == 0 {
                self.observation.events[index].image_path_error = io::Error::last_os_error()
                    .raw_os_error()
                    .and_then(|code| u32::try_from(code).ok());
            } else if (length as usize) < path.len() {
                match String::from_utf16(&path[..length as usize]) {
                    Ok(path) => self.observation.events[index].image_path = Some(path),
                    Err(_) => {
                        self.observation.events[index].image_path_error =
                            Some(windows_sys::Win32::Foundation::ERROR_NO_UNICODE_TRANSLATION)
                    }
                }
            } else {
                self.observation.events[index].image_path_error =
                    Some(windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER);
            }
        }
        Ok(())
    }

    pub(super) fn accept_until(&mut self, cutoff: Instant) -> Result<OwnedHandle, String> {
        self.require_creator();
        loop {
            if Instant::now() >= cutoff {
                return Err("original support handshake cutoff expired".into());
            }
            if self
                .accept
                .as_mut()
                .expect("debug owner retains pending accept")
                .poll()
                .map_err(|error| error.to_string())?
            {
                self.continue_outstanding()?;
                if self.attached {
                    if unsafe { DebugActiveProcessStop(self.observation.process.process_id) } == 0 {
                        return Err(io::Error::last_os_error().to_string());
                    }
                    self.attached = false;
                    self.observation.detached = true;
                }
                return self
                    .accept
                    .take()
                    .expect("pending accept owner")
                    .finish()
                    .map_err(|error| error.to_string());
            }
            self.poll_event(cutoff)?;
            if self.observation.exit_event_continued {
                return Err("original bootstrap exited during support observation".into());
            }
        }
    }

    fn cancel_accept(&mut self, cutoff: Instant) -> Result<(), String> {
        if let Some(accept) = self.accept.as_mut() {
            accept
                .cancel_and_drain_until(cutoff)
                .map_err(|error| error.to_string())?;
        }
        self.accept = None;
        Ok(())
    }

    pub(super) fn cleanup_until(&mut self, job: &Job, cutoff: Instant) -> Result<(), String> {
        self.require_creator();
        let termination = job.terminate(TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS);
        let mut cancellation_error = None;
        while (self.attached || self.accept.is_some()) && Instant::now() < cutoff {
            if let Some(accept) = self.accept.as_mut() {
                match accept.cancel_and_poll() {
                    Ok(true) => self.accept = None,
                    Ok(false) => {}
                    Err(error) => {
                        cancellation_error.get_or_insert_with(|| error.to_string());
                    }
                }
            }
            if self.continue_outstanding().is_ok()
                && self.attached
                && unsafe { DebugActiveProcessStop(self.observation.process.process_id) } != 0
            {
                self.attached = false;
                self.observation.detached = true;
            }
            if self.attached {
                let _ = self.poll_event(cutoff);
            } else if self.accept.is_some() {
                std::thread::yield_now();
            }
        }
        if self.attached || self.outstanding.is_some() || self.accept.is_some() {
            self.fail_stop("original cleanup cutoff exhausted with native ownership unsettled");
        }
        if let Some(error) = cancellation_error {
            return Err(error);
        }
        termination?;
        if !job.wait_empty(cutoff)? {
            return Err("original support Job drain incomplete".into());
        }
        Ok(())
    }

    pub(super) fn observation(&self) -> WindowsLoaderDebugObservationV1 {
        self.observation.clone()
    }
}

impl Drop for OriginalLoaderDebug {
    fn drop(&mut self) {
        if self.attached || self.outstanding.is_some() || self.accept.is_some() {
            self.fail_stop("debug owner dropped before native settlement");
        }
    }
}
