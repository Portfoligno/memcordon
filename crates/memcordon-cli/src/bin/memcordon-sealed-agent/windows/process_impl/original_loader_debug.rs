//! Separate support experiment. Never enabled by an ordinary launch.
use std::{io, marker::PhantomData, rc::Rc, time::Instant};

use memcordon_core::{
    WindowsLoaderDebugEventV1, WindowsLoaderDebugImagePathSourceV1,
    WindowsLoaderDebugObservationV1, WindowsProcessIdentityV1,
};
use windows_sys::Win32::{
    Foundation::{
        DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, ERROR_SEM_TIMEOUT, EXCEPTION_BREAKPOINT,
    },
    System::{
        Diagnostics::Debug::{
            CREATE_PROCESS_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcess,
            DebugActiveProcessStop, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
            LOAD_DLL_DEBUG_EVENT, UNLOAD_DLL_DEBUG_EVENT, WaitForDebugEventEx,
        },
        ProcessStatus::K32GetMappedFileNameW,
        Threading::GetCurrentThreadId,
    },
};

use super::super::pipe::PendingTargetDesktopBootstrapAccept;
use super::{Job, OwnedHandle, TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS};

const MAX_EVENTS: usize = 64;

fn decode_debug_image_path(path: &[u16], length: u32) -> Result<String, u32> {
    if length == 0 {
        return Err(windows_sys::Win32::Foundation::ERROR_INVALID_DATA);
    }
    if length as usize >= path.len() {
        return Err(windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER);
    }
    let value = String::from_utf16(&path[..length as usize])
        .map_err(|_| windows_sys::Win32::Foundation::ERROR_NO_UNICODE_TRANSLATION)?;
    if value.len() > 2048 {
        return Err(windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER);
    }
    Ok(value)
}

fn mapped_debug_image_path(
    process: &OwnedHandle,
    base: *const std::ffi::c_void,
    cutoff: Instant,
) -> Result<String, u32> {
    if base.is_null() {
        return Err(windows_sys::Win32::Foundation::ERROR_INVALID_ADDRESS);
    }
    if Instant::now() >= cutoff {
        return Err(windows_sys::Win32::Foundation::ERROR_TIMEOUT);
    }
    let mut path = [0_u16; 512];
    // Query only the held process and current LOAD event's mapping while
    // its continuation is outstanding. This reads no remote string buffer.
    let length =
        unsafe { K32GetMappedFileNameW(process.raw(), base, path.as_mut_ptr(), path.len() as u32) };
    if length == 0 {
        return Err(io::Error::last_os_error()
            .raw_os_error()
            .and_then(|code| u32::try_from(code).ok())
            .unwrap_or(windows_sys::Win32::Foundation::ERROR_GEN_FAILURE));
    }
    if Instant::now() >= cutoff {
        return Err(windows_sys::Win32::Foundation::ERROR_TIMEOUT);
    }
    decode_debug_image_path(&path, length)
}

fn validate_startup_order(initial_process_seen: bool, event_code: u32) -> Result<(), String> {
    if (!initial_process_seen && event_code != CREATE_PROCESS_DEBUG_EVENT)
        || (initial_process_seen && event_code == CREATE_PROCESS_DEBUG_EVENT)
    {
        return Err("initial debug events omit or duplicate the selected process creation".into());
    }
    Ok(())
}

fn validate_startup_process(
    expected: &WindowsProcessIdentityV1,
    primary_thread_id: u32,
    event_process_id: u32,
    event_thread_id: u32,
    held: &WindowsProcessIdentityV1,
) -> Result<(), String> {
    if primary_thread_id == 0
        || event_process_id != expected.process_id
        || event_thread_id != primary_thread_id
        || held != expected
    {
        return Err(
            "initial debug process event differs from held bootstrap and primary thread".into(),
        );
    }
    Ok(())
}

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
    process: Option<OwnedHandle>,
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
                console_comparison: None,
            },
            process: None,
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
        match super::duplicate_owned(original_process) {
            Ok(process) => owner.process = Some(process),
            Err(error) => {
                owner.cancel_accept(cleanup_cutoff)?;
                return Err(error);
            }
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

    pub(super) fn prepare_resume(
        &mut self,
        primary_thread_id: u32,
        cutoff: Instant,
    ) -> Result<(), String> {
        self.require_creator();
        if primary_thread_id == 0 || self.initial_process_seen {
            return Err(
                "original support debug startup was already consumed or lacks primary thread"
                    .into(),
            );
        }
        loop {
            if Instant::now() >= cutoff {
                return Err("original support debug startup cutoff expired".into());
            }
            if !self.attached || self.observation.exit_event_continued {
                return Err("original bootstrap exited before explicit resume".into());
            }
            if self.observation.events.len() >= MAX_EVENTS || self.observation.omitted_events != 0 {
                return Err("original support debug startup event bound exhausted".into());
            }
            let observed = self.poll_event(cutoff, Some(primary_thread_id))?;
            if !observed && self.initial_process_seen && self.outstanding.is_none() {
                // Queue idle is not proof of a suspend count. The original
                // single ResumeThread call must still observe exactly one.
                return Ok(());
            }
        }
    }

    fn poll_event(&mut self, cutoff: Instant, startup_thread: Option<u32>) -> Result<bool, String> {
        self.require_creator();
        self.continue_outstanding()?;
        if !self.attached {
            return Ok(false);
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
                Ok(false)
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
        // Adopt event-owned image handles before any validation can fail.
        // Process/thread handles remain owned by the debug event protocol.
        let raw_image = match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => unsafe { event.u.CreateProcessInfo.hFile },
            LOAD_DLL_DEBUG_EVENT => unsafe { event.u.LoadDll.hFile },
            _ => std::ptr::null_mut(),
        };
        let image = if raw_image.is_null()
            || raw_image == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
        {
            None
        } else {
            Some(OwnedHandle::new(raw_image)?)
        };
        if event.dwProcessId != self.observation.process.process_id {
            return Err("debug event refers to a foreign process".to_owned());
        }
        if startup_thread.is_some() {
            validate_startup_order(self.initial_process_seen, event.dwDebugEventCode)?;
        }
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
            image_path_source: None,
            continuation: DBG_CONTINUE as u32,
            continuation_error: None,
        };
        // These image handles have documented independent caller ownership.
        // Close even when trace retention is full; never close the event-owned
        // process/thread handles, which Windows closes after continuation.
        match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let created = unsafe { event.u.CreateProcessInfo };
                if let Some(primary_thread_id) = startup_thread {
                    super::process_identity(created.hProcess).and_then(|held| {
                        validate_startup_process(
                            &self.observation.process,
                            primary_thread_id,
                            event.dwProcessId,
                            event.dwThreadId,
                            &held,
                        )
                    })?;
                }
                if event.dwProcessId == self.observation.process.process_id {
                    self.initial_process_seen = true;
                }
                observed.address = Some(created.lpBaseOfImage as usize as u64);
            }
            LOAD_DLL_DEBUG_EVENT => {
                let loaded = unsafe { event.u.LoadDll };
                observed.address = Some(loaded.lpBaseOfDll as usize as u64);
                if raw_image.is_null()
                    && event.dwProcessId == self.observation.process.process_id
                    && self.observation.events.len() < MAX_EVENTS
                {
                    observed.image_path_source =
                        Some(WindowsLoaderDebugImagePathSourceV1::MappedImage);
                    let decoded = mapped_debug_image_path(
                        self.process
                            .as_ref()
                            .expect("attached owner retains original process"),
                        loaded.lpBaseOfDll,
                        cutoff,
                    );
                    match decoded {
                        Ok(path) => observed.image_path = Some(path),
                        Err(error) => observed.image_path_error = Some(error),
                    }
                }
            }
            UNLOAD_DLL_DEBUG_EVENT => {
                observed.address = Some(unsafe { event.u.UnloadDll.lpBaseOfDll } as usize as u64);
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
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                observed.native_exit_code = Some(unsafe { event.u.ExitProcess.dwExitCode });
            }
            _ => (),
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
        self.continue_outstanding()?;
        if let (Some(index), Some(image)) = (retained, image) {
            self.observation.events[index].image_path_source =
                Some(WindowsLoaderDebugImagePathSourceV1::EventFile);
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
                match decode_debug_image_path(&path, length) {
                    Ok(path) => self.observation.events[index].image_path = Some(path),
                    Err(error) => self.observation.events[index].image_path_error = Some(error),
                }
            } else {
                self.observation.events[index].image_path_error =
                    Some(windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER);
            }
        }
        Ok(true)
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
                return self
                    .accept
                    .take()
                    .expect("pending accept owner")
                    .finish()
                    .map_err(|error| error.to_string());
            }
            self.poll_event(cutoff, None)?;
            if self.observation.exit_event_continued {
                return Err("original bootstrap exited during support observation".into());
            }
        }
    }

    pub(super) fn pump_handshake_until(&mut self, cutoff: Instant) -> Result<(), String> {
        self.require_creator();
        if self.observation.exit_event_continued {
            // The pipe wait still consumes an already-completed frame before
            // reporting held-peer exit; do not discard that race here.
            return Ok(());
        }
        if !self.attached
            || self.observation.events.len() >= MAX_EVENTS
            || self.observation.omitted_events != 0
        {
            return Err("support handshake debug ownership or event bound exhausted".into());
        }
        self.poll_event(cutoff, None).map(|_| ())
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
        // Keep the original creator-thread debug association long enough to
        // observe and continue actual EXIT. Detach remains incomplete fallback.
        while self.attached
            && Instant::now() < cutoff
            && self.observation.events.len() < MAX_EVENTS
            && self.observation.omitted_events == 0
        {
            if let Some(accept) = self.accept.as_mut() {
                match accept.cancel_and_poll() {
                    Ok(true) => self.accept = None,
                    Ok(false) => {}
                    Err(error) => {
                        cancellation_error.get_or_insert_with(|| error.to_string());
                    }
                }
            }
            if self.poll_event(cutoff, None).is_err() {
                break;
            }
        }
        // Even if capture exhausted the original cutoff, attempt native
        // detach once. This creates no new wait window; unsettled ownership
        // still takes the existing fail-stop path below.
        if self.continue_outstanding().is_ok()
            && self.attached
            && unsafe { DebugActiveProcessStop(self.observation.process.process_id) } != 0
        {
            self.attached = false;
            self.observation.detached = true;
        }
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
                let _ = self.poll_event(cutoff, None);
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
        if let Some(mut process) = self.process.take() {
            process.close_checked()?;
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

#[cfg(test)]
#[path = "../../../../../tests/sealed_agent/windows_loader_debug_startup.rs"]
mod startup_tests;
