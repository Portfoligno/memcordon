//! A fixed transport-session cutoff for synchronous Windows pipe operations.
//! This cancels only the calling worker's I/O and never extends target lifetime.
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::Arc,
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{ERROR_NOT_FOUND, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{
        CreateEventW, GetCurrentThreadId, OpenThread, SetEvent, THREAD_TERMINATE,
        WaitForSingleObject,
    },
};

pub struct SynchronousIoDeadline {
    deadline: Instant,
    completed: Arc<OwnedHandle>,
    watcher: Option<std::thread::JoinHandle<Result<(), String>>>,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl SynchronousIoDeadline {
    #[allow(unsafe_code)] // Retains a native reference to this exact calling thread and a fresh unnamed event.
    pub fn start(deadline: Instant) -> Result<Self, String> {
        if Instant::now() >= deadline {
            return Err("original terminal transport cutoff already exhausted".into());
        }
        let thread = unsafe { OpenThread(THREAD_TERMINATE, 0, GetCurrentThreadId()) };
        if thread.is_null() {
            return Err(format!(
                "terminal transport own-thread reference: {}",
                io::Error::last_os_error()
            ));
        }
        let thread = unsafe { OwnedHandle::from_raw_handle(thread.cast()) };
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(format!(
                "terminal transport completion event: {}",
                io::Error::last_os_error()
            ));
        }
        let completed = Arc::new(unsafe { OwnedHandle::from_raw_handle(event.cast()) });
        let observed = completed.clone();
        let watcher = std::thread::Builder::new()
            .name("terminal-transport-cutoff".into())
            .spawn(move || {
                let mut failure = None;
                let mut cancellation_failure_recorded = false;
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let millis = if remaining.is_zero() {
                        5
                    } else {
                        u32::try_from(remaining.as_millis().max(1)).unwrap_or(u32::MAX - 1)
                    };
                    // SAFETY: this thread retains the exact event until this wait returns.
                    match unsafe { WaitForSingleObject(observed.as_raw_handle().cast(), millis) } {
                        WAIT_OBJECT_0 => return failure.map_or(Ok(()), Err),
                        WAIT_TIMEOUT => {}
                        _ => {
                            failure.get_or_insert_with(|| {
                                format!(
                                    "terminal transport completion wait: {}",
                                    io::Error::last_os_error()
                                )
                            });
                        }
                    }
                    if Instant::now() < deadline && failure.is_none() {
                        continue;
                    }
                    failure.get_or_insert_with(|| {
                        "original terminal transport session cutoff expired".into()
                    });
                    // SAFETY: only the original calling worker is addressed. Repeat after
                    // the fixed cutoff to close CancelSynchronousIo's no-pending-I/O race.
                    if unsafe {
                        windows_sys::Win32::System::IO::CancelSynchronousIo(
                            thread.as_raw_handle().cast(),
                        )
                    } == 0
                    {
                        let error = io::Error::last_os_error();
                        if error.raw_os_error() != Some(ERROR_NOT_FOUND as i32)
                            && !cancellation_failure_recorded
                        {
                            cancellation_failure_recorded = true;
                            failure = Some(format!(
                                "{}; terminal transport cutoff cancellation: {error}",
                                failure.take().unwrap()
                            ));
                        }
                    }
                }
            })
            .map_err(|error| format!("terminal transport cutoff worker: {error}"))?;
        Ok(Self {
            deadline,
            completed,
            watcher: Some(watcher),
            _thread: std::marker::PhantomData,
        })
    }
    #[allow(unsafe_code)] // Signals only this privately owned event; joins before the original thread starts unrelated I/O.
    fn stop(&mut self) -> Result<(), String> {
        let Some(watcher) = self.watcher.take() else {
            return Ok(());
        };
        if unsafe { SetEvent(self.completed.as_raw_handle().cast()) } == 0 {
            panic!(
                "owned terminal completion event became invalid: {}",
                io::Error::last_os_error()
            );
        }
        watcher
            .join()
            .expect("terminal transport cutoff worker panicked")
    }
    pub fn cutoff(&self) -> Instant {
        self.deadline
    }
    pub fn finish(mut self) -> Result<(), String> {
        let expired = Instant::now() >= self.deadline;
        let result = self.stop();
        if expired && result.is_ok() {
            Err("original terminal transport session cutoff expired".into())
        } else {
            result
        }
    }
}
impl Drop for SynchronousIoDeadline {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
