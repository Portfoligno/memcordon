//! Process-local interruption notification. Handlers never perform cleanup.
use std::{
    io,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};

static ACTIVE: AtomicBool = AtomicBool::new(false);
static OBSERVED: AtomicU8 = AtomicU8::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CiInterrupt {
    UnixInterrupt,
    UnixTerminate,
    WindowsControlC,
    WindowsControlBreak,
}

/// The installing owner must outlive all observers and their joined workers.
/// A token does not retain the registration or reset another peer's signal.
#[derive(Clone)]
pub struct CiInterruptToken {
    owner: Weak<()>,
}
impl CiInterruptToken {
    pub fn observed(&self) -> Option<CiInterrupt> {
        if self.owner.strong_count() == 0 {
            return None;
        }
        match OBSERVED.load(Ordering::Acquire) {
            1 => Some(CiInterrupt::UnixInterrupt),
            2 => Some(CiInterrupt::UnixTerminate),
            3 => Some(CiInterrupt::WindowsControlC),
            4 => Some(CiInterrupt::WindowsControlBreak),
            _ => None,
        }
    }
}

pub struct CiInterruptRegistration {
    owner: Arc<()>,
    #[cfg(unix)]
    previous: [libc::sigaction; 2],
}

#[cfg(unix)]
extern "C" fn unix_notify(signal: libc::c_int) {
    let value = if signal == libc::SIGINT { 1 } else { 2 };
    let _ = OBSERVED.compare_exchange(0, value, Ordering::Relaxed, Ordering::Relaxed);
}

#[cfg(windows)]
unsafe extern "system" fn windows_notify(event: u32) -> i32 {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    let value = match event {
        CTRL_C_EVENT => 3,
        CTRL_BREAK_EVENT => 4,
        _ => return 0,
    };
    let _ = OBSERVED.compare_exchange(0, value, Ordering::Relaxed, Ordering::Relaxed);
    1
}

impl CiInterruptRegistration {
    pub fn install() -> io::Result<Self> {
        ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "CI interrupt registration already active",
                )
            })?;
        OBSERVED.store(0, Ordering::Release);
        let result = Self::install_native();
        if result.is_err() {
            ACTIVE.store(false, Ordering::Release);
        }
        result
    }
    pub fn token(&self) -> CiInterruptToken {
        CiInterruptToken {
            owner: Arc::downgrade(&self.owner),
        }
    }

    #[cfg(unix)]
    fn install_native() -> io::Result<Self> {
        // SAFETY: zero initializes the native action storage; sigemptyset
        // initializes its mask before sigaction reads it. Supported CI targets
        // provide lock-free byte atomics, the handler's only operation.
        let mut previous: [libc::sigaction; 2] = unsafe { std::mem::zeroed() };
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = unix_notify as *const () as usize;
        action.sa_flags = libc::SA_RESTART;
        unsafe {
            libc::sigemptyset(&raw mut action.sa_mask);
        }
        for (index, signal) in [libc::SIGINT, libc::SIGTERM].into_iter().enumerate() {
            // SAFETY: both actions are valid native storage and the handler
            // has the required ABI and process lifetime.
            if unsafe { libc::sigaction(signal, &action, &raw mut previous[index]) } != 0 {
                let error = io::Error::last_os_error();
                if index != 0 {
                    // SAFETY: restore the exact action installed above.
                    if unsafe { libc::sigaction(libc::SIGINT, &previous[0], std::ptr::null_mut()) }
                        != 0
                    {
                        panic!("failed to restore SIGINT after partial CI registration");
                    }
                }
                return Err(error);
            }
        }
        Ok(Self {
            owner: Arc::new(()),
            previous,
        })
    }

    #[cfg(windows)]
    fn install_native() -> io::Result<Self> {
        // SAFETY: callback has the system ABI and process lifetime.
        if unsafe {
            windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(windows_notify), 1)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            owner: Arc::new(()),
        })
    }

    #[cfg(not(any(unix, windows)))]
    fn install_native() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "CI interruption unsupported on this platform",
        ))
    }
}

impl Drop for CiInterruptRegistration {
    fn drop(&mut self) {
        #[cfg(unix)]
        for (signal, previous) in [libc::SIGINT, libc::SIGTERM]
            .into_iter()
            .zip(&self.previous)
        {
            // SAFETY: restore exactly the previous action once, while this
            // registration still exclusively owns the handler pair.
            if unsafe { libc::sigaction(signal, previous, std::ptr::null_mut()) } != 0 {
                panic!("failed to restore CI interrupt handler");
            }
        }
        #[cfg(windows)]
        // SAFETY: remove exactly our callback, leaving prior handlers intact.
        if unsafe {
            windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(windows_notify), 0)
        } == 0
        {
            panic!("failed to restore CI console handler");
        }
        ACTIVE.store(false, Ordering::Release);
    }
}
