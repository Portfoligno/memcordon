#[cfg(unix)]
mod unix {
    use std::io;
    #[cfg(target_os = "macos")]
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    #[cfg(target_os = "macos")]
    const COMMITTED: u32 = 1 << 31;
    #[cfg(target_os = "macos")]
    const SIGNALS: u32 = !COMMITTED;
    static OWNED: AtomicBool = AtomicBool::new(false);
    static ADMISSION: Admission = Admission::new();

    pub(crate) struct Admission(
        AtomicU32,
        #[cfg(target_os = "macos")] std::sync::atomic::AtomicU64,
        #[cfg(target_os = "macos")] AtomicBool,
    );
    impl Admission {
        const fn new() -> Self {
            Self(
                AtomicU32::new(0),
                #[cfg(target_os = "macos")]
                std::sync::atomic::AtomicU64::new(0),
                #[cfg(target_os = "macos")]
                AtomicBool::new(false),
            )
        }
        #[cfg(target_os = "macos")]
        fn record(&self, signal: i32) {
            if ![libc::SIGINT, libc::SIGTERM, libc::SIGHUP].contains(&signal) {
                return;
            }
            let mut old = self.0.load(Ordering::SeqCst);
            while old & SIGNALS == 0 {
                match self.0.compare_exchange(
                    old,
                    old | signal as u32,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => return,
                    Err(observed) => old = observed,
                }
            }
        }
        #[cfg(target_os = "macos")]
        fn interruption(&self) -> Option<i32> {
            let signal = self.0.load(Ordering::SeqCst) & SIGNALS;
            (signal != 0).then_some(signal as i32)
        }
    }

    /// Explicit host-routed cancellation for one execution context. Clones route
    /// signals to that same run; a handle cannot be reused for a later context.
    #[derive(Clone)]
    #[cfg(target_os = "macos")]
    pub struct CancellationHandle(Arc<Admission>);
    #[cfg(target_os = "macos")]
    impl Default for CancellationHandle {
        fn default() -> Self {
            Self::new()
        }
    }
    #[cfg(target_os = "macos")]
    impl CancellationHandle {
        pub fn new() -> Self {
            Self(Arc::new(Admission::new()))
        }
        pub fn interrupt(&self, signal: i32) -> io::Result<()> {
            if ![libc::SIGINT, libc::SIGTERM, libc::SIGHUP].contains(&signal) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported interruption signal",
                ));
            }
            self.0.record(signal);
            Ok(())
        }
    }

    #[derive(Clone)]
    #[cfg(target_os = "macos")]
    pub(crate) enum LaunchAdmission {
        Owned,
        Host(CancellationHandle),
    }
    #[cfg(target_os = "macos")]
    impl LaunchAdmission {
        #[cfg(feature = "test-support")]
        pub(crate) fn record_for_test(&self, signal: i32) {
            self.state().record(signal);
        }
        fn state(&self) -> &Admission {
            match self {
                Self::Owned => &ADMISSION,
                Self::Host(handle) => &handle.0,
            }
        }
        pub(crate) fn interruption(&self) -> Option<i32> {
            self.state().interruption()
        }
        pub(crate) fn check(&self) -> io::Result<()> {
            if self.interruption().is_some() {
                self.observed_at()?;
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "launch admission interrupted",
                ))
            } else {
                Ok(())
            }
        }
        pub(crate) fn commit(&self) -> io::Result<()> {
            self.state()
                .0
                .compare_exchange(0, COMMITTED, Ordering::SeqCst, Ordering::SeqCst)
                .map(|_| ())
                .map_err(|word| {
                    io::Error::new(
                        if word & SIGNALS != 0 {
                            io::ErrorKind::Interrupted
                        } else {
                            io::ErrorKind::AlreadyExists
                        },
                        "launch admission refused",
                    )
                })
        }
        pub(crate) fn next_attempt(&self) {
            self.state().0.fetch_and(SIGNALS, Ordering::SeqCst);
        }
        pub(crate) fn observed_at(&self) -> io::Result<u64> {
            let now = crate::macos_continuous_nanos()?;
            Ok(
                match self
                    .state()
                    .1
                    .compare_exchange(0, now, Ordering::SeqCst, Ordering::SeqCst)
                {
                    Ok(_) => now,
                    Err(first) => first,
                },
            )
        }
    }

    /// Caller-thread exec inheritance, captured before owned handlers are installed.
    /// Contains no function pointers. Hosts must serialize disposition changes while capturing.
    #[derive(Clone)]
    #[cfg(target_os = "macos")]
    pub struct CallerSignalSnapshot {
        pub(crate) mask: libc::sigset_t,
        pub(crate) ignored: Vec<i32>,
    }
    #[cfg(target_os = "macos")]
    impl CallerSignalSnapshot {
        pub fn capture() -> io::Result<Self> {
            let mut mask = unsafe { std::mem::zeroed() };
            let result =
                unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask) };
            if result != 0 {
                return Err(io::Error::from_raw_os_error(result));
            }
            let mut ignored = Vec::new();
            #[cfg(target_os = "macos")]
            let maximum = libc::SIGUSR2;
            #[cfg(not(target_os = "macos"))]
            let maximum = libc::SIGSYS;
            for signal in 1..=maximum {
                if [libc::SIGKILL, libc::SIGSTOP].contains(&signal) {
                    continue;
                }
                let mut action = std::mem::MaybeUninit::<libc::sigaction>::zeroed();
                if unsafe { libc::sigaction(signal, std::ptr::null(), action.as_mut_ptr()) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                if unsafe { action.assume_init() }.sa_sigaction == libc::SIG_IGN {
                    ignored.push(signal);
                }
            }
            Ok(Self { mask, ignored })
        }
    }

    extern "C" fn record_signal(signal: libc::c_int) {
        #[cfg(target_os = "macos")]
        ADMISSION.record(signal);
        #[cfg(not(target_os = "macos"))]
        ADMISSION.0.store(signal as u32, Ordering::SeqCst);
    }

    pub struct SignalSource {
        previous: Vec<(libc::c_int, libc::sigaction)>,
        owned: bool,
        #[cfg(target_os = "macos")]
        pub(crate) snapshot: CallerSignalSnapshot,
        #[cfg(target_os = "macos")]
        pub(crate) admission: LaunchAdmission,
    }
    impl SignalSource {
        /// Requires exclusive disposition management and quiesced previous handler dispatch.
        /// Arbitrary multithreaded embedding should use the host-managed execution context.
        pub fn install() -> io::Result<Self> {
            Self::install_transaction(|_| Ok(()), |_| {})
        }
        fn install_transaction(
            mut before: impl FnMut(usize) -> io::Result<()>,
            mut after: impl FnMut(usize),
        ) -> io::Result<Self> {
            OWNED
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .map_err(|_| {
                    io::Error::other("signal session already owned or restoration failed")
                })?;
            ADMISSION.0.store(0, Ordering::SeqCst);
            #[cfg(target_os = "macos")]
            ADMISSION.1.store(0, Ordering::SeqCst);
            #[cfg(target_os = "macos")]
            let snapshot = match CallerSignalSnapshot::capture() {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    OWNED.store(false, Ordering::SeqCst);
                    return Err(error);
                }
            };
            let mut source = Self {
                previous: Vec::new(),
                owned: true,
                #[cfg(target_os = "macos")]
                snapshot,
                #[cfg(target_os = "macos")]
                admission: LaunchAdmission::Owned,
            };
            for (index, signal) in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP]
                .into_iter()
                .enumerate()
            {
                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                action.sa_sigaction = record_signal as *const () as libc::sighandler_t;
                unsafe { libc::sigemptyset(&mut action.sa_mask) };
                action.sa_flags = libc::SA_RESTART;
                let mut old = std::mem::MaybeUninit::zeroed();
                let installed = before(index).and_then(|()| {
                    if unsafe { libc::sigaction(signal, &action, old.as_mut_ptr()) } != 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
                if let Err(error) = installed {
                    return match source.restore() {
                        Ok(()) => Err(error),
                        Err(rollback) => Err(io::Error::other(format!(
                            "{error}; signal rollback: {rollback}"
                        ))),
                    };
                }
                source.previous.push((signal, unsafe { old.assume_init() }));
                after(index);
            }
            Ok(source)
        }
        #[cfg(all(target_os = "macos", feature = "test-support"))]
        pub(crate) fn installation_fixture(
            failure: Option<usize>,
            interrupt: Option<usize>,
        ) -> io::Result<Option<i32>> {
            let source = Self::install_transaction(
                |index| {
                    if failure == Some(index) {
                        Err(io::Error::from_raw_os_error(libc::EIO))
                    } else {
                        Ok(())
                    }
                },
                |index| {
                    if interrupt == Some(index) {
                        record_signal(libc::SIGINT);
                    }
                },
            )?;
            let observed = source.take();
            source.finish()?;
            Ok(observed)
        }
        #[cfg(target_os = "macos")]
        pub(crate) fn host(
            snapshot: CallerSignalSnapshot,
            cancellation: CancellationHandle,
        ) -> io::Result<Self> {
            cancellation
                .0
                .2
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .map_err(|_| {
                    io::Error::other(
                        "cancellation handle has already been used by an execution context",
                    )
                })?;
            Ok(Self {
                previous: Vec::new(),
                owned: false,
                snapshot,
                admission: LaunchAdmission::Host(cancellation),
            })
        }
        pub fn take(&self) -> Option<i32> {
            #[cfg(target_os = "macos")]
            {
                self.admission.interruption()
            }
            #[cfg(not(target_os = "macos"))]
            {
                let signal = ADMISSION.0.swap(0, Ordering::SeqCst);
                (signal != 0).then_some(signal as i32)
            }
        }
        pub fn wait(&self, duration: std::time::Duration) -> io::Result<Option<i32>> {
            let deadline = std::time::Instant::now() + duration;
            loop {
                if let Some(signal) = self.take() {
                    return Ok(Some(signal));
                }
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Ok(None);
                }
                let timeout = remaining.as_millis().min(10) as i32;
                let result = unsafe { libc::poll(std::ptr::null_mut(), 0, timeout) };
                if result < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
        }
        fn restore(&mut self) -> io::Result<()> {
            let mut failures = Vec::new();
            for (signal, action) in self.previous.drain(..).rev() {
                if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
                    failures.push(io::Error::last_os_error().to_string());
                }
            }
            if self.owned {
                self.owned = false;
                if failures.is_empty() {
                    OWNED.store(false, Ordering::SeqCst);
                }
            }
            if failures.is_empty() {
                Ok(())
            } else {
                Err(io::Error::other(failures.join("; ")))
            }
        }
        #[cfg(target_os = "macos")]
        pub fn finish(mut self) -> io::Result<()> {
            self.restore()
        }
    }
    impl Drop for SignalSource {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) use unix::LaunchAdmission;
#[cfg(unix)]
pub use unix::SignalSource;
#[cfg(target_os = "macos")]
pub use unix::{CallerSignalSnapshot, CancellationHandle};
