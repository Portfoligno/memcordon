#[cfg(unix)]
mod unix {
    use std::io;
    use std::sync::atomic::{AtomicI32, Ordering};

    static LAST_SIGNAL: AtomicI32 = AtomicI32::new(0);

    extern "C" fn record_signal(signal: libc::c_int) {
        LAST_SIGNAL.store(signal, Ordering::SeqCst);
    }

    pub struct SignalSource {
        previous: [(libc::c_int, libc::sighandler_t); 3],
    }

    impl SignalSource {
        pub fn install() -> io::Result<Self> {
            let mut previous = [(0, libc::SIG_DFL); 3];
            for (index, signal) in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP]
                .into_iter()
                .enumerate()
            {
                // SAFETY: `record_signal` has the C signal-handler ABI and only stores to a
                // lock-free atomic. The previous disposition is retained and restored on drop.
                let old = unsafe {
                    libc::signal(signal, record_signal as *const () as libc::sighandler_t)
                };
                if old == libc::SIG_ERR {
                    return Err(io::Error::last_os_error());
                }
                previous[index] = (signal, old);
            }
            LAST_SIGNAL.store(0, Ordering::SeqCst);
            Ok(Self { previous })
        }

        pub fn take(&self) -> Option<i32> {
            let signal = LAST_SIGNAL.swap(0, Ordering::SeqCst);
            (signal != 0).then_some(signal)
        }

        pub fn wait(&self, duration: std::time::Duration) -> io::Result<Option<i32>> {
            if let Some(signal) = self.take() {
                return Ok(Some(signal));
            }
            let timeout = duration.as_millis().min(i32::MAX as u128) as i32;
            // SAFETY: a null pollfd pointer with zero descriptors is valid; signals interrupt the
            // bounded kernel wait without requiring shell or environment coordination.
            let result = unsafe { libc::poll(std::ptr::null_mut(), 0, timeout) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
            Ok(self.take())
        }
    }

    impl Drop for SignalSource {
        fn drop(&mut self) {
            for (signal, disposition) in self.previous {
                // SAFETY: both values were returned by successful calls to `signal` above.
                unsafe {
                    libc::signal(signal, disposition);
                }
            }
        }
    }
}

#[cfg(unix)]
pub use unix::SignalSource;
