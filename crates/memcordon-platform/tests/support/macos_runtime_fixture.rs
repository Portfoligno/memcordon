//! Native test support; ownership uses the production tickets and child API.
#![cfg(all(target_os = "macos", feature = "test-support"))]

use super::{Child, ChildOwner, LocalChild, ProcessGroupLease, UnreapedChild, runtime};
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

pub struct NativeChildProbe {
    child: Child,
}
impl NativeChildProbe {
    pub fn pid(&self) -> i32 {
        self.child.pid
    }
    pub fn observe(&self) -> io::Result<Option<ExitStatus>> {
        self.child.observe()
    }
    pub fn retirement_pending(&self) -> bool {
        let ChildOwner::Local(local) = &self.child.owner else {
            unreachable!()
        };
        local.retirement.observer().pending()
    }
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
    pub fn terminate(&self) -> io::Result<()> {
        self.child.kill()
    }
    pub fn consume_by_external_waiter(&self) -> io::Result<()> {
        let mut status = 0;
        // Deliberately violate the exclusive-waiter contract to exercise ECHILD.
        let result = unsafe { libc::waitpid(self.child.pid, &mut status, 0) };
        if result == self.child.pid {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    pub fn reaped_within(&mut self, duration: Duration) -> io::Result<ExitStatus> {
        let limit = Instant::now() + duration;
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= limit {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "native probe reap bound",
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

fn create(ticket: runtime::Ticket, live: bool) -> io::Result<NativeChildProbe> {
    ticket.begin()?;
    let mut command = Command::new(if live { "/bin/sleep" } else { "/usr/bin/true" });
    if live {
        command.arg("30");
    }
    let native = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = i32::try_from(native.id()).expect("native PID fits pid_t");
    ticket.publish(pid);
    // std::process::Child has no wait-on-Drop; transfer its native obligation
    // into the same local production owner, never a second waiter.
    drop(native);
    Ok(NativeChildProbe {
        child: Child {
            pid,
            status: None,
            owner: ChildOwner::Local(LocalChild {
                kernel: UnreapedChild { pid },
                group: ProcessGroupLease { leader: pid },
                retirement: ticket,
            }),
        },
    })
}

impl runtime::LaunchRuntime {
    #[doc(hidden)]
    pub fn test_process_thread_count() -> io::Result<usize> {
        crate::macos_watchdog::native_thread_count()
    }
    #[doc(hidden)]
    pub fn test_native_child(&self, live: bool) -> io::Result<NativeChildProbe> {
        create(self.reserve()?, live)
    }
    #[doc(hidden)]
    pub fn test_delayed_native_creation(
        &self,
        entered: Arc<AtomicBool>,
        release: Arc<AtomicBool>,
    ) -> io::Result<mpsc::Receiver<io::Result<NativeChildProbe>>> {
        let ticket = self.reserve()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        self.enqueue(Box::new(move || {
            let child = create(ticket, true);
            entered.store(true, Ordering::Release);
            while !release.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(2));
            }
            // On caller disconnection the returned native child drops into its
            // already-reserved retirement slot; no replacement thread exists.
            let _ = sender.try_send(child);
        }))?;
        Ok(receiver)
    }
}
