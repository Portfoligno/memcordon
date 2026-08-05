use std::io;
use std::os::fd::RawFd;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

fn bounded_pause(duration: Duration) {
    let timeout = duration.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: zero-descriptor poll is a bounded kernel wait and remains signal-interruptible.
    unsafe { libc::poll(std::ptr::null_mut(), 0, timeout) };
}

const SHUTDOWN_GRACE: Duration = Duration::from_millis(100);
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[cfg(target_os = "linux")]
pub(crate) struct GuardianCleanupError {
    pub(crate) operation: &'static str,
    pub(crate) error: io::Error,
}

#[cfg(target_os = "linux")]
pub(crate) struct GuardianShutdown {
    pub(crate) errors: Vec<GuardianCleanupError>,
    pub(crate) may_be_alive: bool,
}

pub struct Guardian {
    child: Child,
    control: RawFd,
}

impl Guardian {
    pub fn spawn(process_group: i32, memcordon_executable: &Path) -> io::Result<Self> {
        let mut descriptors = [0_i32; 2];
        // SAFETY: `descriptors` points to storage for both pipe descriptors.
        if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // The guardian must not retain its own copy of the write end across exec, otherwise
        // wrapper death would never produce EOF on the read end.
        // SAFETY: both descriptors were returned by `pipe`; this only changes descriptor flags.
        if unsafe { libc::fcntl(descriptors[1], libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            let error = io::Error::last_os_error();
            // SAFETY: spawn has not occurred and both descriptors are uniquely owned here.
            unsafe {
                libc::close(descriptors[0]);
                libc::close(descriptors[1]);
            }
            return Err(error);
        }
        let mut command = Command::new(memcordon_executable);
        command.args([
            "__guardian",
            &descriptors[0].to_string(),
            &process_group.to_string(),
        ]);
        #[cfg(target_os = "linux")]
        command.process_group(0);
        let child = command.spawn();
        // SAFETY: the read descriptor belongs to the guardian after successful spawn and is
        // unused in the parent; after failure both descriptors must be closed.
        unsafe {
            libc::close(descriptors[0]);
        }
        match child {
            Ok(child) => Ok(Self {
                child,
                control: descriptors[1],
            }),
            Err(error) => {
                // SAFETY: guardian spawn failed, so the parent uniquely owns the write end.
                unsafe {
                    libc::close(descriptors[1]);
                }
                Err(error)
            }
        }
    }

    pub fn disarm(mut self, deadline: Instant) -> io::Result<()> {
        let marker = 1_u8;
        // SAFETY: `control` is the uniquely owned write end and `marker` is readable for one byte.
        let written = unsafe { libc::write(self.control, (&raw const marker).cast(), 1) };
        // SAFETY: the control descriptor is closed exactly once.
        unsafe {
            libc::close(self.control);
        }
        self.control = -1;
        if written != 1 {
            return Err(io::Error::last_os_error());
        }
        loop {
            match self.child.try_wait()? {
                Some(_) => return Ok(()),
                None if Instant::now() < deadline => bounded_pause(
                    SHUTDOWN_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                ),
                None => {
                    self.child.kill()?;
                    let escalation_deadline = Instant::now()
                        .checked_add(SHUTDOWN_GRACE)
                        .unwrap_or_else(Instant::now);
                    loop {
                        match self.child.try_wait()? {
                            Some(_) => return Ok(()),
                            None if Instant::now() < escalation_deadline => {
                                bounded_pause(SHUTDOWN_POLL_INTERVAL.min(
                                    escalation_deadline.saturating_duration_since(Instant::now()),
                                ))
                            }
                            None => {
                                return Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "guardian could not be reaped after forced termination",
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn disarm_until(mut self, deadline: Instant) -> GuardianShutdown {
        let marker = 1_u8;
        // SAFETY: `control` is the uniquely owned write end and marker is readable for one byte.
        let written = unsafe { libc::write(self.control, (&raw const marker).cast(), 1) };
        // SAFETY: the control descriptor is closed exactly once.
        unsafe {
            libc::close(self.control);
        }
        self.control = -1;

        let mut errors = Vec::new();
        let control_delivered = written == 1;
        if !control_delivered {
            errors.push(GuardianCleanupError {
                operation: "guardian-disarm",
                error: io::Error::last_os_error(),
            });
        }
        let process_group = i32::try_from(self.child.id())
            .ok()
            .filter(|value| *value > 0);
        let mut process_group_check_failed = process_group.is_none();
        if process_group.is_none() {
            errors.push(GuardianCleanupError {
                operation: "identify-guardian-process-group",
                error: io::Error::other("guardian PID cannot identify a native process group"),
            });
        }

        let mut direct_child_reaped = false;
        let mut reap_failed = false;
        let mut process_group_absent = false;
        let graceful_deadline = if control_delivered {
            deadline.min(Instant::now() + SHUTDOWN_GRACE)
        } else {
            Instant::now()
        };
        poll_shutdown(
            &mut self.child,
            process_group,
            graceful_deadline,
            &mut direct_child_reaped,
            &mut reap_failed,
            &mut process_group_absent,
            &mut process_group_check_failed,
            &mut errors,
        );

        if !direct_child_reaped || !process_group_absent {
            if !direct_child_reaped && !reap_failed {
                if !process_group_absent {
                    if let Some(process_group) = process_group {
                        // SAFETY: the unreaped leader pins the dedicated process group identity.
                        if unsafe { libc::kill(-process_group, libc::SIGKILL) } != 0 {
                            let error = io::Error::last_os_error();
                            if error.raw_os_error() != Some(libc::ESRCH) {
                                errors.push(GuardianCleanupError {
                                    operation: "terminate-guardian-process-group",
                                    error,
                                });
                            }
                        }
                    }
                }
                match self.child.kill() {
                    Err(error) if error.raw_os_error() != Some(libc::ESRCH) => {
                        errors.push(GuardianCleanupError {
                            operation: "terminate-guardian",
                            error,
                        });
                    }
                    _ => {}
                }
            } else {
                let (operation, message) = if reap_failed {
                    (
                        "terminate-guardian",
                        "guardian reap failed before its process identity could be proven live",
                    )
                } else {
                    (
                        "terminate-guardian-process-group",
                        "guardian leader was reaped before process-group absence was proven",
                    )
                };
                errors.push(GuardianCleanupError {
                    operation,
                    error: io::Error::other(message),
                });
                process_group_check_failed = true;
            }
            poll_shutdown(
                &mut self.child,
                process_group,
                deadline,
                &mut direct_child_reaped,
                &mut reap_failed,
                &mut process_group_absent,
                &mut process_group_check_failed,
                &mut errors,
            );
        }

        if !direct_child_reaped && !reap_failed {
            errors.push(GuardianCleanupError {
                operation: "reap-guardian",
                error: io::Error::new(
                    io::ErrorKind::TimedOut,
                    "guardian did not exit before the cleanup deadline",
                ),
            });
        }
        if !process_group_absent && !process_group_check_failed {
            errors.push(GuardianCleanupError {
                operation: "verify-guardian-process-group-empty",
                error: io::Error::new(
                    io::ErrorKind::TimedOut,
                    "guardian process group remained live after the cleanup deadline",
                ),
            });
        }
        GuardianShutdown {
            errors,
            may_be_alive: !direct_child_reaped || !process_group_absent,
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the bounded shutdown poll updates one explicit proof state for each native check"
)]
#[cfg(target_os = "linux")]
fn poll_shutdown(
    child: &mut Child,
    process_group: Option<i32>,
    deadline: Instant,
    direct_child_reaped: &mut bool,
    reap_failed: &mut bool,
    process_group_absent: &mut bool,
    process_group_check_failed: &mut bool,
    errors: &mut Vec<GuardianCleanupError>,
) {
    loop {
        if !*direct_child_reaped && !*reap_failed {
            match child.try_wait() {
                Ok(Some(_)) => *direct_child_reaped = true,
                Ok(None) => {}
                Err(error) => {
                    errors.push(GuardianCleanupError {
                        operation: "reap-guardian",
                        error,
                    });
                    *reap_failed = true;
                }
            }
        }
        if !*process_group_absent && !*process_group_check_failed {
            let process_group = process_group.expect("checked above");
            // SAFETY: signal zero only queries the dedicated guardian process group's existence.
            if unsafe { libc::kill(-process_group, 0) } != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    *process_group_absent = true;
                } else {
                    errors.push(GuardianCleanupError {
                        operation: "verify-guardian-process-group-empty",
                        error,
                    });
                    *process_group_check_failed = true;
                }
            }
        }
        if (*direct_child_reaped || *reap_failed)
            && (*process_group_absent || *process_group_check_failed)
        {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        bounded_pause(SHUTDOWN_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
}

impl Drop for Guardian {
    fn drop(&mut self) {
        if self.control >= 0 {
            // Unexpected parent-side drop closes the pipe. The guardian treats EOF as a crash.
            // SAFETY: the descriptor is uniquely owned and not used after this close.
            unsafe {
                libc::close(self.control);
            }
            self.control = -1;
        }
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
