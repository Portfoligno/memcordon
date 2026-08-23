use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::time::{Duration, Instant};

use super::cgroup::AttemptCgroup;

pub struct GuardianLease<'a> {
    pub frontend_pidfd: BorrowedFd<'a>,
    pub provider_lease: BorrowedFd<'a>,
    pub init_pidfd: BorrowedFd<'a>,
    pub cgroup: AttemptCgroup,
}

impl GuardianLease<'_> {
    pub fn monitor(self, cleanup_budget: Duration) -> Result<(), String> {
        let mut pollfds = [
            libc::pollfd {
                fd: self.frontend_pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.provider_lease.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
        ];
        loop {
            let status =
                // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
                unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, -1) };
            if status == -1 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if status > 0 {
                // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        self.init_pidfd.as_fd().as_raw_fd(),
                        libc::SIGKILL,
                        0,
                        0,
                    )
                };
                return self.cgroup.kill_and_retire(Instant::now() + cleanup_budget);
            }
        }
    }
}
