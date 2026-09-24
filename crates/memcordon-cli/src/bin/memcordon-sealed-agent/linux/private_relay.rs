//! Bounded, cancellable byte-pipe relay for one private attempt. The frontend
//! must transfer nonblocking pipe/socket endpoints; changing a shared caller
//! file-description's flags would mutate authority outside this attempt.

use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;

use super::descriptor_custody::ProviderPipeStdio;

const RELAY_BUFFER_BYTES: usize = 8192;

struct Channel {
    source: File,
    destination: Option<File>,
    pending: [u8; RELAY_BUFFER_BYTES],
    offset: usize,
    length: usize,
    source_eof: bool,
}

impl Channel {
    fn new(source: File, destination: File) -> Self {
        Self {
            source,
            destination: Some(destination),
            pending: [0; RELAY_BUFFER_BYTES],
            offset: 0,
            length: 0,
            source_eof: false,
        }
    }

    fn completed(&self) -> bool {
        self.source_eof && self.length == 0
    }

    fn pump(&mut self) -> Result<(), String> {
        if !self.source_eof && self.length == 0 {
            // SAFETY: read writes at most the fixed pending capacity to a live
            // descriptor verified nonblocking before this loop.
            let count = unsafe {
                libc::read(
                    self.source.as_raw_fd(),
                    self.pending.as_mut_ptr().cast(),
                    self.pending.len(),
                )
            };
            if count > 0 {
                self.offset = 0;
                self.length = count as usize;
            } else if count == 0 {
                self.source_eof = true;
            } else if !would_retry() {
                return Err(format!(
                    "MCSEALED-PRIVATE-RELAY: read: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        if self.length > 0 {
            let destination = self
                .destination
                .as_ref()
                .ok_or("MCSEALED-PRIVATE-RELAY: destination closed with pending bytes")?;
            // SAFETY: write borrows exactly the initialized pending slice and
            // its destination is a live nonblocking endpoint.
            let count = unsafe {
                libc::write(
                    destination.as_raw_fd(),
                    self.pending[self.offset..self.offset + self.length]
                        .as_ptr()
                        .cast(),
                    self.length,
                )
            };
            if count > 0 {
                self.offset += count as usize;
                self.length -= count as usize;
            } else if count == 0 {
                return Err("MCSEALED-PRIVATE-RELAY: zero-length write".into());
            } else if !would_retry() {
                return Err(format!(
                    "MCSEALED-PRIVATE-RELAY: write: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        if self.completed() {
            self.destination.take();
        }
        Ok(())
    }

    fn poll_descriptors(&self, output: &mut Vec<libc::pollfd>) {
        if !self.source_eof && self.length == 0 {
            output.push(libc::pollfd {
                fd: self.source.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            });
        }
        if self.length > 0 {
            if let Some(destination) = &self.destination {
                output.push(libc::pollfd {
                    fd: destination.as_raw_fd(),
                    events: libc::POLLOUT | libc::POLLHUP,
                    revents: 0,
                });
            }
        }
    }
}

pub struct PrivateRelay {
    stdin: Channel,
    stdout: Channel,
    stderr: Channel,
}

impl PrivateRelay {
    /// Acquires all six endpoints before candidate release. Frontend FDs must
    /// already be nonblocking and pipe/socket typed; no caller flags are
    /// altered. Provider halves are private file descriptions and can be
    /// marked nonblocking without changing the target's complementary halves.
    pub fn prepare(provider: ProviderPipeStdio, frontend: [OwnedFd; 3]) -> Result<Self, String> {
        require_nonblocking_stream(frontend[0].as_raw_fd(), true)?;
        require_nonblocking_stream(frontend[1].as_raw_fd(), false)?;
        require_nonblocking_stream(frontend[2].as_raw_fd(), false)?;
        let mut streams = provider.into_relay_streams();
        let stdin_writer = streams
            .take_stdin_writer()
            .ok_or("MCSEALED-PRIVATE-RELAY: stdin writer absent")?;
        for fd in [
            stdin_writer.as_raw_fd(),
            streams.stdout_reader.as_raw_fd(),
            streams.stderr_reader.as_raw_fd(),
        ] {
            set_nonblocking(fd)?;
        }
        let [stdin, stdout, stderr] = frontend;
        Ok(Self {
            stdin: Channel::new(stdin.into(), stdin_writer),
            stdout: Channel::new(streams.stdout_reader, stdout.into()),
            stderr: Channel::new(streams.stderr_reader, stderr.into()),
        })
    }

    pub fn completed(&self) -> bool {
        self.stdin.completed() && self.stdout.completed() && self.stderr.completed()
    }

    pub fn close_stdin_after_target_exit(&mut self) {
        self.stdin.source_eof = true;
        self.stdin.length = 0;
        self.stdin.destination.take();
    }

    /// One bounded readiness interval. A supervisor checks frontend loss,
    /// revocation, OOM and deadline between calls and can drop the relay
    /// immediately without waiting on a blocked stdio worker.
    pub fn tick(&mut self, interval: Duration) -> Result<(), String> {
        self.stdin.pump()?;
        self.stdout.pump()?;
        self.stderr.pump()?;
        if self.completed() {
            return Ok(());
        }
        let mut descriptors = Vec::with_capacity(6);
        self.stdin.poll_descriptors(&mut descriptors);
        self.stdout.poll_descriptors(&mut descriptors);
        self.stderr.poll_descriptors(&mut descriptors);
        let timeout = interval.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: poll synchronously borrows the initialized descriptor list.
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                timeout,
            )
        };
        if result == -1 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
        {
            return Err(format!(
                "MCSEALED-PRIVATE-RELAY: poll: {}",
                std::io::Error::last_os_error()
            ));
        }
        if descriptors
            .iter()
            .any(|fd| fd.revents & (libc::POLLERR | libc::POLLNVAL) != 0)
        {
            return Err("MCSEALED-PRIVATE-RELAY: endpoint error".into());
        }
        Ok(())
    }
}

fn would_retry() -> bool {
    matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EAGAIN | libc::EINTR)
    )
}

fn require_nonblocking_stream(fd: i32, readable: bool) -> Result<(), String> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes metadata for a live owned descriptor.
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELAY: fstat: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful fstat fully initialized metadata.
    let metadata = unsafe { metadata.assume_init() };
    let kind = metadata.st_mode & libc::S_IFMT;
    if kind != libc::S_IFIFO && kind != libc::S_IFSOCK {
        return Err("MCSEALED-PRIVATE-RELAY: frontend endpoint is not pipe/socket".into());
    }
    // SAFETY: F_GETFL reads flags from a live descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let access = flags & libc::O_ACCMODE;
    if flags == -1
        || flags & libc::O_NONBLOCK == 0
        || (readable && access == libc::O_WRONLY)
        || (!readable && access == libc::O_RDONLY)
    {
        return Err("MCSEALED-PRIVATE-RELAY: frontend endpoint must be nonblocking".into());
    }
    Ok(())
}

fn set_nonblocking(fd: i32) -> Result<(), String> {
    // SAFETY: both calls act on one provider-owned live descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELAY: nonblocking provider endpoint: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
