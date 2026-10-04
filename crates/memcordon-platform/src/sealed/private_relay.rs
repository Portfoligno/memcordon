//! Scoped byte relay. The provider receives fresh anonymous pipes, never the
//! frontend's stdio objects. No thread or native operation outlives this owner.
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const BUFFER_BYTES: usize = 16 * 1024;

struct Stdio {
    fd: OwnedFd,
    original_flags: i32,
    socket: bool,
    restored: bool,
}

impl Stdio {
    fn acquire(fd: RawFd) -> io::Result<Self> {
        // SAFETY: fcntl duplicates the borrowed descriptor into a new owned slot.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful F_DUPFD_CLOEXEC returns a new descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(duplicate) };
        // SAFETY: the owned descriptor stays open through these native queries.
        let original_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if original_flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat initializes the exact native stat object on success.
        if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the preceding successful fstat initialized stat.
        let socket = unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFSOCK;
        // Socket calls use MSG_DONTWAIT. Other descriptors share their status
        // flags with the original stdio description: this scoped change is
        // visible to concurrent users and does not pretend dup isolates flags.
        if !socket
            && unsafe {
                libc::fcntl(
                    fd.as_raw_fd(),
                    libc::F_SETFL,
                    original_flags | libc::O_NONBLOCK,
                )
            } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            original_flags,
            socket,
            restored: socket,
        })
    }

    fn restore(&mut self) -> io::Result<()> {
        if !self.restored {
            // SAFETY: restore the exact original flags on our held description.
            if unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, self.original_flags) } < 0 {
                return Err(io::Error::last_os_error());
            }
            self.restored = true;
        }
        Ok(())
    }

    fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        // SAFETY: the writable slice and owned descriptor remain valid.
        let count = unsafe {
            if self.socket {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            } else {
                libc::read(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            }
        };
        native_count(count)
    }

    fn write(&self, buffer: &[u8]) -> io::Result<usize> {
        // SAFETY: the readable slice and owned descriptor remain valid.
        let count = unsafe {
            if self.socket {
                libc::send(
                    self.fd.as_raw_fd(),
                    buffer.as_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            } else {
                libc::write(self.fd.as_raw_fd(), buffer.as_ptr().cast(), buffer.len())
            }
        };
        native_count(count)
    }
}

impl Drop for Stdio {
    fn drop(&mut self) {
        // Emergency cleanup remains bounded; the normal terminal path observes
        // restoration errors through ByteRelay::finish instead of certifying it.
        let _ = self.restore();
    }
}

fn native_count(count: isize) -> io::Result<usize> {
    if count < 0 {
        Err(io::Error::last_os_error())
    } else {
        usize::try_from(count).map_err(|_| io::Error::other("native byte count overflow"))
    }
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut pair = [-1; 2];
    // SAFETY: pipe2 initializes both descriptor slots on success.
    if unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both successful pipe2 results are distinct new owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) })
}

struct Lane {
    stdio: Stdio,
    channel: Option<OwnedFd>,
    buffer: [u8; BUFFER_BYTES],
    start: usize,
    end: usize,
    eof: bool,
    input: bool,
}

impl Lane {
    fn step(&mut self) -> io::Result<()> {
        let Some(channel) = &self.channel else {
            return Ok(());
        };
        if self.start != self.end {
            let result = if self.input {
                // SAFETY: channel and readable pending buffer remain owned.
                native_count(unsafe {
                    libc::write(
                        channel.as_raw_fd(),
                        self.buffer[self.start..self.end].as_ptr().cast(),
                        self.end - self.start,
                    )
                })
            } else {
                self.stdio.write(&self.buffer[self.start..self.end])
            };
            match result {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "private byte relay write returned zero",
                    ));
                }
                Ok(count) => self.start += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) if self.input && error.raw_os_error() == Some(libc::EPIPE) => {
                    self.start = 0;
                    self.end = 0;
                    self.eof = true;
                    self.channel.take();
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
            if self.eof {
                self.channel.take();
                return Ok(());
            }
            let result = if self.input {
                self.stdio.read(&mut self.buffer)
            } else {
                // SAFETY: the buffer is writable and channel remains owned.
                native_count(unsafe {
                    libc::read(
                        channel.as_raw_fd(),
                        self.buffer.as_mut_ptr().cast(),
                        self.buffer.len(),
                    )
                })
            };
            match result {
                Ok(0) => {
                    self.eof = true;
                    self.channel.take();
                }
                Ok(count) => self.end = count,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn poll(&self) -> Option<libc::pollfd> {
        let channel = self.channel.as_ref()?;
        let pending = self.start != self.end;
        Some(libc::pollfd {
            fd: if self.input == pending {
                channel.as_raw_fd()
            } else {
                self.stdio.fd.as_raw_fd()
            },
            events: if pending { libc::POLLOUT } else { libc::POLLIN },
            revents: 0,
        })
    }
}

pub(super) struct ByteRelay {
    lanes: [Lane; 3],
}

impl ByteRelay {
    pub(super) fn new() -> io::Result<(Self, [OwnedFd; 3])> {
        Self::with_stdio([0, 1, 2])
    }

    pub(super) fn with_stdio(descriptors: [RawFd; 3]) -> io::Result<(Self, [OwnedFd; 3])> {
        let input = Stdio::acquire(descriptors[0])?;
        let output = Stdio::acquire(descriptors[1])?;
        let error = Stdio::acquire(descriptors[2])?;
        let (input_read, input_write) = pipe()?;
        let (output_read, output_write) = pipe()?;
        let (error_read, error_write) = pipe()?;
        let lane = |stdio, channel, input| Lane {
            stdio,
            channel: Some(channel),
            buffer: [0; BUFFER_BYTES],
            start: 0,
            end: 0,
            eof: false,
            input,
        };
        Ok((
            Self {
                lanes: [
                    lane(input, input_write, true),
                    lane(output, output_read, false),
                    lane(error, error_read, false),
                ],
            },
            [input_read, output_write, error_write],
        ))
    }

    pub(super) fn step(&mut self) -> io::Result<()> {
        for lane in &mut self.lanes {
            lane.step()?;
        }
        Ok(())
    }

    pub(super) fn poll_descriptors(&self, output: &mut Vec<libc::pollfd>) {
        output.extend(self.lanes.iter().filter_map(Lane::poll));
    }

    pub(super) fn close_input(&mut self) {
        self.lanes[0].channel.take();
    }

    pub(super) fn outputs_drained(&self) -> bool {
        self.lanes[1..]
            .iter()
            .all(|lane| lane.channel.is_none() && lane.start == lane.end)
    }

    pub(super) fn finish(&mut self) -> io::Result<()> {
        let mut failure = None;
        for lane in &mut self.lanes {
            lane.channel.take();
            if let Err(error) = lane.stdio.restore() {
                if failure.is_none() {
                    failure = Some(error);
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub struct NativeByteRelayProbe(ByteRelay);

#[cfg(feature = "test-support")]
impl NativeByteRelayProbe {
    pub fn new(descriptors: [RawFd; 3]) -> io::Result<(Self, [OwnedFd; 3])> {
        ByteRelay::with_stdio(descriptors).map(|(owner, channels)| (Self(owner), channels))
    }
    pub fn step(&mut self) -> io::Result<()> {
        self.0.step()
    }
    pub fn outputs_drained(&self) -> bool {
        self.0.outputs_drained()
    }
}
