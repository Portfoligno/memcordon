use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub(super) fn poll(
    stream: &UnixStream,
    relay: &super::private_relay::ByteRelay,
    deadline: Option<Instant>,
    read_control: bool,
) -> Result<(), String> {
    let mut descriptors = Vec::with_capacity(4);
    if read_control {
        descriptors.push(libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
    }
    relay.poll_descriptors(&mut descriptors);
    let timeout = deadline.map_or(20, |end| {
        i32::try_from(
            end.saturating_duration_since(Instant::now())
                .as_millis()
                .min(20),
        )
        .unwrap_or(20)
    });
    // SAFETY: every polled descriptor is held by stream/relay and the vector is writable.
    let result = unsafe {
        libc::poll(
            descriptors.as_mut_ptr(),
            descriptors.len() as libc::nfds_t,
            timeout,
        )
    };
    if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

pub(super) fn send_nonblocking(
    stream: &UnixStream,
    frame: &[u8],
    descriptors: &[RawFd],
    deadline: Option<Instant>,
) -> Result<(), String> {
    let mut sent = 0;
    let send_until = deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(5));
    while sent < frame.len() {
        if Instant::now() >= send_until {
            return Err("private request transfer deadline elapsed".into());
        }
        let result = if sent == 0 {
            let mut iovec = libc::iovec {
                iov_base: frame.as_ptr().cast_mut().cast(),
                iov_len: frame.len(),
            };
            // SAFETY: ABI size derives from the actual bounded descriptor array.
            let mut control = vec![
                0_u8;
                unsafe { libc::CMSG_SPACE(std::mem::size_of_val(descriptors) as u32) }
                    as usize
            ];
            // SAFETY: zero is the initial empty msghdr before filling its buffers.
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &raw mut iovec;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = control.len();
            // SAFETY: the CMSG_SPACE-sized buffer holds this exact descriptor copy.
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len =
                    libc::CMSG_LEN(std::mem::size_of_val(descriptors) as u32) as usize;
                std::ptr::copy_nonoverlapping(
                    descriptors.as_ptr(),
                    libc::CMSG_DATA(header).cast(),
                    descriptors.len(),
                );
                native_send(libc::sendmsg(
                    stream.as_raw_fd(),
                    &raw const message,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                ))
            }
        } else {
            // SAFETY: held stream and remaining immutable frame bytes remain valid.
            unsafe {
                native_send(libc::send(
                    stream.as_raw_fd(),
                    frame[sent..].as_ptr().cast(),
                    frame.len() - sent,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                ))
            }
        };
        match result {
            Ok(0) => return Err("private request transfer closed".into()),
            Ok(count) => sent += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                let mut descriptor = libc::pollfd {
                    fd: stream.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: one held stream descriptor and one writable pollfd.
                unsafe {
                    libc::poll(&raw mut descriptor, 1, 10);
                }
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn native_send(count: isize) -> std::io::Result<usize> {
    if count < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        usize::try_from(count).map_err(|_| std::io::Error::other("native transfer count overflow"))
    }
}
