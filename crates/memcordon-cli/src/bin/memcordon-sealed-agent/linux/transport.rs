use std::io::Cursor;
use std::mem::{size_of, size_of_val, zeroed};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::protocol::{Frame, MAX_FRAME_LENGTH, PROTOCOL_VERSION};

const FRAME_HEADER_LENGTH: usize = 72;
const MAX_DESCRIPTORS: usize = 8;

pub fn receive(stream: &UnixStream) -> Result<(Frame, Vec<OwnedFd>), String> {
    receive_until(stream, Instant::now() + Duration::from_secs(30))
}
pub fn receive_until(
    stream: &UnixStream,
    cutoff: Instant,
) -> Result<(Frame, Vec<OwnedFd>), String> {
    let received = receive_inner(stream, false, Some(PROTOCOL_VERSION), false, cutoff)?;
    Ok((received.frame, received.descriptors))
}

/// Receives the ordinary public channel envelope and its owned descriptors.
pub fn receive_public(stream: &UnixStream) -> Result<(Frame, Vec<OwnedFd>, u16), String> {
    receive_public_until(stream, Instant::now() + Duration::from_secs(30))
}
pub fn receive_public_until(
    stream: &UnixStream,
    cutoff: Instant,
) -> Result<(Frame, Vec<OwnedFd>, u16), String> {
    let received = receive_inner(stream, false, None, false, cutoff)?;
    Ok((received.frame, received.descriptors, received.version))
}

pub(crate) fn receive_with_credentials(
    stream: &UnixStream,
) -> Result<(Frame, Vec<OwnedFd>, Option<libc::ucred>), String> {
    let received = receive_inner(
        stream,
        true,
        Some(PROTOCOL_VERSION),
        false,
        Instant::now() + Duration::from_secs(30),
    )?;
    Ok((received.frame, received.descriptors, received.credentials))
}
pub(crate) fn receive_authentication_until(
    stream: &UnixStream,
    cutoff: std::time::Instant,
) -> Result<(Frame, Vec<OwnedFd>, Option<libc::ucred>), String> {
    let received = receive_inner(stream, true, Some(PROTOCOL_VERSION), true, cutoff)?;
    Ok((received.frame, received.descriptors, received.credentials))
}

struct ReceivedMessage {
    frame: Frame,
    descriptors: Vec<OwnedFd>,
    credentials: Option<libc::ucred>,
    version: u16,
}

fn receive_inner(
    stream: &UnixStream,
    accept_credentials: bool,
    expected_version: Option<u16>,
    header_only: bool,
    cutoff: Instant,
) -> Result<ReceivedMessage, String> {
    let mut header = [0_u8; FRAME_HEADER_LENGTH];
    let mut descriptors = Vec::new();
    let mut credentials = None;
    receive_bytes_until(
        stream,
        &mut header,
        accept_credentials,
        &mut descriptors,
        &mut credentials,
        cutoff,
    )?;
    let version = u16::from_be_bytes([header[0], header[1]]);
    if !matches!(
        version,
        PROTOCOL_VERSION | crate::protocol::WORKLOAD_PROTOCOL_VERSION
    ) || expected_version.is_some_and(|expected| expected != version)
    {
        return Err("unsupported provider frame version".into());
    }
    let total = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if header_only && total != FRAME_HEADER_LENGTH {
        return Err("authentication frame must have no payload".into());
    }
    if !(FRAME_HEADER_LENGTH..=MAX_FRAME_LENGTH).contains(&total) {
        return Err("invalid provider frame length".into());
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&header);
    let mut payload = vec![0_u8; total - FRAME_HEADER_LENGTH];
    receive_bytes_until(
        stream,
        &mut payload,
        accept_credentials,
        &mut descriptors,
        &mut credentials,
        cutoff,
    )?;
    bytes.extend_from_slice(&payload);
    let frame = crate::protocol::read_frame_version(&mut Cursor::new(bytes), version)
        .map_err(|error| error.to_string())?;
    if Instant::now() >= cutoff {
        return Err("original provider frame cutoff expired during decode".into());
    }
    Ok(ReceivedMessage {
        frame,
        descriptors,
        credentials,
        version,
    })
}

/// All received rights become owned immediately, even when this same chunk has
/// a malformed header or ancillary inventory. Every subsequent error drops them.
fn receive_bytes_until(
    stream: &UnixStream,
    mut bytes: &mut [u8],
    accept_credentials: bool,
    descriptors: &mut Vec<OwnedFd>,
    credentials: &mut Option<libc::ucred>,
    cutoff: Instant,
) -> Result<(), String> {
    while !bytes.is_empty() {
        wait_ready_until(stream, libc::POLLIN, cutoff)?;
        // SAFETY: libc computes storage sizes from bounded scalar lengths.
        let capacity =
            unsafe { libc::CMSG_SPACE((MAX_DESCRIPTORS * size_of::<libc::c_int>()) as u32) }
                as usize
                + if accept_credentials {
                    (unsafe { libc::CMSG_SPACE(size_of::<libc::ucred>() as u32) }) as usize
                } else {
                    0
                };
        // Native-word storage supplies the alignment required by cmsghdr.
        let mut control = vec![0_usize; capacity.div_ceil(size_of::<usize>())];
        let mut iovec = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: zero initializes unused native msghdr fields.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &raw mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = capacity;
        // SAFETY: all message buffers remain live; nonblocking receive cannot
        // renew the original cutoff while the peer supplies partial bytes.
        let received = unsafe {
            libc::recvmsg(
                stream.as_raw_fd(),
                &raw mut message,
                libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
            )
        };
        if received < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(format!("provider frame receive failed: {error}"));
        }
        let mut ancillary_error = None;
        // SAFETY: recvmsg returned a kernel-populated ancillary buffer.
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
        while !cmsg.is_null() {
            // SAFETY: CMSG_FIRSTHDR/NXTHDR only yield complete native headers.
            let header = unsafe { &*cmsg };
            let header_size = unsafe { libc::CMSG_LEN(0) } as usize;
            let length = header.cmsg_len as usize;
            let offset = (cmsg as usize).saturating_sub(message.msg_control as usize);
            if length < header_size
                || offset
                    .checked_add(length)
                    .is_none_or(|end| end > message.msg_controllen)
            {
                ancillary_error.get_or_insert("invalid ancillary provider data length");
                break;
            }
            let data_length = length - header_size;
            if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
                let count = data_length / size_of::<libc::c_int>();
                // Adopt every complete FD BEFORE rejecting excess/misaligned
                // inventory. Unknown ancillary headers cannot skip later rights.
                let data = unsafe { libc::CMSG_DATA(cmsg).cast::<libc::c_int>() };
                for index in 0..count {
                    let raw = unsafe { *data.add(index) };
                    // SAFETY: each SCM_RIGHTS value is a new kernel-transferred FD.
                    descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
                }
                if data_length % size_of::<libc::c_int>() != 0
                    || descriptors.len() > MAX_DESCRIPTORS
                {
                    ancillary_error
                        .get_or_insert("invalid or excessive provider descriptor inventory");
                }
            } else if header.cmsg_level == libc::SOL_SOCKET
                && header.cmsg_type == libc::SCM_CREDENTIALS
                && accept_credentials
            {
                if data_length != size_of::<libc::ucred>() {
                    ancillary_error.get_or_insert("invalid launcher credential inventory");
                } else {
                    let observed = unsafe { *libc::CMSG_DATA(cmsg).cast::<libc::ucred>() };
                    if credentials.as_ref().is_some_and(|prior| {
                        prior.pid != observed.pid
                            || prior.uid != observed.uid
                            || prior.gid != observed.gid
                    }) {
                        ancillary_error
                            .get_or_insert("launcher credentials changed within one frame");
                    } else {
                        *credentials = Some(observed);
                    }
                }
            } else {
                ancillary_error.get_or_insert("unexpected ancillary provider data");
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&message, cmsg) };
        }
        if message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
            ancillary_error.get_or_insert("provider request or descriptor inventory was truncated");
        }
        if let Some(error) = ancillary_error {
            return Err(error.into());
        }
        if received == 0 {
            return Err("provider frame receive incomplete: peer closed".into());
        }
        let received = usize::try_from(received).map_err(|error| error.to_string())?;
        let (_, rest) = bytes.split_at_mut(received);
        bytes = rest;
    }
    Ok(())
}

fn wait_ready_until(
    stream: &UnixStream,
    events: libc::c_short,
    cutoff: Instant,
) -> Result<(), String> {
    loop {
        let remaining = cutoff.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("original provider frame cutoff expired".into());
        }
        let mut poll = libc::pollfd {
            fd: stream.as_raw_fd(),
            events,
            revents: 0,
        };
        let millis =
            i32::try_from(remaining.as_millis().clamp(1, 100)).expect("bounded poll duration");
        // SAFETY: one initialized live socket poll record.
        let observed = unsafe { libc::poll(&raw mut poll, 1, millis) };
        if observed < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.to_string());
        }
        if observed > 0 {
            if Instant::now() >= cutoff {
                return Err("original provider frame cutoff expired".into());
            }
            return Ok(());
        }
    }
}

use std::os::fd::{AsRawFd, RawFd};

pub fn send(
    stream: &UnixStream,
    encoded_frame: &[u8],
    descriptors: &[RawFd],
) -> Result<(), String> {
    send_until(
        stream,
        encoded_frame,
        descriptors,
        Instant::now() + Duration::from_secs(30),
    )
}

/// Transfer rights exactly once. A partial successful send continues only the
/// remaining frame bytes, never repeating ancillary authority.
pub fn send_until(
    stream: &UnixStream,
    encoded_frame: &[u8],
    descriptors: &[RawFd],
    cutoff: Instant,
) -> Result<(), String> {
    if descriptors.len() > MAX_DESCRIPTORS
        || !(FRAME_HEADER_LENGTH..=MAX_FRAME_LENGTH).contains(&encoded_frame.len())
    {
        return Err("invalid provider descriptor transaction".into());
    }
    let control_length = unsafe { libc::CMSG_SPACE(size_of_val(descriptors) as u32) } as usize;
    let mut control = vec![0_usize; control_length.div_ceil(size_of::<usize>())];
    let mut offset = 0;
    while offset < encoded_frame.len() {
        wait_ready_until(stream, libc::POLLOUT, cutoff)?;
        let remaining = &encoded_frame[offset..];
        let sent = if offset == 0 {
            let mut iovec = libc::iovec {
                iov_base: remaining.as_ptr().cast_mut().cast(),
                iov_len: remaining.len(),
            };
            let mut message: libc::msghdr = unsafe { zeroed() };
            message.msg_iov = &raw mut iovec;
            message.msg_iovlen = 1;
            if !descriptors.is_empty() {
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen = control_length;
                let cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
                // SAFETY: aligned ancillary storage has room for the exact
                // bounded borrowed descriptor list.
                unsafe {
                    (*cmsg).cmsg_level = libc::SOL_SOCKET;
                    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(size_of_val(descriptors) as u32) as usize;
                    std::ptr::copy_nonoverlapping(
                        descriptors.as_ptr(),
                        libc::CMSG_DATA(cmsg).cast(),
                        descriptors.len(),
                    );
                    libc::sendmsg(
                        stream.as_raw_fd(),
                        &raw const message,
                        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                    )
                }
            } else {
                unsafe {
                    libc::sendmsg(
                        stream.as_raw_fd(),
                        &raw const message,
                        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                    )
                }
            }
        } else {
            // SAFETY: only remaining borrowed bytes are sent; no rights are
            // repeated after the first positive sendmsg result.
            unsafe {
                libc::send(
                    stream.as_raw_fd(),
                    remaining.as_ptr().cast(),
                    remaining.len(),
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            }
        };
        if sent < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(format!("provider frame send failed: {error}"));
        }
        if sent == 0 {
            return Err("provider frame send made no progress".into());
        }
        offset += usize::try_from(sent).map_err(|error| error.to_string())?;
    }
    if Instant::now() >= cutoff {
        return Err("original provider frame send cutoff expired".into());
    }
    Ok(())
}
