use std::io::{Cursor, Read};
use std::mem::{size_of, zeroed};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use crate::protocol::{Frame, MAX_FRAME_LENGTH, read_frame};

const FRAME_HEADER_LENGTH: usize = 72;
const MAX_DESCRIPTORS: usize = 6;

pub fn receive(stream: &UnixStream) -> Result<(Frame, Vec<OwnedFd>), String> {
    let mut header = [0_u8; FRAME_HEADER_LENGTH];
    let control_capacity =
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::CMSG_SPACE((MAX_DESCRIPTORS * size_of::<libc::c_int>()) as u32) } as usize;
    let mut control = vec![0_u8; control_capacity];
    let mut iovec = libc::iovec {
        iov_base: header.as_mut_ptr().cast(),
        iov_len: header.len(),
    };
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let received = unsafe {
        libc::recvmsg(
            stream.as_raw_fd(),
            &raw mut message,
            libc::MSG_CMSG_CLOEXEC | libc::MSG_WAITALL,
        )
    };
    if received != FRAME_HEADER_LENGTH as isize {
        return Err(format!(
            "provider frame header receive failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
        return Err("provider request or descriptor inventory was truncated".to_owned());
    }
    let total = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if !(FRAME_HEADER_LENGTH..=MAX_FRAME_LENGTH).contains(&total) {
        return Err("invalid provider frame length".to_owned());
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&header);
    let mut payload = vec![0_u8; total - FRAME_HEADER_LENGTH];
    (&*stream)
        .read_exact(&mut payload)
        .map_err(|error| error.to_string())?;
    bytes.extend_from_slice(&payload);
    let mut descriptors = Vec::new();
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let mut header_ptr = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header_ptr.is_null() {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        let header_ref = unsafe { &*header_ptr };
        if header_ref.cmsg_level != libc::SOL_SOCKET || header_ref.cmsg_type != libc::SCM_RIGHTS {
            return Err("unexpected ancillary provider data".to_owned());
        }
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        let data_length = header_ref.cmsg_len as usize - unsafe { libc::CMSG_LEN(0) } as usize;
        if data_length % size_of::<libc::c_int>() != 0 {
            return Err("misaligned descriptor inventory".to_owned());
        }
        let count = data_length / size_of::<libc::c_int>();
        if descriptors.len() + count > MAX_DESCRIPTORS {
            return Err("too many provider descriptors".to_owned());
        }
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        let data = unsafe { libc::CMSG_DATA(header_ptr).cast::<libc::c_int>() };
        for index in 0..count {
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            let descriptor = unsafe { *data.add(index) };
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            descriptors.push(unsafe { OwnedFd::from_raw_fd(descriptor) });
        }
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        header_ptr = unsafe { libc::CMSG_NXTHDR(&message, header_ptr) };
    }
    let frame = read_frame(&mut Cursor::new(bytes)).map_err(|error| error.to_string())?;
    Ok((frame, descriptors))
}

use std::os::fd::{AsRawFd, RawFd};

pub fn send(
    stream: &UnixStream,
    encoded_frame: &[u8],
    descriptors: &[RawFd],
) -> Result<(), String> {
    if descriptors.len() > MAX_DESCRIPTORS || encoded_frame.len() < FRAME_HEADER_LENGTH {
        return Err("invalid provider descriptor transaction".to_owned());
    }
    let mut iovec = libc::iovec {
        iov_base: encoded_frame.as_ptr().cast_mut().cast(),
        iov_len: encoded_frame.len(),
    };
    let control_length =
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe { libc::CMSG_SPACE((descriptors.len() * size_of::<RawFd>()) as u32) } as usize;
    let mut control = vec![0_u8; control_length];
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iovec;
    message.msg_iovlen = 1;
    if !descriptors.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len =
                libc::CMSG_LEN((descriptors.len() * size_of::<RawFd>()) as u32) as usize;
            std::ptr::copy_nonoverlapping(
                descriptors.as_ptr(),
                libc::CMSG_DATA(cmsg).cast(),
                descriptors.len(),
            );
        }
    }
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const message, libc::MSG_NOSIGNAL) };
    if sent != encoded_frame.len() as isize {
        return Err("short provider frame send".to_owned());
    }
    Ok(())
}
