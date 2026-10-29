#![cfg(target_os = "linux")]

use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[allow(unsafe_code)] // Each test owns a fresh nonblocking native pipe.
fn pipe() -> (OwnedFd, OwnedFd) {
    let mut descriptors = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    }
}

#[allow(unsafe_code)] // Sends one bounded kernel ancillary transaction, intentionally including malformed frame bytes.
fn send_raw(stream: &UnixStream, bytes: &[u8], rights: &[i32]) {
    let capacity = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(rights) as u32) } as usize;
    let mut control = vec![0usize; capacity.div_ceil(std::mem::size_of::<usize>())];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = capacity;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&msg);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(rights) as u32) as usize;
        std::ptr::copy_nonoverlapping(
            rights.as_ptr(),
            libc::CMSG_DATA(header).cast(),
            rights.len(),
        );
        assert_eq!(
            libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL),
            bytes.len() as isize
        );
    }
}

fn frame(payload: Vec<u8>) -> (crate::protocol::Frame, Vec<u8>) {
    let frame = crate::protocol::Frame {
        kind: crate::protocol::MessageKind::Launch,
        nonce: [1; 16],
        attempt_id: [2; 16],
        payload,
    };
    let mut bytes = Vec::new();
    crate::protocol::write_frame(&mut bytes, &frame).unwrap();
    (frame, bytes)
}

#[test]
#[allow(unsafe_code)] // EOF of the original native pipe proves every transferred writer was closed, without process-global fd counts.
fn malformed_or_partial_frames_close_every_received_right() {
    for scenario in 0..4 {
        let (writer, reader) = UnixStream::pair().unwrap();
        let (read, write) = pipe();
        let (_, mut bytes) = frame(vec![9; 8]);
        let count = match scenario {
            0 => {
                bytes[0] = 0xff;
                bytes[1] = 0xff;
                bytes.len()
            }
            1 => 2,
            2 => bytes.len() - 1,
            _ => bytes.len(),
        };
        let rights = vec![write.as_raw_fd(); if scenario == 3 { 9 } else { 1 }];
        send_raw(&writer, &bytes[..count], &rights);
        drop(write);
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(
            crate::linux::transport::receive_public_until(
                &reader,
                Instant::now() + Duration::from_secs(1)
            )
            .is_err()
        );
        let mut byte = 0;
        assert_eq!(
            unsafe { libc::read(read.as_raw_fd(), (&raw mut byte).cast(), 1) },
            0,
            "scenario {scenario} leaked a received pipe writer"
        );
    }
}

#[test]
fn partial_header_progress_cannot_renew_the_original_receive_cutoff() {
    let (mut writer, reader) = UnixStream::pair().unwrap();
    let (_, bytes) = frame(Vec::new());
    let sender = std::thread::spawn(move || {
        for byte in bytes {
            if writer.write_all(&[byte]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let started = Instant::now();
    assert!(
        crate::linux::transport::receive_public_until(&reader, started + Duration::from_millis(40))
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(reader);
    sender.join().unwrap();
}

#[test]
#[allow(unsafe_code)] // A small native send buffer forces byte continuation after one SCM_RIGHTS transfer.
fn short_send_continues_bytes_without_repeating_descriptor_authority() {
    let (writer, reader) = UnixStream::pair().unwrap();
    let (read, write) = pipe();
    let amount = 4096i32;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                writer.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const amount).cast(),
                std::mem::size_of_val(&amount) as libc::socklen_t,
            )
        },
        0
    );
    let (expected, bytes) = frame(vec![7; 512 * 1024]);
    let sender = std::thread::spawn(move || {
        crate::linux::transport::send_until(
            &writer,
            &bytes,
            &[write.as_raw_fd()],
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap()
    });
    let (actual, rights, _) = crate::linux::transport::receive_public_until(
        &reader,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    sender.join().unwrap();
    assert_eq!(actual, expected);
    assert_eq!(rights.len(), 1);
    drop(rights);
    let mut byte = 0;
    assert_eq!(
        unsafe { libc::read(read.as_raw_fd(), (&raw mut byte).cast(), 1) },
        0
    );
}
