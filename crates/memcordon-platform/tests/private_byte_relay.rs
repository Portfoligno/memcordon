#![cfg(all(target_os = "linux", feature = "test-support"))]
use memcordon_platform::NativeByteRelayProbe;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut descriptors = [-1; 2];
    // SAFETY: two writable native descriptor slots.
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: successful pipe2 returns two distinct owned descriptors.
    unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    }
}

#[test]
fn sockets_relay_only_bytes_through_distinct_anonymous_channels_without_flag_changes() {
    let (mut input, frontend_input) = UnixStream::pair().unwrap();
    let (mut output, frontend_output) = UnixStream::pair().unwrap();
    let (mut error, frontend_error) = UnixStream::pair().unwrap();
    let descriptors = [
        frontend_input.as_raw_fd(),
        frontend_output.as_raw_fd(),
        frontend_error.as_raw_fd(),
    ];
    let flags = descriptors.map(|fd| unsafe { libc::fcntl(fd, libc::F_GETFL) });
    let (mut owner, [target_input, target_output, target_error]) =
        NativeByteRelayProbe::new(descriptors).unwrap();
    for channel in [&target_input, &target_output, &target_error] {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        assert_eq!(
            unsafe { libc::fstat(channel.as_raw_fd(), stat.as_mut_ptr()) },
            0
        );
        assert_eq!(
            unsafe { stat.assume_init() }.st_mode & libc::S_IFMT,
            libc::S_IFIFO
        );
    }
    input.write_all(b"input bytes").unwrap();
    input.shutdown(std::net::Shutdown::Write).unwrap();
    let mut target_input = std::fs::File::from(target_input);
    let mut target_output = std::fs::File::from(target_output);
    let mut target_error = std::fs::File::from(target_error);
    target_output.write_all(b"output bytes").unwrap();
    target_error.write_all(b"error bytes").unwrap();
    drop(target_output);
    drop(target_error);
    for _ in 0..8 {
        owner.step().unwrap();
    }
    let mut bytes = Vec::new();
    target_input.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"input bytes");
    output.set_nonblocking(true).unwrap();
    error.set_nonblocking(true).unwrap();
    let mut bytes = [0; 32];
    let count = output.read(&mut bytes).unwrap();
    assert_eq!(&bytes[..count], b"output bytes");
    let count = error.read(&mut bytes).unwrap();
    assert_eq!(&bytes[..count], b"error bytes");
    assert!(owner.outputs_drained());
    drop(owner);
    assert_eq!(
        descriptors.map(|fd| unsafe { libc::fcntl(fd, libc::F_GETFL) }),
        flags
    );
}

#[test]
fn full_native_output_cannot_block_relay_and_drop_restores_exact_shared_pipe_flags() {
    let (input_read, input_write) = pipe();
    let (output_read, output_write) = pipe();
    let (error_read, error_write) = pipe();
    let descriptors = [
        input_read.as_raw_fd(),
        output_write.as_raw_fd(),
        error_write.as_raw_fd(),
    ];
    let flags = descriptors.map(|fd| unsafe { libc::fcntl(fd, libc::F_GETFL) });
    let (mut owner, [target_input, target_output, target_error]) =
        NativeByteRelayProbe::new(descriptors).unwrap();
    let bytes = [1; 4096];
    loop {
        let written =
            unsafe { libc::write(output_write.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            break;
        }
    }
    let mut target_output = std::fs::File::from(target_output);
    target_output.write_all(b"pending bytes").unwrap();
    let started = Instant::now();
    for _ in 0..100 {
        owner.step().unwrap();
    }
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "full pipe blocked owned relay"
    );
    drop(owner);
    assert_eq!(
        descriptors.map(|fd| unsafe { libc::fcntl(fd, libc::F_GETFL) }),
        flags
    );
    drop((
        input_write,
        output_read,
        error_read,
        target_input,
        target_error,
    ));
}
