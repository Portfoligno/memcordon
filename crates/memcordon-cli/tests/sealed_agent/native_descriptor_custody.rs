#![cfg(target_os = "linux")]

use crate::linux::descriptor_custody::{
    ExpectedGatedDescriptorInventory, provider_owned_byte_pipes, verify_pipe_end,
    verify_private_gated_descriptor_inventory,
};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

#[test]
fn provider_owned_pipes_relay_bytes_without_frontend_descriptor_inheritance() {
    let (target, provider) = provider_owned_byte_pipes().unwrap();
    target.verify_native_directions().unwrap();
    assert!(verify_pipe_end(target.stdin_fd().as_raw_fd(), libc::O_WRONLY).is_err());
    assert!(verify_pipe_end(target.stdout_fd().as_raw_fd(), libc::O_RDONLY).is_err());
    let mut relay = provider.into_relay_streams();

    let source = b"private stdin bytes";
    let (mut frontend, mut frontend_peer) = UnixStream::pair().unwrap();
    frontend_peer.write_all(source).unwrap();
    frontend_peer.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        relay.copy_stdin_from(&mut frontend).unwrap(),
        source.len() as u64
    );
    let mut target_stdin = std::fs::File::from(target.stdin_fd().try_clone_to_owned().unwrap());
    let mut received = vec![0_u8; source.len()];
    target_stdin.read_exact(&mut received).unwrap();
    assert_eq!(received, source);
    assert_eq!(target_stdin.read(&mut [0_u8; 1]).unwrap(), 0);

    let stdout = b"private stdout bytes";
    let mut target_stdout = std::fs::File::from(target.stdout_fd().try_clone_to_owned().unwrap());
    target_stdout.write_all(stdout).unwrap();
    let mut captured = vec![0_u8; stdout.len()];
    relay.stdout_reader.read_exact(&mut captured).unwrap();
    assert_eq!(captured, stdout);

    let stderr = b"private stderr bytes";
    let mut target_stderr = std::fs::File::from(target.stderr_fd().try_clone_to_owned().unwrap());
    target_stderr.write_all(stderr).unwrap();
    let mut captured = vec![0_u8; stderr.len()];
    relay.stderr_reader.read_exact(&mut captured).unwrap();
    assert_eq!(captured, stderr);
}

#[test]
fn socket_valued_frontend_stdio_is_not_a_target_pipe() {
    let (frontend, _peer) = UnixStream::pair().unwrap();
    assert!(verify_pipe_end(frontend.as_raw_fd(), libc::O_RDONLY).is_err());
    assert!(verify_pipe_end(frontend.as_raw_fd(), libc::O_WRONLY).is_err());
    let (target, provider) = provider_owned_byte_pipes().unwrap();
    target.verify_native_directions().unwrap();
    drop((frontend, target, provider));
}

#[test]
fn gated_verifier_rejects_a_process_with_extra_descriptors() {
    let (target, _provider) = provider_owned_byte_pipes().unwrap();
    let mut raw = [-1_i32; 2];
    // SAFETY: socketpair initializes both slots on success; each descriptor is
    // transferred to exactly one OwnedFd below.
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                raw.as_mut_ptr(),
            )
        },
        0
    );
    // SAFETY: successful socketpair returned two separately owned descriptors.
    let control = unsafe { OwnedFd::from_raw_fd(raw[0]) };
    // SAFETY: successful socketpair returned two separately owned descriptors.
    let child_control = unsafe { OwnedFd::from_raw_fd(raw[1]) };
    let elf = std::fs::File::open("/proc/self/exe").unwrap();
    let expected = ExpectedGatedDescriptorInventory::capture(
        &target,
        control.as_fd(),
        child_control.as_fd(),
        elf.as_fd(),
    )
    .unwrap();
    assert!(
        verify_private_gated_descriptor_inventory(std::process::id() as i32, expected).is_err()
    );
    drop(control);
}
