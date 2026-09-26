//! Fixed target-phase AF_UNIX denial fixture for the candidate release
//! matrix. This is target-observed syscall evidence, not a case result.

pub(crate) const SELECTOR: &str = "private_tcp::af_unix_socketpair_denied";
pub(crate) const IMPORT_SELECTOR: &str = "private_tcp::io_uring_and_pidfd_import_denied";
pub(crate) const NAMESPACE_SELECTOR: &str = "private_tcp::namespace_reentry_denied";
pub(crate) const PORT_COLLISION_SELECTOR: &str = "private_tcp::port_collision_same_namespace";

pub(crate) fn expected_errno_bytes() -> [u8; 8] {
    let mut bytes = [0_u8; 8];
    bytes[..4].copy_from_slice(&libc::EAFNOSUPPORT.to_le_bytes());
    bytes[4..].copy_from_slice(&libc::EPERM.to_le_bytes());
    bytes
}

pub(crate) fn observe_target_denials() -> Result<[u8; 8], String> {
    // SAFETY: socket takes only scalar arguments and returns one owned fd on
    // unexpected success, which is immediately closed before rejection.
    let socket = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let socket_error = std::io::Error::last_os_error().raw_os_error();
    if socket >= 0 {
        // SAFETY: successful socket returned one unique owned descriptor.
        unsafe { libc::close(socket) };
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX socket succeeded".into());
    }
    if socket_error != Some(libc::EAFNOSUPPORT) {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX socket errno {socket_error:?} differs"
        ));
    }
    let mut pair = [-1; 2];
    // SAFETY: socketpair receives two writable descriptor slots. Unexpected
    // successful descriptors are closed before rejecting the case.
    let status = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    };
    let pair_error = std::io::Error::last_os_error().raw_os_error();
    if status == 0 {
        for fd in pair {
            // SAFETY: successful socketpair initialized each unique fd.
            unsafe { libc::close(fd) };
        }
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: AF_UNIX socketpair succeeded".into());
    }
    if pair_error != Some(libc::EPERM) {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE-FIXTURE: socketpair errno {pair_error:?} differs"
        ));
    }
    Ok(expected_errno_bytes())
}

pub(crate) fn expected_import_errno_bytes() -> [u8; 8] {
    let mut bytes = [0_u8; 8];
    bytes[..4].copy_from_slice(&libc::EPERM.to_le_bytes());
    bytes[4..].copy_from_slice(&libc::EPERM.to_le_bytes());
    bytes
}

pub(crate) fn expected_namespace_errno_bytes() -> [u8; 8] {
    expected_import_errno_bytes()
}

pub(crate) fn observe_import_denials() -> Result<[u8; 8], String> {
    // Linux io_uring_params is a 120-byte aligned UAPI structure. A real
    // zero-filled structure requests ordinary defaults, unlike a null pointer.
    // SAFETY: the fixed seccomp policy must reject this syscall. A nonnegative
    // result is an unexpected owned ring descriptor, closed before failure.
    let mut parameters = [0_u64; 15];
    let ring = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1_u32, parameters.as_mut_ptr()) };
    let ring_error = std::io::Error::last_os_error().raw_os_error();
    if ring >= 0 {
        // SAFETY: an unexpected successful setup returned one owned fd.
        unsafe { libc::close(ring as libc::c_int) };
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: io_uring_setup succeeded".into());
    }
    if ring_error != Some(libc::EPERM) {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE-FIXTURE: io_uring_setup errno {ring_error:?} differs"
        ));
    }

    // SAFETY: the policy must reject pidfd_getfd before either invalid fd
    // argument is resolved. A nonnegative result is an imported owned fd.
    let imported = unsafe { libc::syscall(libc::SYS_pidfd_getfd, -1_i32, 0_i32, 0_u32) };
    let imported_error = std::io::Error::last_os_error().raw_os_error();
    if imported >= 0 {
        // SAFETY: an unexpected import returned one owned fd.
        unsafe { libc::close(imported as libc::c_int) };
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: pidfd_getfd succeeded".into());
    }
    if imported_error != Some(libc::EPERM) {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE-FIXTURE: pidfd_getfd errno {imported_error:?} differs"
        ));
    }
    Ok(expected_import_errno_bytes())
}

pub(crate) fn observe_namespace_denials() -> Result<[u8; 8], String> {
    observe_namespace_denials_held().map(|(observed, _namespace)| observed)
}

// Public source protocol retains the actual setns operand through the root
// held-target ACK. Legacy callers retain their original close-on-return shape.
pub(crate) fn observe_namespace_denials_held() -> Result<([u8; 8], std::fs::File), String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let namespace = std::fs::File::open("/proc/self/ns/net").map_err(|error| error.to_string())?;
    let before = namespace
        .metadata()
        .map_err(|error| error.to_string())?
        .ino();
    if before == 0 {
        return Err("namespace fixture handle inode absent".into());
    }
    // SAFETY: a live NSFS network namespace fd and exact namespace flag.
    let reentry = unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) };
    let reentry_error = std::io::Error::last_os_error().raw_os_error();
    if reentry != -1 || reentry_error != Some(libc::EPERM) {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE-FIXTURE: setns result {reentry} errno {reentry_error:?} differs"
        ));
    }
    // SAFETY: unshare receives only one fixed scalar flag; success would
    // mutate this disposable target's namespace and is never accepted.
    let creation = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    let creation_error = std::io::Error::last_os_error().raw_os_error();
    if creation != -1 || creation_error != Some(libc::EPERM) {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE-FIXTURE: unshare result {creation} errno {creation_error:?} differs"
        ));
    }
    if std::fs::metadata("/proc/self/ns/net")
        .map_err(|error| error.to_string())?
        .ino()
        != before
    {
        return Err("namespace fixture changed its namespace".into());
    }
    let mut observed = [0; 8];
    observed[..4].copy_from_slice(
        &reentry_error
            .ok_or("namespace reentry errno absent")?
            .to_le_bytes(),
    );
    observed[4..].copy_from_slice(
        &creation_error
            .ok_or("namespace creation errno absent")?
            .to_le_bytes(),
    );
    Ok((observed, namespace))
}

pub(crate) fn expected_port_collision_errno_bytes() -> [u8; 4] {
    libc::EADDRINUSE.to_le_bytes()
}

pub(crate) fn observe_port_collision(challenge: &[u8; 32]) -> Result<[u8; 4], String> {
    // The fixed target fixture creates a listener, requires its competing
    // bind to return EADDRINUSE, and completes the challenge over that same
    // listener before it returns. This is a separate physical release attempt.
    let errno = super::private_qualification::tcp_listener_client_competitor_observed(challenge)?;
    if errno != libc::EADDRINUSE {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: collision errno differs".into());
    }
    Ok(errno.to_le_bytes())
}
