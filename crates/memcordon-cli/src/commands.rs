mod application;
pub use application::{clean, doctor, execute, plan};

#[cfg(unix)]
const LAUNCHER_STATUS_MAGIC: &[u8; 4] = b"MCLS";
#[cfg(unix)]
const LAUNCHER_STATUS_VERSION: u8 = 1;
#[cfg(unix)]
const LAUNCHER_STATUS_LENGTH: usize = 12;
#[cfg(unix)]
const LAUNCHER_STATUS_READY: u8 = 1;
#[cfg(unix)]
const LAUNCHER_STATUS_ERROR: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InternalInvocation {
    Launcher {
        control_fd: i32,
        exec_status_fd: i32,
        command: Vec<std::ffi::OsString>,
    },
    Guardian {
        control_fd: i32,
        process_group: i32,
    },
}

pub(crate) fn route_internal(
    argv: &[std::ffi::OsString],
) -> Option<Result<InternalInvocation, &'static str>> {
    let name = argv.first()?;
    if name == "__launcher" {
        if argv.len() < 5 || argv.get(3).is_none_or(|argument| argument != "--") {
            return Some(Err(
                "internal launcher requires CONTROL_FD EXEC_STATUS_FD -- PROGRAM [ARGUMENT...]",
            ));
        }
        let control_fd = parse_nonnegative_descriptor(argv.get(1));
        let exec_status_fd = parse_nonnegative_descriptor(argv.get(2));
        return Some(match (control_fd, exec_status_fd) {
            (Ok(control_fd), Ok(exec_status_fd)) => Ok(InternalInvocation::Launcher {
                control_fd,
                exec_status_fd,
                command: argv[4..].to_vec(),
            }),
            _ => Err("internal launcher descriptors must be nonnegative decimal integers"),
        });
    }
    if name == "__guardian" {
        if argv.len() != 3 {
            return Some(Err(
                "internal guardian requires exactly CONTROL_FD PROCESS_GROUP",
            ));
        }
        let control_fd = parse_nonnegative_descriptor(argv.get(1));
        let process_group = parse_positive_process_group(argv.get(2));
        return Some(match (control_fd, process_group) {
            (Ok(control_fd), Ok(process_group)) => Ok(InternalInvocation::Guardian {
                control_fd,
                process_group,
            }),
            _ => Err(
                "internal guardian requires a nonnegative descriptor and positive process group",
            ),
        });
    }
    None
}

fn parse_nonnegative_descriptor(value: Option<&std::ffi::OsString>) -> Result<i32, ()> {
    value
        .and_then(|value| value.to_str())
        .ok_or(())
        .and_then(|value| value.parse::<i32>().map_err(|_| ()))
        .and_then(|value| (value >= 0).then_some(value).ok_or(()))
}

fn parse_positive_process_group(value: Option<&std::ffi::OsString>) -> Result<i32, ()> {
    value
        .and_then(|value| value.to_str())
        .ok_or(())
        .and_then(|value| value.parse::<i32>().map_err(|_| ()))
        .and_then(|value| (value > 0).then_some(value).ok_or(()))
}

pub(crate) fn execute_internal(invocation: InternalInvocation) -> i32 {
    match invocation {
        InternalInvocation::Launcher {
            control_fd,
            exec_status_fd,
            command,
        } => launcher(control_fd, exec_status_fd, command),
        InternalInvocation::Guardian {
            control_fd,
            process_group,
        } => guardian(control_fd, process_group),
    }
}

#[cfg(unix)]
fn launcher(control_fd: i32, exec_status_fd: i32, command: Vec<std::ffi::OsString>) -> i32 {
    use std::os::unix::process::CommandExt;

    let (program, arguments) = match command.split_first() {
        Some(parts) => parts,
        None => return 126,
    };
    // SAFETY: the validated inherited descriptor is marked close-on-exec before target launch.
    if unsafe { libc::fcntl(exec_status_fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        write_launcher_status(exec_status_fd, LAUNCHER_STATUS_ERROR, errno);
        // SAFETY: launcher setup failed, so it consumes both inherited descriptors.
        unsafe {
            libc::close(control_fd);
            libc::close(exec_status_fd);
        }
        return 126;
    }
    if !write_launcher_status(exec_status_fd, LAUNCHER_STATUS_READY, 0) {
        // SAFETY: readiness delivery failed, so it consumes both inherited descriptors.
        unsafe {
            libc::close(control_fd);
            libc::close(exec_status_fd);
        }
        return 126;
    }
    let mut release = 0_u8;
    // SAFETY: release is writable and both descriptors came from the trusted parent protocol.
    let read = unsafe { libc::read(control_fd, (&raw mut release).cast(), 1) };
    // SAFETY: the release descriptor is consumed regardless of protocol outcome.
    unsafe { libc::close(control_fd) };
    if read != 1 || release != 1 {
        write_launcher_status(exec_status_fd, LAUNCHER_STATUS_ERROR, libc::EPROTO);
        // SAFETY: the invalid release consumes the remaining status descriptor.
        unsafe { libc::close(exec_status_fd) };
        return 126;
    }
    let error = std::process::Command::new(program).args(arguments).exec();
    write_launcher_status(
        exec_status_fd,
        LAUNCHER_STATUS_ERROR,
        error.raw_os_error().unwrap_or(libc::EIO),
    );
    // SAFETY: failed target exec leaves the launcher owning the status descriptor.
    unsafe { libc::close(exec_status_fd) };
    if error.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    }
}

#[cfg(unix)]
fn write_launcher_status(descriptor: i32, kind: u8, errno: i32) -> bool {
    let mut record = [0_u8; LAUNCHER_STATUS_LENGTH];
    record[..4].copy_from_slice(LAUNCHER_STATUS_MAGIC);
    record[4] = LAUNCHER_STATUS_VERSION;
    record[5] = kind;
    record[8..].copy_from_slice(&errno.to_ne_bytes());
    let mut written = 0;
    while written < record.len() {
        // SAFETY: the remaining fixed record bytes are readable and descriptor is inherited.
        let result = unsafe {
            libc::write(
                descriptor,
                record[written..].as_ptr().cast(),
                record.len() - written,
            )
        };
        if result > 0 {
            written += usize::try_from(result).unwrap_or(0);
        } else if result < 0
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        } else {
            return false;
        }
    }
    true
}

#[cfg(unix)]
fn guardian(control_fd: i32, process_group: i32) -> i32 {
    let mut marker = 0_u8;
    // SAFETY: marker is writable and the descriptor is supplied by the trusted parent.
    let read = unsafe { libc::read(control_fd, (&raw mut marker).cast(), 1) };
    // SAFETY: the guardian consumes its inherited control descriptor after the read.
    unsafe { libc::close(control_fd) };
    if read == 1 && marker == 1 {
        return 0;
    }
    // SAFETY: validation requires a positive group, so negation targets that exact group.
    unsafe { libc::kill(-process_group, libc::SIGKILL) };
    0
}

#[cfg(not(unix))]
fn launcher(_control_fd: i32, _exec_status_fd: i32, _command: Vec<std::ffi::OsString>) -> i32 {
    126
}

#[cfg(not(unix))]
fn guardian(_control_fd: i32, _process_group: i32) -> i32 {
    126
}
