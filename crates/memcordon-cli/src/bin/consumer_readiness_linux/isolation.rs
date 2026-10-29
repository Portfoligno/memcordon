//! Current fixture operations for independently controlled isolation actors.
use super::{Result, Transcript};
use std::{
    ffi::OsString,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixListener, UnixStream},
    },
    time::Duration,
};

pub(super) fn run(
    transcript: &mut Transcript,
    mode: &str,
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<()> {
    match mode {
        "isolation-listener" => {
            use std::os::fd::AsRawFd;
            if arguments.next().is_some() {
                return Err("unexpected current listener operand".into());
            }
            super::wait_release()?;
            let tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            let endpoint = tcp.local_addr()?;
            let name = format!("memcordon-isolation-{}", transcript.challenge);
            let abstract_address = SocketAddr::from_abstract_name(name.as_bytes())?;
            let unix = UnixListener::bind_addr(&abstract_address)?;
            let mut positive = TcpStream::connect_timeout(&endpoint, Duration::from_secs(3))?;
            let (mut accepted, _) = tcp.accept()?;
            positive.write_all(transcript.challenge.as_bytes())?;
            let mut bytes = vec![0; transcript.challenge.len()];
            accepted.read_exact(&mut bytes)?;
            if bytes != transcript.challenge.as_bytes() {
                return Err("original listener TCP positive changed bytes".into());
            }
            let mut positive = UnixStream::connect_addr(&abstract_address)?;
            let (mut accepted, _) = unix.accept()?;
            positive.write_all(transcript.challenge.as_bytes())?;
            accepted.read_exact(&mut bytes)?;
            if bytes != transcript.challenge.as_bytes() {
                return Err("original listener Unix positive changed bytes".into());
            }
            transcript.record("isolation-listener-ready",serde_json::json!({"tcp":endpoint.to_string(),"abstract_name":name.as_bytes(),"tcp_descriptor":tcp.as_raw_fd(),"abstract_descriptor":unix.as_raw_fd(),"positive_bytes":bytes}))?;
            // A second original stdin gate keeps both original listener objects
            // alive throughout the other attempt's experiment.
            super::wait_release()?;
            transcript.record(
                "isolation-listener-retired",
                serde_json::json!({"tcp":endpoint.to_string(),"abstract_name":name.as_bytes(),"tcp_descriptor":tcp.as_raw_fd(),"abstract_descriptor":unix.as_raw_fd()}),
            )
        }
        "isolation-peer" => {
            let kind = arguments
                .next()
                .ok_or("current isolation peer kind absent")?
                .into_string()
                .map_err(|_| "peer kind not UTF8")?;
            let endpoint = arguments
                .next()
                .ok_or("original peer endpoint absent")?
                .into_string()
                .map_err(|_| "peer endpoint not UTF8")?;
            if arguments.next().is_some() {
                return Err("unexpected isolation peer operand".into());
            }
            super::wait_release()?;
            let private_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            let private_endpoint = private_listener.local_addr()?;
            let mut private_sender =
                TcpStream::connect_timeout(&private_endpoint, Duration::from_secs(3))?;
            let (mut private_receiver, _) = private_listener.accept()?;
            private_sender.write_all(transcript.challenge.as_bytes())?;
            let mut private_bytes = vec![0; transcript.challenge.len()];
            private_receiver.read_exact(&mut private_bytes)?;
            if private_bytes != transcript.challenge.as_bytes() {
                return Err("neighboring private TCP bytes changed".into());
            }
            transcript.record(
                "isolation-private-tcp-positive",
                serde_json::json!({"endpoint":private_endpoint.to_string(),"bytes":private_bytes}),
            )?;
            drop(private_sender);
            drop(private_receiver);
            drop(private_listener);
            let error = match kind.as_str() {
                "tcp" => TcpStream::connect_timeout(&endpoint.parse()?, Duration::from_secs(3))
                    .err()
                    .ok_or("cross-attempt TCP communication succeeded")?,
                "abstract" => {
                    UnixStream::connect_addr(&SocketAddr::from_abstract_name(endpoint.as_bytes())?)
                        .err()
                        .ok_or("cross-attempt abstract communication succeeded")?
                }
                "proc-fd" => {
                    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
                    std::fs::write(
                        "/work/private-handle-positive",
                        transcript.challenge.as_bytes(),
                    )?;
                    let private = std::fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                        .open("/work/private-handle-positive")?;
                    let metadata = private.metadata()?;
                    transcript.record("isolation-private-opath-positive",serde_json::json!({"device":metadata.dev(),"inode":metadata.ino(),"mode":metadata.mode(),"bytes":std::fs::read("/work/private-handle-positive")?}))?;
                    std::fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                        .open(&endpoint)
                        .err()
                        .ok_or("foreign attempt resource handle import succeeded")?
                }
                _ => return Err("unknown current isolation peer kind".into()),
            };
            let code = error
                .raw_os_error()
                .ok_or("cross-attempt connect native errno absent")?;
            if ![
                libc::EPERM,
                libc::ENOENT,
                libc::EACCES,
                libc::ECONNREFUSED,
                libc::ENETUNREACH,
                libc::EHOSTUNREACH,
            ]
            .contains(&code)
            {
                return Err(error.into());
            }
            let (mut sender, mut receiver) = UnixStream::pair()?;
            sender.write_all(transcript.challenge.as_bytes())?;
            let mut bytes = vec![0; transcript.challenge.len()];
            receiver.read_exact(&mut bytes)?;
            transcript.record("isolation-peer-denied",serde_json::json!({"kind":kind,"endpoint":endpoint,"native_errno":code,"neighbor_bytes":bytes}))
        }
        "isolation-proc" => {
            use std::os::unix::fs::MetadataExt;
            let host_pid = arguments
                .next()
                .ok_or("original host PID absent")?
                .into_string()
                .map_err(|_| "host PID not UTF8")?
                .parse::<u32>()?;
            let host_birth = arguments
                .next()
                .ok_or("original host birth absent")?
                .into_string()
                .map_err(|_| "host birth not UTF8")?
                .parse::<u64>()?;
            let path = arguments
                .next()
                .ok_or("original host proc-root marker absent")?;
            if host_pid == 0 || arguments.next().is_some() {
                return Err("host proc identity operands differ".into());
            }
            super::wait_release()?;
            let error = std::fs::read(format!("/proc/{host_pid}/stat"))
                .err()
                .ok_or("original host PID became visible in imported proc filesystem")?;
            let errno = error
                .raw_os_error()
                .ok_or("host proc denial native errno absent")?;
            if ![libc::ENOENT, libc::EACCES, libc::EPERM].contains(&errno) {
                return Err(error.into());
            }
            let namespace = std::fs::metadata("/proc/self/ns/pid")?;
            transcript.record("isolation-host-proc-absent",serde_json::json!({"host_pid":host_pid,"host_birth":host_birth,"native_errno":errno,"self_pid":std::process::id(),"pid_namespace":{"device":namespace.dev(),"inode":namespace.ino()}}))?;
            super::outside_file(transcript, "proc-root", &path, None)
        }
        "isolation-path" => {
            use std::os::unix::ffi::OsStrExt;
            let kind = arguments
                .next()
                .ok_or("isolation path kind absent")?
                .into_string()
                .map_err(|_| "path kind not UTF8")?;
            let source = arguments.next().ok_or("original host source path absent")?;
            let supplied = arguments.next().ok_or("original hostile path absent")?;
            if arguments.next().is_some()
                || !std::path::Path::new(&source).is_absolute()
                || !std::path::Path::new(&supplied).is_absolute()
            {
                return Err("isolation source/path operands differ".into());
            }
            super::wait_release()?;
            let mut probe = supplied;
            let mut native_errno = None;
            match kind.as_str() {
                "symlink" => {
                    let path = std::path::Path::new("/work/isolation-symbolic-alias");
                    std::os::unix::fs::symlink(&source, path)?;
                    if std::fs::read_link(path)?.as_os_str() != source {
                        return Err("actual symlink target changed".into());
                    }
                    probe = path.as_os_str().to_owned();
                }
                "dotdot" => {
                    probe = OsString::from(format!(
                        "/work/../../{}",
                        std::str::from_utf8(source.as_bytes())?.trim_start_matches('/')
                    ));
                }
                "proc-root" | "proc-cwd" | "proc-fd" => {}
                "hardlink" => {
                    std::fs::write(
                        "/work/isolation-private-hardlink-source",
                        transcript.challenge.as_bytes(),
                    )?;
                    std::fs::hard_link(
                        "/work/isolation-private-hardlink-source",
                        "/work/isolation-private-hardlink-destination",
                    )?;
                    let bytes = std::fs::read("/work/isolation-private-hardlink-destination")?;
                    if bytes != transcript.challenge.as_bytes() {
                        return Err("neighboring private hard link changed bytes".into());
                    }
                    transcript.record(
                        "isolation-private-hardlink-positive",
                        serde_json::json!({"bytes":bytes}),
                    )?;
                    let error = std::fs::hard_link(&source, "/work/isolation-hard-alias")
                        .err()
                        .ok_or("host hard link import succeeded")?;
                    native_errno = error.raw_os_error();
                    if ![
                        Some(libc::ENOENT),
                        Some(libc::EPERM),
                        Some(libc::EACCES),
                        Some(libc::EXDEV),
                    ]
                    .contains(&native_errno)
                    {
                        return Err(error.into());
                    }
                }
                "mount-alias" => {
                    std::fs::write("/work/isolation-mount-alias", b"private-mount-target")?;
                    let source_c = std::ffi::CString::new(source.as_bytes())?;
                    let target = std::ffi::CString::new("/work/isolation-mount-alias")?;
                    // SAFETY: both paths are live NUL-terminated strings; the
                    // fixed bind operation has no filesystem/data argument.
                    let result = unsafe {
                        libc::mount(
                            source_c.as_ptr(),
                            target.as_ptr(),
                            std::ptr::null(),
                            libc::MS_BIND,
                            std::ptr::null(),
                        )
                    };
                    if result == 0 {
                        return Err("host bind mount import succeeded".into());
                    }
                    native_errno = std::io::Error::last_os_error().raw_os_error();
                    if native_errno != Some(libc::EPERM) {
                        return Err(
                            "host mount alias did not reach native permission rejection".into()
                        );
                    }
                }
                _ => return Err("unknown isolation path operation".into()),
            }
            transcript.record("isolation-path-alias",serde_json::json!({"kind":kind,"source":source,"probe":probe,"native_import_errno":native_errno}))?;
            super::outside_file(transcript, &kind, &probe, None)
        }
        _ => Err("unknown current isolation fixture operation".into()),
    }
}
