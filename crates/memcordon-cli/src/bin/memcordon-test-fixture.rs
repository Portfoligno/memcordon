use std::ffi::{OsStr, OsString};
use std::fs;
#[cfg(windows)]
use std::io::Read;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use memcordon_core::{ByteSize, NativeArgument};

#[cfg(all(target_os = "linux", feature = "test-fixtures"))]
mod private_installed_loss_fixture;

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("memcordon-test-fixture: {}", message.as_ref());
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn assert_private_runtime(mut args: impl Iterator<Item = OsString>) {
    use std::os::fd::{FromRawFd, OwnedFd};
    let expected_uid: u32 = take_value(&mut args, "private runtime UID")
        .to_str()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| fail("invalid expected UID"));
    let expected_gid: u32 = take_value(&mut args, "private runtime GID")
        .to_str()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| fail("invalid expected GID"));
    if args.next().is_some() || expected_uid == 0 || expected_gid == 0 {
        fail("private runtime requires exactly one nonroot UID and GID");
    }
    // Inspect the entry table before opening /proc or any other fixture resource.
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes the supplied native structure.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        fail(io::Error::last_os_error().to_string());
    }
    // SAFETY: the successful native call initialized limit.
    let limit = unsafe { limit.assume_init() }.rlim_cur;
    if limit > 1_048_576 {
        fail("entry descriptor bound exceeds fixture capacity");
    }
    let mut entry_fds = Vec::new();
    for fd in 0..limit {
        let fd = i32::try_from(fd).unwrap_or_else(|_| fail("descriptor index overflow"));
        // SAFETY: F_GETFD only observes this fixture's descriptor table.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
            entry_fds.push(fd);
        } else if io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
            fail("cannot inspect entry descriptor");
        }
    }
    if entry_fds != [0, 1, 2] {
        fail(format!("unexpected entry descriptors: {entry_fds:?}"));
    }
    for fd in &entry_fds {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat observes an already enumerated descriptor.
        if unsafe { libc::fstat(*fd, metadata.as_mut_ptr()) } != 0 {
            fail(io::Error::last_os_error().to_string());
        }
        // SAFETY: successful fstat initialized metadata.
        if unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFIFO {
            fail("entry stdio is not a provider pipe");
        }
    }
    let status =
        fs::read_to_string("/proc/self/status").unwrap_or_else(|error| fail(error.to_string()));
    let values = |name: &str| -> Vec<String> {
        let line = status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap_or_else(|| fail(format!("missing native status field {name}")));
        line.split_whitespace().map(str::to_owned).collect()
    };
    let ids = |name: &str, expected: u32| {
        let actual: Vec<u32> = values(name)
            .iter()
            .map(|value| {
                value
                    .parse::<u32>()
                    .unwrap_or_else(|_| fail("malformed native identity"))
            })
            .collect();
        if actual != [expected; 4] {
            fail(format!("native {name} differs: {actual:?}"));
        }
        actual
    };
    let uid = ids("Uid:", expected_uid);
    let gid = ids("Gid:", expected_gid);
    let groups: Vec<u32> = values("Groups:")
        .iter()
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|_| fail("malformed supplementary group"))
        })
        .collect();
    if groups.contains(&0) {
        fail("target retained root supplementary group");
    }
    if values("NoNewPrivs:") != ["1"] {
        fail("target lacks no-new-privileges");
    }
    let mut capabilities = serde_json::Map::new();
    for name in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let tokens = values(name);
        if tokens.len() != 1 || u64::from_str_radix(&tokens[0], 16).ok() != Some(0) {
            fail(format!("target retained native capability set {name}"));
        }
        capabilities.insert(name.trim_end_matches(':').into(), tokens[0].clone().into());
    }
    let namespace =
        fs::read_link("/proc/self/ns/net").unwrap_or_else(|error| fail(error.to_string()));
    for (path, expected) in [
        ("/proc/sys/net/ipv4/ip_unprivileged_port_start", "0"),
        ("/proc/sys/net/ipv4/ip_local_port_range", "32768 60999"),
        ("/proc/sys/net/ipv4/ip_local_reserved_ports", ""),
        ("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1"),
    ] {
        let actual = fs::read_to_string(path).unwrap_or_else(|error| fail(error.to_string()));
        let tokens: Vec<_> = actual.split_whitespace().collect();
        if tokens != expected.split_whitespace().collect::<Vec<_>>() {
            fail(format!("private sysctl {path} differs: {actual:?}"));
        }
    }
    let ipv6 =
        fs::read_to_string("/proc/net/if_inet6").unwrap_or_else(|error| fail(error.to_string()));
    if !ipv6.trim().is_empty() {
        fail("private namespace retained IPv6 addresses");
    }
    let denied = |name: &str, result: libc::c_long| {
        if result >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
            fail(format!("native filter anchor {name} did not return EPERM"));
        }
    };
    for (name, family, kind, protocol) in [
        ("unix", libc::AF_UNIX, libc::SOCK_STREAM, 0),
        ("ipv6", libc::AF_INET6, libc::SOCK_STREAM, 0),
        ("udp", libc::AF_INET, libc::SOCK_DGRAM, 0),
        ("raw", libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP),
        ("netlink", libc::AF_NETLINK, libc::SOCK_RAW, 0),
        ("packet", libc::AF_PACKET, libc::SOCK_RAW, 0),
    ] {
        // SAFETY: native socket creation with scalar arguments; successful FDs are immediately owned.
        let result = unsafe { libc::socket(family, kind, protocol) };
        if result >= 0 {
            // SAFETY: socket returned a new unique descriptor.
            drop(unsafe { OwnedFd::from_raw_fd(result) });
            fail(format!("forbidden {name} socket was created"));
        }
        let expected_errno = if family == libc::AF_INET {
            libc::EPROTONOSUPPORT
        } else {
            libc::EAFNOSUPPORT
        };
        if io::Error::last_os_error().raw_os_error() != Some(expected_errno) {
            fail(format!(
                "native socket filter anchor {name} returned the wrong argument-class errno"
            ));
        }
    }
    let mut pair = [-1; 2];
    // SAFETY: socketpair receives storage for exactly two descriptors.
    let result =
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
    if result == 0 {
        for fd in pair {
            drop(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        fail("forbidden Unix socketpair was created");
    }
    denied("socketpair", result.into());
    // SAFETY: all pointers are valid native structures or null where the forbidden syscall is
    // expected to be rejected before dereference; invalid descriptors cannot affect live objects.
    unsafe {
        let message: libc::msghdr = std::mem::zeroed();
        denied(
            "recvmsg",
            libc::recvmsg(-1, &message as *const _ as *mut _, 0) as libc::c_long,
        );
        denied("sendmsg", libc::sendmsg(-1, &message, 0) as libc::c_long);
        denied("unshare", libc::unshare(libc::CLONE_NEWNET).into());
        denied("setns", libc::setns(-1, libc::CLONE_NEWNET).into());
        denied("ptrace", libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0));
        denied(
            "pidfd_getfd",
            libc::syscall(libc::SYS_pidfd_getfd, -1, 0, 0),
        );
        denied(
            "io_uring_setup",
            libc::syscall(libc::SYS_io_uring_setup, 1, std::ptr::null::<u8>()),
        );
        denied("setresuid", libc::setresuid(!0, !0, !0).into());
        denied("setresgid", libc::setresgid(!0, !0, !0).into());
        denied(
            "fcntl-async",
            libc::fcntl(0, libc::F_SETFL, libc::O_ASYNC).into(),
        );
        for (name, flags) in [
            ("clone-newnet", libc::CLONE_NEWNET | libc::SIGCHLD),
            ("clone-detached", libc::CLONE_DETACHED | libc::SIGCHLD),
        ] {
            let clone = libc::syscall(libc::SYS_clone, flags, 0_usize, 0_usize, 0_usize, 0_usize);
            if clone == 0 {
                // Unexpectedly permitted clone owns no fixture work or publication.
                libc::_exit(0);
            }
            if clone > 0 {
                let child = i32::try_from(clone).unwrap_or_else(|_| fail("native child PID range"));
                while libc::waitpid(child, std::ptr::null_mut(), 0) < 0 {
                    if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                        fail("unexpected permitted clone could not be reaped");
                    }
                }
                fail(format!(
                    "forbidden native clone flags {name} were permitted"
                ));
            }
            denied(name, clone);
        }
    }
    // Genuine TCP byte operations within the namespace; no external prebound socket is imported.
    use std::io::Read;
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .unwrap_or_else(|error| fail(format!("private TCP bind: {error}")));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| fail(error.to_string()));
    let mut client =
        std::net::TcpStream::connect(address).unwrap_or_else(|error| fail(error.to_string()));
    let (mut server, _) = listener
        .accept()
        .unwrap_or_else(|error| fail(error.to_string()));
    let expected = b"private";
    client
        .write_all(expected)
        .unwrap_or_else(|error| fail(error.to_string()));
    let mut bytes = vec![0; expected.len()];
    server
        .read_exact(&mut bytes)
        .unwrap_or_else(|error| fail(error.to_string()));
    if bytes != expected {
        fail("private TCP byte integrity differs");
    }
    println!(
        "{}",
        serde_json::json!({
            "format": "memcordon.private-native-fixture", "revision": 1,
            "uid": uid, "gid": gid, "groups": groups, "no_new_privileges": true,
            "capabilities": capabilities, "entry_fds": entry_fds,
            "network_namespace": namespace.to_str().unwrap_or_else(|| fail("native namespace is not UTF-8")),
            "ipv6_addresses": 0, "tcp_port": address.port(), "tcp_bytes": "private",
            "denied": ["unix", "ipv6", "udp", "raw", "netlink", "packet", "socketpair", "recvmsg", "sendmsg", "unshare", "setns", "ptrace", "pidfd_getfd", "io_uring_setup", "setresuid", "setresgid", "fcntl-async", "clone-newnet", "clone-detached"]
        })
    );
}

fn take_value(args: &mut impl Iterator<Item = OsString>, option: &str) -> OsString {
    args.next()
        .unwrap_or_else(|| fail(format!("{option} requires a value")))
}

#[cfg(target_os = "macos")]
fn open_descriptors() -> Vec<(i32, i32)> {
    // SAFETY: these calls inspect only this disposable fixture's descriptor table.
    let limit = unsafe { libc::getdtablesize() };
    if limit < 0 {
        fail(io::Error::last_os_error().to_string());
    }
    let mut descriptors = Vec::new();
    for fd in 0..limit {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags >= 0 {
            descriptors.push((fd, flags));
        } else if io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
            fail(format!(
                "inspect descriptor {fd}: {}",
                io::Error::last_os_error()
            ));
        }
    }
    descriptors
}

fn parse_duration(value: &OsStr) -> Duration {
    let value = value
        .to_str()
        .unwrap_or_else(|| fail("duration must be valid UTF-8"));
    memcordon::parse_duration(value).unwrap_or_else(|error| fail(error))
}

fn assert_native_containment(mut args: impl Iterator<Item = OsString>) {
    let mut memory = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--limit") => {
                memory = Some(
                    take_value(&mut args, "--limit")
                        .to_str()
                        .and_then(|text| ByteSize::from_str(text).ok())
                        .unwrap_or_else(|| fail("invalid containment memory size"))
                        .bytes(),
                )
            }
            _ => fail("unexpected containment argument"),
        }
    }
    memcordon_platform::test_support::assert_native_containment(
        memory.unwrap_or_else(|| fail("assert-native-containment requires --limit")),
    )
    .unwrap_or_else(|error| fail(error.to_string()));
}

fn write_pid(path: Option<&Path>) {
    if let Some(path) = path {
        #[cfg(target_os = "linux")]
        let identity = {
            // /proc/self selects this task even when the mounted procfs and
            // getpid use different PID namespaces. Never look up a namespace
            // PID as though it were a host PID.
            let stat = fs::read_to_string("/proc/self/stat")
                .unwrap_or_else(|error| fail(error.to_string()));
            let birth = stat
                .rsplit_once(')')
                .and_then(|(_, fields)| fields.split_whitespace().nth(19))
                .and_then(|field| field.parse::<u128>().ok())
                .unwrap_or_else(|| fail("own native birth absent"));
            memcordon_platform::test_support::ProcessIdentity {
                pid: std::process::id(),
                birth,
            }
        };
        #[cfg(not(target_os = "linux"))]
        let identity = memcordon_platform::test_support::ProcessIdentity::current()
            .unwrap_or_else(|error| fail(format!("cannot observe process identity: {error}")));
        identity
            .publish_to(path)
            .unwrap_or_else(|error| fail(format!("cannot write PID file: {error}")));
    }
}

fn record_argv(mut args: impl Iterator<Item = OsString>) {
    let output = PathBuf::from(take_value(&mut args, "record-argv output path"));
    let arguments: Vec<NativeArgument> = args
        .map(|argument| NativeArgument::from_os(&argument))
        .collect();
    let mut bytes = serde_json::to_vec_pretty(&arguments)
        .unwrap_or_else(|error| fail(format!("cannot serialize argv: {error}")));
    bytes.push(b'\n');
    fs::write(output, bytes).unwrap_or_else(|error| fail(format!("cannot write argv: {error}")));
}

fn assert_no_memcordon_environment(args: impl Iterator<Item = OsString>) {
    if args.count() != 0 {
        fail("assert-no-memcordon-environment accepts no arguments");
    }
    if let Some((name, _)) = std::env::vars_os().find(|(name, _)| {
        name.to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("MEMCORDON_")
    }) {
        fail(format!(
            "target inherited unexpected MemCordon environment key {}",
            name.to_string_lossy()
        ));
    }
}

fn tcp_loopback(mut args: impl Iterator<Item = OsString>) {
    use std::io::{Read, Write};
    let marker = PathBuf::from(take_value(&mut args, "TCP completion marker"));
    if args.next().is_some() {
        fail("tcp-loopback accepts one marker path");
    }
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .unwrap_or_else(|error| fail(error.to_string()));
    let address = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        stream.write_all(&byte).unwrap();
    });
    let mut stream =
        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"x");
    worker.join().unwrap();
    fs::write(marker, b"tcp-echo-complete\n").unwrap();
}

fn prebound_listener(args: impl Iterator<Item = OsString>, reject_policy: bool) -> i32 {
    use std::io::{Read, Write};
    if args.count() != 0 {
        fail("prebound listener anchor accepts no arguments");
    }
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .unwrap_or_else(|error| fail(error.to_string()));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| fail(error.to_string()));
    assert_ne!(address.port(), 0);
    if reject_policy {
        let requested_port = if address.port() == u16::MAX {
            1
        } else {
            address.port() + 1
        };
        assert_ne!(requested_port, address.port());
        // The listener is already owned. A deliberate consumer policy mismatch
        // returns before any readiness or HTTP dispatch can happen.
        println!(
            "{}",
            serde_json::json!({"format":"memcordon.prebound-listener", "revision":1,
            "state":"listener-policy-failure", "bound_port":address.port(), "requested_port":requested_port,
            "readiness_emitted":false, "dispatch_started":false})
        );
        return 42;
    }
    let competing_bind = std::net::TcpListener::bind(address)
        .expect_err("same-attempt competitor acquired the held port");
    assert_eq!(competing_bind.kind(), io::ErrorKind::AddrInUse);
    println!(
        "{}",
        serde_json::json!({"format":"memcordon.prebound-listener", "revision":1,
        "state":"ready", "bound_port":address.port(), "competitor":"address-in-use"})
    );
    io::stdout()
        .flush()
        .unwrap_or_else(|error| fail(error.to_string()));
    // The exact listener remains owned through readiness and is moved into the
    // server. It is never closed and replaced by a second bind.
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 4096, "HTTP request exceeds fixture bound");
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
        let body = b"owned";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
    });
    let mut client =
        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = Vec::new();
    client.take(4096).read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let body = response
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| &response[offset + b"\r\n\r\n".len()..])
        .expect("HTTP header terminator absent");
    assert_eq!(body, b"owned");
    server.join().unwrap();
    println!(
        "{}",
        serde_json::json!({"format":"memcordon.prebound-listener", "revision":1,
        "state":"completed", "bound_port":address.port(), "http_body":"owned", "server_joined":true})
    );
    0
}

fn tcp_client(mut args: impl Iterator<Item = OsString>) {
    use std::io::{Read, Write};
    let port: u16 = take_value(&mut args, "TCP peer port")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let marker = PathBuf::from(take_value(&mut args, "TCP completion marker"));
    if args.next().is_some() {
        fail("tcp-client accepts port and marker");
    }
    let address = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut stream =
        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"x");
    fs::write(marker, b"tcp-echo-complete\n").unwrap();
}

fn gate_marker(mut args: impl Iterator<Item = OsString>) {
    let path = PathBuf::from(take_value(&mut args, "gate-marker path"));
    if args.next().is_some() {
        fail("gate-marker accepts exactly one path");
    }
    fs::write(path, b"target-executed\n")
        .unwrap_or_else(|error| fail(format!("cannot write gate marker: {error}")));
}

fn gate_wait(mut args: impl Iterator<Item = OsString>) {
    let ready = PathBuf::from(take_value(&mut args, "ready marker"));
    let finish = PathBuf::from(take_value(&mut args, "finish marker"));
    if args.next().is_some() {
        fail("gate-wait accepts ready and finish paths");
    }
    fs::write(ready, b"authorized\n").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    while !finish.exists() {
        if std::time::Instant::now() >= deadline {
            fail("gate-wait deadline expired");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn gate_failure(mut args: impl Iterator<Item = OsString>) {
    let mut phase = None;
    let mut marker = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--phase") => phase = Some(take_value(&mut args, "--phase")),
            Some("--marker") => marker = Some(PathBuf::from(take_value(&mut args, "--marker"))),
            _ => fail("unexpected gate-failure argument"),
        }
    }
    if phase.is_none() {
        fail("gate-failure requires --phase");
    }
    let marker = marker.unwrap_or_else(|| fail("gate-failure requires --marker"));
    fs::write(marker, b"target-executed\n")
        .unwrap_or_else(|error| fail(format!("cannot write gate-failure marker: {error}")));
}

fn touch_allocation(bytes: u64) -> Vec<u8> {
    let length = usize::try_from(bytes).unwrap_or_else(|_| fail("allocation does not fit usize"));
    let mut memory = vec![0_u8; length];
    for byte in memory.iter_mut().step_by(4096) {
        *byte = 1;
    }
    memory
}

fn parse_pid_duration_and_completion(
    mut args: impl Iterator<Item = OsString>,
) -> (Option<PathBuf>, Option<Duration>, Option<PathBuf>) {
    let mut pid_file = None;
    let mut duration = None;
    let mut completion_marker = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--pid-file") => {
                pid_file = Some(PathBuf::from(take_value(&mut args, "--pid-file")))
            }
            Some("--duration") | Some("--hold") => {
                duration = Some(parse_duration(&take_value(&mut args, "--duration")))
            }
            Some("--completion-marker") => {
                completion_marker =
                    Some(PathBuf::from(take_value(&mut args, "--completion-marker")))
            }
            _ => fail("unexpected fixture argument"),
        }
    }
    (pid_file, duration, completion_marker)
}

fn hold(args: impl Iterator<Item = OsString>) {
    let (pid_file, duration, completion_marker) = parse_pid_duration_and_completion(args);
    write_pid(pid_file.as_deref());
    thread::sleep(duration.unwrap_or(Duration::from_secs(30)));
    if let Some(path) = completion_marker {
        fs::write(path, b"completed\n")
            .unwrap_or_else(|error| fail(format!("cannot write completion marker: {error}")));
    }
}

fn exit_fixture(mut args: impl Iterator<Item = OsString>) -> i32 {
    let mut code = None;
    let mut pid_file = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--code") => {
                let value = take_value(&mut args, "--code");
                let parsed = value
                    .to_str()
                    .and_then(|text| text.parse::<u8>().ok())
                    .unwrap_or_else(|| fail("exit code must be in 0..=255"));
                code = Some(i32::from(parsed));
            }
            Some("--pid-file") => {
                pid_file = Some(PathBuf::from(take_value(&mut args, "--pid-file")))
            }
            _ => fail("unexpected exit argument"),
        }
    }
    write_pid(pid_file.as_deref());
    code.unwrap_or_else(|| fail("exit requires --code"))
}

fn allocate(mut args: impl Iterator<Item = OsString>, release_before_hold: bool) {
    let mut bytes = None;
    let mut duration = None;
    let mut pid_file = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--bytes") => {
                let value = take_value(&mut args, "--bytes");
                bytes = Some(
                    value
                        .to_str()
                        .and_then(|text| ByteSize::from_str(text).ok())
                        .unwrap_or_else(|| fail("invalid byte size"))
                        .bytes(),
                );
            }
            Some("--hold") => duration = Some(parse_duration(&take_value(&mut args, "--hold"))),
            Some("--pid-file") => {
                pid_file = Some(PathBuf::from(take_value(&mut args, "--pid-file")))
            }
            _ => fail("unexpected allocation argument"),
        }
    }
    write_pid(pid_file.as_deref());
    let memory = touch_allocation(bytes.unwrap_or_else(|| fail("allocation requires --bytes")));
    if release_before_hold {
        drop(memory);
        thread::yield_now();
        thread::sleep(duration.unwrap_or(Duration::from_secs(30)));
    } else {
        thread::sleep(duration.unwrap_or(Duration::from_secs(30)));
        drop(memory);
    }
}

#[allow(clippy::zombie_processes)]
fn spawn_background(mut args: impl Iterator<Item = OsString>) -> i32 {
    let mut duration = None;
    let mut pid_file = None;
    let mut completion_marker = None;
    let mut exit_code = None;
    let mut exit_gate = None;
    let mut child_group_gate = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--child-duration") => duration = Some(take_value(&mut args, "--child-duration")),
            Some("--pid-file") => {
                pid_file = Some(PathBuf::from(take_value(&mut args, "--pid-file")))
            }
            Some("--exit-gate") => {
                exit_gate = Some(PathBuf::from(take_value(&mut args, "--exit-gate")))
            }
            Some("--child-group-gate") => {
                child_group_gate = Some(PathBuf::from(take_value(&mut args, "--child-group-gate")))
            }
            Some("--completion-marker") => {
                completion_marker =
                    Some(PathBuf::from(take_value(&mut args, "--completion-marker")))
            }
            Some("--exit-code") => {
                let value = take_value(&mut args, "--exit-code");
                exit_code = Some(
                    value
                        .to_str()
                        .and_then(|value| value.parse::<u8>().ok())
                        .unwrap_or_else(|| fail("exit code must be in 0..=255")),
                )
            }
            _ => fail("unexpected spawn-background argument"),
        }
    }
    let executable = std::env::current_exe().unwrap_or_else(|error| fail(error.to_string()));
    let mut command = Command::new(executable);
    if let Some(gate) = child_group_gate {
        command.arg("macos-gated-group-change").arg(gate);
    } else {
        command
            .arg("hold")
            .arg("--duration")
            .arg(duration.unwrap_or_else(|| OsString::from("30s")));
    }
    command.stdout(Stdio::null()).stderr(Stdio::null());
    if let Some(path) = completion_marker {
        command.arg("--completion-marker").arg(path);
    }
    // Deliberately do not wait: this fixture tests whether MemCordon owns and cleans a
    // descendant after its direct child exits. The outer test session remains the safety net.
    let child = command
        .spawn()
        .unwrap_or_else(|error| fail(format!("background child failed to spawn: {error}")));
    let path = pid_file.unwrap_or_else(|| fail("spawn-background requires --pid-file"));
    let identity = memcordon_platform::test_support::ProcessIdentity::for_pid(child.id())
        .unwrap_or_else(|error| fail(format!("cannot observe child identity: {error}")));
    identity
        .publish_to(&path)
        .unwrap_or_else(|error| fail(format!("cannot write child PID file: {error}")));
    if let Some(gate) = exit_gate {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !gate.exists() {
            if Instant::now() >= deadline {
                fail("background root exit gate timed out");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    i32::from(exit_code.unwrap_or(0))
}

#[allow(clippy::zombie_processes)]
fn fork_continually(mut args: impl Iterator<Item = OsString>) {
    let mut pid_file = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--pid-file") => {
                pid_file = Some(PathBuf::from(take_value(&mut args, "--pid-file")))
            }
            _ => fail("unexpected fork-continually argument"),
        }
    }
    let path = pid_file.unwrap_or_else(|| fail("fork-continually requires --pid-file"));
    let executable = std::env::current_exe().unwrap_or_else(|error| fail(error.to_string()));
    loop {
        let child = Command::new(&executable)
            .args(["hold", "--duration", "30s"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| fail(format!("continual child failed to spawn: {error}")));
        let identity = memcordon_platform::test_support::ProcessIdentity::for_pid(child.id())
            .unwrap_or_else(|error| fail(format!("cannot observe child identity: {error}")));
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap_or_else(|error| fail(format!("cannot append child identity: {error}")));
        writeln!(file, "{} {}", identity.pid, identity.birth)
            .unwrap_or_else(|error| fail(format!("cannot record child identity: {error}")));
        thread::sleep(Duration::from_millis(5));
    }
}

fn spawn_tree(mut args: impl Iterator<Item = OsString>) {
    let mut depth = None;
    let mut breadth = None;
    let mut leaf_mode = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--depth") => {
                depth = take_value(&mut args, "--depth")
                    .to_str()
                    .and_then(|v| v.parse().ok())
            }
            Some("--breadth") => {
                breadth = take_value(&mut args, "--breadth")
                    .to_str()
                    .and_then(|v| v.parse().ok())
            }
            Some("--leaf-mode") => {
                leaf_mode = take_value(&mut args, "--leaf-mode")
                    .to_str()
                    .map(str::to_owned)
            }
            _ => fail("unexpected spawn-tree argument"),
        }
    }
    let depth: u32 = depth.unwrap_or_else(|| fail("spawn-tree requires --depth"));
    let breadth: u32 = breadth.unwrap_or_else(|| fail("spawn-tree requires --breadth"));
    let mode = leaf_mode.unwrap_or_else(|| fail("spawn-tree requires --leaf-mode"));
    if mode != "hold" && mode != "allocate" {
        fail("leaf mode must be hold or allocate");
    }
    let executable = std::env::current_exe().unwrap_or_else(|error| fail(error.to_string()));
    let mut children: Vec<Child> = Vec::new();
    for _ in 0..breadth {
        let mut command = Command::new(&executable);
        if depth == 0 {
            if mode == "allocate" {
                command.args(["allocate", "--bytes", "16MiB", "--hold", "30s"]);
            } else {
                command.args(["hold", "--duration", "30s"]);
            }
        } else {
            command
                .arg("spawn-tree")
                .arg("--depth")
                .arg((depth - 1).to_string())
                .arg("--breadth")
                .arg(breadth.to_string())
                .arg("--leaf-mode")
                .arg(&mode);
        }
        children.push(
            command
                .spawn()
                .unwrap_or_else(|error| fail(error.to_string())),
        );
    }
    thread::sleep(Duration::from_secs(30));
    for mut child in children {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(windows)]
const WINDOWS_CAUSAL_CONCURRENT_CHILDREN: usize = 256;

#[cfg(windows)]
fn windows_inventory_leaf(mut args: impl Iterator<Item = OsString>) {
    let ordinal = take_value(&mut args, "windows-inventory-leaf ordinal")
        .to_str()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value < WINDOWS_CAUSAL_CONCURRENT_CHILDREN)
        .unwrap_or_else(|| fail("invalid inventory leaf ordinal"));
    let lifetime = take_value(&mut args, "windows-inventory-leaf lifetime")
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=240_000).contains(value))
        .unwrap_or_else(|| fail("invalid inventory leaf lifetime"));
    if args.next().is_some() {
        fail("windows-inventory-leaf accepts exactly two arguments");
    }
    let identity = memcordon_platform::test_support::ProcessIdentity::current()
        .unwrap_or_else(|error| fail(format!("cannot observe inventory leaf identity: {error}")));
    println!(
        "MEMCORDON-INVENTORY-READY:{}",
        serde_json::json!({"kind":"inventory-leaf-ready", "ordinal":ordinal, "pid":identity.pid, "birth":identity.birth})
    );
    io::stdout()
        .flush()
        .unwrap_or_else(|error| fail(format!("cannot publish leaf readiness: {error}")));
    thread::sleep(Duration::from_millis(lifetime));
    fail("inventory leaf self-expired before provider cleanup");
}

#[cfg(windows)]
fn windows_execution_leaf(mut args: impl Iterator<Item = OsString>) {
    let ordinal = take_value(&mut args, "windows-execution-leaf ordinal")
        .to_str()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value < 4096)
        .unwrap_or_else(|| fail("invalid execution leaf ordinal"));
    let hold_millis = take_value(&mut args, "windows-execution-leaf hold")
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value <= 240_000)
        .unwrap_or_else(|| fail("invalid execution leaf hold"));
    let gate_directory = args.next().map(PathBuf::from);
    if args.next().is_some() {
        fail("windows-execution-leaf accepts at most three arguments");
    }
    let identity = memcordon_platform::test_support::ProcessIdentity::current()
        .unwrap_or_else(|error| fail(format!("cannot observe execution leaf identity: {error}")));
    println!(
        "MEMCORDON-INVENTORY-READY:{}",
        serde_json::json!({"kind":"inventory-leaf-ready", "ordinal":ordinal, "pid":identity.pid, "birth":identity.birth})
    );
    io::stdout()
        .flush()
        .unwrap_or_else(|error| fail(format!("cannot publish execution leaf readiness: {error}")));
    if let Some(gate_directory) = gate_directory {
        let ready = serde_json::to_vec(&serde_json::json!({
            "ordinal": ordinal,
            "pid": identity.pid,
            "birth": identity.birth,
        }))
        .unwrap_or_else(|error| fail(format!("cannot encode leaf barrier: {error}")));
        fs::write(gate_directory.join(format!("ready-{ordinal}")), ready)
            .unwrap_or_else(|error| fail(format!("cannot publish leaf barrier: {error}")));
        let deadline = Instant::now() + Duration::from_secs(240);
        while !gate_directory.join("release").is_file() {
            if Instant::now() >= deadline {
                fail("execution leaf release barrier expired");
            }
            thread::sleep(Duration::from_millis(10));
        }
    } else {
        thread::sleep(Duration::from_millis(hold_millis));
    }
}

#[cfg(windows)]
fn windows_execution_family(mode: &str, args: impl Iterator<Item = OsString>) {
    let mut args = args;
    let external_gate = if mode == "windows-concurrent-257" {
        Some(PathBuf::from(take_value(
            &mut args,
            "external concurrent barrier",
        )))
    } else {
        None
    };
    if args.next().is_some() {
        fail("windows execution family received unexpected arguments");
    }
    let (waves, width, barrier_millis) = match mode {
        "windows-concurrent-257" => (1, 256, Some(0)),
        "windows-sequential-churn-4096" => (128, 32, Some(200)),
        "windows-short-lived-bursts" => (32, 32, None),
        _ => fail("unknown Windows execution family"),
    };
    let expiry = Instant::now()
        + if mode == "windows-sequential-churn-4096" {
            Duration::from_secs(480)
        } else {
            Duration::from_secs(240)
        };
    let identity = memcordon_platform::test_support::ProcessIdentity::current()
        .unwrap_or_else(|error| fail(format!("cannot observe execution root identity: {error}")));
    println!(
        "MEMCORDON-INVENTORY-READY:{}",
        serde_json::json!({"kind":"inventory-root-ready", "ordinal":null, "pid":identity.pid, "birth":identity.birth})
    );
    io::stdout()
        .flush()
        .unwrap_or_else(|error| fail(format!("cannot publish execution root readiness: {error}")));
    let executable = std::env::current_exe()
        .unwrap_or_else(|error| fail(format!("cannot resolve execution fixture image: {error}")));
    for wave in 0..waves {
        if Instant::now() >= expiry {
            fail("execution fixture expiry elapsed before spawning wave");
        }
        let owned_gate_directory = barrier_millis.filter(|_| external_gate.is_none()).map(|_| {
            tempfile::Builder::new()
                .prefix("windows-execution-wave-")
                .tempdir()
                .unwrap_or_else(|error| fail(format!("cannot create execution barrier: {error}")))
        });
        let gate_directory = external_gate
            .as_deref()
            .or_else(|| owned_gate_directory.as_ref().map(|gate| gate.path()));
        let mut children = Vec::with_capacity(width);
        for offset in 0..width {
            let ordinal = wave * width + offset;
            let mut command = Command::new(&executable);
            command
                .arg("windows-execution-leaf")
                .arg(ordinal.to_string())
                .arg("0");
            if let Some(gate_directory) = gate_directory {
                command.arg(gate_directory);
            }
            children.push(
                command
                    .spawn()
                    .unwrap_or_else(|error| fail(format!("cannot create execution leaf: {error}"))),
            );
        }
        if let Some(gate_directory) = gate_directory {
            let deadline = Instant::now() + Duration::from_secs(240);
            for offset in 0..width {
                let ordinal = wave * width + offset;
                while !gate_directory.join(format!("ready-{ordinal}")).is_file() {
                    if Instant::now() >= deadline {
                        fail("execution wave did not reach the complete ready barrier");
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
            if external_gate.is_some() {
                fs::write(gate_directory.join("family-ready"), b"ready\n").unwrap_or_else(
                    |error| fail(format!("cannot publish complete family barrier: {error}")),
                );
                while !gate_directory.join("release").is_file() {
                    if Instant::now() >= deadline {
                        fail("independent concurrent release barrier expired");
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            } else {
                thread::sleep(Duration::from_millis(
                    barrier_millis.expect("barrier exists"),
                ));
                fs::write(gate_directory.join("release"), b"release\n").unwrap_or_else(|error| {
                    fail(format!("cannot release execution wave: {error}"))
                });
            }
        }
        for mut child in children {
            if Instant::now() >= expiry {
                fail("execution fixture expiry elapsed before reaping wave");
            }
            let status = child
                .wait()
                .unwrap_or_else(|error| fail(format!("cannot reap execution leaf: {error}")));
            if !status.success() {
                fail("execution leaf failed");
            }
        }
    }
}

#[cfg(windows)]
fn windows_deny_process_query() {
    use std::ptr;
    use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetKernelObjectSecurity,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let descriptor_text: Vec<u16> = "D:P(D;;0x1000;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: SDDL is NUL-terminated and Windows owns the returned LocalAlloc block.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        fail(format!(
            "cannot prepare query-denial DACL: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: The pseudo-handle identifies only this fixture child, and the
    // descriptor remains valid until SetKernelObjectSecurity returns.
    let applied = unsafe {
        SetKernelObjectSecurity(
            GetCurrentProcess(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    // SAFETY: the descriptor was allocated by the SDDL conversion API.
    unsafe { LocalFree(descriptor as HLOCAL) };
    if applied == 0 {
        fail(format!(
            "cannot apply query-denial DACL: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: A fresh open is the behavior the provider's observer will use.
    let reopened = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, std::process::id()) };
    if !reopened.is_null() {
        use windows_sys::Win32::Foundation::CloseHandle;
        // SAFETY: OpenProcess returned a real owned process handle.
        unsafe { CloseHandle(reopened) };
        fail("query denial was bypassed in the fixture's effective context");
    }
    if io::Error::last_os_error().raw_os_error() != Some(5) {
        fail("fresh process query failed for a reason other than access denied");
    }
}

#[cfg(windows)]
fn windows_identity_denied_leaf(mut args: impl Iterator<Item = OsString>) {
    let gate_directory = PathBuf::from(take_value(&mut args, "windows-identity-denied-leaf gate"));
    if args.next().is_some() {
        fail("windows-identity-denied-leaf accepts exactly one argument");
    }
    let identity = memcordon_platform::test_support::ProcessIdentity::current()
        .unwrap_or_else(|error| fail(format!("cannot observe denial leaf identity: {error}")));
    println!(
        "MEMCORDON-INVENTORY-READY:{}",
        serde_json::json!({"kind":"inventory-leaf-ready", "ordinal":0, "pid":identity.pid, "birth":identity.birth})
    );
    io::stdout()
        .flush()
        .unwrap_or_else(|error| fail(format!("cannot publish denial leaf readiness: {error}")));
    fs::write(gate_directory.join("ready"), b"ready\n")
        .unwrap_or_else(|error| fail(format!("cannot publish denial barrier: {error}")));
    let deadline = Instant::now() + Duration::from_secs(240);
    while !gate_directory.join("deny").is_file() {
        if Instant::now() >= deadline {
            fail("query-denial barrier expired");
        }
        thread::sleep(Duration::from_millis(10));
    }
    windows_deny_process_query();
    println!(
        "MEMCORDON-INVENTORY-DENIED:{}",
        serde_json::json!({"pid":identity.pid,"birth":identity.birth})
    );
    io::stdout()
        .flush()
        .unwrap_or_else(|error| fail(format!("cannot publish denied state: {error}")));
    fs::write(gate_directory.join("denied"), b"denied\n")
        .unwrap_or_else(|error| fail(format!("cannot publish denied barrier: {error}")));
    while !gate_directory.join("release").is_file() {
        if Instant::now() >= deadline {
            fail("denied child expired before provider cleanup");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(windows)]
fn windows_identity_access_denied(args: impl Iterator<Item = OsString>) {
    if args.count() != 0 {
        fail("windows-identity-access-denied accepts no arguments");
    }
    let identity = memcordon_platform::test_support::ProcessIdentity::current()
        .unwrap_or_else(|error| fail(format!("cannot observe denial root identity: {error}")));
    println!(
        "MEMCORDON-INVENTORY-READY:{}",
        serde_json::json!({"kind":"inventory-root-ready", "ordinal":null, "pid":identity.pid, "birth":identity.birth})
    );
    io::stdout()
        .flush()
        .unwrap_or_else(|error| fail(format!("cannot publish denial root readiness: {error}")));
    let gate = tempfile::Builder::new()
        .prefix("windows-query-denial-")
        .tempdir()
        .unwrap_or_else(|error| fail(format!("cannot create denial barrier: {error}")));
    let executable = std::env::current_exe()
        .unwrap_or_else(|error| fail(format!("cannot resolve denial fixture image: {error}")));
    let mut child = Command::new(executable)
        .arg("windows-identity-denied-leaf")
        .arg(gate.path())
        .spawn()
        .unwrap_or_else(|error| fail(format!("cannot create denial leaf: {error}")));
    let deadline = Instant::now() + Duration::from_secs(240);
    while !gate.path().join("ready").is_file() {
        if Instant::now() >= deadline {
            fail("denial leaf did not reach the ready barrier");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let retained = memcordon_platform::test_support::ProcessIdentity::for_pid(child.id())
        .unwrap_or_else(|error| fail(format!("cannot retain denial leaf identity: {error}")));
    println!(
        "MEMCORDON-INVENTORY-RETAINED:{}",
        serde_json::json!({"pid":retained.pid,"birth":retained.birth})
    );
    io::stdout()
        .flush()
        .unwrap_or_else(|error| fail(format!("cannot publish retained identity: {error}")));
    thread::sleep(Duration::from_millis(500));
    fs::write(gate.path().join("deny"), b"deny\n")
        .unwrap_or_else(|error| fail(format!("cannot trigger denial: {error}")));
    while !gate.path().join("denied").is_file() {
        if Instant::now() >= deadline {
            fail("denial leaf did not prove query denial");
        }
        if child
            .try_wait()
            .unwrap_or_else(|error| fail(error.to_string()))
            .is_some()
        {
            fail("denial leaf exited before native observer failure");
        }
        thread::sleep(Duration::from_millis(10));
    }
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    fail("denial fixture expired before native provider cleanup");
}

#[cfg(windows)]
fn windows_replay_ack_loss(args: impl Iterator<Item = OsString>) {
    if args.count() != 0 {
        fail("windows-replay-ack-loss accepts no arguments");
    }
    let identity = memcordon_platform::test_support::ProcessIdentity::current()
        .unwrap_or_else(|error| fail(format!("cannot observe replay fixture identity: {error}")));
    println!(
        "MEMCORDON-INVENTORY-READY:{}",
        serde_json::json!({"kind":"inventory-root-ready", "ordinal":null, "pid":identity.pid, "birth":identity.birth})
    );
    io::stdout()
        .flush()
        .unwrap_or_else(|error| fail(format!("cannot publish replay fixture identity: {error}")));
}

#[cfg(windows)]
fn windows_prior_boot_hold(args: impl Iterator<Item = OsString>) {
    if args.count() != 0 {
        fail("windows-prior-boot-hold accepts no arguments");
    }
    let identity = memcordon_platform::test_support::ProcessIdentity::current()
        .unwrap_or_else(|error| fail(format!("cannot observe reboot fixture identity: {error}")));
    let birth = u64::try_from(identity.birth)
        .unwrap_or_else(|_| fail("reboot fixture creation time exceeds native FILETIME width"));
    println!(
        "MEMCORDON-PRIOR-BOOT-READY:{}",
        serde_json::json!({"schema_version":1,"pid":identity.pid,"birth":birth})
    );
    io::stdout()
        .flush()
        .unwrap_or_else(|error| fail(format!("cannot publish reboot readiness: {error}")));
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut release = [0_u8; 1];
        let result = io::stdin().read_exact(&mut release).map(|()| release[0]);
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(Duration::from_secs(900)) {
        Ok(Ok(b'R')) => {}
        Ok(Ok(_)) => fail("reboot fixture received an invalid release byte"),
        Ok(Err(error)) => fail(format!("reboot fixture lost its held stdin: {error}")),
        Err(_) => fail("reboot fixture expired without reset or release"),
    }
}

#[cfg(windows)]
fn windows_guardian_loss_hold(args: impl Iterator<Item = OsString>) {
    if args.count() != 0 {
        fail("windows-guardian-loss-hold accepts no arguments");
    }
    let identity =
        memcordon_platform::test_support::ProcessIdentity::current().unwrap_or_else(|error| {
            fail(format!(
                "cannot observe guardian-loss fixture identity: {error}"
            ))
        });
    println!(
        "MEMCORDON-GUARDIAN-LOSS-READY:{}",
        serde_json::json!({"schema_version":1,"pid":identity.pid,"birth":identity.birth})
    );
    io::stdout()
        .flush()
        .unwrap_or_else(|error| fail(format!("cannot publish guardian-loss readiness: {error}")));
    // This finite emergency expiry is independent of provider-owned retirement.
    thread::sleep(Duration::from_secs(240));
    fail("guardian-loss fixture self-expired before provider cleanup");
}

#[cfg(windows)]
fn windows_inventory_capacity(args: impl Iterator<Item = OsString>) {
    if args.count() != 0 {
        fail("windows-inventory-capacity accepts no arguments");
    }
    let count = WINDOWS_CAUSAL_CONCURRENT_CHILDREN;
    let _family_bound = count
        .checked_add(1)
        .unwrap_or_else(|| fail("inventory fixture family bound overflow"));
    let identity = memcordon_platform::test_support::ProcessIdentity::current()
        .unwrap_or_else(|error| fail(format!("cannot observe inventory root identity: {error}")));
    println!(
        "MEMCORDON-INVENTORY-READY:{}",
        serde_json::json!({"kind":"inventory-root-ready", "ordinal":null, "pid":identity.pid, "birth":identity.birth})
    );
    io::stdout()
        .flush()
        .unwrap_or_else(|error| fail(format!("cannot publish root readiness: {error}")));
    let executable = std::env::current_exe()
        .unwrap_or_else(|error| fail(format!("cannot resolve inventory fixture image: {error}")));
    let mut children = Vec::with_capacity(count);
    for ordinal in 0..count {
        let child = Command::new(&executable)
            .arg("windows-inventory-leaf")
            .arg(ordinal.to_string())
            .arg("240000")
            .spawn()
            .unwrap_or_else(|error| fail(format!("cannot create inventory leaf: {error}")));
        children.push(child);
    }
    thread::sleep(Duration::from_secs(240));
    for mut child in children {
        let _ = child.kill();
        let _ = child.wait();
    }
    fail("inventory root self-expired before provider cleanup");
}

#[cfg(windows)]
fn attempt_job_breakaway() {
    use std::os::windows::process::CommandExt;

    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let executable = std::env::current_exe().unwrap_or_else(|error| fail(error.to_string()));
    let result = Command::new(executable)
        .args(["exit", "--code", "0"])
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
        .status();
    if let Ok(status) = result {
        fail(format!(
            "Job Object unexpectedly allowed breakaway child with status {status}"
        ));
    }
}

#[cfg(not(windows))]
fn attempt_job_breakaway() {
    fail("Job Object breakaway fixture is only available on Windows");
}

#[cfg(unix)]
fn new_session_and_hold() {
    // SAFETY: setsid has no Rust memory-safety preconditions for the current process.
    if unsafe { libc::setsid() } == -1 {
        fail(io::Error::last_os_error().to_string());
    }
    thread::sleep(Duration::from_secs(30));
}

#[cfg(not(unix))]
fn new_session_and_hold() {
    fail("new-session-and-hold is Unix-only");
}

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let command = args
        .next()
        .and_then(|value| value.to_str().map(str::to_owned))
        .unwrap_or_else(|| fail("a fixture subcommand is required"));
    let status = match command.as_str() {
        #[cfg(target_os = "macos")]
        "macos-signal-parent" => macos_signal_parent(args),
        #[cfg(target_os = "macos")]
        "macos-signal-target" => macos_signal_target(args),
        #[cfg(target_os = "macos")]
        "__macos-guardian" | "__macos-guardian-envelope-v1" => loop {
            std::thread::park();
        },
        #[cfg(target_os = "macos")]
        "macos-gated-group-change" => {
            let gate = PathBuf::from(take_value(&mut args, "group transition gate"));
            let deadline = Instant::now() + Duration::from_secs(10);
            while !gate.exists() {
                if Instant::now() >= deadline {
                    fail("group transition gate timed out");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            // SAFETY: this disposable descendant deliberately changes its own session/group.
            if unsafe { libc::setsid() } < 0 {
                fail("descendant setsid failed");
            }
            std::fs::write(gate.with_extension("changed"), b"changed\n")
                .unwrap_or_else(|error| fail(error.to_string()));
            std::thread::sleep(Duration::from_secs(20));
            0
        }
        #[cfg(target_os = "macos")]
        "macos-envelope-caller" => {
            use std::os::fd::AsRawFd;

            let image = PathBuf::from(take_value(&mut args, "memcordon image"));
            let fixture = PathBuf::from(take_value(&mut args, "target fixture"));
            let directory = PathBuf::from(take_value(&mut args, "target directory"));
            let inherited = std::fs::File::create(directory.join("ambient-source")).unwrap();
            let descriptor = inherited.as_raw_fd();
            // This disposable process owns the descriptor and has no other threads.
            let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
            if flags < 0
                || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0
            {
                fail(io::Error::last_os_error().to_string());
            }
            let status = Command::new(&fixture)
                .arg("macos-envelope-parent")
                .arg(image)
                .arg(&fixture)
                .arg(directory)
                .arg(descriptor.to_string())
                .status()
                .unwrap();
            status.code().unwrap_or(125)
        }
        #[cfg(target_os = "macos")]
        "macos-envelope-parent" => {
            use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
            use std::os::unix::ffi::OsStringExt;
            let image = PathBuf::from(take_value(&mut args, "memcordon image"));
            let fixture = PathBuf::from(take_value(&mut args, "target fixture"));
            let directory = PathBuf::from(take_value(&mut args, "target directory"));
            if let Some(ambient) = args.next() {
                let ambient: i32 = ambient.to_str().unwrap().parse().unwrap();
                let flags = unsafe { libc::fcntl(ambient, libc::F_GETFD) };
                if flags < 0 || flags & libc::FD_CLOEXEC != 0 {
                    fail("additional caller descriptor was not inherited into the parent fixture");
                }
            }
            std::fs::write(directory.join("source"), b"envelope-source\n").unwrap();
            let source = std::fs::File::open(directory.join("source")).unwrap();
            let fd = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD, 64) };
            if fd < 0 {
                fail(io::Error::last_os_error().to_string());
            }
            let _inherited = unsafe { OwnedFd::from_raw_fd(fd) };
            let mut mask = 0;
            unsafe {
                libc::sigemptyset(&mut mask);
                libc::sigaddset(&mut mask, libc::SIGUSR2);
                if libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) != 0 {
                    fail("cannot set fixture signal mask");
                }
                if libc::signal(libc::SIGUSR1, libc::SIG_IGN) == libc::SIG_ERR {
                    fail("cannot set fixture signal disposition");
                }
                libc::umask(0o027);
            }
            let mut limits = std::mem::MaybeUninit::<libc::rlimit>::uninit();
            if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limits.as_mut_ptr()) } != 0 {
                fail("cannot read fixture descriptor limit");
            }
            let mut limits = unsafe { limits.assume_init() };
            limits.rlim_cur = 256;
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) } != 0 {
                fail("cannot set fixture descriptor limit");
            }
            // The caller may itself inherit descriptors from Cargo or its runner.
            // Require their exact preservation, while excluding CLOEXEC sources.
            let expected_descriptors: Vec<_> = open_descriptors()
                .into_iter()
                .filter_map(|(fd, flags)| (flags & libc::FD_CLOEXEC == 0).then_some(fd))
                .collect();
            let status = Command::new(image)
                .args(["+2s", "--"])
                .arg(fixture)
                .arg("macos-envelope-target")
                .arg(&directory)
                .arg(fd.to_string())
                .arg(serde_json::to_string(&expected_descriptors).unwrap())
                .arg(OsString::from_vec(b"native argument \xff".to_vec()))
                .current_dir(&directory)
                .env("PATH", OsString::from_vec(b"/native-path-\xff".to_vec()))
                .status()
                .unwrap();
            status.code().unwrap_or(125)
        }
        #[cfg(target_os = "macos")]
        "macos-envelope-target" => {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let directory = PathBuf::from(take_value(&mut args, "expected directory"));
            let descriptor: i32 = take_value(&mut args, "inherited descriptor")
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            let expected_descriptors: Vec<i32> = serde_json::from_slice(
                take_value(&mut args, "expected descriptor manifest").as_bytes(),
            )
            .unwrap();
            let argument = take_value(&mut args, "native argument");
            if argument.as_bytes() != b"native argument \xff" {
                fail("native argument bytes changed");
            }
            if std::env::var_os("PATH").unwrap().as_bytes() != b"/native-path-\xff" {
                fail("native environment bytes changed");
            }
            let actual_cwd = std::fs::metadata(std::env::current_dir().unwrap()).unwrap();
            let expected_cwd = std::fs::metadata(&directory).unwrap();
            if (actual_cwd.dev(), actual_cwd.ino()) != (expected_cwd.dev(), expected_cwd.ino()) {
                fail("caller cwd changed");
            }
            let mut mask = 0;
            if unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask) } != 0
                || unsafe { libc::sigismember(&mask, libc::SIGUSR2) } != 1
            {
                fail("caller signal mask changed");
            }
            let mut action = std::mem::MaybeUninit::<libc::sigaction>::zeroed();
            if unsafe { libc::sigaction(libc::SIGUSR1, std::ptr::null(), action.as_mut_ptr()) } != 0
                || unsafe { action.assume_init() }.sa_sigaction != libc::SIG_IGN
            {
                fail("caller ignored signal changed");
            }
            let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
            if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0
                || unsafe { limit.assume_init() }.rlim_cur != 256
            {
                fail("caller resource limit changed");
            }
            let expected = b"envelope-source\n";
            let mut contents = vec![0; expected.len()];
            if unsafe { libc::pread(descriptor, contents.as_mut_ptr().cast(), contents.len(), 0) }
                != expected.len() as isize
                || contents != expected
            {
                fail("intended descriptor mapping changed");
            }
            let actual_descriptors: Vec<_> =
                open_descriptors().into_iter().map(|(fd, _)| fd).collect();
            if actual_descriptors != expected_descriptors {
                fail(format!(
                    "target descriptor manifest changed: expected {expected_descriptors:?}, actual {actual_descriptors:?}"
                ));
            }
            let output = directory.join("created");
            std::fs::write(&output, b"caller envelope preserved\n").unwrap();
            if std::fs::metadata(output).unwrap().permissions().mode() & 0o777 != 0o640 {
                fail("caller umask changed");
            }
            0
        }
        #[cfg(target_os = "macos")]
        "macos-accounting-backend" => {
            let image = PathBuf::from(take_value(&mut args, "memcordon image"));
            let fixture = PathBuf::from(take_value(&mut args, "target fixture"));
            let mut policy =
                memcordon_core::Policy::new(memcordon_core::ByteSize::from_bytes(16 * 1024 * 1024))
                    .with_deadline(Duration::from_secs(5))
                    .unwrap();
            policy.metric = memcordon_core::Metric::Rss;
            let command = memcordon_core::CommandSpec::new(fixture)
                .args(["allocate", "--bytes", "64MiB", "--hold", "20s"]);
            let execution = memcordon_platform::run(policy, &command, &image)
                .unwrap_or_else(|error| fail(error.to_string()));
            if !matches!(
                execution.outcome,
                memcordon_core::RunOutcome::LimitExceeded { .. }
            ) || !execution
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.is_consistent())
                || !execution.restart_safety.is_safe()
            {
                fail(format!(
                    "native memory outcome or retirement is invalid: {execution:?}"
                ));
            }
            0
        }
        #[cfg(target_os = "macos")]
        "macos-envelope-transfer" => {
            let directory = PathBuf::from(take_value(&mut args, "fixture directory"));
            memcordon_platform::test_support::macos_envelope_transfer_fixture(&directory)
                .unwrap_or_else(|error| fail(error.to_string()));
            0
        }
        #[cfg(target_os = "macos")]
        "macos-guardian-inspector-wrapper" => {
            let image = PathBuf::from(take_value(&mut args, "memcordon image"));
            let fixture = PathBuf::from(take_value(&mut args, "fixture image"));
            let directory = PathBuf::from(take_value(&mut args, "identity directory"));
            let both = take_value(&mut args, "both inspectors") == "both";
            memcordon_platform::test_support::macos_guardian_inspector_wrapper(
                &image, &fixture, &directory, both,
            )
            .unwrap_or_else(|error| fail(error));
            0
        }
        #[cfg(target_os = "macos")]
        "macos-custody-wrapper" => {
            let image = PathBuf::from(take_value(&mut args, "memcordon image"));
            let fixture = PathBuf::from(take_value(&mut args, "fixture image"));
            let pid_file = PathBuf::from(take_value(&mut args, "descendant marker"));
            let marker = PathBuf::from(take_value(&mut args, "guardian marker"));
            memcordon_platform::test_support::macos_custody_wrapper(
                &image, &fixture, &pid_file, &marker,
            )
            .unwrap_or_else(|error| fail(error));
            0
        }
        #[cfg(target_os = "macos")]
        "macos-closed-stdio" => {
            use std::os::unix::process::CommandExt;
            let program = take_value(&mut args, "native executable");
            // SAFETY: this disposable fixture process deliberately has closed standard streams.
            for descriptor in [0, 1, 2] {
                unsafe { libc::close(descriptor) };
            }
            let _ = Command::new(program).args(args).exec();
            126
        }
        "exit" => exit_fixture(args),
        #[cfg(target_os = "macos")]
        "macos-ignore-term" => {
            let marker = PathBuf::from(take_value(&mut args, "signal readiness marker"));
            if unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) } == libc::SIG_ERR {
                fail("cannot ignore graceful signal");
            }
            fs::write(marker, b"signal-ready\n").unwrap();
            loop {
                std::thread::park();
            }
        }
        "hold" | "wait-for-signal" => {
            hold(args);
            0
        }
        "spin" => {
            let (pid_file, _, _) = parse_pid_duration_and_completion(args);
            write_pid(pid_file.as_deref());
            loop {
                std::hint::spin_loop();
            }
        }
        "allocate" => {
            allocate(args, false);
            0
        }
        "burst" => {
            allocate(args, true);
            0
        }
        "spawn-background" => spawn_background(args),
        "fork-continually" => {
            fork_continually(args);
            0
        }
        "monitor-failure" => {
            hold(args);
            0
        }
        "spawn-tree" => {
            spawn_tree(args);
            0
        }
        #[cfg(windows)]
        "windows-guardian-loss-hold" => {
            windows_guardian_loss_hold(args);
            0
        }
        #[cfg(windows)]
        "windows-inventory-capacity" => {
            windows_inventory_capacity(args);
            0
        }
        #[cfg(windows)]
        "windows-inventory-leaf" => {
            windows_inventory_leaf(args);
            0
        }
        #[cfg(windows)]
        "windows-execution-leaf" => {
            windows_execution_leaf(args);
            0
        }
        #[cfg(windows)]
        mode @ ("windows-concurrent-257"
        | "windows-sequential-churn-4096"
        | "windows-short-lived-bursts") => {
            windows_execution_family(mode, args);
            0
        }
        #[cfg(windows)]
        "windows-identity-access-denied" => {
            windows_identity_access_denied(args);
            0
        }
        #[cfg(windows)]
        "windows-identity-denied-leaf" => {
            windows_identity_denied_leaf(args);
            0
        }
        #[cfg(windows)]
        "windows-replay-ack-loss" => {
            windows_replay_ack_loss(args);
            0
        }
        #[cfg(windows)]
        "windows-prior-boot-hold" => {
            windows_prior_boot_hold(args);
            0
        }
        "print-pid-and-hold" => {
            println!("{}", std::process::id());
            io::stdout()
                .flush()
                .unwrap_or_else(|error| fail(error.to_string()));
            hold(args);
            0
        }
        "new-session-and-hold" => {
            new_session_and_hold();
            0
        }
        "assert-native-containment" => {
            assert_native_containment(args);
            0
        }
        "record-argv" => {
            record_argv(args);
            0
        }
        "assert-no-memcordon-environment" => {
            assert_no_memcordon_environment(args);
            0
        }
        "gate-marker" => {
            gate_marker(args);
            0
        }
        "gate-wait" => {
            gate_wait(args);
            0
        }
        "tcp-loopback" => {
            tcp_loopback(args);
            0
        }
        "prebound-listener-owned" => prebound_listener(args, false),
        "prebound-listener-policy-failure" => prebound_listener(args, true),
        #[cfg(all(target_os = "linux", feature = "test-fixtures"))]
        "private-installed-owner-loss" => {
            let request = PathBuf::from(take_value(&mut args, "expected contract"));
            let ready = PathBuf::from(take_value(&mut args, "native readiness identity"));
            let mode = take_value(&mut args, "native owner kind");
            let hash = take_value(&mut args, "expected installed fixture hash");
            let observed = PathBuf::from(take_value(&mut args, "native observation output"));
            let assessed = PathBuf::from(take_value(&mut args, "assessment acknowledgement"));
            if args.next().is_some() {
                fail("unexpected native owner loss argument");
            }
            let result = private_installed_loss_fixture::run(
                &request,
                &ready,
                mode.to_str()
                    .unwrap_or_else(|| fail("owner kind is not UTF-8")),
                hash.to_str()
                    .unwrap_or_else(|| fail("fixture hash is not UTF-8")),
                &observed,
                &assessed,
            )
            .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string(&result).unwrap_or_else(|error| fail(error.to_string()))
            );
            0
        }
        #[cfg(target_os = "linux")]
        "assert-private-runtime" => {
            assert_private_runtime(args);
            0
        }
        "tcp-client" => {
            tcp_client(args);
            0
        }
        "gate-failure" => {
            gate_failure(args);
            0
        }
        "attempt-job-breakaway" => {
            attempt_job_breakaway();
            0
        }
        _ => fail("unknown fixture subcommand"),
    };
    std::process::exit(status);
}

#[cfg(target_os = "macos")]
fn fixture_signal(value: &OsStr) -> i32 {
    match value.to_str() {
        Some("interrupt") => libc::SIGINT,
        Some("terminate") => libc::SIGTERM,
        Some("hangup") => libc::SIGHUP,
        _ => fail("unknown fixture signal"),
    }
}

#[cfg(target_os = "macos")]
extern "C" fn fixture_caught_signal(_: libc::c_int) {}

#[cfg(target_os = "macos")]
fn macos_signal_parent(mut args: impl Iterator<Item = OsString>) -> i32 {
    use std::os::unix::process::CommandExt;

    let signal_name = take_value(&mut args, "signal");
    let signal = fixture_signal(&signal_name);
    let policy = take_value(&mut args, "signal policy");
    let route = take_value(&mut args, "execution route");
    let image = PathBuf::from(take_value(&mut args, "frontend"));
    let fixture = PathBuf::from(take_value(&mut args, "target"));
    let marker = PathBuf::from(take_value(&mut args, "marker"));
    let (disposition, blocked, expected) = match policy.to_str() {
        Some("ignored") => (libc::SIG_IGN, false, "ignored"),
        Some("default") => (libc::SIG_DFL, false, "default"),
        Some("caught") => (
            fixture_caught_signal as *const () as usize,
            false,
            "default",
        ),
        Some("blocked-default") => (libc::SIG_DFL, true, "blocked-default"),
        _ => fail("unknown fixture signal policy"),
    };
    // SAFETY: only this disposable fixture process changes its signal state.
    // Native exec below reproduces ignored dispositions and the calling mask.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = disposition;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
            fail(io::Error::last_os_error().to_string());
        }
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, signal);
        if libc::pthread_sigmask(
            if blocked {
                libc::SIG_BLOCK
            } else {
                libc::SIG_UNBLOCK
            },
            &mask,
            std::ptr::null_mut(),
        ) != 0
        {
            fail("cannot set fixture calling mask");
        }
    }
    let mut command = match route.to_str() {
        Some("direct") => Command::new(&fixture),
        Some("supervised") => {
            let mut command = Command::new(&image);
            command.args(["+2s", "--quiet", "--report"]);
            command
                .arg(marker.with_extension("json"))
                .arg("--")
                .arg(&fixture);
            command
        }
        _ => fail("unknown fixture execution route"),
    };
    command
        .arg("macos-signal-target")
        .arg(signal_name)
        .arg(expected)
        .arg(marker);
    fail(command.exec().to_string());
}

#[cfg(target_os = "macos")]
fn macos_signal_target(mut args: impl Iterator<Item = OsString>) -> i32 {
    let signal = fixture_signal(&take_value(&mut args, "signal"));
    let expected = take_value(&mut args, "expected signal policy");
    let marker = PathBuf::from(take_value(&mut args, "marker"));
    let ignored = expected == "ignored";
    let blocked = expected == "blocked-default";
    // SAFETY: read our own dispositions/mask and signal this fixture only.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        let mut mask: libc::sigset_t = std::mem::zeroed();
        if libc::sigaction(signal, std::ptr::null(), &mut action) != 0
            || libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask) != 0
        {
            fail("cannot inspect target signal policy");
        }
        if action.sa_sigaction
            != if ignored {
                libc::SIG_IGN
            } else {
                libc::SIG_DFL
            }
            || (libc::sigismember(&mask, signal) == 1) != blocked
        {
            fail("target signal policy differs from caller exec semantics");
        }
        fs::write(&marker, b"signal policy verified\n").unwrap();
        if libc::raise(signal) != 0 {
            fail("target self-signal failed");
        }
    }
    if !ignored && !blocked {
        fail("default unblocked target survived self-signal");
    }
    fs::write(marker.with_extension("completed"), b"signal survived\n").unwrap();
    0
}
