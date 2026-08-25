#[cfg(target_os = "linux")]
fn spawn_elevated_transition_descendant() {
    let mut readiness = [-1, -1];
    // SAFETY: readiness points to storage for exactly two file descriptors.
    if unsafe { libc::pipe(readiness.as_mut_ptr()) } == -1 {
        std::process::exit(103);
    }
    let readiness_argument =
        std::ffi::CString::new(readiness[1].to_string()).expect("descriptor text has no NUL");
    // SAFETY: the fixture is single-threaded here and both fork children either exec or _exit.
    let first = unsafe { libc::fork() };
    if first == -1 {
        std::process::exit(104);
    }
    if first == 0 {
        // SAFETY: the child does not read its own readiness pipe.
        unsafe { libc::close(readiness[0]) };
        // SAFETY: setsid has no pointer arguments and affects only this child.
        if unsafe { libc::setsid() } == -1 {
            unsafe { libc::_exit(105) };
        }
        // SAFETY: this single-threaded child immediately exits or execs after the second fork.
        let second = unsafe { libc::fork() };
        if second == -1 {
            unsafe { libc::_exit(106) };
        }
        if second > 0 {
            unsafe { libc::_exit(0) };
        }
        let arguments = [
            c"/proc/self/exe".as_ptr(),
            c"elevated-transition-descendant".as_ptr(),
            readiness_argument.as_ptr(),
            std::ptr::null(),
        ];
        // SAFETY: executable and argv are NUL-terminated live strings with a trailing null.
        unsafe { libc::execv(c"/proc/self/exe".as_ptr(), arguments.as_ptr()) };
        unsafe { libc::_exit(107) };
    }
    // SAFETY: the parent does not write its own readiness pipe.
    unsafe { libc::close(readiness[1]) };
    let mut status = 0;
    let mut ready = [0_u8; 1];
    // SAFETY: first is a live direct child, status is initialized, and ready is writable.
    let first_reaped = unsafe { libc::waitpid(first, &raw mut status, 0) } == first;
    let ready_count = unsafe { libc::read(readiness[0], ready.as_mut_ptr().cast(), ready.len()) };
    unsafe { libc::close(readiness[0]) };
    if !first_reaped
        || !libc::WIFEXITED(status)
        || libc::WEXITSTATUS(status) != 0
        || ready_count != 1
        || ready != [1]
    {
        std::process::exit(108);
    }
}

#[cfg(target_os = "linux")]
fn capability_bounding_set() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("CapBnd:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
}

#[cfg(target_os = "linux")]
fn main() {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mode = std::env::args().nth(1).unwrap_or_else(|| "exit".to_owned());
    match mode.as_str() {
        "exit" => {}
        "exit-17" => std::process::exit(17),
        "exit-126" => std::process::exit(126),
        "exit-127" => std::process::exit(127),
        "mark" => {
            std::fs::write(
                "/tmp/memcordon-sealed-preauthorization-marker",
                b"authorized\n",
            )
            .unwrap();
        }
        "fault-ready" => {
            let Some(marker) = std::env::args_os().nth(2) else {
                std::process::exit(116);
            };
            if std::fs::write(marker, b"authorized\n").is_err() {
                std::process::exit(117);
            }
            loop {
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        }
        "frontend-hold" => {
            let Some(marker) = std::env::args_os().nth(2) else {
                std::process::exit(118);
            };
            let mut ready = match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(marker)
            {
                Ok(ready) => ready,
                Err(_) => std::process::exit(119),
            };
            if ready.write_all(b"frontend-ready\n").is_err() || ready.sync_all().is_err() {
                std::process::exit(120);
            }
            loop {
                // SAFETY: the staged helper is a separately exec'd process and pause has no
                // pointer arguments; SIGKILL is the only successful terminal outcome.
                unsafe { libc::pause() };
            }
        }
        "frontend-exit-before-ready" => std::process::exit(121),
        "child" => {
            if unsafe { libc::fork() } == 0 {
                std::thread::sleep(std::time::Duration::from_secs(30));
                unsafe { libc::_exit(0) };
            }
        }
        "retained-stream" => {
            // SAFETY: fork has no pointer arguments; both resulting single-threaded paths use
            // only async-process-local state and terminate independently below.
            let descendant = unsafe { libc::fork() };
            if descendant == -1 {
                std::process::exit(119);
            }
            if descendant == 0 {
                let stdout_open = b"retained-stdout-open\n";
                let stderr_open = b"retained-stderr-open\n";
                // SAFETY: the byte slices remain live for each write and standard descriptors
                // are inherited from the verified launch descriptor inventory.
                if unsafe {
                    libc::write(
                        libc::STDOUT_FILENO,
                        stdout_open.as_ptr().cast(),
                        stdout_open.len(),
                    )
                } != stdout_open.len() as isize
                    || unsafe {
                        libc::write(
                            libc::STDERR_FILENO,
                            stderr_open.as_ptr().cast(),
                            stderr_open.len(),
                        )
                    } != stderr_open.len() as isize
                {
                    unsafe { libc::_exit(120) };
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
                let stdout_release = b"retained-stdout-release\n";
                let stderr_release = b"retained-stderr-release\n";
                // SAFETY: the byte slices remain live for each write and the inherited streams
                // must still be open until this descendant exits.
                if unsafe {
                    libc::write(
                        libc::STDOUT_FILENO,
                        stdout_release.as_ptr().cast(),
                        stdout_release.len(),
                    )
                } != stdout_release.len() as isize
                    || unsafe {
                        libc::write(
                            libc::STDERR_FILENO,
                            stderr_release.as_ptr().cast(),
                            stderr_release.len(),
                        )
                    } != stderr_release.len() as isize
                {
                    unsafe { libc::_exit(121) };
                }
                unsafe { libc::_exit(0) };
            }
        }
        "concurrency-gate" => {
            let Some(gate) = std::env::args_os().nth(2) else {
                std::process::exit(122);
            };
            let ready = b"concurrency-ready\n";
            // SAFETY: the byte slice remains live for the write and stdout is inherited from
            // the verified launch descriptor inventory.
            if unsafe { libc::write(libc::STDOUT_FILENO, ready.as_ptr().cast(), ready.len()) }
                != ready.len() as isize
            {
                std::process::exit(123);
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                if std::fs::read(&gate).is_ok_and(|contents| contents == b"release\n") {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    std::process::exit(124);
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let released = b"concurrency-release\n";
            // SAFETY: the byte slice remains live for the write and stdout is inherited from
            // the verified launch descriptor inventory.
            if unsafe {
                libc::write(
                    libc::STDOUT_FILENO,
                    released.as_ptr().cast(),
                    released.len(),
                )
            } != released.len() as isize
            {
                std::process::exit(125);
            }
        }
        "double-fork" => {
            if unsafe { libc::fork() } == 0 {
                if unsafe { libc::fork() } == 0 {
                    std::thread::sleep(std::time::Duration::from_secs(30));
                    unsafe { libc::_exit(0) };
                }
                unsafe { libc::_exit(0) };
            }
        }
        "setsid" => {
            if unsafe { libc::fork() } == 0 {
                let _ = unsafe { libc::setsid() };
                std::thread::sleep(std::time::Duration::from_secs(30));
                unsafe { libc::_exit(0) };
            }
        }
        "fork-storm" => {
            for _ in 0..64 {
                if unsafe { libc::fork() } == 0 {
                    std::thread::sleep(std::time::Duration::from_secs(30));
                    unsafe { libc::_exit(0) };
                }
            }
        }
        "deny-cgroup" => {
            if std::fs::OpenOptions::new()
                .write(true)
                .open("/sys/fs/cgroup/cgroup.procs")
                .is_ok()
            {
                std::process::exit(90);
            }
        }
        "deny-setns" => {
            let result = std::fs::File::open("/proc/1/ns/pid")
                .ok()
                .map(|file| unsafe {
                    use std::os::fd::AsRawFd;
                    libc::setns(file.as_raw_fd(), libc::CLONE_NEWPID)
                });
            if result == Some(0) {
                std::process::exit(91);
            }
        }
        "deny-cgroup-mount" => {
            let temporary = std::path::Path::new("/tmp/memcordon-sealed-cgroup-mount");
            let _ = std::fs::create_dir(temporary);
            let mounted = unsafe {
                libc::mount(
                    c"none".as_ptr(),
                    c"/tmp/memcordon-sealed-cgroup-mount".as_ptr(),
                    c"cgroup2".as_ptr(),
                    0,
                    std::ptr::null(),
                )
            } == 0;
            if mounted {
                let _ = unsafe {
                    libc::umount2(
                        c"/tmp/memcordon-sealed-cgroup-mount".as_ptr(),
                        libc::MNT_DETACH,
                    )
                };
                std::process::exit(92);
            }
        }
        "assert-credential-transition-root" => {
            if unsafe { libc::geteuid() } != 0 {
                std::process::exit(95);
            }
            spawn_elevated_transition_descendant();
        }
        "assert-effective-uid" => {
            let expected = std::env::args()
                .nth(2)
                .and_then(|value| value.parse::<libc::uid_t>().ok());
            if expected != Some(unsafe { libc::geteuid() }) {
                std::process::exit(96);
            }
        }
        "assert-file-capability-transition" => {
            if unsafe { libc::setuid(0) } != 0 || unsafe { libc::geteuid() } != 0 {
                std::process::exit(97);
            }
            spawn_elevated_transition_descendant();
        }
        "assert-bounding-capability-absent" => {
            let capability = std::env::args()
                .nth(2)
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|value| *value < 64);
            let bounding_set = capability_bounding_set();
            if unsafe { libc::geteuid() } != 0
                || capability
                    .is_none_or(|value| bounding_set.is_none_or(|set| set & (1_u64 << value) != 0))
            {
                std::process::exit(111);
            }
            spawn_elevated_transition_descendant();
        }
        "elevated-transition-descendant" => {
            let readiness = std::env::args()
                .nth(2)
                .and_then(|value| value.parse::<libc::c_int>().ok());
            if unsafe { libc::geteuid() } != 0
                || std::fs::OpenOptions::new()
                    .write(true)
                    .open("/sys/fs/cgroup/cgroup.procs")
                    .is_ok()
            {
                std::process::exit(98);
            }
            let Some(readiness) = readiness else {
                std::process::exit(109);
            };
            // SAFETY: the descriptor was inherited through exec specifically for readiness.
            if unsafe { libc::write(readiness, [1_u8].as_ptr().cast(), 1) } != 1 {
                std::process::exit(110);
            }
            unsafe { libc::close(readiness) };
            loop {
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        }
        "assert-mount-marker" => {
            let Some(marker) = std::env::args_os().nth(2) else {
                std::process::exit(99);
            };
            if !std::fs::read(marker).is_ok_and(|contents| contents == b"caller-mount-context\n") {
                std::process::exit(100);
            }
        }
        "assert-recursive-provider-rejected" => {
            let Some(memcordon) = std::env::args_os().nth(2) else {
                std::process::exit(126);
            };
            let Some(report) = std::env::args_os().nth(3) else {
                std::process::exit(127);
            };
            let status = std::process::Command::new(memcordon)
                .arg("--sealed")
                .arg("--report")
                .arg(&report)
                .arg("--")
                .arg("/usr/bin/true")
                .status();
            if !status.is_ok_and(|status| !status.success()) {
                std::process::exit(101);
            }
            let value = std::fs::read(report)
                .ok()
                .filter(|bytes| bytes.len() <= 1024 * 1024)
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
            let rejection = value
                .as_ref()
                .and_then(|value| value.pointer("/attempts/0/error/provider_rejection"));
            let exact_rejection = rejection.is_some_and(|rejection| {
                rejection
                    .pointer("/code")
                    .and_then(serde_json::Value::as_str)
                    == Some("MCSEALED-RECURSIVE-PROVIDER-REQUEST")
                    && rejection
                        .pointer("/detail")
                        .and_then(serde_json::Value::as_str)
                        == Some("caller is already inside an active sealed attempt")
                    && rejection
                        .pointer("/phase")
                        .and_then(serde_json::Value::as_str)
                        == Some("request-validation")
                    && rejection
                        .pointer("/target_created")
                        .and_then(serde_json::Value::as_bool)
                        == Some(false)
                    && rejection
                        .pointer("/target_released")
                        .and_then(serde_json::Value::as_bool)
                        == Some(false)
                    && rejection
                        .pointer("/cleanup_attempted")
                        .and_then(serde_json::Value::as_bool)
                        == Some(false)
            });
            let exact_envelope = value.as_ref().is_some_and(|value| {
                value
                    .pointer("/supervision/targets_authorized")
                    .and_then(serde_json::Value::as_u64)
                    == Some(0)
                    && value
                        .pointer("/supervision/restart/restarts_launched")
                        .and_then(serde_json::Value::as_u64)
                        == Some(0)
                    && value
                        .pointer("/attempts/0/authorized_offset_ms")
                        .is_some_and(serde_json::Value::is_null)
            });
            if !exact_rejection || !exact_envelope {
                std::process::exit(102);
            }
        }
        "identity" => {
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            if !status.contains("CapEff:\t0000000000000000") {
                std::process::exit(93);
            }
            let mut descriptors = std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            descriptors.sort();
            if descriptors.len() > 4 {
                std::process::exit(94);
            }
        }
        _ => std::process::exit(2),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(125);
}
