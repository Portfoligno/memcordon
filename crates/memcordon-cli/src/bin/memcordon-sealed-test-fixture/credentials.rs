//! Sealed fixture credential transition assertions and descendants.

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

pub(super) fn command_assert_credential_transition_root() {
    {
        if unsafe { libc::geteuid() } != 0 {
            std::process::exit(95);
        }
        spawn_elevated_transition_descendant();
    }
}

pub(super) fn command_assert_effective_uid() {
    {
        let expected = std::env::args()
            .nth(2)
            .and_then(|value| value.parse::<libc::uid_t>().ok());
        if expected != Some(unsafe { libc::geteuid() }) {
            std::process::exit(96);
        }
    }
}

pub(super) fn command_assert_file_capability_transition() {
    {
        if unsafe { libc::setuid(0) } != 0 || unsafe { libc::geteuid() } != 0 {
            std::process::exit(97);
        }
        spawn_elevated_transition_descendant();
    }
}

pub(super) fn command_assert_bounding_capability_absent() {
    {
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
}

pub(super) fn command_elevated_transition_descendant() {
    {
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
}

pub(super) fn command_identity() {
    {
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
}
