//! Sealed fixture process, stream, and readiness handlers.
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;

pub(super) fn command_exit() {
    {}
}

pub(super) fn command_exit_17() {
    std::process::exit(17)
}

pub(super) fn command_exit_126() {
    std::process::exit(126)
}

pub(super) fn command_exit_127() {
    std::process::exit(127)
}

pub(super) fn command_mark() {
    {
        std::fs::write(
            "/tmp/memcordon-sealed-preauthorization-marker",
            b"authorized\n",
        )
        .unwrap();
    }
}

pub(super) fn command_fault_ready() {
    {
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
}

pub(super) fn command_frontend_hold() {
    {
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
}

pub(super) fn command_frontend_exit_before_ready() {
    std::process::exit(121)
}

pub(super) fn command_child() {
    {
        if unsafe { libc::fork() } == 0 {
            std::thread::sleep(std::time::Duration::from_secs(30));
            unsafe { libc::_exit(0) };
        }
    }
}

pub(super) fn command_retained_stream() {
    {
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
}

pub(super) fn command_concurrency_gate() {
    {
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
}

pub(super) fn command_double_fork() {
    {
        if unsafe { libc::fork() } == 0 {
            if unsafe { libc::fork() } == 0 {
                std::thread::sleep(std::time::Duration::from_secs(30));
                unsafe { libc::_exit(0) };
            }
            unsafe { libc::_exit(0) };
        }
    }
}

pub(super) fn command_setsid() {
    {
        if unsafe { libc::fork() } == 0 {
            let _ = unsafe { libc::setsid() };
            std::thread::sleep(std::time::Duration::from_secs(30));
            unsafe { libc::_exit(0) };
        }
    }
}

pub(super) fn command_fork_storm() {
    {
        for _ in 0..64 {
            if unsafe { libc::fork() } == 0 {
                std::thread::sleep(std::time::Duration::from_secs(30));
                unsafe { libc::_exit(0) };
            }
        }
    }
}
