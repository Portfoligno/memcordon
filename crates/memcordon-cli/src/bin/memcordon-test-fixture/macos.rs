//! Fixture macos handlers; invoked only through the command registry.
use super::*;

#[cfg(target_os = "macos")]
pub(super) fn open_descriptors() -> Vec<(i32, i32)> {
    // SAFETY: these calls inspect only this disposable fixture's descriptor table.
    let limit = unsafe { libc::getdtablesize() };
    if limit < 0 {
        fail(std_io::Error::last_os_error().to_string());
    }
    let mut descriptors = Vec::new();
    for fd in 0..limit {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags >= 0 {
            descriptors.push((fd, flags));
        } else if std_io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
            fail(format!(
                "inspect descriptor {fd}: {}",
                std_io::Error::last_os_error()
            ));
        }
    }
    descriptors
}

#[cfg(target_os = "macos")]
pub(super) fn fixture_signal(value: &OsStr) -> i32 {
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
pub(super) fn macos_signal_parent(mut args: impl Iterator<Item = OsString>) -> i32 {
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
            fail(std_io::Error::last_os_error().to_string());
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
pub(super) fn macos_signal_target(mut args: impl Iterator<Item = OsString>) -> i32 {
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

pub(super) fn command_macos_signal_parent(args: std::env::ArgsOs) -> i32 {
    macos_signal_parent(args)
}

pub(super) fn command_macos_signal_target(args: std::env::ArgsOs) -> i32 {
    macos_signal_target(args)
}

pub(super) fn command_macos_guardian(_args: std::env::ArgsOs) -> i32 {
    loop {
        std::thread::park();
    }
}

pub(super) fn command_macos_gated_group_change(mut args: std::env::ArgsOs) -> i32 {
    {
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
}

pub(super) fn command_macos_envelope_caller(mut args: std::env::ArgsOs) -> i32 {
    {
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
            fail(std_io::Error::last_os_error().to_string());
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
}

pub(super) fn command_macos_envelope_parent(mut args: std::env::ArgsOs) -> i32 {
    {
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
            fail(std_io::Error::last_os_error().to_string());
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
}

pub(super) fn command_macos_envelope_target(mut args: std::env::ArgsOs) -> i32 {
    {
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
        let actual_descriptors: Vec<_> = open_descriptors().into_iter().map(|(fd, _)| fd).collect();
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
}

pub(super) fn command_macos_accounting_backend(mut args: std::env::ArgsOs) -> i32 {
    {
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
}

pub(super) fn command_macos_envelope_transfer(mut args: std::env::ArgsOs) -> i32 {
    {
        let directory = PathBuf::from(take_value(&mut args, "fixture directory"));
        memcordon_platform::test_support::macos_envelope_transfer_fixture(&directory)
            .unwrap_or_else(|error| fail(error.to_string()));
        0
    }
}

pub(super) fn command_macos_guardian_inspector_wrapper(mut args: std::env::ArgsOs) -> i32 {
    {
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
}

pub(super) fn command_macos_custody_wrapper(mut args: std::env::ArgsOs) -> i32 {
    {
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
}

pub(super) fn command_macos_closed_stdio(mut args: std::env::ArgsOs) -> i32 {
    {
        use std::os::unix::process::CommandExt;
        let program = take_value(&mut args, "native executable");
        // SAFETY: this disposable fixture process deliberately has closed standard streams.
        for descriptor in [0, 1, 2] {
            unsafe { libc::close(descriptor) };
        }
        let _ = Command::new(program).args(args).exec();
        126
    }
}

pub(super) fn command_macos_ignore_term(mut args: std::env::ArgsOs) -> i32 {
    {
        let marker = PathBuf::from(take_value(&mut args, "signal readiness marker"));
        if unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) } == libc::SIG_ERR {
            fail("cannot ignore graceful signal");
        }
        fs::write(marker, b"signal-ready\n").unwrap();
        loop {
            std::thread::park();
        }
    }
}
