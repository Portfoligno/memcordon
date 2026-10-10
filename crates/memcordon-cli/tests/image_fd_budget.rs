#[path = "../src/bin/memcordon-sealed-agent/linux/image_fd_budget.rs"]
mod budget;

#[test]
fn finite_simultaneous_images_preserve_hard_ceiling() {
    let required = budget::required(32, 1200, 100).unwrap();
    assert_eq!(required, 1348);
    assert_eq!(budget::target(required, 1024, 4096).unwrap(), required);
    assert_eq!(budget::target(required, 4096, 4096).unwrap(), 4096);
    let error = budget::target(required, 1024, 1024).unwrap_err();
    assert!(error.contains("required=1348; soft=1024; hard=1024"));
    assert!(budget::required(u64::MAX, 1, 1).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn actual_limit_adjustment_runs_in_separate_process() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_limit_adjustment", "--ignored"])
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "runs only in a child process so parent limits remain unchanged"]
fn child_limit_adjustment() {
    let mut original = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, original.as_mut_ptr()) },
        0
    );
    let original = unsafe { original.assume_init() };
    let low = libc::rlimit {
        rlim_cur: 64.min(original.rlim_max),
        rlim_max: original.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &low) }, 0);
    drop(budget::ensure(100, 100).unwrap());
    let mut after = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, after.as_mut_ptr()) },
        0
    );
    let after = unsafe { after.assume_init() };
    assert_eq!(after.rlim_max, original.rlim_max);
    assert!(after.rlim_cur >= 216);
    // A later policy image acquisition must count the first graph's live
    // handles rather than reuse only its original admission budget.
    let held = (0..96)
        .map(|_| std::fs::File::open("/dev/null").unwrap())
        .collect::<Vec<_>>();
    drop(budget::ensure(200, 0).unwrap());
    let mut later = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, later.as_mut_ptr()) },
        0
    );
    let later = unsafe { later.assume_init() };
    assert!(later.rlim_cur >= 96 + 200 + 16);
    assert_eq!(later.rlim_max, original.rlim_max);
    drop(held);
    assert!(budget::ensure(usize::try_from(after.rlim_max).unwrap(), 1).is_err());
    assert!(
        budget::target(
            original.rlim_max.saturating_add(1),
            after.rlim_cur,
            after.rlim_max
        )
        .is_err()
    );
}
