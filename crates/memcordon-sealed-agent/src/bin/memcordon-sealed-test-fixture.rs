#[cfg(target_os = "linux")]
fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "exit".to_owned());
    match mode.as_str() {
        "exit" => {}
        "fail" => std::process::exit(17),
        "mark" => {
            std::fs::write(
                "/tmp/memcordon-sealed-preauthorization-marker",
                b"authorized\n",
            )
            .unwrap();
        }
        "child" => {
            if unsafe { libc::fork() } == 0 {
                std::thread::sleep(std::time::Duration::from_secs(30));
                unsafe { libc::_exit(0) };
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
        "identity" => {
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            if !status.contains("NoNewPrivs:\t1") || !status.contains("CapEff:\t0000000000000000") {
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
