//! Sealed fixture cgroup, namespace, mount, and recursion assertions.

pub(super) fn command_deny_cgroup() {
    {
        if std::fs::OpenOptions::new()
            .write(true)
            .open("/sys/fs/cgroup/cgroup.procs")
            .is_ok()
        {
            std::process::exit(90);
        }
    }
}

pub(super) fn command_deny_setns() {
    {
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
}

pub(super) fn command_deny_cgroup_mount() {
    {
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
}

pub(super) fn command_assert_mount_marker() {
    {
        let Some(marker) = std::env::args_os().nth(2) else {
            std::process::exit(99);
        };
        if !std::fs::read(marker).is_ok_and(|contents| contents == b"caller-mount-context\n") {
            std::process::exit(100);
        }
    }
}

pub(super) fn command_assert_recursive_provider_rejected() {
    {
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
}
