//! Same-machine, same-live-job timeout inputs. These records never certify work.
#![allow(unsafe_code)]

use crate::{CiError, Result, release::source::BuildSourceIdentity};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant},
};

const WORK_MILLIS: u64 = 140 * 60 * 1000;
const CLEANUP_MILLIS: u64 = 155 * 60 * 1000;
const RECORD: &str = "target/ci-session/native-budget.json";

#[derive(Debug)]
pub struct ClockReading {
    pub domain: String,
    pub millis: u64,
}

/// Boot-relative counters include suspended time. No `Instant` is serialized.
pub fn clock_reading() -> Result<ClockReading> {
    #[cfg(target_os = "linux")]
    {
        let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: clock_gettime initializes the correctly sized output on success.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, time.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let time = unsafe { time.assume_init() };
        let millis = u64::try_from(time.tv_sec)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1000))
            .and_then(|value| {
                u64::try_from(time.tv_nsec)
                    .ok()
                    .and_then(|nanos| value.checked_add(nanos / 1_000_000))
            })
            .ok_or_else(|| invalid("native boot counter overflow"))?;
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        Ok(ClockReading {
            domain: format!("linux-clock-boottime:{}", boot.trim()),
            millis,
        })
    }
    #[cfg(target_os = "macos")]
    {
        let millis = memcordon_platform::macos_continuous_nanos()? / 1_000_000;
        let mut boot = [0_u8; 128];
        let mut size = boot.len();
        // SAFETY: the bounded buffer receives a read-only boot-session UUID.
        let status = unsafe {
            libc::sysctlbyname(
                c"kern.bootsessionuuid".as_ptr(),
                boot.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if status != 0 {
            return Err(invalid("Darwin boot domain unavailable"));
        }
        let boot = boot
            .get(..size)
            .and_then(|bytes| bytes.strip_suffix(&[0]))
            .filter(|bytes| !bytes.is_empty() && !bytes.contains(&0))
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .ok_or_else(|| invalid("invalid Darwin boot domain"))?;
        Ok(ClockReading {
            domain: format!("darwin-continuous:{boot}"),
            millis,
        })
    }
    #[cfg(windows)]
    {
        #[repr(C)]
        struct TimeOfDay {
            boot: i64,
            current: i64,
            bias: i64,
            zone: u32,
            reserved: u32,
            boot_bias: u64,
            sleep_bias: u64,
        }
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQuerySystemInformation(
                class: u32,
                information: *mut std::ffi::c_void,
                length: u32,
                returned: *mut u32,
            ) -> i32;
        }
        let mut information = std::mem::MaybeUninit::<TimeOfDay>::zeroed();
        let mut returned = 0;
        // SAFETY: the existing SystemTimeOfDayInformation native layout is sized
        // exactly; successful returned length is checked before observing fields.
        let status = unsafe {
            NtQuerySystemInformation(
                3,
                information.as_mut_ptr().cast(),
                u32::try_from(std::mem::size_of::<TimeOfDay>()).expect("fixed native layout fits"),
                &mut returned,
            )
        };
        if status < 0 || usize::try_from(returned).ok() != Some(std::mem::size_of::<TimeOfDay>()) {
            return Err(invalid("Windows boot identity unavailable"));
        }
        let boot = unsafe { information.assume_init() }.boot;
        // SAFETY: GetTickCount64 takes no arguments and has no failure sentinel.
        let millis = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() };
        Ok(ClockReading {
            domain: format!("windows-gettickcount64:{boot}"),
            millis,
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Err(invalid("native split clock unsupported on this host"))
    }
}

fn invalid(message: &str) -> CiError {
    CiError::Message(message.into())
}

pub fn record_path(root: &Path, relative: &Path) -> Result<std::path::PathBuf> {
    let mut path = root.canonicalize()?;
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return Err(invalid("native record path must be relative"));
        };
        path.push(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                let final_part = index + 1 == components.len();
                if metadata.file_type().is_symlink()
                    || if final_part {
                        !metadata.is_file()
                    } else {
                        !metadata.is_dir()
                    }
                {
                    return Err(invalid("native record path has unsafe file kind"));
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(invalid("native record path traverses reparse point"));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(path)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Association {
    run: String,
    job: String,
    attempt: String,
    checkout: String,
}

impl Association {
    fn current(root: &Path) -> Result<Self> {
        let value = |key| std::env::var(key).unwrap_or_default();
        let association = Self {
            run: value("GITHUB_RUN_ID"),
            job: value("GITHUB_JOB"),
            attempt: value("GITHUB_RUN_ATTEMPT"),
            checkout: root.canonicalize()?.display().to_string(),
        };
        if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && [&association.run, &association.job, &association.attempt]
                .iter()
                .any(|value| value.is_empty())
        {
            return Err(invalid("native live-job association absent"));
        }
        Ok(association)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeBudget {
    revision: u32,
    source: BuildSourceIdentity,
    target: String,
    association: Association,
    domain: String,
    started: u64,
    work_cutoff: u64,
    cleanup_cutoff: u64,
    wall_started: u64,
}

struct WallWindow {
    started: u64,
    cutoff: u64,
    now: u64,
}

impl NativeBudget {
    fn remaining(
        &self,
        selected: &BuildSourceIdentity,
        target: &str,
        association: &Association,
        now: &ClockReading,
        wall: WallWindow,
        cleanup: bool,
    ) -> Result<Duration> {
        let duration = if cleanup { CLEANUP_MILLIS } else { WORK_MILLIS };
        let cutoff = if cleanup {
            self.cleanup_cutoff
        } else {
            self.work_cutoff
        };
        if self.revision != 1
            || &self.source != selected
            || self.target != target
            || &self.association != association
            || self.domain != now.domain
            || self.wall_started != wall.started
            || self.work_cutoff.checked_sub(self.started) != Some(WORK_MILLIS)
            || self.cleanup_cutoff.checked_sub(self.started) != Some(CLEANUP_MILLIS)
            || wall.cutoff.checked_sub(wall.started) != Some(duration)
            || now.millis < self.started
        {
            return Err(invalid(
                "native operation source/job/clock or fixed interval differs",
            ));
        }
        let remaining = cutoff
            .saturating_sub(now.millis)
            .min(wall.cutoff.saturating_sub(wall.now));
        if remaining == 0 {
            return Err(invalid("original native operation deadline exhausted"));
        }
        Ok(Duration::from_millis(remaining))
    }
}

/// Only a fresh compiler operation may create this record. Existing bytes fail closed.
pub fn begin(
    root: &Path,
    selected: &BuildSourceIdentity,
    target: &str,
    wall_started: u64,
) -> Result<()> {
    let now = clock_reading()?;
    let record = NativeBudget {
        revision: 1,
        source: selected.clone(),
        target: target.into(),
        association: Association::current(root)?,
        domain: now.domain,
        started: now.millis,
        work_cutoff: now
            .millis
            .checked_add(WORK_MILLIS)
            .ok_or_else(|| invalid("native counter overflow"))?,
        cleanup_cutoff: now
            .millis
            .checked_add(CLEANUP_MILLIS)
            .ok_or_else(|| invalid("native counter overflow"))?,
        wall_started,
    };
    let path = record_path(root, Path::new(RECORD))?;
    fs::create_dir_all(path.parent().expect("fixed session parent"))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&serde_json::to_vec(&record)?)?;
    file.sync_all()?;
    Ok(())
}

/// Missing records never renew a clock. Wall rollback cannot extend boot-relative time.
pub fn resume(
    root: &Path,
    selected: &BuildSourceIdentity,
    target: &str,
    wall_started: u64,
    wall_cutoff: u64,
    wall_now: u64,
    cleanup: bool,
) -> Result<Instant> {
    let path = record_path(root, Path::new(RECORD))?;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 16 * 1024 {
        return Err(invalid("native clock record exceeds bound"));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    let record: NativeBudget = serde_json::from_slice(&bytes)?;
    let remaining = record.remaining(
        selected,
        target,
        &Association::current(root)?,
        &clock_reading()?,
        WallWindow {
            started: wall_started,
            cutoff: wall_cutoff,
            now: wall_now,
        },
        cleanup,
    )?;
    Instant::now()
        .checked_add(remaining)
        .ok_or_else(|| invalid("native retained deadline overflow"))
}

#[cfg(test)]
#[path = "../tests/private/ci_operation_time.rs"]
mod tests;
