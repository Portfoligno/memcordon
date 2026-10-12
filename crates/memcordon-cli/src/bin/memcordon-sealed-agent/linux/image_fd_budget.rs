//! Finite descriptor capacity for simultaneously held immutable image members.
pub(super) fn required(ambient: u64, runtime: usize, input: usize) -> Result<u64, String> {
    // Image opening/revalidation walks directories one at a time. Keep bounded
    // scratch capacity for both roots, manifests, directory walks and ELF reads.
    const SCRATCH: u64 = 16;
    ambient
        .checked_add(u64::try_from(runtime).map_err(|_| "runtime image count overflow")?)
        .and_then(|value| value.checked_add(u64::try_from(input).ok()?))
        .and_then(|value| value.checked_add(SCRATCH))
        .ok_or_else(|| "immutable image descriptor budget overflow".into())
}

pub(super) fn target(required: u64, soft: u64, hard: u64) -> Result<u64, String> {
    if required > hard {
        return Err(format!(
            "immutable image descriptor capacity exceeds original hard limit; required={required}; soft={soft}; hard={hard}"
        ));
    }
    Ok(soft.max(required))
}

#[cfg(target_os = "linux")]
pub(super) fn ensure(
    runtime: usize,
    input: usize,
) -> Result<std::sync::MutexGuard<'static, ()>, String> {
    static CAPACITY: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let capacity = CAPACITY
        .lock()
        .map_err(|_| "image descriptor capacity lock poisoned")?;
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // getrlimit initializes the complete structure on success.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut limit = unsafe { limit.assume_init() };
    let mut ambient = 0u64;
    for entry in std::fs::read_dir("/proc/self/fd").map_err(|error| error.to_string())? {
        entry.map_err(|error| error.to_string())?;
        ambient = ambient.checked_add(1).ok_or("process FD census overflow")?;
        if ambient > limit.rlim_max {
            return Err("process FD census exceeds original hard limit".into());
        }
    }
    let needed = required(ambient, runtime, input)?;
    let selected = target(needed, limit.rlim_cur, limit.rlim_max)?;
    if selected != limit.rlim_cur {
        limit.rlim_cur = selected;
        // Only the soft ceiling changes; the original hard ceiling is retained.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
            return Err(format!(
                "immutable image descriptor capacity adjustment failed; required={needed}; hard={}; cause={}",
                limit.rlim_max,
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(capacity)
}
