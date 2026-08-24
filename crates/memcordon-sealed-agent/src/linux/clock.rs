/// Returns the current Linux monotonic-clock offset in whole milliseconds.
///
/// Launch deadlines use this shared boot-relative clock domain across the
/// frontend and privileged provider. A clock read failure is never converted
/// into a plausible timestamp.
pub fn monotonic_millis() -> Result<u64, String> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is an initialized, writable timespec of the exact ABI size;
    // CLOCK_MONOTONIC has no additional pointer, lifetime, or thread requirements.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut value) } != 0 {
        return Err(format!(
            "MCSEALED-CLOCK-MONOTONIC: {}",
            std::io::Error::last_os_error()
        ));
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err("MCSEALED-CLOCK-MONOTONIC: kernel returned an invalid timespec".to_owned());
    }
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| "MCSEALED-CLOCK-MONOTONIC: seconds are not representable".to_owned())?;
    let nanoseconds = u64::try_from(value.tv_nsec)
        .map_err(|_| "MCSEALED-CLOCK-MONOTONIC: nanoseconds are not representable".to_owned())?;
    Ok(seconds
        .saturating_mul(1_000)
        .saturating_add(nanoseconds / 1_000_000))
}
