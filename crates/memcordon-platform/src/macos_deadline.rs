//! Same-boot continuous Darwin time. All wire values are checked nanoseconds.
use std::io;
use std::time::Duration;

#[repr(C)]
struct Timebase {
    numer: u32,
    denom: u32,
}
unsafe extern "C" {
    fn mach_timebase_info(info: *mut Timebase) -> i32;
    fn mach_continuous_time() -> u64;
}

pub fn continuous_nanos() -> io::Result<u64> {
    let mut timebase = Timebase { numer: 0, denom: 0 };
    // SAFETY: the timebase API initializes this local value; the clock has no arguments.
    let (result, ticks) = unsafe { (mach_timebase_info(&mut timebase), mach_continuous_time()) };
    if result != 0 || timebase.denom == 0 {
        return Err(io::Error::other(
            "Darwin continuous clock timebase unavailable",
        ));
    }
    let nanos = u128::from(ticks)
        .checked_mul(u128::from(timebase.numer))
        .and_then(|value| value.checked_div(u128::from(timebase.denom)))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| io::Error::other("Darwin continuous clock range exceeded"))?;
    Ok(nanos)
}

pub(crate) fn add(origin: u64, duration: Duration) -> io::Result<u64> {
    u64::try_from(duration.as_nanos())
        .ok()
        .and_then(|duration| origin.checked_add(duration))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "deadline range exceeded"))
}

pub(crate) fn remaining_retirement(
    force: u64,
    observed: u64,
    reserve: Duration,
) -> io::Result<Duration> {
    Ok(Duration::from_nanos(
        add(force, reserve)?.saturating_sub(observed),
    ))
}

#[cfg(feature = "test-support")]
pub fn retirement_mutation_probe(
    force: u64,
    observed: u64,
    work_expiry: u64,
    clamp: bool,
) -> io::Result<Duration> {
    let correct = remaining_retirement(force, observed, Duration::from_secs(3))?;
    Ok(if clamp {
        correct.min(Duration::from_nanos(work_expiry.saturating_sub(observed)))
    } else {
        correct
    })
}

pub(crate) fn boot_identity() -> io::Result<String> {
    let mut bytes = [0_u8; 128];
    let mut length = bytes.len();
    // SAFETY: name is NUL-terminated, the output size describes writable storage,
    // and null new-value arguments request a read-only sysctl observation.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let value = bytes
        .get(..length)
        .and_then(|bytes| bytes.strip_suffix(&[0]))
        .filter(|bytes| !bytes.is_empty() && !bytes.contains(&0))
        .ok_or_else(|| io::Error::other("invalid bounded boot-session identity"))?;
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| io::Error::other("boot-session identity is not UTF-8"))
}
