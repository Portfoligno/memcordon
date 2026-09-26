//! Live independent `/proc` reader-clock calibration for BPF start times.
//! Linux proc/array.c reports nsec_to_clock_t(start_boottime + the *reader*
//! time namespace's boottime offset), not the target's raw BPF nanoseconds.

use crate::private_kernel_observer::KernelTaskIdentityV1;
use crate::{CiError, Result};

#[derive(Clone, Debug)]
pub(crate) struct VerifiedProcClockCalibrationV1 {
    reader_pid: u32,
    reader_start_ticks: u64,
    time_ns_inode: u64,
    boottime_offset_ns: i128,
}

fn fail(message: &'static str) -> CiError {
    CiError::Message(message.into())
}

fn parse_start_ticks(stat: &str) -> Result<u64> {
    let end = stat
        .rfind(')')
        .ok_or_else(|| fail("reader proc stat lacks command close"))?;
    stat[end + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| fail("reader proc stat lacks start ticks"))?
        .parse()
        .map_err(|_| fail("reader proc start ticks invalid"))
}

#[cfg(target_os = "linux")]
pub(crate) fn read_live_start_ticks(pid: u32) -> Result<u64> {
    if pid == 0 {
        return Err(fail("proc identity PID absent"));
    }
    parse_start_ticks(&std::fs::read_to_string(format!("/proc/{pid}/stat"))?)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn read_live_start_ticks(_pid: u32) -> Result<u64> {
    Err(fail("proc identity requires Linux"))
}

pub(crate) fn require_live_start_ticks(pid: u32, expected: u64) -> Result<()> {
    if expected == 0 || read_live_start_ticks(pid)? != expected {
        return Err(fail("proc start ticks changed"));
    }
    Ok(())
}

fn parse_time_ns_inode(link: &str) -> Result<u64> {
    let value = link
        .strip_prefix("time:[")
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| fail("reader time namespace link invalid"))?;
    value
        .parse()
        .map_err(|_| fail("reader time namespace inode invalid"))
}

fn parse_boottime_offset(text: &str) -> Result<i128> {
    let mut found = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("boottime") {
            continue;
        }
        if found.is_some() {
            return Err(fail("duplicate reader boottime offset"));
        }
        let seconds: i128 = fields
            .next()
            .ok_or_else(|| fail("reader boottime seconds absent"))?
            .parse()
            .map_err(|_| fail("reader boottime seconds invalid"))?;
        let nanos: i128 = fields
            .next()
            .ok_or_else(|| fail("reader boottime nanos absent"))?
            .parse()
            .map_err(|_| fail("reader boottime nanos invalid"))?;
        if fields.next().is_some() || !(0..1_000_000_000).contains(&nanos) {
            return Err(fail("reader boottime offset malformed"));
        }
        found = Some(
            seconds
                .checked_mul(1_000_000_000)
                .and_then(|value| value.checked_add(nanos))
                .ok_or_else(|| fail("reader boottime offset overflow"))?,
        );
    }
    found.ok_or_else(|| fail("reader boottime offset absent"))
}

impl VerifiedProcClockCalibrationV1 {
    /// Must be invoked while the protected witness reader is alive at a CI
    /// barrier. The caller provides its independently captured pidfd identity.
    #[cfg(target_os = "linux")]
    pub(crate) fn observe_live_reader(reader_pid: u32, reader_start_ticks: u64) -> Result<Self> {
        use std::fs;
        if reader_pid == 0 || reader_start_ticks == 0 {
            return Err(fail("reader identity absent"));
        }
        let proc = format!("/proc/{reader_pid}");
        let ns_path = format!("{proc}/ns/time");
        let link_before = fs::read_link(&ns_path)?.to_string_lossy().into_owned();
        let stat_before = fs::read_to_string(format!("{proc}/stat"))?;
        let offsets = fs::read_to_string(format!("{proc}/timens_offsets"))?;
        let stat_after = fs::read_to_string(format!("{proc}/stat"))?;
        let link_after = fs::read_link(&ns_path)?.to_string_lossy().into_owned();
        if link_before != link_after
            || parse_start_ticks(&stat_before)? != reader_start_ticks
            || parse_start_ticks(&stat_after)? != reader_start_ticks
        {
            return Err(fail("reader identity changed during clock calibration"));
        }
        let hz = std::process::Command::new("/usr/bin/getconf")
            .arg("CLK_TCK")
            .output()?;
        if !hz.status.success() || hz.stdout != b"100\n" {
            return Err(fail("unsupported proc USER_HZ for clock calibration"));
        }
        Ok(Self {
            reader_pid,
            reader_start_ticks,
            time_ns_inode: parse_time_ns_inode(&link_before)?,
            boottime_offset_ns: parse_boottime_offset(&offsets)?,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn observe_live_reader(_reader_pid: u32, _reader_start_ticks: u64) -> Result<Self> {
        Err(fail("proc clock calibration requires Linux"))
    }

    pub(crate) fn reader_identity(&self) -> (u32, u64) {
        (self.reader_pid, self.reader_start_ticks)
    }

    pub(crate) fn matches(&self, task: KernelTaskIdentityV1, producer_start_ticks: u64) -> bool {
        if self.time_ns_inode == 0
            || task.time_ns_inode != self.time_ns_inode
            || task.start_time == 0
            || producer_start_ticks == 0
        {
            return false;
        }
        let Some(total) = i128::from(task.start_time).checked_add(self.boottime_offset_ns) else {
            return false;
        };
        total >= 0 && u64::try_from(total / 10_000_000).ok() == Some(producer_start_ticks)
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        reader_pid: u32,
        reader_start_ticks: u64,
        time_ns_inode: u64,
        boottime_offset_ns: i128,
    ) -> Self {
        Self {
            reader_pid,
            reader_start_ticks,
            time_ns_inode,
            boottime_offset_ns,
        }
    }
}

#[doc(hidden)]
pub(crate) fn parse_clock_inputs_for_test(
    stat: &str,
    ns: &str,
    offsets: &str,
) -> Result<(u64, u64, i128)> {
    Ok((
        parse_start_ticks(stat)?,
        parse_time_ns_inode(ns)?,
        parse_boottime_offset(offsets)?,
    ))
}
