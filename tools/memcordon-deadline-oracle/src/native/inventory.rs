//! Independent native inventory. libproc list wrappers return PID counts.
use std::collections::BTreeMap;
use std::io;

use serde::{Deserialize, Serialize};

pub(super) const MAX_PID_CAPACITY: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub(super) struct ProcessIdentity {
    pub(super) pid: i32,
    pub(super) birth_seconds: u64,
    pub(super) birth_microseconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub(super) struct ProcessObservation {
    pub(super) identity: ProcessIdentity,
    pub(super) state: u32,
    pub(super) parent_pid: i32,
    pub(super) process_group: i32,
    pub(super) session_id: i32,
}

pub(super) trait ProcessApi {
    fn all_pids(&self) -> io::Result<Vec<i32>>;
    fn session_id(&self, pid: i32) -> io::Result<Option<i32>>;
    fn observation(&self, pid: i32) -> io::Result<Option<ProcessObservation>>;
}

pub(super) struct NativeProcessApi;

fn clear_errno() {
    unsafe { *libc::__error() = 0 };
}

fn native_error(detail: &'static str) -> io::Error {
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(0) {
        io::Error::other(detail)
    } else {
        error
    }
}

/// Retry a full buffer; never reinterpret a returned PID count as bytes.
pub(super) fn enumerate_pids(
    initial_capacity: usize,
    mut list: impl FnMut(&mut [i32]) -> io::Result<usize>,
) -> io::Result<Vec<i32>> {
    let mut capacity = initial_capacity;
    loop {
        if capacity == 0 || capacity > MAX_PID_CAPACITY {
            return Err(io::Error::other("native PID inventory exceeded safety cap"));
        }
        let mut pids = vec![0; capacity];
        let count = list(&mut pids)?;
        if count == 0 {
            return Err(io::Error::other("native all-PID inventory unavailable"));
        }
        if count >= capacity {
            capacity = capacity
                .checked_mul(2)
                .ok_or_else(|| io::Error::other("native PID inventory capacity overflow"))?;
            continue;
        }
        pids.truncate(count);
        pids.retain(|pid| *pid > 0);
        pids.sort_unstable();
        pids.dedup();
        if pids.is_empty() {
            return Err(io::Error::other(
                "native all-PID inventory contained no identities",
            ));
        }
        return Ok(pids);
    }
}

impl ProcessApi for NativeProcessApi {
    fn all_pids(&self) -> io::Result<Vec<i32>> {
        unsafe extern "C" {
            fn proc_listallpids(buffer: *mut std::ffi::c_void, bytes: i32) -> i32;
        }
        enumerate_pids(1024, |pids| {
            let bytes = pids
                .len()
                .checked_mul(std::mem::size_of::<i32>())
                .and_then(|bytes| i32::try_from(bytes).ok())
                .ok_or_else(|| io::Error::other("native PID buffer overflow"))?;
            clear_errno();
            let count = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
            if count <= 0 {
                return Err(native_error("native all-PID inventory unavailable"));
            }
            usize::try_from(count).map_err(io::Error::other)
        })
    }

    fn session_id(&self, pid: i32) -> io::Result<Option<i32>> {
        let session = unsafe { libc::getsid(pid) };
        if session < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(None);
            }
            return Err(error);
        }
        Ok(Some(session))
    }

    fn observation(&self, pid: i32) -> io::Result<Option<ProcessObservation>> {
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let size = std::mem::size_of::<libc::proc_bsdinfo>();
        clear_errno();
        let count = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                i32::try_from(size).expect("native structure size"),
            )
        };
        if count == 0 {
            let error = native_error("native identity unavailable");
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(None);
            }
            return Err(error);
        }
        if usize::try_from(count).ok() != Some(size) {
            return Err(io::Error::other("partial native identity"));
        }
        let info = unsafe { info.assume_init() };
        let Some(session_id) = self.session_id(pid)? else {
            return Ok(None);
        };
        Ok(Some(ProcessObservation {
            identity: ProcessIdentity {
                pid,
                birth_seconds: info.pbi_start_tvsec,
                birth_microseconds: info.pbi_start_tvusec,
            },
            state: info.pbi_status,
            parent_pid: i32::try_from(info.pbi_ppid).map_err(io::Error::other)?,
            process_group: i32::try_from(info.pbi_pgid).map_err(io::Error::other)?,
            session_id,
        }))
    }
}

#[derive(Debug, Serialize)]
pub(super) struct SessionSnapshot {
    pub(super) complete: bool,
    pub(super) members: Vec<ProcessObservation>,
    pub(super) raced_pids: usize,
}

pub(super) fn session_snapshot(api: &impl ProcessApi, session: i32) -> io::Result<SessionSnapshot> {
    let mut members = BTreeMap::new();
    let mut raced_pids = 0;
    for pid in api.all_pids()? {
        if api.session_id(pid)? != Some(session) {
            continue;
        }
        let Some(first) = api.observation(pid)? else {
            raced_pids += 1;
            continue;
        };
        if api.session_id(pid)? != Some(session) {
            raced_pids += 1;
            continue;
        }
        let Some(second) = api.observation(pid)? else {
            raced_pids += 1;
            continue;
        };
        if first.identity != second.identity || second.session_id != session {
            raced_pids += 1;
            continue;
        }
        members.insert(second.identity, second);
    }
    Ok(SessionSnapshot {
        complete: true,
        members: members.into_values().collect(),
        raced_pids,
    })
}

pub(super) fn same_identity(api: &impl ProcessApi, expected: ProcessIdentity) -> io::Result<bool> {
    Ok(api
        .observation(expected.pid)?
        .is_some_and(|actual| actual.identity == expected))
}

#[derive(Default)]
pub(super) struct StableEmpty {
    pub(super) count: usize,
    last: Option<std::time::Instant>,
}

impl StableEmpty {
    pub(super) fn observe(&mut self, snapshot: &SessionSnapshot, now: std::time::Instant) -> bool {
        if !snapshot.complete || !snapshot.members.is_empty() {
            self.count = 0;
            self.last = None;
        } else if self
            .last
            .is_none_or(|last| now.duration_since(last) >= std::time::Duration::from_millis(20))
        {
            self.count += 1;
            self.last = Some(now);
        }
        self.count >= 3
    }
}
