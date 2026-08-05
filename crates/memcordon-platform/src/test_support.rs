//! Native containment used only by black-box process tests.

use std::io;
use std::process::{Child, Command};

#[cfg(target_os = "linux")]
use memcordon_core::ByteSize;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub birth: u128,
}

#[cfg(target_os = "linux")]
pub fn linux_limit_delta_is_authoritative() -> bool {
    crate::linux_cgroup::test_limit_delta()
}

#[cfg(target_os = "linux")]
pub fn linux_configure(path: &std::path::Path, limit: u64) -> io::Result<()> {
    crate::linux_cgroup::test_configure(path, ByteSize::from_bytes(limit))
}

#[cfg(target_os = "linux")]
pub fn linux_monitor_errors(path: &std::path::Path) -> bool {
    crate::linux_cgroup::test_monitor_errors(path)
}

#[cfg(target_os = "linux")]
pub fn linux_verify(path: &std::path::Path, pid: i32) -> io::Result<()> {
    crate::linux_cgroup::test_verify(path, pid)
}

#[cfg(target_os = "linux")]
pub fn linux_launcher_status(bytes: &[u8]) -> io::Result<Option<i32>> {
    crate::linux_cgroup::test_launcher_status(bytes)
}

#[cfg(target_os = "linux")]
pub fn linux_launcher_status_timeout() -> io::ErrorKind {
    crate::linux_cgroup::test_launcher_status_timeout()
}

#[cfg(windows)]
pub fn windows_encode_command_line(
    program: std::ffi::OsString,
    arguments: Vec<std::ffi::OsString>,
) -> Vec<u16> {
    let command = memcordon_core::CommandSpec::new(program).args(arguments);
    crate::windows_job::test_encode_command_line(&command)
}

#[cfg(windows)]
pub fn windows_target_remains_suspended_until_assignment() -> io::Result<bool> {
    crate::windows_job::test_target_remains_suspended_until_assignment()
}

#[cfg(windows)]
pub fn windows_kill_on_job_close() -> io::Result<bool> {
    crate::windows_job::test_kill_on_job_close()
}

#[cfg(windows)]
pub fn windows_nested_assignment() -> io::Result<bool> {
    crate::windows_job::test_nested_assignment()
}

#[cfg(windows)]
pub fn windows_assignment_failure() -> io::Result<bool> {
    crate::windows_job::test_assignment_failure()
}

impl ProcessIdentity {
    pub fn current() -> io::Result<Self> {
        Self::for_pid(std::process::id())
    }

    pub fn for_pid(pid: u32) -> io::Result<Self> {
        process_identity(pid)
    }

    pub fn still_exists(self) -> io::Result<bool> {
        match Self::for_pid(self.pid) {
            Ok(current) => Ok(current == self),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
pub fn assert_native_containment(expected_memory: u64) -> io::Result<()> {
    let membership = std::fs::read_to_string("/proc/self/cgroup")?;
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| io::Error::other("fixture is not in a unified cgroup"))?;
    if !relative
        .split('/')
        .any(|part| part.starts_with("memcordon-"))
    {
        return Err(io::Error::other(
            "fixture was observable before MemCordon cgroup assignment",
        ));
    }
    let memory_max = std::fs::read_to_string(
        std::path::Path::new("/sys/fs/cgroup")
            .join(relative.trim_start_matches('/'))
            .join("memory.max"),
    )?;
    if memory_max.trim() != expected_memory.to_string() {
        return Err(io::Error::other(
            "fixture cgroup does not have the MemCordon memory limit",
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub fn force_terminate(pid: u32) -> io::Result<()> {
    let pid = i32::try_from(pid).map_err(io::Error::other)?;
    // SAFETY: the caller supplies the process id of the wrapper it just spawned.
    if unsafe { libc::kill(pid, libc::SIGKILL) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub fn request_interrupt(pid: u32) -> io::Result<()> {
    let pid = i32::try_from(pid).map_err(io::Error::other)?;
    // SAFETY: the caller supplies the process id of the wrapper it just spawned.
    if unsafe { libc::kill(pid, libc::SIGTERM) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
pub fn force_terminate(pid: u32) -> io::Result<()> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

    // SAFETY: the process id belongs to the wrapper spawned by the calling test.
    let process = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: process is a live owned handle with terminate access.
    let result = unsafe { TerminateProcess(process, 137) };
    // SAFETY: process is uniquely owned by this function.
    unsafe { CloseHandle(process) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
pub fn assert_native_containment(expected_memory: u64) -> io::Result<()> {
    use std::mem::{MaybeUninit, size_of};
    use windows_sys::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        QueryInformationJobObject,
    };

    // A null handle queries the current process's immediate job. In a nested runner this
    // distinguishes MemCordon's inner job from any outer CI containment job.
    let mut information =
        unsafe { MaybeUninit::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>::zeroed().assume_init() };
    // SAFETY: the null handle selects the immediate job and the output buffer has the exact class
    // size documented by QueryInformationJobObject.
    let result = unsafe {
        QueryInformationJobObject(
            std::ptr::null_mut(),
            JobObjectExtendedLimitInformation,
            (&raw mut information).cast(),
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(u32::MAX),
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else if information.JobMemoryLimit != usize::try_from(expected_memory).unwrap_or(usize::MAX)
        || information.BasicLimitInformation.LimitFlags
            & (JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
            != JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    {
        Err(io::Error::other(
            "fixture immediate job does not have the MemCordon memory and kill-on-close limits",
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn assert_native_containment(_expected_memory: u64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native containment assertion is only available on Linux and Windows",
    ))
}

#[cfg(target_os = "linux")]
fn process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    let stat = std::fs::read_to_string(
        std::path::Path::new("/proc")
            .join(pid.to_string())
            .join("stat"),
    )?;
    let after_name = stat
        .rsplit_once(')')
        .map(|(_, fields)| fields)
        .ok_or_else(|| io::Error::other("malformed Linux process stat"))?;
    let birth = after_name
        .split_whitespace()
        .nth(19)
        .and_then(|field| field.parse::<u128>().ok())
        .ok_or_else(|| io::Error::other("Linux process stat lacks start identity"))?;
    Ok(ProcessIdentity { pid, birth })
}

#[cfg(target_os = "macos")]
fn process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    use std::mem::{MaybeUninit, size_of};

    const PROC_PIDTBSDINFO: i32 = 3;
    #[repr(C)]
    struct ProcBsdInfo {
        flags: u32,
        status: u32,
        xstatus: u32,
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        ruid: u32,
        rgid: u32,
        svuid: u32,
        svgid: u32,
        rfu_1: u32,
        comm: [libc::c_char; 16],
        name: [libc::c_char; 32],
        nfiles: u32,
        pgid: u32,
        pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        nice: i32,
        start_tvsec: u64,
        start_tvusec: u64,
    }
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
    }
    let mut info = MaybeUninit::<ProcBsdInfo>::zeroed();
    let size = i32::try_from(size_of::<ProcBsdInfo>()).map_err(io::Error::other)?;
    // SAFETY: info is writable for the exact declared structure size.
    let read = unsafe {
        proc_pidinfo(
            i32::try_from(pid).map_err(io::Error::other)?,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if read != size {
        let error = io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(libc::ESRCH) {
            io::Error::new(io::ErrorKind::NotFound, error)
        } else {
            error
        });
    }
    // SAFETY: proc_pidinfo initialized the full structure after exact-size success.
    let info = unsafe { info.assume_init() };
    Ok(ProcessIdentity {
        pid,
        birth: u128::from(info.start_tvsec) * 1_000_000 + u128::from(info.start_tvusec),
    })
}

#[cfg(windows)]
fn process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // SAFETY: pid is a plain process identity and requested access is query-only.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            io::Error::last_os_error(),
        ));
    }
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all FILETIME pointers are valid writable structures.
    let result =
        unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) };
    // SAFETY: process is an owned handle opened above.
    unsafe { CloseHandle(process) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    let birth = (u128::from(creation.dwHighDateTime) << 32) | u128::from(creation.dwLowDateTime);
    Ok(ProcessIdentity { pid, birth })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    Ok(ProcessIdentity { pid, birth: 0 })
}

#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(unix)]
#[derive(Debug)]
pub struct OuterTestBoundary {
    session: i32,
}

#[cfg(unix)]
impl OuterTestBoundary {
    pub fn configure(command: &mut Command) -> io::Result<()> {
        // SAFETY: the callback invokes only the async-signal-safe setsid operation.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        Ok(())
    }

    pub fn after_spawn(child: &Child) -> io::Result<Self> {
        Ok(Self {
            session: i32::try_from(child.id()).map_err(io::Error::other)?,
        })
    }

    pub fn terminate(&self) -> io::Result<()> {
        terminate_unix_session(self.session)
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn unix_session_members(session: i32) -> io::Result<Vec<i32>> {
    let mut members = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let Some(after_name) = stat.rsplit_once(')').map(|(_, fields)| fields) else {
            continue;
        };
        let member_session = after_name
            .split_whitespace()
            .nth(3)
            .and_then(|field| field.parse::<i32>().ok());
        if member_session != Some(session) {
            continue;
        }
        members.push(pid);
    }
    Ok(members)
}

#[cfg(target_os = "macos")]
fn unix_session_members(session: i32) -> io::Result<Vec<i32>> {
    use std::mem::size_of;
    use std::ptr;

    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_listallpids(buffer: *mut libc::c_void, buffersize: libc::c_int) -> libc::c_int;
    }

    // Querying once without a buffer returns the current process count. Reserve slack for races.
    let count = unsafe { proc_listallpids(ptr::null_mut(), 0) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pids = vec![0_i32; usize::try_from(count).map_err(io::Error::other)? + 64];
    let bytes = pids
        .len()
        .checked_mul(size_of::<i32>())
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| io::Error::other("process inventory is too large"))?;
    // SAFETY: the buffer is writable for the exact byte count supplied.
    let found = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    if found < 0 {
        return Err(io::Error::last_os_error());
    }
    pids.truncate(usize::try_from(found).map_err(io::Error::other)?);
    let mut members = Vec::new();
    for pid in pids {
        if pid <= 0 {
            continue;
        }
        // SAFETY: getsid accepts a process identity and does not dereference Rust memory.
        if unsafe { libc::getsid(pid) } == session {
            members.push(pid);
        }
    }
    Ok(members)
}

#[cfg(unix)]
fn terminate_unix_session(session: i32) -> io::Result<()> {
    use std::collections::BTreeSet;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut first_error = None;
    let mut signalled = BTreeSet::new();
    loop {
        let mut members = Vec::new();
        for pid in unix_session_members(session)? {
            let Ok(pid_value) = u32::try_from(pid) else {
                continue;
            };
            match process_identity(pid_value) {
                Ok(identity) if !signalled.contains(&identity) => members.push((pid, identity)),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        if members.is_empty() {
            return first_error.map_or(Ok(()), Err);
        }
        for (pid, identity) in members {
            // SAFETY: kill accepts a process identity and does not dereference Rust memory.
            if unsafe { libc::kill(pid, libc::SIGKILL) } == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) && first_error.is_none() {
                    first_error = Some(error);
                }
            } else {
                signalled.insert(identity);
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(first_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "test-owned Unix session did not become empty",
                )
            }));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(windows)]
#[derive(Debug)]
pub struct OuterTestBoundary {
    job: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl OuterTestBoundary {
    pub fn configure(command: &mut Command) -> io::Result<()> {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED};

        command.creation_flags(CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP);
        Ok(())
    }

    pub fn after_spawn(child: &Child) -> io::Result<Self> {
        use std::mem::size_of;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        };
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        use windows_sys::Win32::System::Threading::{
            OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
        };

        // SAFETY: null security/name creates an unnamed job owned by this process.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let length = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
            .map_err(io::Error::other)?;
        // SAFETY: the information pointer is valid for the supplied structure size.
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const information).cast(),
                length,
            )
        };
        // SAFETY: Child's raw handle is valid while `child` is borrowed.
        let assigned = unsafe { AssignProcessToJobObject(job, child.as_raw_handle().cast()) };
        if configured == 0 || assigned == 0 {
            let error = io::Error::last_os_error();
            // SAFETY: job was created successfully and has not yet been closed.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
            return Err(error);
        }

        // The standard Child API exposes the process handle but not the primary thread handle.
        // Enumerate the just-created process's threads while it remains suspended, then resume
        // them only after assignment to the kill-on-close Job Object.
        // SAFETY: snapshot flags and process id are plain values.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
            return Err(error);
        }
        let mut entry = THREADENTRY32 {
            dwSize: u32::try_from(size_of::<THREADENTRY32>()).map_err(io::Error::other)?,
            ..Default::default()
        };
        let mut found = false;
        // SAFETY: entry points to initialized writable storage of the declared size.
        let mut available = unsafe { Thread32First(snapshot, &mut entry) } != 0;
        while available {
            if entry.th32OwnerProcessID == child.id() {
                // SAFETY: the thread id came from the OS snapshot.
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if !thread.is_null() {
                    // SAFETY: the handle has suspend/resume access and is closed below.
                    if unsafe { ResumeThread(thread) } != u32::MAX {
                        found = true;
                    }
                    unsafe { windows_sys::Win32::Foundation::CloseHandle(thread) };
                }
            }
            // SAFETY: entry remains valid writable storage.
            available = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
        }
        // SAFETY: snapshot is an owned valid handle.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(snapshot) };
        if !found {
            let error = io::Error::other("could not resume suspended test process thread");
            unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
            return Err(error);
        }
        Ok(Self { job })
    }

    pub fn terminate(&self) -> io::Result<()> {
        // SAFETY: job remains valid for the lifetime of this boundary.
        if unsafe { windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job, 1) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
impl Drop for OuterTestBoundary {
    fn drop(&mut self) {
        // SAFETY: job is uniquely owned by this value.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.job) };
    }
}

#[cfg(not(any(unix, windows)))]
#[derive(Debug)]
pub struct OuterTestBoundary;

#[cfg(not(any(unix, windows)))]
impl OuterTestBoundary {
    pub fn configure(_command: &mut Command) -> io::Result<()> {
        Ok(())
    }

    pub fn after_spawn(_child: &Child) -> io::Result<Self> {
        Ok(Self)
    }

    pub fn terminate(&self) -> io::Result<()> {
        Ok(())
    }
}
